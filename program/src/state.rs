//! Program state
use {
    crate::{check_id, duplicate_block_proof::DuplicateBlockProofData, error::SlashingError, id},
    bytemuck::{Pod, Zeroable},
    solana_program::{
        account_info::{next_account_info, AccountInfo},
        clock::Slot,
        msg,
        program::invoke_signed,
        program_error::ProgramError,
        pubkey::Pubkey,
        rent::Rent,
        system_instruction, system_program,
        sysvar::{self, Sysvar},
    },
    spl_pod::primitives::PodU64,
};

const PACKET_DATA_SIZE: usize = 1232;
type PodSlot = PodU64;
pub(crate) type PodEpoch = PodU64;

/// Types of slashing proofs
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofType {
    /// Invalid proof type
    InvalidType,
    /// Proof consisting of 2 shreds signed by the leader indicating the leader
    /// submitted a duplicate block.
    DuplicateBlockProof,
}

impl ProofType {
    /// Size of the proof account to create in order to hold the proof data
    /// header and contents
    pub const fn proof_account_length(&self) -> usize {
        match self {
            Self::InvalidType => panic!("Cannot determine size of invalid proof type"),
            Self::DuplicateBlockProof => {
                // Duplicate block proof consists of 2 shreds that can be `PACKET_DATA_SIZE`.
                DuplicateBlockProofData::size(PACKET_DATA_SIZE)
            }
        }
    }

    /// Display string for this proof type's violation
    pub fn violation_str(&self) -> &str {
        match self {
            Self::InvalidType => "invalid",
            Self::DuplicateBlockProof => "duplicate block",
        }
    }
}

impl From<ProofType> for u8 {
    fn from(value: ProofType) -> Self {
        match value {
            ProofType::InvalidType => 0,
            ProofType::DuplicateBlockProof => 1,
        }
    }
}

impl From<u8> for ProofType {
    fn from(value: u8) -> Self {
        match value {
            1 => Self::DuplicateBlockProof,
            _ => Self::InvalidType,
        }
    }
}

/// Trait that proof accounts must satisfy in order to verify via the slashing
/// program
pub trait SlashingProofData<'a> {
    /// The type of proof this data represents
    const PROOF_TYPE: ProofType;
    /// The context needed to verify the proof
    type Context;

    /// The size of the proof in bytes
    fn packed_len(&self) -> usize;

    /// Pack the proof data into a raw data buffer
    fn pack_proof(self) -> Vec<u8>;

    /// Zero copy from raw data buffers and initialize any context
    fn unpack_proof_and_context<'b>(
        proof_account_data: &'a [u8],
        instruction_data: &'a [u8],
        accounts: &SlashingAccounts<'a, 'b>,
    ) -> Result<(Self, Self::Context), SlashingError>
    where
        Self: Sized;

    /// Verification logic for this type of proof data
    fn verify_proof(
        &self,
        context: Self::Context,
        slot: Slot,
        pubkey: &Pubkey,
    ) -> Result<(), SlashingError>;
}

/// Accounts relevant for the slashing program
pub struct SlashingAccounts<'a, 'b> {
    pub(crate) proof_account: &'a AccountInfo<'b>,
    pub(crate) reporter_account: &'a AccountInfo<'b>,
    pub(crate) violation_pda_account: &'a AccountInfo<'b>,
    pub(crate) instructions_sysvar: &'a AccountInfo<'b>,
    pub(crate) system_program_account: &'a AccountInfo<'b>,
}

impl<'a, 'b> SlashingAccounts<'a, 'b> {
    pub(crate) fn new<I>(account_info_iter: &mut I) -> Result<Self, ProgramError>
    where
        I: Iterator<Item = &'a AccountInfo<'b>>,
    {
        let res = Self {
            proof_account: next_account_info(account_info_iter)?,
            reporter_account: next_account_info(account_info_iter)?,
            violation_pda_account: next_account_info(account_info_iter)?,
            instructions_sysvar: next_account_info(account_info_iter)?,
            system_program_account: next_account_info(account_info_iter)?,
        };
        if !sysvar::instructions::check_id(res.instructions_sysvar.key) {
            return Err(ProgramError::from(SlashingError::MissingInstructionsSysvar));
        }
        if !system_program::check_id(res.system_program_account.key) {
            return Err(ProgramError::from(
                SlashingError::MissingSystemProgramAccount,
            ));
        }
        Ok(res)
    }

    pub(crate) fn reporter(&self) -> &Pubkey {
        self.reporter_account.key
    }

    pub(crate) fn proof_account(&self) -> &Pubkey {
        self.proof_account.key
    }

    fn violation_account(&self) -> &Pubkey {
        self.violation_pda_account.key
    }

    fn violation_account_exists(&self) -> Result<bool, ProgramError> {
        Ok(!self.violation_pda_account.data_is_empty()
            && check_id(self.violation_pda_account.owner)
            && ViolationReport::version(&self.violation_pda_account.try_borrow_data()?) > 0)
    }

    fn write_violation_report<T>(
        &self,
        report: ViolationReport,
        proof: T,
    ) -> Result<(), ProgramError>
    where
        T: SlashingProofData<'a>,
    {
        self.violation_pda_account.try_borrow_mut_data()?
            [0..std::mem::size_of::<ViolationReport>()]
            .copy_from_slice(bytemuck::bytes_of(&report));
        self.violation_pda_account.try_borrow_mut_data()?[std::mem::size_of::<ViolationReport>()..]
            .copy_from_slice(&T::pack_proof(proof));
        Ok(())
    }
}

/// On chain proof report of a slashable violation
/// The report account will contain this optionally followed by the
/// serialized proof
#[repr(C)]
#[derive(Copy, Clone, Debug, Pod, Zeroable)]
pub struct ViolationReport {
    /// The report format version number
    pub version: u8,
    /// The first reporter of this violation
    pub reporter: Pubkey,
    /// Account to credit the lamports when this proof report is closed
    pub destination: Pubkey,
    /// Epoch in which this report was created
    pub epoch: PodEpoch,
    /// Identity of the violator
    pub pubkey: Pubkey,
    /// Slot in which the violation occurred
    pub slot: PodSlot,
    /// Discriminant of `ProofType` representing the violation type
    pub violation_type: u8,
    /// Account where the proof is stored
    pub proof_account: Pubkey,
}

impl ViolationReport {
    /// The current version
    pub const VERSION: u8 = 1;

    /// Returns the version of the violation account
    pub fn version(data: &[u8]) -> u8 {
        data[0]
    }
}

/// Store a `ProofReport` of a successful proof at a
/// PDA derived from the `pubkey`, `slot`, and `T:PROOF_TYPE`.
///
/// Returns a boolean specifying if this was the first report of this
/// violation
pub(crate) fn store_violation_report<'a, 'b, T>(
    slot: Slot,
    report: ViolationReport,
    accounts: &SlashingAccounts<'a, 'b>,
    proof_data: T,
) -> Result<(), ProgramError>
where
    T: SlashingProofData<'a>,
{
    let pubkey_seed = report.pubkey.as_ref();
    let slot_seed = slot.to_le_bytes();
    let violation_seed = [report.violation_type];
    let mut seeds: Vec<&[u8]> = vec![&pubkey_seed, &slot_seed, &violation_seed];
    let (pda, bump) = Pubkey::find_program_address(&seeds, &id());
    let bump_seed = [bump];
    seeds.push(&bump_seed);

    if pda != *accounts.violation_account() {
        return Err(ProgramError::from(
            SlashingError::InvalidViolationReportAcccount,
        ));
    }

    // Check if it was already reported
    if accounts.violation_account_exists()? {
        msg!(
            "{} violation verified in slot {} however the violation has already been reported",
            T::PROOF_TYPE.violation_str(),
            slot,
        );
        return Err(ProgramError::from(SlashingError::DuplicateReport));
    }

    // Create the account via CPI
    let data_len = std::mem::size_of::<ViolationReport>()
        .checked_add(proof_data.packed_len())
        .ok_or(ProgramError::ArithmeticOverflow)?;
    let lamports = Rent::get()?.minimum_balance(data_len);
    let create_account_ix = system_instruction::create_account(
        &report.reporter,
        &pda,
        lamports,
        data_len as u64,
        &id(),
    );
    invoke_signed(
        &create_account_ix,
        &[
            accounts.reporter_account.clone(),
            accounts.violation_pda_account.clone(),
            accounts.system_program_account.clone(),
        ],
        &[&seeds],
    )?;

    // Write the report
    accounts.write_violation_report(report, proof_data)
}

#[cfg(test)]
mod tests {
    use crate::state::PACKET_DATA_SIZE;

    #[test]
    fn test_packet_size_parity() {
        assert_eq!(PACKET_DATA_SIZE, solana_sdk::packet::PACKET_DATA_SIZE);
    }
}
