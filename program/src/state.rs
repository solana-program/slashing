//! Program state
use {
    crate::{
        address::ViolationReportAddress, check_id, duplicate_block_proof::DuplicateBlockProofData,
        error::SlashingError, id,
    },
    bytemuck::{Pod, Zeroable},
    solana_program::{
        account_info::{next_account_info, AccountInfo},
        clock::{Epoch, Slot},
        msg,
        program::invoke_signed,
        program_error::ProgramError,
        pubkey::Pubkey,
        rent::Rent,
        sysvar::{self, Sysvar},
    },
    solana_system_interface::{instruction as system_instruction, program as system_program},
    spl_pod::{bytemuck::pod_from_bytes, primitives::PodU64},
    std::{fmt::Display, str::FromStr},
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

impl Display for ProofType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.violation_str())
    }
}

impl FromStr for ProofType {
    type Err = std::fmt::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == Self::DuplicateBlockProof.violation_str() {
            Ok(Self::DuplicateBlockProof)
        } else if s == Self::InvalidType.violation_str() {
            Ok(Self::InvalidType)
        } else {
            Err(Self::Err {})
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
        let mut account_data = self.violation_pda_account.try_borrow_mut_data()?;
        account_data[0..std::mem::size_of::<ViolationReport>()]
            .copy_from_slice(bytemuck::bytes_of(&report));
        account_data[std::mem::size_of::<ViolationReport>()..]
            .copy_from_slice(&T::pack_proof(proof));
        Ok(())
    }
}

/// On chain proof report of a slashable violation
/// The report account will contain this followed by the
/// serialized proof
#[repr(C)]
#[derive(Copy, Clone, Debug, Pod, Zeroable, PartialEq)]
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
}

impl ViolationReport {
    /// The current version
    pub const VERSION: u8 = 1;

    /// Returns the version of the violation account
    pub fn version(data: &[u8]) -> u8 {
        data[0]
    }

    /// Returns the packed length of this violation report plus the packed
    /// length of `proof`
    pub fn packed_len<'a, T: SlashingProofData<'a>>(proof: &T) -> usize {
        std::mem::size_of::<ViolationReport>().saturating_add(proof.packed_len())
    }

    /// Returns the maximum size of the serialized report plus the maximum size
    /// of a proof for `T`
    pub const fn size<'a, T: SlashingProofData<'a>>() -> usize {
        std::mem::size_of::<ViolationReport>().saturating_add(T::PROOF_TYPE.proof_account_length())
    }

    /// The epoch in which this report was created
    pub fn epoch(&self) -> Epoch {
        Epoch::from(self.epoch)
    }

    /// The slot in which the violation occurred
    pub fn slot(&self) -> Slot {
        Slot::from(self.slot)
    }

    /// The type of violation that occurred
    pub fn violation_type(&self) -> ProofType {
        ProofType::from(self.violation_type)
    }
}

/// Store a `ProofReport` of a successful proof at a
/// PDA derived from the `pubkey`, `slot`, and `T:PROOF_TYPE`.
///
/// Returns a boolean specifying if this was the first report of this
/// violation
pub(crate) fn store_violation_report<'a, 'b, T>(
    report: ViolationReport,
    accounts: &SlashingAccounts<'a, 'b>,
    proof_data: T,
) -> Result<(), ProgramError>
where
    T: SlashingProofData<'a>,
{
    let report_address = ViolationReportAddress::new(&report);
    let report_key = report_address.key();
    let seeds = report_address.seeds();
    let cpi_accounts = [
        accounts.violation_pda_account.clone(),
        accounts.system_program_account.clone(),
    ];

    if *report_key != *accounts.violation_account() {
        return Err(ProgramError::from(
            SlashingError::InvalidViolationReportAcccount,
        ));
    }

    // Check if it was already reported
    if accounts.violation_account_exists()? {
        msg!(
            "{} violation verified in slot {} however the violation has already been reported",
            T::PROOF_TYPE.violation_str(),
            u64::from(report.slot),
        );
        return Err(ProgramError::from(SlashingError::DuplicateReport));
    }

    if *report_key == report.destination {
        return Err(ProgramError::from(
            SlashingError::DestinationAddressIsReportAccount,
        ));
    }

    // Check if the account has been prefunded to store the report
    let data_len = ViolationReport::packed_len(&proof_data);
    let lamports = Rent::get()?.minimum_balance(data_len);
    if accounts.violation_pda_account.try_lamports()? < lamports {
        return Err(ProgramError::from(SlashingError::ReportAccountNotPrefunded));
    }

    // Assign the slashing program as the owner
    let assign_instruction = system_instruction::assign(report_key, &id());
    invoke_signed(&assign_instruction, &cpi_accounts, &[&seeds])?;

    // Allocate enough space for the report
    accounts.violation_pda_account.realloc(data_len, false)?;

    // Verify that the account can now hold the report
    if accounts.violation_pda_account.data_len() != data_len {
        msg!(
            "Something has gone wrong, account is improperly sized {} vs expected {}",
            accounts.violation_pda_account.data_len(),
            data_len
        );
        return Err(ProgramError::InvalidAccountData);
    }

    // Write the report
    accounts.write_violation_report(report, proof_data)
}

pub(crate) fn close_violation_report<'a, 'b>(
    report_account: &'a AccountInfo<'b>,
    destination_account: &'a AccountInfo<'b>,
) -> Result<(), ProgramError> {
    let report_data = report_account.try_borrow_data()?;
    let report: &ViolationReport =
        pod_from_bytes(&report_data[0..std::mem::size_of::<ViolationReport>()])?;
    let destination = report.destination;

    if Epoch::from(report.epoch).saturating_add(3) > sysvar::clock::Clock::get()?.epoch {
        return Err(ProgramError::from(
            SlashingError::CloseViolationReportTooSoon,
        ));
    }

    if destination != *destination_account.key {
        return Err(ProgramError::from(SlashingError::InvalidDestinationAccount));
    }

    // Drop the report account to close it
    drop(report_data);

    // Reallocate the account to 0 bytes
    report_account.realloc(0, false)?;

    // Assign the system program as the owner
    report_account.assign(&system_program::id());

    // Transfer the lamports to the destination address
    let report_lamports = report_account.lamports();
    **report_account.try_borrow_mut_lamports()? = 0;

    let destination_lamports = destination_account.lamports();
    **(destination_account.try_borrow_mut_lamports()?) = destination_lamports
        .checked_add(report_lamports)
        .ok_or(ProgramError::ArithmeticOverflow)?;

    msg!(
        "Closed violation report and credited {} lamports to the destination address",
        report_lamports
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::state::PACKET_DATA_SIZE;

    #[test]
    fn test_packet_size_parity() {
        assert_eq!(PACKET_DATA_SIZE, solana_sdk::packet::PACKET_DATA_SIZE);
    }
}
