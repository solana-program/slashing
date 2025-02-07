//! Program instructions

use {
    crate::{
        duplicate_block_proof::DuplicateBlockProofData,
        error::SlashingError,
        get_violation_report_address, id,
        sigverify::Ed25519SignatureOffsets,
        state::{ProofType, ViolationReport},
    },
    bytemuck::{Pod, Zeroable},
    num_enum::{IntoPrimitive, TryFromPrimitive},
    solana_program::{
        hash::{Hash, HASH_BYTES},
        instruction::{AccountMeta, Instruction},
        program_error::ProgramError,
        pubkey::{Pubkey, PUBKEY_BYTES},
        rent::Rent,
        system_instruction, system_program, sysvar,
    },
    solana_signature::SIGNATURE_BYTES,
    spl_pod::{
        bytemuck::{pod_from_bytes, pod_get_packed_len},
        primitives::PodU64,
    },
};

/// Instructions supported by the program
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, TryFromPrimitive, IntoPrimitive)]
pub enum SlashingInstruction {
    /// Submit a slashable violation proof for `node_pubkey`, which indicates
    /// that they submitted a duplicate block to the network
    ///
    ///
    /// Accounts expected by this instruction:
    /// 0. `[]` Proof account, must be previously initialized with the proof
    ///    data.
    /// 1. `[WRITE]` PDA to store the violation report
    /// 2. `[]` Instructions sysvar
    /// 3. `[]` System program
    ///
    /// We expect the proof account to be properly sized as to hold a duplicate
    /// block proof. See [`ProofType`] for sizing requirements.
    ///
    /// Deserializing the proof account from `offset` should result in a
    /// [`DuplicateBlockProofData`]
    ///
    /// We also expect that the PDA has already been prefunded with the
    /// necessary lamports to hold the report. Use [`VioaltionReport::size`]
    /// for the calculation.
    ///
    /// Data expected by this instruction:
    ///   `DuplicateBlockProofInstructionData`
    DuplicateBlockProof,
}

/// Data expected by
/// `SlashingInstruction::DuplicateBlockProof`
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Pod, Zeroable)]
pub struct DuplicateBlockProofInstructionData {
    /// Offset into the proof account to begin reading, expressed as `u64`
    pub offset: PodU64,
    /// Slot for which the violation occurred
    pub slot: PodU64,
    /// Identity pubkey of the Node that signed the duplicate block
    pub node_pubkey: Pubkey,
    /// Account to credit as the reporter of this violation
    pub reporter: Pubkey,
    /// Account to credit the lamports when this proof report is closed
    pub destination: Pubkey,
    /// The first shred's merkle root (the message of the first sigverify
    /// instruction)
    pub shred_1_merkle_root: Hash,
    /// The first shred's signature (the signature of the first sigverify
    /// instruction)
    pub shred_1_signature: [u8; SIGNATURE_BYTES],
    /// The second shred's merkle root (the message of the second sigverify
    /// instruction)
    pub shred_2_merkle_root: Hash,
    /// The second shred's signature (the signature of the second sigverify
    /// instruction)
    pub shred_2_signature: [u8; SIGNATURE_BYTES],
}

impl DuplicateBlockProofInstructionData {
    // 1 Byte for the instruction type discriminant
    const DATA_START: u16 = 1;
    const NODE_PUBKEY_OFFSET: u16 = 16 + Self::DATA_START;
    const REPORTER_OFFSET: u16 = PUBKEY_BYTES as u16 + Self::NODE_PUBKEY_OFFSET;
    const DESTINATION_OFFSET: u16 = PUBKEY_BYTES as u16 + Self::REPORTER_OFFSET;

    const MESSAGE_1_OFFSET: u16 = PUBKEY_BYTES as u16 + Self::DESTINATION_OFFSET;
    const SIGNATURE_1_OFFSET: u16 = HASH_BYTES as u16 + Self::MESSAGE_1_OFFSET;
    const MESSAGE_2_OFFSET: u16 = SIGNATURE_BYTES as u16 + Self::SIGNATURE_1_OFFSET;
    const SIGNATURE_2_OFFSET: u16 = HASH_BYTES as u16 + Self::MESSAGE_2_OFFSET;

    pub(crate) fn offset(&self) -> Result<usize, ProgramError> {
        usize::try_from(u64::from(self.offset)).map_err(|_| ProgramError::ArithmeticOverflow)
    }

    /// The offset into the instruction data where the signature verification
    /// data starts, aka the first shred's merkle root
    pub const fn sigverify_data_offset() -> usize {
        Self::MESSAGE_1_OFFSET as usize
    }
}

/// Utility function for encoding instruction data
pub(crate) fn encode_instruction<D: Pod>(
    accounts: Vec<AccountMeta>,
    instruction: SlashingInstruction,
    instruction_data: &D,
) -> Instruction {
    let mut data = vec![u8::from(instruction)];
    data.extend_from_slice(bytemuck::bytes_of(instruction_data));
    Instruction {
        program_id: id(),
        accounts,
        data,
    }
}

/// Utility function for decoding just the instruction type
pub(crate) fn decode_instruction_type(input: &[u8]) -> Result<SlashingInstruction, ProgramError> {
    if input.is_empty() {
        Err(ProgramError::InvalidInstructionData)
    } else {
        SlashingInstruction::try_from(input[0])
            .map_err(|_| SlashingError::InvalidInstruction.into())
    }
}

/// Utility function for decoding instruction data
pub(crate) fn decode_instruction_data<T: Pod>(input_with_type: &[u8]) -> Result<&T, ProgramError> {
    if input_with_type.len() != pod_get_packed_len::<T>().saturating_add(1) {
        Err(ProgramError::InvalidInstructionData)
    } else {
        pod_from_bytes(&input_with_type[1..])
    }
}

/// Create a `SlashingInstruction::DuplicateBlockProof` instruction
pub fn duplicate_block_proof(
    proof_account: &Pubkey,
    instruction_data: &DuplicateBlockProofInstructionData,
) -> Instruction {
    let (pda, _) = get_violation_report_address(
        &instruction_data.node_pubkey,
        u64::from(instruction_data.slot),
        ProofType::DuplicateBlockProof,
    );

    let accounts = vec![
        AccountMeta::new_readonly(*proof_account, false),
        AccountMeta::new(pda, false),
        AccountMeta::new_readonly(sysvar::instructions::id(), false),
        AccountMeta::new_readonly(system_program::id(), false),
    ];

    encode_instruction(
        accounts,
        SlashingInstruction::DuplicateBlockProof,
        instruction_data,
    )
}

/// Utility to create instructions for prefunding the report account, signature
/// verification and the `SlashingInstruction::DuplicateBlockProof` in the
/// expected format.
///
/// `sigverify_data` should equal the `(shredx.merkle_root, shredx.signature)`
/// specified in the proof account
///
/// Returns three instructions, the transfer, the sigverify and the slashing
/// instruction. These must be sent consecutively as the first three
/// instructions in a transaction with the same ordering to function properly.
pub fn duplicate_block_proof_with_sigverify_and_prefund(
    proof_account: &Pubkey,
    instruction_data: &DuplicateBlockProofInstructionData,
    rent: &Rent,
) -> [Instruction; 3] {
    let slashing_ix = duplicate_block_proof(proof_account, instruction_data);

    let signature_instruction_index = 2;
    let public_key_offset = DuplicateBlockProofInstructionData::NODE_PUBKEY_OFFSET;
    let public_key_instruction_index = 2;
    let message_data_size = HASH_BYTES as u16;
    let message_instruction_index = 2;

    let shred1_sigverify_offset = Ed25519SignatureOffsets {
        signature_offset: DuplicateBlockProofInstructionData::SIGNATURE_1_OFFSET,
        signature_instruction_index,
        public_key_offset,
        public_key_instruction_index,
        message_data_offset: DuplicateBlockProofInstructionData::MESSAGE_1_OFFSET,
        message_data_size,
        message_instruction_index,
    };
    let shred2_sigverify_offset = Ed25519SignatureOffsets {
        signature_offset: DuplicateBlockProofInstructionData::SIGNATURE_2_OFFSET,
        signature_instruction_index,
        public_key_offset,
        public_key_instruction_index,
        message_data_offset: DuplicateBlockProofInstructionData::MESSAGE_2_OFFSET,
        message_data_size,
        message_instruction_index,
    };
    let sigverify_ix = Ed25519SignatureOffsets::to_instruction(&[
        shred1_sigverify_offset,
        shred2_sigverify_offset,
    ]);

    let (pda, _) = get_violation_report_address(
        &instruction_data.node_pubkey,
        u64::from(instruction_data.slot),
        ProofType::DuplicateBlockProof,
    );
    let lamports = rent.minimum_balance(ViolationReport::size::<DuplicateBlockProofData>());
    let transfer_ix = system_instruction::transfer(&instruction_data.reporter, &pda, lamports);

    [transfer_ix, sigverify_ix, slashing_ix]
}

#[cfg(test)]
pub(crate) fn construct_instructions_and_sysvar(
    instruction_data: &DuplicateBlockProofInstructionData,
) -> ([Instruction; 3], Vec<u8>) {
    use solana_sdk::sysvar::instructions::{self, BorrowedAccountMeta, BorrowedInstruction};

    fn borrow_account(account: &AccountMeta) -> BorrowedAccountMeta {
        BorrowedAccountMeta {
            pubkey: &account.pubkey,
            is_signer: account.is_signer,
            is_writable: account.is_writable,
        }
    }
    fn borrow_instruction(ix: &Instruction) -> BorrowedInstruction {
        BorrowedInstruction {
            program_id: &ix.program_id,
            accounts: ix.accounts.iter().map(borrow_account).collect(),
            data: &ix.data,
        }
    }

    let instructions = duplicate_block_proof_with_sigverify_and_prefund(
        &Pubkey::new_unique(),
        instruction_data,
        &Rent::default(),
    );
    let borrowed_instructions: Vec<BorrowedInstruction> =
        instructions.iter().map(borrow_instruction).collect();
    let mut instructions_sysvar_data =
        instructions::construct_instructions_data(&borrowed_instructions);
    instructions::store_current_index(&mut instructions_sysvar_data, 2);
    (instructions, instructions_sysvar_data)
}

#[cfg(test)]
mod tests {
    use {super::*, solana_program::program_error::ProgramError, solana_signature::Signature};

    const TEST_BYTES: [u8; 8] = [42; 8];

    #[test]
    fn serialize_duplicate_block_proof() {
        let offset = 34;
        let slot = 42;
        let node_pubkey = Pubkey::new_unique();
        let reporter = Pubkey::new_unique();
        let destination = Pubkey::new_unique();
        let shred_1_merkle_root = Hash::new_unique();
        let shred_1_signature = Signature::new_unique().into();
        let shred_2_merkle_root = Hash::new_unique();
        let shred_2_signature = Signature::new_unique().into();
        let instruction_data = DuplicateBlockProofInstructionData {
            offset: PodU64::from(offset),
            slot: PodU64::from(slot),
            node_pubkey,
            reporter,
            destination,
            shred_1_merkle_root,
            shred_1_signature,
            shred_2_merkle_root,
            shred_2_signature,
        };
        let instruction = duplicate_block_proof(&Pubkey::new_unique(), &instruction_data);
        let mut expected = vec![0];
        expected.extend_from_slice(&offset.to_le_bytes());
        expected.extend_from_slice(&slot.to_le_bytes());
        expected.extend_from_slice(&node_pubkey.to_bytes());
        expected.extend_from_slice(&reporter.to_bytes());
        expected.extend_from_slice(&destination.to_bytes());
        expected.extend_from_slice(&shred_1_merkle_root.to_bytes());
        expected.extend_from_slice(&shred_1_signature);
        expected.extend_from_slice(&shred_2_merkle_root.to_bytes());
        expected.extend_from_slice(&shred_2_signature);
        assert_eq!(instruction.data, expected);

        assert_eq!(
            SlashingInstruction::DuplicateBlockProof,
            decode_instruction_type(&instruction.data).unwrap()
        );
        let instruction_data: &DuplicateBlockProofInstructionData =
            decode_instruction_data(&instruction.data).unwrap();

        assert_eq!(instruction_data.offset, offset.into());
        assert_eq!(instruction_data.slot, slot.into());
        assert_eq!(instruction_data.node_pubkey, node_pubkey);
        assert_eq!(instruction_data.reporter, reporter);
        assert_eq!(instruction_data.destination, destination);
        assert_eq!(instruction_data.shred_1_merkle_root, shred_1_merkle_root);
        assert_eq!(instruction_data.shred_1_signature, shred_1_signature);
        assert_eq!(instruction_data.shred_2_merkle_root, shred_2_merkle_root);
        assert_eq!(instruction_data.shred_2_signature, shred_2_signature);
    }

    #[test]
    fn deserialize_invalid_instruction() {
        let mut expected = vec![12];
        expected.extend_from_slice(&TEST_BYTES);
        let err: ProgramError = decode_instruction_type(&expected).unwrap_err();
        assert_eq!(err, SlashingError::InvalidInstruction.into());
    }
}
