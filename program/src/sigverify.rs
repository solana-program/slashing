//! Parsing signature verification results through instruction introspection
use {
    crate::error::SlashingError,
    bytemuck::{Pod, Zeroable},
    solana_program::{
        account_info::AccountInfo,
        ed25519_program,
        instruction::Instruction,
        msg,
        pubkey::{Pubkey, PUBKEY_BYTES},
        sysvar::instructions::{get_instruction_relative, load_current_index_checked},
    },
    solana_signature::SIGNATURE_BYTES,
    std::mem::MaybeUninit,
};

const SIGNATURE_OFFSETS_SERIALIZED_SIZE: usize = 14;
const SIGNATURE_OFFSETS_START: usize = 2;

#[derive(Default, Debug, Copy, Clone, Zeroable, Pod, Eq, PartialEq)]
#[repr(C)]
pub(crate) struct Ed25519SignatureOffsets {
    pub(crate) signature_offset: u16, // offset to ed25519 signature of 64 bytes
    pub(crate) signature_instruction_index: u16, // instruction index to find signature
    pub(crate) public_key_offset: u16, // offset to public key of 32 bytes
    pub(crate) public_key_instruction_index: u16, // instruction index to find public key
    pub(crate) message_data_offset: u16, // offset to start of message data
    pub(crate) message_data_size: u16, // size of message data
    pub(crate) message_instruction_index: u16, // index of instruction data to get message data
}

impl Ed25519SignatureOffsets {
    pub(crate) fn to_instruction(offsets: &[Self]) -> Instruction {
        let mut instruction_data = Vec::with_capacity(
            SIGNATURE_OFFSETS_START
                .saturating_add(SIGNATURE_OFFSETS_SERIALIZED_SIZE.saturating_mul(offsets.len())),
        );

        let num_signatures = offsets.len() as u16;
        instruction_data.extend_from_slice(&num_signatures.to_le_bytes());

        for offsets in offsets {
            instruction_data.extend_from_slice(bytemuck::bytes_of(offsets));
        }

        Instruction {
            program_id: ed25519_program::id(),
            accounts: vec![],
            data: instruction_data,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct SignatureVerification<'a> {
    pub(crate) pubkey: &'a Pubkey,
    pub(crate) message: &'a [u8],
    pub(crate) signature: &'a [u8; SIGNATURE_BYTES],
}

impl<'a> SignatureVerification<'a> {
    fn new(
        pubkey: &'a [u8],
        message: &'a [u8],
        signature: &'a [u8],
    ) -> Result<SignatureVerification<'a>, SlashingError> {
        let pubkey: &'a Pubkey = bytemuck::try_from_bytes(pubkey).map_err(|_| {
            msg!("Failed to deserialize pubkey");
            SlashingError::InvalidSignatureVerification
        })?;

        let signature: &'a [u8; SIGNATURE_BYTES] = signature.try_into().map_err(|_| {
            msg!("Failed to deserialize signature");
            SlashingError::InvalidSignatureVerification
        })?;

        Ok(Self {
            pubkey,
            message,
            signature,
        })
    }

    fn get_data_slice<'b>(
        data: &'a [u8],
        _instructions_sysvar: &'a AccountInfo<'b>,
        instruction_index: u16,
        current_index: u16,
        offset_start: u16,
        size: usize,
    ) -> Result<&'a [u8], SlashingError> {
        if instruction_index != current_index {
            // For duplicate block slashing the message is small enough to fit inside the
            // slashing instruction but this might not be the case for future slashing cases
            // TODO: re-implement load_instruction_at_checked(instruction_index as usize,
            // instructions_sysvar) in a zero copy way.
            msg!("Signature verification instruction must store the data within the slashing instruction");
            return Err(SlashingError::InvalidSignatureVerification);
        }
        let start = offset_start as usize;
        let end = start.saturating_add(size);
        if end > data.len() {
            return Err(SlashingError::InvalidSignatureVerification);
        }

        Ok(&data[start..end])
    }

    /// Perform instruction introspection to grab details about signature
    /// verification
    pub(crate) fn inspect_verifications<'b, const NUM_VERIFICATIONS: usize>(
        instruction_data: &'a [u8],
        instructions_sysvar: &'a AccountInfo<'b>,
        relative_index: i64,
    ) -> Result<[SignatureVerification<'a>; NUM_VERIFICATIONS], SlashingError> {
        let mut verifications = [MaybeUninit::<SignatureVerification>::uninit(); NUM_VERIFICATIONS];

        // Instruction inspection to unpack successful signature verifications
        let current_index = load_current_index_checked(instructions_sysvar)
            .map_err(|_| SlashingError::InvalidSignatureVerification)?;
        let sigverify_ix = get_instruction_relative(relative_index, instructions_sysvar)
            .map_err(|_| SlashingError::MissingSignatureVerification)?;
        if sigverify_ix.program_id != ed25519_program::id() {
            return Err(SlashingError::MissingSignatureVerification);
        }
        let num_signatures = u16::from_le_bytes(
            sigverify_ix.data[0..2]
                .try_into()
                .map_err(|_| SlashingError::MissingSignatureVerification)?,
        );
        if num_signatures < NUM_VERIFICATIONS as u16 {
            return Err(SlashingError::MissingSignatureVerification);
        }
        let expected_data_size = NUM_VERIFICATIONS
            .saturating_mul(SIGNATURE_OFFSETS_SERIALIZED_SIZE)
            .saturating_add(SIGNATURE_OFFSETS_START);
        if sigverify_ix.data.len() < expected_data_size {
            return Err(SlashingError::InvalidSignatureVerification);
        }

        for (i, verification) in verifications.iter_mut().enumerate().take(NUM_VERIFICATIONS) {
            let start = i
                .saturating_mul(SIGNATURE_OFFSETS_SERIALIZED_SIZE)
                .saturating_add(SIGNATURE_OFFSETS_START);
            let end = start.saturating_add(SIGNATURE_OFFSETS_SERIALIZED_SIZE);

            let offsets: &Ed25519SignatureOffsets =
                bytemuck::try_from_bytes(&sigverify_ix.data[start..end])
                    .map_err(|_| SlashingError::InvalidSignatureVerification)?;

            // Parse out signature
            let signature = Self::get_data_slice(
                instruction_data,
                instructions_sysvar,
                offsets.signature_instruction_index,
                current_index,
                offsets.signature_offset,
                SIGNATURE_BYTES,
            )?;

            // Parse out pubkey
            let pubkey = Self::get_data_slice(
                instruction_data,
                instructions_sysvar,
                offsets.public_key_instruction_index,
                current_index,
                offsets.public_key_offset,
                PUBKEY_BYTES,
            )?;

            // Parse out message
            let message = Self::get_data_slice(
                instruction_data,
                instructions_sysvar,
                offsets.message_instruction_index,
                current_index,
                offsets.message_data_offset,
                offsets.message_data_size as usize,
            )?;

            *verification =
                MaybeUninit::new(SignatureVerification::new(pubkey, message, signature)?);
        }
        unsafe { std::mem::transmute_copy(&verifications) }
    }
}
