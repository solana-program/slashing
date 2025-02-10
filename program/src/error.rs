//! Error types

use {
    num_derive::FromPrimitive,
    solana_program::{decode_error::DecodeError, program_error::ProgramError},
    thiserror::Error,
};

/// Errors that may be returned by the program.
#[derive(Clone, Copy, Debug, Eq, Error, FromPrimitive, PartialEq)]
pub enum SlashingError {
    /// Attempting to close a violation report before 3
    /// epochs have passed
    #[error("Closing violation report too soon")]
    CloseViolationReportTooSoon,

    /// Violation has already been reported
    #[error("Duplicate report")]
    DuplicateReport,

    /// Violation is too old for statute of limitations
    #[error("Exceeds statute of limitations")]
    ExceedsStatuteOfLimitations,

    /// Destination account does not match the key on the report
    #[error("Invalid destination account")]
    InvalidDestinationAccount,

    /// Invalid shred variant
    #[error("Invalid shred variant")]
    InvalidShredVariant,

    /// Invalid merkle shred
    #[error("Invalid Merkle shred")]
    InvalidMerkleShred,

    /// Invalid duplicate block payload proof
    #[error("Invalid payload proof")]
    InvalidPayloadProof,

    /// Invalid duplicate block erasure meta proof
    #[error("Invalid erasure meta conflict")]
    InvalidErasureMetaConflict,

    /// Invalid instruction
    #[error("Invalid instruction")]
    InvalidInstruction,

    /// Invalid duplicate block last index proof
    #[error("Invalid last index conflict")]
    InvalidLastIndexConflict,

    /// Invalid violation report account
    #[error("Invalid violation report account")]
    InvalidViolationReportAcccount,

    /// Invalid shred version on duplicate block proof shreds
    #[error("Invalid shred version")]
    InvalidShredVersion,

    /// Invalid signature verification instruction
    #[error("Signature verification instruction is invalid")]
    InvalidSignatureVerification,

    /// Legacy shreds are not supported
    #[error("Legacy shreds are not eligible for slashing")]
    LegacyShreds,

    /// Missing instructions sysvar
    #[error("Instructions sysvar is missing")]
    MissingInstructionsSysvar,

    /// Missing signature verification instruction
    #[error("Signature verification instruction is missing")]
    MissingSignatureVerification,

    /// Missing system program account
    #[error("System program account is missing")]
    MissingSystemProgramAccount,

    /// Unable to deserialize proof buffer
    #[error("Proof buffer deserialization error")]
    ProofBufferDeserializationError,

    /// Proof buffer is too small
    #[error("Proof buffer too small")]
    ProofBufferTooSmall,

    /// Report account is not prefunded with enough lamports to store
    /// the violation report
    #[error("Report account is not prefunded with enough lamports")]
    ReportAccountNotPrefunded,

    /// Shred deserialization error
    #[error("Deserialization error")]
    ShredDeserializationError,

    /// Invalid shred type on duplicate block proof shreds
    #[error("Shred type mismatch")]
    ShredTypeMismatch,

    /// Signature verification instruction did not match the shred
    #[error("Mismatch between signature verification and shred")]
    SignatureVerificationMismatch,

    /// Invalid slot on duplicate block proof shreds
    #[error("Slot mismatch")]
    SlotMismatch,
}

impl From<SlashingError> for ProgramError {
    fn from(e: SlashingError) -> Self {
        ProgramError::Custom(e as u32)
    }
}

impl<T> DecodeError<T> for SlashingError {
    fn type_of() -> &'static str {
        "Slashing Error"
    }
}
