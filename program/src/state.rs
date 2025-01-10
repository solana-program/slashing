//! Program state
use {
    crate::{duplicate_block_proof::DuplicateBlockProofData, error::SlashingError},
    solana_program::{account_info::AccountInfo, clock::Slot, pubkey::Pubkey},
    std::slice::Iter,
};

const PACKET_DATA_SIZE: usize = 1232;

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
                DuplicateBlockProofData::size_of(PACKET_DATA_SIZE)
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

    /// Zero copy from raw data buffers and initialize any context
    fn unpack<'b>(
        proof_account_data: &'a [u8],
        instruction_data: &'a [u8],
        account_info_iter: &'a mut Iter<'_, AccountInfo<'b>>,
    ) -> Result<(Self, Self::Context), SlashingError>
    where
        Self: Sized;

    /// Verification logic for this type of proof data
    fn verify_proof(
        self,
        context: Self::Context,
        slot: Slot,
        pubkey: &Pubkey,
    ) -> Result<(), SlashingError>;
}

#[cfg(test)]
mod tests {
    use crate::state::PACKET_DATA_SIZE;

    #[test]
    fn test_packet_size_parity() {
        assert_eq!(PACKET_DATA_SIZE, solana_sdk::packet::PACKET_DATA_SIZE);
    }
}
