//! Slashing program
#![deny(missing_docs)]

pub mod duplicate_block_proof;
mod entrypoint;
pub mod error;
pub mod instruction;
pub mod processor;
mod shred;
mod sigverify;
pub mod state;

// Export current SDK types for downstream users building with a different SDK
// version
pub use solana_program;
use {
    solana_program::{clock::Slot, pubkey::Pubkey},
    state::ProofType,
};

solana_program::declare_id!("S1ashing11111111111111111111111111111111111");

/// Returns the account where a violation report will be populated on
/// a successful proof of `node_pubkey` committing a `violation_type`
/// violation in slot `slot`
pub fn get_violation_report_address(
    node_pubkey: &Pubkey,
    slot: Slot,
    violation_type: ProofType,
) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[
            node_pubkey.as_ref(),
            &slot.to_le_bytes(),
            &[violation_type.into()],
        ],
        &id(),
    )
}
