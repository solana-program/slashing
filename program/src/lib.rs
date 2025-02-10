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
    state::{ProofType, ViolationReport},
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

struct ViolationReportAddress<'a> {
    address: Pubkey,
    pubkey_seed: &'a [u8],
    slot_seed: &'a [u8; 8],
    violation_seed: [u8; 1],
    bump_seed: [u8; 1],
}

impl<'a> ViolationReportAddress<'a> {
    pub(crate) fn new(report: &'a ViolationReport) -> ViolationReportAddress<'a> {
        let pubkey_seed = report.pubkey.as_ref();
        let slot_seed = &report.slot.0;
        let violation_seed = [report.violation_type];
        let (pda, bump) =
            Pubkey::find_program_address(&[pubkey_seed, slot_seed, &violation_seed], &id());
        let bump_seed = [bump];
        Self {
            address: pda,
            pubkey_seed,
            slot_seed,
            violation_seed,
            bump_seed,
        }
    }

    pub(crate) fn key(&self) -> &Pubkey {
        &self.address
    }

    pub(crate) fn seeds(&self) -> [&[u8]; 4] {
        [
            self.pubkey_seed,
            self.slot_seed,
            &self.violation_seed,
            &self.bump_seed,
        ]
    }

    pub(crate) fn seeds_owned(&self) -> [Vec<u8>; 4] {
        [
            self.pubkey_seed.to_owned(),
            Vec::from(self.slot_seed),
            Vec::from(self.violation_seed),
            Vec::from(self.bump_seed),
        ]
    }
}
