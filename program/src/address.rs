//! Helper struct to derive the seeds for the report PDA

use {
    crate::{id, state::ViolationReport},
    solana_program::pubkey::Pubkey,
};

pub(crate) struct ViolationReportAddress<'a> {
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
}
