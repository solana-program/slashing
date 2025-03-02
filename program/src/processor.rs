//! Program state processor

use {
    crate::{
        check_id,
        duplicate_block_proof::DuplicateBlockProofData,
        error::SlashingError,
        instruction::{
            decode_instruction_data, decode_instruction_type, DuplicateBlockProofInstructionData,
            SlashingInstruction,
        },
        state::{
            close_violation_report, store_violation_report, PodEpoch, ProofType, SlashingAccounts,
            SlashingProofData, ViolationReport,
        },
    },
    solana_program::{
        account_info::{next_account_info, AccountInfo},
        entrypoint::ProgramResult,
        msg,
        program_error::ProgramError,
        pubkey::Pubkey,
        sysvar::{clock::Clock, epoch_schedule::EpochSchedule, Sysvar},
    },
};

fn verify_proof_data<'a, 'b, T>(
    report: ViolationReport,
    accounts: &SlashingAccounts<'a, 'b>,
    proof_data: &'a [u8],
    instruction_data: &'a [u8],
) -> ProgramResult
where
    T: SlashingProofData<'a>,
{
    // Statute of limitations is 1 epoch
    let slot = u64::from(report.slot);
    let clock = Clock::get()?;
    let Some(elapsed) = clock.slot.checked_sub(slot) else {
        return Err(ProgramError::ArithmeticOverflow);
    };
    let epoch_schedule = EpochSchedule::get()?;
    if elapsed > epoch_schedule.slots_per_epoch {
        return Err(SlashingError::ExceedsStatuteOfLimitations.into());
    }

    let (proof_data, context) =
        T::unpack_proof_and_context(proof_data, instruction_data, accounts)?;

    SlashingProofData::verify_proof(&proof_data, context, slot, &report.pubkey)?;

    store_violation_report(report, accounts, proof_data)?;
    msg!(
        "{} violation verified in slot {}. This incident has been recorded",
        T::PROOF_TYPE.violation_str(),
        slot
    );
    Ok(())
}

/// Instruction processor
pub fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    input: &[u8],
) -> ProgramResult {
    let instruction_type = decode_instruction_type(input)?;
    let account_info_iter = &mut accounts.iter();
    match instruction_type {
        SlashingInstruction::CloseViolationReport => {
            let report_account = next_account_info(account_info_iter)?;
            let destination_account = next_account_info(account_info_iter)?;

            if !check_id(report_account.owner) || report_account.data_is_empty() {
                return Err(ProgramError::from(
                    SlashingError::InvalidViolationReportAcccount,
                ));
            }

            close_violation_report(report_account, destination_account)?;
        }
        SlashingInstruction::DuplicateBlockProof => {
            let accounts = SlashingAccounts::new(account_info_iter)?;
            let data = decode_instruction_data::<DuplicateBlockProofInstructionData>(input)?;
            let proof_data = &accounts.proof_account.try_borrow_data()?[data.offset()?..];
            let violation_report = ViolationReport {
                version: ViolationReport::VERSION,
                reporter: data.reporter,
                destination: data.destination,
                epoch: PodEpoch::from(Clock::get()?.epoch),
                pubkey: data.node_pubkey,
                slot: data.slot,
                violation_type: u8::from(ProofType::DuplicateBlockProof),
            };
            verify_proof_data::<DuplicateBlockProofData>(
                violation_report,
                &accounts,
                proof_data,
                input,
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use {
        super::verify_proof_data,
        crate::{
            duplicate_block_proof::DuplicateBlockProofData,
            error::SlashingError,
            get_violation_report_address, id,
            instruction::{construct_instructions_and_sysvar, DuplicateBlockProofInstructionData},
            shred::tests::new_rand_data_shred,
            state::{PodEpoch, ProofType, SlashingAccounts, SlashingProofData, ViolationReport},
        },
        rand::Rng,
        solana_ledger::shred::Shredder,
        solana_sdk::{
            account_info::AccountInfo,
            clock::{Clock, Slot, DEFAULT_SLOTS_PER_EPOCH},
            epoch_schedule::EpochSchedule,
            program_error::ProgramError,
            pubkey::Pubkey,
            rent::Rent,
            signature::Keypair,
            signer::Signer,
            sysvar::instructions::{self},
        },
        spl_pod::primitives::PodU64,
        std::sync::{Arc, RwLock},
    };

    const SLOT: Slot = 53084024;
    // Based on the empircal size of two data shreds
    const SIZE: usize = 2414 + std::mem::size_of::<ViolationReport>();
    lazy_static::lazy_static! {
        static ref CLOCK_SLOT: Arc<RwLock<Slot>> = Arc::new(RwLock::new(SLOT));
    }

    fn generate_proof_data(leader: Arc<Keypair>) -> (DuplicateBlockProofInstructionData, Vec<u8>) {
        let mut rng = rand::rng();
        let (slot, parent_slot, reference_tick, version) = (SLOT, SLOT - 1, 0, 0);
        let shredder = Shredder::new(slot, parent_slot, reference_tick, version).unwrap();
        let next_shred_index = rng.random_range(0..32_000);
        let shred1 =
            new_rand_data_shred(&mut rng, next_shred_index, &shredder, &leader, true, true);
        let shred2 =
            new_rand_data_shred(&mut rng, next_shred_index, &shredder, &leader, true, true);
        let sigverify_data = DuplicateBlockProofInstructionData {
            slot: PodU64::from(slot),
            offset: PodU64::from(0),
            node_pubkey: leader.pubkey(),
            reporter: Pubkey::new_unique(),
            destination: Pubkey::new_unique(),
            shred_1_merkle_root: shred1.merkle_root().unwrap(),
            shred_2_merkle_root: shred2.merkle_root().unwrap(),
            shred_1_signature: shred1.signature().as_ref().try_into().unwrap(),
            shred_2_signature: shred2.signature().as_ref().try_into().unwrap(),
        };
        let proof_data = DuplicateBlockProofData {
            shred1: shred1.payload().as_ref(),
            shred2: shred2.payload().as_ref(),
        };
        (sigverify_data, proof_data.pack_proof())
    }

    #[test]
    fn test_statute_of_limitations() {
        *CLOCK_SLOT.write().unwrap() = SLOT + 5;
        verify_with_clock().unwrap();

        *CLOCK_SLOT.write().unwrap() = SLOT - 1;
        assert_eq!(
            verify_with_clock().unwrap_err(),
            ProgramError::ArithmeticOverflow
        );

        *CLOCK_SLOT.write().unwrap() = SLOT + DEFAULT_SLOTS_PER_EPOCH + 1;
        assert_eq!(
            verify_with_clock().unwrap_err(),
            SlashingError::ExceedsStatuteOfLimitations.into()
        );
    }

    fn verify_with_clock() -> Result<(), ProgramError> {
        struct SyscallStubs {}
        impl solana_sdk::program_stubs::SyscallStubs for SyscallStubs {
            fn sol_get_clock_sysvar(&self, var_addr: *mut u8) -> u64 {
                unsafe {
                    let clock = Clock {
                        slot: *CLOCK_SLOT.read().unwrap(),
                        ..Clock::default()
                    };
                    *(var_addr as *mut _ as *mut Clock) = clock;
                }
                solana_program::entrypoint::SUCCESS
            }

            fn sol_get_epoch_schedule_sysvar(&self, var_addr: *mut u8) -> u64 {
                unsafe {
                    *(var_addr as *mut _ as *mut EpochSchedule) = EpochSchedule::default();
                }
                solana_program::entrypoint::SUCCESS
            }

            fn sol_get_rent_sysvar(&self, var_addr: *mut u8) -> u64 {
                unsafe {
                    *(var_addr as *mut _ as *mut Rent) = Rent::default();
                }
                solana_program::entrypoint::SUCCESS
            }
        }

        solana_sdk::program_stubs::set_syscall_stubs(Box::new(SyscallStubs {}));
        let leader = Arc::new(Keypair::new());
        let (instruction_data, proof_data) = generate_proof_data(leader.clone());
        let mut lamports = 0;
        let (instructions, mut instructions_sysvar_data) =
            construct_instructions_and_sysvar(&instruction_data);
        let instructions_sysvar_account = AccountInfo::new(
            &instructions::ID,
            false,
            true,
            &mut lamports,
            &mut instructions_sysvar_data,
            &instructions::ID,
            false,
            0,
        );
        let (pda, _) =
            get_violation_report_address(&leader.pubkey(), SLOT, ProofType::DuplicateBlockProof);
        let mut pda_lamports = 1_000_000_000;
        let mut pda_data = [0u8; SIZE];
        let owner = id();
        let violation_pda_info = AccountInfo::new(
            &pda,
            false,
            true,
            &mut pda_lamports,
            &mut pda_data,
            &owner,
            false,
            0,
        );
        let mut reporter_lamports = 0;
        let owner = id();
        let reporter = Pubkey::new_unique();
        let proof_account = AccountInfo::new(
            &reporter,
            true,
            true,
            &mut reporter_lamports,
            &mut [],
            &owner,
            false,
            0,
        );

        let accounts = SlashingAccounts {
            proof_account: &proof_account,
            violation_pda_account: &violation_pda_info,
            instructions_sysvar: &instructions_sysvar_account,
            system_program_account: &proof_account,
        };

        let report = ViolationReport {
            version: ViolationReport::VERSION,
            reporter,
            destination: Pubkey::new_unique(),
            epoch: PodEpoch::from(100),
            pubkey: leader.pubkey(),
            slot: PodU64::from(SLOT),
            violation_type: u8::from(ProofType::DuplicateBlockProof),
        };

        verify_proof_data::<DuplicateBlockProofData>(
            report,
            &accounts,
            &proof_data,
            &instructions[2].data,
        )
    }
}
