#![cfg(feature = "test-sbf")]

use {
    rand::Rng,
    solana_entry::entry::Entry,
    solana_ledger::{
        blockstore_meta::ErasureMeta,
        shred::{ProcessShredsStats, ReedSolomonCache, Shred, Shredder},
    },
    solana_program::pubkey::Pubkey,
    solana_program_test::*,
    solana_sdk::{
        clock::{Clock, Epoch, Slot, DEFAULT_SLOTS_PER_EPOCH},
        decode_error::DecodeError,
        ed25519_instruction::SIGNATURE_OFFSETS_START,
        hash::{Hash, HASH_BYTES},
        instruction::{Instruction, InstructionError},
        rent::Rent,
        signature::{Keypair, Signer},
        system_instruction, system_transaction,
        transaction::{Transaction, TransactionError},
    },
    solana_signature::SIGNATURE_BYTES,
    spl_pod::{
        bytemuck::{pod_from_bytes, pod_get_packed_len},
        primitives::PodU64,
    },
    spl_record::{instruction as record, state::RecordData},
    spl_slashing::{
        duplicate_block_proof::DuplicateBlockProofData,
        error::SlashingError,
        id,
        instruction::{
            close_violation_report, duplicate_block_proof_with_sigverify_and_prefund,
            DuplicateBlockProofInstructionData,
        },
        processor::process_instruction,
        state::{ProofType, SlashingProofData, ViolationReport},
    },
    std::{assert_ne, sync::Arc},
};

const SLOT: Slot = 53084024;
const EPOCH: Epoch = 42;

fn program_test() -> ProgramTest {
    let mut program_test = ProgramTest::new("spl_slashing", id(), processor!(process_instruction));
    program_test.add_program(
        "spl_record",
        spl_record::id(),
        processor!(spl_record::processor::process_instruction),
    );
    program_test
}

async fn setup_clock(context: &mut ProgramTestContext) {
    let clock: Clock = context.banks_client.get_sysvar().await.unwrap();
    let mut new_clock = clock.clone();
    new_clock.slot = SLOT;
    new_clock.epoch = EPOCH;
    context.set_sysvar(&new_clock);
}

async fn increment_clock_epoch(context: &mut ProgramTestContext, increment: Epoch) {
    let clock: Clock = context.banks_client.get_sysvar().await.unwrap();
    let mut new_clock = clock.clone();
    new_clock.slot = new_clock
        .slot
        .saturating_add(increment.saturating_mul(DEFAULT_SLOTS_PER_EPOCH));
    new_clock.epoch = new_clock.epoch.saturating_add(increment);
    context.set_sysvar(&new_clock);
}

async fn initialize_duplicate_proof_account(
    context: &mut ProgramTestContext,
    authority: &Keypair,
    account: &Keypair,
) {
    let account_length = ProofType::DuplicateBlockProof
        .proof_account_length()
        .saturating_add(pod_get_packed_len::<RecordData>());
    println!("Creating account of size {account_length}");
    let transaction = Transaction::new_signed_with_payer(
        &[
            system_instruction::create_account(
                &context.payer.pubkey(),
                &account.pubkey(),
                1.max(Rent::default().minimum_balance(account_length)),
                account_length as u64,
                &spl_record::id(),
            ),
            record::initialize(&account.pubkey(), &authority.pubkey()),
        ],
        Some(&context.payer.pubkey()),
        &[&context.payer, account],
        context.last_blockhash,
    );
    context
        .banks_client
        .process_transaction(transaction)
        .await
        .unwrap();
}

async fn write_proof(
    context: &mut ProgramTestContext,
    authority: &Keypair,
    account: &Keypair,
    proof: &[u8],
) {
    let mut offset = 0;
    let proof_len = proof.len();
    let chunk_size = 800;
    println!("Writing a proof of size {proof_len}");
    while offset < proof_len {
        let end = std::cmp::min(offset.checked_add(chunk_size).unwrap(), proof_len);
        let transaction = Transaction::new_signed_with_payer(
            &[record::write(
                &account.pubkey(),
                &authority.pubkey(),
                offset as u64,
                &proof[offset..end],
            )],
            Some(&context.payer.pubkey()),
            &[&context.payer, authority],
            context.last_blockhash,
        );
        context
            .banks_client
            .process_transaction(transaction)
            .await
            .unwrap();

        offset = offset.checked_add(chunk_size).unwrap();
    }
}

async fn close_report(
    context: &mut ProgramTestContext,
    report_key: Pubkey,
    destination: Pubkey,
    increment: Epoch,
) -> Result<(), BanksClientError> {
    increment_clock_epoch(context, increment).await;
    let initial_lamports = context
        .banks_client
        .get_account(report_key)
        .await
        .unwrap()
        .unwrap()
        .lamports;
    assert!(context
        .banks_client
        .get_account(destination)
        .await
        .unwrap()
        .is_none());

    let transaction = Transaction::new_signed_with_payer(
        &[close_violation_report(&report_key, &destination)],
        Some(&context.payer.pubkey()),
        &[&context.payer],
        context.last_blockhash,
    );

    context
        .banks_client
        .simulate_transaction(transaction.clone())
        .await?
        .result
        .unwrap()?;
    context
        .banks_client
        .process_transaction(transaction)
        .await?;

    let new_lamports = context
        .banks_client
        .get_account(destination)
        .await
        .unwrap()
        .unwrap()
        .lamports;

    assert!(context
        .banks_client
        .get_account(report_key)
        .await
        .unwrap()
        .is_none());
    assert_eq!(new_lamports, initial_lamports);

    Ok(())
}

fn slashing_instructions(
    reporter: &Pubkey,
    destination: &Pubkey,
    proof_account: &Pubkey,
    slot: Slot,
    node_pubkey: Pubkey,
    shred1: &Shred,
    shred2: &Shred,
) -> [Instruction; 3] {
    let instruction_data = DuplicateBlockProofInstructionData {
        offset: PodU64::from(RecordData::WRITABLE_START_INDEX as u64),
        slot: PodU64::from(slot),
        node_pubkey,
        reporter: *reporter,
        destination: *destination,
        shred_1_merkle_root: shred1.merkle_root().unwrap(),
        shred_1_signature: (*shred1.signature()).into(),
        shred_2_merkle_root: shred2.merkle_root().unwrap(),
        shred_2_signature: (*shred2.signature()).into(),
    };
    duplicate_block_proof_with_sigverify_and_prefund(
        proof_account,
        &instruction_data,
        &Rent::default(),
    )
}

pub fn new_rand_data_shred<R: Rng>(
    rng: &mut R,
    next_shred_index: u32,
    shredder: &Shredder,
    keypair: &Keypair,
    is_last_in_slot: bool,
) -> Shred {
    let (mut data_shreds, _) = new_rand_shreds(
        rng,
        next_shred_index,
        next_shred_index,
        5,
        shredder,
        keypair,
        is_last_in_slot,
    );
    data_shreds.pop().unwrap()
}

pub(crate) fn new_rand_coding_shreds<R: Rng>(
    rng: &mut R,
    next_shred_index: u32,
    num_entries: usize,
    shredder: &Shredder,
    keypair: &Keypair,
) -> Vec<Shred> {
    let (_, coding_shreds) = new_rand_shreds(
        rng,
        next_shred_index,
        next_shred_index,
        num_entries,
        shredder,
        keypair,
        true,
    );
    coding_shreds
}

pub(crate) fn new_rand_shreds<R: Rng>(
    rng: &mut R,
    next_shred_index: u32,
    next_code_index: u32,
    num_entries: usize,
    shredder: &Shredder,
    keypair: &Keypair,
    is_last_in_slot: bool,
) -> (Vec<Shred>, Vec<Shred>) {
    let entries: Vec<_> = std::iter::repeat_with(|| {
        let tx = system_transaction::transfer(
            &Keypair::new(),       // from
            &Pubkey::new_unique(), // to
            rng.random(),          // lamports
            Hash::new_unique(),    // recent blockhash
        );
        Entry::new(
            &Hash::new_unique(), // prev_hash
            1,                   // num_hashes,
            vec![tx],            // transactions
        )
    })
    .take(num_entries)
    .collect();
    shredder.entries_to_shreds(
        keypair,
        &entries,
        is_last_in_slot,
        // chained_merkle_root
        Some(Hash::new_from_array(rng.random())),
        next_shred_index,
        next_code_index, // next_code_index
        true,            // merkle_variant
        &ReedSolomonCache::default(),
        &mut ProcessShredsStats::default(),
    )
}

#[tokio::test]
async fn valid_proof_data() {
    let mut context = program_test().start_with_context().await;
    setup_clock(&mut context).await;

    let authority = Keypair::new();
    let account = Keypair::new();
    let reporter = context.payer.pubkey();
    let destination = Pubkey::new_unique();

    let mut rng = rand::rng();
    let leader = Arc::new(Keypair::new());
    let (slot, parent_slot, reference_tick, version) = (SLOT, 53084023, 0, 0);
    let shredder = Shredder::new(slot, parent_slot, reference_tick, version).unwrap();
    let next_shred_index = rng.random_range(0..32_000);
    let shred1 = new_rand_data_shred(&mut rng, next_shred_index, &shredder, &leader, true);
    let shred2 = new_rand_data_shred(&mut rng, next_shred_index, &shredder, &leader, true);

    assert_ne!(
        shred1.merkle_root().unwrap(),
        shred2.merkle_root().unwrap(),
        "Expecting merkle root conflict",
    );

    let duplicate_proof = DuplicateBlockProofData {
        shred1: shred1.payload().as_ref(),
        shred2: shred2.payload().as_ref(),
    };
    let data = duplicate_proof.pack_proof();

    initialize_duplicate_proof_account(&mut context, &authority, &account).await;
    write_proof(&mut context, &authority, &account, &data).await;

    let transaction = Transaction::new_signed_with_payer(
        &slashing_instructions(
            &reporter,
            &destination,
            &account.pubkey(),
            slot,
            leader.pubkey(),
            &shred1,
            &shred2,
        ),
        Some(&context.payer.pubkey()),
        &[&context.payer],
        context.last_blockhash,
    );
    context
        .banks_client
        .process_transaction(transaction)
        .await
        .unwrap();

    // Verify that the report was written
    let (report_key, _) = Pubkey::find_program_address(
        &[
            &leader.pubkey().to_bytes(),
            &slot.to_le_bytes(),
            &[u8::from(ProofType::DuplicateBlockProof)],
        ],
        &spl_slashing::id(),
    );
    let report_account = context
        .banks_client
        .get_account(report_key)
        .await
        .unwrap()
        .unwrap();
    let violation_report_size = std::mem::size_of::<ViolationReport>();
    let violation_report: &ViolationReport =
        pod_from_bytes(&report_account.data[0..violation_report_size]).unwrap();
    let expected_violation_report = ViolationReport {
        version: ViolationReport::VERSION,
        reporter,
        destination,
        epoch: PodU64::from(EPOCH),
        pubkey: leader.pubkey(),
        slot: PodU64::from(slot),
        violation_type: ProofType::DuplicateBlockProof.into(),
        proof_account: account.pubkey(),
    };
    assert_eq!(*violation_report, expected_violation_report);

    // Verify that the proof was also serialized to the account
    let proof =
        DuplicateBlockProofData::unpack_proof(&report_account.data[violation_report_size..])
            .unwrap();
    assert_eq!(duplicate_proof, proof);

    // Close the report
    close_report(&mut context, report_key, destination, 3)
        .await
        .unwrap();
}

#[tokio::test]
async fn valid_proof_coding() {
    let mut context = program_test().start_with_context().await;
    setup_clock(&mut context).await;

    let authority = Keypair::new();
    let account = Keypair::new();
    let reporter = context.payer.pubkey();
    let destination = Pubkey::new_unique();

    let mut rng = rand::rng();
    let leader = Arc::new(Keypair::new());
    let (slot, parent_slot, reference_tick, version) = (SLOT, 53084023, 0, 0);
    let shredder = Shredder::new(slot, parent_slot, reference_tick, version).unwrap();
    let next_shred_index = rng.random_range(0..32_000);
    let shred1 =
        new_rand_coding_shreds(&mut rng, next_shred_index, 10, &shredder, &leader)[0].clone();
    let shred2 =
        new_rand_coding_shreds(&mut rng, next_shred_index, 10, &shredder, &leader)[1].clone();

    assert_ne!(
        shred1.merkle_root().unwrap(),
        shred2.merkle_root().unwrap(),
        "Expected merkle root failure"
    );

    let duplicate_proof = DuplicateBlockProofData {
        shred1: shred1.payload().as_ref(),
        shred2: shred2.payload().as_ref(),
    };
    let data = duplicate_proof.pack_proof();

    initialize_duplicate_proof_account(&mut context, &authority, &account).await;
    write_proof(&mut context, &authority, &account, &data).await;

    let transaction = Transaction::new_signed_with_payer(
        &slashing_instructions(
            &reporter,
            &destination,
            &account.pubkey(),
            slot,
            leader.pubkey(),
            &shred1,
            &shred2,
        ),
        Some(&context.payer.pubkey()),
        &[&context.payer],
        context.last_blockhash,
    );
    context
        .banks_client
        .process_transaction(transaction)
        .await
        .unwrap();

    // Verify that the report was written
    let (report_key, _) = Pubkey::find_program_address(
        &[
            &leader.pubkey().to_bytes(),
            &slot.to_le_bytes(),
            &[u8::from(ProofType::DuplicateBlockProof)],
        ],
        &spl_slashing::id(),
    );
    let report_account = context
        .banks_client
        .get_account(report_key)
        .await
        .unwrap()
        .unwrap();
    let violation_report_size = std::mem::size_of::<ViolationReport>();
    let violation_report: &ViolationReport =
        pod_from_bytes(&report_account.data[0..violation_report_size]).unwrap();

    let expected_violation_report = ViolationReport {
        version: ViolationReport::VERSION,
        reporter,
        destination,
        epoch: PodU64::from(EPOCH),
        pubkey: leader.pubkey(),
        slot: PodU64::from(slot),
        violation_type: ProofType::DuplicateBlockProof.into(),
        proof_account: account.pubkey(),
    };
    assert_eq!(*violation_report, expected_violation_report);

    // Verify that the proof was also serialized to the account
    let proof =
        DuplicateBlockProofData::unpack_proof(&report_account.data[violation_report_size..])
            .unwrap();
    assert_eq!(duplicate_proof, proof);

    // Close the report
    close_report(&mut context, report_key, destination, 3)
        .await
        .unwrap();
}

#[tokio::test]
async fn invalid_proof_data() {
    let mut context = program_test().start_with_context().await;
    setup_clock(&mut context).await;

    let authority = Keypair::new();
    let account = Keypair::new();
    let reporter = context.payer.pubkey();
    let destination = Pubkey::new_unique();

    let mut rng = rand::rng();
    let leader = Arc::new(Keypair::new());
    let (slot, parent_slot, reference_tick, version) = (SLOT, 53084023, 0, 0);
    let shredder = Shredder::new(slot, parent_slot, reference_tick, version).unwrap();
    let next_shred_index = rng.random_range(0..32_000);
    let shred1 = new_rand_data_shred(&mut rng, next_shred_index, &shredder, &leader, true);
    let shred2 = shred1.clone();

    let duplicate_proof = DuplicateBlockProofData {
        shred1: shred1.payload().as_ref(),
        shred2: shred2.payload().as_ref(),
    };
    let data = duplicate_proof.pack_proof();

    initialize_duplicate_proof_account(&mut context, &authority, &account).await;
    write_proof(&mut context, &authority, &account, &data).await;

    let transaction = Transaction::new_signed_with_payer(
        &slashing_instructions(
            &reporter,
            &destination,
            &account.pubkey(),
            slot,
            leader.pubkey(),
            &shred1,
            &shred2,
        ),
        Some(&context.payer.pubkey()),
        &[&context.payer],
        context.last_blockhash,
    );
    let err = context
        .banks_client
        .process_transaction(transaction)
        .await
        .unwrap_err()
        .unwrap();
    let TransactionError::InstructionError(2, InstructionError::Custom(code)) = err else {
        panic!("Invalid error {err:?}");
    };
    let err: SlashingError = SlashingError::decode_custom_error_to_enum(code).unwrap();
    assert_eq!(err, SlashingError::InvalidPayloadProof);
}

#[tokio::test]
async fn invalid_proof_coding() {
    let mut context = program_test().start_with_context().await;
    setup_clock(&mut context).await;

    let authority = Keypair::new();
    let account = Keypair::new();
    let reporter = context.payer.pubkey();
    let destination = Pubkey::new_unique();

    let mut rng = rand::rng();
    let leader = Arc::new(Keypair::new());
    let (slot, parent_slot, reference_tick, version) = (SLOT, 53084023, 0, 0);
    let shredder = Shredder::new(slot, parent_slot, reference_tick, version).unwrap();
    let next_shred_index = rng.random_range(0..32_000);
    let coding_shreds = new_rand_coding_shreds(&mut rng, next_shred_index, 10, &shredder, &leader);
    let shred1 = coding_shreds[0].clone();
    let shred2 = coding_shreds[1].clone();

    assert!(
        ErasureMeta::check_erasure_consistency(&shred1, &shred2),
        "Expecting no erasure conflict"
    );
    let duplicate_proof = DuplicateBlockProofData {
        shred1: shred1.payload().as_ref(),
        shred2: shred2.payload().as_ref(),
    };
    let data = duplicate_proof.pack_proof();

    initialize_duplicate_proof_account(&mut context, &authority, &account).await;
    write_proof(&mut context, &authority, &account, &data).await;

    let transaction = Transaction::new_signed_with_payer(
        &slashing_instructions(
            &reporter,
            &destination,
            &account.pubkey(),
            slot,
            leader.pubkey(),
            &shred1,
            &shred2,
        ),
        Some(&context.payer.pubkey()),
        &[&context.payer],
        context.last_blockhash,
    );
    let err = context
        .banks_client
        .process_transaction(transaction)
        .await
        .unwrap_err()
        .unwrap();
    let TransactionError::InstructionError(2, InstructionError::Custom(code)) = err else {
        panic!("Invalid error {err:?}");
    };
    let err: SlashingError = SlashingError::decode_custom_error_to_enum(code).unwrap();
    assert_eq!(err, SlashingError::InvalidErasureMetaConflict);
}

#[tokio::test]
async fn missing_sigverify() {
    let mut context = program_test().start_with_context().await;
    setup_clock(&mut context).await;

    let authority = Keypair::new();
    let account = Keypair::new();
    let reporter = context.payer.pubkey();
    let destination = Pubkey::new_unique();

    let mut rng = rand::rng();
    let leader = Arc::new(Keypair::new());
    let (slot, parent_slot, reference_tick, version) = (SLOT, 53084023, 0, 0);
    let shredder = Shredder::new(slot, parent_slot, reference_tick, version).unwrap();
    let next_shred_index = rng.random_range(0..32_000);
    let shred1 =
        new_rand_coding_shreds(&mut rng, next_shred_index, 10, &shredder, &leader)[0].clone();
    let shred2 =
        new_rand_coding_shreds(&mut rng, next_shred_index, 10, &shredder, &leader)[1].clone();

    let duplicate_proof = DuplicateBlockProofData {
        shred1: shred1.payload().as_ref(),
        shred2: shred2.payload().as_ref(),
    };
    let data = duplicate_proof.pack_proof();

    initialize_duplicate_proof_account(&mut context, &authority, &account).await;
    write_proof(&mut context, &authority, &account, &data).await;
    // Remove the sigverify
    let instructions = [slashing_instructions(
        &reporter,
        &destination,
        &account.pubkey(),
        slot,
        leader.pubkey(),
        &shred1,
        &shred2,
    )[2]
    .clone()];

    let transaction = Transaction::new_signed_with_payer(
        &instructions,
        Some(&context.payer.pubkey()),
        &[&context.payer],
        context.last_blockhash,
    );
    let err = context
        .banks_client
        .simulate_transaction(transaction)
        .await
        .unwrap()
        .result
        .unwrap()
        .unwrap_err();
    let TransactionError::InstructionError(0, InstructionError::Custom(code)) = err else {
        panic!("Invalid error {err:?}");
    };
    let err: SlashingError = SlashingError::decode_custom_error_to_enum(code).unwrap();
    assert_eq!(err, SlashingError::MissingSignatureVerification);

    // Only sigverify one of the shreds
    let mut instructions = slashing_instructions(
        &reporter,
        &destination,
        &account.pubkey(),
        slot,
        leader.pubkey(),
        &shred1,
        &shred2,
    );
    instructions[1].data[0] = 1;

    let transaction = Transaction::new_signed_with_payer(
        &instructions,
        Some(&context.payer.pubkey()),
        &[&context.payer],
        context.last_blockhash,
    );
    let err = context
        .banks_client
        .process_transaction(transaction)
        .await
        .unwrap_err()
        .unwrap();
    let TransactionError::InstructionError(2, InstructionError::Custom(code)) = err else {
        panic!("Invalid error {err:?}");
    };
    let err: SlashingError = SlashingError::decode_custom_error_to_enum(code).unwrap();
    assert_eq!(err, SlashingError::MissingSignatureVerification);
}

#[tokio::test]
async fn improper_sigverify() {
    let mut context = program_test().start_with_context().await;
    setup_clock(&mut context).await;

    let authority = Keypair::new();
    let account = Keypair::new();
    let reporter = context.payer.pubkey();
    let destination = Pubkey::new_unique();

    let mut rng = rand::rng();
    let leader = Arc::new(Keypair::new());
    let (slot, parent_slot, reference_tick, version) = (SLOT, 53084023, 0, 0);
    let shredder = Shredder::new(slot, parent_slot, reference_tick, version).unwrap();
    let next_shred_index = rng.random_range(0..32_000);
    let shred1 =
        new_rand_coding_shreds(&mut rng, next_shred_index, 10, &shredder, &leader)[0].clone();
    let shred2 =
        new_rand_coding_shreds(&mut rng, next_shred_index, 10, &shredder, &leader)[1].clone();

    let duplicate_proof = DuplicateBlockProofData {
        shred1: shred1.payload().as_ref(),
        shred2: shred2.payload().as_ref(),
    };
    let data = duplicate_proof.pack_proof();

    initialize_duplicate_proof_account(&mut context, &authority, &account).await;
    write_proof(&mut context, &authority, &account, &data).await;

    // Replace one of the signature verifications with a random message instead
    let message = Hash::new_unique().to_bytes();
    let signature = <[u8; SIGNATURE_BYTES]>::from(leader.sign_message(&message));
    let mut instructions = slashing_instructions(
        &reporter,
        &destination,
        &account.pubkey(),
        slot,
        leader.pubkey(),
        &shred1,
        &shred2,
    );
    const MESSAGE_START: usize = DuplicateBlockProofInstructionData::sigverify_data_offset();
    const SIGNATURE_START: usize = MESSAGE_START + HASH_BYTES;
    instructions[2].data[MESSAGE_START..SIGNATURE_START].copy_from_slice(&message);
    instructions[2].data[SIGNATURE_START..SIGNATURE_START + SIGNATURE_BYTES]
        .copy_from_slice(&signature);

    let transaction = Transaction::new_signed_with_payer(
        &instructions,
        Some(&context.payer.pubkey()),
        &[&context.payer],
        context.last_blockhash,
    );
    let err = context
        .banks_client
        .simulate_transaction(transaction)
        .await
        .unwrap()
        .result
        .unwrap()
        .unwrap_err();
    let TransactionError::InstructionError(2, InstructionError::Custom(code)) = err else {
        panic!("Invalid error {err:?}");
    };
    let err: SlashingError = SlashingError::decode_custom_error_to_enum(code).unwrap();
    assert_eq!(err, SlashingError::SignatureVerificationMismatch);

    // Put the sigverify data in the sigverify instruction (not allowed currently)
    let mut instructions = slashing_instructions(
        &reporter,
        &destination,
        &account.pubkey(),
        slot,
        leader.pubkey(),
        &shred1,
        &shred2,
    );
    instructions[1].data[SIGNATURE_OFFSETS_START..SIGNATURE_OFFSETS_START + 2]
        .copy_from_slice(&100u16.to_le_bytes());
    instructions[1].data[SIGNATURE_OFFSETS_START + 2..SIGNATURE_OFFSETS_START + 4]
        .copy_from_slice(&1u16.to_le_bytes());
    instructions[1].data.extend_from_slice(&[0; 200]);
    instructions[1].data[100..100 + SIGNATURE_BYTES]
        .copy_from_slice(&<[u8; SIGNATURE_BYTES]>::from(*shred1.signature()));
    let transaction = Transaction::new_signed_with_payer(
        &instructions,
        Some(&context.payer.pubkey()),
        &[&context.payer],
        context.last_blockhash,
    );
    let err = context
        .banks_client
        .process_transaction(transaction)
        .await
        .unwrap_err()
        .unwrap();
    let TransactionError::InstructionError(2, InstructionError::Custom(code)) = err else {
        panic!("Invalid error {err:?}");
    };
    let err: SlashingError = SlashingError::decode_custom_error_to_enum(code).unwrap();
    assert_eq!(err, SlashingError::InvalidSignatureVerification);
}

#[tokio::test]
async fn double_report() {
    let mut context = program_test().start_with_context().await;
    setup_clock(&mut context).await;

    let authority = Keypair::new();
    let account = Keypair::new();
    let reporter = context.payer.pubkey();
    let destination = Pubkey::new_unique();

    let mut rng = rand::rng();
    let leader = Arc::new(Keypair::new());
    let (slot, parent_slot, reference_tick, version) = (SLOT, 53084023, 0, 0);
    let shredder = Shredder::new(slot, parent_slot, reference_tick, version).unwrap();
    let next_shred_index = rng.random_range(0..32_000);
    let shred1 = new_rand_data_shred(&mut rng, next_shred_index, &shredder, &leader, true);
    let shred2 = new_rand_data_shred(&mut rng, next_shred_index, &shredder, &leader, true);

    assert_ne!(
        shred1.merkle_root().unwrap(),
        shred2.merkle_root().unwrap(),
        "Expecting merkle root conflict",
    );

    let duplicate_proof = DuplicateBlockProofData {
        shred1: shred1.payload().as_ref(),
        shred2: shred2.payload().as_ref(),
    };
    let data = duplicate_proof.pack_proof();

    initialize_duplicate_proof_account(&mut context, &authority, &account).await;
    write_proof(&mut context, &authority, &account, &data).await;

    let transaction = Transaction::new_signed_with_payer(
        &slashing_instructions(
            &reporter,
            &destination,
            &account.pubkey(),
            slot,
            leader.pubkey(),
            &shred1,
            &shred2,
        ),
        Some(&context.payer.pubkey()),
        &[&context.payer],
        context.last_blockhash,
    );
    context
        .banks_client
        .process_transaction(transaction)
        .await
        .unwrap();

    // Verify that the report was written
    let (report_account, _) = Pubkey::find_program_address(
        &[
            &leader.pubkey().to_bytes(),
            &slot.to_le_bytes(),
            &[u8::from(ProofType::DuplicateBlockProof)],
        ],
        &spl_slashing::id(),
    );
    let report_account = context
        .banks_client
        .get_account(report_account)
        .await
        .unwrap()
        .unwrap();
    let violation_report_size = std::mem::size_of::<ViolationReport>();
    let violation_report: &ViolationReport =
        pod_from_bytes(&report_account.data[0..violation_report_size]).unwrap();

    let expected_violation_report = ViolationReport {
        version: ViolationReport::VERSION,
        reporter,
        destination,
        epoch: PodU64::from(EPOCH),
        pubkey: leader.pubkey(),
        slot: PodU64::from(slot),
        violation_type: ProofType::DuplicateBlockProof.into(),
        proof_account: account.pubkey(),
    };
    assert_eq!(*violation_report, expected_violation_report);

    // Verify that the proof was also serialized to the account
    let proof =
        DuplicateBlockProofData::unpack_proof(&report_account.data[violation_report_size..])
            .unwrap();
    assert_eq!(duplicate_proof, proof);

    // Setup the new reporter
    let new_reporter = Keypair::new();
    let transaction = Transaction::new_signed_with_payer(
        &[system_instruction::transfer(
            &context.payer.pubkey(),
            &new_reporter.pubkey(),
            1_000_000_000,
        )],
        Some(&context.payer.pubkey()),
        &[&context.payer],
        context.last_blockhash,
    );
    context
        .banks_client
        .process_transaction(transaction)
        .await
        .unwrap();

    // Report the violation again but use the new reporter
    let transaction = Transaction::new_signed_with_payer(
        &slashing_instructions(
            &new_reporter.pubkey(),
            &Pubkey::new_unique(),
            &account.pubkey(),
            slot,
            leader.pubkey(),
            &shred1,
            &shred2,
        ),
        Some(&context.payer.pubkey()),
        &[&context.payer, &new_reporter],
        context.last_blockhash,
    );
    let err = context
        .banks_client
        .process_transaction(transaction)
        .await
        .unwrap_err()
        .unwrap();
    let TransactionError::InstructionError(2, InstructionError::Custom(code)) = err else {
        panic!("Invalid error {err:?}");
    };
    let err: SlashingError = SlashingError::decode_custom_error_to_enum(code).unwrap();
    assert_eq!(err, SlashingError::DuplicateReport);

    // Verify that the report was not rewritten
    let (report_account, _) = Pubkey::find_program_address(
        &[
            &leader.pubkey().to_bytes(),
            &slot.to_le_bytes(),
            &[u8::from(ProofType::DuplicateBlockProof)],
        ],
        &spl_slashing::id(),
    );
    let report_account = context
        .banks_client
        .get_account(report_account)
        .await
        .unwrap()
        .unwrap();
    let violation_report_size = std::mem::size_of::<ViolationReport>();
    let violation_report: &ViolationReport =
        pod_from_bytes(&report_account.data[0..violation_report_size]).unwrap();

    assert_eq!(*violation_report, expected_violation_report);
}

#[tokio::test]
async fn close_report_destination_and_early() {
    let mut context = program_test().start_with_context().await;
    setup_clock(&mut context).await;

    let authority = Keypair::new();
    let account = Keypair::new();
    let reporter = context.payer.pubkey();
    let destination = Pubkey::new_unique();

    let mut rng = rand::rng();
    let leader = Arc::new(Keypair::new());
    let (slot, parent_slot, reference_tick, version) = (SLOT, 53084023, 0, 0);
    let shredder = Shredder::new(slot, parent_slot, reference_tick, version).unwrap();
    let next_shred_index = rng.random_range(0..32_000);
    let shred1 = new_rand_data_shred(&mut rng, next_shred_index, &shredder, &leader, true);
    let shred2 = new_rand_data_shred(&mut rng, next_shred_index, &shredder, &leader, true);

    assert_ne!(
        shred1.merkle_root().unwrap(),
        shred2.merkle_root().unwrap(),
        "Expecting merkle root conflict",
    );

    let duplicate_proof = DuplicateBlockProofData {
        shred1: shred1.payload().as_ref(),
        shred2: shred2.payload().as_ref(),
    };
    let data = duplicate_proof.pack_proof();

    initialize_duplicate_proof_account(&mut context, &authority, &account).await;
    write_proof(&mut context, &authority, &account, &data).await;

    let (report_key, _) = Pubkey::find_program_address(
        &[
            &leader.pubkey().to_bytes(),
            &slot.to_le_bytes(),
            &[u8::from(ProofType::DuplicateBlockProof)],
        ],
        &spl_slashing::id(),
    );

    // Trying to create an account with the destination set to the report account
    // should fail
    let transaction = Transaction::new_signed_with_payer(
        &slashing_instructions(
            &reporter,
            &report_key,
            &account.pubkey(),
            slot,
            leader.pubkey(),
            &shred1,
            &shred2,
        ),
        Some(&context.payer.pubkey()),
        &[&context.payer],
        context.last_blockhash,
    );
    let err = context
        .banks_client
        .process_transaction(transaction)
        .await
        .unwrap_err()
        .unwrap();
    let TransactionError::InstructionError(2, InstructionError::Custom(code)) = err else {
        panic!("Invalid error {err:?}");
    };
    let err: SlashingError = SlashingError::decode_custom_error_to_enum(code).unwrap();
    assert_eq!(err, SlashingError::DestinationAddressIsReportAccount);

    // Use a proper destination account
    let transaction = Transaction::new_signed_with_payer(
        &slashing_instructions(
            &reporter,
            &destination,
            &account.pubkey(),
            slot,
            leader.pubkey(),
            &shred1,
            &shred2,
        ),
        Some(&context.payer.pubkey()),
        &[&context.payer],
        context.last_blockhash,
    );
    context
        .banks_client
        .process_transaction(transaction)
        .await
        .unwrap();

    // Verify that the report was written
    let report_account = context
        .banks_client
        .get_account(report_key)
        .await
        .unwrap()
        .unwrap();
    let violation_report_size = std::mem::size_of::<ViolationReport>();
    let violation_report: &ViolationReport =
        pod_from_bytes(&report_account.data[0..violation_report_size]).unwrap();

    let expected_violation_report = ViolationReport {
        version: ViolationReport::VERSION,
        reporter,
        destination,
        epoch: PodU64::from(EPOCH),
        pubkey: leader.pubkey(),
        slot: PodU64::from(slot),
        violation_type: ProofType::DuplicateBlockProof.into(),
        proof_account: account.pubkey(),
    };
    assert_eq!(*violation_report, expected_violation_report);

    // Verify that the proof was also serialized to the account
    let proof =
        DuplicateBlockProofData::unpack_proof(&report_account.data[violation_report_size..])
            .unwrap();
    assert_eq!(duplicate_proof, proof);

    // Close the report should fail as only 0 epochs have passed
    let err = close_report(&mut context, report_key, destination, 0)
        .await
        .unwrap_err()
        .unwrap();
    let TransactionError::InstructionError(0, InstructionError::Custom(code)) = err else {
        panic!("Invalid error {err:?}");
    };
    let err: SlashingError = SlashingError::decode_custom_error_to_enum(code).unwrap();
    assert_eq!(err, SlashingError::CloseViolationReportTooSoon);

    // Close the report should fail as only 1 epochs have passed
    setup_clock(&mut context).await;
    let err = close_report(&mut context, report_key, destination, 1)
        .await
        .unwrap_err()
        .unwrap();
    let TransactionError::InstructionError(0, InstructionError::Custom(code)) = err else {
        panic!("Invalid error {err:?}");
    };
    let err: SlashingError = SlashingError::decode_custom_error_to_enum(code).unwrap();
    assert_eq!(err, SlashingError::CloseViolationReportTooSoon);

    // Close the report should fail as only 2 epochs have passed
    setup_clock(&mut context).await;
    let err = close_report(&mut context, report_key, destination, 2)
        .await
        .unwrap_err()
        .unwrap();
    let TransactionError::InstructionError(0, InstructionError::Custom(code)) = err else {
        panic!("Invalid error {err:?}");
    };
    let err: SlashingError = SlashingError::decode_custom_error_to_enum(code).unwrap();
    assert_eq!(err, SlashingError::CloseViolationReportTooSoon);

    // Close report should fail with invalid destination account
    setup_clock(&mut context).await;
    let err = close_report(&mut context, report_key, Pubkey::new_unique(), 3)
        .await
        .unwrap_err()
        .unwrap();
    let TransactionError::InstructionError(0, InstructionError::Custom(code)) = err else {
        panic!("Invalid error {err:?}");
    };
    let err: SlashingError = SlashingError::decode_custom_error_to_enum(code).unwrap();
    assert_eq!(err, SlashingError::InvalidDestinationAccount);

    // Close report should succeed with 3+ epochs
    setup_clock(&mut context).await;
    close_report(&mut context, report_key, destination, 3)
        .await
        .unwrap()
}
