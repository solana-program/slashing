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
        clock::{Clock, Slot},
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
    spl_pod::{bytemuck::pod_get_packed_len, primitives::PodU64},
    spl_record::{instruction as record, state::RecordData},
    spl_slashing::{
        duplicate_block_proof::DuplicateBlockProofData,
        error::SlashingError,
        id,
        instruction::{duplicate_block_proof_with_sigverify, DuplicateBlockProofInstructionData},
        processor::process_instruction,
        state::ProofType,
    },
    std::sync::Arc,
};

const SLOT: Slot = 53084024;

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

fn slashing_instructions(
    proof_account: &Pubkey,
    slot: Slot,
    node_pubkey: Pubkey,
    shred1: &Shred,
    shred2: &Shred,
) -> [Instruction; 2] {
    let instruction_data = DuplicateBlockProofInstructionData {
        slot: PodU64::from(slot),
        offset: PodU64::from(RecordData::WRITABLE_START_INDEX as u64),
        node_pubkey,
        shred_1_merkle_root: shred1.merkle_root().unwrap(),
        shred_1_signature: (*shred1.signature()).into(),
        shred_2_merkle_root: shred2.merkle_root().unwrap(),
        shred_2_signature: (*shred2.signature()).into(),
    };
    duplicate_block_proof_with_sigverify(proof_account, &instruction_data, 1)
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
            rng.gen(),             // lamports
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
        Some(Hash::new_from_array(rng.gen())),
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

    let mut rng = rand::thread_rng();
    let leader = Arc::new(Keypair::new());
    let (slot, parent_slot, reference_tick, version) = (SLOT, 53084023, 0, 0);
    let shredder = Shredder::new(slot, parent_slot, reference_tick, version).unwrap();
    let next_shred_index = rng.gen_range(0..32_000);
    let shred1 = new_rand_data_shred(&mut rng, next_shred_index, &shredder, &leader, true);
    let shred2 = new_rand_data_shred(&mut rng, next_shred_index, &shredder, &leader, true);

    assert_ne!(
        shred1.merkle_root().unwrap(),
        shred2.merkle_root().unwrap(),
        "Expecting merkle root conflict",
    );

    let duplicate_proof = DuplicateBlockProofData {
        shred1: shred1.payload().as_slice(),
        shred2: shred2.payload().as_slice(),
    };
    let data = duplicate_proof.pack();

    initialize_duplicate_proof_account(&mut context, &authority, &account).await;
    write_proof(&mut context, &authority, &account, &data).await;

    let transaction = Transaction::new_signed_with_payer(
        &slashing_instructions(&account.pubkey(), slot, leader.pubkey(), &shred1, &shred2),
        Some(&context.payer.pubkey()),
        &[&context.payer],
        context.last_blockhash,
    );
    context
        .banks_client
        .process_transaction(transaction)
        .await
        .unwrap();
}

#[tokio::test]
async fn valid_proof_coding() {
    let mut context = program_test().start_with_context().await;
    setup_clock(&mut context).await;

    let authority = Keypair::new();
    let account = Keypair::new();

    let mut rng = rand::thread_rng();
    let leader = Arc::new(Keypair::new());
    let (slot, parent_slot, reference_tick, version) = (SLOT, 53084023, 0, 0);
    let shredder = Shredder::new(slot, parent_slot, reference_tick, version).unwrap();
    let next_shred_index = rng.gen_range(0..32_000);
    let shred1 =
        new_rand_coding_shreds(&mut rng, next_shred_index, 10, &shredder, &leader)[0].clone();
    let shred2 =
        new_rand_coding_shreds(&mut rng, next_shred_index, 10, &shredder, &leader)[1].clone();

    let duplicate_proof = DuplicateBlockProofData {
        shred1: shred1.payload().as_slice(),
        shred2: shred2.payload().as_slice(),
    };
    let data = duplicate_proof.pack();

    initialize_duplicate_proof_account(&mut context, &authority, &account).await;
    write_proof(&mut context, &authority, &account, &data).await;

    let transaction = Transaction::new_signed_with_payer(
        &slashing_instructions(&account.pubkey(), slot, leader.pubkey(), &shred1, &shred2),
        Some(&context.payer.pubkey()),
        &[&context.payer],
        context.last_blockhash,
    );
    context
        .banks_client
        .process_transaction(transaction)
        .await
        .unwrap();
}

#[tokio::test]
async fn invalid_proof_data() {
    let mut context = program_test().start_with_context().await;
    setup_clock(&mut context).await;

    let authority = Keypair::new();
    let account = Keypair::new();

    let mut rng = rand::thread_rng();
    let leader = Arc::new(Keypair::new());
    let (slot, parent_slot, reference_tick, version) = (SLOT, 53084023, 0, 0);
    let shredder = Shredder::new(slot, parent_slot, reference_tick, version).unwrap();
    let next_shred_index = rng.gen_range(0..32_000);
    let shred1 = new_rand_data_shred(&mut rng, next_shred_index, &shredder, &leader, true);
    let shred2 = shred1.clone();

    let duplicate_proof = DuplicateBlockProofData {
        shred1: shred1.payload().as_slice(),
        shred2: shred2.payload().as_slice(),
    };
    let data = duplicate_proof.pack();

    initialize_duplicate_proof_account(&mut context, &authority, &account).await;
    write_proof(&mut context, &authority, &account, &data).await;

    let transaction = Transaction::new_signed_with_payer(
        &slashing_instructions(&account.pubkey(), slot, leader.pubkey(), &shred1, &shred2),
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
    let TransactionError::InstructionError(1, InstructionError::Custom(code)) = err else {
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

    let mut rng = rand::thread_rng();
    let leader = Arc::new(Keypair::new());
    let (slot, parent_slot, reference_tick, version) = (SLOT, 53084023, 0, 0);
    let shredder = Shredder::new(slot, parent_slot, reference_tick, version).unwrap();
    let next_shred_index = rng.gen_range(0..32_000);
    let coding_shreds = new_rand_coding_shreds(&mut rng, next_shred_index, 10, &shredder, &leader);
    let shred1 = coding_shreds[0].clone();
    let shred2 = coding_shreds[1].clone();

    assert!(
        ErasureMeta::check_erasure_consistency(&shred1, &shred2),
        "Expecting no erasure conflict"
    );
    let duplicate_proof = DuplicateBlockProofData {
        shred1: shred1.payload().as_slice(),
        shred2: shred2.payload().as_slice(),
    };
    let data = duplicate_proof.pack();

    initialize_duplicate_proof_account(&mut context, &authority, &account).await;
    write_proof(&mut context, &authority, &account, &data).await;

    let transaction = Transaction::new_signed_with_payer(
        &slashing_instructions(&account.pubkey(), slot, leader.pubkey(), &shred1, &shred2),
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
    let TransactionError::InstructionError(1, InstructionError::Custom(code)) = err else {
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

    let mut rng = rand::thread_rng();
    let leader = Arc::new(Keypair::new());
    let (slot, parent_slot, reference_tick, version) = (SLOT, 53084023, 0, 0);
    let shredder = Shredder::new(slot, parent_slot, reference_tick, version).unwrap();
    let next_shred_index = rng.gen_range(0..32_000);
    let shred1 =
        new_rand_coding_shreds(&mut rng, next_shred_index, 10, &shredder, &leader)[0].clone();
    let shred2 =
        new_rand_coding_shreds(&mut rng, next_shred_index, 10, &shredder, &leader)[1].clone();

    let duplicate_proof = DuplicateBlockProofData {
        shred1: shred1.payload().as_slice(),
        shred2: shred2.payload().as_slice(),
    };
    let data = duplicate_proof.pack();

    initialize_duplicate_proof_account(&mut context, &authority, &account).await;
    write_proof(&mut context, &authority, &account, &data).await;
    // Remove the sigverify
    let instructions =
        [
            slashing_instructions(&account.pubkey(), slot, leader.pubkey(), &shred1, &shred2)[1]
                .clone(),
        ];

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
    let TransactionError::InstructionError(0, InstructionError::Custom(code)) = err else {
        panic!("Invalid error {err:?}");
    };
    let err: SlashingError = SlashingError::decode_custom_error_to_enum(code).unwrap();
    assert_eq!(err, SlashingError::MissingSignatureVerification);

    // Only sigverify one of the shreds
    let mut instructions =
        slashing_instructions(&account.pubkey(), slot, leader.pubkey(), &shred1, &shred2);
    instructions[0].data[0] = 1;

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
    let TransactionError::InstructionError(1, InstructionError::Custom(code)) = err else {
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

    let mut rng = rand::thread_rng();
    let leader = Arc::new(Keypair::new());
    let (slot, parent_slot, reference_tick, version) = (SLOT, 53084023, 0, 0);
    let shredder = Shredder::new(slot, parent_slot, reference_tick, version).unwrap();
    let next_shred_index = rng.gen_range(0..32_000);
    let shred1 =
        new_rand_coding_shreds(&mut rng, next_shred_index, 10, &shredder, &leader)[0].clone();
    let shred2 =
        new_rand_coding_shreds(&mut rng, next_shred_index, 10, &shredder, &leader)[1].clone();

    let duplicate_proof = DuplicateBlockProofData {
        shred1: shred1.payload().as_slice(),
        shred2: shred2.payload().as_slice(),
    };
    let data = duplicate_proof.pack();

    initialize_duplicate_proof_account(&mut context, &authority, &account).await;
    write_proof(&mut context, &authority, &account, &data).await;

    // Replace one of the signature verifications with a random message instead
    let message = Hash::new_unique().to_bytes();
    let signature = <[u8; SIGNATURE_BYTES]>::from(leader.sign_message(&message));
    let mut instructions =
        slashing_instructions(&account.pubkey(), slot, leader.pubkey(), &shred1, &shred2);
    const MESSAGE_START: usize = 1 + 8 + 8 + 32;
    const SIGNATURE_START: usize = MESSAGE_START + HASH_BYTES;
    instructions[1].data[MESSAGE_START..SIGNATURE_START].copy_from_slice(&message);
    instructions[1].data[SIGNATURE_START..SIGNATURE_START + SIGNATURE_BYTES]
        .copy_from_slice(&signature);

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
    let TransactionError::InstructionError(1, InstructionError::Custom(code)) = err else {
        panic!("Invalid error {err:?}");
    };
    let err: SlashingError = SlashingError::decode_custom_error_to_enum(code).unwrap();
    assert_eq!(err, SlashingError::SignatureVerificationMismatch);

    // Put the sigverify data in the sigverify instruction (not allowed currently)
    let mut instructions =
        slashing_instructions(&account.pubkey(), slot, leader.pubkey(), &shred1, &shred2);
    instructions[0].data[SIGNATURE_OFFSETS_START..SIGNATURE_OFFSETS_START + 2]
        .copy_from_slice(&100u16.to_le_bytes());
    instructions[0].data[SIGNATURE_OFFSETS_START + 2..SIGNATURE_OFFSETS_START + 4]
        .copy_from_slice(&0u16.to_le_bytes());
    instructions[0].data.extend_from_slice(&[0; 200]);
    instructions[0].data[100..100 + SIGNATURE_BYTES]
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
    let TransactionError::InstructionError(1, InstructionError::Custom(code)) = err else {
        panic!("Invalid error {err:?}");
    };
    let err: SlashingError = SlashingError::decode_custom_error_to_enum(code).unwrap();
    assert_eq!(err, SlashingError::InvalidSignatureVerification);
}
