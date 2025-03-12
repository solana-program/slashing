#![allow(clippy::arithmetic_side_effects)]

use {
    clap::{ArgMatches, CommandFactory, Parser},
    futures::future::join_all,
    solana_account_decoder::UiAccountEncoding,
    solana_clap_v3_utils::keypair::pubkey_from_source,
    solana_client::rpc_config::{RpcAccountInfoConfig, RpcProgramAccountsConfig},
    solana_ledger::{
        blockstore::Blockstore,
        blockstore_options::{AccessType, BlockstoreOptions},
        shred::layout,
    },
    solana_remote_wallet::remote_wallet::RemoteWalletManager,
    solana_sdk::{
        account::ReadableAccount,
        clock::Slot,
        pubkey::Pubkey,
        signature::{Keypair, Signature, Signer, SIGNATURE_BYTES},
        transaction::Transaction,
    },
    spl_pod::{
        bytemuck::{pod_from_bytes, pod_get_packed_len},
        primitives::PodU64,
    },
    spl_record::state::RecordData,
    solana_slashing_program::{
        duplicate_block_proof::DuplicateBlockProofData,
        get_violation_report_address,
        instruction::{
            close_violation_report, duplicate_block_proof_with_sigverify_and_prefund,
            DuplicateBlockProofInstructionData,
        },
        state::{ProofType, SlashingProofData, ViolationReport},
    },
    std::{path::PathBuf, rc::Rc, sync::Arc, time::Duration},
};

mod config;
use config::*;

mod cli;
use cli::*;

mod output;
use output::*;

// Scan once a day
const DEFAULT_SCAN_INTERVAL_S: u64 = 86400;

macro_rules! get_pubkey_from_source {
    ($command_config:expr,  $matches:expr, $wallet_manager:expr, $field:ident) => {
        $command_config
            .$field
            .map(|source| {
                pubkey_from_source($matches, &source, stringify!($field), $wallet_manager)
            })
            .transpose()
            .map_err(|e| Error::from(e.to_string()))
    };
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let cli = Cli::parse();
    let matches = Cli::command().get_matches();
    let mut wallet_manager = None;

    let command = cli.command.clone();
    let config = Config::new(cli, matches.clone(), &mut wallet_manager).await;

    solana_logger::setup_with_default("solana=info");

    let res = command
        .execute(&config, &matches, &mut wallet_manager)
        .await?;
    println!("{}", res);

    Ok(())
}

pub type CommandResult = Result<String, Error>;

impl Command {
    pub async fn execute(
        self,
        config: &Config,
        matches: &ArgMatches,
        wallet_manager: &mut Option<Rc<RemoteWalletManager>>,
    ) -> CommandResult {
        match self {
            Command::Attach(command_config) => {
                command_attach(config, command_config, matches, wallet_manager).await
            }
            Command::Close(command_config) => {
                command_close(config, command_config, matches, wallet_manager).await
            }
            Command::Display(command_config) => {
                command_display(config, command_config, matches, wallet_manager).await
            }
        }
    }
}

async fn command_attach(
    config: &Config,
    command_config: AttachCli,
    matches: &ArgMatches,
    wallet_manager: &mut Option<Rc<RemoteWalletManager>>,
) -> CommandResult {
    let payer = config.fee_payer()?;
    let reporter = get_pubkey_from_source!(command_config, matches, wallet_manager, reporter)?
        .ok_or(Error::from("Reporter or default signer was not specified"))
        .or(config.default_signer().map(|s| s.pubkey()))?;
    let destination =
        get_pubkey_from_source!(command_config, matches, wallet_manager, destination)?
            .ok_or(Error::from(
                "Destination or default signer was not specified",
            ))
            .or(config.default_signer().map(|s| s.pubkey()))?;

    let ledger_path = PathBuf::from(command_config.ledger);
    let ledger_path = std::fs::canonicalize(&ledger_path).map_err(|err| {
        Error::from(format!(
            "Unable to access ledger path '{}': {}",
            ledger_path.display(),
            err
        ))
    })?;
    let mut starting_slot = command_config.start_slot.unwrap_or(0);
    let mut reported_violations = 0;

    loop {
        println_display(
            config,
            format!("\nChecking duplicate slots from {}", starting_slot),
        );

        let blockstore = Blockstore::open_with_options(
            &ledger_path,
            BlockstoreOptions {
                access_type: AccessType::Secondary,
                ..BlockstoreOptions::default()
            },
        )
        .map_err(|err| {
            Error::from(format!(
                "Unable to open blockstore at {:?}: {:?}",
                ledger_path, err
            ))
        })?;
        let mut closable_proof_accounts = vec![];

        for slot in blockstore.duplicate_slots_iterator(starting_slot)? {
            if slot > command_config.end_slot.unwrap_or(u64::MAX) {
                continue;
            }

            println_display(config, format!("\nDuplicate proof found for slot {}", slot));

            match report_duplicate_block_violation(
                config,
                &blockstore,
                &mut closable_proof_accounts,
                &payer,
                reporter,
                destination,
                slot,
            )
            .await
            {
                Ok(true) => reported_violations += 1,
                Err(e) => eprintln_display(config, format!("Unable to report violation {:?}", e)),
                _ => (),
            }
            starting_slot = slot + 1;
        }

        // Close any proof accounts, regardless of whether the report was successful
        for proof_account in closable_proof_accounts {
            let close_ix = spl_record::instruction::close_account(
                &proof_account.pubkey(),
                &payer.pubkey(),
                &payer.pubkey(),
            );
            let transaction = Transaction::new_signed_with_payer(
                &[close_ix],
                Some(&payer.pubkey()),
                &[payer.clone(), proof_account],
                config.rpc_client.get_latest_blockhash().await?,
            );
            if process_transaction(config, transaction).await?.is_some() {
                println_display(config, "Closed proof account".to_string());
            }
        }

        if !command_config.continuous {
            return Ok(format!("Reported {} violations", reported_violations));
        };
        drop(blockstore);
        std::thread::sleep(Duration::from_secs(
            command_config
                .scan_interval
                .unwrap_or(DEFAULT_SCAN_INTERVAL_S),
        ));
    }
}

async fn report_duplicate_block_violation(
    config: &Config,
    blockstore: &Blockstore,
    closable_proof_accounts: &mut Vec<Arc<Keypair>>,
    payer: &Arc<dyn Signer>,
    reporter: Pubkey,
    destination: Pubkey,
    slot: Slot,
) -> Result<bool, Error> {
    // Check if this violation has already been reported
    let node_pubkey = config.rpc_client.get_slot_leaders(slot, 1).await?[0];
    let (pda, _) = get_violation_report_address(&node_pubkey, slot, ProofType::DuplicateBlockProof);
    if let Some(report_account) = config
        .rpc_client
        .get_account_with_commitment(&pda, config.rpc_client.commitment())
        .await?
        .value
    {
        if !report_account.data.is_empty()
            && solana_slashing_program::check_id(&report_account.owner)
            && ViolationReport::version(report_account.data()) > 0
        {
            println_display(
                config,
                format!(
                    "Duplicate block violation already reported for {} at {}",
                    node_pubkey, slot
                ),
            );
            return Ok(false);
        }
    }

    // Write the proof on chain
    let proof_account = Arc::new(Keypair::new());
    closable_proof_accounts.push(proof_account.clone());
    let proof = blockstore.get_duplicate_slot(slot).ok_or(Error::from(
        "Unable to fetch duplicate proof from blockstore",
    ))?;
    let duplicate_proof = DuplicateBlockProofData {
        shred1: proof.shred1.as_ref(),
        shred2: proof.shred2.as_ref(),
    };
    let proof_data = duplicate_proof.pack_proof();
    initialize_and_write_proof(
        config,
        payer,
        &proof_account,
        ProofType::DuplicateBlockProof,
        &proof_data,
    )
    .await?;

    // Submit the violation to the slashing program
    let shred_1_merkle_root = layout::get_merkle_root(proof.shred1.as_ref()).unwrap();
    let shred_2_merkle_root = layout::get_merkle_root(proof.shred2.as_ref()).unwrap();
    let shred_1_signature = proof.shred1.as_ref()[..SIGNATURE_BYTES].try_into().unwrap();
    let shred_2_signature = proof.shred2.as_ref()[..SIGNATURE_BYTES].try_into().unwrap();

    let instruction_data = DuplicateBlockProofInstructionData {
        offset: PodU64::from(RecordData::WRITABLE_START_INDEX as u64),
        slot: PodU64::from(slot),
        node_pubkey,
        reporter,
        destination,
        shred_1_merkle_root,
        shred_1_signature,
        shred_2_merkle_root,
        shred_2_signature,
    };
    let instructions = duplicate_block_proof_with_sigverify_and_prefund(
        &proof_account.pubkey(),
        &instruction_data,
        Some(&payer.pubkey()),
        &config.rent,
    );
    let transaction = Transaction::new_signed_with_payer(
        &instructions,
        Some(&payer.pubkey()),
        &[payer.as_ref()],
        config.rpc_client.get_latest_blockhash().await?,
    );
    if let Some(_signature) = process_transaction(config, transaction).await? {
        let report_account = config.rpc_client.get_account(&pda).await?;
        let report: &ViolationReport =
            pod_from_bytes(&report_account.data()[..std::mem::size_of::<ViolationReport>()])?;
        println_display(
            config,
            ViolationReportOutput::from_report(pda, report, vec![]).to_string(),
        );
    }

    Ok(true)
}

/// Close a violation report
/// If `report_account` is specified we close the report account, otherwise we
/// close any eligible accounts filtered by `reporter`, `destination`, or
/// `node_pubkey`
async fn command_close(
    config: &Config,
    command_config: CloseCli,
    matches: &ArgMatches,
    wallet_manager: &mut Option<Rc<RemoteWalletManager>>,
) -> CommandResult {
    let epoch = config.rpc_client.get_epoch_info().await?.epoch;
    let report_account =
        get_pubkey_from_source!(command_config, matches, wallet_manager, report_account)?;
    let node_pubkey =
        get_pubkey_from_source!(command_config, matches, wallet_manager, node_pubkey)?;
    let reporter_pubkey =
        get_pubkey_from_source!(command_config, matches, wallet_manager, reporter)?;
    let destination_pubkey =
        get_pubkey_from_source!(command_config, matches, wallet_manager, destination)?;
    let payer = config.fee_payer()?;

    let ignore_filter = |account_pubkey: Pubkey, report: &ViolationReport| {
        report_account
            .map(|pk| pk != account_pubkey)
            .unwrap_or_default()
            || node_pubkey
                .map(|pk| pk != report.pubkey)
                .unwrap_or_default()
            || reporter_pubkey
                .map(|pk| pk != report.reporter)
                .unwrap_or_default()
            || destination_pubkey
                .map(|pk| pk != report.destination)
                .unwrap_or_default()
    };
    let gpa_config = RpcProgramAccountsConfig {
        account_config: RpcAccountInfoConfig {
            encoding: Some(UiAccountEncoding::Base64),
            commitment: Some(config.rpc_client.commitment()),
            ..RpcAccountInfoConfig::default()
        },
        ..RpcProgramAccountsConfig::default()
    };

    let reports = config
        .rpc_client
        .get_program_accounts_with_config(&solana_slashing_program::id(), gpa_config)
        .await?;
    let mut early_reports = 0;

    let mut displays = vec![];
    for (pubkey, report_account) in reports {
        let report: &ViolationReport =
            pod_from_bytes(&report_account.data()[..std::mem::size_of::<ViolationReport>()])?;
        if report.epoch() + 3 > epoch {
            early_reports += 1;
            continue;
        }
        if ignore_filter(pubkey, report) {
            continue;
        }
        let lamports = report_account.lamports;

        let close_ix = close_violation_report(&pubkey, &report.destination);
        let transaction = Transaction::new_signed_with_payer(
            &[close_ix],
            Some(&payer.pubkey()),
            &[payer.as_ref()],
            config.rpc_client.get_latest_blockhash().await?,
        );
        let signature = process_transaction(config, transaction).await?;

        displays.push(CloseReportOutput {
            report_account: pubkey,
            pubkey: report.pubkey,
            reporter: report.reporter,
            destination: report.destination,
            lamports,
            signature,
        });
    }

    Ok(format_output(
        config,
        "Close".to_string(),
        CloseReportOutputList(early_reports, displays),
    ))
}

/// Display violation reports
/// If specified, we filter by `epoch`, `node_pubkey`, and `reporter`
/// If verbose is specified we additionally deserialize the raw proof
async fn command_display(
    config: &Config,
    command_config: DisplayCli,
    matches: &ArgMatches,
    wallet_manager: &mut Option<Rc<RemoteWalletManager>>,
) -> CommandResult {
    let node_pubkey =
        get_pubkey_from_source!(command_config, matches, wallet_manager, node_pubkey)?;
    let reporter_pubkey =
        get_pubkey_from_source!(command_config, matches, wallet_manager, reporter)?;

    let ignore_filter = |report: &ViolationReport| {
        command_config
            .epoch
            .map(|e| e != report.epoch())
            .unwrap_or_default()
            || node_pubkey
                .map(|pk| pk != report.pubkey)
                .unwrap_or_default()
            || reporter_pubkey
                .map(|pk| pk != report.reporter)
                .unwrap_or_default()
    };

    let gpa_config = RpcProgramAccountsConfig {
        account_config: RpcAccountInfoConfig {
            encoding: Some(UiAccountEncoding::Base64),
            commitment: Some(config.rpc_client.commitment()),
            ..RpcAccountInfoConfig::default()
        },
        ..RpcProgramAccountsConfig::default()
    };

    let reports = config
        .rpc_client
        .get_program_accounts_with_config(&solana_slashing_program::id(), gpa_config)
        .await?;

    let mut displays = vec![];
    for (pubkey, report_account) in reports {
        let report: &ViolationReport =
            pod_from_bytes(&report_account.data()[..std::mem::size_of::<ViolationReport>()])?;
        if ignore_filter(report) {
            continue;
        }
        let proof = report_account.data()[std::mem::size_of::<ViolationReport>()..].to_vec();
        displays.push(ViolationReportOutput::from_report(pubkey, report, proof));
    }

    displays.sort_by(|a, b| a.slot.cmp(&b.slot));

    Ok(format_output(
        config,
        "Display".to_string(),
        ViolationReportListOutput(displays),
    ))
}

async fn initialize_and_write_proof(
    config: &Config,
    payer: &Arc<dyn Signer>,
    proof_account: &Keypair,
    proof_type: ProofType,
    proof_data: &[u8],
) -> Result<(), Error> {
    // Initialize account with the record program
    let account_length = proof_type
        .proof_account_length()
        .saturating_add(pod_get_packed_len::<RecordData>());
    let lamports = 1.max(config.rent.minimum_balance(account_length));
    let signers: [&dyn Signer; 2] = [&**payer, proof_account];
    let initialize_ix =
        spl_record::instruction::initialize(&proof_account.pubkey(), &payer.pubkey());
    let transaction = Transaction::new_signed_with_payer(
        &[
            solana_system_interface::instruction::create_account(
                &payer.pubkey(),
                &proof_account.pubkey(),
                lamports,
                account_length as u64,
                &spl_record::id(),
            ),
            initialize_ix,
        ],
        Some(&payer.pubkey()),
        &signers,
        config.rpc_client.get_latest_blockhash().await?,
    );
    if process_transaction(config, transaction).await?.is_some() {
        println_display(
            config,
            format!("Initialized proof account {}", proof_account.pubkey()),
        )
    }

    // Write the proof
    let mut offset = 0;
    let chunk_size = 800;
    let proof_len = proof_data.len();
    let mut writes = vec![];
    while offset < proof_len {
        let end = std::cmp::min(offset.checked_add(chunk_size).unwrap(), proof_len);
        let write_ix = spl_record::instruction::write(
            &proof_account.pubkey(),
            &payer.pubkey(),
            offset as u64,
            &proof_data[offset..end],
        );
        let transaction = Transaction::new_signed_with_payer(
            &[write_ix],
            Some(&payer.pubkey()),
            &[&**payer],
            config.rpc_client.get_latest_blockhash().await?,
        );
        writes.push(process_transaction(config, transaction));
        offset = offset.checked_add(chunk_size).unwrap();
    }
    join_all(writes)
        .await
        .into_iter()
        .collect::<Result<Vec<_>, Error>>()?;

    Ok(())
}

async fn process_transaction(
    config: &Config,
    transaction: Transaction,
) -> Result<Option<Signature>, Error> {
    if config.dry_run {
        let simulation_data = config.rpc_client.simulate_transaction(&transaction).await?;

        if config.verbose() {
            if let Some(logs) = simulation_data.value.logs {
                for log in logs {
                    println!("    {}", log);
                }
            }

            println!(
                "\nSimulation succeeded, consumed {} compute units",
                simulation_data.value.units_consumed.unwrap()
            );
        } else {
            println_display(config, "Simulation succeeded".to_string());
        }

        Ok(None)
    } else {
        Ok(Some(
            config
                .rpc_client
                .send_and_confirm_transaction_with_spinner(&transaction)
                .await?,
        ))
    }
}
