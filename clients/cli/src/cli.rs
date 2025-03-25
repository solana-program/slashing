use {
    clap::{
        builder::{PossibleValuesParser, TypedValueParser, ValueParser},
        Args, Parser, Subcommand,
    },
    lazy_static::lazy_static,
    solana_clap_v3_utils::input_parsers::{
        parse_url_or_moniker,
        signer::{SignerSource, SignerSourceParserBuilder},
    },
    solana_cli_output::OutputFormat,
    solana_sdk::clock::{Epoch, Slot},
};

lazy_static! {
    static ref SIGNER_PARSER: ValueParser =
        SignerSourceParserBuilder::default().allow_all().build();
    static ref PUBKEY_PARSER: ValueParser =
        SignerSourceParserBuilder::default().allow_pubkey().build();
}

#[derive(Clone, Debug, Parser)]
#[clap(author, version, about, long_about = None)]
pub struct Cli {
    /// Configuration file to use
    #[clap(global(true), short = 'C', long = "config", id = "PATH")]
    pub config_file: Option<String>,

    /// Show additional information
    #[clap(global(true), short, long)]
    pub verbose: bool,

    /// Simulate transaction instead of executing
    #[clap(global(true), long, alias = "dryrun")]
    pub dry_run: bool,

    /// URL for Solana JSON RPC or moniker (or their first letter):
    /// [mainnet-beta, testnet, devnet, localhost].
    /// Default from the configuration file.
    #[clap(
        global(true),
        short = 'u',
        long = "url",
        id = "URL_OR_MONIKER",
        value_parser = parse_url_or_moniker,
    )]
    pub json_rpc_url: Option<String>,

    /// Specify the fee-payer account. This may be a keypair file, the ASK
    /// keyword or the pubkey of an offline signer, provided an appropriate
    /// --signer argument is also passed. Defaults to the client keypair.
    #[clap(
        global(true),
        long,
        id = "PAYER_KEYPAIR",
        value_parser = SIGNER_PARSER.clone(),
    )]
    pub fee_payer: Option<SignerSource>,

    /// Return information in specified output format
    #[clap(
        global(true),
        long = "output",
        id = "FORMAT",
        conflicts_with = "verbose",
        value_parser = PossibleValuesParser::new(["json", "json-compact"]).map(|o| parse_output_format(&o)),
    )]
    pub output_format: Option<OutputFormat>,

    #[clap(subcommand)]
    pub command: Command,
}

#[derive(Clone, Debug, Subcommand)]
pub enum Command {
    /// Command to display existing reports filtered by criteria.
    Display(DisplayCli),

    /// Close any eligible reports that meet the epoch requirement.
    /// Can filter by criteria
    Close(CloseCli),

    /// Attach to a validator's ledger directory and submit new violations.
    /// Can filter to only submit on certain slots.
    /// Can also be run in continuous mode to scan as the ledger is updated.
    Attach(AttachCli),
}

#[derive(Clone, Debug, Args)]
pub struct DisplayCli {
    /// The epoch's reports to display
    #[clap(long)]
    pub epoch: Option<Epoch>,

    /// The validator whose violation reports to display
    #[clap(value_parser = PUBKEY_PARSER.clone())]
    pub node_pubkey: Option<SignerSource>,

    /// The reporter whose reports to display
    #[clap(long, value_parser = PUBKEY_PARSER.clone())]
    pub reporter: Option<SignerSource>,
}

#[derive(Clone, Debug, Args)]
pub struct CloseCli {
    /// The report account to close
    #[clap(value_parser = PUBKEY_PARSER.clone())]
    pub report_account: Option<SignerSource>,

    /// The validator whose violation reports to close
    #[clap(long, value_parser = PUBKEY_PARSER.clone())]
    pub node_pubkey: Option<SignerSource>,

    /// The reporter whose reports to close
    #[clap(long, value_parser = PUBKEY_PARSER.clone())]
    pub reporter: Option<SignerSource>,

    /// The destination address whose associated reports to close
    #[clap(long, value_parser = PUBKEY_PARSER.clone())]
    pub destination: Option<SignerSource>,
}

#[derive(Clone, Debug, Args)]
pub struct AttachCli {
    /// The path to the validator ledger directory to attach to
    #[clap(short, long)]
    pub ledger: String,

    /// The reporting pubkey to publish on a successful report. Defaults to
    /// the default signer
    #[clap(long, value_parser = PUBKEY_PARSER.clone())]
    pub reporter: Option<SignerSource>,

    /// The destination pubkey to credit upon closing a successful report.
    /// Defaults to the default signer
    #[clap(long, value_parser = PUBKEY_PARSER.clone())]
    pub destination: Option<SignerSource>,

    /// The start of the slot range to report violations for
    #[clap(long)]
    pub start_slot: Option<Slot>,

    /// The end of the slot range to report violations for
    #[clap(long, conflicts_with = "continuous")]
    pub end_slot: Option<Slot>,

    /// Specify to continuously check the ledger for new violations.
    /// If specified without `scan_interval`, this will perform a scan once
    /// a day (roughly 1/2 an epoch).
    /// Cannot be specified with the end slot argument
    #[clap(long)]
    pub continuous: bool,

    #[clap(long, requires = "continuous")]
    pub scan_interval: Option<u64>,
}

pub fn parse_output_format(output_format: &str) -> OutputFormat {
    match output_format {
        "json" => OutputFormat::Json,
        "json-compact" => OutputFormat::JsonCompact,
        _ => unreachable!(),
    }
}
