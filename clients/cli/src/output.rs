use {
    crate::config::Config,
    console::style,
    serde::{Deserialize, Serialize},
    serde_with::{serde_as, DisplayFromStr},
    solana_cli_output::{display::writeln_name_value, QuietDisplay, VerboseDisplay},
    solana_ledger::{
        blockstore_meta::{DuplicateSlotProof, ErasureMeta},
        shred::{Payload, Shred, ShredType},
    },
    solana_sdk::{
        clock::{Epoch, Slot},
        pubkey::Pubkey,
        signature::Signature,
    },
    solana_slashing_program::{
        duplicate_block_proof::DuplicateBlockProofData,
        state::{ProofType, ViolationReport},
    },
    std::fmt::{Display, Formatter, Result, Write},
};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CommandOutput<T>
where
    T: Serialize + Display + QuietDisplay + VerboseDisplay,
{
    pub(crate) command_name: String,
    pub(crate) command_output: T,
}

impl<T> Display for CommandOutput<T>
where
    T: Serialize + Display + QuietDisplay + VerboseDisplay,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.command_output, f)
    }
}

impl<T> QuietDisplay for CommandOutput<T>
where
    T: Serialize + Display + QuietDisplay + VerboseDisplay,
{
    fn write_str(&self, w: &mut dyn std::fmt::Write) -> std::fmt::Result {
        QuietDisplay::write_str(&self.command_output, w)
    }
}

impl<T> VerboseDisplay for CommandOutput<T>
where
    T: Serialize + Display + QuietDisplay + VerboseDisplay,
{
    fn write_str(&self, w: &mut dyn std::fmt::Write) -> std::fmt::Result {
        writeln_name_value(w, "Command:", &self.command_name)?;
        VerboseDisplay::write_str(&self.command_output, w)
    }
}

pub fn format_output<T>(config: &Config, command_name: String, command_output: T) -> String
where
    T: Serialize + Display + QuietDisplay + VerboseDisplay,
{
    config.output_format.formatted_string(&CommandOutput {
        command_name,
        command_output,
    })
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CloseReportOutput {
    #[serde_as(as = "DisplayFromStr")]
    pub report_account: Pubkey,
    #[serde_as(as = "DisplayFromStr")]
    pub pubkey: Pubkey,
    #[serde_as(as = "DisplayFromStr")]
    pub reporter: Pubkey,
    #[serde_as(as = "DisplayFromStr")]
    pub destination: Pubkey,
    #[serde_as(as = "DisplayFromStr")]
    pub lamports: u64,
    #[serde_as(as = "Option<DisplayFromStr>")]
    pub signature: Option<Signature>,
}

impl QuietDisplay for CloseReportOutput {}
impl VerboseDisplay for CloseReportOutput {}

impl Display for CloseReportOutput {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        writeln!(f)?;
        writeln_name_value(
            f,
            "Closed report account ",
            &self.report_account.to_string(),
        )?;
        writeln_name_value(f, "  Violator:", &self.pubkey.to_string())?;
        writeln_name_value(f, "  Reporter:", &self.reporter.to_string())?;
        writeln!(
            f,
            "Reclaimed {} to destination {}",
            &self.lamports.to_string(),
            &self.destination.to_string()
        )?;
        if let Some(signature) = self.signature {
            writeln_name_value(f, "  Signature:", &signature.to_string())?;
        }

        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CloseReportOutputList(pub u64, pub Vec<CloseReportOutput>);

impl QuietDisplay for CloseReportOutputList {}
impl VerboseDisplay for CloseReportOutputList {}

impl Display for CloseReportOutputList {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        let mut lamports = 0;
        for report in self.1.iter() {
            lamports += report.lamports;
            report.fmt(f)?;
        }

        writeln!(f)?;
        writeln_name_value(f, "Reports too soon to close:", &self.0.to_string())?;
        writeln_name_value(f, "Closed reports:", &self.1.len().to_string())?;
        writeln_name_value(f, "Total lamports recovered:", &lamports.to_string())?;

        Ok(())
    }
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ViolationReportOutput {
    #[serde_as(as = "DisplayFromStr")]
    pub report_address: Pubkey,
    #[serde_as(as = "DisplayFromStr")]
    pub reporter: Pubkey,
    #[serde_as(as = "DisplayFromStr")]
    pub destination: Pubkey,
    pub epoch: Epoch,
    #[serde_as(as = "DisplayFromStr")]
    pub pubkey: Pubkey,
    pub slot: Slot,
    #[serde_as(as = "DisplayFromStr")]
    pub violation_type: ProofType,
    pub proof: Vec<u8>,
}

impl ViolationReportOutput {
    pub(crate) fn from_report(
        report_address: Pubkey,
        report: &ViolationReport,
        proof: Vec<u8>,
    ) -> Self {
        Self {
            report_address,
            reporter: report.reporter,
            destination: report.destination,
            epoch: Epoch::from(report.epoch),
            pubkey: report.pubkey,
            slot: Slot::from(report.slot),
            violation_type: ProofType::from(report.violation_type),
            proof,
        }
    }

    fn write_common(&self, w: &mut dyn Write) -> Result {
        writeln!(w)?;
        writeln!(w, "{}", style("Slashing violation report").bold())?;
        writeln_name_value(
            w,
            "  Report account address:",
            &self.report_address.to_string(),
        )?;
        writeln_name_value(w, "  Violator:", &self.pubkey.to_string())?;
        writeln_name_value(w, "  Violation Type:", self.violation_type.violation_str())?;
        writeln_name_value(w, "  Violation Slot:", &self.slot.to_string())?;
        writeln_name_value(w, "  Reporter:", &self.reporter.to_string())?;
        writeln_name_value(w, "  Reported Epoch:", &self.epoch.to_string())?;
        writeln_name_value(w, "  Destination:", &self.destination.to_string())
    }

    fn display_duplicate_block_proof(w: &mut dyn Write, proof: DuplicateSlotProof) -> Result {
        let shred1 = Shred::new_from_serialized_shred(proof.shred1).unwrap();
        let shred2 = Shred::new_from_serialized_shred(proof.shred2).unwrap();

        for (i, shred) in [&shred1, &shred2].iter().enumerate() {
            write!(w, "    Shred{}: ", i + 1)?;
            writeln!(
                w,
                "fec_set_index {}, index {}, shred_type {:?}\n       \
             version {}, merkle_root {:?}, chained_merkle_root {:?}, last_in_slot {}",
                shred.fec_set_index(),
                shred.index(),
                shred.shred_type(),
                shred.version(),
                shred.merkle_root().ok(),
                shred.chained_merkle_root().ok(),
                shred.last_in_slot(),
            )?;
            writeln!(w, "       payload: {:?}", shred.payload())?;
        }

        if shred1.shred_type() == ShredType::Code && shred2.shred_type() == ShredType::Code {
            writeln!(
                w,
                "    Erasure consistency {}",
                ErasureMeta::check_erasure_consistency(&shred1, &shred2)
            )?;
        }

        Ok(())
    }
}

impl QuietDisplay for ViolationReportOutput {}

impl VerboseDisplay for ViolationReportOutput {
    fn write_str(&self, w: &mut dyn Write) -> Result {
        self.write_common(w)?;
        match self.violation_type {
            ProofType::DuplicateBlockProof => {
                let duplicate_proof: DuplicateBlockProofData =
                    DuplicateBlockProofData::unpack_proof(&self.proof).unwrap();
                let duplicate_slot_proof = DuplicateSlotProof {
                    shred1: Payload::Unique(Vec::from(duplicate_proof.shred1)),
                    shred2: Payload::Unique(Vec::from(duplicate_proof.shred2)),
                };
                Self::display_duplicate_block_proof(w, duplicate_slot_proof)
            }
            ProofType::InvalidType => {
                panic!("Invalid violation type for {}", self.report_address);
            }
        }
    }
}

impl Display for ViolationReportOutput {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        self.write_common(f)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ViolationReportListOutput(pub Vec<ViolationReportOutput>);

impl QuietDisplay for ViolationReportListOutput {}

impl VerboseDisplay for ViolationReportListOutput {
    fn write_str(&self, w: &mut dyn Write) -> Result {
        for report in self.0.iter() {
            VerboseDisplay::write_str(report, w)?;
        }

        writeln!(w)?;
        writeln_name_value(w, "Open reports:", &self.0.len().to_string())?;

        Ok(())
    }
}

impl Display for ViolationReportListOutput {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        for report in self.0.iter() {
            report.fmt(f)?;
        }

        writeln!(f)?;
        writeln_name_value(f, "Open reports:", &self.0.len().to_string())?;

        Ok(())
    }
}
