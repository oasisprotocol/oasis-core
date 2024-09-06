//! Generating quotes from reports.
use std::{
    convert::TryInto,
    fs::File,
    os::fd::AsRawFd,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, Result};

use crate::common::sgx::{
    pcs::{td_enclave_identity, TdAttributes},
    EnclaveIdentity,
};

/// Linux ConfigFS TSM report subsystem path.
const CONFIGFS_TSM_REPORT_PATH: &str = "/sys/kernel/config/tsm/report";

/// A ConfigFS TSM transaction for generating a quote.
struct ReportTransaction {
    entry: PathBuf,
    expected_generation: u64,
}

impl ReportTransaction {
    fn create() -> Result<Self> {
        // Start a new tsm report transaction by creating an entry.
        let entry = Path::new(CONFIGFS_TSM_REPORT_PATH).join("entry");
        std::fs::create_dir_all(entry.clone())?;

        // Read expected generation.
        let expected_generation = Self::read_generation(&entry)?;

        Ok(Self {
            entry,
            expected_generation,
        })
    }

    fn read_generation(entry: &Path) -> Result<u64> {
        let data = std::fs::read_to_string(entry.join("generation"))?;
        Ok(data.trim_end_matches('\n').parse()?)
    }

    fn write_option(&mut self, name: &str, data: &[u8]) -> Result<()> {
        std::fs::write(self.entry.join(name), data)?;

        // Increment expected generation.
        self.expected_generation += 1;

        Ok(())
    }

    fn read_option(&self, name: &str) -> Result<Vec<u8>> {
        let data = std::fs::read(self.entry.join(name))?;

        // Check generation.
        let generation = Self::read_generation(&self.entry)?;
        if generation != self.expected_generation {
            return Err(anyhow!(
                "unexpected generation (expected: {} got: {})",
                self.expected_generation,
                generation
            ));
        }

        Ok(data)
    }
}

impl Drop for ReportTransaction {
    fn drop(&mut self) {
        // Ensure everything gets cleaned up at the end.
        let _ = std::fs::remove_dir_all(&self.entry);
    }
}

/// Length of the REPORTDATA used in TDG.MR.REPORT TDCALL.
const TDX_REPORTDATA_LEN: usize = 64;
/// Length of TDREPORT used in TDG.MR.REPORT TDCALL.
const TDX_REPORT_LEN: usize = 1024;
/// Path to the TDX guest device.
const TDX_GUEST_DEVICE: &str = "/dev/tdx_guest";

/// Request struct for TDX_CMD_GET_REPORT0 IOCTL.
#[repr(C)]
struct tdx_report_req {
    /// User buffer with REPORTDATA to be included into TDREPORT.
    reportdata: [u8; TDX_REPORTDATA_LEN],
    /// User buffer to store TDREPORT output from TDCALL[TDG.MR.REPORT].
    tdreport: [u8; TDX_REPORT_LEN],
}

/// Raw TDX TD report as returned by TDG.MR.REPORT.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawTdReport {
    /// TD attributes.
    pub td_attributes: TdAttributes,
    /// XFAM (eXtended Features Available Mask).
    pub xfam: [u8; 8],
    /// Measurement of the initial contents of the TD.
    pub mr_td: [u8; 48],
    /// Software-defined ID for non-owner-defined configuration of the TD, e.g., runtime or OS
    /// configuration.
    pub mr_config_id: [u8; 48],
    /// Software-defined ID for the TD’s owner.
    pub mr_owner: [u8; 48],
    /// Software-defined ID for owner-defined configuration of the TD, e.g., specific to the
    /// workload rather than the runtime or OS.
    pub mr_owner_config: [u8; 48],
    /// Runtime extendable measurement register 0.
    pub rtmr0: [u8; 48],
    /// Runtime extendable measurement register 1.
    pub rtmr1: [u8; 48],
    /// Runtime extendable measurement register 2.
    pub rtmr2: [u8; 48],
    /// Runtime extendable measurement register 3.
    pub rtmr3: [u8; 48],
}

impl RawTdReport {
    /// Parse given TDREPORT_STRUCT.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() != TDX_REPORT_LEN {
            return Err(anyhow!("malformed TD report"));
        }

        // Skip first 512 bytes of TDREPORT_STRUCT that we do not currently need. These contain
        // REPORTMACSTRUCT, opaque TEE_TCB_INFO_STRUCT and some reserved bytes.
        let data = &data[512..];

        // Only parse the TDINFO_STRUCT.
        Ok(Self {
            td_attributes: TdAttributes::parse(&data[0..8])?,
            xfam: data[8..16].try_into().unwrap(),
            mr_td: data[16..64].try_into().unwrap(),
            mr_config_id: data[64..112].try_into().unwrap(),
            mr_owner: data[112..160].try_into().unwrap(),
            mr_owner_config: data[160..208].try_into().unwrap(),
            rtmr0: data[208..256].try_into().unwrap(),
            rtmr1: data[256..304].try_into().unwrap(),
            rtmr2: data[304..352].try_into().unwrap(),
            rtmr3: data[352..400].try_into().unwrap(),
        })
    }

    /// Converts this report into an enclave identity.
    pub fn as_enclave_identity(&self) -> EnclaveIdentity {
        td_enclave_identity(
            &self.mr_td,
            &self.rtmr0,
            &self.rtmr1,
            &self.rtmr2,
            &self.rtmr3,
        )
    }
}

/// Generates a TD report with the given report data.
pub fn get_report(report_data: &[u8]) -> Result<RawTdReport> {
    if report_data.len() != TDX_REPORTDATA_LEN {
        return Err(anyhow!("invalid report data length"));
    }

    let mut request = tdx_report_req {
        reportdata: [0; TDX_REPORTDATA_LEN],
        tdreport: [0; TDX_REPORT_LEN],
    };
    request.reportdata.copy_from_slice(report_data);

    nix::ioctl_readwrite!(get_report0_ioctl, b'T', 0x01, tdx_report_req);

    let device = File::options()
        .read(true)
        .write(true)
        .open(TDX_GUEST_DEVICE)?;

    unsafe {
        get_report0_ioctl(
            device.as_raw_fd(),
            std::ptr::addr_of!(request) as *mut tdx_report_req,
        )?;
    }

    // Read and parse output.
    let report = RawTdReport::parse(&request.tdreport)?;

    Ok(report)
}

/// First generates a TD report with the given report data and then uses it to generate a quote.
pub fn get_quote(report_data: &[u8]) -> Result<Vec<u8>> {
    let mut tx = ReportTransaction::create()?;
    tx.write_option("inblob", report_data)?;
    let quote = tx.read_option("outblob")?;
    Ok(quote)
}
