//! Quote policy.
use super::{constants::*, report::TdReport, Error};

/// Quote validity policy.
#[derive(Clone, Debug, PartialEq, Eq, cbor::Encode, cbor::Decode)]
pub struct QuotePolicy {
    /// Whether PCS quotes are disabled and will always be rejected.
    #[cbor(optional)]
    pub disabled: bool,

    /// Validity (in days) of the TCB collateral.
    pub tcb_validity_period: u16,

    /// Minimum TCB evaluation data number that is considered to be valid. TCB bundles containing
    /// smaller values will be invalid.
    pub min_tcb_evaluation_data_number: u32,

    /// A list of hexadecimal encoded FMSPCs specifying which processor packages and platform
    /// instances are blocked.
    #[cbor(optional)]
    pub fmspc_blacklist: Vec<String>,

    /// Optional TDX-specific policy. In case this is `None`, TDX quotes are disallowed.
    #[cbor(optional)]
    pub tdx: Option<TdxQuotePolicy>,
}

impl Default for QuotePolicy {
    fn default() -> Self {
        Self {
            disabled: false,
            tcb_validity_period: 30,
            min_tcb_evaluation_data_number: DEFAULT_MIN_TCB_EVALUATION_DATA_NUMBER,
            fmspc_blacklist: Vec::new(),
            tdx: None,
        }
    }
}

impl QuotePolicy {
    /// Whether the quote with timestamp `ts` is expired.
    pub fn is_expired(&self, now: i64, ts: i64) -> bool {
        if self.disabled {
            return true;
        }

        now.checked_sub(ts)
            .map(|d| d > 60 * 60 * 24 * (self.tcb_validity_period as i64))
            .expect("quote timestamp is in the future") // This should never happen.
    }
}

/// TDX-specific quote policy.
#[derive(Clone, Debug, Default, PartialEq, Eq, cbor::Encode, cbor::Decode)]
pub struct TdxQuotePolicy {
    /// Allowed TDX modules. Empty to allow ANY Intel-signed module.
    pub allowed_tdx_modules: Vec<TdxModulePolicy>,
}

impl TdxQuotePolicy {
    /// Verify whether the TDX policy is satisfied for the given report.
    pub fn verify(&self, report: &TdReport) -> Result<(), Error> {
        self.verify_tdx_module(report)?;
        Ok(())
    }

    fn verify_tdx_module(&self, report: &TdReport) -> Result<(), Error> {
        // If at least one TDX Module matches, then we are good.
        for allowed_module in &self.allowed_tdx_modules {
            if allowed_module.matches(report) {
                return Ok(());
            }
        }

        // No module matched. Iff the list of modules is empty, allow ANY Intel-signed module.
        // As per the TDX specifications, MRSIGNER is all-zero for Intel.
        if self.allowed_tdx_modules.is_empty() && report.mr_signer_seam == TDX_MRSIGNER_INTEL {
            return Ok(());
        }

        Err(Error::TdxModuleNotAllowed)
    }
}

/// TDX module policy.
#[derive(Clone, Debug, PartialEq, Eq, cbor::Encode, cbor::Decode)]
#[cbor(no_default)]
pub struct TdxModulePolicy {
    /// Optional allowed measurement of the TDX Module. In case it is `None`, ANY measurement is
    /// allowed and only the signer is checked.
    pub mr_seam: Option<[u8; 48]>,

    /// Allowed signer of the TDX Module (zero for Intel).
    pub mr_signer_seam: [u8; 48],
}

impl TdxModulePolicy {
    /// Returns true iff the TDX module in the given report matches this module policy.
    pub fn matches(&self, report: &TdReport) -> bool {
        // Check MRSEAM if set.
        if let Some(mr_seam) = self.mr_seam {
            if mr_seam != report.mr_seam {
                return false;
            }
        }

        // Check MRSIGNER.
        if self.mr_signer_seam != report.mr_signer_seam {
            return false;
        }

        true
    }
}
