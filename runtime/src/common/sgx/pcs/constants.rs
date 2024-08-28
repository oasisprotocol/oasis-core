use chrono::Duration;

// Required values of various TCB fields.
pub const REQUIRED_TCB_INFO_ID: &str = "SGX";
pub const REQUIRED_TCB_INFO_VERSION: u32 = 3;
pub const REQUIRED_QE_ID: &str = "QE";
pub const REQUIRED_QE_IDENTITY_VERSION: u32 = 2;

pub const DEFAULT_MIN_TCB_EVALUATION_DATA_NUMBER: u32 = 12; // As of 2022-08-01.
pub const DEFAULT_TCB_VALIDITY_PERIOD: Duration = Duration::try_days(30).unwrap();

// PCS timestamp format.
pub const PCS_TS_FMT: &str = "%FT%T%.9fZ";

// OIDs for PCK X509 certificate extensions.
pub const PCK_SGX_EXTENSIONS_OID: &[u64] = &[1, 2, 840, 113741, 1, 13, 1];
pub const PCK_SGX_EXTENSIONS_FMSPC_OID: &[u64] = &[1, 2, 840, 113741, 1, 13, 1, 4];
pub const PCK_SGX_EXTENSIONS_TCB_OID: &[u64] = &[1, 2, 840, 113741, 1, 13, 1, 2];
