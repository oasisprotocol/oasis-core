use chrono::Duration;

// Required values of various TCB fields.
pub const REQUIRED_TCB_INFO_VERSION: u32 = 3;
pub const REQUIRED_QE_IDENTITY_VERSION: u32 = 2;

pub const DEFAULT_MIN_TCB_EVALUATION_DATA_NUMBER: u32 = 12; // As of 2022-08-01.
pub const DEFAULT_TCB_VALIDITY_PERIOD: Duration = Duration::try_days(30).unwrap();

// PCS timestamp format.
pub const PCS_TS_FMT: &str = "%FT%T%.9fZ";

// OIDs for PCK X509 certificate extensions.
pub const PCK_SGX_EXTENSIONS_OID: &[u64] = &[1, 2, 840, 113741, 1, 13, 1];
pub const PCK_SGX_EXTENSIONS_FMSPC_OID: &[u64] = &[1, 2, 840, 113741, 1, 13, 1, 4];
pub const PCK_SGX_EXTENSIONS_TCB_OID: &[u64] = &[1, 2, 840, 113741, 1, 13, 1, 2];

pub const QE_VENDOR_ID_INTEL: [u8; 16] = [
    0x93, 0x9a, 0x72, 0x33, 0xf7, 0x9c, 0x4c, 0xa9, 0x94, 0x0a, 0x0d, 0xb3, 0x95, 0x7f, 0x06, 0x07,
];

pub const TDX_MRSIGNER_INTEL: [u8; 48] = [0; 48];

pub const QUOTE_HEADER_LEN: usize = 48;
pub const ECDSA_P256_SIGNATURE_LEN: usize = 64;
pub const ECDSA_P256_PUBLIC_KEY_LEN: usize = 64;
pub const QE_VENDOR_ID_LEN: usize = 16;
pub const QE_USER_DATA_LEN: usize = 20;
pub const SGX_REPORT_BODY_LEN: usize = 384;
pub const TDX_REPORT_BODY_LEN: usize = 584;
pub const CPUSVN_LEN: usize = 16;

pub const QUOTE_VERSION_3: u16 = 3;
pub const QUOTE_VERSION_4: u16 = 4;
