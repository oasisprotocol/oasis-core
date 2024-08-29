//! TDX structures.
use std::convert::TryInto;

use byteorder::{ByteOrder, LittleEndian};
pub use sgx_isa::Report as SgxReport;
use tiny_keccak::{Hasher, TupleHash};

use super::{constants::*, utils::*, Error};
use crate::common::sgx::{EnclaveIdentity, MrEnclave};

/// TDX TD report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TdReport {
    /// Describes the TCB of TDX.
    pub tee_tcb_svn: [u8; 16],
    /// Measurement of the TDX Module.
    pub mr_seam: [u8; 48],
    /// Signer of the TDX Module (zero for Intel).
    pub mr_signer_seam: [u8; 48],
    /// TDX Module attributes (must be zero for TDX 1.0).
    pub seam_attributes: [u8; 8],
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
    /// Custom report data.
    pub report_data: [u8; 64],
}

impl TdReport {
    /// Parse a TDX report.
    pub fn parse(mut data: &[u8]) -> Result<Self, Error> {
        if data.len() != TDX_REPORT_BODY_LEN {
            return Err(Error::MalformedReport);
        }

        let report = Self {
            tee_tcb_svn: data
                .take_prefix(16)
                .map_err(|_| Error::MalformedReport)?
                .try_into()
                .unwrap(),
            mr_seam: data
                .take_prefix(48)
                .map_err(|_| Error::MalformedReport)?
                .try_into()
                .unwrap(),
            mr_signer_seam: data
                .take_prefix(48)
                .map_err(|_| Error::MalformedReport)?
                .try_into()
                .unwrap(),
            seam_attributes: data
                .take_prefix(8)
                .map_err(|_| Error::MalformedReport)?
                .try_into()
                .unwrap(),
            td_attributes: TdAttributes::parse(
                data.take_prefix(8).map_err(|_| Error::MalformedReport)?,
            )?,
            xfam: data
                .take_prefix(8)
                .map_err(|_| Error::MalformedReport)?
                .try_into()
                .unwrap(),
            mr_td: data
                .take_prefix(48)
                .map_err(|_| Error::MalformedReport)?
                .try_into()
                .unwrap(),
            mr_config_id: data
                .take_prefix(48)
                .map_err(|_| Error::MalformedReport)?
                .try_into()
                .unwrap(),
            mr_owner: data
                .take_prefix(48)
                .map_err(|_| Error::MalformedReport)?
                .try_into()
                .unwrap(),
            mr_owner_config: data
                .take_prefix(48)
                .map_err(|_| Error::MalformedReport)?
                .try_into()
                .unwrap(),
            rtmr0: data
                .take_prefix(48)
                .map_err(|_| Error::MalformedReport)?
                .try_into()
                .unwrap(),
            rtmr1: data
                .take_prefix(48)
                .map_err(|_| Error::MalformedReport)?
                .try_into()
                .unwrap(),
            rtmr2: data
                .take_prefix(48)
                .map_err(|_| Error::MalformedReport)?
                .try_into()
                .unwrap(),
            rtmr3: data
                .take_prefix(48)
                .map_err(|_| Error::MalformedReport)?
                .try_into()
                .unwrap(),
            report_data: data
                .take_prefix(64)
                .map_err(|_| Error::MalformedReport)?
                .try_into()
                .unwrap(),
        };

        // SEAM attributes must be zero for TDX 1.0.
        if report.seam_attributes != [0; 8] {
            return Err(Error::MalformedReport);
        }

        Ok(report)
    }

    /// Converts this report into an enclave identity.
    pub fn as_enclave_identity(&self) -> EnclaveIdentity {
        // TODO: Change the EnclaveIdentity structure to allow specifying all the different things.

        // Compute MRENCLAVE as TupleHash[TD_ENCLAVE_IDENTITY_CONTEXT](MRTD, RTMR0, RTMR1, RTMR2, RTMR3).
        //
        // MRTD  -- Measurement of virtual firmware.
        // RTMR0 -- Measurement of virtual firmware data and configuration.
        // RTMR1 -- Measurement of OS loader, option ROM, boot parameters.
        // RTMR2 -- Measurement of OS kernel, initrd, boot parameters.
        // RTMR3 -- Reserved.
        //
        let mut mr_enclave = MrEnclave::default();
        let mut h = TupleHash::v256(TD_ENCLAVE_IDENTITY_CONTEXT);
        h.update(&self.mr_td);
        h.update(&self.rtmr0);
        h.update(&self.rtmr1);
        h.update(&self.rtmr2);
        h.update(&self.rtmr3);
        h.finalize(&mut mr_enclave.0);

        EnclaveIdentity {
            mr_signer: Default::default(), // All-zero MRSIGNER (invalid in SGX).
            mr_enclave,
        }
    }
}

/// TD enclave identity conversion context.
pub const TD_ENCLAVE_IDENTITY_CONTEXT: &[u8] = b"oasis-core/tdx: TD enclave identity";

bitflags::bitflags! {
    /// TDX TD attributes.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct TdAttributes: u64 {
        /// TUD.DEBUG (TD runs in debug mode).
        const DEBUG = 0b00000000_00000000_00000000_00000000_00000000_00000000_00000000_00000001;
        // TUD bits 7:1 reserved for future use and must be zero.

        // SEC bits 27:8 reserved for future use and must be zero.
        /// SEC.SEPT_VE_DISABLE (Disable EPT violation conversion to #VE on TD access of PENDING pages).
        const SEPT_VE_DISABLE = 0b00000000_00000000_00000000_00000000_00010000_00000000_00000000_00000000;
        // SEC bit 28 reserved for future use and must be zero.
        /// SEC.PKS (TD is allowed to use Supervisor Protection Keys).
        const PKS = 0b00000000_00000000_00000000_00000000_01000000_00000000_00000000_00000000;
        /// SEC.KL (TD is allowed to use Key Locker).
        const KL = 0b00000000_00000000_00000000_00000000_10000000_00000000_00000000_00000000;

        // OTHER bits 62:32 reserved for future use and must be zero.
        /// OTHER.PERFMON (TD is allowed to use Perfmon and PERF_METRICS capabilities).
        const PERFMON = 0b10000000_00000000_00000000_00000000_00000000_00000000_00000000_00000000;
    }
}

impl TdAttributes {
    /// Parse raw TDX attributes.
    pub fn parse(data: &[u8]) -> Result<Self, Error> {
        if data.len() != 8 {
            return Err(Error::MalformedReport);
        }

        let attrs = LittleEndian::read_u64(data);

        Self::from_bits(attrs).ok_or(Error::MalformedReport)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_td_attributes() {
        let attrs = TdAttributes::DEBUG | TdAttributes::SEPT_VE_DISABLE | TdAttributes::PKS;
        assert!(attrs.contains(TdAttributes::DEBUG));
        assert!(attrs.contains(TdAttributes::SEPT_VE_DISABLE));
        assert!(attrs.contains(TdAttributes::PKS));
        assert!(attrs.contains(TdAttributes::DEBUG | TdAttributes::SEPT_VE_DISABLE));
        assert!(!attrs.contains(TdAttributes::KL));
        assert!(!attrs.contains(TdAttributes::DEBUG | TdAttributes::KL));

        let reserved = vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let result = TdAttributes::parse(&reserved);
        assert!(matches!(result, Err(Error::MalformedReport)));

        let reserved = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
        let result = TdAttributes::parse(&reserved);
        assert!(matches!(result, Err(Error::MalformedReport)));
    }
}
