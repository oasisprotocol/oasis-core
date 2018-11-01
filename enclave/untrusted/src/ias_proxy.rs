use std::sync::Arc;

use sgx_types;

use ekiden_common::bytes::B64;
use ekiden_common::identity::EntityIdentity;
use ekiden_common::signature::Signed;
use ekiden_enclave_common::api;

use grpcio::Channel;

use super::generated::ias;
use super::generated::ias_grpc;

const EVIDENCE_SIGNATURE_CONTEXT: B64 = B64(*b"EkIASEvi");

#[derive(Serialize)]
struct Evidence<'a> {
    quote: &'a [u8],
    pse_manifest: &'a [u8],
}

pub struct ProxyIAS {
    entity_identity: Arc<EntityIdentity>,
    spid: sgx_types::sgx_spid_t,
    quote_type: sgx_types::sgx_quote_sign_type_t,
    client: ias_grpc::IasClient,
}

impl ProxyIAS {
    pub fn new(
        entity_identity: Arc<EntityIdentity>,
        spid: sgx_types::sgx_spid_t,
        quote_type: sgx_types::sgx_quote_sign_type_t,
        channel: Channel,
    ) -> Self {
        ProxyIAS {
            entity_identity,
            spid,
            quote_type,
            client: ias_grpc::IasClient::new(channel),
        }
    }
}

impl super::identity::IAS for ProxyIAS {
    fn get_spid(&self) -> &sgx_types::sgx_spid_t {
        &self.spid
    }

    fn get_quote_type(&self) -> sgx_types::sgx_quote_sign_type_t {
        self.quote_type
    }

    fn sigrl(&self, _gid: &sgx_types::sgx_epid_group_id_t) -> Vec<u8> {
        eprintln!("warning: ProxyIAS doesn't support sigrl. sigrl will be empty");
        vec![]
    }

    fn report(&self, quote: &[u8]) -> api::AvReport {
        let mut req = ias::VerifyEvidenceRequest::new();
        req.set_evidence(
            Signed::sign(
                &self.entity_identity.get_entity_signer(),
                &EVIDENCE_SIGNATURE_CONTEXT,
                Evidence {
                    quote: quote,
                    pse_manifest: &vec![],
                },
            ).into(),
        );

        let mut res = self.client
            .verify_evidence(&req)
            .expect("failed to get AVR from proxy");

        let mut avr = api::AvReport::new();
        avr.set_body(res.take_avr());
        avr.set_signature(res.take_signature());
        avr.set_certificates(res.take_certificate_chain());
        avr
    }
}
