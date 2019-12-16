use grpcio::{CallOption, Channel, Client, Error, Marshaller, Method, MethodType, Result};
use serde::{de::DeserializeOwned, Serialize};
use serde_cbor::Value;
use serde_derive::{Deserialize, Serialize};

use crate::{
    common::{cbor, crypto::hash::Hash, roothash::Namespace},
    storage::mkvs::{urkel::sync, WriteLog},
};

// NOTE: The return value is intentionally ignored as it is not required
//       during the interoperability tests.
const METHOD_APPLY: Method<ApplyRequest, Value> = Method {
    ty: MethodType::Unary,
    name: "/oasis-core.Storage/Apply",
    req_mar: Marshaller {
        ser: cbor_encode,
        de: cbor_decode,
    },
    resp_mar: Marshaller {
        ser: cbor_encode,
        de: cbor_decode,
    },
};

const METHOD_SYNC_GET: Method<sync::GetRequest, sync::ProofResponse> = Method {
    ty: MethodType::Unary,
    name: "/oasis-core.Storage/SyncGet",
    req_mar: Marshaller {
        ser: cbor_encode,
        de: cbor_decode,
    },
    resp_mar: Marshaller {
        ser: cbor_encode,
        de: cbor_decode,
    },
};

const METHOD_SYNC_GET_PREFIXES: Method<sync::GetPrefixesRequest, sync::ProofResponse> = Method {
    ty: MethodType::Unary,
    name: "/oasis-core.Storage/SyncGetPrefixes",
    req_mar: Marshaller {
        ser: cbor_encode,
        de: cbor_decode,
    },
    resp_mar: Marshaller {
        ser: cbor_encode,
        de: cbor_decode,
    },
};

const METHOD_SYNC_ITERATE: Method<sync::IterateRequest, sync::ProofResponse> = Method {
    ty: MethodType::Unary,
    name: "/oasis-core.Storage/SyncIterate",
    req_mar: Marshaller {
        ser: cbor_encode,
        de: cbor_decode,
    },
    resp_mar: Marshaller {
        ser: cbor_encode,
        de: cbor_decode,
    },
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApplyRequest {
    pub namespace: Namespace,
    pub src_round: u64,
    pub src_root: Hash,
    pub dst_round: u64,
    pub dst_root: Hash,
    pub writelog: WriteLog,
}

/// A (simplified) storage gRPC service client.
///
/// # Note
///
/// This client only implements methods required for testing the
/// interoperability of the read syncer interface.
#[derive(Clone)]
pub struct StorageClient {
    client: Client,
}

impl StorageClient {
    pub fn new(channel: Channel) -> Self {
        StorageClient {
            client: Client::new(channel),
        }
    }

    pub fn apply(&self, request: &ApplyRequest) -> Result<()> {
        self.client
            .unary_call(
                &METHOD_APPLY,
                &request,
                CallOption::default().wait_for_ready(true),
            )
            .map(|_| ())
    }

    pub fn sync_get(&self, request: &sync::GetRequest) -> Result<sync::ProofResponse> {
        self.client.unary_call(
            &METHOD_SYNC_GET,
            &request,
            CallOption::default().wait_for_ready(true),
        )
    }

    pub fn sync_get_prefixes(
        &self,
        request: &sync::GetPrefixesRequest,
    ) -> Result<sync::ProofResponse> {
        self.client.unary_call(
            &METHOD_SYNC_GET_PREFIXES,
            &request,
            CallOption::default().wait_for_ready(true),
        )
    }

    pub fn sync_iterate(&self, request: &sync::IterateRequest) -> Result<sync::ProofResponse> {
        self.client.unary_call(
            &METHOD_SYNC_ITERATE,
            &request,
            CallOption::default().wait_for_ready(true),
        )
    }
}

#[inline]
fn cbor_encode<T>(t: &T, buf: &mut Vec<u8>)
where
    T: Serialize,
{
    cbor::to_writer(buf, t)
}

/// CBOR decoding wrapper for gRPC.
#[inline]
fn cbor_decode<T>(buf: &[u8]) -> Result<T>
where
    T: DeserializeOwned,
{
    cbor::from_slice(buf).map_err(|e| Error::Codec(Box::new(e)))
}
