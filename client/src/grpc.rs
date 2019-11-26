//! Helpers for calling Oasis gRPC services.
use grpcio::{Error, Result};
use serde::{de::DeserializeOwned, Serialize};

use oasis_core_runtime::common::cbor;

/// CBOR-encoded NULL value.
static CBOR_NULL: &'static [u8] = &[0xF6];

/// CBOR encoding wrapper for gRPC.
#[inline]
pub fn cbor_encode<T>(t: &T, buf: &mut Vec<u8>)
where
    T: Serialize,
{
    cbor::to_writer(buf, t)
}

/// CBOR decoding wrapper for gRPC.
#[inline]
pub fn cbor_decode<T>(mut buf: &[u8]) -> Result<T>
where
    T: DeserializeOwned,
{
    // gRPC can return an empty buffer if there is no response. Unfortunately the
    // CBOR parser fails to decode an empty buffer even if the target type is the
    // unit type (). As a workaround we replace the buffer with a decodable one.
    if buf.is_empty() {
        buf = CBOR_NULL;
    }

    cbor::from_slice(buf).map_err(|e| Error::Codec(Box::new(e)))
}

/// A helper macro for defining gRPC methods using the CBOR codec.
macro_rules! grpc_method {
    ($id:ident, $name:expr, $rq:ty, $rsp:ty) => {
        const $id: ::grpcio::Method<$rq, $rsp> = ::grpcio::Method {
            ty: ::grpcio::MethodType::Unary,
            name: $name,
            req_mar: ::grpcio::Marshaller {
                ser: $crate::grpc::cbor_encode,
                de: $crate::grpc::cbor_decode,
            },
            resp_mar: ::grpcio::Marshaller {
                ser: $crate::grpc::cbor_encode,
                de: $crate::grpc::cbor_decode,
            },
        };
    };
}

/// A helper macro for defining gRPC streams using the CBOR codec.
macro_rules! grpc_stream {
    ($id:ident, $name:expr, $rq:ty, $rsp:ty) => {
        const $id: ::grpcio::Method<$rq, $rsp> = ::grpcio::Method {
            ty: ::grpcio::MethodType::ServerStreaming,
            name: $name,
            req_mar: ::grpcio::Marshaller {
                ser: $crate::grpc::cbor_encode,
                de: $crate::grpc::cbor_decode,
            },
            resp_mar: ::grpcio::Marshaller {
                ser: $crate::grpc::cbor_encode,
                de: $crate::grpc::cbor_decode,
            },
        };
    };
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_empty_cbor_decode() {
        let _: () = cbor_decode(&[]).unwrap();
    }
}
