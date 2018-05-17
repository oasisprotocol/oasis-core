use std::convert::{Into, TryFrom};
use std::sync::Arc;

use ekiden_common::futures::{future, BoxFuture, Future, Stream};
use ekiden_registry_api as api;
use grpcio::{RpcContext, RpcStatus, ServerStreamingSink, UnarySink, WriteFlags};
use grpcio::RpcStatusCode::{Internal, InvalidArgument};
use protobuf::RepeatedField;

use super::contract_backend::ContractRegistryBackend;
use ekiden_common::bytes::B256;
use ekiden_common::contract::Contract;
use ekiden_common::error::Error;
use ekiden_common::signature::{Signature, Signed};

#[derive(Clone)]
pub struct ContractRegistryService {
    inner: Arc<ContractRegistryBackend>,
}

impl ContractRegistryService {
    pub fn new(backend: Arc<ContractRegistryBackend>) -> Self {
        Self { inner: backend }
    }
}

macro_rules! invalid {
    ($sink:ident,$code:ident,$e:expr) => {
        $sink.fail(RpcStatus::new(
            $code,
            Some($e.description().to_owned()),
        ))
    }
}

impl api::ContractRegistry for ContractRegistryService {
    fn register_contract(
        &self,
        ctx: RpcContext,
        req: api::RegisterContractRequest,
        sink: UnarySink<api::RegisterContractResponse>,
    ) {
        let f = move || -> Result<BoxFuture<()>, Error> {
            let c = Contract::try_from(req.get_contract().clone())?;
            let s = Signature::try_from(req.get_signature().clone())?;
            Ok(self.inner.register_contract(Signed::from_parts(c, s)))
        };
        let f = match f() {
            Ok(f) => f.then(|res| match res {
                Ok(()) => Ok(api::RegisterContractResponse::new()),
                Err(e) => Err(e),
            }),
            Err(e) => {
                ctx.spawn(invalid!(sink, InvalidArgument, e).map_err(|_e| ()));
                return;
            }
        };
        ctx.spawn(f.then(move |r| match r {
            Ok(ret) => sink.success(ret),
            Err(e) => invalid!(sink, Internal, e),
        }).map_err(|_e| ()));
    }

    fn get_contract(
        &self,
        ctx: RpcContext,
        req: api::ContractRequest,
        sink: UnarySink<api::ContractResponse>,
    ) {
        let f = move || -> Result<BoxFuture<Contract>, Error> {
            let id = B256::from_slice(req.get_id());
            Ok(self.inner.get_contract(id))
        };
        let f = match f() {
            Ok(f) => f.then(|res| match res {
                Ok(con) => {
                    let mut r = api::ContractResponse::new();
                    r.set_contract(con.into());
                    Ok(r)
                }
                Err(e) => Err(e),
            }),
            Err(e) => {
                ctx.spawn(invalid!(sink, InvalidArgument, e).map_err(|_e| ()));
                return;
            }
        };
        ctx.spawn(f.then(move |r| match r {
            Ok(ret) => sink.success(ret),
            Err(e) => invalid!(sink, Internal, e),
        }).map_err(|_e| ()));
    }

    fn get_contracts(
        &self,
        ctx: RpcContext,
        _req: api::ContractsRequest,
        sink: ServerStreamingSink<api::ContractsResponse>,
    ) {
        let f = self.inner
            .get_contracts()
            .map(|res| -> (api::ContractsResponse, WriteFlags) {
                let mut r = api::ContractsResponse::new();
                r.set_contract(RepeatedField::from_vec(vec![res.into()]));
                (r, WriteFlags::default())
            });
        ctx.spawn(f.forward(sink).then(|_f| future::ok(())));
    }
}
