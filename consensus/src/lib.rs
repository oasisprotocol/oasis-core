extern crate abci;
extern crate futures;
extern crate grpc;
extern crate hyper;
extern crate protobuf;
extern crate tls_api;
extern crate tokio_core;
extern crate tokio_proto;

extern crate ekiden_consensus_api;

mod ekidenmint;
mod errors;
mod tendermint;
pub mod generated;
mod rpc;
mod state;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::sync::mpsc;
use std::thread;
use std::time;

use abci::server::{AbciProto, AbciService};
use tokio_proto::TcpServer;

use ekiden_consensus_api::ConsensusServer;
use errors::Error;
use generated::tendermint::ResponseBroadcastTx;
use rpc::ConsensusServerImpl;
use state::State;
use tendermint::TendermintProxy;

#[derive(Debug)]
pub struct Config {
    pub tendermint_host: String,
    pub tendermint_port: u16,
    pub tendermint_abci_port: u16,
    pub grpc_port: u16,
    pub no_tendermint: bool,
    pub artificial_delay: u64,
}

pub fn run(config: &Config) -> Result<(), Box<Error>> {
    // Create a shared State object and ekidenmint
    let state = Arc::new(Mutex::new(State::new()));
    let delay = time::Duration::from_millis(config.artificial_delay);

    // Create new channel (gRPC broadcast => Tendermint/Ekidenmint).
    let (sender, receiver) = mpsc::channel();

    // Start the Ekiden consensus gRPC server.
    let mut rpc_server = grpc::ServerBuilder::new_plain();
    rpc_server.http.set_port(config.grpc_port);
    rpc_server.http.set_cpu_pool_threads(1);
    rpc_server.add_service(ConsensusServer::new_service_def(ConsensusServerImpl::new(
        Arc::clone(&state),
        sender,
    )));
    let _server = rpc_server.build().expect("rpc_server");

    // Short circuit Tendermint if `-x` is enabled
    if config.no_tendermint {
        let app = ekidenmint::Ekidenmint::new(Arc::clone(&state));
        // Setup short circuit
        for req in receiver {
            thread::sleep(delay);
            app.deliver_tx_fallible(&req.payload).unwrap();
            req.response.send(Ok(ResponseBroadcastTx::new())).unwrap();
        }
        return Ok(());
    }

    // Create Tendermint proxy/app.
    let _tendermint =
        TendermintProxy::new(&config.tendermint_host, config.tendermint_port, receiver);

    // Start the Tendermint ABCI listener
    let abci_listen_addr = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
        config.tendermint_abci_port,
    );
    let mut app_server = TcpServer::new(AbciProto, abci_listen_addr);
    app_server.threads(1);
    app_server.serve(move || {
        Ok(AbciService {
            app: Box::new(ekidenmint::Ekidenmint::new(Arc::clone(&state))),
        })
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    //use super::generated::consensus;

    #[test]
    fn empty() {
        assert_eq!(8, 8)
    }
}
