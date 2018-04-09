extern crate abci;
extern crate futures;
extern crate grpcio;
extern crate protobuf;
extern crate tokio_proto;

extern crate ekiden_consensus_api;
extern crate ekiden_core;

mod ekidenmint;
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

use ekiden_consensus_api::create_consensus;
use ekiden_core::error::Result;

use generated::tendermint::ResponseBroadcastTx;
use rpc::ConsensusService;
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

pub fn run(config: &Config) -> Result<()> {
    // Create a shared State object and ekidenmint
    let state = Arc::new(Mutex::new(State::new()));
    let delay = time::Duration::from_millis(config.artificial_delay);

    // Create new channel (gRPC broadcast => Tendermint/Ekidenmint).
    let (sender, receiver) = mpsc::channel();

    // Start the Ekiden consensus gRPC server.
    let service = create_consensus(ConsensusService::new(state.clone(), sender));

    let grpc_environment = Arc::new(grpcio::EnvBuilder::new().build());
    let mut rpc_server = grpcio::ServerBuilder::new(grpc_environment)
        .register_service(service)
        .bind("0.0.0.0", config.grpc_port)
        .build()?;
    rpc_server.start();

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
