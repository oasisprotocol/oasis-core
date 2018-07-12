//! ABCI server.
use std::net::SocketAddr;
use std::sync::Arc;

use tokio_codec::Decoder;

use ekiden_common::error::Error;
use ekiden_common::futures::prelude::*;
use ekiden_common::tokio::net::TcpListener;

use super::codec::AbciCodec;
use super::service::AbciService;
use super::Application;

/// Start an ABCI TCP server.
///
/// Returns a task that should be spawned onto an event loop.
pub fn start(
    address: &SocketAddr,
    application: Arc<Application>,
) -> Box<Future<Item = (), Error = ()> + Send> {
    let service = Arc::new(AbciService::new(application));

    info!("Starting Tendermint ABCI server on {}", address);

    TcpListener::bind(address)
        .unwrap()
        .incoming()
        .for_each(move |socket| {
            // TODO: Enforce connection policy to prevent arbitrary connections.
            trace!(
                "Accepted incoming ABCI connection from {}",
                socket.peer_addr().unwrap()
            );

            let socket = AbciCodec::new().framed(socket);
            let service = service.clone();

            // Process requests one by one in a separate task.
            let iter = stream::repeat::<_, Error>(());
            spawn(
                iter.fold(socket, move |socket, _| {
                    let service = service.clone();

                    socket.into_future().map_err(|(error, _)| error).and_then(
                        move |(request, socket)| {
                            if let Some(request) = request {
                                // Handle a single request.
                                service
                                    .handle(request)
                                    .and_then(move |response| {
                                        // Send a single response back.
                                        socket.send(response)
                                    })
                                    .into_box()
                            } else {
                                // No more requests, we are done.
                                future::err(Error::new("done")).into_box()
                            }
                        },
                    )
                }).map_err(|error| {
                        if error.message != "done" {
                            error!("Error while processing ABCI connection: {}", error.message);
                        }
                    })
                    .discard(),
            );

            Ok(())
        })
        .map_err(|error| {
            error!("Error while accepting ABCI connection: {}", error);
        })
        .into_box()
}
