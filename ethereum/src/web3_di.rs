use std::result::Result as StdResult;
use std::thread;

use ekiden_common::futures::sync::oneshot;
#[allow(unused_imports)]
use ekiden_common::futures::{future, Future};
use tokio_core;
use web3::api::Web3;
use web3::transports::ws::WebSocket;

use ekiden_di;

type Web3ViaWebsocket = Web3<WebSocket>;
struct Web3Factory {}

/// Dependency injection for a web3 client.
/// Expects a tokio Remote handle from the eventloop the client will be run on.
create_component!(
    websocket,
    "web3",
    Web3Factory,
    Web3ViaWebsocket,
    (|container: &mut Container| -> StdResult<Box<Any>, ekiden_di::error::Error> {
        let args = container.get_arguments().unwrap();
        let host = value_t_or_exit!(args, "web3-host", String);

        // Spawn the websocket creation on the eventloop represented by `remote`.

        let (init_tx, init_rx) = oneshot::channel();
        thread::spawn(move || match tokio_core::reactor::Core::new() {
            Ok(mut core) => match WebSocket::with_event_loop(&host, &core.handle())
                .map_err(|e| ekiden_di::error::Error::from(format!("{:?}", e)))
            {
                Ok(transport) => {
                    let client = Web3::new(transport);
                    init_tx.send(Ok(client)).unwrap();
                    loop {
                        core.turn(None);
                    }
                }
                Err(e) => init_tx.send(Err(e)).unwrap(),
            },
            Err(e) => {
                init_tx
                    .send(Err(ekiden_di::error::Error::from(format!("{:?}", e))))
                    .unwrap();
            }
        });

        let client = init_rx.wait().unwrap()?;

        Ok(Box::new(Arc::new(client)))
    }),
    [Arg::with_name("web3-host")
        .long("web3-host")
        .env("WEB3_HOST")
        .help("address of the web3 websocket endpoint")
        .default_value("ws://localhost:9454")
        .takes_value(true)]
);
