use std::mem;
use std::result::Result as StdResult;

use web3::api::Web3;
use web3::transports::ws::WebSocket;

use ekiden_di;

type Web3ViaWebsocket = Web3<WebSocket>;
struct Web3Factory {}

create_component!(
    websocket,
    "web3",
    Web3Factory,
    Web3ViaWebsocket,
    (|container: &mut Container| -> StdResult<Box<Any>, ekiden_di::error::Error> {
        let args = container.get_arguments().unwrap();
        let host = value_t_or_exit!(args, "web3-host", String);

        let (handle, transport) =
            WebSocket::new(&host).map_err(|e| ekiden_di::error::Error::from(format!("{:?}", e)))?;
        let client = Web3::new(transport);

        //TODO: memory leak here, to prevent the websocket from being dropped.
        mem::forget(handle);

        Ok(Box::new(Arc::new(client)))
    }),
    [Arg::with_name("web3-host")
        .long("web3-host")
        .help("address of the web3 websocket endpoint")
        .default_value("ws://localhost:9454")
        .takes_value(true)]
);
