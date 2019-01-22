use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use clap;
use log::error;
use tokio_uds::{UnixDatagram, UnixStream};

use ekiden_core::environment::Environment;
use ekiden_core::futures::prelude::*;
use ekiden_core::futures::{Async, Future, Poll};
use ekiden_core::tokio::io::{copy, shutdown, AsyncRead};
use ekiden_core::tokio::net::{TcpListener, UdpSocket};

macro_rules! try_poll {
    ($e:expr) => {
        match $e {
            Ok(Async::Ready(ready_result)) => ready_result,
            Ok(Async::NotReady) => return Ok(Async::NotReady),
            Err(_) => return Err(()),
        }
    };
}

struct Proxy {
    environment: Arc<Environment>,
    name: String,
    local_addr: SocketAddr,
    remote_addr: PathBuf,
}

struct StreamProxy {
    common: Proxy,
}

impl StreamProxy {
    fn new(common: Proxy) -> StreamProxy {
        StreamProxy { common: common }
    }

    fn start(&mut self) -> impl Future<Item = (), Error = ()> {
        let name_listen_err = self.common.name.clone();
        let name_fwd_err = self.common.name.clone();
        let environment = self.common.environment.clone();
        let remote_addr = self.common.remote_addr.clone();

        let listener = TcpListener::bind(&self.common.local_addr).unwrap();
        listener
            .incoming()
            .for_each(move |local_socket| {
                let name = name_fwd_err.clone();
                let remote_addr = remote_addr.clone();
                environment.spawn(Box::new(
                    UnixStream::connect(remote_addr)
                        .and_then(move |remote_socket| {
                            let (remote_read, remote_write) = remote_socket.split();
                            let (local_read, local_write) = local_socket.split();

                            let from_local = copy(local_read, remote_write)
                                .and_then(|(n, _, writer)| shutdown(writer).map(move |_| n));
                            let from_remote = copy(remote_read, local_write)
                                .and_then(|(n, _, writer)| shutdown(writer).map(move |_| n));

                            from_local.join(from_remote).map(move |_| ())
                        })
                        .map_err(move |err| {
                            error!("[{}] error forwarding between sockets: {}", name, err);
                        }),
                ));
                Ok(())
            })
            .map_err(move |err| {
                error!(
                    "[{}] error listening on local socket: {}",
                    name_listen_err, err
                );
            })
    }
}

struct DgramProxy {
    common: Proxy,
    source: UdpSocket,
    sink: UnixDatagram,
    buf: Vec<u8>,
    packet_size: Option<usize>,
}

impl DgramProxy {
    fn new(common: Proxy) -> DgramProxy {
        let source = UdpSocket::bind(&common.local_addr).unwrap();
        DgramProxy {
            common: common,
            source: source,
            sink: UnixDatagram::unbound().unwrap(),
            buf: vec![0; 65536],
            packet_size: None,
        }
    }
}

impl Future for DgramProxy {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<(), ()> {
        loop {
            match self.packet_size {
                Some(n) => {
                    try_poll!(
                        self.sink
                            .poll_send_to(&self.buf[..n], self.common.remote_addr.as_path())
                    );
                    self.packet_size = None;
                }
                None => {
                    let (n, _) = try_poll!(self.source.poll_recv_from(&mut self.buf));
                    self.packet_size = Some(n);
                }
            }
        }
    }
}

/// Return the command line argument specification.
pub fn get_arguments<'a, 'b>() -> Vec<clap::Arg<'a, 'b>> {
    vec![
        clap::Arg::with_name("proxy-bind")
            .long("proxy-bind")
            .takes_value(true)
            .multiple(true)
            .number_of_values(4)
            .use_delimiter(true),
    ]
}

/// Run the proxy servers for prometheus and tracing.
pub fn start_proxies(environment: Arc<Environment>, cmdline_options: &clap::ArgMatches) {
    // Go through the command line parameters.
    if cmdline_options.occurrences_of("proxy-bind") < 1 {
        return;
    }

    let values: Vec<&str> = cmdline_options.values_of("proxy-bind").unwrap().collect();
    for spec in values.chunks(4) {
        let common = Proxy {
            environment: environment.clone(),
            name: String::from(spec[1]),
            local_addr: spec[2].parse().unwrap(),
            remote_addr: PathBuf::from(spec[3]),
        };
        match spec[0] {
            "stream" => {
                environment.spawn(Box::new(StreamProxy::new(common).start()));
            }
            "dgram" => {
                environment.spawn(Box::new(DgramProxy::new(common)));
            }
            _ => {
                panic!("{} is not a known proxy type", spec[0]);
            }
        };
    }
}
