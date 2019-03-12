use std::{net::SocketAddr, path::PathBuf, thread};

use clap;
use futures::{prelude::*, try_ready, Poll};
use tokio::{
    io::{copy, shutdown, AsyncRead},
    net::{TcpListener, UdpSocket},
    runtime::current_thread::Runtime,
    spawn,
};
use tokio_uds::{UnixDatagram, UnixStream};

struct Proxy {
    #[allow(unused)]
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
        let remote_addr = self.common.remote_addr.clone();

        let listener =
            TcpListener::bind(&self.common.local_addr).expect("proxy TCP bind must succeed");
        listener
            .incoming()
            .for_each(move |local_socket| {
                let remote_addr = remote_addr.clone();
                spawn(
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
                        .map_err(move |_err| ()),
                );
                Ok(())
            })
            .map_err(move |_err| ())
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
        let source = UdpSocket::bind(&common.local_addr).expect("proxy UDP bind must succeed");
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
                    try_ready!(self
                        .sink
                        .poll_send_to(&self.buf[..n], self.common.remote_addr.as_path())
                        .map_err(|_err| ()));
                    self.packet_size = None;
                }
                None => {
                    let (n, _) =
                        try_ready!(self.source.poll_recv_from(&mut self.buf).map_err(|_err| ()));
                    self.packet_size = Some(n);
                }
            }
        }
    }
}

/// Return the command line argument specification.
pub fn get_arguments<'a, 'b>() -> Vec<clap::Arg<'a, 'b>> {
    vec![clap::Arg::with_name("proxy-bind")
        .long("proxy-bind")
        .takes_value(true)
        .multiple(true)
        .number_of_values(4)
        .use_delimiter(true)]
}

/// Run the proxy servers for prometheus and tracing.
pub fn start_proxies(cmdline_options: clap::ArgMatches<'static>) {
    // Go through the command line parameters.
    if cmdline_options.occurrences_of("proxy-bind") < 1 {
        return;
    }

    // Spawn the proxy-running thread.
    thread::spawn(move || {
        let mut rt = Runtime::new().unwrap();

        let values: Vec<&str> = cmdline_options.values_of("proxy-bind").unwrap().collect();
        for spec in values.chunks(4) {
            let common = Proxy {
                name: String::from(spec[1]),
                local_addr: spec[2].parse().unwrap(),
                remote_addr: PathBuf::from(spec[3]),
            };
            match spec[0] {
                "stream" => {
                    rt.spawn(StreamProxy::new(common).start());
                }
                "dgram" => {
                    rt.spawn(DgramProxy::new(common));
                }
                _ => {
                    panic!("{} is not a known proxy type", spec[0]);
                }
            };
        }

        rt.run().expect("proxy runtime execution error");
    });
}
