use std::net::ToSocketAddrs;
use std::sync::Mutex;

extern crate clap;
use clap::value_t_or_exit;
extern crate grpcio;
extern crate lazy_static;
use lazy_static::lazy_static;
extern crate log;
use log::error;
extern crate rustracing;
extern crate rustracing_jaeger;
use rustracing_jaeger::Tracer;
extern crate trackable;
use trackable::error::ErrorKindExt;
use trackable::track;

/// Create a Vec of args for App::args(&...) with configuration options for tracing.
pub fn get_arguments<'a, 'b>() -> Vec<clap::Arg<'a, 'b>> {
    vec![
        clap::Arg::with_name("tracing-enable").long("tracing-enable"),
        clap::Arg::with_name("tracing-sample-probability")
            .long("tracing-sample-probability")
            .takes_value(true)
            .default_value("0.001"),
        clap::Arg::with_name("tracing-agent-addr")
            .long("tracing-agent-addr")
            .help("Address of the Jaeger agent's compact thrift UDP port")
            .takes_value(true)
            .default_value("127.0.0.1:6831"),
    ]
}

lazy_static! {
    static ref GLOBAL_TRACER: Mutex<Option<Tracer>> = Mutex::new(None);
}

/// Read options from an ArgMatches (use get_arguments). Start a thread that reports to the Jaeger
/// agent under a given service name.
pub fn report_forever(service_name: &str, matches: &clap::ArgMatches) {
    let tracer = if matches.is_present("tracing-enable") {
        let (tracer, span_rx) = Tracer::new(
            rustracing::sampler::ProbabilisticSampler::new(value_t_or_exit!(
                matches,
                "tracing-sample-probability",
                f64
            )).expect("sampler creation must succeed"),
        );
        let agent_addr = matches
            .value_of("tracing-agent-addr")
            .unwrap()
            .to_socket_addrs()
            .expect("tracing agent address must be a valid socket address")
            .next()
            .expect("must have a tracing agent address");
        let mut reporter = rustracing_jaeger::reporter::JaegerCompactReporter::new(service_name)
            .expect("reporter creation must succeed");
        reporter.set_agent_addr(agent_addr);

        std::thread::spawn(move || {
            // TODO: is it better to batch these?
            for span in span_rx {
                if let Err(error) = reporter.report(&[span]) {
                    error!("Failed to report span: {:?}", error);
                }
            }
        });
        tracer
    } else {
        let (tracer, _span_rx) = Tracer::new(rustracing::sampler::NullSampler);
        // Drop the span receiver, and spans will fail to send themselves and ignore the error.
        tracer
    };
    let mut guard = GLOBAL_TRACER.lock().unwrap();
    assert!(guard.is_none(), "Reinitializing tracer");
    *guard = Some(tracer);
}

/// Obtain a copy of the global Tracer object.
pub fn get_tracer() -> Tracer {
    GLOBAL_TRACER
        .lock()
        .unwrap()
        .clone()
        .expect("Getting tracer before initialization")
}

/// A SetHttpHeaderField adapter for GRPC metadata.
pub struct MetadataBuilderCarrier(pub grpcio::MetadataBuilder);

impl rustracing::carrier::SetHttpHeaderField for MetadataBuilderCarrier {
    fn set_http_header_field(&mut self, name: &str, value: &str) -> rustracing::Result<()> {
        track!(
            self.0
                .add_str(name, value)
                .map_err(|error| rustracing::ErrorKind::InvalidInput.cause(error))
        )?;
        Ok(())
    }
}

/// Inject a span context as the only headers of a GRPC CallOption.
pub fn inject_to_options(
    mut options: grpcio::CallOption,
    context: Option<&rustracing_jaeger::span::SpanContext>,
) -> grpcio::CallOption {
    if let Some(sc) = context {
        let mut carrier = MetadataBuilderCarrier(grpcio::MetadataBuilder::with_capacity(1));
        match sc.inject_to_http_header(&mut carrier) {
            Ok(()) => {
                options = options.headers(carrier.0.build());
            }
            Err(error) => {
                error!(
                    "Tracing provider unable to inject span context: {:?}",
                    error
                );
            }
        }
    }
    options
}

/// An IterHttpHeaderFields adpter for GRPC metadata.
pub struct MetadataCarrier<'a>(pub &'a grpcio::Metadata);

impl<'a> rustracing::carrier::IterHttpHeaderFields<'a> for MetadataCarrier<'a> {
    type Fields = grpcio::MetadataIter<'a>;

    fn fields(&self) -> Self::Fields {
        self.0.iter()
    }
}

#[test]
fn test_propagation() {
    let sc1 = rustracing::span::SpanContext::new(
        rustracing_jaeger::span::SpanContextStateBuilder::new()
            .trace_id(rustracing_jaeger::span::TraceId { high: 1, low: 2 })
            .span_id(3)
            .finish(),
        vec![],
    );

    let mut mbc = MetadataBuilderCarrier(grpcio::MetadataBuilder::with_capacity(1));
    sc1.inject_to_http_header(&mut mbc).unwrap();

    let m = mbc.0.build();
    let sc2 = rustracing_jaeger::span::SpanContext::extract_from_http_header(&MetadataCarrier(&m))
        .unwrap()
        .unwrap();
    assert_eq!(sc2.state().trace_id(), sc1.state().trace_id());
    assert_eq!(sc2.state().span_id(), sc2.state().span_id());
}
