#![feature(use_extern_macros)]

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

pub fn get_arguments<'a, 'b>() -> Vec<clap::Arg<'a, 'b>> {
    vec![
        clap::Arg::with_name("tracing-enable").long("tracing-enable"),
        clap::Arg::with_name("tracing-sample-probability")
            .long("tracing-probability")
            .takes_value(true)
            .default_value("0.001"),
    ]
}

lazy_static! {
    static ref GLOBAL_TRACER: Mutex<Option<Tracer>> = Mutex::new(None);
}

pub fn report_forever(service_name: &str, matches: &clap::ArgMatches) {
    let tracer = if matches.is_present("tracing-enable") {
        let (tracer, span_rx) = Tracer::new(
            rustracing::sampler::ProbabilisticSampler::new(value_t_or_exit!(
                matches,
                "tracing-sample-probability",
                f64
            )).unwrap(),
        );
        let reporter =
            rustracing_jaeger::reporter::JaegerCompactReporter::new(service_name).unwrap();

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

pub fn get_tracer() -> Tracer {
    GLOBAL_TRACER
        .lock()
        .unwrap()
        .clone()
        .expect("Getting tracer before initialization")
}

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
