#![feature(test)]

extern crate test;

#[macro_use]
extern crate ekiden_instrumentation;
extern crate ekiden_instrumentation_prometheus;

fn maybe_init() {
    drop(ekiden_instrumentation_prometheus::init());
}

#[bench]
fn benchmark_counter(b: &mut test::Bencher) {
    maybe_init();

    b.iter(|| {
        measure_counter_inc!("my_counter");
    });
}

#[bench]
fn benchmark_gauge(b: &mut test::Bencher) {
    maybe_init();

    b.iter(|| {
        measure_gauge!("my_gauge", 42);
    });
}

#[bench]
fn benchmark_histogram(b: &mut test::Bencher) {
    maybe_init();

    b.iter(|| {
        measure_histogram!("my_histogram", 42);
    });
}
