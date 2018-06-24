#[macro_use]
extern crate genet_sdk;
extern crate genet_abi;

#[macro_use]
extern crate lazy_static;

use genet_sdk::{
    context::Context,
    io::{Reader, ReaderWorker},
    layer::{Layer, LayerClass},
    ptr::Ptr,
    result::Result,
};
use std::iter;

pub fn tcp_ipv4_pcap() -> &'static [u8] {
    &[
        0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x33, 0xf6, 0x7e, 0x58, 0x88, 0x65,
        0x0d, 0x00, 0x42, 0x00, 0x00, 0x00, 0x42, 0x00, 0x00, 0x00, 0xac, 0xbc, 0x32, 0xbc, 0x2a,
        0x87, 0x80, 0x13, 0x82, 0x62, 0xa2, 0x45, 0x08, 0x00, 0x45, 0x00, 0x00, 0x34, 0x69, 0xaf,
        0x40, 0x00, 0x31, 0x06, 0x01, 0xf7, 0xca, 0xe8, 0xee, 0x28, 0xc0, 0xa8, 0x64, 0x64, 0x00,
        0x50, 0xc4, 0x27, 0x22, 0xdd, 0xb1, 0xc0, 0x63, 0x6a, 0x47, 0x9b, 0x80, 0x10, 0x00, 0x72,
        0xf7, 0x6c, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0xf9, 0x28, 0x89, 0x4f, 0x61, 0x8f, 0x78,
        0x9d,
    ]
}

#[derive(Clone)]
struct TestReader {}

impl Reader for TestReader {
    fn new_worker(&self, ctx: &Context, arg: &str) -> Box<ReaderWorker> {
        Box::new(TestReaderWorker {})
    }

    fn id(&self) -> &str {
        "test-input"
    }
}

struct TestReaderWorker {}

impl ReaderWorker for TestReaderWorker {
    fn read(&mut self) -> Result<Vec<Layer>> {
        let layers = iter::repeat(())
            .take(100)
            .map(|_| Layer::new(&ETH_CLASS, tcp_ipv4_pcap()))
            .collect();
        Ok(layers)
    }
}

lazy_static! {
    static ref ETH_CLASS: Ptr<LayerClass> = LayerClass::new(token!("[link-1]"));
}

genet_readers!(TestReader {});
