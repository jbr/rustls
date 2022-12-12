use bencher::{benchmark_group, benchmark_main, Bencher};

#[allow(dead_code)]
mod common;
use crate::common::*;

use rustls::ServerConnection;

use std::io;
use std::sync::Arc;

fn bench_ewouldblock(c: &mut Bencher) {
    let server_config = make_server_config(KeyType::Rsa);
    let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();
    let mut read_ewouldblock = FailsReads::new(io::ErrorKind::WouldBlock);
    c.iter(|| server.read_tls(&mut read_ewouldblock));
}

benchmark_group!(benches, bench_ewouldblock);
benchmark_main!(benches);
