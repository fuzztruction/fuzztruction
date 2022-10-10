// This test program is used in the tests in src/lib.rs
use std::io::{self, Read};

fn main() {
    // Wait to exit until stdin is closed.
    let mut buf = vec![];
    io::stdin().read_to_end(&mut buf).unwrap();
}
