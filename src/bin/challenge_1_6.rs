// Copyright 2016 Martin Grabmueller. See the LICENSE file at the
// top-level directory of this distribution for license information.

extern crate cryptopals;

use std::fs::File;
use std::io::Read;

use cryptopals::{codec, xor};

pub fn main() {
    let mut f = File::open("data/6.txt").unwrap();
    let mut hc = Vec::new();
    let _ = f.read_to_end(&mut hc).unwrap();
    let c = codec::base64::decode(&String::from_utf8(hc).unwrap()).unwrap();

    for &(ref key, ref decoded) in xor::crack_repeating_xor(&c).iter().take(1) {
        println!("key: {:?}", String::from_utf8_lossy(&key));
        println!("decoded: {}", String::from_utf8_lossy(&decoded));
    }
}
