// Copyright 2016 Martin Grabmueller. See the LICENSE file at the
// top-level directory of this distribution for license information.

extern crate cryptopals;

use std::io::BufReader;
use std::io::BufRead;
use std::fs::File;

use cryptopals::{codec, xor};


pub fn main() {
    let f = File::open("data/4.txt").unwrap();
    let reader = BufReader::new(f);

    for (i, l) in reader.lines().enumerate() {
        let line = l.unwrap();
        let decoded = codec::hex::decode(&line).unwrap();
        if let Some((k, decrypted)) = xor::crack_single_byte_xor(&decoded) {
            println!("#{}: {:x}: {:?}", i, k,
                     String::from_utf8_lossy(&decrypted));
        }
    }
}
