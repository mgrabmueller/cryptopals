// Copyright 2016 Martin Grabmueller. See the LICENSE file at the
// top-level directory of this distribution for license information.

extern crate cryptopals;

use std::fs::File;
use std::io::Read;

use cryptopals::{codec};

pub fn main() {
    let mut f = File::open("data/10.txt").unwrap();
    let mut hc = Vec::new();
    let _ = f.read_to_end(&mut hc).unwrap();
    let c = codec::base64::decode(&String::from_utf8(hc).unwrap()).unwrap();

    // TODO: AES-CBC.
    println!("Success.");
}
