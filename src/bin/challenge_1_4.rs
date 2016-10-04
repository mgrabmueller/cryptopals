// Copyright 2016 Martin Grabmueller. See the LICENSE file at the
// top-level directory of this distribution for license information.

extern crate cryptopals;

use std::io::BufReader;
use std::io::BufRead;
use std::fs::File;

use cryptopals::{codec};


pub fn main() {
    let f = File::open("data/4.txt").unwrap();
    let reader = BufReader::new(f);

    for l in reader.lines() {
        let line = l.unwrap();
        println!("{} => {:?}", line, codec::hex::decode(&line).unwrap());
    }
}