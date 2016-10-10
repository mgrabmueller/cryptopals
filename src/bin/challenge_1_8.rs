// Copyright 2016 Martin Grabmueller. See the LICENSE file at the
// top-level directory of this distribution for license information.

extern crate cryptopals;

use std::collections::HashSet;
use std::io::BufReader;
use std::io::BufRead;
use std::fs::File;

use cryptopals::codec;

pub fn main() {
    let f = File::open("data/8.txt").unwrap();
    let reader = BufReader::new(f);

    for (i, l) in reader.lines().enumerate() {
        let line = l.unwrap();
        let decoded = codec::hex::decode(&line).unwrap();

        let mut m = HashSet::new();
        for (j, chunk) in decoded.chunks(16).enumerate() {
            if m.contains(chunk) {
                println!("#{}: repeated ciphertext in chunk {}", i, j);
                for (k, c) in decoded.chunks(16).enumerate() {
                    println!("{}: {} {}", k, codec::hex::encode(c),
                             if j == k { " <===" } else { "" });
                }
                break;
            }
            m.insert(chunk);
        }
    }
    println!("Success.");
}
