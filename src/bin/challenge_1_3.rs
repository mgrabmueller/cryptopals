// Copyright 2016 Martin Grabmueller. See the LICENSE file at the
// top-level directory of this distribution for license information.

extern crate cryptopals;

use cryptopals::{codec, xor};

pub fn main() {
    let input = codec::hex::decode("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736").unwrap();
    let res = xor::crack_single_byte_xor(&input).unwrap();
    assert_eq!((88, vec![67, 111, 111, 107, 105, 110, 103, 32,
                         77, 67, 39, 115, 32, 108, 105, 107, 101,
                         32, 97, 32, 112, 111, 117, 110, 100, 32,
                         111, 102, 32, 98, 97, 99, 111, 110]), res);
    println!("Success.");
}
