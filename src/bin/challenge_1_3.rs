// Copyright 2016 Martin Grabmueller. See the LICENSE file at the
// top-level directory of this distribution for license information.

extern crate cryptopals;

use cryptopals::{codec, xor};

pub fn main() {
    let input = codec::hex::decode("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736").unwrap();
    let res = xor::crack_single_byte_xor(&input);
    assert_eq!(Some(88), res);
    println!("Success.");
}
