// Copyright 2016 Martin Grabmueller. See the LICENSE file at the
// top-level directory of this distribution for license information.

extern crate cryptopals;

use cryptopals::{codec, xor};

pub fn main() {
    let b0 = codec::hex::decode("1c0111001f010100061a024b53535009181c").unwrap();
    let b1 = codec::hex::decode("686974207468652062756c6c277320657965").unwrap();
    let expected = codec::hex::decode("746865206b696420646f6e277420706c6179").unwrap();
    assert_eq!(expected, xor::xor_bytes(&b0, &b1));
    println!("Success.");
}
