// Copyright 2016 Martin Grabmueller. See the LICENSE file at the
// top-level directory of this distribution for license information.

extern crate cryptopals;

use cryptopals::padding::pkcs7;

pub fn main() {
    let input = b"YELLOW SUB";
    let output = pkcs7::pad(input, 16);
    let mut expected: Vec<u8> = Vec::new();
    expected.extend(b"YELLOW SUB\x06\x06\x06\x06\x06\x06");
    assert_eq!(expected, output);
    println!("Success.");
}
