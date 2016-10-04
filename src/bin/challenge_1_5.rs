// Copyright 2016 Martin Grabmueller. See the LICENSE file at the
// top-level directory of this distribution for license information.

extern crate cryptopals;

use cryptopals::{codec, xor};

pub fn main() {
    let input = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    let key = b"ICE";
    let expected = codec::hex::decode("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f").unwrap();
    assert_eq!(expected, xor::repeating(key, input));
    println!("Success.");
}
