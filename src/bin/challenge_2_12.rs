// Copyright 2016 Martin Grabmueller. See the LICENSE file at the
// top-level directory of this distribution for license information.

extern crate cryptopals;

use std::collections::HashSet;
use std::iter::repeat;

use cryptopals::{codec};
use cryptopals::cipher::aes;

fn encrypt(input: &[u8]) -> Vec<u8> {
    let k = [108, 160, 83, 138, 150, 88, 223, 10, 240, 46, 58, 98, 81, 221, 74, 211];
    let key = aes::AesKey::Key128(aes::AesKey128{key: k});
    let suffix = codec::base64::decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
                                        aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
                                        dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\
                                        YnkK").unwrap();
    let mut data = Vec::with_capacity(suffix.len() + input.len());
    data.extend(input);
    data.extend(suffix);
    let res = aes::encrypt_ecb(&key, &data);
    res
}

fn detect_block_size(input: &[u8]) -> usize {
    let mut pad = Vec::new();

    let l1 = encrypt(&pad).len();
    pad.push(b'A');
    let mut l2 = encrypt(&pad).len();
    while l1 == l2 {
        pad.push(b'A');
        l2 = encrypt(&pad).len();
    }
    let len1 = l2;
    while len1 == l2 {
        pad.push(b'A');
        l2 = encrypt(&pad).len();
    }
    l2 - len1
}

fn detect() {
    let input = [0u8,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                 0,0,0,0,0];

    let ciphertext = encrypt(&input);
    if aes::detect_ecb(&ciphertext) {
        println!("ECB encrypted");
        let blocksize = detect_block_size(&ciphertext);
        println!("Block size: {}", blocksize);

        let block: Vec<_> = repeat(b'A').take(blocksize).collect();
        let test: Vec<_> = repeat(b' ').take(blocksize - 1).collect();
        
        let block1 = &encrypt(&test)[0..blocksize];
    } else {
        println!("NOT ECB encrypted - giving up!");
        return;
    }
    println!("{}", codec::hex::encode(&ciphertext));
}

pub fn main() {
    detect();
}
