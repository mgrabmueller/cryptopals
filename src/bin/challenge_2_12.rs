// Copyright 2016 Martin Grabmueller. See the LICENSE file at the
// top-level directory of this distribution for license information.

extern crate cryptopals;

use std::collections::HashMap;
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

/// Detect the block size of the block cipher that was used to encrypt
/// `input`.  We assume that ECB mode was used.
fn detect_block_size() -> usize {
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

fn make_dict(blocksize: usize, decoded_prefix: Vec<u8>) -> HashMap<Vec<u8>, u8> {
    let pfx_len = decoded_prefix.len();
    let mut hm = HashMap::new();
    let mut v = Vec::with_capacity(blocksize);
    v.extend(decoded_prefix.iter()
             .skip(pfx_len - (blocksize-1)));
    v.extend(b"?");

    for u in 0usize..256 {
        v[blocksize-1] = u as u8;
        let mut ct = encrypt(&v);
        let mut ct1 = ct.split_off(0);
        ct1.truncate(blocksize);
        hm.insert(ct1, u as u8);
    }
    hm
}

//82, R

fn detect() {
    let input = [0u8,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                 0,0,0,0,0];

    let ciphertext = encrypt(&input);
    if aes::detect_ecb(&ciphertext) {
        println!("ECB encrypted");
        let blocksize = detect_block_size();
        println!("Block size: {}", blocksize);
        let ctx = encrypt(b"");
        let blocks = ctx.len() / blocksize;
        println!("Block count: {}", blocks);

        let mut decoded_prefix: Vec<u8> = repeat(b'A').take(blocksize).collect();
        let mut pfx_offset = 1;
        'outer:
        for block_cnt in 0..blocks {
            for i in 0..16 {

                let hm = make_dict(blocksize, decoded_prefix.clone());
                let cipher = {
                    let test = &decoded_prefix[pfx_offset..pfx_offset+(blocksize-i-1)];

                    encrypt(test)
                };
                let start = block_cnt*blocksize;
                let block1 = &cipher[start..start+blocksize];
                if let Some(plain) = hm.get(block1) {
                    decoded_prefix.push(*plain);
                    pfx_offset += 1;
                } else {
                    println!("Could not find block.");
                    break 'outer;
                }
            }
        }

        println!("");
        let padlen = decoded_prefix[decoded_prefix.len()-1] as usize;
        let mut result: Vec<_> = decoded_prefix.into_iter().skip(blocksize).collect();
        let reslen = result.len();
        result.truncate(reslen - padlen);
        println!("Decoded: {}", String::from_utf8_lossy(&result));
    } else {
        println!("NOT ECB encrypted - giving up!");
        return;
    }
}

// ollin' in my 5.
// ollin' in my 5.R|ollin' in my 5.?
pub fn main() {
    detect();
}
