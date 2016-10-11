// Copyright 2016 Martin Grabmueller. See the LICENSE file at the
// top-level directory of this distribution for license information.

extern crate cryptopals;

use cryptopals::{random};
use cryptopals::cipher::aes;

fn rand_vec(low: usize, high: usize) -> Vec<u8> {
    let len = random::gen_range(low, high);
    let mut result: Vec<u8> = Vec::with_capacity(len);
    for _ in 0..len {
        result.push(random::gen());
    }
    result
}

fn encryption_oracle(input: &[u8]) -> Vec<u8> {
    let key = random_aes_key();
    let b = random::gen();
    let prefix = rand_vec(5, 11);
    let suffix = rand_vec(5, 11);
    let mut data = Vec::with_capacity(prefix.len() + suffix.len() + input.len());
    data.extend(prefix);
    data.extend(input);
    data.extend(suffix);
//    println!("{}", ::cryptopals::codec::hex::encode(&data));
    if b {
        let res = aes::encrypt_ecb(&key, &data);
//        println!("{}", ::cryptopals::codec::hex::encode(&res));
        res
    } else {
        let mut iv = [0u8; 16];
        random::fill_bytes(&mut iv[..]);
        let res = aes::encrypt_cbc(&key, &iv, &data);
//        println!("{}", ::cryptopals::codec::hex::encode(&res));
        res
    }
}

fn random_aes_key() -> aes::AesKey {
    let mut k = [0u8; 16];
    random::fill_bytes(&mut k[..]);
    aes::AesKey::Key128(aes::AesKey128{key: k})
}

fn detect(trial: usize) {
    let input = [0u8,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];

    let ciphertext = encryption_oracle(&input);
    if aes::detect_ecb(&ciphertext) {
        println!("Trial #{}: detected ECB", trial);
    } else {
        println!("Trial #{}: NOT detected ECB", trial);
    }
}

pub fn main() {
    for i in 0..20 {
        detect(i);
    }
}
