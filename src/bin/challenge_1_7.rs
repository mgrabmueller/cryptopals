// Copyright 2016 Martin Grabmueller. See the LICENSE file at the
// top-level directory of this distribution for license information.

extern crate cryptopals;

use std::fs::File;
use std::io::Read;

use cryptopals::{codec};
use cryptopals::cipher::aes;

// From
// http://stackoverflow.com/questions/25428920/how-to-get-a-slice-as-an-array-in-rust
fn to_byte_array_16(slice: &[u8]) -> [u8; 16] {
    let mut array = [0u8; 16];
    for (&x, p) in slice.iter().zip(array.iter_mut()) {
        *p = x;
    }
    array
}

pub fn main() {
    let mut f = File::open("data/7.txt").unwrap();
    let mut hc = Vec::new();
    let _ = f.read_to_end(&mut hc).unwrap();
    let c = codec::base64::decode(&String::from_utf8(hc).unwrap()).unwrap();

    let keybytes = b"YELLOW SUBMARINE";
    let key = aes::AesKey::Key128(aes::AesKey128{key: to_byte_array_16(keybytes)});

    let mut decrypted: Vec<u8> = Vec::with_capacity(c.len());
    for chunk in c.chunks(16) {
        let mut output = [0u8; 16];
        aes::decrypt(&key, &to_byte_array_16(&chunk), &mut output);
        decrypted.extend(output.iter());
    }
    let dec_len = decrypted.len();
    let pad_len = decrypted[dec_len-1] as usize;
    decrypted.truncate(dec_len - pad_len);
    println!("{}", String::from_utf8_lossy(&decrypted));
}
