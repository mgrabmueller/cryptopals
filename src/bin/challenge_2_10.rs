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
    let mut f = File::open("data/10.txt").unwrap();
    let mut hc = Vec::new();
    let _ = f.read_to_end(&mut hc).unwrap();
    let c = codec::base64::decode(&String::from_utf8(hc).unwrap()).unwrap();

    let keybytes = b"YELLOW SUBMARINE";
    let key = aes::AesKey::Key128(aes::AesKey128{key: to_byte_array_16(keybytes)});
    let iv = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
    
    let decrypted = aes::decrypt_cbc(&key, &iv, &c);
    println!("{}", String::from_utf8_lossy(&decrypted));
}
