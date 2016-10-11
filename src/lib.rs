// Copyright 2016 Martin Grabmueller. See the LICENSE file at the
// top-level directory of this distribution for license information.

//! This crate contains various helper routines for solving the
//! Cryptopals Crypto Challenges at https://cryptopals.com.

#[cfg(test)]
#[macro_use]
extern crate quickcheck;
extern crate byteorder;
extern crate rand;

pub mod error;
pub mod codec;
pub mod xor;
pub mod distance;
pub mod language;
pub mod cipher;
pub mod padding;

pub mod random {
    pub fn fill_bytes(buffer: &mut [u8]) {
        use ::rand::Rng;
        let mut rng = ::rand::thread_rng();
        rng.fill_bytes(buffer);
    }
}
