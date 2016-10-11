// Copyright 2016 Martin Grabmueller. See the LICENSE file at the
// top-level directory of this distribution for license information.

//! Example implementation of AES (the Advanced Encryption Standard).
//! Note that this implementation has neither been verified to be
//! correct, nor to be secure. Do not use it for production!
//!
//! The implementation of the basic block-sized AES is based on the
//! one in Joshua Davies: "Implementing SSL/TLS (Using Cryptography
//! and PKI)", Wiley Publishing Inc., 2011.  The cipher modes EBC, CBC
//! and CTR have been implemented from scratch.

use std::collections::HashSet;
use std::io::Cursor;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

/// Key for AES cipher.  This comes in three sizes: 128, 192 and 256
/// bytes.
pub enum AesKey {
    /// 128-bit key.
    Key128(AesKey128),
    /// 192-bit key.
    Key192(AesKey192),
    /// 256-bit key.
    Key256(AesKey256),
}

/// Container for 128-bit value to be used as an AES key.
pub struct AesKey128 {
    /// Raw key material.
    pub key: [u8; 16],
}

/// Container for 192-bit value to be used as an AES key.
pub struct AesKey192 {
    /// Raw key material.
    pub key: [u8; 24],
}

/// Container for 256-bit value to be used as an AES key.
pub struct AesKey256 {
    /// Raw key material.
    pub key: [u8; 32],
}

/// `SBOX` implements the sboxes used in the sub_word operation (used
/// in key schedule generation) and sub_bytes operation (used in the
/// encryption rounds).
static SBOX: [[u8; 16]; 16] =
    [[0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
      0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76],
     [0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
      0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0],
     [0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
      0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15],
     [0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
      0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75],
     [0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
      0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84],
     [0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
      0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf],
     [0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
      0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8],
     [0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
      0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2],
     [0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
      0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73],
     [0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
      0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb],
     [0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
      0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79],
     [0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
      0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08],
     [0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
      0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a],
     [0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
      0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e],
     [0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
      0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf],
     [0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
      0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]
    ];

/// `INV_SBOX` implements the inverse of `SBOX` and is used in
/// decryption.
static INV_SBOX: [[u8; 16]; 16] =
    [[0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
      0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb],
     [0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
      0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb],
     [0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d,
      0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e],
     [0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2,
      0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25],
     [0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
      0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92],
     [0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
      0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84],
     [0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a,
      0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06],
     [0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
      0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b],
     [0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea,
      0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73],
     [0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85,
      0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e],
     [0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
      0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b],
     [0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20,
      0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4],
     [0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31,
      0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f],
     [0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
      0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef],
     [0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0,
      0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61],
     [0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26,
      0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d]
    ];

/// rot_word operation.  This is used in generation the key schedule.
fn rot_word(w: &mut [u8; 4]) {
    let tmp = w[0];
    w[0] = w[1];
    w[1] = w[2];
    w[2] = w[3];
    w[3] = tmp;
}

// sub_word operation.  This is used in generating the key schedule.
fn sub_word(w: &mut [u8; 4]) {
    for i in 0..4 {
        w[i] = SBOX[((w[i] & 0xf0) >> 4) as usize][(w[i] & 0x0f) as usize];
    }
}

/// Derive the key schedule from the input key, which may be 16, 24 or
/// 32 bytes in length.  The length of `w` depends on the key length.
/// On return, `w` contains the round keys (10 for AES-128, 12 for
/// AES-192 and 14 for AES-256).
fn compute_key_schedule(key: &[u8], w: &mut [[u8; 4]]) {
    let keylength = key.len();
    let keywords = keylength / 4;
    let mut rcon = 0x01;
    for i in 0..keylength {
        w[i / 4][i % 4] = key[i];
    }
    for i in keywords..4*(keywords+7) {
        w[i] = w[i-1];
        if i % keywords == 0 {
            rot_word(&mut w[i]);
            sub_word(&mut w[i]);
            if i % 36 == 0 {
                rcon = 0x1b;
            }
            w[i][0] ^= rcon;
            rcon <<= 1;
        } else if keywords > 6 && i % keywords == 4 {
            sub_word(&mut w[i]);
        }
        w[i][0] ^= w[i - keywords][0];            
        w[i][1] ^= w[i - keywords][1];
        w[i][2] ^= w[i - keywords][2];
        w[i][3] ^= w[i - keywords][3];            
    }
}

/// XOR the round key `w` with the state.
fn add_round_key(state: &mut [[u8; 4]; 4], w: &[[u8;4]]) {
    for c in 0..4 {
        for r in 0..4 {
            state[r][c] = state[r][c] ^ w[c][r];
        }
    }
}

/// Perform SBOX substitution on the state.
fn sub_bytes(state: &mut [[u8; 4]]) {
    for r in 0..4 {
        for c in 0..4 {
            state[r][c] = SBOX[((state[r][c] & 0xf0) >> 4) as usize]
                [(state[r][c] & 0x0f) as usize];
        }
    }
}

/// Perform the shift_rows operation on the state.
fn shift_rows(state: &mut [[u8; 4]]) {
    let tmp = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = tmp;

    let tmp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = tmp;
    let tmp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = tmp;

    let tmp = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = state[3][0];
    state[3][0] = tmp;
}

fn xtime(x: u8) -> u8 {
    (x << 1) ^ (if x & 0x80 != 0 { 0x1b } else { 0x00 })
}

fn dot(xin: u8, y: u8) -> u8 {
    let mut x = xin;
    let mut product = 0;
    let mut mask = 0x01;
    while mask != 0 {
        if y & mask != 0 {
            product ^= x;
        }
        x = xtime(x);
        mask <<= 1;
    }
    product
}

/// Perform the mix_columns operation on the state.
fn mix_columns(s: &mut [[u8; 4]]) {
    let mut t = [0u8; 4];
    for c in 0..4 {
        t[0] = dot(2, s[0][c]) ^ dot(3, s[1][c]) ^ s[2][c] ^ s[3][c];
        t[1] = s[0][c] ^ dot(2, s[1][c]) ^ dot(3, s[2][c]) ^ s[3][c];
        t[2] = s[0][c] ^ s[1][c] ^ dot(2, s[2][c]) ^ dot(3, s[3][c]);
        t[3] = dot(3, s[0][c]) ^ s[1][c] ^ s[2][c] ^ dot(2, s[3][c]);
        s[0][c] = t[0];
        s[1][c] = t[1];
        s[2][c] = t[2];
        s[3][c] = t[3];
    }
}

/// Perform the encryption of one block. `w` is the key schedule, `nr`
/// the number of rounds and `input` and `output` are the in- and
/// output blocks, respectively.
fn encrypt_block(w: &[[u8; 4]], nr: usize, input: &[u8; 16], output: &mut [u8; 16]) {
    let mut state = [[0u8; 4]; 4];

    for r in 0..4 {
        for c in 0..4 {
            state[r][c] = input[r + (4 * c)];
        }
    }

    add_round_key(&mut state, &w[0..4]);

    for round in 0..nr {
        sub_bytes(&mut state);
        shift_rows(&mut state);
        if round < nr-1 {
            mix_columns(&mut state);
        }
        add_round_key(&mut state, &w[(round+1)*4..(round+2)*4]);
    }
    for r in 0..4 {
        for c in 0..4 {
            output[r + (4 * c)] = state[r][c];
        }
    }
}

/// Encrypt the plaintext block `input` with AES, using the given key.
/// The ciphertext output is placed in `output`.
pub fn encrypt(key: &AesKey, input: &[u8; 16], output: &mut [u8; 16]) {
    let (keysize, keybytes): (usize, Vec<_>) = match key {
        &AesKey::Key128(AesKey128 {key}) => (16, key[..].iter().cloned().collect()),
        &AesKey::Key192(AesKey192 {key}) => (24, key[..].iter().cloned().collect()),
        &AesKey::Key256(AesKey256 {key}) => (32, key[..].iter().cloned().collect()),
    };
    let mut w = [[0u8; 4]; 60];

    let nr = (keysize >> 2) + 6;
    compute_key_schedule(&keybytes, &mut w);

    encrypt_block(&w, nr, input, output);
}

/// Encrypt the arbitrary-length plaintext block `input` with AES in
/// ECB mode, using the given key.  The ciphertext output is returned
/// as a vector of bytes.
pub fn encrypt_ecb(key: &AesKey, plaintext: &[u8]) -> Vec<u8> {
    let (keysize, keybytes): (usize, Vec<_>) = match key {
        &AesKey::Key128(AesKey128 {key}) => (16, key[..].iter().cloned().collect()),
        &AesKey::Key192(AesKey192 {key}) => (24, key[..].iter().cloned().collect()),
        &AesKey::Key256(AesKey256 {key}) => (32, key[..].iter().cloned().collect()),
    };
    let mut w = [[0u8; 4]; 60];
    let padded_plaintext = ::padding::pkcs7::pad(&plaintext, 16);
    let mut result = Vec::with_capacity(padded_plaintext.len());

    let nr = (keysize >> 2) + 6;
    compute_key_schedule(&keybytes, &mut w);
    let mut input = [0u8; 16];
    let mut output = [0u8; 16];
    for chunk in padded_plaintext.chunks(16) {
        for x in 0..16 {
            input[x] = chunk[x];
        }
        encrypt_block(&w, nr, &input, &mut output);
        for x in 0..16 {
            result.push(output[x]);
        }
    }
    result
}

/// Encrypt the arbitrary-length plaintext block `input` with AES in
/// CBC mode, using the given key and initialization vector.  The
/// ciphertext output is returned as a vector of bytes.
pub fn encrypt_cbc(key: &AesKey, iv: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
    let (keysize, keybytes): (usize, Vec<_>) = match key {
        &AesKey::Key128(AesKey128 {key}) => (16, key[..].iter().cloned().collect()),
        &AesKey::Key192(AesKey192 {key}) => (24, key[..].iter().cloned().collect()),
        &AesKey::Key256(AesKey256 {key}) => (32, key[..].iter().cloned().collect()),
    };
    let mut w = [[0u8; 4]; 60];
    let padded_plaintext = ::padding::pkcs7::pad(&plaintext, 16);
    let mut result = Vec::with_capacity(padded_plaintext.len());

    let nr = (keysize >> 2) + 6;
    compute_key_schedule(&keybytes, &mut w);
    let mut input = [0u8; 16];
    let mut output = [0u8; 16];
    let mut r = *iv;
    for chunk in padded_plaintext.chunks(16) {
        for x in 0..16 {
            input[x] = chunk[x] ^ r[x];
        }
        encrypt_block(&w, nr, &input, &mut output);
        for x in 0..16 {
            result.push(output[x]);
        }
        r = output;
    }
    result
}

/// Encrypt the arbitrary-length plaintext block `input` with AES in
/// CBC mode, using the given key and initialization vector.  The
/// ciphertext output is returned as a vector of bytes.
///
/// Note that this implementation uses the most significant 64 bits of
/// the IV as a nonce, and the least significant 64 bits as the
/// initial counter value.  To produce the input to the block cipher,
/// the nonce is encoded in big-endian format and concatenated with
/// a 64-bit counter, also encoded in big-endian format.
pub fn encrypt_ctr(key: &AesKey, iv: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
    let (keysize, keybytes): (usize, Vec<_>) = match key {
        &AesKey::Key128(AesKey128 {key}) => (16, key[..].iter().cloned().collect()),
        &AesKey::Key192(AesKey192 {key}) => (24, key[..].iter().cloned().collect()),
        &AesKey::Key256(AesKey256 {key}) => (32, key[..].iter().cloned().collect()),
    };
    let mut w = [[0u8; 4]; 60];
    let mut result = Vec::with_capacity(plaintext.len());
    let mut rdr = Cursor::new(iv);
    let nonce = rdr.read_u64::<BigEndian>().unwrap();
    let mut ctr = rdr.read_u64::<BigEndian>().unwrap();
    
    let nr = (keysize >> 2) + 6;
    compute_key_schedule(&keybytes, &mut w);
    let mut input = [0u8; 16];
    let mut output = [0u8; 16];

    let mut wtr = vec![];
    for chunk in plaintext.chunks(16) {
        wtr.truncate(0);
        wtr.write_u64::<BigEndian>(nonce).unwrap();
        wtr.write_u64::<BigEndian>(ctr).unwrap();
        ctr += 1;
        for x in 0..16 {
            input[x] = wtr[x];
        }
        encrypt_block(&w, nr, &input, &mut output);
        for x in 0..chunk.len() {
            result.push(chunk[x] ^ output[x]);
        }
    }
    result
}

/// Inverse of the shift_rows operation, used in decryption.
fn inv_shift_rows(state: &mut [[u8; 4]; 4]) {
    let tmp = state[1][2];
    state[1][2] = state[1][1];
    state[1][1] = state[1][0];
    state[1][0] = state[1][3];
    state[1][3] = tmp;

    let tmp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = tmp;
    let tmp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = tmp;

    let tmp = state[3][0];
    state[3][0] = state[3][1];
    state[3][1] = state[3][2];
    state[3][2] = state[3][3];
    state[3][3] = tmp;
}

/// Inverse of the sub_bytes operation, used in decryption.
fn inv_sub_bytes(state: &mut [[u8; 4]; 4]) {
    for r in 0..4 {
        for c in 0..4 {
            state[r][c] = INV_SBOX[((state[r][c] & 0xf0) >> 4) as usize]
                [(state[r][c] & 0x0f) as usize];
        }
    }
}

/// Inverse of the mix_columns operation, used in decryption.
fn inv_mix_columns(s: &mut [[u8; 4]; 4]) {
    let mut t = [0u8; 4];
    for c in 0..4 {
        t[0] = dot(0x0e, s[0][c]) ^ dot(0x0b, s[1][c]) ^
            dot(0x0d, s[2][c]) ^ dot(0x09, s[3][c]);
        t[1] = dot(0x09, s[0][c]) ^ dot(0x0e, s[1][c]) ^
            dot(0x0b, s[2][c]) ^ dot(0x0d, s[3][c]);
        t[2] = dot(0x0d, s[0][c]) ^ dot(0x09, s[1][c]) ^
            dot(0x0e, s[2][c]) ^ dot(0x0b, s[3][c]);
        t[3] = dot(0x0b, s[0][c]) ^ dot(0x0d, s[1][c]) ^
            dot(0x09, s[2][c]) ^ dot(0x0e, s[3][c]);
        s[0][c] = t[0];
        s[1][c] = t[1];
        s[2][c] = t[2];
        s[3][c] = t[3];
    }
}

/// Perform the encryption of one block. `w` is the key schedule, `nr`
/// the number of rounds and `input` and `output` are the in- and
/// output blocks, respectively.
fn decrypt_block(w: &[[u8; 4]], nr: usize, input: &[u8; 16], output: &mut [u8; 16]) {
    let mut state = [[0u8; 4]; 4];
    for r in 0..4 {
        for c in 0..4 {
            state[r][c] = input[r + (4 * c)];
        }
    }

    add_round_key(&mut state, &w[nr*4..(nr+1)*4]);

    let mut round = nr;
    while round > 0 {
        inv_shift_rows(&mut state);
        inv_sub_bytes(&mut state);
        add_round_key(&mut state, &w[(round-1)*4..(round)*4]);
        if round > 1 {
            inv_mix_columns(&mut state);
        }
        round -= 1;
    }
    for r in 0..4 {
        for c in 0..4 {
            output[r + (4 * c)] = state[r][c];
        }
    }
}

/// Decrypt the ciphertext block `input` with AES, using the given
/// key.  The plaintext output is placed in `output`.
pub fn decrypt(key: &AesKey, input: &[u8; 16], output: &mut [u8; 16]) {
    let (keysize, keybytes): (usize, Vec<_>) = match key {
        &AesKey::Key128(AesKey128 {key}) => (16, key[..].iter().cloned().collect()),
        &AesKey::Key192(AesKey192 {key}) => (24, key[..].iter().cloned().collect()),
        &AesKey::Key256(AesKey256 {key}) => (32, key[..].iter().cloned().collect()),
    };
    let mut w = [[0u8; 4]; 60];

    let nr = (keysize >> 2) + 6;
    compute_key_schedule(&keybytes, &mut w);

    decrypt_block(&w, nr, input, output);
}

/// Decrypt the ciphertext block `input` with AES in ECB mode, using
/// the given key.  The plaintext output is returned as a byte vector
pub fn decrypt_ecb(key: &AesKey, ciphertext: &[u8]) -> Vec<u8> {
    let (keysize, keybytes): (usize, Vec<_>) = match key {
        &AesKey::Key128(AesKey128 {key}) => (16, key[..].iter().cloned().collect()),
        &AesKey::Key192(AesKey192 {key}) => (24, key[..].iter().cloned().collect()),
        &AesKey::Key256(AesKey256 {key}) => (32, key[..].iter().cloned().collect()),
    };
    let mut w = [[0u8; 4]; 60];
    let mut result = Vec::with_capacity(ciphertext.len());

    let nr = (keysize >> 2) + 6;
    compute_key_schedule(&keybytes, &mut w);

    let mut input = [0u8; 16];
    let mut output = [0u8; 16];
    for chunk in ciphertext.chunks(16) {
        for x in 0..16 {
            input[x] = chunk[x];
        }
        decrypt_block(&w, nr, &input, &mut output);
        for x in 0..16 {
            result.push(output[x]);
        }
    }
    let res_len = result.len();
    let padding_len = result[res_len - 1] as usize;
    result.truncate(res_len - padding_len);
    result
}

/// Decrypt the ciphertext block `input` with AES in ECB mode, using
/// the given key.  The plaintext output is returned as a byte vector
pub fn decrypt_cbc(key: &AesKey, iv: &[u8; 16], ciphertext: &[u8]) -> Vec<u8> {
    let (keysize, keybytes): (usize, Vec<_>) = match key {
        &AesKey::Key128(AesKey128 {key}) => (16, key[..].iter().cloned().collect()),
        &AesKey::Key192(AesKey192 {key}) => (24, key[..].iter().cloned().collect()),
        &AesKey::Key256(AesKey256 {key}) => (32, key[..].iter().cloned().collect()),
    };
    let mut w = [[0u8; 4]; 60];
    let mut result = Vec::with_capacity(ciphertext.len());

    let nr = (keysize >> 2) + 6;
    compute_key_schedule(&keybytes, &mut w);

    let mut input = [0u8; 16];
    let mut output = [0u8; 16];
    let mut r = *iv;
    for chunk in ciphertext.chunks(16) {
        for x in 0..16 {
            input[x] = chunk[x];
        }
        decrypt_block(&w, nr, &input, &mut output);
        for x in 0..16 {
            result.push(output[x] ^ r[x]);
        }
        r = input;
    }
    let res_len = result.len();
    let padding_len = result[res_len - 1] as usize;
    result.truncate(res_len - padding_len);
    result
}

/// Decrypt the ciphertext block `input` with AES in ECB mode, using
/// the given key.  The plaintext output is returned as a byte vector
pub fn decrypt_ctr(key: &AesKey, iv: &[u8; 16], ciphertext: &[u8]) -> Vec<u8> {
    let (keysize, keybytes): (usize, Vec<_>) = match key {
        &AesKey::Key128(AesKey128 {key}) => (16, key[..].iter().cloned().collect()),
        &AesKey::Key192(AesKey192 {key}) => (24, key[..].iter().cloned().collect()),
        &AesKey::Key256(AesKey256 {key}) => (32, key[..].iter().cloned().collect()),
    };
    let mut w = [[0u8; 4]; 60];
    let mut result = Vec::with_capacity(ciphertext.len());
    let mut rdr = Cursor::new(iv);
    let nonce = rdr.read_u64::<BigEndian>().unwrap();
    let mut ctr = rdr.read_u64::<BigEndian>().unwrap();
    
    let nr = (keysize >> 2) + 6;
    compute_key_schedule(&keybytes, &mut w);
    let mut input = [0u8; 16];
    let mut output = [0u8; 16];

    let mut wtr = vec![];
    for chunk in ciphertext.chunks(16) {
        wtr.truncate(0);
        wtr.write_u64::<BigEndian>(nonce).unwrap();
        wtr.write_u64::<BigEndian>(ctr).unwrap();
        ctr += 1;
        for x in 0..16 {
            input[x] = wtr[x];
        }
        encrypt_block(&w, nr, &input, &mut output);
        for x in 0..chunk.len() {
            result.push(chunk[x] ^ output[x]);
        }
    }
    result
}

pub fn detect_ecb(input: &[u8]) -> bool {
    if input.len() % 16 != 0 {
        return false;
    }
    
    let mut m = HashSet::new();
    for chunk in input.chunks(16) {
        if m.contains(chunk) {
            return true;
        }
        m.insert(chunk);
    }
    false
}

#[cfg(test)]
mod tests {
    use super::{encrypt, decrypt};
    use super::{encrypt_ecb, decrypt_ecb};
    use super::{encrypt_cbc, decrypt_cbc};
    use super::{encrypt_ctr, decrypt_ctr};
    use super::{detect_ecb};
    use super::{AesKey, AesKey128};
    use ::codec;

    // From
    // http://stackoverflow.com/questions/25428920/how-to-get-a-slice-as-an-array-in-rust
    fn to_byte_array_16(slice: &[u8]) -> [u8; 16] {
        let mut array = [0u8; 16];
        for (&x, p) in slice.iter().zip(array.iter_mut()) {
            *p = x;
        }
        array
    }

    #[test]
    fn encrypt_0() {
        let input = b"YELLOW SUBMARINE";
        let mut output = [0u8; 16];
        let expected = codec::hex::decode("761ab98c7086c509261f322cb3ffa7d9").unwrap();

        let keybytes = codec::hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let key = AesKey::Key128(AesKey128{key: to_byte_array_16(&keybytes)});

        encrypt(&key, input, &mut output);
        assert_eq!(expected, output);
    }

    #[test]
    fn decrypt_0() {
        let input = codec::hex::decode("761ab98c7086c509261f322cb3ffa7d9").unwrap();
        let mut output = [0u8; 16];
        let expected = b"YELLOW SUBMARINE";

        let keybytes = codec::hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let key = AesKey::Key128(AesKey128{key: to_byte_array_16(&keybytes)});

        decrypt(&key, &to_byte_array_16(&input), &mut output);
        assert_eq!(to_byte_array_16(expected), output);
    }

    #[test]
    fn decrypt_encrypt_0() {
        let input = b"YELLOW SUBMARINE";
        let mut output = [0u8; 16];

        let keybytes = codec::hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let key = AesKey::Key128(AesKey128{key: to_byte_array_16(&keybytes)});

        encrypt(&key, input, &mut output);
        let mut decrypted = [0u8; 16];
        decrypt(&key, &output, &mut decrypted);
        assert_eq!(to_byte_array_16(input), decrypted);
    }

    #[test]
    fn encrypt_ecb_0() {
        let plaintext = b"Cooller";
        let keybytes = codec::hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let key = AesKey::Key128(AesKey128{key: to_byte_array_16(&keybytes)});
        let expected = vec![40, 80, 126, 246, 153, 18, 246, 8, 200, 113,
                            212, 145, 203, 140, 137, 97];
            
        let ciphertext = encrypt_ecb(&key, plaintext);
        assert_eq!(expected, ciphertext);
    }

    #[test]
    fn encrypt_ecb_1() {
        let plaintext = b"This is an example text for testing encryption and decryption.\n";
        let keybytes = codec::hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let key = AesKey::Key128(AesKey128{key: to_byte_array_16(&keybytes)});
        let expected = vec![0xdd, 0xd0, 0x52, 0x5b, 0xdb, 0x4f, 0x1b, 0x3e,
                            0x66, 0xa7, 0x4f, 0x29, 0x08, 0x25, 0x01, 0x5d,
                            0x25, 0x86, 0xd6, 0xde, 0x47, 0x6a, 0x68, 0xc5,
                            0x02, 0xa4, 0x65, 0x6e, 0x74, 0x5f, 0x17, 0x4c,
                            0x0e, 0x6a, 0x0e, 0x1b, 0x1e, 0xe0, 0xcb, 0x10,
                            0xc4, 0xd0, 0xa2, 0xa6, 0x5d, 0xe8, 0x57, 0xda,
                            0xe3, 0xfa, 0xa5, 0x4d, 0x4e, 0xb2, 0xa5, 0x2e,
                            0xee, 0x5e, 0xc8, 0x2e, 0x69, 0xd9, 0x48, 0x02];
            
        let ciphertext = encrypt_ecb(&key, plaintext);
        assert_eq!(expected, ciphertext);
    }

    #[test]
    fn decrypt_ecb_0() {
        let ciphertext = vec![40, 80, 126, 246, 153, 18, 246, 8, 200, 113,
                              212, 145, 203, 140, 137, 97];
        let expected = vec![b'C', b'o', b'o', b'l', b'l', b'e', b'r'];

        let keybytes = codec::hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let key = AesKey::Key128(AesKey128{key: to_byte_array_16(&keybytes)});

        let plaintext = decrypt_ecb(&key, &ciphertext);
        assert_eq!(&expected, &plaintext);
    }

    #[test]
    fn decrypt_ecb_1() {
        let ciphertext = vec![0xdd, 0xd0, 0x52, 0x5b, 0xdb, 0x4f, 0x1b, 0x3e,
                              0x66, 0xa7, 0x4f, 0x29, 0x08, 0x25, 0x01, 0x5d,
                              0x25, 0x86, 0xd6, 0xde, 0x47, 0x6a, 0x68, 0xc5,
                              0x02, 0xa4, 0x65, 0x6e, 0x74, 0x5f, 0x17, 0x4c,
                              0x0e, 0x6a, 0x0e, 0x1b, 0x1e, 0xe0, 0xcb, 0x10,
                              0xc4, 0xd0, 0xa2, 0xa6, 0x5d, 0xe8, 0x57, 0xda,
                              0xe3, 0xfa, 0xa5, 0x4d, 0x4e, 0xb2, 0xa5, 0x2e,
                              0xee, 0x5e, 0xc8, 0x2e, 0x69, 0xd9, 0x48, 0x02];

        let expected: Vec<_> = b"This is an example text for testing encryption and decryption.\n"
            .iter().cloned().collect();

        let keybytes = codec::hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let key = AesKey::Key128(AesKey128{key: to_byte_array_16(&keybytes)});

        let plaintext = decrypt_ecb(&key, &ciphertext);
        assert_eq!(expected, plaintext);
    }

    #[test]
    fn encrypt_cbc_0() {
        let plaintext = b"Cooller";
        let keybytes = codec::hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let key = AesKey::Key128(AesKey128{key: to_byte_array_16(&keybytes)});
        let iv = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf];
        let expected = vec![184, 150, 45, 131, 33, 100, 210, 30, 247, 102,
                            16, 15, 77, 186, 157, 60];
            
        let ciphertext = encrypt_cbc(&key, &iv, plaintext);
        assert_eq!(expected, ciphertext);
    }

    #[test]
    fn encrypt_cbc_1() {
        let plaintext = b"Need a longer text oh yeah.";
        let keybytes = codec::hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let key = AesKey::Key128(AesKey128{key: to_byte_array_16(&keybytes)});
        let iv = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf];
        let expected = vec![142, 180, 175, 89, 254, 0, 125, 125, 142, 78, 32,
                            224, 101, 202, 49, 247, 146, 217, 135, 92, 254,
                            111, 190, 89, 137, 225, 117, 77, 14, 53, 2, 178];
            
        let ciphertext = encrypt_cbc(&key, &iv, plaintext);
        assert_eq!(expected, ciphertext);
    }

    #[test]
    fn encrypt_cbc_2() {
        let plaintext = b"This is an example text for testing encryption and decryption.\n";
        let keybytes = codec::hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let key = AesKey::Key128(AesKey128{key: to_byte_array_16(&keybytes)});
        let iv = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let expected = vec![0xdd, 0xd0, 0x52, 0x5b, 0xdb, 0x4f, 0x1b, 0x3e,
                            0x66, 0xa7, 0x4f, 0x29, 0x08, 0x25, 0x01, 0x5d,
                            0xfd, 0xdc, 0x12, 0x46, 0xc3, 0xf4, 0x7c, 0xaa,
                            0x85, 0xe4, 0x19, 0x3a, 0x06, 0xdc, 0x14, 0x22,
                            0x82, 0x46, 0x3b, 0x6d, 0xed, 0x3c, 0x55, 0xa6,
                            0x4d, 0x7f, 0x41, 0x83, 0xde, 0x85, 0xe0, 0x17,
                            0x41, 0xef, 0xe7, 0xf5, 0xbf, 0x8f, 0x9f, 0x2a,
                            0x05, 0x36, 0x9e, 0x19, 0x6b, 0x6f, 0x49, 0x6f];
            
        let ciphertext = encrypt_cbc(&key, &iv, plaintext);
        assert_eq!(expected, ciphertext);
    }

    #[test]
    fn decrypt_cbc_0() {
        let ciphertext = vec![142, 180, 175, 89, 254, 0, 125, 125, 142, 78, 32,
                            224, 101, 202, 49, 247, 146, 217, 135, 92, 254,
                            111, 190, 89, 137, 225, 117, 77, 14, 53, 2, 178];
        let expected = vec![78, 101, 101, 100, 32, 97, 32, 108, 111, 110, 103,
                            101, 114, 32, 116, 101, 120, 116, 32, 111, 104,
                            32, 121, 101, 97, 104, 46];

        let keybytes = codec::hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let key = AesKey::Key128(AesKey128{key: to_byte_array_16(&keybytes)});
        let iv = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf];

        let plaintext = decrypt_cbc(&key, &iv, &ciphertext);
        assert_eq!(&expected, &plaintext);
    }

    #[test]
    fn decrypt_cbc_1() {
        let ciphertext = vec![0xdd, 0xd0, 0x52, 0x5b, 0xdb, 0x4f, 0x1b, 0x3e,
                              0x66, 0xa7, 0x4f, 0x29, 0x08, 0x25, 0x01, 0x5d,
                              0xfd, 0xdc, 0x12, 0x46, 0xc3, 0xf4, 0x7c, 0xaa,
                              0x85, 0xe4, 0x19, 0x3a, 0x06, 0xdc, 0x14, 0x22,
                              0x82, 0x46, 0x3b, 0x6d, 0xed, 0x3c, 0x55, 0xa6,
                              0x4d, 0x7f, 0x41, 0x83, 0xde, 0x85, 0xe0, 0x17,
                              0x41, 0xef, 0xe7, 0xf5, 0xbf, 0x8f, 0x9f, 0x2a,
                              0x05, 0x36, 0x9e, 0x19, 0x6b, 0x6f, 0x49, 0x6f];
        let expected: Vec<_> = b"This is an example text for testing encryption and decryption.\n"
            .iter().cloned().collect();

        let keybytes = codec::hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let key = AesKey::Key128(AesKey128{key: to_byte_array_16(&keybytes)});
        let iv = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

        let plaintext = decrypt_cbc(&key, &iv, &ciphertext);
        assert_eq!(&expected, &plaintext);
    }

    #[test]
    fn encrypt_ctr_0() {
        let plaintext = b"Cooller";
        let keybytes = codec::hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let key = AesKey::Key128(AesKey128{key: to_byte_array_16(&keybytes)});
        let iv = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf];
        let expected = vec![73, 251, 100, 217, 45, 11, 130];
            
        let ciphertext = encrypt_ctr(&key, &iv, plaintext);
        assert_eq!(expected, ciphertext);
    }

    #[test]
    fn encrypt_ctr_1() {
        let plaintext = b"Need a longer text oh yeah.";
        let keybytes = codec::hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let key = AesKey::Key128(AesKey128{key: to_byte_array_16(&keybytes)});
        let iv = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf];
        let expected = vec![68, 241, 110, 209, 97, 15, 208, 41,
                            158, 173, 243, 61, 180, 115, 158, 63,
                            122, 23, 204, 251, 14, 56, 11, 243,
                            251, 178, 211];
            
        let ciphertext = encrypt_ctr(&key, &iv, plaintext);
        assert_eq!(expected, ciphertext);
    }

    #[test]
    fn encrypt_ctr_2() {
        let plaintext = b"This is an example text for testing encryption and decryption.\n";
        let keybytes = codec::hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let key = AesKey::Key128(AesKey128{key: to_byte_array_16(&keybytes)});
        let iv = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let expected = vec![0x92, 0xc9, 0x52, 0x44, 0xa7, 0xe6, 0x28, 0xa2,
                            0x0e, 0x21, 0xa1, 0x07, 0xd9, 0xa9, 0xb5, 0x09,
                            0x1f, 0x23, 0x33, 0xe1, 0xf0, 0xb8, 0xc0, 0x3e,
                            0x2f, 0x14, 0xcf, 0xc3, 0x11, 0x91, 0x5e, 0x7e,
                            0x20, 0xb8, 0xe0, 0x73, 0xfc, 0xf5, 0xc5, 0xfe,
                            0x9a, 0xf9, 0x0e, 0x01, 0x0f, 0xef, 0x90, 0xfc,
                            0xd7, 0xc9, 0x0b, 0x4a, 0x51, 0x09, 0xb0, 0x41,
                            0x20, 0x29, 0x5f, 0x31, 0xf2, 0x99, 0xf6];
            
        let ciphertext = encrypt_ctr(&key, &iv, plaintext);
        assert_eq!(expected, ciphertext);
    }

    #[test]
    fn decrypt_ctr_0() {
        let ciphertext = vec![68, 241, 110, 209, 97, 15, 208, 41, 158, 173, 243, 61,
                              180, 115, 158, 63, 122, 23, 204, 251, 14, 56, 11, 243,
                              251, 178, 211];
        let expected: Vec<_> = b"Need a longer text oh yeah.".into_iter().cloned().collect();

        let keybytes = codec::hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let key = AesKey::Key128(AesKey128{key: to_byte_array_16(&keybytes)});
        let iv = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf];

        let plaintext = decrypt_ctr(&key, &iv, &ciphertext);
        assert_eq!(&expected, &plaintext);
    }

    #[test]
    fn decrypt_ctr_1() {
        let ciphertext = vec![0x92, 0xc9, 0x52, 0x44, 0xa7, 0xe6, 0x28, 0xa2,
                            0x0e, 0x21, 0xa1, 0x07, 0xd9, 0xa9, 0xb5, 0x09,
                            0x1f, 0x23, 0x33, 0xe1, 0xf0, 0xb8, 0xc0, 0x3e,
                            0x2f, 0x14, 0xcf, 0xc3, 0x11, 0x91, 0x5e, 0x7e,
                            0x20, 0xb8, 0xe0, 0x73, 0xfc, 0xf5, 0xc5, 0xfe,
                            0x9a, 0xf9, 0x0e, 0x01, 0x0f, 0xef, 0x90, 0xfc,
                            0xd7, 0xc9, 0x0b, 0x4a, 0x51, 0x09, 0xb0, 0x41,
                            0x20, 0x29, 0x5f, 0x31, 0xf2, 0x99, 0xf6];
        let expected: Vec<_> = b"This is an example text for testing encryption and decryption.\n"
            .iter().cloned().collect();
            
        let keybytes = codec::hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let key = AesKey::Key128(AesKey128{key: to_byte_array_16(&keybytes)});
        let iv = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

        let plaintext = decrypt_ctr(&key, &iv, &ciphertext);
        assert_eq!(&expected, &plaintext);
    }

    #[test]
    fn detect_ecb_0() {
        let plaintext = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.\n";
        let keybytes = codec::hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let key = AesKey::Key128(AesKey128{key: to_byte_array_16(&keybytes)});
            
        let ciphertext = encrypt_ecb(&key, plaintext);
        assert!(detect_ecb(&ciphertext));
    }

    #[test]
    fn detect_ecb_1() {
        let plaintext = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.\n";
        let keybytes = codec::hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let key = AesKey::Key128(AesKey128{key: to_byte_array_16(&keybytes)});
        let iv = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
            
        let ciphertext = encrypt_cbc(&key, &iv, plaintext);
        assert!(!detect_ecb(&ciphertext));
    }

    #[test]
    fn detect_ecb_2() {
        let plaintext = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.\n";
        let keybytes = codec::hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let key = AesKey::Key128(AesKey128{key: to_byte_array_16(&keybytes)});
        let iv = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
            
        let ciphertext = encrypt_ctr(&key, &iv, plaintext);
        assert!(!detect_ecb(&ciphertext));
    }
}
