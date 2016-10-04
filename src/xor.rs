// Copyright 2016 Martin Grabmueller. See the LICENSE file at the
// top-level directory of this distribution for license information.

//! Collection of XOR-base "encryption" routines.  This is no real
//! crypto, but can be used to implement better ciphers.

use std::ascii::AsciiExt;

/// Apply the byte `key` via xor to all the bytes in `msg`, and return
/// the result as a vector.
pub fn apply(key: u8, msg: &[u8]) -> Vec<u8> {
    msg.iter().map(|c| *c ^ key).collect()
}

/// XOR all the corresponding bytes in `b0` and `b1`, respectively,
/// and return the result as a vector.
///
/// # Panics
/// Will panic if the input slices have different lengths.
pub fn xor_bytes(b0: &[u8], b1: &[u8]) -> Vec<u8> {
    assert_eq!(b0.len(), b1.len());

    let l = b0.len();
    let mut res = Vec::with_capacity(l);
    
    for i in 0..l {
        res.push(b0[i] ^ b1[i]);
    }
    res
}

static LETTER_ORDER: &'static [u8] = b"etaoinshrdlucmfwypvbg kjqxz";

fn score_english(msg: &[u8]) -> f32 {
    let mut score = 0.0;
    for b in msg {
        let c = (*b).to_ascii_lowercase() as char;
        if let Some(_) = LETTER_ORDER.iter().position(|&x| x == c as u8) {
            score += 1.0;
        }
    }
    score
}

/// Attempt to crack a single-byte XOR encrypted message.  On success,
/// the key byte is returned, `None` otherwise.
pub fn crack_single_byte_xor(msg: &[u8]) -> Option<u8> {
    let mut solutions = Vec::new();
    for key in 0..255u8 {
        let output = apply(key, &msg);
        let score = score_english(&output);
        solutions.push((score, key, output));
    }
    let mut sl = &mut solutions[..];
    sl.sort_by(|&(s0, _, _), &(s1, _, _)| match s1.partial_cmp(&s0) {
               Some(o) => o,
               _ => ::std::cmp::Ordering::Less
    });
    Some(sl[0].1)
}

#[cfg(test)]
mod tests {
    use super::{apply, xor_bytes, crack_single_byte_xor};
    use ::codec;
    
    #[test]
    fn apply_empty() {
        let input = vec![];
        let expected: Vec<u8> = vec![];
        assert_eq!(expected, apply(0x80, &input));
    }

    #[test]
    fn apply_short() {
        let input = vec![0x80, 0x7f, 0xff];
        let expected: Vec<u8> = vec![0x00, 0xff, 0x7f];
        assert_eq!(expected, apply(0x80, &input));
    }

    #[test]
    #[should_panic]
    fn xor_bytes_panic() {
        let b0 = [0, 1, 2];
        let b1 = [0, 1, 2, 3];
        let expected = vec![0, 0, 0, 0];
        assert_eq!(expected, xor_bytes(&b0, &b1));
    }

    #[test]
    fn xor_bytes_0() {
        let b0 = [0, 1, 2, 3];
        let b1 = [0, 1, 2, 3];
        let expected = vec![0, 0, 0, 0];
        assert_eq!(expected, xor_bytes(&b0, &b1));
    }

    #[test]
    fn xor_bytes_1() {
        let b0 = codec::hex::decode("1c0111001f010100061a024b53535009181c").unwrap();
        let b1 = codec::hex::decode("686974207468652062756c6c277320657965").unwrap();
        let expected = codec::hex::decode("746865206b696420646f6e277420706c6179").unwrap();
        assert_eq!(expected, xor_bytes(&b0, &b1));
    }

    #[test]
    fn crack_1() {
        let input = codec::hex::decode("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736").unwrap();
        let res = crack_single_byte_xor(&input);
        assert_eq!(Some(88), res);
    }
}
