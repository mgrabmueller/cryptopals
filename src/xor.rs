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

static LETTER_FREQS: [(char, f32); 28] = [
    ('e', 12.49),
    ('t', 9.28),
    (' ', 9.00),
    ('a', 8.04),
    ('o', 7.64),
    ('i', 7.57),
    ('n', 7.23),
    ('s', 6.51),
    ('r', 6.28),
    ('h', 5.05),
    ('l', 4.07),
    ('d', 3.82),
    ('c', 3.34),
    ('u', 2.73),
    ('m', 2.51),
    ('f', 2.40),
    ('p', 2.14),
    ('g', 1.87),
    ('w', 1.68),
    ('y', 1.66),
    ('b', 1.48),
    ('v', 1.05),
    ('\n', 1.00),
    ('k', 0.54),
    ('x', 0.23),
    ('j', 0.16),
    ('q', 0.12),
    ('z', 0.09),
];

fn score_english(msg: &[u8]) -> f32 {
    if msg.len() == 0 {
        return 0.0;
    }

    let mut score = 0.0;
    for b in msg {
        let c = (*b).to_ascii_lowercase() as char;
        if let Some(&(_, f)) = LETTER_FREQS.iter().find(|&&(d, _)| d == c) {
            score += f;
        }
    }
    score /= msg.len() as f32;
    score
}

const THRESHOLD: f32 = 5.0;

/// Attempt to crack a single-byte XOR encrypted message.  On success,
/// the key byte is returned, `None` otherwise.
pub fn crack_single_byte_xor(msg: &[u8]) -> Option<(u8, Vec<u8>)> {
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
    if sl[0].0 >= THRESHOLD {
        Some((sl[0].1, sl[0].2.iter().cloned().collect()))
    } else {
        None
    }
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
        let res = crack_single_byte_xor(&input).unwrap();
        assert_eq!((88, vec![67, 111, 111, 107, 105, 110, 103, 32,
                             77, 67, 39, 115, 32, 108, 105, 107, 101,
                             32, 97, 32, 112, 111, 117, 110, 100, 32,
                             111, 102, 32, 98, 97, 99, 111, 110]),
                   res);
    }
}
