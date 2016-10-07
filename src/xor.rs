// Copyright 2016 Martin Grabmueller. See the LICENSE file at the
// top-level directory of this distribution for license information.

//! Collection of XOR-base "encryption" routines.  This is no real
//! crypto, but can be used to implement better ciphers.

use super::distance;
use super::language;

/// Apply the byte `key` via XOR to all the bytes in `msg`, and return
/// the result as a vector.
pub fn one_byte(key: u8, msg: &[u8]) -> Vec<u8> {
    msg.iter().map(|c| *c ^ key).collect()
}

/// Apply the key `key` to the message `msg` with XOR, by repeating
/// the key as often as necessary.
pub fn repeating(key: &[u8], msg: &[u8]) -> Vec<u8> {
    assert!(key.len() > 0);
    
    msg.chunks(key.len())
        .flat_map(|chunk| xor_bytes(chunk, &key[0..chunk.len()]))
        .collect()
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

pub fn score_english(msg: &[u8]) -> f32 {
    if msg.len() == 0 {
        return 0.0;
    }
    (language::english::score_string(msg) as f32) / (msg.len() as f32)
}

const THRESHOLD: f32 = 100.0;

/// Attempt to crack a single-byte XOR encrypted message.  On success,
/// the key byte is returned, `None` otherwise.
pub fn crack_single_byte_xor(msg: &[u8]) -> Option<(u8, Vec<u8>)> {
    let mut solutions = Vec::new();
    for key in 0..255u8 {
        let output = one_byte(key, &msg);
        let score = score_english(&output);
        solutions.push((score, key, output.clone()));
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

const MIN_KEYSIZE: usize = 2;
const MAX_KEYSIZE: usize = 40;

fn detect_keysize(c: &[u8], max_key_sizes: usize) -> Vec<usize> {
    let mut scores = Vec::with_capacity(3);
    for keysize in MIN_KEYSIZE..::std::cmp::min(c.len()/4, MAX_KEYSIZE+1) {
        let i1 = &c[0..keysize];
        let i2 = &c[keysize..keysize*2];
        let i3 = &c[keysize*2..keysize*3];
        let i4 = &c[keysize*3..keysize*4];
        let dist = ((distance::hamming(i1, i2) +
                     distance::hamming(i1, i3) +
                     distance::hamming(i1, i4)) / 4) as f32 / keysize as f32;
        scores.push((dist, keysize));
    }
    &scores[..].sort_by(|&(d1, _), &(d2, _)|
                        match d1.partial_cmp(&d2) {
                            None => ::std::cmp::Ordering::Less,
                            Some(o) => o,
                        });
    scores.into_iter().take(max_key_sizes).map(|(_, k)| k).collect()
}

fn transpose(c: &[u8], keysize: usize) -> Vec<Vec<u8>> {
    let mut transposed = Vec::with_capacity(keysize);
    for _ in 0..keysize {
        transposed.push(Vec::with_capacity(c.len() / keysize));
    }
    for (i, &b) in c.iter().enumerate() {
        transposed[i % keysize].push(b);
    }
    transposed
}

fn break_it(c: &[u8], keysize: usize) -> Vec<u8> {
    let transposed = transpose(c, keysize);
    let mut key = Vec::with_capacity(keysize);
    for i in 0..keysize {
//        println!("{}", codec::hex::encode(&transposed[i]));
        if let Some((k, _)) = crack_single_byte_xor(&transposed[i]) {
//            println!("found key: {}", k);
//            println!("{:?}", String::from_utf8_lossy(&d));
            key.push(k);
        } else {
//            println!("cannot find key");
            key.push(0);
        }
    }
    key
}

/// Attempt to decrypt message `c`, which is assumed to be encrypted
/// with a repeating XOR scheme with a key length somewhere between 2
/// and 40 bytes.  The plaintext is assumed to be English text in
/// ASCII encoding.
pub fn crack_repeating_xor(c: &[u8], max_key_sizes: usize) -> Vec<(Vec<u8>, Vec<u8>)> {
    let keysizes = detect_keysize(&c, max_key_sizes);
    let mut results = Vec::with_capacity(keysizes.len());
    for keysize in keysizes {
        println!("keysize: {}", keysize);
        let key = break_it(&c, keysize);
        let decoded = repeating(&key, &c);
        let score = score_english(&decoded);
        results.push((score, key, decoded));
    }
    &results[..].sort_by(|&(d1, _, _), &(d2, _, _)|
                        match d2.partial_cmp(&d1) {
                            None => ::std::cmp::Ordering::Less,
                            Some(o) => o,
                        });
    results.into_iter().map(|(_, k, d)| (k, d)).collect()
}

#[cfg(test)]
mod tests {
    use super::{one_byte, xor_bytes, crack_single_byte_xor, repeating};
    use super::{crack_repeating_xor};
    use ::codec;
    
    #[test]
    fn apply_empty() {
        let input = vec![];
        let expected: Vec<u8> = vec![];
        assert_eq!(expected, one_byte(0x80, &input));
    }

    #[test]
    fn apply_short() {
        let input = vec![0x80, 0x7f, 0xff];
        let expected: Vec<u8> = vec![0x00, 0xff, 0x7f];
        assert_eq!(expected, one_byte(0x80, &input));
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

    #[test]
    fn repeating_empty() {
        let input = [];
        let key = b"northpole";
        let expected: Vec<u8> = vec![];
        assert_eq!(expected, repeating(key, &input));
    }

    #[test]
    #[should_panic]
    fn repeating_panic() {
        let input = [0, 1, 2];
        let key = [];
        let expected: Vec<u8> = vec![];
        assert_eq!(expected, repeating(&key, &input));
    }

    #[test]
    fn repeating_1() {
        let input = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
        let key = b"ICE";
        let expected = codec::hex::decode("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f").unwrap();
        assert_eq!(expected, repeating(key, input));
    }

    #[test]
    fn crack_repeating() {
        let key = b"ICE";
        let input = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
        let encrypted = repeating(key, input);
        let decrypted = crack_repeating_xor(&encrypted, 15);
        let mut found = false;
        for &(_, ref d) in decrypted.iter() {
            let scr = ::language::english::score_string(&d);
            println!("{} {:?}", scr, String::from_utf8_lossy(&d));
            if &d[..] == &input[..] {
                found = true;
            }
        }
        assert!(found);
    }
}
