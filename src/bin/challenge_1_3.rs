// Copyright 2016 Martin Grabmueller. See the LICENSE file at the
// top-level directory of this distribution for license information.

extern crate cryptopals;

use std::collections::BTreeMap;
use std::ascii::AsciiExt;

use cryptopals::{codec, xor};

static LETTER_ORDER: &'static [u8] = b"etaoinshrdlucmfwypvbg kjqxz";

fn score_english(msg: &[u8]) -> f32 {
    let mut freqs: BTreeMap<char, usize> = BTreeMap::new();
    for b in msg {
        let c = (*b).to_ascii_lowercase() as char;
        *freqs.entry(c).or_insert(0) += 1;
    }
    let mut vec: Vec<_> = freqs.iter().collect();
    vec.as_mut_slice().sort_by(|&(_, f0), &(_, f1)| f1.cmp(f0));

    let mut score = 0.0;
    for i in 0..LETTER_ORDER.len()-1 {
        let c0 = LETTER_ORDER[i];
        let c1 = LETTER_ORDER[i+1];
        let p0 = vec.iter().position(|&(x, _)| *x == c0 as char);
        let p1 = vec.iter().position(|&(x, _)| *x == c1 as char);
        match (p0, p1) {
            (Some(pos0), Some(pos1)) =>
                if pos0 <= pos1 {
                    score += 2.0;
                } else {
                    score += 1.0;
                },
            (Some(_), None) =>
                score += 0.5,
            (None, Some(_)) =>
                score += 0.5,
            _ =>
                score -= 0.5,
        }
    }
    score
}

pub fn main() {
    let input = codec::hex::decode("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736").unwrap();

    let mut solutions = Vec::new();
    for key in 0..255u8 {
        let output = xor::apply(key, &input);
        let score = score_english(&output);
        solutions.push((score, key, output));
    }
    let mut sl = &mut solutions[..];
    sl.sort_by(|&(s0, _, _), &(s1, _, _)| match s1.partial_cmp(&s0) {
               Some(o) => o,
               _ => std::cmp::Ordering::Less
    });
    for &(s, k, ref o) in sl.iter().take(5) {
        let sol = String::from_utf8_lossy(&o);
        println!("{:x} -> {} {:?}", k, s, sol);
    }
}
