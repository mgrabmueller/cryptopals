// Copyright 2016 Martin Grabmueller. See the LICENSE file at the
// top-level directory of this distribution for license information.

//! Bit distance metrics for byte strings.

/// Calculate the number of different bits between two byte vectors.
///
/// # Example
/// ```
/// use cryptopals::distance::hamming;
/// assert_eq!(2, hamming(&[0x00], &[0x81]));
/// ```
///
/// # Panics
/// Panics when the two arguments have different lengths.
pub fn hamming(b1: &[u8], b2: &[u8]) -> usize {
    assert_eq!(b1.len(), b2.len());
    fn bitcnt(b: u8) -> usize {
        let mut mask = 0x80;
        let mut cnt = 0;
        while mask != 0 {
            if mask & b != 0 {
                cnt += 1;
            }
            mask = mask >> 1;
        }
        cnt
    }
    b1.iter().zip(b2).map(|(a, b)| bitcnt(a ^ b)).fold(0, |a, b| a + b)
}

#[cfg(test)]
mod tests {
    use super::{hamming};
    
    #[test]
    fn hamming_1() {
        let input1 = vec![0x00];
        let input2 = vec![0x81];
        assert_eq!(2, hamming(&input1, &input2));
    }

    #[test]
    fn hamming_2() {
        let input1 = b"this is a test";
        let input2 = b"wokka wokka!!!";
        assert_eq!(37, hamming(input1, input2));
    }
}
