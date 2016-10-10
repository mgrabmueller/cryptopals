// Copyright 2016 Martin Grabmueller. See the LICENSE file at the
// top-level directory of this distribution for license information.

//! Padding algorithms.

/// PKCS#7 padding.
pub mod pkcs7 {
    use std::iter::repeat;
    
    pub fn pad(b: &[u8], block_size: usize) -> Vec<u8> {
        let l = b.len();
        let padding = block_size - (l % block_size);
        let mut res = Vec::with_capacity(l + padding);
        res.extend(b);
        res.extend(repeat(padding as u8).take(padding));
        res
    }
    
    #[cfg(test)]
    mod tests {
        use super::{pad};
        
        #[test]
        fn pad_empty() {
            let s = b"";
            let expected: Vec<u8> = vec![16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16];
            assert_eq!(expected, pad(s, 16));
        }
        
        #[test]
        fn pad_non_empty() {
            let s = b"abcde";
            let expected: Vec<u8> = vec![97, 98, 99, 100, 101, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11];
            assert_eq!(expected, pad(s, 16));
        }
        
        #[test]
        fn pad_full() {
            let s = b"0123456789abcdef";
            let expected: Vec<u8> = vec![48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 97, 98,
                                         99, 100, 101, 102, 16, 16, 16, 16, 16, 16, 16,
                                         16, 16, 16, 16, 16, 16, 16, 16, 16];
            assert_eq!(expected, pad(s, 16));
        }
        
        #[test]
        fn pad_20() {
            let input = b"YELLOW SUBMARINE";
            let output = pad(input, 20);
            let mut expected: Vec<u8> = Vec::new();
            expected.extend(b"YELLOW SUBMARINE\x04\x04\x04\x04");
            assert_eq!(expected, output);
        }

        quickcheck! {
            fn prop_pad_len(xs: Vec<u8>) -> bool {
                let padded = pad(&xs, 16);
                let l = padded.len();
                (l % 16 == 0) && (l > xs.len())
            }

            fn prop_pad_padding(xs: Vec<u8>) -> bool {
                let padded = pad(&xs, 16);
                let l = padded.len();
                padded[l-1] as usize == l - xs.len()
            }
        }
    }
}
