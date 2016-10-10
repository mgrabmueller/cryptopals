// Copyright 2016 Martin Grabmueller. See the LICENSE file at the
// top-level directory of this distribution for license information.

//! Various encoding and decoding algorithms, to decode readable
//! strings to byte vectors and vice versa.

/// Standard BASE64 encoding.
pub mod base64 {
    use ::error;
    
    static BASE64_CHARS: &'static [u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    /// Decode a string in BASE64 to a vector of bytes. Ignore all
    /// whitespace.
    pub fn decode(s: &str) -> Result<Vec<u8>, error::Error> {
        let mut ret = Vec::new();

        fn pos(l: Option<char>) -> Result<Option<u8>, error::Error> {
            match l {
                None =>
                    Err(error::Error::InvalidBase64Length),
                Some(c) if c == '=' =>
                    Ok(None),
                Some(c) =>
                    match BASE64_CHARS.iter().position(|b| *b as char == c) {
                        None => Err(error::Error::InvalidBase64Char(c)),
                        Some(p) => Ok(Some(p as u8)),
                    },
            }
        }
        let mut it = s.chars().filter(|c| *c != '\r' && *c != '\n');
        loop {
            if let Some(x0) = it.next() {
                
                let l0 = try!(pos(Some(x0)));
                let l1 = try!(pos(it.next()));
                let l2 = try!(pos(it.next()));
                let l3 = try!(pos(it.next()));
                match (l0, l1, l2, l3) {
                    (Some(c0), Some(c1), Some(c2), Some(c3)) => {
                        ret.push((c0 << 2) | ((c1 >> 4) & 3));
                        ret.push((c1 << 4) | ((c2 >> 2) & 15));
                        ret.push((c2 << 6) | (c3 & 63));
                    },
                    (Some(c0), Some(c1), Some(c2), None) => {
                        ret.push((c0 << 2) | ((c1 >> 4) & 3));
                        ret.push((c1 << 4) | ((c2 >> 2) & 15));
                    },
                    (Some(c0), Some(c1), None, None) => {
                        ret.push((c0 << 2) | ((c1 >> 4) & 3));
                    },
                    _ => {
                        return Err(error::Error::InvalidBase64Padding);
                    }
                }
            } else {
                break;
            }
        }
        return Ok(ret);
    }

    /// Encode a vector of bytes as a BASE64 string.
    pub fn encode(bytes: &[u8]) -> String {
        let mut ret = String::new();
        let mut it = bytes.iter();
        loop {
            if let Some(b0) = it.next() {
                let c0 = b0 >> 2;
                let (c1, c2, c3) =
                    if let Some(b1) = it.next() {
                        let c1 = ((b0 & 3) << 4) | (b1 >> 4);
                        let (c2, c3) =
                            if let Some(b2) = it.next() {
                                let c2 = ((b1 & 15) << 2) | ((b2 >> 6u8) & 3);
                                let c3 = b2 & 63;
                                (BASE64_CHARS[c2 as usize], BASE64_CHARS[c3 as usize])
                            } else {
                                let c2 = (b1 & 15) << 2;
                                (BASE64_CHARS[c2 as usize], b'=')
                            };
                        (BASE64_CHARS[c1 as usize], c2, c3)
                    } else {
                        let c1 = (b0 & 3) << 4;
                        (BASE64_CHARS[c1 as usize], b'=', b'=')
                    };
                ret.push(BASE64_CHARS[c0 as usize] as char);
                ret.push(c1 as char);
                ret.push(c2 as char);
                ret.push(c3 as char);
            } else {
                break;
            }
        }
        ret
    }

    #[cfg(test)]
    mod tests {
        use super::{decode, encode};
        
        #[test]
        fn decode_empty() {
            let s = "";
            let expected: Vec<u8> = vec![];
            assert_eq!(expected, decode(s).unwrap());
        }
        
        #[test]
        fn decode_1() {
            let s = "Fw==";
            let expected: Vec<u8> = vec![0x17];
            assert_eq!(expected, decode(s).unwrap());
        }
        
        #[test]
        fn decode_2() {
            let s = "Fy8=";
            let expected: Vec<u8> = vec![0x17, 0x2f];
            assert_eq!(expected, decode(s).unwrap());
        }
        
        #[test]
        fn decode_3() {
            let s = "Fy//";
            let expected: Vec<u8> = vec![0x17, 0x2f, 0xff];
            assert_eq!(expected, decode(s).unwrap());
        }
        
        #[test]
        fn decode_4() {
            let s = "Fy//AA==";
            let expected: Vec<u8> = vec![0x17, 0x2f, 0xff, 0x00];
            assert_eq!(expected, decode(s).unwrap());
        }
        
        #[test]
        fn decode_5() {
            let s = "YnIAdGhlcg==";
            let expected: Vec<u8> = vec![b'b', b'r', 0, b't', b'h', b'e', b'r'];
            assert_eq!(expected, decode(s).unwrap());
        }

        /// From Cryptopals Crypto Challenges Set 1 / Challenge 1
        #[test]
        fn decode_6() {
            let s = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
            let expected: Vec<u8> =
                vec![73, 39, 109, 32, 107, 105, 108, 108, 105, 110, 103, 32, 121,
                     111, 117, 114, 32, 98, 114, 97, 105, 110, 32, 108, 105, 107,
                     101, 32, 97, 32, 112, 111, 105, 115, 111, 110, 111, 117, 115,
                     32, 109, 117, 115, 104, 114, 111, 111, 109];
            assert_eq!(expected, decode(s).unwrap());
        }
        
        #[test]
        fn encode_empty() {
            let bytes = [];
            let expected = "";
            assert_eq!(expected, encode(&bytes));
        }

        #[test]
        fn encode_1() {
            let bytes = [0x17];
            let expected = "Fw==";
            assert_eq!(expected, encode(&bytes));
        }

        #[test]
        fn encode_2() {
            let bytes = [0x17, 0x2f];
            let expected = "Fy8=";
            assert_eq!(expected, encode(&bytes));
        }

        #[test]
        fn encode_3() {
            let bytes = [0x17, 0x2f, 0xff];
            let expected = "Fy//";
            assert_eq!(expected, encode(&bytes));
        }

        #[test]
        fn encode_4() {
            let bytes = [0x17, 0x2f, 0xff, 0x00];
            let expected = "Fy//AA==";
            assert_eq!(expected, encode(&bytes));
        }

        #[test]
        fn encode_5() {
            let bytes = [b'b', b'r', 0, b't', b'h', b'e', b'r'];
            let expected = "YnIAdGhlcg==";
            assert_eq!(expected, encode(&bytes));
        }

        /// From Cryptopals Crypto Challenges Set 1 / Challenge 1
        #[test]
        fn encode_6() {
            let bytes = [73, 39, 109, 32, 107, 105, 108, 108, 105, 110, 103, 32, 121,
                         111, 117, 114, 32, 98, 114, 97, 105, 110, 32, 108, 105, 107,
                         101, 32, 97, 32, 112, 111, 105, 115, 111, 110, 111, 117, 115,
                         32, 109, 117, 115, 104, 114, 111, 111, 109];
            let expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
            assert_eq!(expected, encode(&bytes));
        }

        use quickcheck::{Gen, Arbitrary};
        
        #[derive(Copy, Clone, Debug)]
        struct B64Chars(char, char, char, char);
    
        impl Arbitrary for B64Chars {
            fn arbitrary<G: Gen>(g: &mut G) -> B64Chars {
                B64Chars(*g.choose(super::BASE64_CHARS).unwrap() as char,
                         *g.choose(super::BASE64_CHARS).unwrap() as char,
                         *g.choose(super::BASE64_CHARS).unwrap() as char,
                         *g.choose(super::BASE64_CHARS).unwrap() as char)
            }
        }

        quickcheck! {
            fn prop_decode_encode(xs: Vec<u8>) -> bool {
                decode(&encode(&xs)).unwrap() == xs
            }

            fn prop_encode_decode(xs: Vec<B64Chars>) -> bool {
                use std::iter::FromIterator;
                let s = String::from_iter(xs.into_iter()
                                          .flat_map(|B64Chars(c0, c1, c2, c3)| vec![c0, c1, c2, c3].into_iter()));
                encode(&decode(&s).unwrap()) == s
            }
        }
    }
}

/// Standard hex encoding.
pub mod hex {
    use ::error;

    /// Convert a string in hex notation to a vector of bytes.
    pub fn decode(s: &str) -> Result<Vec<u8>, error::Error> {
        fn unhex(c: char) -> Result<u8, error::Error> {
            match c {
                'a'...'f' => Ok(((c as usize) - ('a' as usize) + 10) as u8),
                'A'...'F' => Ok(((c as usize) - ('A' as usize) + 10) as u8),
                '0'...'9' => Ok(((c as usize) - ('0' as usize)) as u8),
                _ => Err(error::Error::InvalidHexChar(c)),
            }
        }
        
        let mut it = s.chars();
        let mut ret = Vec::new();
        loop {
            if let Some(c0) = it.next() {
                if let Some(c1) = it.next() {
                    let hi = try!(unhex(c0));
                    let lo = try!(unhex(c1));
                    ret.push(hi << 4 | lo);
                } else {
                    return Err(error::Error::InvalidHexLength);
                }
            } else {
                break;
            }
        }
        Ok(ret)
    }

    static HEX_CHARS: [char; 16] =
        ['0', '1', '2', '3', '4', '5', '6', '7',
         '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'];

    /// Convert a vector of bytes into a string in hex notation.
    pub fn encode(bytes: &[u8]) -> String {
        let mut ret = String::new();
        for b in bytes.into_iter() {
            let hi = (b >> 4) & 0x0fu8;
            let lo = b & 0x0f;
            ret.push(HEX_CHARS[hi as usize]);
            ret.push(HEX_CHARS[lo as usize]);
        }
        ret
    }

    #[cfg(test)]
    mod tests {
        use super::{decode, encode};
        
        #[test]
        fn decode_empty() {
            let s = "";
            let expected: Vec<u8> = vec![];
            assert_eq!(expected, decode(s).unwrap());
        }
        
        #[test]
        fn decode_1() {
            let s = "ff";
            let expected: Vec<u8> = vec![255];
            assert_eq!(expected, decode(s).unwrap());
        }
        
        #[test]
        fn decode_2() {
            let s = "107fff";
            let expected: Vec<u8> = vec![16, 127, 255];
            assert_eq!(expected, decode(s).unwrap());
        }
        
        /// From Cryptopals Crypto Challenges Set 1 / Challenge 1
        #[test]
        fn decode_3() {
            let s = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
            let expected: Vec<u8> = vec![73, 39, 109, 32, 107, 105, 108, 108,
                                         105, 110, 103, 32, 121, 111, 117, 114,
                                         32, 98, 114, 97, 105, 110, 32, 108, 105,
                                         107, 101, 32, 97, 32, 112, 111, 105,
                                         115, 111, 110, 111, 117, 115, 32, 109,
                                         117, 115, 104, 114, 111, 111, 109];
            assert_eq!(expected, decode(s).unwrap());
        }

        #[test]
        fn decode_invalid_char() {
            let s = "ffx1";
            assert!(decode(s).is_err());
        }

        #[test]
        fn decode_invalid_len() {
            let s = "ffa";
            assert!(decode(s).is_err());
        }

        #[test]
        fn encode_empty() {
            let bytes = [];
            let expected = "";
            assert_eq!(expected, encode(&bytes));
        }

        #[test]
        fn encode_1() {
            let bytes = [255];
            let expected = "ff";
            assert_eq!(expected, encode(&bytes));
        }

        #[test]
        fn encode_2() {
            let bytes = [255, 17];
            let expected = "ff11";
            assert_eq!(expected, encode(&bytes));
        }

        /// From Cryptopals Crypto Challenges Set 1 / Challenge 1
        #[test]
        fn encode_3() {
            let bytes = [73, 39, 109, 32, 107, 105, 108, 108, 105, 110, 103,
                         32, 121, 111, 117, 114, 32, 98, 114, 97, 105, 110,
                         32, 108, 105, 107, 101, 32, 97, 32, 112, 111, 105,
                         115, 111, 110, 111, 117, 115, 32, 109, 117, 115,
                         104, 114, 111, 111, 109];
            let expected = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
            assert_eq!(expected, encode(&bytes));
        }

        use quickcheck::{Gen, Arbitrary};
        
        #[derive(Copy, Clone, Debug)]
        struct HexChar(char, char);
    
        impl Arbitrary for HexChar {
            fn arbitrary<G: Gen>(g: &mut G) -> HexChar {
                HexChar(*g.choose(&super::HEX_CHARS).unwrap(), *g.choose(&super::HEX_CHARS).unwrap())
            }
        }

        quickcheck! {
            fn prop_decode_encode(xs: Vec<u8>) -> bool {
                decode(&encode(&xs)).unwrap() == xs
            }

            fn prop_encode_decode(xs: Vec<HexChar>) -> bool {
                use std::iter::FromIterator;
                let s = String::from_iter(xs.into_iter().flat_map(|HexChar(c0, c1)| vec![c0, c1].into_iter()));
                encode(&decode(&s).unwrap()) == s
            }
        }
    }
}

/// Standard binary encoding.
pub mod bin {
    use ::error;

    /// Convert a string in binary notation to a vector of
    /// bytes. Binary strings are big-endian, that means that for each
    /// byte, the most significant byte comes first in the string
    /// representation.
    pub fn decode(s: &str) -> Result<Vec<u8>, error::Error> {
        fn unbin(c: char) -> Result<u8, error::Error> {
            match c {
                '0' => Ok(0),
                '1' => Ok(1),
                _ => Err(error::Error::InvalidBinChar(c)),
            }
        }
        
        let mut it = s.chars();
        let mut ret = Vec::new();
        loop {
            if let Some(c0a) = it.next() {
                let c0 = try!(unbin(c0a));
                let c1 = try!(unbin(try!(it.next().ok_or(error::Error::InvalidBinLength))));
                let c2 = try!(unbin(try!(it.next().ok_or(error::Error::InvalidBinLength))));
                let c3 = try!(unbin(try!(it.next().ok_or(error::Error::InvalidBinLength))));
                let c4 = try!(unbin(try!(it.next().ok_or(error::Error::InvalidBinLength))));
                let c5 = try!(unbin(try!(it.next().ok_or(error::Error::InvalidBinLength))));
                let c6 = try!(unbin(try!(it.next().ok_or(error::Error::InvalidBinLength))));
                let c7 = try!(unbin(try!(it.next().ok_or(error::Error::InvalidBinLength))));
                let b = (c0 << 7) | (c1 << 6) | (c2 << 5) | (c3 << 4) | (c4 << 3) | (c5 << 2) | (c6 << 1) | c7;
                ret.push(b);
            } else {
                break;
            }
        }
        Ok(ret)
    }

    /// Convert a vector of bytes into a string in binary notation.
    /// Binary strings are big-endian, that means that for each byte,
    /// the most significant byte comes first in the string
    /// representation.
    pub fn encode(bytes: &[u8]) -> String {
        let mut ret = String::new();
        fn enc(b: u8) -> char {
            if b == 0 {
                '0'
            } else {
                '1'
            }
        }
        for b in bytes {
            ret.push(enc(b & 0x80));
            ret.push(enc(b & 0x40));
            ret.push(enc(b & 0x20));
            ret.push(enc(b & 0x10));
            ret.push(enc(b & 0x08));
            ret.push(enc(b & 0x04));
            ret.push(enc(b & 0x02));
            ret.push(enc(b & 0x01));
        }
        ret
    }

    #[cfg(test)]
    mod tests {
        use super::{decode, encode};
        
        #[test]
        fn decode_empty() {
            let s = "";
            let expected: Vec<u8> = vec![];
            assert_eq!(expected, decode(s).unwrap());
        }
        
        #[test]
        fn decode_1() {
            let s = "11111111";
            let expected: Vec<u8> = vec![255];
            assert_eq!(expected, decode(s).unwrap());
        }
        
        #[test]
        fn decode_2() {
            let s = "1111111110000010";
            let expected: Vec<u8> = vec![255, 130];
            assert_eq!(expected, decode(s).unwrap());
        }
        
        #[test]
        fn decode_invalid_char() {
            let s = "11111112";
            assert!(decode(s).is_err());
        }

        #[test]
        fn decode_invalid_len() {
            let s = "111";
            assert!(decode(s).is_err());
        }

        #[test]
        fn encode_empty() {
            let bytes = [];
            let expected = "";
            assert_eq!(expected, encode(&bytes));
        }

        #[test]
        fn encode_1() {
            let bytes = [255];
            let expected = "11111111";
            assert_eq!(expected, encode(&bytes));
        }

        #[test]
        fn encode_2() {
            let bytes = [255, 130];
            let expected = "1111111110000010";
            assert_eq!(expected, encode(&bytes));
        }
    }
}
