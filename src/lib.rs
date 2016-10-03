// Copyright 2016 Martin Grabmueller. See the LICENSE file at the
// top-level directory of this distribution for license information.

mod error;

/// Convert a string in hex notation to a vector of bytes.
pub fn from_hex(s: &str) -> Result<Vec<u8>, error::Error> {
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
pub fn to_hex(bytes: &[u8]) -> String {
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
    use super::{from_hex, to_hex};
    
    #[test]
    fn from_hex_empty() {
        let s = "";
        let expected: Vec<u8> = vec![];
        assert_eq!(expected, from_hex(s).unwrap());
    }

    #[test]
    fn from_hex_empty_1() {
        let s = "ff";
        let expected: Vec<u8> = vec![255];
        assert_eq!(expected, from_hex(s).unwrap());
    }

    #[test]
    fn from_hex_empty_2() {
        let s = "107fff";
        let expected: Vec<u8> = vec![16, 127, 255];
        assert_eq!(expected, from_hex(s).unwrap());
    }

    #[test]
    fn from_hex_empty_3() {
        let s = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let expected: Vec<u8> = vec![73, 39, 109, 32, 107, 105, 108, 108, 105, 110, 103, 32, 121, 111, 117, 114, 32, 98, 114, 97, 105, 110, 32, 108, 105, 107, 101, 32, 97, 32, 112, 111, 105, 115, 111, 110, 111, 117, 115, 32, 109, 117, 115, 104, 114, 111, 111, 109];
        assert_eq!(expected, from_hex(s).unwrap());
    }

    #[test]
    fn from_hex_invalid_char() {
        let s = "ffx1";
        assert!(from_hex(s).is_err());
    }

    #[test]
    fn from_hex_invalid_len() {
        let s = "ffa";
        assert!(from_hex(s).is_err());
    }

    #[test]
    fn to_hex_empty() {
        let bytes = [];
        let expected = "";
        assert_eq!(expected, to_hex(&bytes));
    }

    #[test]
    fn to_hex_1() {
        let bytes = [255];
        let expected = "ff";
        assert_eq!(expected, to_hex(&bytes));
    }

    #[test]
    fn to_hex_2() {
        let bytes = [255, 17];
        let expected = "ff11";
        assert_eq!(expected, to_hex(&bytes));
    }

    #[test]
    fn to_hex_3() {
        let bytes = [73, 39, 109, 32, 107, 105, 108, 108, 105, 110, 103, 32, 121, 111, 117, 114, 32, 98, 114, 97, 105, 110, 32, 108, 105, 107, 101, 32, 97, 32, 112, 111, 105, 115, 111, 110, 111, 117, 115, 32, 109, 117, 115, 104, 114, 111, 111, 109];
        let expected = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        assert_eq!(expected, to_hex(&bytes));
    }

}
