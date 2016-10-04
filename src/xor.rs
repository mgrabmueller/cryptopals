// Copyright 2016 Martin Grabmueller. See the LICENSE file at the
// top-level directory of this distribution for license information.

pub fn apply(key: u8, msg: &[u8]) -> Vec<u8> {
    msg.iter().map(|c| *c ^ key).collect()
}

pub fn xor_bytes(b0: &[u8], b1: &[u8]) -> Vec<u8> {
    assert_eq!(b0.len(), b1.len());

    let l = b0.len();
    let mut res = Vec::with_capacity(l);
    
    for i in 0..l {
        res.push(b0[i] ^ b1[i]);
    }
    res
}

#[cfg(test)]
mod tests {
    use super::{apply, xor_bytes};
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
}
