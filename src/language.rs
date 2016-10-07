// Copyright 2016 Martin Grabmueller. See the LICENSE file at the
// top-level directory of this distribution for license information.

//! Collection of XOR-base "encryption" routines.  This is no real
//! crypto, but can be used to implement better ciphers.

pub mod english {

    use std::ascii::AsciiExt;

    // Letter statistics taken from
    // http://jnicholl.org/Cryptanalysis/Data/EnglishData.php.
    static LETTER_FREQS: [(u8, usize); 26] =
        [
            (b'E', 1231),
            (b'T', 959),
            (b'A', 805),
            (b'O', 794),
            (b'N', 719),
            (b'I', 718),
            (b'S', 659),
            (b'R', 603),
            (b'H', 514),
            (b'L', 403),
            (b'D', 365),
            (b'C', 320),
            (b'U', 310),
            (b'P', 229),
            (b'F', 228),
            (b'M', 225),
            (b'W', 203),
            (b'Y', 188),
            (b'B', 162),
            (b'G', 161),
            (b'V', 93),
            (b'K', 52),
            (b'Q', 20),
            (b'X', 20),
            (b'J', 10),
            (b'Z', 9)
        ];

    static DIGRAM_FREQS: [(&'static [u8], usize); 109] =
        [
            (b"TH", 1582),
            (b"IN", 784),
            (b"ER", 667),
            (b"RE", 625),
            (b"AN", 542),
            (b"HE", 542),
            (b"AR", 511),
            (b"EN", 511),
            (b"TI", 510),
            (b"TE", 492),
            (b"AT", 440),
            (b"ON", 420),
            (b"HA", 420),
            (b"OU", 361),
            (b"IT", 356),
            (b"ES", 343),
            (b"ST", 340),
            (b"OR", 339),
            (b"NT", 337),
            (b"HI", 330),
            (b"EA", 321),
            (b"VE", 321),
            (b"CO", 296),
            (b"DE", 275),
            (b"RA", 275),
            (b"RO", 275),
            (b"LI", 273),
            (b"RI", 271),
            (b"IO", 270),
            (b"LE", 263),
            (b"ND", 263),
            (b"MA", 260),
            (b"SE", 259),
            (b"AL", 246),
            (b"IC", 244),
            (b"FO", 239),
            (b"IL", 232),
            (b"NE", 232),
            (b"LA", 229),
            (b"TA", 225),
            (b"EL", 216),
            (b"ME", 216),
            (b"EC", 214),
            (b"IS", 211),
            (b"DI", 210),
            (b"SI", 210),
            (b"CA", 202),
            (b"UN", 201),
            (b"UT", 189),
            (b"NC", 188),
            (b"WI", 188),
            (b"HO", 184),
            (b"TR", 183),
            (b"BE", 181),
            (b"CE", 177),
            (b"WH", 177),
            (b"LL", 176),
            (b"FI", 175),
            (b"NO", 175),
            (b"TO", 175),
            (b"PE", 174),
            (b"AS", 172),
            (b"WA", 171),
            (b"UR", 169),
            (b"LO", 166),
            (b"PA", 165),
            (b"US", 165),
            (b"MO", 164),
            (b"OM", 163),
            (b"AI", 162),
            (b"PR", 161),
            (b"WE", 158),
            (b"AC", 152),
            (b"EE", 148),
            (b"ET", 146),
            (b"SA", 146),
            (b"NI", 142),
            (b"RT", 142),
            (b"NA", 141),
            (b"OL", 141),
            (b"EV", 131),
            (b"IE", 129),
            (b"MI", 128),
            (b"NG", 128),
            (b"PL", 128),
            (b"IV", 127),
            (b"PO", 125),
            (b"CH", 122),
            (b"EI", 122),
            (b"AD", 120),
            (b"SS", 120),
            (b"IL", 118),
            (b"OS", 117),
            (b"UL", 115),
            (b"EM", 114),
            (b"NS", 113),
            (b"OT", 113),
            (b"GE", 112),
            (b"IR", 112),
            (b"AV", 111),
            (b"CT", 111),
            (b"TU", 108),
            (b"DA", 107),
            (b"AM", 104),
            (b"CI", 104),
            (b"SU", 102),
            (b"BL", 101),
            (b"OF", 101),
            (b"BU", 100),
        ];

    /// Return the frequency of the given letter in English texts, as
    /// an unsigned integer.  The results are in the range 9...1231.
    pub fn letter_freq(b: u8) -> Option<usize> {
        let u = b.to_ascii_uppercase();
        if let &Some(&(_, f)) = &LETTER_FREQS[..].iter().find(|&&(l, _)| l == u) {
            Some(f)
        } else {
            None
        }
    }
    
    /// Return the frequency of the given two-letter combination in
    /// English texts, as an unsigned integer.  The results are in the
    /// range 100...1582.
    pub fn digram_freq(di: &[u8]) -> Option<usize> {
        let u1 = di[0].to_ascii_uppercase();
        let u2 = di[1].to_ascii_uppercase();
        let di = [u1, u2];
        if let &Some(&(_, f)) = &DIGRAM_FREQS[..].iter().find(|&&(l, _)| l == di) {
            Some(f)
        } else {
            None
        }
    }

    pub fn score_string(b: &[u8]) -> usize {
        let mut score: usize = 0;
        let mut penalty: usize = 0;
        for c in b.windows(2) {
            if let Some(f) = digram_freq(c) {
                score += f;
            }
        }
        for &x in b {
            if let Some(f) = letter_freq(x) {
                score += f;
            } else {
                match x {
                    b' ' => score += 1000,
                    b'\n' => score += 500,
                    x if x < b' ' => penalty += 30000,
                    x if x > 126 => penalty += 20000,
                    _ => penalty += 100,
                }
            }
        }
        let mut in_word = false;
        let mut word_len = 0;
        for &x in b {
            match x {
                b'A'...b'Z' | b'a'...b'z' => {
                    if !in_word {
                        in_word = true;
                    }
                    word_len += 1;
                },
                _ => {
                    if in_word {
                        match word_len {
                            _ if word_len == 1 => {
                                score += 299;
                            },
                            _ if word_len == 2 => {
                                score += 1765;
                            },
                            _ if word_len == 3 => {
                                score += 2051;
                            },
                            _ if word_len == 4 => {
                                score += 1478;
                            },
                            _ if word_len == 5 => {
                                score += 1070;
                            },
                            _ if word_len == 6 => {
                                score += 838;
                            },
                            _ if word_len == 7 => {
                                score += 793;
                            },
                            _ if word_len == 8 => {
                                score += 594;
                            },
                            _ if word_len == 9 => {
                                score += 443;
                            },
                            _ if word_len == 10 => {
                                score += 307;
                            },
                            _ if word_len == 11 => {
                                score += 176;
                            },
                            _ if word_len == 12 => {
                                score += 95;
                            },
                            _ if word_len == 13 => {
                                score += 51;
                            },
                            _ => {
                            },
                        }
                        in_word = false;
                        word_len = 0;
                    }
                }
            }
        }
        
        score.saturating_sub(penalty)
    }
    
    #[cfg(test)]
    mod tests {
    
        #[test]
        fn letter_freq_0() {
            use super::letter_freq;
            assert_eq!(Some(20), letter_freq(b'x'));
            assert_eq!(Some(1231), letter_freq(b'e'));
            assert_eq!(None, letter_freq(b' '));
        }

        #[test]
        fn digram_freq_0() {
            use super::digram_freq;
            assert_eq!(Some(115), digram_freq(b"UL"));
            assert_eq!(Some(784), digram_freq(b"IN"));
            assert_eq!(None, digram_freq(b"BB"));
        }

        #[test]
        fn score_string_0() {
            use super::score_string;
            assert_eq!(0, score_string(b""));
            assert_eq!(5415, score_string(b"Hello."));
            assert_eq!(14183, score_string(b"good morning sir"));
            assert_eq!(38954, score_string(b"In a galaxy far away, a long time ago."));
            assert_eq!(12520, score_string(b"hhadmqhwbwidhkljklJKHKjlhjkasfdytwbckq"));
        }
    }
}
