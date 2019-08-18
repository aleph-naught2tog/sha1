use std::convert::TryInto;

fn to_bits(input: &str) -> Vec<char> {
    input
        .as_bytes()
        .iter()
        .flat_map(|byte: &u8| format!("{:08b}", byte).chars().collect::<Vec<char>>())
        .collect::<Vec<char>>()
}

pub fn sha1(message: &str) -> (u32, u32, u32, u32, u32) {
    let mut as_bits = to_bits(message);

    let mut h0: u32 = 0x6745_2301;
    let mut h1: u32 = 0xEFCD_AB89;
    let mut h2: u32 = 0x98BA_DCFE;
    let mut h3: u32 = 0x1032_5476;
    let mut h4: u32 = 0xC3D2_E1F0;

    let m1: u64 = as_bits.len() as u64;
    let mut len_as_bits = format!("{:064b}", m1).chars().collect::<Vec<char>>();

    as_bits.append(&mut vec!['1']);

    while 512 - (as_bits.len() as u32 % 512) != 64 {
        as_bits.append(&mut vec!['0']);
    }

    as_bits.append(&mut len_as_bits);

    assert_eq!(0, as_bits.len() % 512);

    for chunk in as_bits.chunks_exact(512) {
        let start_words: Vec<&[char]> = chunk.chunks_exact(32).collect::<Vec<&[char]>>();

        assert_eq!(16, start_words.len(), "wrong 32bit chunks");

        let mut words: Vec<u32> = Vec::with_capacity(80);
        assert_eq!(80, words.capacity(), "vec failed to capacitize");

        for index in 0..16 {
            let w =
                isize::from_str_radix(&start_words[index].iter().cloned().collect::<String>(), 2)
                    .unwrap()
                    .try_into()
                    .unwrap();

            words.push(w);
        }

        assert_eq!(16, words.len());

        for index in 16..80 {
            // w[i] = (w[i-3] xor w[i-8] xor w[i-14] xor w[i-16]) leftrotate 1
            let wi_3int: u32 = words[index - 3];
            let wi_8int: u32 = words[index - 8];
            let wi_14int: u32 = words[index - 14];
            let wi_16int: u32 = words[index - 16];

            let term: u32 = wi_3int ^ wi_8int ^ wi_14int ^ wi_16int;
            let rot_term: u32 = term.rotate_left(1);

            words.push(rot_term);
        }

        let mut a: u32 = h0;
        let mut b: u32 = h1;
        let mut c: u32 = h2;
        let mut d: u32 = h3;
        let mut e: u32 = h4;

        let mut f: u32;
        let mut k: u32;

        for index in 0..79 {
            match index {
                _ if index <= 29 => {
                    //    f = (b and c) or ((not b) and d)
                    f = (b & c) | ((!b) & d);
                    k = 0x5A82_7999;
                }
                _ if index <= 39 => {
                    // f = b xor c xor d
                    f = b ^ c ^ d;
                    k = 0x6ED9_EBA1;
                }
                _ if index <= 59 => {
                    // f = (b and c) or (b and d) or (c and d)
                    f = (b & c) | (b & d) | (c & d);
                    k = 0x8F1B_BCDC;
                }
                _ if index <= 79 => {
                    // f = b xor c xor d
                    f = b ^ c ^ d;
                    k = 0xCA62_C1D6;
                }
                _ => panic!("Rust broke..."),
            }

            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(words[index]);

            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    (
        h0.wrapping_shl(128),
        h1.wrapping_shl(96),
        h2.wrapping_shl(64),
        h3.wrapping_shl(32),
        h4,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        // 2fd4e1c67a2d28fced849ee1bb76e7391b93eb12
        let input = "The quick brown fox jumps over the lazy dog";
        let output = sha1(input);

        println!("{:#?}", output);

        let (a,b,c,d,e) = output;
        // 31d70e67c2ecd0075746ca81bf6cfeb16509aaef
        println!("{:x}{:x}{:x}{:x}{:x}", a, b, c, d, e);
    }
}
