use crate::to_hex_string;
use crate::utils::preprocess_little_endian;
use crate::utils::BLOCK_SIZE;
use std::convert::TryInto;

#[allow(clippy::cast_lossless, dead_code)]
fn get_md5_k(index: u32) -> u32 {
    let next_i = (index + 1) as f64;
    let value = next_i.sin().abs() as f64;
    (value * 4_294_967_296f64).floor() as u32
}

// fn get_md5_k(index: u32) -> u32 {
//     [
//         0x00000000, // enable use as a 1-indexed table
//         0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
//         0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
//         0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
//         0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
//         0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
//         0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
//         0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
//         0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
//         0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
//         0xeb86d391,
//     ][index as usize]
// }

fn to_md5_word(chunk: &[char]) -> Vec<u32> {
    chunk
        .chunks_exact(32)
        .map(|block| {
            let int_bits = block.iter().collect::<String>();
            u32::from_be(u32::from_str_radix(&int_bits, 2).unwrap())
        })
        .collect()
}

const SHIFTS: [usize; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9,
    14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15,
    21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

#[allow(clippy::many_single_char_names, dead_code)]
fn md5(raw_message: &str) -> String {
    let mut hash_state: [u32; 4] = [
        0x6745_2301u32,
        0xefcd_ab89u32,
        0x98ba_dcfeu32,
        0x1032_5476u32,
    ];

    let message = preprocess_little_endian(raw_message.to_string());
    let blocks = message.chars().collect::<Vec<char>>();

    for chunk in blocks.chunks_exact(BLOCK_SIZE) {
        let w: Vec<u32> = to_md5_word(chunk);

        println!("{:#?}", w);

        assert_eq!(16, w.len());

        let mut a: u32 = hash_state[0];
        let mut b: u32 = hash_state[1];
        let mut c: u32 = hash_state[2];
        let mut d: u32 = hash_state[3];

        for i in 0..=63 {
            let temp: u32;
            let f: u32;
            let g: u32;

            // bitwise & is commutative+associative, so we can reorder those
            match i {
                0..=15 => {
                    // F := (B and C) or ((not B) and D)
                    f = (b & c) | (!b & d);
                    // g := i
                    g = i;
                }
                16..=31 => {
                    // F := (D and B) or ((not D) and C)
                    f = (b & d) | (c & !d);
                    // g := (5×i + 1) mod 16
                    g = (5 * i + 1) % 16;
                }
                32..=47 => {
                    // F := B xor C xor D
                    f = b ^ c ^ d;
                    // g := (3×i + 5) mod 16
                    g = (3 * i + 5) % 16;
                }
                48..=63 => {
                    // F := C xor (B or (not D))
                    f = c ^ (b | !d);
                    // g := (7×i) mod 16
                    g = (7 * i) % 16;
                }
                _ => panic!("Indexing broke"),
            }

            let before_hex_string = format!(
                "before (hex): [i = {}] A={:08x} B={:08x} C={:08x} D={:08x}",
                i, a, b, c, d
            );
            let before_dec_string = format!(
                "before (dec): [i = {}] A={:10} B={:10} C={:10} D={:10}",
                i, a, b, c, d
            );

            let i_as_u32: u32 = i.try_into().unwrap();
            let w_g: u32 = w[g as usize];
            let s_i_as_u32: u32 = SHIFTS[i as usize].try_into().unwrap();

            temp = d;
            d = c;
            c = b;

            b = calc_b(a, b, f, i_as_u32, w_g, s_i_as_u32);
            a = temp;

            let after_hex_string = format!(
                "after (hex):  [i = {}] A={:08x} B={:08x} C={:08x} D={:08x}",
                i, a, b, c, d
            );

            let after_dec_string = format!(
                "after (dec):  [i = {}] A={:10} B={:10} C={:10} D={:10}",
                i, a, b, c, d
            );

            println!("{}", before_hex_string);
            println!("{}", after_hex_string);
            println!("{}", before_dec_string);
            println!("{}", after_dec_string);
            println!("{}", "-".repeat(40));
        }

        hash_state[0] = hash_state[0].wrapping_add(a);
        hash_state[1] = hash_state[1].wrapping_add(b);
        hash_state[2] = hash_state[2].wrapping_add(c);
        hash_state[3] = hash_state[3].wrapping_add(d);
    }

    hash_state
        .iter()
        .flat_map(|value| to_hex_string(*value))
        .collect::<String>()
}

fn calc_b(a: u32, b: u32, f: u32, i: u32, w_at_g: u32, rotation: u32) -> u32 {
    let k_at_i = get_md5_k(i);

    let value = a
        .wrapping_add(f)
        .wrapping_add(k_at_i)
        .wrapping_add(w_at_g)
        .rotate_left(rotation);

    b.wrapping_add(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_k() {
        assert_eq!(0xd76a_a478, get_md5_k(0));
        assert_eq!(0xa4be_ea44, get_md5_k(36));
    }

    #[test]
    fn test_to_md5_word() {
        let raw_message = "1";
        let message = preprocess_little_endian(raw_message.to_string());
        let blocks = message.chars().collect::<Vec<char>>();
        let block = blocks.chunks_exact(BLOCK_SIZE).next().unwrap();
        let res = to_md5_word(block);
        assert_eq!(32817, *res.get(0).unwrap());
        assert_eq!(8, *res.get(14).unwrap());
    }

    #[test]
    fn test_md5() {
        // assert_eq!(md5("1"), "c4ca4238a0b923820dcc509a6f75849b");

        // assert_eq!(
        //     md5("The quick brown fox jumps over the lazy dog"),
        //     "9e107d9d372bb6826bd81d3542a419d6"
        // );

        // assert_eq!(
        //     md5("The quick brown fox jumps over the lazy dog."),
        //     "e4d909c290d0fb1ca068ffaddf22cbd0"
        // );

        assert_eq!(md5(""), "d41d8cd98f00b204e9800998ecf8427e");
    }
}
