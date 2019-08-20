use crate::utils::preprocess_little_endian;
use crate::to_hex_string;
use crate::utils::preprocess;
use crate::utils::BLOCK_SIZE;
use std::convert::TryInto;

/*
   v = sin(i + 1)
   a = abs(v)
   floor(a × (2 pow 32))
*/
#[allow(clippy::cast_lossless, dead_code)]
fn get_md5_k(index: u32) -> u32 {
    let next_i = (index + 1) as f64;
    let value = next_i.sin().abs() as f64;
    (value * 4_294_967_296f64).floor() as u32
}

#[allow(clippy::many_single_char_names, dead_code)]
fn md5(raw_message: &str) -> String {
    let s: [usize; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];

    let mut hash_state: [u32; 4] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];

    let message = preprocess_little_endian(raw_message.to_string());
    let blocks = message.chars().collect::<Vec<char>>();

    for chunk in blocks.chunks_exact(BLOCK_SIZE) {
        let w: Vec<u32> = chunk
            .chunks_exact(32)
            .map(|block| {
                let int_bits = block.iter().collect::<String>();
                u32::from_be(u32::from_str_radix(&int_bits, 2).unwrap())
            })
            .collect();

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

            match i {
                0..=15 => {
                    // F := (B and C) or ((not B) and D)
                    f = (b & c) | ((!b) & d);
                    // g := i
                    g = i;
                }
                16..=31 => {
                    // F := (D and B) or ((not D) and C)
                    f = (d & b) | ((!d) & c);
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
                    f = c ^ (b | (!d));
                    // g := (7×i) mod 16
                    g = (7 * i) % 16;
                }
                _ => panic!("Indexing broke"),
            }

            temp = d;
            d = c;
            c = b;
            b = b.wrapping_add(
                (a.wrapping_add(f)
                    .wrapping_add(get_md5_k(i.try_into().unwrap()))
                    .wrapping_add(w[g as usize]))
                .rotate_left(s[i as usize].try_into().unwrap()),
            );
            a = temp;

            println!("[i = {}] A={} B={} C={} D={}", i, a, b, c, d)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_k() {
        assert_eq!(0xd76a_a478, get_md5_k(0));
        assert_eq!(0xa4be_ea44, get_md5_k(36));
    }

    #[test]
    fn test_md5() {
        assert_eq!(md5("1"), "c4ca4238a0b923820dcc509a6f75849b");

        // assert_eq!(
        //     md5("The quick brown fox jumps over the lazy dog"),
        //     "9e107d9d372bb6826bd81d3542a419d6"
        // );

        // assert_eq!(
        //     md5("The quick brown fox jumps over the lazy dog."),
        //     "e4d909c290d0fb1ca068ffaddf22cbd0"
        // );

        // assert_eq!(md5(""), "d41d8cd98f00b204e9800998ecf8427e");
    }
}
