use crate::to_hex_string;
use crate::utils::preprocess_little_endian;
use crate::utils::BLOCK_SIZE;
use std::convert::TryInto;

#[allow(clippy::cast_lossless, dead_code)]
fn get_md5_k(index: u32) -> u32 {
    // this is defined in the RTC as 1-indexed, so we send in index + 1
    let next_i = (index + 1) as f64;
    let value = next_i.sin().abs() as f64;
    (value * 4_294_967_296f64).floor() as u32
}

fn to_md5_word(chunk: &[char]) -> Vec<u32> {
    chunk
        .chunks_exact(32)
        .map(|block| {
            let int_bits = block.iter().collect::<String>();
            u32::from_be(u32::from_str_radix(&int_bits, 2).unwrap())
        })
        .collect()
}

fn build_rotations() -> Vec<u32> {
    std::iter::repeat([7u32, 12u32, 17u32, 22u32])
        .take(4)
        .collect::<Vec<[u32; 4]>>()
        .iter()
        .chain(
            std::iter::repeat([5u32, 9u32, 14u32, 20u32])
                .take(4)
                .collect::<Vec<[u32; 4]>>()
                .iter(),
        )
        .chain(
            std::iter::repeat([4u32, 11u32, 16u32, 23u32])
                .take(4)
                .collect::<Vec<[u32; 4]>>()
                .iter(),
        )
        .chain(
            std::iter::repeat([6u32, 10u32, 15u32, 21u32])
                .take(4)
                .collect::<Vec<[u32; 4]>>()
                .iter(),
        )
        .flatten()
        .copied()
        .collect::<Vec<u32>>()
}

#[allow(clippy::many_single_char_names, dead_code)]
fn md5(raw_message: &str) -> String {
    let rotations: Vec<u32> = build_rotations();

    assert_eq!(64, rotations.len());

    let mut hash_state: [u32; 4] = [
        0x6745_2301u32,
        0xefcd_ab89u32,
        0x98ba_dcfeu32,
        0x1032_5476u32,
    ];

    let message = preprocess_little_endian(raw_message.to_string());
    let message_as_chars = message.chars().collect::<Vec<char>>();

    for word in message_as_chars.chunks_exact(BLOCK_SIZE).map(&to_md5_word) {
        assert_eq!(16, word.len());

        let mut a_val: u32 = hash_state[0];
        let mut b_val: u32 = hash_state[1];
        let mut c_val: u32 = hash_state[2];
        let mut d_val: u32 = hash_state[3];

        // Because we have 64 rotations, this will go round 64x per word-block
        for (i, rotation_as_fn_of_i) in rotations.iter().enumerate() {
            // We calculate this value using bitwise ops, the selection of which
            // is based in i (or rather on an array of 4 operations)
            let f_as_value_from_i_picked_fn: u32;

            // g is similarly index-based by array-of-4
            let g_as_index_into_word: usize;

            // bitwise & is commutative+associative, so we can reorder those
            match i {
                // First 15 iterations use this, etc.
                0..=15 => {
                    // F := (B and C) or ((not B) and D)
                    // g := i
                    f_as_value_from_i_picked_fn = (b_val & c_val) | (!b_val & d_val);
                    g_as_index_into_word = i;
                }
                // then the next 15...
                16..=31 => {
                    // F := (D and B) or ((not D) and C)
                    // g := (5×i + 1) mod 16
                    f_as_value_from_i_picked_fn = (b_val & d_val) | (c_val & !d_val);
                    g_as_index_into_word = (5 * i + 1) % 16;
                }
                32..=47 => {
                    // F := B xor C xor D
                    // g := (3×i + 5) mod 16
                    f_as_value_from_i_picked_fn = b_val ^ c_val ^ d_val;
                    g_as_index_into_word = (3 * i + 5) % 16;
                }
                48..=63 => {
                    // F := C xor (B or (not D))
                    // g := (7×i) mod 16
                    f_as_value_from_i_picked_fn = c_val ^ (b_val | !d_val);
                    g_as_index_into_word = (7 * i) % 16;
                }
                _ => panic!("Indexing broke"),
            }

            // `try_into.unwrap` is us saying "no seriously, this is totally not
            // bigger than a u32 I promise be nice"
            let i_as_u32: u32 = i.try_into().unwrap();

            let value_of_word_at_g: u32 = word[g_as_index_into_word];
            println!("value - {}", value_of_word_at_g);

            // we "reorder" every iteration
            // fuck temp variables, temp ALL THE VARIABLES
            // WE HAVE THE MEMORY
            let d_before_swap = d_val;
            let c_before_swap = c_val;
            let b_before_swap = b_val;
            let a_before_swap = a_val;

            d_val = c_before_swap; // @2 -> @3
            c_val = b_before_swap; // @1 -> @2
            a_val = d_before_swap; // @3 -> @0

            b_val = calc_b(
                a_before_swap,
                b_before_swap,
                f_as_value_from_i_picked_fn,
                i_as_u32,
                value_of_word_at_g,
                *rotation_as_fn_of_i,
            );
        }

        hash_state[0] = hash_state[0].wrapping_add(a_val);
        hash_state[1] = hash_state[1].wrapping_add(b_val);
        hash_state[2] = hash_state[2].wrapping_add(c_val);
        hash_state[3] = hash_state[3].wrapping_add(d_val);
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
    fn test_empty_string() {
        // basis: https://rosettacode.org/wiki/MD5/Implementation_Debug for ""
        let input = "";
        let message = preprocess_little_endian(input.to_string());
        let message_as_chars = message.chars().collect::<Vec<char>>();
        assert_eq!(512, message_as_chars.len());

        let mut blocks = message_as_chars.chunks_exact(BLOCK_SIZE).map(&to_md5_word);
        assert_eq!(1, blocks.len());

        let only_block = blocks.next().unwrap();

        assert_eq!(128, only_block[0]);
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

        // THIS ONE IS WRONG BUT CHARACTERIZATION
        assert_eq!(
            md5(""),
            "d98c1dd404b2008f980980e97e42f8ec",
            "characterization failed"
        );
        assert_eq!(
            md5(""),
            "d41d8cd98f00b204e9800998ecf8427e",
            "reality failed"
        );
    }
}
