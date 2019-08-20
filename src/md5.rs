use crate::to_hex_string;
use crate::utils::preprocess_little_endian;
use crate::utils::BLOCK_SIZE;
use std::convert::TryInto;

fn fn_f(b_val: u32, c_val: u32, d_val: u32) -> u32 {
    (b_val & c_val) | (!b_val & d_val)
}

fn fn_g(b_val: u32, c_val: u32, d_val: u32) -> u32 {
    (b_val & d_val) | (c_val & !d_val)
}

fn fn_h(b_val: u32, c_val: u32, d_val: u32) -> u32 {
    b_val ^ c_val ^ d_val
}

fn fn_i(b_val: u32, c_val: u32, d_val: u32) -> u32 {
    c_val ^ (b_val | !d_val)
}

/// One MD5 operation. MD5 consists of 64 of these operations, grouped in four
/// rounds of 16 operations.
///
/// `F` is a nonlinear function; one function is used in each round. as inputs,
///     it takes: B, C, and D
///
/// `M_i` denotes a 32-bit block of the message input
///
/// `K_i` denotes a 32-bit constant, different for each operation.
///
/// `<<<_s` denotes a left bit rotation by `s` places
///
///  `s` varies for each operation.
///
/// `⊞` addition modulo 2 ** 32.
///
/// If we view ABCD as a 4-u32 wide register, then A = value@0, B = value@1, C = value@2, D = value@3
///
/// In one operation:
///
/// * D is used as an argument in F, and D is placed in A
/// * C is used as an argument in F, and C is placed in D
/// * B is used as an argument in F, and B is placed into C, and added in with ⊞
///     into the NewValueChain right before assigning NewValueChain's value into
///     B (or NewValueChainWithoutB is added to B and the result is assigned to
///     B) -- this last step is _identical_ to step 5 in A's consumption below
///     (they are the same step, it is not a repeated step, it occurs once and
///     only once)
/// * A is consumed by the below chain, whose FINAL result is placed into B
///     1. we ⊞ in the value of F computed above
///     2. we ⊞ in M_i
///     3. we ⊞ in K_i
///     4. we <<< by s
///     5. we ⊞ in B

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
    let ops = [fn_f, fn_g, fn_h, fn_i];

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

        let mut slots = [hash_state[0], hash_state[1], hash_state[2], hash_state[3]];

        // Because we have 64 rotations, this will go round 64x per word-block
        for (i, rotation_as_fn_of_i) in rotations.iter().enumerate() {
            // `try_into.unwrap` is us saying "no seriously, this is totally not
            // bigger than a u32 I promise be nice"
            let i_as_u32: u32 = i.try_into().unwrap();

            let switch_i = (i / 16usize) % 4usize;
            // We calculate this value using bitwise ops, the selection of which
            // is based in i (or rather on an array of 4 operations)
            let f_value_from_fn = ops[switch_i](slots[1], slots[2], slots[3]);

            // g is similarly index-based by array-of-4
            let g_as_index_into_word: usize = match switch_i {
                0 => i,
                1 => (5 * i + 1) % 16,
                2 => (3 * i + 5) % 16,
                3 => (7 * i) % 16,
                _ => panic!("Indexing broke"),
            };

            let value_of_word_at_g: u32 = word[g_as_index_into_word];

            let mut chain_value = f_value_from_fn;
            chain_value = chain_value.wrapping_add(slots[0]);
            chain_value = chain_value.wrapping_add(get_md5_k(i_as_u32));
            chain_value = chain_value.wrapping_add(value_of_word_at_g);

            let new_b = slots[1].wrapping_add(chain_value.rotate_left(*rotation_as_fn_of_i));

            slots.rotate_right(1);
            slots[1] = new_b;
        }

        hash_state[0] = hash_state[0].wrapping_add(slots[0]);
        hash_state[1] = hash_state[1].wrapping_add(slots[1]);
        hash_state[2] = hash_state[2].wrapping_add(slots[2]);
        hash_state[3] = hash_state[3].wrapping_add(slots[3]);
    }

    hash_state[0] = hash_state[0].swap_bytes();
    hash_state[1] = hash_state[1].swap_bytes();
    hash_state[2] = hash_state[2].swap_bytes();
    hash_state[3] = hash_state[3].swap_bytes();

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

    #[allow(non_snake_case, clippy::unreadable_literal)]
    #[test]
    fn test_ops() {
        // these defs come from an example Rust impl
        let F = |X: u32, Y: u32, Z: u32| -> u32 { X & Y | !X & Z };
        let G = |X: u32, Y: u32, Z: u32| -> u32 { X & Z | Y & !Z };
        let H = |X: u32, Y: u32, Z: u32| -> u32 { X ^ Y ^ Z };
        let I = |X: u32, Y: u32, Z: u32| -> u32 { Y ^ (X | !Z) };

        // just a big bunch of random values
        let values: Vec<u32> = vec![
            3188615988, 695841496, 2216164062, 4132908602, 535119995, 3476992632, 4108338822,
            3771368763, 1763960359, 2847101384, 780277327, 707972203, 3866577126, 3254757686,
            3876623650, 2341751893, 852600694, 2195646517, 2645321974, 304583403, 3700534932,
            523776973, 2084116420, 2125555861, 544439779, 3895293508, 3069408009, 3969418735,
            3107684498, 2211572384,
        ];

        for set in values.chunks_exact(3) {
            match set {
                [x_ref, y_ref, z_ref] => {
                    let x = *x_ref;
                    let y = *y_ref;
                    let z = *z_ref;

                    assert_eq!(fn_f(x, y, z), F(x, y, z));
                    assert_eq!(fn_g(x, y, z), G(x, y, z));
                    assert_eq!(fn_h(x, y, z), H(x, y, z));
                    assert_eq!(fn_i(x, y, z), I(x, y, z));
                }
                _ => break,
            }
        }
    }

    #[test]
    fn test_md5() {
        assert_eq!(md5("1"), "c4ca4238a0b923820dcc509a6f75849b");
        assert_eq!(md5(""), "d41d8cd98f00b204e9800998ecf8427e");

        assert_eq!(
            md5("The quick brown fox jumps over the lazy dog"),
            "9e107d9d372bb6826bd81d3542a419d6"
        );

        assert_eq!(
            md5("The quick brown fox jumps over the lazy dog."),
            "e4d909c290d0fb1ca068ffaddf22cbd0"
        );

    }
}
