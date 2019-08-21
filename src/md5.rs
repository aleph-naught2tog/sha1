// #![allow(clippy::unreadable_literal)]

use crate::utils::to_hex_string;
use crate::utils::preprocess_little_endian;
use crate::utils::BLOCK_SIZE;
use std::convert::TryInto;

mod state;
use state::State;

fn round_0_op(b_val: u32, c_val: u32, d_val: u32) -> u32 {
    (b_val & c_val) | (!b_val & d_val)
}

fn round_1_op(b_val: u32, c_val: u32, d_val: u32) -> u32 {
    (b_val & d_val) | (c_val & !d_val)
}

fn round_2_op(b_val: u32, c_val: u32, d_val: u32) -> u32 {
    b_val ^ c_val ^ d_val
}

fn round_3_op(b_val: u32, c_val: u32, d_val: u32) -> u32 {
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

fn to_md5_words(chunk: &[char]) -> Vec<u32> {
    chunk
        .chunks_exact(32)
        .map(|block| {
            let int_bits = block.iter().collect::<String>();
            let value = u32::from_str_radix(&int_bits, 2).unwrap();
            u32::from_be(value)
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

pub fn md5(raw_message: &str) -> String {
    let should_debug = std::env::var("SHOULD_DEBUG").is_ok();

    const INITIAL_HASH_STATE: [u32; 4] = [
        0x6745_2301u32,
        0xefcd_ab89u32,
        0x98ba_dcfeu32,
        0x1032_5476u32,
    ];

    const OPERATIONS: [fn(u32, u32, u32) -> u32; 4] =
        [round_0_op, round_1_op, round_2_op, round_3_op];

    let rotations: Vec<u32> = build_rotations();

    let mut hash_state: [u32; 4] = INITIAL_HASH_STATE;

    let message = preprocess_little_endian(raw_message.to_string());
    let message_as_chars = message.chars().collect::<Vec<char>>();

    assert_eq!(0, message_as_chars.len() % BLOCK_SIZE);

    let mut state = State::new(hash_state);

    for chunk in message_as_chars.chunks_exact(BLOCK_SIZE) {
        // Each chunk is 512 bits
        // `to_md5_words` is a vec of 32-bit words
        let words = to_md5_words(chunk);

        // 16 * 32 = 512, hence our 16 words for enumeration.
        assert_eq!(16, words.len());

        // Because we have 64 rotations, this will go round 64x per words-block
        for (index, rotation) in rotations.iter().enumerate() {
            // --- varies over index, invariant over message ---
            // both our operation and how we index into the word are based on an
            // array of four values
            let round_index = (index / 16usize) % 4usize;
            if should_debug && index % 16 == 0 {
                println!("\nRound {}", round_index + 1);
            }

            let operation = OPERATIONS[round_index];
            let word_index: usize = match round_index {
                0 => index,
                1 => (5 * index + 1) % 16,
                2 => (3 * index + 5) % 16,
                3 => (7 * index) % 16,
                _ => panic!("Indexing broke"),
            };

            state.index = index;
            state.round_index = round_index;
            state.word_index = word_index;
            state.word_index_one = state.word_index + 1;

            // `try_into.unwrap` is us saying "no seriously, this is totally not
            // bigger than a u32 I promise be nice"
            // since `i` varies between 0 and 63, that's a solid bet
            let constant = get_md5_k(index.try_into().unwrap());
            state.constant = constant;

            // --- variant over message ---
            let word: u32 = words[word_index];

            let operation_result = operation(state.slots[1], state.slots[2], state.slots[3]);

            let intermediate_value = operation_result
                .wrapping_add(state.slots[0])
                .wrapping_add(constant)
                .wrapping_add(word)
                .rotate_left(*rotation);

            /*
             assign to the first slot ('a') here + rotate the set *after*

             this is equivalent to:
                  1. assigning this value to a temp variable
                  2. rotating everything rightwards by 1
                  3. assigning the temp variable to the first slot

            (this is also why some impls look like they assign the
            calculated value to `b` and others to `a`)
            */
            state.slots[0] = state.slots[1].wrapping_add(intermediate_value);

            if should_debug {
                state.pretty_print();
            }

            // rotate names after we print
            state.rotate_right();
        }

        hash_state[0] = hash_state[0].wrapping_add(state.slots[0]);
        hash_state[1] = hash_state[1].wrapping_add(state.slots[1]);
        hash_state[2] = hash_state[2].wrapping_add(state.slots[2]);
        hash_state[3] = hash_state[3].wrapping_add(state.slots[3]);
    }

    hash_state
        .iter()
        .flat_map(|value| to_hex_string(u32::from_be(*value)))
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
    fn test_to_md5_word_short() {
        let raw_message = "1";
        let message = preprocess_little_endian(raw_message.to_string());
        let blocks = message.chars().collect::<Vec<char>>();
        let block = blocks.chunks_exact(BLOCK_SIZE).next().unwrap();
        let res = to_md5_words(block);
        assert_eq!(32817, *res.get(0).unwrap());
        assert_eq!(raw_message.len() as u32 * 8u32, *res.get(14).unwrap());
    }

    #[test]
    fn test_to_md5_word_long() {
        let raw_message = "The";
        let message = preprocess_little_endian(raw_message.to_string());
        let blocks = message.chars().collect::<Vec<char>>();
        let block = blocks.chunks_exact(BLOCK_SIZE).next().unwrap();
        let res = to_md5_words(block);
        assert_eq!(2_154_129_492, *res.get(0).unwrap());
        assert_eq!(
            raw_message.as_bytes().len() as u32 * 8u32,
            *res.get(14).unwrap()
        );
    }

}
