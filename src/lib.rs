#![allow(clippy::unreadable_literal, clippy::many_single_char_names)]

mod md5;
mod sha2;

mod utils;

use crate::utils::preprocess;
use crate::utils::to_hex_string;
use crate::utils::BLOCK_SIZE;

pub fn demo() {
    let inputs: [&str; 4] = ["", "1", "abc", "The quick brown fox jumps over the lazy dog"];

    for raw_message in inputs.iter() {
        println!("Raw: {}", raw_message);
        println!("  MD5: {}", md5::md5(raw_message));
        println!("  SHA1: {}", sha1(raw_message));
        println!("  SHA256: {}", sha2::sha256(raw_message));
    }
}

const K: [u32; 4] = [0x5A82_7999, 0x6ED9_EBA1, 0x8F1B_BCDC, 0xCA62_C1D6];
fn get_k(index: usize) -> u32 {
    K[(index / 20) as usize]
}

fn calculate_f(index: usize, b: u32, c: u32, d: u32) -> u32 {
    match index {
        20..=39 | 60..=79 => b ^ c ^ d,
        0..=19 => (b & c) | ((!b) & d),
        40..=59 => (b & c) | (b & d) | (c & d),
        _ => panic!("Rust broke... {}", index),
    }
}

// chunk : &[char]
// so a slice of that is &[&[char]]
fn get_upcoming_block(chunk: &[char]) -> Vec<u32> {
    // chunks_exact is on a slice and returns slices
    // but then we gather those up into a vec
    // which is how we end up with Vec<&[char]>
    let mut block_units: Vec<u32> = chunk
        .chunks_exact(32)
        .map(|block| {
            let int_bits = block.iter().collect::<String>();
            u32::from_str_radix(&int_bits, 2).unwrap()
        })
        .collect();

    assert_eq!(16, block_units.len());

    let mut upcoming_block: Vec<u32> = Vec::with_capacity(80);

    upcoming_block.append(&mut block_units);

    for index in 16..80 {
        // -3, -8, -14, -16
        let term: u32 = (upcoming_block[index - 3]
            ^ upcoming_block[index - 8]
            ^ upcoming_block[index - 14]
            ^ upcoming_block[index - 16])
            .rotate_left(1);

        upcoming_block.push(term);
    }

    upcoming_block
}

// * message length is defined as a u64
// * all other variables are u32
// * the final result itself is 160-bits aka 5 u32 values
#[allow(clippy::many_single_char_names)]
pub fn sha1(raw_message: &str) -> String {
    let should_debug = std::env::var("SHOULD_DEBUG").is_ok();

    let mut hash_state: [u32; 5] = [
        0x6745_2301,
        0xEFCD_AB89,
        0x98BA_DCFE,
        0x1032_5476,
        0xC3D2_E1F0,
    ];

    let message = preprocess(raw_message.to_string());
    let blocks = message.chars().collect::<Vec<char>>();

    /*
       Each chunk = 512-bit unit of the preprocessed message.
       Each chunk is a set 16 words -- each word being 32 bits.

       chunks_exact yields slices, which is why we end up in Slice Hell

       blocks :  Vec<char>
       chunk <- blocks.chunks_exact  : yields &[char]
       so chunk is a &[char] -- a char slice
    */
    for upcoming_block in blocks.chunks_exact(BLOCK_SIZE).map(&get_upcoming_block) {
        if should_debug {
            for v in &upcoming_block {
                println!("{:x}", v);
            }
        }

        let mut a: u32 = hash_state[0];
        let mut b: u32 = hash_state[1];
        let mut c: u32 = hash_state[2];
        let mut d: u32 = hash_state[3];
        let mut e: u32 = hash_state[4];

        for (index, current_item) in upcoming_block.iter().enumerate() {
            let constant_k = get_k(index); // <- independent

            let f_value = calculate_f(index, b, c, d);
            let temp = a
                .rotate_left(5)
                .wrapping_add(f_value)
                .wrapping_add(e)
                .wrapping_add(constant_k)
                .wrapping_add(*current_item); // independent

            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;

            if should_debug {
                println!(
                    "t={:>2}: {:08X} {:08X} {:08X} {:08X} {:08X}",
                    index, a, b, c, d, e
                )
            }
        }

        hash_state[0] = a.wrapping_add(hash_state[0]);
        hash_state[1] = b.wrapping_add(hash_state[1]);
        hash_state[2] = c.wrapping_add(hash_state[2]);
        hash_state[3] = d.wrapping_add(hash_state[3]);
        hash_state[4] = e.wrapping_add(hash_state[4]);
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
    fn it_works() {
        let input = "abc";
        let output = sha1(input);

        assert_eq!("a9993e364706816aba3e25717850c26c9cd0d89d", output);
    }

    #[test]
    fn test_md5() {
        assert_eq!(md5::md5("1"), "c4ca4238a0b923820dcc509a6f75849b");
        assert_eq!(md5::md5(""), "d41d8cd98f00b204e9800998ecf8427e");

        assert_eq!(
            md5::md5("The quick brown fox jumps over the lazy dog"),
            "9e107d9d372bb6826bd81d3542a419d6"
        );

        assert_eq!(
            md5::md5("The quick brown fox jumps over the lazy dog."),
            "e4d909c290d0fb1ca068ffaddf22cbd0"
        );
    }

}
