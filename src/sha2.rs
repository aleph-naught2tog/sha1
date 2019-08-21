// #![allow(clippy::unreadable_literal)]

use crate::utils::preprocess;
use crate::utils::to_hex_string;
use crate::utils::BLOCK_SIZE;

const ROUND_CONSTANTS: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

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

    // here we differ from Sha1
    let count = 64;
    let mut upcoming_block: Vec<u32> = Vec::with_capacity(count);

    upcoming_block.append(&mut block_units);

    for index in 16..count {
        let w_min15: u32 = upcoming_block[index - 15];
        let w_min2: u32 = upcoming_block[index - 2];
        let w_min16: u32 = upcoming_block[index - 16];
        let w_min7: u32 = upcoming_block[index - 7];

        let s0: u32 = w_min15.rotate_right(7) ^ w_min15.rotate_right(18) ^ w_min15.wrapping_shr(3);
        let s1: u32 = w_min2.rotate_right(17) ^ w_min2.rotate_right(19) ^ w_min2.wrapping_shr(10);

        let term = w_min16
            .wrapping_add(s0)
            .wrapping_add(w_min7)
            .wrapping_add(s1);

        upcoming_block.push(term);
    }

    upcoming_block
}

pub fn sha256(raw_message: &str) -> String {
    let mut hash_state: [u32; 8] = [
        0x6a09e667u32,
        0xbb67ae85u32,
        0x3c6ef372u32,
        0xa54ff53au32,
        0x510e527fu32,
        0x9b05688cu32,
        0x1f83d9abu32,
        0x5be0cd19u32,
    ];

    let message = preprocess(raw_message.to_string());
    let blocks = message.chars().collect::<Vec<char>>();

    for upcoming_block in blocks.chunks_exact(BLOCK_SIZE).map(&get_upcoming_block) {
        let mut a: u32 = hash_state[0];
        let mut b: u32 = hash_state[1];
        let mut c: u32 = hash_state[2];
        let mut d: u32 = hash_state[3];
        let mut e: u32 = hash_state[4];
        let mut f: u32 = hash_state[5];
        let mut g: u32 = hash_state[6];
        let mut h: u32 = hash_state[7];

        for (index, current_item) in upcoming_block.iter().enumerate() {
            let constant_k = ROUND_CONSTANTS[index];

            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);

            let temp1: u32 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(constant_k)
                .wrapping_add(*current_item);

            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);

            let maj = (a & b) ^ (a & c) ^ (b & c);

            let temp2: u32 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        hash_state[0] = hash_state[0].wrapping_add(a);
        hash_state[1] = hash_state[1].wrapping_add(b);
        hash_state[2] = hash_state[2].wrapping_add(c);
        hash_state[3] = hash_state[3].wrapping_add(d);
        hash_state[4] = hash_state[4].wrapping_add(e);
        hash_state[5] = hash_state[5].wrapping_add(f);
        hash_state[6] = hash_state[6].wrapping_add(g);
        hash_state[7] = hash_state[7].wrapping_add(h);
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
    fn test_sha256() {
        assert_eq!(
            sha256(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );

        assert_eq!(
            sha256("The quick brown fox jumps over the lazy dog"),
            "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
        )
    }

}
