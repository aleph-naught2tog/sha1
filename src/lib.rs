const BLOCK_SIZE: usize = 512; // 32 * 16
const LENGTH_OF_LENGTH_STR: usize = 64;

fn calc_zero_padding(length: usize) -> usize {
    (BLOCK_SIZE - LENGTH_OF_LENGTH_STR - length - 1) % BLOCK_SIZE
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
pub fn get_upcoming_block(chunk: &[char]) -> Vec<u32> {
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
    for chunk in blocks.chunks_exact(BLOCK_SIZE) {
        let upcoming_block: Vec<u32> = get_upcoming_block(chunk);

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

/// The goal with preprocessing the message is to get a series of blocks to
/// operate on, each of which is 512 bits in length.
///
/// The first step is to convert the message itself to a series of bits. That
/// is, given the string "a" we want to end up with "01100001", which is 97 in
/// binary. (Why 97? In ASCII, the letter "a" is represented by 97 -- for
/// example, in JavaScript if you do `String.fromCharCode(97)` you will get "a",
/// and in languages with `char`s and `int`s, you frequently move back and forth
/// between `char`s and u8 (8-bit unsigned ints -- so from 0 to 255).)
///
/// Second, we get the length of that array of bits, and write it as a 64-bit
/// int -- meaning we take the length, write it in binary, and lengthen it so it
/// has the same value but is 64 bits long by adding a bunch of 0s to the start.
/// What's important about this is that we know it will be 64 bits long --
/// because we are _making_ it 64 bits long.
///
/// Next, we add a "1" to the end of the message -- because the algorithm says
/// so.
///
/// Finally, before we add on the 64-bits telling us how long the message was
/// originally, we add a ton of zeroes -- enough to make sure that, once we add
/// that 64-bit length, our whole message is something nicely divisible by 512.
///
/// "abc" -> "01100001 01100010 01100011" (24 bits)
/// length = 8
/// length_as_64_bit_str = 63 0's and a 1
/// number_of_zeroes = 512 - 1 - 64 - length; // 423 zeroes
/// "01100001 01100010 01100011" + "1" + 423 0s + (63 0s + 1)
fn preprocess(raw_message: String) -> String {
    let as_bits = to_bits(&raw_message);

    let length = as_bits.len();
    let length_as_64bit_str = format!("{:064b}", length);

    let zeroes = "0".repeat(calc_zero_padding(length));

    let mut message: String = as_bits.iter().collect::<String>();
    message += "1"; // 'cuz the algorithm says to
    message += &zeroes;
    message += &length_as_64bit_str;

    assert_eq!(0, message.len() % BLOCK_SIZE);

    message
}

fn to_bits(input: &str) -> Vec<char> {
    input
        .as_bytes()
        .iter()
        .flat_map(|byte| to_bit_string(*byte))
        .collect::<Vec<char>>()
}

fn to_hex_string(value: u32) -> Vec<char> {
    format!("{:08x}", value).chars().collect::<Vec<char>>()
}

fn to_bit_string(byte: u8) -> Vec<char> {
    format!("{:08b}", byte).chars().collect::<Vec<char>>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_preprocess() {
        let message = "abc";
        let rest = String::from("01100001")
            + &String::from("01100010")
            + &String::from("01100011")
            + &String::from("1")
            + &"0".repeat(423)
            + &String::from("0000000000000000000000000000000000000000000000000000000000011000");

        assert_eq!(rest, preprocess(message.to_string()));
    }

    #[test]
    fn test_num_zeros() {
        let message = "abc";
        let length = to_bits(&message).len();
        assert_eq!(423, calc_zero_padding(length));
    }

    #[test]
    fn it_works() {
        let input = "abc";
        let output = sha1(input);

        assert_eq!("a9993e364706816aba3e25717850c26c9cd0d89d", output);
    }

    #[test]
    fn lazy_dog_test() {
        let input = "The quick brown fox jumps over the lazy dog";
        let output = sha1(input);

        assert_eq!("2fd4e1c67a2d28fced849ee1bb76e7391b93eb12", output);
    }

    #[test]
    fn test_to_bits() {
        assert_eq!("01100001", to_bits("a").iter().collect::<String>());
        assert_eq!("01100010", to_bits("b").iter().collect::<String>());
        assert_eq!("01100011", to_bits("c").iter().collect::<String>());
    }
}
