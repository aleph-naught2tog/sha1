pub const BLOCK_SIZE: usize = 512; // 32 * 16
const LENGTH_OF_LENGTH_STR: usize = 64;

pub fn calc_zero_padding(length: usize) -> usize {
    (BLOCK_SIZE - LENGTH_OF_LENGTH_STR - length - 1) % BLOCK_SIZE
}

pub fn to_hex_string(value: u32) -> Vec<char> {
    format!("{:08x}", value).chars().collect::<Vec<char>>()
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
pub fn preprocess(raw_message: String) -> String {
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

pub fn preprocess_little_endian(raw_message: String) -> String {
    let as_bits = to_bits(&raw_message);

    let length = as_bits.len();
    let length_as_64bit_str = format!("{:064b}", usize::from_be(length));

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
    fn test_to_bits() {
        assert_eq!("01100001", to_bits("a").iter().collect::<String>());
        assert_eq!("01100010", to_bits("b").iter().collect::<String>());
        assert_eq!("01100011", to_bits("c").iter().collect::<String>());
    }

    #[test]
    fn test_preprocess_little_endian() {
        let output = "00110001100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000";
        assert_eq!(output, preprocess_little_endian(String::from("1")));
    }

}
