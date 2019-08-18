use core::arch::x86_64;
use std::iter::FlatMap;

fn to_bits(input: &str) -> Vec<char> {
    input
        .as_bytes()
        .iter()
        .flat_map(|byte: &u8| format!("{:08b}", byte).chars().collect::<Vec<char>>())
        .collect::<Vec<char>>()
}

pub fn sha1(message: &str) {
    let mut as_bits = to_bits(message);

    let h0: u32 = 0x6745_2301;
    let h1: u32 = 0xEFCD_AB89;
    let h2: u32 = 0x98BA_DCFE;
    let h3: u32 = 0x1032_5476;
    let h4: u32 = 0xC3D2_E1F0;

    let m1 = as_bits.len();
    let mut len_as_bits = format!("{:064b}", m1 as u64).chars().collect::<Vec<char>>();

    println!("{}", as_bits.len());

    as_bits.append(&mut vec!['1']);
    println!("{}", as_bits.len());

    while (as_bits.len() % 512) != (448 % 512) {
        as_bits.append(&mut vec!['0']);
    }

    println!("{}", as_bits.len());
    println!("{:#?}", len_as_bits);
    as_bits.append(&mut len_as_bits);

    println!("{}", as_bits.len());
    assert_eq!(0, as_bits.len() % 512);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        sha1("a");
    }
}
