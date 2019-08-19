use std::convert::TryInto;

fn to_bits(input: &str) -> Vec<char> {
    input
        .as_bytes()
        .iter()
        .flat_map(|byte: &u8| format!("{:08b}", byte).chars().collect::<Vec<char>>())
        .collect::<Vec<char>>()
}

pub fn from_binary(word: &[char]) -> u32 {
    isize::from_str_radix(&word.iter().cloned().collect::<String>(), 2)
        .unwrap()
        .try_into()
        .unwrap()
}

// these are all temp variables used for computation
struct Workers {
    a: u32,
    b: u32,
    c: u32,
    d: u32,
    e: u32,
}

// these only get set within the loop based on the index
struct Noise {
    f: u32,
    k: u32,
}

fn make_noise(index: u32, workers: &Workers) -> Noise {
    let Workers { b, c, d, .. } = workers;

    match index {
        _ if index <= 29 => {
            //    f = (b and c) or ((not b) and d)
            let f = (b & c) | ((!b) & d);
            let k = 0x5A82_7999;
            Noise { f, k }
        }
        _ if index <= 39 => {
            // f = b xor c xor d
            let f = b ^ c ^ d;
            let k = 0x6ED9_EBA1;
            Noise { f, k }
        }
        _ if index <= 59 => {
            // f = (b and c) or (b and d) or (c and d)
            let f = (b & c) | (b & d) | (c & d);
            let k = 0x8F1B_BCDC;
            Noise { f, k }
        }
        _ if index <= 79 => {
            // f = b xor c xor d
            let f = b ^ c ^ d;
            let k = 0xCA62_C1D6;
            Noise { f, k }
        }
        _ => panic!("Rust broke..."),
    }
}

const BLOCK_SIZE: usize = 512; // 32 * 16

pub fn sha1(_message: &str) -> (u32, u32, u32, u32, u32) {
    let mut message = String::from("abc");

    let mut hash_state: [u32; 5] = [
        0x6745_2301,
        0xEFCD_AB89,
        0x98BA_DCFE,
        0x1032_5476,
        0xC3D2_E1F0,
    ];

    message += "1";

    // message_length... is a 64 bit quantity
    // + 1 for the '1'
    // + 1 for the added length onto here
    let message_length_in_bytes: u64 = (message.len() as u64) / 4 + 1 + 1;
    let len_as_bits = format!("{:064b}", message_length_in_bytes)
        .chars()
        .collect::<String>();

    assert_eq!(64, len_as_bits.len());

    while BLOCK_SIZE - (message.len() % BLOCK_SIZE) != 64 {
        message += "0";
    }

    message += &len_as_bits;

    // assert_eq!(0, message.len() % BLOCK_SIZE);
    println!("{}", message);
    let as_bits = to_bits(&message);
    // 11000010110001001100011100000000000000000000011000
    //011000010110001001100011
    //0011000100110000001
    println!("{}", as_bits.iter().collect::<String>());
    let blocks = as_bits.chunks_exact(BLOCK_SIZE);

    for chunk in blocks {
        let u32_pieces: Vec<&[char]> = chunk.chunks_exact(32).collect();
        let mut values: Vec<u32> = Vec::with_capacity(80);

        for num in u32_pieces {
            let as_int = from_binary(num);
            values.push(as_int);
        }

        for index in 16..80 {
            let term: u32 =
                (values[index - 3] ^ values[index - 8] ^ values[index - 14] ^ values[index - 16])
                    .rotate_left(1);

            values.push(term);
        }

        let mut workers = Workers {
            a: hash_state[0],
            b: hash_state[1],
            c: hash_state[2],
            d: hash_state[3],
            e: hash_state[4],
        };

        for index in 0..79 {
            let Noise { f, k } = make_noise(index, &workers);

            let temp = workers
                .a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(workers.e)
                .wrapping_add(k)
                .wrapping_add(values[index as usize]);

            workers.e = workers.d;
            workers.d = workers.c;
            workers.c = workers.b.rotate_left(30);
            workers.b = workers.a;
            workers.a = temp;
        }

        hash_state[0] = hash_state[0].wrapping_add(workers.a);
        hash_state[1] = hash_state[1].wrapping_add(workers.b);
        hash_state[2] = hash_state[2].wrapping_add(workers.c);
        hash_state[3] = hash_state[3].wrapping_add(workers.d);
        hash_state[4] = hash_state[4].wrapping_add(workers.e);
    }

    (
        hash_state[0],
        hash_state[1],
        hash_state[2],
        hash_state[3],
        hash_state[4],
    )
}

const LENGTH_OF_LENGTH_STR: usize = 64;

fn calc_zero_padding(length: usize) -> usize {
    (BLOCK_SIZE - LENGTH_OF_LENGTH_STR - length - 1) % BLOCK_SIZE
}

fn preprocess(mut message: String) {
    let as_bits = to_bits(&message);
    let length = as_bits.len();
    let number_of_zeroes = calc_zero_padding(length);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_bits() {
        assert_eq!("01100001", to_bits("a").iter().collect::<String>());
        assert_eq!("01100010", to_bits("b").iter().collect::<String>());
        assert_eq!("01100011", to_bits("c").iter().collect::<String>());
    }

    #[test]
    fn test_num_zeros() {
        let message = "abc";
        let length = to_bits(&message).len();
        assert_eq!(423, calc_zero_padding(length));
    }

    #[test]
    fn it_works() {
        // let input = "abc";
        // let output = sha1(input);

        // println!("{:#?}", output);

        // let (a, b, c, d, e) = output;
        // println!("{:08x} {:08x} {:08x} {:08x} {:08x}", a, b, c, d, e);

        // // this is not necessarily correct, but characterizes this state.
        // assert_eq!(
        //     "481c469ee2e6dddeccff0bf8a876cb04639efb",
        //     format!("{:x}{:x}{:x}{:x}{:x}", a, b, c, d, e)
        // );
    }
}
