fn to_bits(input: &str) -> Vec<char> {
    input
        .as_bytes()
        .iter()
        .flat_map(|byte: &u8| format!("{:08b}", byte).chars().collect::<Vec<char>>())
        .collect::<Vec<char>>()
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

pub fn get_schedule(chunk: &[char]) -> Vec<u32> {
    let message_blocks: Vec<&[char]> = chunk.chunks_exact(32).collect();
    let mut schedule: Vec<u32> = Vec::with_capacity(80);

    for index in 0..80 {
        match index {
            _ if index <= 15 => {
                let num = message_blocks[index];
                let w = num.iter().collect::<String>();
                let as_int = u32::from_str_radix(&w, 2).unwrap();
                schedule.push(as_int);
            }
            _ => {
                let term: u32 = (schedule[index - 3]
                    ^ schedule[index - 8]
                    ^ schedule[index - 14]
                    ^ schedule[index - 16])
                    .rotate_left(1);

                schedule.push(term);
            }
        }
    }

    schedule
}

pub fn sha1(_message: &str) -> (u32, u32, u32, u32, u32) {
    let message = String::from("abc");

    let mut hash_state: [u32; 5] = [
        0x6745_2301,
        0xEFCD_AB89,
        0x98BA_DCFE,
        0x1032_5476,
        0xC3D2_E1F0,
    ];

    let bit_blocks = preprocess(message).chars().collect::<Vec<char>>();
    let blocks = bit_blocks.chunks_exact(BLOCK_SIZE);

    /*
       Each chunk = 512-bit unit of the preprocessed message.
       Each chunk is a set 16 words -- each word being 32 bits.
    */
    for chunk in blocks {
        let schedule: Vec<u32> = get_schedule(chunk);

        for v in 0..16 {
            println!("{:x}", schedule[v]);
        }

        let mut workers = Workers {
            a: hash_state[0],
            b: hash_state[1],
            c: hash_state[2],
            d: hash_state[3],
            e: hash_state[4],
        };

        for index in 0..80 {
            let Noise { f, k } = make_noise(index, &workers);

            let temp = workers
                .a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(workers.e)
                .wrapping_add(k)
                .wrapping_add(schedule[index as usize]);

            workers.e = workers.d;
            workers.d = workers.c;
            workers.c = workers.b.rotate_left(30);
            workers.b = workers.a;
            workers.a = temp;

            println!(
                "t= {:>2}: {:08X} {:08X} {:08X} {:08X} {:08X}",
                index, workers.a, workers.b, workers.c, workers.d, workers.e
            )
        }

        hash_state[0] = workers.a.wrapping_add(hash_state[0]);
        hash_state[1] = workers.b.wrapping_add(hash_state[1]);
        hash_state[2] = workers.c.wrapping_add(hash_state[2]);
        hash_state[3] = workers.d.wrapping_add(hash_state[3]);
        hash_state[4] = workers.e.wrapping_add(hash_state[4]);
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

fn preprocess(raw_message: String) -> String {
    let as_bits = to_bits(&raw_message);
    let length = as_bits.len();
    let number_of_zeroes = calc_zero_padding(length);
    let zeroes = "0".repeat(number_of_zeroes);

    let length_as_64bit_str = format!("{:064b}", length);

    let mut message: String = as_bits.iter().collect::<String>();
    message += "1";
    message += &zeroes;
    message += &length_as_64bit_str;

    assert_eq!(0, message.len() % BLOCK_SIZE);

    message
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
    fn test_preprocess() {
        println!("{:064b}", 24);
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

        println!("{:#?}", output);

        let (a, b, c, d, e) = output;

        assert_eq!(
            "a9993e36 4706816a ba3e2571 7850c26c 9cd0d89d",
            format!("{:08x} {:08x} {:08x} {:08x} {:08x}", a, b, c, d, e)
        );
    }
}
