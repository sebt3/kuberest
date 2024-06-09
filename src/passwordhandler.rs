use rand::{
    distributions::{Distribution, Uniform, WeightedIndex},
    thread_rng, RngCore,
};

//const LOWER: &[char] = &['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'];
//const UPPER: &[char] = &['A', 'B', 'C', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'];
const ALPHA: &[char] = &[
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u',
    'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
];
const NUMBERS: &[char] = &['0', '1', '2', '3', '4', '5', '6', '7', '8', '9'];
const SYMBOLS: &[char] = &[
    '~', '`', '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '-', '_', '+', '=', '{', '}', '[', ']', '|',
    '\\', ':', ';', '"', '\'', ',', '<', '>', '.', '/', '?',
];

pub struct Passwords {
    rng: Box<dyn RngCore>,
}
impl Passwords {
    #[must_use]
    pub fn new() -> Passwords {
        Passwords {
            rng: Box::new(thread_rng()),
        }
    }

    pub fn generate(&mut self, length: u32, alpha: u32, numbers: u32, symbols: u32) -> String {
        let mut character_sets = vec![ALPHA];
        if numbers > 0 {
            character_sets.push(NUMBERS);
        }
        if symbols > 0 {
            character_sets.push(SYMBOLS);
        }
        let weights = match (numbers > 0, symbols > 0) {
            (true, true) => vec![alpha, numbers, symbols],
            (true, false) => vec![alpha, numbers],
            (false, true) => vec![alpha, symbols],
            (false, false) => vec![alpha],
        };
        let weighted_dist = WeightedIndex::new(weights).unwrap();
        let mut password = String::with_capacity(length as usize);
        for _ in 0..length {
            let selected_set = character_sets.get(weighted_dist.sample(&mut self.rng)).unwrap();
            let dist_char = Uniform::from(0..selected_set.len());
            let index = dist_char.sample(&mut self.rng);
            password.push(selected_set[index]);
        }
        password
    }
}
