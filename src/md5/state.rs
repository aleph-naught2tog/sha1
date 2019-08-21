#[derive(Debug)]
pub struct State<'a> {
    // 'a is the lifetime specifier
    pub slots: [u32; 4],
    slot_names: [&'a str; 4],
    a_index: usize,
    b_index: usize,
    c_index: usize,
    d_index: usize,
    pub word_index: usize,
    pub word_index_one: usize,
    pub rotation: u32,
    pub round_index: usize,
    pub index: usize,
    pub constant: u32,
}

impl Default for State<'_> {
    fn default() -> Self {
        State {
            slots: [0, 0, 0, 0],
            slot_names: ["A", "B", "C", "D"],
            a_index: 0,
            b_index: 1,
            c_index: 2,
            d_index: 3,
            word_index: 0,
            word_index_one: 1,
            rotation: 0,
            round_index: 0,
            index: 0,
            constant: 0,
        }
    }
}

impl State<'_> {
    pub fn new(slots: [u32; 4]) -> Self {
        State {
            slots,
            ..State::default()
        }
    }

    // '_ is a placeholder for the lifetime
    pub fn rotate_right(&mut self) {
        self.slots.rotate_right(1);
        self.slot_names.rotate_right(1);
        self.a_index = (self.a_index + 1) % 4;
        self.b_index = (self.b_index + 1) % 4;
        self.c_index = (self.c_index + 1) % 4;
        self.d_index = (self.d_index + 1) % 4;
    }

    pub fn pretty_print(&self) {
        let debug_message = self.pretty_str();

        println!("{}", debug_message);
    }

    pub fn pretty_str(&self) -> String {
        let name_str = self.slot_names.join("");

        format!(
            "Applying [{names} {word_i:>2} {rot:>2} {i_plus_1:>2}]: A={slot_0:08X} B={slot_1:08X} C={slot_2:08X} D={slot_3:08X} T[0]={k_value:08X}",
            names = name_str,
            word_i = self.word_index,
            rot = self.rotation,
            i_plus_1 = self.index + 1,
            slot_0 = self.slots[self.a_index],
            slot_1 = self.slots[self.b_index],
            slot_2 = self.slots[self.c_index],
            slot_3 = self.slots[self.d_index],
            k_value = self.constant
        )
    }
}
