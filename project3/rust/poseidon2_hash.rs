use poseidon_rs::poseidon2::{Poseidon2, Fr};
use std::fs::File;
use std::io::Write;

fn main() {
    let inputs = vec![
        Fr::from(123456789u64),
        Fr::from(987654321u64),
    ];
    let poseidon = Poseidon2::new(2);
    let hash = poseidon.hash(inputs.clone());

    let mut file = File::create("../inputs/input.json").unwrap();
    write!(
        file,
        "{{\n  \"x\": [{}, {}],\n  \"hash\": \"{}\"\n}}",
        inputs[0], inputs[1], hash
    )
    .unwrap();

    println!("输入与哈希结果已写入 inputs/input.json");
}
