use poseidon_rs::poseidon2::{Poseidon2, Fr};
use std::fs::File;
use std::io::Write;
use serde::Serialize;

#[derive(Serialize)]
struct Input {
    x: Vec<Fr>,
    hash: String,
}

fn main() {
    let inputs = vec![Fr::from(123456789u64), Fr::from(987654321u64)];
    let poseidon = Poseidon2::new(2);
    let hash = poseidon.hash(inputs.clone());

    let input_struct = Input {
        x: inputs,
        hash: format!("{}", hash),
    };

    let json_str = serde_json::to_string_pretty(&input_struct).unwrap();
    let mut file = File::create("inputs/input.json").unwrap();
    file.write_all(json_str.as_bytes()).unwrap();

    println!("输入与哈希结果已写入 inputs/input.json");
}
