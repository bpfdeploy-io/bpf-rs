use bpf_feature::{detect, DetectOpts};

fn main() {
    let features = detect(DetectOpts::default()).unwrap();
    let json_dump = serde_json::to_string_pretty(&features).unwrap();
    println!("{}", json_dump)
}
