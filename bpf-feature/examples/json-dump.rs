#[cfg(feature = "serde")]
fn main() {
    use bpf_feature::{detect, DetectOpts};
    let features = detect(DetectOpts::default());
    let json_dump = serde_json::to_string_pretty(&features).unwrap();
    println!("{}", json_dump)
}

#[cfg(not(feature = "serde"))]
fn main() {}
