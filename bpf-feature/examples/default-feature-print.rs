use bpf_feature::{detect, DetectOpts};

fn main() {
    println!("{:#?}", detect(DetectOpts::default()))
}
