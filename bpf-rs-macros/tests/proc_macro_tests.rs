// TESTME: Look into using dtolnay's trybuild crate for proc macros
// Example of its use: https://github.com/auto-impl-rs/auto_impl

// Needs to be in sync with actual trait from bpf-rs
trait StaticName {
    fn name(&self) -> &'static str;
}

#[test]
fn test_derive_display() {
    use bpf_rs_macros::Display;
    #[derive(Display)]
    struct Person(&'static str);

    impl StaticName for Person {
        fn name(&self) -> &'static str {
            self.0
        }
    }

    let alice = Person("alice");
    assert_eq!(alice.to_string(), "alice");
}

#[cfg(feature = "serde")]
#[test]
fn test_derive_serialize() {
    use bpf_rs_macros::SerializeFromDisplay;

    #[derive(SerializeFromDisplay)]
    struct Person(&'static str);

    impl std::fmt::Display for Person {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    let alice = Person("alice");
    assert_eq!(alice.to_string(), "alice");
}
