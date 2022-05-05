use serde::{
    ser::{Serialize, SerializeMap, SerializeSeq},
    Serializer,
};
use std::collections::HashMap;

#[derive(serde::Serialize)]
pub struct SerializableError {
    pub msg: &'static str,
}

pub fn flatten_result<S>(
    result: &Result<impl Serialize, impl Serialize>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match result {
        Ok(t) => t.serialize(serializer),
        Err(e) => e.serialize(serializer),
    }
}

pub fn to_list<S, E>(
    map: &HashMap<impl Serialize, Result<bool, E>>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut seq = serializer.serialize_seq(None)?;
    for (k, v) in map.iter() {
        match v {
            Ok(true) => {
                seq.serialize_element(k)?;
            }
            _ => {}
        };
    }
    seq.end()
}

pub fn to_list_inner<S, E>(
    map: &HashMap<impl Serialize, Vec<Result<impl Serialize, E>>>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut seq = serializer.serialize_map(None)?;
    for (k, v) in map.iter() {
        let ok_items: Vec<_> = v
            .iter()
            .filter_map(|r| match r {
                Ok(h) => Some(h),
                Err(_) => None,
            })
            .collect();
        seq.serialize_entry(k, &ok_items)?
    }
    seq.end()
}
