//! Serialization utilities for generating snforge-compatible JSON test data.
//!
//! Produces JSON in the format expected by Cairo's `read_json` + `Serde::deserialize`.
//! Values must be JSON integers (not strings) for snforge to parse correctly.

use crate::poseidon_hash::Felt;
use num_bigint::BigUint;
use serde_json::{json, Number, Value};

/// Serialize an array of u16 values as Cairo Serde: [length, v0, v1, ...]
fn serde_u16_array(values: &[u16]) -> Vec<Value> {
    let mut out = Vec::with_capacity(values.len() + 1);
    out.push(Value::Number(Number::from(values.len())));
    for &v in values {
        out.push(Value::Number(Number::from(v)));
    }
    out
}

/// Serialize an array of Felt values as Cairo Serde: [length, f0, f1, ...]
/// Felt values that fit in u64 are serialized as JSON numbers.
/// Larger values are serialized as decimal strings (snforge handles both).
fn serde_felt_array(values: &[Felt]) -> Vec<Value> {
    let mut out = Vec::with_capacity(values.len() + 1);
    out.push(Value::Number(Number::from(values.len())));
    for v in values {
        out.push(felt_to_json_value(v));
    }
    out
}

fn felt_to_json_value(f: &Felt) -> Value {
    let bytes = f.to_bytes_be();
    let num = BigUint::from_bytes_be(&bytes);
    let decimal = num.to_string();
    // Use arbitrary_precision to emit large numbers as JSON integers (not strings)
    Value::Number(Number::from_string_unchecked(decimal))
}

/// Generate snforge-compatible JSON for hash_to_point test data.
pub fn hash_to_point_test_json(
    message: &[Felt],
    salt: &[Felt],
    expected: &[u16],
) -> Value {
    let mut payload = Vec::new();
    payload.extend(serde_felt_array(message));
    payload.extend(serde_felt_array(salt));
    payload.extend(serde_u16_array(expected));
    json!({ "hash_to_point_test": payload })
}

/// Generate snforge-compatible JSON for packing test data.
pub fn packing_test_json(values: &[u16], packed: &[Felt]) -> Value {
    let mut payload = Vec::new();
    payload.extend(serde_u16_array(values));
    payload.extend(serde_felt_array(packed));
    json!({ "packing_test": payload })
}
