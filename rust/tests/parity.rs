//! Cross-SDK tokenizer parity: normalize_path must match the canonical vectors byte-for-byte.
//! Source of truth: ../tokenize.vectors.json (key "normalizePath"), kept in sync with
//! packages/shared/src/tokenize.ts.

use nemesis_shield::Client;

#[test]
fn normalize_path_matches_canonical_vectors() {
    let raw = include_str!("../../tokenize.vectors.json");
    let doc: serde_json::Value = serde_json::from_str(raw).expect("valid vectors JSON");
    let cases = doc["normalizePath"].as_array().expect("normalizePath array");

    let mut failures: Vec<String> = Vec::new();
    for c in cases {
        let path = c["path"].as_str().unwrap();
        let expect = c["expect"].as_str().unwrap();
        let got = Client::normalize_path(path);
        if got != expect {
            failures.push(format!("path={:?}  expect={:?}  got={:?}", path, expect, got));
        }
    }

    let total = cases.len();
    let passed = total - failures.len();
    println!("tokenizer parity: {}/{} passed", passed, total);
    assert!(
        failures.is_empty(),
        "{}/{} vectors failed:\n{}",
        failures.len(),
        total,
        failures.join("\n")
    );
}
