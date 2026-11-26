//! The kernel against the shared gate conformance vectors.
//!
//! `fixtures/selin_gate_vectors.json` is printed from this kernel by
//! `examples/selin_gate_vectors.rs`, and CI regenerates it and diffs it against the committed
//! copy. The JS edge gate (`gate.mjs`) is held to the same file by `test/gate_vectors.test.mjs`.
//!
//! A row matches when the signal, `passed` and the refusing checks are exactly as written, χ and
//! mirror χ are within 1e-12 (NaN matches only NaN), and the scores come back unchanged.

use std::collections::HashSet;

use archon_kernel::{
    AdcclGate, GateSignal, VerificationReport, CHIRAL_FLOOR, DOMAIN_REFUSAL, MIRROR_GAP_MIN,
    SOVEREIGN_CEILING,
};
use serde_json::{Map, Value};

const VECTORS: &str = include_str!("fixtures/selin_gate_vectors.json");

/// How close χ and mirror χ must be to the file's values.
const TOLERANCE: f64 = 1e-12;

/// The checks the contract names.
const CHECKS: [&str; 5] = ["domain", "floor", "mirror", "components", "ceiling"];

fn vectors() -> Value {
    serde_json::from_str(VECTORS).expect("the vector file is JSON")
}

fn text<'a>(value: &'a Value, what: &str) -> &'a str {
    value
        .as_str()
        .unwrap_or_else(|| panic!("{what}: {value} is not a string"))
}

/// A number as the file writes it: a decimal string, or NaN, Infinity, -Infinity.
fn number(value: &Value, what: &str) -> f64 {
    let s = text(value, what);
    s.parse()
        .unwrap_or_else(|e| panic!("{what}: {s:?} is not a number ({e})"))
}

fn signal_name(signal: GateSignal) -> &'static str {
    match signal {
        GateSignal::Execute => "execute",
        GateSignal::Suspend => "suspend",
        GateSignal::Abort => "abort",
    }
}

/// The checks a `rejection_reason` names, in order, read through the file's tag map.
fn refused_by(reason: Option<&str>, tags: &Map<String, Value>) -> Vec<String> {
    reason.map_or_else(Vec::new, |reason| {
        reason
            .split(" | ")
            .map(|part| {
                let tag = part.split(':').next().unwrap_or_default();
                tags.get(tag)
                    .and_then(Value::as_str)
                    .map_or_else(|| format!("unknown tag {tag:?}"), str::to_string)
            })
            .collect()
    })
}

/// Within the tolerance, and NaN only for NaN.
fn near(got: f64, want: f64) -> bool {
    if want.is_nan() {
        got.is_nan()
    } else {
        (got - want).abs() <= TOLERANCE
    }
}

/// The same double, and NaN for NaN.
fn same(got: f64, want: f64) -> bool {
    got.to_bits() == want.to_bits() || (got.is_nan() && want.is_nan())
}

/// Every way the kernel's report on `row` differs from what the row records.
fn divergences(row: &Value, tags: &Map<String, Value>) -> Vec<String> {
    let id = text(&row["id"], "id");
    let v = number(&row["v"], id);
    let j = number(&row["j"], id);
    let gate = match &row["threshold"] {
        Value::Null => AdcclGate::default(),
        t => AdcclGate::new(number(t, id)),
    };
    let report: VerificationReport = gate.evaluate(v, j);

    let expect = &row["expect"];
    let mut out = Vec::new();
    let signal = text(&expect["signal"], id);
    if signal_name(report.signal) != signal {
        out.push(format!("signal {:?}, expected {signal}", report.signal));
    }
    let passed = expect["passed"].as_bool().expect("passed is a boolean");
    if report.passed != passed {
        out.push(format!("passed {}, expected {passed}", report.passed));
    }
    if report.passed == report.rejection_reason.is_some() {
        out.push("rejection_reason must be null exactly when passed".to_string());
    }
    let want: Vec<&str> = expect["refused_by"]
        .as_array()
        .expect("refused_by is an array")
        .iter()
        .map(|c| text(c, id))
        .collect();
    let got = refused_by(report.rejection_reason.as_deref(), tags);
    if got != want {
        out.push(format!("refused by {got:?}, expected {want:?}"));
    }
    if want == ["domain"] && report.rejection_reason.as_deref() != Some(DOMAIN_REFUSAL) {
        out.push(format!(
            "domain refusal reads {:?}, expected {DOMAIN_REFUSAL:?}",
            report.rejection_reason
        ));
    }
    for (name, got) in [
        ("chi", report.chiral_invariant),
        ("mirror_chi", report.mirror_chi),
    ] {
        let want = number(&expect[name], name);
        if !near(got, want) {
            out.push(format!(
                "{name} {got:?}, expected {want:?} within {TOLERANCE:e}"
            ));
        }
    }
    if !same(report.v_gate_score, v) || !same(report.drift_penalty_j, j) {
        out.push(format!(
            "scores came back as ({:?}, {:?}), not ({v:?}, {j:?})",
            report.v_gate_score, report.drift_penalty_j
        ));
    }
    out
}

#[test]
fn vector_file_is_complete_and_uses_the_kernel_constants() {
    let file = vectors();
    assert_eq!(file["format"], "selin-gate-conformance");
    assert_eq!(file["version"], 1);

    let constants = &file["constants"];
    for (name, value) in [
        ("chiral_floor", CHIRAL_FLOOR),
        ("sovereign_ceiling", SOVEREIGN_CEILING),
        ("mirror_gap_min", MIRROR_GAP_MIN),
    ] {
        assert_eq!(
            number(&constants[name], name).to_bits(),
            value.to_bits(),
            "{name}"
        );
    }
    assert_eq!(file["domain_refusal"], DOMAIN_REFUSAL);

    let tags = file["tags"].as_object().expect("tags is an object");
    let mut named: Vec<&str> = tags.values().map(|c| text(c, "tag")).collect();
    named.sort_unstable();
    let mut checks = CHECKS.to_vec();
    checks.sort_unstable();
    assert_eq!(named, checks, "every check has exactly one tag");

    let rows = file["rows"].as_array().expect("rows is an array");
    assert!(
        rows.len() >= 30,
        "only {} vectors; the file must hold at least 30",
        rows.len()
    );
    let mut ids = HashSet::new();
    for row in rows {
        let id = text(&row["id"], "id");
        assert!(ids.insert(id), "duplicate id {id}");
    }
    for check in CHECKS {
        assert!(
            rows.iter().any(|r| r["expect"]["refused_by"]
                .as_array()
                .is_some_and(|c| c.iter().any(|c| c == check))),
            "no vector is refused by {check}"
        );
    }
    for signal in ["execute", "suspend", "abort"] {
        assert!(
            rows.iter().any(|r| r["expect"]["signal"] == signal),
            "no vector expects {signal}"
        );
    }
}

#[test]
fn kernel_meets_every_gate_vector() {
    let file = vectors();
    let tags = file["tags"].as_object().expect("tags is an object");
    let rows = file["rows"].as_array().expect("rows is an array");
    let failures: Vec<String> = rows
        .iter()
        .flat_map(|row| {
            let id = text(&row["id"], "id");
            divergences(row, tags)
                .into_iter()
                .map(move |d| format!("{id}: {d}"))
        })
        .collect();
    assert!(
        failures.is_empty(),
        "{} divergence(s) across {} vectors:\n{}",
        failures.len(),
        rows.len(),
        failures.join("\n")
    );
}
