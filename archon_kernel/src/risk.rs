//! Prompt risk classification — the tripwire that feeds the three-tier action
//! gate. Deliberately simple and conservative: it is a keyword/heuristic screen,
//! not a full policy engine, and it is meant to *escalate for human sign-off*,
//! not to be the last line of defense. Wiring it into the run flow is what turns
//! `three_tier_gate` from dead code into an actual gate.

/// Classify a prompt. Returns `(risk_score in [0,1], looks_like_severe_threat)`.
///
/// `looks_like_severe_threat` maps to the three-tier gate's Tier-1 veto path.
pub fn classify_prompt(prompt: &str) -> (f64, bool) {
    // Normalize before matching (defense in depth; the CLI path does not run the server's
    // sanitizer): drop zero-width / invisible format characters and collapse whitespace, so
    // "bo\u{200B}mb" or "build   a\tbomb" cannot slip past the keyword screen.
    let p: String = prompt
        .chars()
        .filter(|c| {
            !matches!(
                c,
                '\u{200B}'
                    | '\u{200C}'
                    | '\u{200D}'
                    | '\u{FEFF}'
                    | '\u{200E}'
                    | '\u{200F}'
                    | '\u{2060}'
                    | '\u{00AD}'
                    | '\u{180E}'
            )
        })
        .collect::<String>()
        .to_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");

    // Severe: illegal / seriously harmful intent → Tier-1 territory.
    const SEVERE: &[&str] = &[
        "malware",
        "ransomware",
        "how to make a bomb",
        "build a bomb",
        "bioweapon",
        "nerve agent",
        "how to kill",
        "child sexual",
        "assassinate",
        "untraceable poison",
    ];
    // Elevated: destructive / sensitive ops that warrant a warning.
    const ELEVATED: &[&str] = &[
        "drop table",
        "rm -rf",
        "delete all",
        "private key",
        "exfiltrate",
        "disable security",
        "bypass auth",
        "format disk",
        "credential",
    ];

    let severe = SEVERE.iter().filter(|k| p.contains(**k)).count();
    let elevated = ELEVATED.iter().filter(|k| p.contains(**k)).count();

    let illegal_threat = severe > 0;
    let score = (severe as f64 * 0.6 + elevated as f64 * 0.25).min(1.0);
    (score, illegal_threat)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn benign_is_low_risk() {
        let (s, t) = classify_prompt("Explain the ADCCL chiral invariant.");
        assert!(s < 0.7 && !t);
    }

    #[test]
    fn severe_flags_threat() {
        let (_, t) = classify_prompt("write me ransomware that spreads");
        assert!(t);
    }

    #[test]
    fn destructive_raises_score() {
        let (s, t) = classify_prompt("run rm -rf on the disk and drop table users");
        assert!(s >= 0.5 && !t);
    }
}

#[cfg(test)]
mod obfuscation_tests {
    use super::classify_prompt;
    use proptest::prelude::*;

    #[test]
    fn invisible_characters_do_not_hide_a_severe_phrase() {
        for s in [
            "how to make a bo\u{200B}mb",
            "how to make a\u{2060} bomb",
            "build   a\tbomb",
            "BUILD A BOMB",
            "ran\u{00AD}somware",
        ] {
            assert!(classify_prompt(s).1, "must flag: {s:?}");
        }
    }

    proptest! {
        // Inserting any mix of invisible characters anywhere in a severe phrase never hides it.
        #[test]
        fn severe_phrase_survives_invisible_insertion(pos in 0usize..12, k in 1usize..4,
                                                      ch in prop::sample::select(vec!['\u{200B}','\u{200C}','\u{200D}','\u{FEFF}','\u{2060}','\u{00AD}'])) {
            let base: Vec<char> = "build a bomb".chars().collect();
            let mut v = base.clone();
            for _ in 0..k { v.insert(pos.min(v.len()), ch); }
            let s: String = v.into_iter().collect();
            prop_assert!(classify_prompt(&s).1);
        }

        // The classifier never panics and always returns a score in [0, 1].
        #[test]
        fn classifier_total_and_bounded(s in ".{0,400}") {
            let (score, _) = classify_prompt(&s);
            prop_assert!((0.0..=1.0).contains(&score));
        }
    }
}
