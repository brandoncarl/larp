use base64::{
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
    Engine as _,
};
use zeroize::Zeroizing;

pub struct Redactor {
    patterns: Vec<Zeroizing<String>>,
    max_len: usize,
}

impl Redactor {
    pub fn new<'a>(secrets: impl IntoIterator<Item = &'a str>) -> Self {
        let mut patterns: Vec<Zeroizing<String>> = Vec::new();
        for secret in secrets {
            if secret.is_empty() {
                continue;
            }
            patterns.push(Zeroizing::new(secret.to_string()));
            if secret.len() >= 8 {
                let bytes = secret.as_bytes();
                for encoded in [
                    STANDARD.encode(bytes),
                    STANDARD_NO_PAD.encode(bytes),
                    URL_SAFE.encode(bytes),
                    URL_SAFE_NO_PAD.encode(bytes),
                    bytes
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<String>(),
                    bytes
                        .iter()
                        .map(|byte| format!("{byte:02X}"))
                        .collect::<String>(),
                    percent_encode(bytes, false),
                    percent_encode(bytes, true),
                ] {
                    if encoded != secret {
                        patterns.push(Zeroizing::new(encoded));
                    }
                }
                if let Ok(json) = serde_json::to_string(secret) {
                    let escaped = &json[1..json.len() - 1];
                    if escaped != secret {
                        patterns.push(Zeroizing::new(escaped.to_string()));
                    }
                }
            }
        }
        patterns.sort_by_key(|pattern| std::cmp::Reverse(pattern.len()));
        patterns.dedup_by(|left, right| left.as_str() == right.as_str());
        let max_len = patterns
            .iter()
            .map(|pattern| pattern.len())
            .max()
            .unwrap_or(0);
        Self { patterns, max_len }
    }

    pub fn max_pattern_len(&self) -> usize {
        self.max_len
    }

    pub fn redact(&self, value: &mut String) {
        for pattern in &self.patterns {
            if value.contains(pattern.as_str()) {
                let previous = Zeroizing::new(std::mem::take(value));
                *value = previous.replace(pattern.as_str(), "REDACTED");
            }
        }
    }
}

fn percent_encode(bytes: &[u8], all: bool) -> String {
    let mut result = String::new();
    for byte in bytes {
        if !all && (byte.is_ascii_alphanumeric() || b"-._~".contains(byte)) {
            result.push(*byte as char);
        } else {
            result.push_str(&format!("%{byte:02X}"));
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::Redactor;
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    #[test]
    fn redacts_literal_and_common_encodings() {
        let secret = "s3cr3t+/alpha";
        let redactor = Redactor::new([secret]);
        let mut output = format!(
            "raw={secret} b64={} hex={} url=s3cr3t%2B%2Falpha",
            STANDARD.encode(secret),
            secret
                .as_bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        );
        redactor.redact(&mut output);
        assert!(!output.contains(secret));
        assert!(!output.contains(&STANDARD.encode(secret)));
        assert!(output.matches("REDACTED").count() >= 3);
    }

    #[test]
    fn handles_patterns_across_capture_chunks() {
        let redactor = Redactor::new(["secret-across-chunks"]);
        let mut output = "header: secret-across-chunks\n".to_string();
        redactor.redact(&mut output);
        assert_eq!(output, "header: REDACTED\n");
    }
}
