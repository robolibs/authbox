use super::{DidDocument, VerificationMethod};

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum PrivacyRisk {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl PrivacyRisk {
    pub const NONE: Self = Self::None;
    pub const LOW: Self = Self::Low;
    pub const MEDIUM: Self = Self::Medium;
    pub const HIGH: Self = Self::High;
    pub const CRITICAL: Self = Self::Critical;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivacyConcern {
    pub risk: PrivacyRisk,
    pub category: String,
    pub description: String,
    pub location: String,
    pub recommendation: String,
}

pub fn contains_email_pattern(text: &str) -> bool {
    text.split(|ch: char| {
        ch.is_whitespace() || matches!(ch, '"' | '\'' | '<' | '>' | ',' | ';' | '#' | ':')
    })
    .any(token_looks_like_email)
}

fn token_looks_like_email(token: &str) -> bool {
    let Some(at) = token.find('@') else {
        return false;
    };
    if at == 0 || at + 1 >= token.len() || token[at + 1..].contains('@') {
        return false;
    }
    let local = &token[..at];
    let domain = &token[at + 1..];
    if local.is_empty()
        || !local
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '%' | '+' | '-'))
    {
        return false;
    }
    let Some(dot) = domain.rfind('.') else {
        return false;
    };
    dot > 0
        && dot + 2 < domain.len() + 1
        && domain[..dot]
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'))
        && domain[dot + 1..].chars().all(|c| c.is_ascii_alphabetic())
        && domain[dot + 1..].len() >= 2
}

pub fn contains_phone_pattern(text: &str) -> bool {
    let mut digits = 0usize;
    let mut run_len = 0usize;
    for ch in text.chars().chain(std::iter::once('x')) {
        if ch.is_ascii_digit() || matches!(ch, '+' | '-' | '.' | ' ' | '\t' | '(' | ')') {
            run_len += 1;
            if ch.is_ascii_digit() {
                digits += 1;
            }
            continue;
        }
        if digits >= 7 && run_len >= 7 {
            return true;
        }
        digits = 0;
        run_len = 0;
    }
    false
}

pub fn contains_name_pattern(text: &str) -> bool {
    let words: Vec<&str> = text
        .split(|ch: char| !ch.is_ascii_alphabetic())
        .filter(|word| !word.is_empty())
        .collect();
    words
        .windows(2)
        .any(|pair| capitalized_word(pair[0]) && capitalized_word(pair[1]))
}

fn capitalized_word(word: &str) -> bool {
    let trimmed = word.trim_matches(|ch: char| !ch.is_ascii_alphabetic());
    let mut chars = trimmed.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_uppercase()
        && chars.clone().next().is_some()
        && chars.all(|ch| ch.is_ascii_lowercase())
}

pub fn contains_address_pattern(text: &str) -> bool {
    const SUFFIXES: &[&str] = &[
        "Street",
        "St",
        "Avenue",
        "Ave",
        "Road",
        "Rd",
        "Drive",
        "Dr",
        "Boulevard",
        "Blvd",
    ];
    let words: Vec<&str> = text.split_whitespace().collect();
    words.windows(3).any(|triple| {
        triple[0]
            .trim_matches(|ch: char| !ch.is_ascii_alphanumeric())
            .chars()
            .all(|ch| ch.is_ascii_digit())
            && capitalized_word(triple[1])
            && SUFFIXES.contains(&triple[2].trim_matches(|ch: char| !ch.is_ascii_alphabetic()))
    })
}

pub fn scan_did_for_pii(did: &str) -> Vec<PrivacyConcern> {
    let mut concerns = Vec::new();
    if contains_email_pattern(did) || did.contains("%40") {
        concerns.push(PrivacyConcern {
            risk: PrivacyRisk::Critical,
            category: "Email Address".to_string(),
            description:
                "DID appears to contain an email address. This is personally identifiable information."
                    .to_string(),
            location: "id".to_string(),
            recommendation: "Use a non-PII pairwise or pseudonymous identifier".to_string(),
        });
    }
    if contains_phone_pattern(did) {
        concerns.push(PrivacyConcern {
            risk: PrivacyRisk::Critical,
            category: "Phone Number".to_string(),
            description:
                "DID appears to contain a phone number. This is personally identifiable information."
                    .to_string(),
            location: "id".to_string(),
            recommendation: "Do not put telephone numbers in immutable identifiers".to_string(),
        });
    }
    if contains_name_pattern(did) {
        concerns.push(PrivacyConcern {
            risk: PrivacyRisk::High,
            category: "Personal Name".to_string(),
            description:
                "DID appears to contain a personal name. This may be personally identifiable."
                    .to_string(),
            location: "id".to_string(),
            recommendation: "Use a non-PII pairwise or pseudonymous identifier".to_string(),
        });
    }
    concerns
}

pub fn scan_for_pii(doc: &DidDocument) -> Vec<PrivacyConcern> {
    let mut concerns = scan_did_for_pii(&doc.id);
    for (index, method) in doc.verification_methods.iter().enumerate() {
        if contains_email_pattern(&method.id)
            || contains_phone_pattern(&method.id)
            || contains_name_pattern(&method.id)
        {
            concerns.push(PrivacyConcern {
                risk: PrivacyRisk::High,
                category: "PII in Verification Method".to_string(),
                description:
                    "Verification method ID may contain personally identifiable information."
                        .to_string(),
                location: format!("verificationMethod[{index}].id"),
                recommendation: "Avoid embedding PII in verification method identifiers"
                    .to_string(),
            });
        }
    }
    for (index, service) in doc.services.iter().enumerate() {
        if contains_email_pattern(&service.id)
            || contains_email_pattern(&service.service_endpoint_json)
        {
            concerns.push(PrivacyConcern {
                risk: PrivacyRisk::Critical,
                category: "Email in Service".to_string(),
                description:
                    "Service contains an email address. Avoid storing PII on immutable registries."
                        .to_string(),
                location: format!("service[{index}]"),
                recommendation: "Remove personal email addresses from service entries".to_string(),
            });
        }
        if contains_address_pattern(&service.service_endpoint_json) {
            concerns.push(PrivacyConcern {
                risk: PrivacyRisk::Critical,
                category: "Physical Address".to_string(),
                description: "Service endpoint contains what appears to be a physical address."
                    .to_string(),
                location: format!("service[{index}].serviceEndpoint"),
                recommendation: "Remove physical addresses from service endpoints".to_string(),
            });
        }
    }
    concerns
}

pub fn scan_document(doc: &DidDocument) -> Vec<PrivacyConcern> {
    let mut concerns = scan_for_pii(doc);
    concerns.extend(check_correlation_risks(doc));
    concerns
}

pub fn get_max_risk(concerns: &[PrivacyConcern]) -> PrivacyRisk {
    concerns
        .iter()
        .map(|concern| concern.risk.clone())
        .max()
        .unwrap_or(PrivacyRisk::None)
}

pub fn is_safe_for_immutable_storage(doc: &DidDocument) -> bool {
    get_max_risk(&scan_for_pii(doc)) <= PrivacyRisk::Low
}

pub fn check_correlation_risks(doc: &DidDocument) -> Vec<PrivacyConcern> {
    let mut all_vm_refs = Vec::new();
    all_vm_refs.extend(doc.authentication.iter().cloned());
    all_vm_refs.extend(doc.assertion_method.iter().cloned());
    all_vm_refs.extend(doc.key_agreement.iter().cloned());
    all_vm_refs.extend(doc.capability_invocation.iter().cloned());
    all_vm_refs.extend(doc.capability_delegation.iter().cloned());
    let total = all_vm_refs.len();
    all_vm_refs.sort();
    all_vm_refs.dedup();
    if all_vm_refs.len() < total {
        vec![PrivacyConcern {
            risk: PrivacyRisk::Medium,
            category: "Key Reuse".to_string(),
            description:
                "Same verification method used for multiple purposes. Consider using separate keys for each purpose."
                    .to_string(),
            location: "verification relationships".to_string(),
            recommendation: "Use separate keys for each verification relationship".to_string(),
        }]
    } else {
        Vec::new()
    }
}

pub fn detect_key_reuse(doc: &DidDocument) -> Vec<PrivacyConcern> {
    check_correlation_risks(doc)
}

#[allow(dead_code)]
fn reused_across_relationships(method: &VerificationMethod, doc: &DidDocument) -> bool {
    let refs = [
        &doc.authentication,
        &doc.assertion_method,
        &doc.key_agreement,
        &doc.capability_invocation,
        &doc.capability_delegation,
    ];
    refs.iter()
        .filter(|items| items.iter().any(|item| item == &method.id))
        .count()
        > 1
}

pub fn format_concerns(concerns: &[PrivacyConcern]) -> String {
    if concerns.is_empty() {
        return "No privacy concerns detected.".to_string();
    }
    let mut result = "Privacy Concerns Detected:\n".to_string();
    for concern in concerns {
        result.push_str("\n[");
        result.push_str(match concern.risk {
            PrivacyRisk::None => "NONE",
            PrivacyRisk::Low => "LOW",
            PrivacyRisk::Medium => "MEDIUM",
            PrivacyRisk::High => "HIGH",
            PrivacyRisk::Critical => "CRITICAL",
        });
        result.push_str("] ");
        result.push_str(&concern.category);
        result.push_str("\n  Location: ");
        result.push_str(&concern.location);
        result.push_str("\n  Details: ");
        result.push_str(&concern.description);
        result.push('\n');
    }
    result
}
