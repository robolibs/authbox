//! Shared JSON helpers for the Rust authbox port.
//!
//! The C++ tree vendors `include/json.hpp`; this Rust module keeps the same
//! top-level concern without cloning that C header's parser/DOM internals.
//! Strict JSON is delegated to `serde_json`; permissive JSON5-shaped input is
//! delegated to `json5`.  The local `Json` enum keeps DID/PKI call sites stable
//! without hiding a custom parser in those modules.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

#[derive(Clone, Debug, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Number(String),
    String(String),
    Array(Vec<Json>),
    Object(BTreeMap<String, Json>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JsonError {
    pub message: String,
}

impl JsonError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for JsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for JsonError {}

pub type JsonResult<T> = Result<T, JsonError>;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct JsonParseFlags(u32);

impl JsonParseFlags {
    pub const DEFAULT: Self = Self(0);
    pub const ALLOW_JSON5: Self = Self(0x1);

    // Kept as opt-in flag names for rough source-shape compatibility.  They no
    // longer mean "reimplement json.hpp"; any non-default flag selects the
    // crate-backed JSON5 parser.
    pub const ALLOW_TRAILING_COMMA: Self = Self::ALLOW_JSON5;
    pub const ALLOW_UNQUOTED_KEYS: Self = Self::ALLOW_JSON5;
    pub const ALLOW_C_STYLE_COMMENTS: Self = Self::ALLOW_JSON5;
    pub const ALLOW_SINGLE_QUOTED_STRINGS: Self = Self::ALLOW_JSON5;
    pub const ALLOW_HEXADECIMAL_NUMBERS: Self = Self::ALLOW_JSON5;
    pub const ALLOW_LEADING_PLUS_SIGN: Self = Self::ALLOW_JSON5;
    pub const ALLOW_LEADING_OR_TRAILING_DECIMAL_POINT: Self = Self::ALLOW_JSON5;
    pub const ALLOW_MULTI_LINE_STRINGS: Self = Self::ALLOW_JSON5;

    // json.hpp-specific forms we deliberately do not normalize.  Passing these
    // still routes to `json5`, which will accept whatever the ecosystem parser
    // supports and reject the rest.
    pub const ALLOW_GLOBAL_OBJECT: Self = Self(0x2);
    pub const ALLOW_EQUALS_IN_OBJECT: Self = Self(0x4);
    pub const ALLOW_NO_COMMAS: Self = Self(0x8);
    pub const ALLOW_INF_AND_NAN: Self = Self(0x10);
    pub const ALLOW_LOCATION_INFORMATION: Self = Self(0x20);
    pub const DEPRECATED: Self = Self(0x40);
    pub const ALLOW_SIMPLIFIED_JSON: Self = Self(
        Self::ALLOW_GLOBAL_OBJECT.0
            | Self::ALLOW_EQUALS_IN_OBJECT.0
            | Self::ALLOW_NO_COMMAS.0
            | Self::ALLOW_UNQUOTED_KEYS.0,
    );

    pub const fn bits(self) -> u32 {
        self.0
    }

    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn is_default(self) -> bool {
        self.0 == 0
    }
}

impl std::ops::BitOr for JsonParseFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        self.union(rhs)
    }
}

pub struct JsonParser<'a> {
    text: &'a str,
    flags: JsonParseFlags,
}

impl<'a> JsonParser<'a> {
    pub fn new(text: &'a str) -> Self {
        Self::with_flags(text, JsonParseFlags::DEFAULT)
    }

    pub fn with_flags(text: &'a str, flags: JsonParseFlags) -> Self {
        Self { text, flags }
    }

    pub fn parse(self) -> JsonResult<Json> {
        parse_value(self.text, self.flags)
    }
}

pub fn parse(text: &str) -> JsonResult<Json> {
    parse_value(text, JsonParseFlags::DEFAULT)
}

pub fn parse_with_flags(text: &str, flags: JsonParseFlags) -> JsonResult<Json> {
    parse_value(text, flags)
}

pub fn json_string(value: &Json, key: &str) -> Option<String> {
    match value {
        Json::Object(obj) => match obj.get(key) {
            Some(Json::String(text)) => Some(text.clone()),
            _ => None,
        },
        _ => None,
    }
}

pub fn json_array(value: &Json, key: &str) -> Vec<Json> {
    match value {
        Json::Object(obj) => match obj.get(key) {
            Some(Json::Array(items)) => items.clone(),
            _ => Vec::new(),
        },
        _ => Vec::new(),
    }
}

pub fn parse_string_array_from_obj(value: &Json, key: &str) -> Vec<String> {
    json_array(value, key)
        .into_iter()
        .filter_map(|item| match item {
            Json::String(text) => Some(text),
            _ => None,
        })
        .collect()
}

pub fn to_compact_string(value: &Json) -> String {
    serde_json::to_string(&to_serde_value(value)).unwrap_or_else(|_| write_compact_fallback(value))
}

pub fn to_pretty_string(value: &Json) -> String {
    to_pretty_string_with(value, "  ", "\n")
}

pub fn to_pretty_string_with(value: &Json, indent: &str, newline: &str) -> String {
    let mut out = String::new();
    write_pretty(value, indent, newline, 0, &mut out);
    out
}

pub fn escape(input: &str) -> String {
    let quoted = serde_json::to_string(input).unwrap_or_else(|_| format!("\"{input}\""));
    quoted
        .strip_prefix('"')
        .and_then(|text| text.strip_suffix('"'))
        .unwrap_or(&quoted)
        .to_string()
}

fn parse_value(text: &str, flags: JsonParseFlags) -> JsonResult<Json> {
    let serde_value = if flags.is_default() {
        serde_json::from_str::<serde_json::Value>(text)
            .map_err(|err| JsonError::new(format!("JSON parse error: {err}")))?
    } else {
        json5::from_str::<serde_json::Value>(text)
            .map_err(|err| JsonError::new(format!("JSON5 parse error: {err}")))?
    };
    Ok(from_serde_value(serde_value))
}

fn from_serde_value(value: serde_json::Value) -> Json {
    match value {
        serde_json::Value::Null => Json::Null,
        serde_json::Value::Bool(value) => Json::Bool(value),
        serde_json::Value::Number(value) => Json::Number(value.to_string()),
        serde_json::Value::String(value) => Json::String(value),
        serde_json::Value::Array(values) => {
            Json::Array(values.into_iter().map(from_serde_value).collect())
        }
        serde_json::Value::Object(fields) => Json::Object(
            fields
                .into_iter()
                .map(|(key, value)| (key, from_serde_value(value)))
                .collect(),
        ),
    }
}

fn to_serde_value(value: &Json) -> serde_json::Value {
    match value {
        Json::Null => serde_json::Value::Null,
        Json::Bool(value) => serde_json::Value::Bool(*value),
        Json::Number(value) => number_value(value),
        Json::String(value) => serde_json::Value::String(value.clone()),
        Json::Array(values) => {
            serde_json::Value::Array(values.iter().map(to_serde_value).collect())
        }
        Json::Object(fields) => serde_json::Value::Object(
            fields
                .iter()
                .map(|(key, value)| (key.clone(), to_serde_value(value)))
                .collect(),
        ),
    }
}

fn number_value(number: &str) -> serde_json::Value {
    serde_json::from_str::<serde_json::Number>(number)
        .map(serde_json::Value::Number)
        .unwrap_or_else(|_| serde_json::Value::String(number.to_string()))
}

fn write_compact_fallback(value: &Json) -> String {
    match value {
        Json::Null => "null".to_string(),
        Json::Bool(value) => value.to_string(),
        Json::Number(value) => value.clone(),
        Json::String(value) => format!("\"{}\"", escape(value)),
        Json::Array(values) => {
            let inner = values
                .iter()
                .map(to_compact_string)
                .collect::<Vec<_>>()
                .join(",");
            format!("[{inner}]")
        }
        Json::Object(fields) => {
            let inner = fields
                .iter()
                .map(|(key, value)| format!("\"{}\":{}", escape(key), to_compact_string(value)))
                .collect::<Vec<_>>()
                .join(",");
            format!("{{{inner}}}")
        }
    }
}

fn write_pretty(value: &Json, indent: &str, newline: &str, depth: usize, out: &mut String) {
    match value {
        Json::Null | Json::Bool(_) | Json::Number(_) | Json::String(_) => {
            out.push_str(&to_compact_string(value));
        }
        Json::Array(values) => {
            if values.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push('[');
            out.push_str(newline);
            for (idx, item) in values.iter().enumerate() {
                write_indent(indent, depth + 1, out);
                write_pretty(item, indent, newline, depth + 1, out);
                if idx + 1 != values.len() {
                    out.push(',');
                }
                out.push_str(newline);
            }
            write_indent(indent, depth, out);
            out.push(']');
        }
        Json::Object(fields) => {
            if fields.is_empty() {
                out.push_str("{}");
                return;
            }
            out.push('{');
            out.push_str(newline);
            for (idx, (key, item)) in fields.iter().enumerate() {
                write_indent(indent, depth + 1, out);
                out.push('"');
                out.push_str(&escape(key));
                out.push_str("\": ");
                write_pretty(item, indent, newline, depth + 1, out);
                if idx + 1 != fields.len() {
                    out.push(',');
                }
                out.push_str(newline);
            }
            write_indent(indent, depth, out);
            out.push('}');
        }
    }
}

fn write_indent(indent: &str, depth: usize, out: &mut String) {
    for _ in 0..depth {
        out.push_str(indent);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_parser_uses_serde_json_rules() {
        assert_eq!(
            parse("{\"answer\":42}").unwrap(),
            Json::Object(BTreeMap::from([(
                "answer".to_string(),
                Json::Number("42".to_string())
            )]))
        );
        assert!(parse("{answer: 42}").is_err());
        assert!(parse("[1,]").is_err());
        assert!(parse("{\"a\":1 // comment\n}").is_err());
    }

    #[test]
    fn permissive_flags_delegate_to_json5() {
        let value = parse_with_flags(
            "{// comment\n unquoted: 'value', hex: 0x2a, plus: +7, leading: .5, trailing: 5.,}",
            JsonParseFlags::ALLOW_JSON5,
        )
        .unwrap();
        let Json::Object(obj) = value else {
            panic!("expected object");
        };
        assert_eq!(
            obj.get("unquoted"),
            Some(&Json::String("value".to_string()))
        );
        assert_eq!(obj.get("hex"), Some(&Json::Number("42".to_string())));
        assert_eq!(obj.get("plus"), Some(&Json::Number("7".to_string())));
        assert_eq!(obj.get("leading"), Some(&Json::Number("0.5".to_string())));
        assert_eq!(obj.get("trailing"), Some(&Json::Number("5.0".to_string())));
    }

    #[test]
    fn json_hpp_only_simplified_forms_are_not_reimplemented() {
        assert!(
            parse_with_flags(
                "a = 1 b: true",
                JsonParseFlags::ALLOW_SIMPLIFIED_JSON | JsonParseFlags::ALLOW_SINGLE_QUOTED_STRINGS,
            )
            .is_err()
        );
    }

    #[test]
    fn compact_and_pretty_writers_roundtrip() {
        let value = parse("{\"a\":[1,true],\"b\":{\"c\":\"d\"}}").unwrap();
        let compact = to_compact_string(&value);
        assert_eq!(parse(&compact).unwrap(), value);

        let pretty = to_pretty_string(&value);
        assert!(pretty.contains('\n'));
        assert_eq!(parse(&pretty).unwrap(), value);
    }

    #[test]
    fn object_helpers_cover_did_call_sites() {
        let value = parse("{\"id\":\"did:example:123\",\"types\":[\"A\",\"B\"]}").unwrap();
        assert_eq!(
            json_string(&value, "id"),
            Some("did:example:123".to_string())
        );
        assert_eq!(
            parse_string_array_from_obj(&value, "types"),
            vec!["A".to_string(), "B".to_string()]
        );
    }

    #[test]
    fn string_escaping_uses_serde_json() {
        let value = Json::String("quote: \" slash: \\ newline:\n".to_string());
        let encoded = to_compact_string(&value);
        assert_eq!(parse(&encoded).unwrap(), value);
    }
}
