pub mod der {
    use crate::pki::{Asn1Class, Asn1Tag, Oid};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    pub mod detail {
        use crate::pki::{Asn1Class, Asn1Tag};

        pub fn append_identifier(out: &mut Vec<u8>, cls: Asn1Class, constructed: bool, tag: u32) {
            super::append_identifier(out, cls, constructed, tag);
        }

        pub fn append_length(out: &mut Vec<u8>, length: usize) {
            super::append_length(out, length);
        }

        pub fn encode_string(str: &str, tag: Asn1Tag) -> Vec<u8> {
            super::encode_string(str, tag)
        }

        pub fn encode_time_string(str: &str, tag: Asn1Tag) -> Vec<u8> {
            encode_string(str, tag)
        }
    }

    pub fn concat(parts: &[Vec<u8>]) -> Vec<u8> {
        let total = parts.iter().map(Vec::len).sum();
        let mut out = Vec::with_capacity(total);
        for part in parts {
            out.extend(part);
        }
        out
    }

    pub fn encode_tlv(cls: Asn1Class, constructed: bool, tag: u32, content: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        append_identifier(&mut out, cls, constructed, tag);
        append_length(&mut out, content.len());
        out.extend(content);
        out
    }

    pub fn encode_sequence(content: &[u8]) -> Vec<u8> {
        encode_tlv(
            Asn1Class::Universal,
            true,
            Asn1Tag::Sequence as u32,
            content,
        )
    }

    pub fn encode_set(content: &[u8]) -> Vec<u8> {
        encode_tlv(Asn1Class::Universal, true, Asn1Tag::Set as u32, content)
    }

    pub fn encode_integer_bytes(value: &[u8]) -> Vec<u8> {
        let mut sanitized = value.to_vec();
        while sanitized.len() > 1 && sanitized[0] == 0 && sanitized[1] & 0x80 == 0 {
            sanitized.remove(0);
        }
        if sanitized.is_empty() {
            sanitized.push(0);
        }
        if sanitized[0] & 0x80 != 0 {
            sanitized.insert(0, 0);
        }
        encode_tlv(
            Asn1Class::Universal,
            false,
            Asn1Tag::Integer as u32,
            &sanitized,
        )
    }

    pub fn encode_integer(mut value: u64) -> Vec<u8> {
        let mut buffer = Vec::new();
        loop {
            buffer.insert(0, (value & 0xff) as u8);
            value >>= 8;
            if value == 0 {
                break;
            }
        }
        encode_integer_bytes(&buffer)
    }

    pub fn encode_bit_string(bits: &[u8]) -> Vec<u8> {
        encode_bit_string_with_unused_bits(bits, 0)
    }

    pub fn encode_bit_string_with_unused_bits(bits: &[u8], unused_bits: u8) -> Vec<u8> {
        let mut content = Vec::with_capacity(bits.len() + 1);
        content.push(unused_bits);
        content.extend(bits);
        encode_tlv(
            Asn1Class::Universal,
            false,
            Asn1Tag::BitString as u32,
            &content,
        )
    }

    pub fn encode_octet_string(bytes: &[u8]) -> Vec<u8> {
        encode_tlv(
            Asn1Class::Universal,
            false,
            Asn1Tag::OctetString as u32,
            bytes,
        )
    }

    pub fn encode_boolean(value: bool) -> Vec<u8> {
        encode_tlv(
            Asn1Class::Universal,
            false,
            Asn1Tag::Boolean as u32,
            &[if value { 0xff } else { 0x00 }],
        )
    }

    pub fn encode_oid(oid: &Oid) -> Vec<u8> {
        let mut body = Vec::new();
        if oid.nodes.len() < 2 {
            body.push(0);
        } else {
            body.push((oid.nodes[0] * 40 + oid.nodes[1]) as u8);
            for node in &oid.nodes[2..] {
                let mut value = *node;
                let mut buffer = [0u8; 5];
                let mut idx = 4usize;
                buffer[idx] = (value & 0x7f) as u8;
                value >>= 7;
                while value > 0 && idx > 0 {
                    idx -= 1;
                    buffer[idx] = ((value & 0x7f) as u8) | 0x80;
                    value >>= 7;
                }
                body.extend(&buffer[idx..]);
            }
        }
        encode_tlv(
            Asn1Class::Universal,
            false,
            Asn1Tag::ObjectIdentifier as u32,
            &body,
        )
    }

    pub fn encode_utf8_string(text: &str) -> Vec<u8> {
        encode_string(text, Asn1Tag::Utf8String)
    }

    pub fn encode_printable_string(text: &str) -> Vec<u8> {
        encode_string(text, Asn1Tag::PrintableString)
    }

    pub fn encode_ia5_string(text: &str) -> Vec<u8> {
        encode_string(text, Asn1Tag::Ia5String)
    }

    pub fn encode_utctime(text: &str) -> Vec<u8> {
        encode_string(text, Asn1Tag::UtcTime)
    }

    pub fn encode_generalized_time(text: &str) -> Vec<u8> {
        encode_string(text, Asn1Tag::GeneralizedTime)
    }

    pub fn format_time(tp: SystemTime, utc_time: bool) -> String {
        let seconds = seconds_since_unix_epoch(tp);
        let (year, month, day, hour, minute, second) = unix_seconds_to_utc(seconds);
        if utc_time {
            format!(
                "{:02}{:02}{:02}{:02}{:02}{:02}Z",
                year.rem_euclid(100),
                month,
                day,
                hour,
                minute,
                second
            )
        } else {
            format!("{year:04}{month:02}{day:02}{hour:02}{minute:02}{second:02}Z")
        }
    }

    pub fn serialize_time(tp: SystemTime) -> Vec<u8> {
        let seconds = seconds_since_unix_epoch(tp);
        let (year, _, _, _, _, _) = unix_seconds_to_utc(seconds);
        let use_utc = (1950..=2049).contains(&year);
        let formatted = format_time(tp, use_utc);
        if use_utc {
            encode_utctime(&formatted)
        } else {
            encode_generalized_time(&formatted)
        }
    }

    pub fn encode_context_primitive(tag: u32, content: &[u8]) -> Vec<u8> {
        encode_tlv(Asn1Class::ContextSpecific, false, tag, content)
    }

    pub fn encode_context_constructed(tag: u32, content: &[u8]) -> Vec<u8> {
        encode_tlv(Asn1Class::ContextSpecific, true, tag, content)
    }

    fn encode_string(text: &str, tag: Asn1Tag) -> Vec<u8> {
        encode_tlv(Asn1Class::Universal, false, tag as u32, text.as_bytes())
    }

    fn append_identifier(out: &mut Vec<u8>, cls: Asn1Class, constructed: bool, tag: u32) {
        let mut first = cls as u8 | if constructed { 0x20 } else { 0x00 };
        if tag < 31 {
            first |= (tag & 0x1f) as u8;
            out.push(first);
            return;
        }
        first |= 0x1f;
        out.push(first);
        let mut value = tag;
        let mut buffer = [0u8; 5];
        let mut idx = 4usize;
        buffer[idx] = (value & 0x7f) as u8;
        value >>= 7;
        while value > 0 && idx > 0 {
            idx -= 1;
            buffer[idx] = ((value & 0x7f) as u8) | 0x80;
            value >>= 7;
        }
        out.extend(&buffer[idx..]);
    }

    fn append_length(out: &mut Vec<u8>, length: usize) {
        if length < 0x80 {
            out.push(length as u8);
            return;
        }
        let mut buffer = [0u8; std::mem::size_of::<usize>()];
        let mut idx = buffer.len();
        let mut value = length;
        while value > 0 {
            idx -= 1;
            buffer[idx] = (value & 0xff) as u8;
            value >>= 8;
        }
        let octets = buffer.len() - idx;
        out.push(0x80 | octets as u8);
        out.extend(&buffer[idx..]);
    }

    fn seconds_since_unix_epoch(tp: SystemTime) -> i64 {
        match tp.duration_since(UNIX_EPOCH) {
            Ok(duration) => duration.as_secs().min(i64::MAX as u64) as i64,
            Err(error) => {
                let duration: Duration = error.duration();
                -(duration.as_secs().min(i64::MAX as u64) as i64)
            }
        }
    }

    fn unix_seconds_to_utc(seconds: i64) -> (i32, u32, u32, u32, u32, u32) {
        let days = seconds.div_euclid(86_400);
        let seconds_of_day = seconds.rem_euclid(86_400);
        let (year, month, day) = civil_from_days(days);
        let hour = (seconds_of_day / 3_600) as u32;
        let minute = ((seconds_of_day % 3_600) / 60) as u32;
        let second = (seconds_of_day % 60) as u32;
        (year, month, day, hour, minute, second)
    }

    fn civil_from_days(days_since_unix_epoch: i64) -> (i32, u32, u32) {
        let z = days_since_unix_epoch + 719_468;
        let era = if z >= 0 { z } else { z - 146_096 }.div_euclid(146_097);
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096).div_euclid(365);
        let y = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2).div_euclid(153);
        let day = doy - (153 * mp + 2).div_euclid(5) + 1;
        let month = mp + if mp < 10 { 3 } else { -9 };
        let year = y + if month <= 2 { 1 } else { 0 };
        (year as i32, month as u32, day as u32)
    }
}
