//! Strict JSON decoding shared by API and signed-artifact parsers.

use serde::de::{DeserializeOwned, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use std::fmt;

struct StrictJsonValue(serde_json::Value);

impl<'de> Deserialize<'de> for StrictJsonValue {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictJsonValueVisitor)
    }
}

struct StrictJsonValueVisitor;

impl<'de> Visitor<'de> for StrictJsonValueVisitor {
    type Value = StrictJsonValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> std::result::Result<Self::Value, E> {
        Ok(StrictJsonValue(serde_json::Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> std::result::Result<Self::Value, E> {
        Ok(StrictJsonValue(serde_json::Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> std::result::Result<Self::Value, E> {
        Ok(StrictJsonValue(serde_json::Value::Number(value.into())))
    }

    fn visit_f64<E>(self, value: f64) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(serde_json::Value::Number)
            .map(StrictJsonValue)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E> {
        Ok(StrictJsonValue(serde_json::Value::String(
            value.to_string(),
        )))
    }

    fn visit_string<E>(self, value: String) -> std::result::Result<Self::Value, E> {
        Ok(StrictJsonValue(serde_json::Value::String(value)))
    }

    fn visit_none<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(StrictJsonValue(serde_json::Value::Null))
    }

    fn visit_unit<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(StrictJsonValue(serde_json::Value::Null))
    }

    fn visit_some<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        StrictJsonValue::deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(StrictJsonValue(value)) = sequence.next_element()? {
            values.push(value);
        }
        Ok(StrictJsonValue(serde_json::Value::Array(values)))
    }

    fn visit_map<A>(self, mut object: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = serde_json::Map::new();
        while let Some(key) = object.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(serde::de::Error::custom("duplicate JSON object key"));
            }
            let StrictJsonValue(value) = object.next_value()?;
            values.insert(key, value);
        }
        Ok(StrictJsonValue(serde_json::Value::Object(values)))
    }
}

pub(crate) fn parse(bytes: &[u8]) -> std::result::Result<serde_json::Value, serde_json::Error> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = StrictJsonValue::deserialize(&mut deserializer)?.0;
    deserializer.end()?;
    Ok(value)
}

pub(crate) fn from_slice<T: DeserializeOwned>(
    bytes: &[u8],
) -> std::result::Result<T, serde_json::Error> {
    serde_json::from_value(parse(bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_duplicate_keys_at_any_depth() {
        assert!(parse(br#"{"iat":1,"iat":2}"#).is_err());
        assert!(parse(br#"{"metadata":{"role":"user","role":"admin"}}"#).is_err());
    }

    #[test]
    fn accepts_unambiguous_nested_values() {
        let parsed = parse(br#"{"meta":{"iat":1},"included":[]}"#).unwrap();
        assert_eq!(parsed["meta"]["iat"], 1);
    }
}
