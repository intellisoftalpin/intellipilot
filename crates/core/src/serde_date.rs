//! serde helpers for `time::Date` rendered as ISO `YYYY-MM-DD`.

/// `Option<Date>` ⇄ ISO date string (or `null`).
#[allow(clippy::option_if_let_else)] // the match reads clearer than map_or_else
pub mod option {
    use serde::{Deserialize, Deserializer, Serializer, de};
    use time::Date;
    use time::format_description::FormatItem;
    use time::macros::format_description;

    const FMT: &[FormatItem<'_>] = format_description!("[year]-[month]-[day]");

    pub fn serialize<S: Serializer>(v: &Option<Date>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(d) => {
                let rendered = d.format(&FMT).map_err(serde::ser::Error::custom)?;
                s.serialize_some(&rendered)
            }
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Date>, D::Error> {
        let opt = Option::<String>::deserialize(d)?;
        match opt {
            None => Ok(None),
            Some(s) => Date::parse(&s, &FMT).map(Some).map_err(de::Error::custom),
        }
    }
}

/// `Option<Option<Date>>` for PATCH bodies that must tell "field absent"
/// (leave alone) from "field present and null" (clear it).
///
/// Pair with `#[serde(default)]`: absent → `None`, `null` → `Some(None)`,
/// `"2026-05-22"` → `Some(Some(date))`. Mirrors `serde_with::rust::
/// double_option`, which cannot be composed with a custom inner format.
#[allow(clippy::option_if_let_else)] // the match reads clearer than map_or_else
pub mod double_option {
    use serde::{Deserialize, Deserializer, Serializer, de};
    use time::Date;
    use time::format_description::FormatItem;
    use time::macros::format_description;

    const FMT: &[FormatItem<'_>] = format_description!("[year]-[month]-[day]");

    pub fn serialize<S: Serializer>(v: &Option<Option<Date>>, s: S) -> Result<S::Ok, S::Error> {
        match v.as_ref().and_then(|inner| inner.as_ref()) {
            Some(d) => {
                let rendered = d.format(&FMT).map_err(serde::ser::Error::custom)?;
                s.serialize_some(&rendered)
            }
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Option<Date>>, D::Error> {
        let opt = Option::<String>::deserialize(d)?;
        match opt {
            None => Ok(Some(None)),
            Some(s) => Date::parse(&s, &FMT)
                .map(|v| Some(Some(v)))
                .map_err(de::Error::custom),
        }
    }
}

/// Required `Date` ⇄ ISO date string (`YYYY-MM-DD`).
pub mod required {
    use serde::{Deserialize, Deserializer, Serializer, de};
    use time::Date;
    use time::format_description::FormatItem;
    use time::macros::format_description;

    const FMT: &[FormatItem<'_>] = format_description!("[year]-[month]-[day]");

    pub fn serialize<S: Serializer>(v: &Date, s: S) -> Result<S::Ok, S::Error> {
        let rendered = v.format(&FMT).map_err(serde::ser::Error::custom)?;
        s.serialize_str(&rendered)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Date, D::Error> {
        let s = String::deserialize(d)?;
        Date::parse(&s, &FMT).map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use serde::{Deserialize, Serialize};
    use time::macros::date;

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct Holder {
        #[serde(with = "super::option", default)]
        d: Option<time::Date>,
    }

    #[test]
    fn round_trips_iso_date() {
        let h = Holder {
            d: Some(date!(2026 - 05 - 22)),
        };
        let json = serde_json::to_string(&h).unwrap();
        assert_eq!(json, r#"{"d":"2026-05-22"}"#);
        let back: Holder = serde_json::from_str(&json).unwrap();
        assert_eq!(back, h);
    }

    #[test]
    fn null_is_none() {
        let back: Holder = serde_json::from_str(r#"{"d":null}"#).unwrap();
        assert_eq!(back.d, None);
    }
}
