//! MAINTENANCE NOTE
//! This code is copied from https://github.com/time-rs/time/tree/serde-rfc3339 (non-perma-link)
//! https://github.com/time-rs/time/blob/7dcd89ef6b0f8ee4bbe794a72c80c76639193102/src/serde/rfc3339.rs
//! Once https://github.com/time-rs/time/issues/387 is closed this file can be deleted.
//!
//! Use the well-known [RFC3339 format] when serializing and deserializing an [`OffsetDateTime`].
//!
//! Use this module in combination with serde's [`#[with]`][with] attribute.
//!
//! [RFC3339 format]: https://tools.ietf.org/html/rfc3339#section-5.6
//! [with]: https://serde.rs/field-attrs.html#with

use serde::de::Error as _;
use serde::ser::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// Serialize an [`OffsetDateTime`] using the well-known RFC3339 format.
pub fn serialize<S: Serializer>(
    datetime: &OffsetDateTime,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    datetime
        .format(&Rfc3339)
        .map_err(S::Error::custom)?
        .serialize(serializer)
}

/// Deserialize an [`OffsetDateTime`] from its RFC3339 representation.
pub fn deserialize<'a, D: Deserializer<'a>>(deserializer: D) -> Result<OffsetDateTime, D::Error> {
    OffsetDateTime::parse(<_>::deserialize(deserializer)?, &Rfc3339).map_err(D::Error::custom)
}

#[cfg(test)]
mod test {
    use serde::{Deserialize, Serialize};
    use time::OffsetDateTime;

    #[test]
    fn offset_date_time_can_deserialize_rfc3339_2() {
        #[derive(Deserialize, Serialize, Debug, PartialEq, Eq)]
        struct SoLong {
            #[serde(with = "crate::internal::serde_rfc3339")]
            bye_time: OffsetDateTime,
        }

        let ts = SoLong {
            bye_time: OffsetDateTime::from_unix_timestamp(1638576000).unwrap(),
        };
        let json_string = serde_json::to_string(&ts).unwrap();

        assert_eq!("{\"bye_time\":\"2021-12-04T00:00:00Z\"}", &json_string);
    }
}
