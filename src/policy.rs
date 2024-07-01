//! Policy types
//!
//! Policies are a list of rules which map data labels to a list of users/groups. This allows the
//! separation of concerns when it comes to labeling data vs defining who to encrypt to.
//!
//! Policies are defined using the ironcore admin console: <https://admin.ironcorelabs.com/policy>
//! and are stored on the server. This allows a policy to be updated independently of any application code.
//!
//! Data labeling is provided in three dimensions (category, sensitivity, dataSubject).
//! You only need to use the dimensions that make sense for your use case. The values of the labels
//! are arbitrary, but the example below may be instructive in selecting label names.
//!
//! In addition to defining labels, a list of rules is required to map the labels to a set of users/groups.
//! Rules are checked in the order they are defined. If a rule matches, it can produce any number of users/groups.
//! Rules defined after the matching rule will not be processed.
//!
//! The `%USER%` and `%LOGGED_IN_USER%` are special tokens that will be replaced when the policy is applied.
//! * `%USER%` - replaced by `substitute_user_id` (see `PolicyGrant`)
//! * `%LOGGED_IN_USER%` - replaced by the user currently authenticated to make SDK calls.
//!
//! A policy could look something like:
//! ```json
//! {
//!  "dataSubjects": [
//!    "PATIENT",
//!    "EMPLOYEE"
//!  ],
//!  "sensitivities": [
//!    "RESTRICTED",
//!    "CLASSIFIED",
//!    "INTERNAL"
//!  ],
//!  "categories": [
//!    "HEALTH",
//!    "PII"
//!  ],
//!  "rules": [
//!    {
//!      "sensitivity": "RESTRICTED",
//!      "users": [
//!        "%USER%"
//!      ],
//!      "dataSubject": "PATIENT",
//!      "groups": [
//!        "group_other_%USER%",
//!        "group_id_doctors",
//!        "data_recovery"
//!      ],
//!      "category": "HEALTH"
//!    },
//!    {
//!      "sensitivity": "INTERNAL",
//!      "users": [
//!        "joe@ironcorelabs",
//!        "%LOGGED_IN_USER%"
//!      ],
//!      "groups": [
//!        "group_%LOGGED_IN_USER%",
//!        "data_recovery"
//!      ],
//!      "category": "PII"
//!    },
//!    {
//!      "groups": [
//!        "data_recovery"
//!      ],
//!    },
//!  ]
//! }
//! ```
//! Example:
//! ```
//! # use ironoxide::prelude::*;
//! # fn run() -> Result<(), IronOxideErr> {
//! # use std::convert::TryInto;
//! PolicyGrant::new(Some("PII".try_into()?), Some("INTERNAL".try_into()?), None, None);
//! # Ok(())
//! # }
//! ```
//! If the current user of the sdk is "alice@ironcorelabs" and the PolicyGrant above is evaluated, it will match the
//! second-to-last rule in the example policy above and will return users: `[joe@ironcorelabs, alice@ironcorelabs]` and
//! groups `[group_alice@ironcorelabs, data_recovery"]`
//!
//! The PolicyGrant `PolicyGrant::new(None, None, None, None)` will match the last rule in the example and will return
//! the group `[data_recovery]`
//!
use crate::{internal::user_api::UserId, IronOxideErr, Result};
use regex::Regex;
use std::convert::{TryFrom, TryInto};

/// Document access granted by a policy.
///
/// For use with [document_encrypt](../document/trait.DocumentOps.html#tymethod.document_encrypt).
///
/// The triple (`category`, `sensitivity`, `data_subject`) maps to a single policy rule. Each policy
/// rule may generate any number of users/groups.
///
/// `substitute_user` replaces `%USER%` in a matched policy rule.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct PolicyGrant {
    category: Option<Category>,
    sensitivity: Option<Sensitivity>,
    data_subject: Option<DataSubject>,
    substitute_user: Option<UserId>,
}

impl PolicyGrant {
    pub fn new(
        category: Option<Category>,
        sensitivity: Option<Sensitivity>,
        data_subject: Option<DataSubject>,
        substitute_user: Option<UserId>,
    ) -> PolicyGrant {
        PolicyGrant {
            category,
            sensitivity,
            data_subject,
            substitute_user,
        }
    }

    pub fn category(&self) -> Option<&Category> {
        self.category.as_ref()
    }

    pub fn sensitivity(&self) -> Option<&Sensitivity> {
        self.sensitivity.as_ref()
    }

    pub fn data_subject(&self) -> Option<&DataSubject> {
        self.data_subject.as_ref()
    }
    pub fn substitute_user(&self) -> Option<&UserId> {
        self.substitute_user.as_ref()
    }
}

macro_rules! policy_field {
    ($t: ident, $l: literal) => {
        #[derive(Clone, Debug, Eq, Hash, PartialEq)]
        pub struct $t(pub(crate) String);

        impl TryFrom<&str> for $t {
            type Error = IronOxideErr;
            fn try_from(value: &str) -> Result<Self> {
                validate_simple_policy_field_value(value, $l).map(Self)
            }
        }
        impl TryFrom<String> for $t {
            type Error = IronOxideErr;
            fn try_from(value: String) -> Result<Self> {
                value.as_str().try_into()
            }
        }
        impl $t {
            pub(crate) const QUERY_PARAM: &'static str = $l;

            pub fn inner(&self) -> &str {
                self.0.as_str()
            }
        }
    };
}

policy_field!(Category, "category");
policy_field!(DataSubject, "dataSubject");
policy_field!(Sensitivity, "sensitivity");

const NAME_AND_ID_MAX_LEN: usize = 100;

fn validate_simple_policy_field_value(field_id: &str, field_type: &str) -> Result<String> {
    let simple_policy_field_regex = Regex::new("^[A-Za-z0-9_-]+$").expect("regex is valid");
    let trimmed_id = field_id.trim();
    if trimmed_id.is_empty() || trimmed_id.len() > NAME_AND_ID_MAX_LEN {
        Err(IronOxideErr::ValidationError(
            field_type.to_string(),
            format!("'{trimmed_id}' must have length between 1 and 100"),
        ))
    } else if !simple_policy_field_regex.is_match(trimmed_id) {
        Err(IronOxideErr::ValidationError(
            field_type.to_string(),
            format!("'{trimmed_id}' contains invalid characters"),
        ))
    } else {
        Ok(trimmed_id.to_string())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::internal::tests::contains;
    use galvanic_assert::{matchers::eq, *};
    use std::convert::TryInto;

    #[test]
    fn test_default_policy() {
        let default_policy = PolicyGrant::default();
        let empty_policy = PolicyGrant {
            category: None,
            sensitivity: None,
            data_subject: None,
            substitute_user: None,
        };
        assert_eq!(default_policy, empty_policy);
    }

    #[test]
    fn validate_simple_policy_id_good() {
        let name_type = "name_type";
        let id = "abc-123";
        let result = validate_simple_policy_field_value(id, name_type);
        assert_that!(&result, is_variant!(Ok));

        let id = "SIMPLE_2";
        let result = validate_simple_policy_field_value(id, name_type);
        assert_that!(&result, is_variant!(Ok));

        let id = "LOTS-O-CHARS_012345678901234567890123456789012345678901234567890123456789012345678901234567890123456";
        let result = validate_simple_policy_field_value(id, name_type);
        assert_that!(&result, is_variant!(Ok))
    }

    #[test]
    fn validate_simple_policy_id_invalid_chars() {
        let name_type = "name_type";

        // very limited special chars
        let invalid = "abc!123";
        let result = validate_simple_policy_field_value(invalid, name_type);
        assert_that!(&result, is_variant!(Err));
        let validation_error = result.unwrap_err();
        assert_that!(
            &validation_error,
            is_variant!(IronOxideErr::ValidationError)
        );

        //no unicode
        let invalid = "❤HEART❤";
        let result = validate_simple_policy_field_value(invalid, name_type);
        assert_that!(&result, is_variant!(Err));
        let validation_error = result.unwrap_err();
        assert_that!(
            &validation_error,
            is_variant!(IronOxideErr::ValidationError)
        );

        // no spaces
        let invalid = "spaces not allowed";
        let result = validate_simple_policy_field_value(invalid, name_type);
        assert_that!(&result, is_variant!(Err));
        let validation_error = result.unwrap_err();
        assert_that!(
            &validation_error,
            is_variant!(IronOxideErr::ValidationError)
        );
    }

    #[test]
    fn validate_simple_policy_id_invalid_length() {
        let name_type = "name_type";
        let invalid = "too many chars 012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789";
        let result = validate_simple_policy_field_value(invalid, name_type);
        assert_that!(&result, is_variant!(Err));
        let validation_error = result.unwrap_err();
        assert_that!(
            &validation_error,
            is_variant!(IronOxideErr::ValidationError)
        );
        assert_that!(&format!("{}", validation_error), contains("100"));
    }

    #[test]
    fn can_inspect_policy_grant() -> Result<()> {
        let category = "CATEGORY".try_into()?;
        let sensitivity = "SENSITIVITY".try_into()?;
        let dat_subj = "DATA_SUBJECT".try_into()?;
        let sub_userid = "a-user-id".try_into()?;

        let policy = PolicyGrant::new(
            Some(category),
            Some(sensitivity),
            Some(dat_subj),
            Some(sub_userid),
        );

        assert_that!(&policy.category().unwrap().inner(), eq("CATEGORY"));
        assert_that!(&policy.sensitivity().unwrap().inner(), eq("SENSITIVITY"));
        assert_that!(&policy.data_subject().unwrap().inner(), eq("DATA_SUBJECT"));
        assert_that!(&policy.substitute_user().unwrap().id(), eq("a-user-id"));

        Ok(())
    }
}
