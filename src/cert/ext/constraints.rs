use std::fmt::Display;

use der::oid::{
    db::rfc5280::{ID_CE_BASIC_CONSTRAINTS, ID_CE_NAME_CONSTRAINTS, ID_CE_POLICY_CONSTRAINTS},
    AssociatedOid, ObjectIdentifier,
};

use crate::utils::{IndentString, OptionInto, VecInto};

use super::name::GeneralName;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BasicConstraints {
    pub ca: bool,
    pub path_len_constraint: Option<u8>,
}

impl AssociatedOid for BasicConstraints {
    const OID: ObjectIdentifier = ID_CE_BASIC_CONSTRAINTS;
}

impl From<x509_cert::ext::pkix::BasicConstraints> for BasicConstraints {
    fn from(value: x509_cert::ext::pkix::BasicConstraints) -> Self {
        Self {
            ca: value.ca,
            path_len_constraint: value.path_len_constraint,
        }
    }
}

impl Display for BasicConstraints {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Basic Constraints:")?;
        match self.path_len_constraint {
            Some(len) => {
                write!(
                    f,
                    "{}",
                    format!("CA:{}, pathlen:{}", self.ca.to_string().to_uppercase(), len).indent(4)
                )
            }
            None => {
                write!(
                    f,
                    "{}",
                    format!("CA:{}", self.ca.to_string().to_uppercase()).indent(4)
                )
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyConstraints {
    pub require_explicit_policy: Option<u32>,
    pub inhibit_policy_mapping: Option<u32>,
}

impl AssociatedOid for PolicyConstraints {
    const OID: ObjectIdentifier = ID_CE_POLICY_CONSTRAINTS;
}

impl From<x509_cert::ext::pkix::PolicyConstraints> for PolicyConstraints {
    fn from(value: x509_cert::ext::pkix::PolicyConstraints) -> Self {
        Self {
            require_explicit_policy: value.require_explicit_policy,
            inhibit_policy_mapping: value.require_explicit_policy,
        }
    }
}

impl Display for PolicyConstraints {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Policy Constraints:")?;
        if self.require_explicit_policy.is_some() {
            write!(
                f,
                "\n{}",
                format!(
                    "Require Explicit Policy: {}",
                    self.require_explicit_policy.unwrap()
                )
                .indent(4)
            )?;
        }
        if self.inhibit_policy_mapping.is_some() {
            write!(
                f,
                "\n{}",
                format!(
                    "Inhibit Policy Mapping: {}",
                    self.inhibit_policy_mapping.unwrap()
                )
                .indent(4)
            )?;
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NameConstraints {
    pub permitted_subtrees: Option<GeneralSubtrees>,
    pub excluded_subtrees: Option<GeneralSubtrees>,
}

impl AssociatedOid for NameConstraints {
    const OID: ObjectIdentifier = ID_CE_NAME_CONSTRAINTS;
}

impl From<x509_cert::ext::pkix::NameConstraints> for NameConstraints {
    fn from(value: x509_cert::ext::pkix::NameConstraints) -> Self {
        Self {
            permitted_subtrees: value.permitted_subtrees.opt_into(),
            excluded_subtrees: value.excluded_subtrees.opt_into(),
        }
    }
}

impl Display for NameConstraints {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.permitted_subtrees {
            Some(permitted) => {
                writeln!(f, "Permitted:")?;
                write!(f, "{}", permitted.to_string().indent(4))?;
            }
            None => {}
        }

        match &self.excluded_subtrees {
            Some(excluded) => {
                if self.permitted_subtrees.is_some() {
                    writeln!(f)?;
                }
                writeln!(f, "Excluded:")?;
                write!(f, "{}", excluded.to_string().indent(4))?;
            }
            None => {}
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneralSubtrees(pub Vec<GeneralSubtree>);

impl From<x509_cert::ext::pkix::constraints::name::GeneralSubtrees> for GeneralSubtrees {
    fn from(value: x509_cert::ext::pkix::constraints::name::GeneralSubtrees) -> Self {
        Self(value.vec_into())
    }
}

impl Display for GeneralSubtrees {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            self.0
                .clone()
                .iter()
                .map(|v| v.to_string())
                .collect::<Vec<String>>()
                .join("\n")
                .indent(4)
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneralSubtree {
    pub base: GeneralName,
    pub minimum: u32,
    pub maximum: Option<u32>,
}

impl From<x509_cert::ext::pkix::constraints::name::GeneralSubtree> for GeneralSubtree {
    fn from(value: x509_cert::ext::pkix::constraints::name::GeneralSubtree) -> Self {
        Self {
            base: value.base.into(),
            minimum: value.minimum,
            maximum: value.maximum,
        }
    }
}

impl Display for GeneralSubtree {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.base)
    }
}
