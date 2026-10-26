//! Kit-to-Kit capability names, versions and constraints (SPEC-v3 §5).

use std::cmp::Ordering;
use std::fmt;

use crate::{Result, invalid};

const DEFAULT_NAMESPACE: &str = "com.docker.kit";

/// A normalized capability name: `namespace/base`. Bare names live in
/// `com.docker.kit/`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CapName(String);

impl CapName {
    pub fn parse(text: &str) -> Result<Self> {
        let text = text.trim();
        let (namespace, base) = match text.rsplit_once('/') {
            Some((ns, base)) => (ns, base),
            None => (DEFAULT_NAMESPACE, text),
        };
        if !is_base_name(base) {
            return Err(invalid(format!(
                "capability name {text:?} is not a valid name"
            )));
        }
        // `deb/` and `apk/` are the single labels the spec defines, for the
        // provides publishing derives from a rootfs's package database.
        let derived = namespace == "deb" || namespace == "apk";
        if namespace != DEFAULT_NAMESPACE && !derived && !is_reverse_dns(namespace) {
            return Err(invalid(format!(
                "capability namespace {namespace:?} in {text:?} must be reverse-DNS"
            )));
        }
        Ok(Self(format!("{namespace}/{base}")))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CapName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

fn is_base_name(s: &str) -> bool {
    let bytes = s.as_bytes();
    !bytes.is_empty()
        && bytes[0].is_ascii_alphanumeric()
        && !matches!(bytes[bytes.len() - 1], b'-' | b'.')
        && bytes.iter().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'.' | b'+')
        })
}

/// Lowercase kebab-case: `[a-z0-9-]+`, not starting or ending with `-`.
pub(crate) fn is_kebab(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !s.starts_with('-')
        && !s.ends_with('-')
}

fn is_reverse_dns(s: &str) -> bool {
    let labels: Vec<&str> = s.split('.').collect();
    labels.len() >= 2
        && s.len() <= 253
        && labels.iter().all(|l| {
            let b = l.as_bytes();
            !b.is_empty()
                && b.len() <= 63
                && b[0].is_ascii_alphanumeric()
                && b[b.len() - 1].is_ascii_alphanumeric()
                && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'-')
        })
}

/// `[0-9]+(\.[0-9A-Za-z-]+)*`, compared per segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version(Vec<String>);

impl Version {
    pub fn parse(text: &str) -> Result<Self> {
        let segments: Vec<&str> = text.split('.').collect();
        let first_ok = !segments[0].is_empty() && segments[0].bytes().all(|b| b.is_ascii_digit());
        let rest_ok = segments[1..]
            .iter()
            .all(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'));
        if !first_ok || !rest_ok {
            return Err(invalid(format!("version {text:?} is not version-shaped")));
        }
        Ok(Self(segments.into_iter().map(str::to_string).collect()))
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        for (a, b) in self.0.iter().zip(other.0.iter()) {
            let ord = match (a.parse::<u64>(), b.parse::<u64>()) {
                (Ok(x), Ok(y)) => x.cmp(&y),
                _ => a.cmp(b),
            };
            if ord != Ordering::Equal {
                return ord;
            }
        }
        self.0.len().cmp(&other.0.len())
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.join("."))
    }
}

/// A `provides` entry: `name` or `name@version`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provide {
    pub name: CapName,
    pub version: Option<Version>,
}

impl Provide {
    pub fn parse(text: &str) -> Result<Self> {
        match text.split_once('@') {
            Some((name, version)) => Ok(Self {
                name: CapName::parse(name)?,
                version: Some(Version::parse(version.trim())?),
            }),
            None => Ok(Self {
                name: CapName::parse(text)?,
                version: None,
            }),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Ge,
    Gt,
    Le,
    Lt,
    Eq,
}

impl Op {
    /// Two-character operators first, so `>=` is not read as `>`.
    const ALL: [Op; 5] = [Op::Ge, Op::Le, Op::Gt, Op::Lt, Op::Eq];

    pub fn as_str(self) -> &'static str {
        match self {
            Op::Ge => ">=",
            Op::Gt => ">",
            Op::Le => "<=",
            Op::Lt => "<",
            Op::Eq => "=",
        }
    }
}

/// A `requires` or `integrates` entry: a name with ANDed version bounds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Constraint {
    pub name: CapName,
    pub bounds: Vec<(Op, Version)>,
}

impl Constraint {
    pub fn parse(text: &str) -> Result<Self> {
        let text = text.trim();
        let split = text.find(|c: char| c.is_whitespace() || matches!(c, '>' | '<' | '='));
        let (name, rest) = match split {
            Some(i) => (&text[..i], text[i..].trim()),
            None => (text, ""),
        };
        let name = CapName::parse(name)?;
        let bounds = if rest.is_empty() {
            Vec::new()
        } else {
            rest.split(',')
                .map(|clause| {
                    let clause = clause.trim();
                    let (op, version) = Op::ALL
                        .into_iter()
                        .find_map(|op| clause.strip_prefix(op.as_str()).map(|v| (op, v)))
                        .ok_or_else(|| {
                            invalid(format!(
                                "constraint {text:?}: unknown operator in {clause:?}"
                            ))
                        })?;
                    Ok((op, Version::parse(version.trim())?))
                })
                .collect::<Result<_>>()?
        };
        let c = Self { name, bounds };
        if !c.is_satisfiable() {
            return Err(invalid(format!(
                "constraint {text:?} can never be satisfied"
            )));
        }
        Ok(c)
    }

    fn is_satisfiable(&self) -> bool {
        let lower = self
            .bounds
            .iter()
            .filter(|(op, _)| matches!(op, Op::Ge | Op::Gt | Op::Eq));
        let upper = self
            .bounds
            .iter()
            .filter(|(op, _)| matches!(op, Op::Le | Op::Lt | Op::Eq));
        for (lo_op, lo) in lower {
            for (hi_op, hi) in upper.clone() {
                match lo.cmp(hi) {
                    Ordering::Greater => return false,
                    Ordering::Equal => {
                        let exclusive = matches!(lo_op, Op::Gt) || matches!(hi_op, Op::Lt);
                        if exclusive {
                            return false;
                        }
                    }
                    Ordering::Less => {}
                }
            }
        }
        true
    }

    /// Whether `provide` satisfies this constraint. An unversioned provide
    /// satisfies only an unconstrained require.
    pub fn is_satisfied_by(&self, provide: &Provide) -> bool {
        if provide.name != self.name {
            return false;
        }
        let Some(version) = &provide.version else {
            return self.bounds.is_empty();
        };
        self.bounds.iter().all(|(op, bound)| match op {
            Op::Ge => version >= bound,
            Op::Gt => version > bound,
            Op::Le => version <= bound,
            Op::Lt => version < bound,
            Op::Eq => version == bound,
        })
    }
}

impl fmt::Display for Constraint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)?;
        for (i, (op, version)) in self.bounds.iter().enumerate() {
            let sep = if i == 0 { " " } else { ", " };
            write!(f, "{sep}{} {version}", op.as_str())?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_names_normalize() {
        assert_eq!(CapName::parse("gh").unwrap().as_str(), "com.docker.kit/gh");
        assert_eq!(
            CapName::parse("com.docker.kit/gh").unwrap(),
            CapName::parse("gh").unwrap()
        );
        assert_ne!(
            CapName::parse("com.example/gh").unwrap(),
            CapName::parse("gh").unwrap()
        );
        assert!(CapName::parse("com..example/gh").is_err());
        assert!(CapName::parse("Gh").is_err());
        assert!(CapName::parse("libstdc++6").is_ok());
        assert!(CapName::parse("deb/libstdc++6").is_ok());
        assert!(CapName::parse("rpm/bash").is_err());
    }

    #[test]
    fn versions_compare_per_segment() {
        let v = |s| Version::parse(s).unwrap();
        assert!(v("2.10.0") > v("2.9.1"));
        assert!(v("1.0") < v("1.0.1"));
        assert!(v("1.0.b") > v("1.0.a"));
        assert!(Version::parse("v1.0").is_err());
    }

    #[test]
    fn constraints() {
        let c = Constraint::parse("node >= 20.0.0, < 21.0.0").unwrap();
        assert!(c.is_satisfied_by(&Provide::parse("node@20.5.1").unwrap()));
        assert!(!c.is_satisfied_by(&Provide::parse("node@21.0.0").unwrap()));
        assert!(!c.is_satisfied_by(&Provide::parse("node").unwrap()));
        assert!(
            Constraint::parse("node")
                .unwrap()
                .is_satisfied_by(&Provide::parse("node").unwrap())
        );
        assert!(Constraint::parse("node > 2, < 2").is_err());
        assert!(Constraint::parse("node = 2, = 3").is_err());
    }
}
