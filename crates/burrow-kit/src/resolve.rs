//! Set resolution (SPEC-v3 §5.3): judging that a set of Kits is coherent and
//! ordering it by its dependency graph.

use std::collections::{BTreeMap, BTreeSet};

use sha2::{Digest, Sha256};

use crate::descriptor::{Descriptor, Kind};
use crate::image::{ImageConfig, merge_image_configs};
use crate::names::{CapName, Constraint, Provide, Version};
use crate::{Result, refused};

/// A Kit as the node loaded it: the reference it was consumed by, what the
/// registry said it is, and what its manifest carried.
#[derive(Debug, Clone)]
pub struct Loaded {
    pub reference: String,
    /// The platform manifest's digest, `sha256:...`.
    pub digest: String,
    pub descriptor: Descriptor,
    pub image_config: ImageConfig,
    /// Layer blob digests in application order.
    pub layers: Vec<String>,
}

impl Loaded {
    /// The provides entries with the version fallback applied: an
    /// unversioned provide takes a version-shaped consumption tag, else the
    /// descriptor's `version:`.
    pub fn provides(&self) -> Vec<Provide> {
        let fallback = reference_version(&self.reference).or_else(|| {
            self.descriptor
                .version
                .as_deref()
                .and_then(|v| Version::parse(v).ok())
        });
        self.descriptor
            .provides
            .iter()
            .map(|p| Provide {
                name: p.name.clone(),
                version: p.version.clone().or_else(|| fallback.clone()),
            })
            .collect()
    }

    pub fn label(&self) -> String {
        match &self.descriptor.display_name {
            Some(name) => format!("{name} ({})", self.reference),
            None => self.reference.clone(),
        }
    }
}

fn reference_version(reference: &str) -> Option<Version> {
    if reference.contains('@') {
        return None;
    }
    let after_slash = reference.rsplit('/').next()?;
    let (_, tag) = after_slash.split_once(':')?;
    Version::parse(tag).ok()
}

/// A coherent set in composition order: the workload and its mixins,
/// providers before requirers.
#[derive(Debug, Clone)]
pub struct Resolved {
    pub kits: Vec<Loaded>,
    pub workload: usize,
}

impl Resolved {
    pub fn workload(&self) -> &Loaded {
        &self.kits[self.workload]
    }

    /// The workload's image config with its mixins' merged in, in
    /// composition order.
    pub fn image_config(&self) -> ImageConfig {
        let mixins: Vec<&ImageConfig> = self
            .kits
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != self.workload)
            .map(|(_, k)| &k.image_config)
            .collect();
        merge_image_configs(&self.workload().image_config, &mixins)
    }
}

pub fn resolve(kits: Vec<Loaded>) -> Result<Resolved> {
    let workloads: Vec<usize> = kits
        .iter()
        .enumerate()
        .filter(|(_, k)| k.descriptor.kind == Kind::Workload)
        .map(|(i, _)| i)
        .collect();
    let workload = match workloads[..] {
        [i] => i,
        [] => {
            return Err(refused(
                "a composition needs exactly one workload kit; none was given",
            ));
        }
        _ => {
            let names: Vec<String> = workloads.iter().map(|&i| kits[i].label()).collect();
            return Err(refused(format!(
                "a composition needs exactly one workload kit; got {}",
                names.join(", ")
            )));
        }
    };

    let provides: Vec<Vec<Provide>> = kits.iter().map(Loaded::provides).collect();
    let mut provider: BTreeMap<&CapName, (usize, &Provide)> = BTreeMap::new();
    for (i, list) in provides.iter().enumerate() {
        for p in list {
            let &mut (prev, _) = provider.entry(&p.name).or_insert((i, p));
            if prev != i {
                return Err(refused(format!(
                    "{} is provided by both {} and {}; one name has one owner",
                    p.name,
                    kits[prev].label(),
                    kits[i].label()
                )));
            }
        }
    }

    let mut edges: BTreeSet<(usize, usize)> = BTreeSet::new();
    for (i, kit) in kits.iter().enumerate() {
        for c in &kit.descriptor.conflicts {
            if let Some((j, _)) = provider.get(c) {
                return Err(refused(format!(
                    "{} conflicts with {}, provided by {}",
                    kit.label(),
                    c,
                    kits[*j].label()
                )));
            }
        }
        for req in &kit.descriptor.requires {
            let Some(&(j, provide)) = provider.get(&req.name) else {
                return Err(refused(format!(
                    "{} requires {}, which nothing in the set provides",
                    kit.label(),
                    req.name
                )));
            };
            if j == i {
                return Err(refused(format!(
                    "{} requires {}, which only it provides",
                    kit.label(),
                    req.name
                )));
            }
            check_provide(kit, "requires", req, &kits[j], provide)?;
            edges.insert((j, i));
        }
        for integ in &kit.descriptor.integrates {
            let Some(&(j, provide)) = provider.get(&integ.name) else {
                continue;
            };
            if j == i {
                continue;
            }
            check_provide(kit, "integrates with", integ, &kits[j], provide)?;
            edges.insert((j, i));
        }
    }

    let order = topo_order(kits.len(), &edges)
        .ok_or_else(|| refused("the kits' dependency graph has a cycle"))?;
    let mut rank = vec![0; kits.len()];
    for (pos, &i) in order.iter().enumerate() {
        rank[i] = pos;
    }
    let mut ordered: Vec<(usize, Loaded)> = kits.into_iter().enumerate().collect();
    ordered.sort_by_key(|(i, _)| rank[*i]);
    Ok(Resolved {
        kits: ordered.into_iter().map(|(_, k)| k).collect(),
        workload: rank[workload],
    })
}

fn check_provide(
    kit: &Loaded,
    verb: &str,
    constraint: &Constraint,
    provider: &Loaded,
    provide: &Provide,
) -> Result<()> {
    if constraint.is_satisfied_by(provide) {
        return Ok(());
    }
    let version = provide
        .version
        .as_ref()
        .map_or_else(|| "no version".into(), Version::to_string);
    Err(refused(format!(
        "{} {verb} {constraint} but {} provides {version}",
        kit.label(),
        provider.label()
    )))
}

/// Kahn's algorithm, breaking ties by input position so the result is a
/// function of the set and not of argument order.
fn topo_order(n: usize, edges: &BTreeSet<(usize, usize)>) -> Option<Vec<usize>> {
    let mut indegree = vec![0usize; n];
    for (_, to) in edges {
        indegree[*to] += 1;
    }
    let mut out = Vec::with_capacity(n);
    let mut done = vec![false; n];
    while out.len() < n {
        let next = (0..n).find(|i| !done[*i] && indegree[*i] == 0)?;
        done[next] = true;
        out.push(next);
        for (from, to) in edges {
            if *from == next {
                indegree[*to] -= 1;
            }
        }
    }
    Some(out)
}

/// The identity of a composition: a digest over the resolved manifests, so
/// the same set always composes to the same template.
pub fn lock_digest(resolved: &Resolved) -> String {
    let mut hasher = Sha256::new();
    for kit in &resolved.kits {
        hasher.update(kit.digest.as_bytes());
        hasher.update(b"\n");
    }
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kit(reference: &str, json: &str) -> Loaded {
        Loaded {
            reference: reference.into(),
            digest: format!("sha256:{}", reference.len()),
            descriptor: Descriptor::parse(json).unwrap(),
            image_config: ImageConfig::default(),
            layers: vec![],
        }
    }

    #[test]
    fn orders_providers_first() {
        let tool = kit(
            "r/tool:1.0.0",
            r#"{"schemaVersion":"3","kind":"mixin","requires":["hello >= 1.0.0"]}"#,
        );
        let hello = kit(
            "r/hello:1.0.0",
            r#"{"schemaVersion":"3","kind":"workload","provides":["hello"]}"#,
        );
        let resolved = resolve(vec![tool, hello]).unwrap();
        assert_eq!(resolved.kits[0].reference, "r/hello:1.0.0");
        assert_eq!(resolved.workload, 0);
    }

    #[test]
    fn refusals() {
        let a = kit(
            "a",
            r#"{"schemaVersion":"3","kind":"workload","provides":["x"]}"#,
        );
        let b = kit(
            "b",
            r#"{"schemaVersion":"3","kind":"mixin","provides":["x"]}"#,
        );
        assert!(matches!(
            resolve(vec![a.clone(), b]),
            Err(crate::Error::Refused(_))
        ));
        let c = kit(
            "c",
            r#"{"schemaVersion":"3","kind":"mixin","conflicts":["x"]}"#,
        );
        assert!(resolve(vec![a.clone(), c]).is_err());
        let d = kit(
            "d",
            r#"{"schemaVersion":"3","kind":"mixin","requires":["nope"]}"#,
        );
        assert!(resolve(vec![a.clone(), d]).is_err());
        let e = kit("e", r#"{"schemaVersion":"3","kind":"mixin"}"#);
        assert!(resolve(vec![e]).is_err());
        let w2 = kit("w2", r#"{"schemaVersion":"3","kind":"workload"}"#);
        assert!(resolve(vec![a, w2]).is_err());
    }

    #[test]
    fn unversioned_provide_only_meets_unconstrained_require() {
        let a = kit(
            "a",
            r#"{"schemaVersion":"3","kind":"workload","provides":["x"]}"#,
        );
        let b = kit(
            "b",
            r#"{"schemaVersion":"3","kind":"mixin","requires":["x >= 1"]}"#,
        );
        assert!(resolve(vec![a, b.clone()]).is_err());
        let a = kit(
            "r/a:2.0",
            r#"{"schemaVersion":"3","kind":"workload","provides":["x"]}"#,
        );
        assert!(resolve(vec![a, b]).is_ok());
    }
}
