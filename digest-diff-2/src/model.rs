use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Pair {
    pub old: String,
    pub new: String,
}
impl Pair {
    pub fn validate(&self) -> Result<(), String> {
        static REF: LazyLock<Regex> = LazyLock::new(|| {
            Regex::new(r"^[a-z0-9][a-zA-Z0-9._:/-]*@sha256:[a-f0-9]{64}$").unwrap()
        });
        if [&self.old, &self.new]
            .iter()
            .all(|s| s.len() <= 512 && REF.is_match(s))
        {
            Ok(())
        } else {
            Err("Use image@sha256:<64 lowercase hex characters> for both images".into())
        }
    }
    pub fn id(&self) -> String {
        hash(&format!("{}|{}|linux/amd64|v2", self.old, self.new))
    }
    pub fn query(&self) -> String {
        url::form_urlencoded::Serializer::new(String::new())
            .append_pair("old", &self.old)
            .append_pair("new", &self.new)
            .finish()
    }
}
pub fn hash(s: &str) -> String {
    hex::encode(Sha256::digest(s.as_bytes()))
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Package {
    pub name: String,
    pub version: String,
    #[serde(rename = "type")]
    pub kind: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Changed {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub old_version: String,
    pub new_version: String,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    #[serde(default)]
    pub namespace: String,
    pub package: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub version: String,
    pub severity: String,
    #[serde(default)]
    pub fix_state: String,
    #[serde(default)]
    pub fix_versions: Vec<String>,
    #[serde(default)]
    pub url: String,
}
impl Finding {
    pub fn identity(&self) -> String {
        format!(
            "{}|{}|{}|{}",
            self.namespace, self.id, self.kind, self.package
        )
    }
    pub fn link(&self) -> String {
        if let Ok(u) = url::Url::parse(&self.url)
            && matches!(u.scheme(), "http" | "https")
            && u.host_str().is_some()
            && u.username().is_empty()
            && u.password().is_none()
        {
            return u.to_string();
        }
        static CVE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^CVE-\d{4}-\d{4,}$").unwrap());
        static GHSA: LazyLock<Regex> =
            LazyLock::new(|| Regex::new(r"^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$").unwrap());
        if CVE.is_match(&self.id) {
            format!("https://www.cve.org/CVERecord?id={}", self.id)
        } else if GHSA.is_match(&self.id) {
            format!("https://github.com/advisories/{}", self.id)
        } else {
            String::new()
        }
    }
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Vulnerabilities {
    pub introduced: Vec<Finding>,
    pub resolved: Vec<Finding>,
    pub persisting: Vec<Finding>,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Report {
    pub added: Vec<Package>,
    pub removed: Vec<Package>,
    pub changed: Vec<Changed>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vulnerabilities: Option<Vulnerabilities>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scan: Option<serde_json::Value>,
}
pub fn packages(old: &[Package], new: &[Package]) -> Report {
    fn index(pkgs: &[Package]) -> BTreeMap<(String, String), String> {
        let mut sets: BTreeMap<(String, String), BTreeSet<String>> = BTreeMap::new();
        for p in pkgs {
            sets.entry((p.name.clone(), p.kind.clone()))
                .or_default()
                .insert(p.version.clone());
        }
        sets.into_iter()
            .map(|(k, v)| (k, v.into_iter().collect::<Vec<_>>().join(", ")))
            .collect()
    }
    let (a, b) = (index(old), index(new));
    let mut r = Report::default();
    for ((name, kind), version) in &b {
        match a.get(&(name.clone(), kind.clone())) {
            None => r.added.push(Package {
                name: name.clone(),
                kind: kind.clone(),
                version: version.clone(),
            }),
            Some(v) if v != version => r.changed.push(Changed {
                name: name.clone(),
                kind: kind.clone(),
                old_version: v.clone(),
                new_version: version.clone(),
            }),
            _ => {}
        }
    }
    for ((name, kind), version) in a {
        if !b.contains_key(&(name.clone(), kind.clone())) {
            r.removed.push(Package {
                name,
                kind,
                version,
            })
        }
    }
    r
}
pub fn vulnerabilities(old: Vec<Finding>, new: Vec<Finding>) -> Vulnerabilities {
    let a: BTreeSet<_> = old.iter().map(Finding::identity).collect();
    let b: BTreeSet<_> = new.iter().map(Finding::identity).collect();
    let mut r = Vulnerabilities::default();
    for f in new {
        if a.contains(&f.identity()) {
            r.persisting.push(f)
        } else {
            r.introduced.push(f)
        }
    }
    for f in old {
        if !b.contains(&f.identity()) {
            r.resolved.push(f)
        }
    }
    fn rank(s: &str) -> u8 {
        match s {
            "Critical" => 0,
            "High" => 1,
            "Medium" => 2,
            "Low" => 3,
            _ => 4,
        }
    }
    for fs in [&mut r.introduced, &mut r.resolved, &mut r.persisting] {
        fs.sort_by_key(|f| (rank(&f.severity), f.identity(), f.version.clone()));
    }
    r
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pinned_only() {
        let good = Pair {
            old: format!("alpine@sha256:{}", "a".repeat(64)),
            new: format!("alpine@sha256:{}", "b".repeat(64)),
        };
        assert!(good.validate().is_ok());
        for bad in ["alpine:latest", "/etc/passwd", "--help"] {
            assert!(
                Pair {
                    old: bad.into(),
                    ..good.clone()
                }
                .validate()
                .is_err()
            )
        }
    }
    #[test]
    fn multiple_versions() {
        let p = |v: &str| Package {
            name: "lib".into(),
            kind: "python".into(),
            version: v.into(),
        };
        assert_eq!(
            packages(&[p("1"), p("2")], &[p("2")]).changed[0].old_version,
            "1, 2"
        )
    }
    #[test]
    fn advisory_safety() {
        let f = Finding {
            id: "CVE-2026-12345".into(),
            url: "javascript:alert(1)".into(),
            ..Default::default()
        };
        assert!(f.link().starts_with("https://www.cve.org/"));
        assert!(
            Finding {
                id: "<script>".into(),
                ..Default::default()
            }
            .link()
            .is_empty()
        )
    }
    #[test]
    fn version_change_persists() {
        let f = Finding {
            id: "CVE-2026-12345".into(),
            package: "lib".into(),
            version: "1".into(),
            ..Default::default()
        };
        let r = vulnerabilities(
            vec![f.clone()],
            vec![Finding {
                version: "2".into(),
                ..f
            }],
        );
        assert_eq!(r.persisting.len(), 1);
        assert!(r.introduced.is_empty())
    }
}
