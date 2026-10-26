//! Create-phase expansion (SPEC-v3 §6, §6.1).
//!
//! Expansion is structural: placeholders are substituted into the decoded
//! document, every string value and every map key, and the result re-read.
//! A value lands verbatim whatever it contains, so quotes and backslashes
//! cannot terminate or re-escape the scalar they land in.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Map, Value};

use crate::descriptor::{ArgDecl, Descriptor};
use crate::{Result, invalid};

static PLACEHOLDER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\$\{\{\s*kit\.(args|env)\.([A-Za-z_][A-Za-z0-9_]*)\s*\}\}")
        .expect("placeholder pattern compiles")
});

/// Resolves the create-phase values for one Kit's declared args from what
/// the installer supplied: defaults fill gaps, every value is checked against
/// its `enum` or `pattern`, and a required arg nobody supplied is an error.
/// Build-phase args were answered at publish and take no value here.
pub fn resolve_args(
    descriptor: &Descriptor,
    supplied: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    for (name, decl) in &descriptor.args {
        if decl.build_arg.is_some() {
            continue;
        }
        let value = match supplied.get(name) {
            Some(v) => v.clone(),
            None => match &decl.default {
                Some(d) => d.clone(),
                None if decl.is_required => {
                    return Err(invalid(format!(
                        "{}: arg {name:?} is required",
                        descriptor.label()
                    )));
                }
                None => continue,
            },
        };
        check_arg(name, decl, &value)?;
        out.insert(name.clone(), value);
    }
    Ok(out)
}

fn check_arg(name: &str, decl: &ArgDecl, value: &str) -> Result<()> {
    if value.contains("${{") {
        return Err(invalid(format!("arg {name:?}: values are not templates")));
    }
    if let Some(allowed) = &decl.enum_
        && !allowed.iter().any(|a| a == value)
    {
        return Err(invalid(format!(
            "arg {name:?}: {value:?} is not one of {allowed:?}"
        )));
    }
    if let Some(pattern) = &decl.pattern {
        let re = Regex::new(&format!("^(?:{pattern})$"))
            .map_err(|e| invalid(format!("arg {name:?}: {e}")))?;
        if !re.is_match(value) {
            return Err(invalid(format!(
                "arg {name:?}: {value:?} does not match {pattern:?}"
            )));
        }
    }
    Ok(())
}

/// Expands `${{ kit.args.* }}` throughout a decoded descriptor. Every
/// reference must name a declared arg with a value; `kit.env` references
/// are left for [`expand_env`].
pub fn expand_args(
    raw: &Value,
    declared: &BTreeMap<String, ArgDecl>,
    values: &BTreeMap<String, String>,
) -> Result<Value> {
    expand_value(raw, &Scope::Args { declared, values }, "")
}

/// The container environment `${{ kit.env.* }}` resolves against: image
/// defaults, then arg exports, then runtime overrides.
#[derive(Debug, Clone, Default)]
pub struct ContainerEnv(pub BTreeMap<String, String>);

impl ContainerEnv {
    pub fn compose(
        image_env: &[String],
        exports: &BTreeMap<String, String>,
        overrides: &BTreeMap<String, String>,
    ) -> Self {
        let mut env = BTreeMap::new();
        for kv in image_env {
            if let Some((k, v)) = kv.split_once('=') {
                env.insert(k.to_string(), v.to_string());
            }
        }
        env.extend(exports.iter().map(|(k, v)| (k.clone(), v.clone())));
        env.extend(overrides.iter().map(|(k, v)| (k.clone(), v.clone())));
        Self(env)
    }
}

/// Expands `${{ kit.env.* }}` in every string value. Values stay strings,
/// keys are never expanded, a missing name is an error and a referenced
/// value may not itself carry a placeholder.
pub fn expand_env(raw: &Value, env: &ContainerEnv) -> Result<Value> {
    expand_value(raw, &Scope::Env(env), "")
}

/// Which `${{ kit.<scope>.* }}` references a pass resolves. An args pass
/// also expands map keys and lets a whole-value reference adopt a type.
enum Scope<'a> {
    Args {
        declared: &'a BTreeMap<String, ArgDecl>,
        values: &'a BTreeMap<String, String>,
    },
    Env(&'a ContainerEnv),
}

impl<'a> Scope<'a> {
    fn name(&self) -> &'static str {
        match self {
            Scope::Args { .. } => "args",
            Scope::Env(_) => "env",
        }
    }

    fn lookup(&self, name: &str) -> Result<&'a str> {
        match self {
            Scope::Args { declared, values } => {
                if !declared.contains_key(name) {
                    return Err(invalid(format!(
                        "${{{{ kit.args.{name} }}}} references an undeclared arg"
                    )));
                }
                values
                    .get(name)
                    .map(String::as_str)
                    .ok_or_else(|| invalid(format!("arg {name:?} has no value")))
            }
            Scope::Env(env) => {
                let value = env.0.get(name).ok_or_else(|| {
                    invalid(format!(
                        "${{{{ kit.env.{name} }}}} names a variable the container does not have"
                    ))
                })?;
                if value.contains("${{") {
                    return Err(invalid(format!(
                        "environment variable {name} carries a placeholder and cannot be referenced"
                    )));
                }
                if value.contains('\0') {
                    return Err(invalid(format!("environment variable {name} contains NUL")));
                }
                Ok(value)
            }
        }
    }
}

fn expand_value(value: &Value, scope: &Scope<'_>, path: &str) -> Result<Value> {
    match value {
        Value::String(s) => expand_scalar(s, scope),
        Value::Array(items) => items
            .iter()
            .enumerate()
            .map(|(i, v)| expand_value(v, scope, &format!("{path}[{i}]")))
            .collect::<Result<Vec<_>>>()
            .map(Value::Array),
        Value::Object(map) => {
            let mut out = Map::with_capacity(map.len());
            for (k, v) in map {
                let key = match scope {
                    Scope::Args { .. } => expand_text(k, scope)?,
                    Scope::Env(_) => k.clone(),
                };
                let child = format!("{path}.{key}");
                let value = expand_value(v, scope, &child)?;
                if out.contains_key(&key) {
                    return Err(invalid(format!("{child}: two keys expand onto {key:?}")));
                }
                out.insert(key, value);
            }
            Ok(Value::Object(out))
        }
        other => Ok(other.clone()),
    }
}

/// A string value. In an args pass a value that is one reference and
/// nothing else takes the type its resolved spelling names.
fn expand_scalar(s: &str, scope: &Scope<'_>) -> Result<Value> {
    if let Scope::Args { .. } = scope
        && let Some(caps) = PLACEHOLDER.captures(s)
        && caps.get_match().len() == s.len()
        && &caps[1] == scope.name()
    {
        return Ok(adopt(scope.lookup(&caps[2])?));
    }
    expand_text(s, scope).map(Value::String)
}

/// Substitutes every reference in `scope`, leaving the others verbatim.
fn expand_text(s: &str, scope: &Scope<'_>) -> Result<String> {
    if !s.contains("${{") {
        return Ok(s.to_string());
    }
    let mut out = String::with_capacity(s.len());
    let mut last = 0;
    for caps in PLACEHOLDER.captures_iter(s) {
        let whole = caps.get_match();
        out.push_str(&s[last..whole.start()]);
        if &caps[1] == scope.name() {
            out.push_str(scope.lookup(&caps[2])?);
        } else {
            out.push_str(whole.as_str());
        }
        last = whole.end();
    }
    out.push_str(&s[last..]);
    Ok(out)
}

/// A whole-value reference takes the type its spelling names, but only a
/// spelling that survives a round trip converts.
fn adopt(text: &str) -> Value {
    match text {
        "true" => return Value::Bool(true),
        "false" => return Value::Bool(false),
        _ => {}
    }
    if let Ok(n) = text.parse::<i64>()
        && n.to_string() == text
    {
        return Value::from(n);
    }
    if let Ok(f) = text.parse::<f64>()
        && f.is_finite()
        && f.to_string() == text
        && let Some(n) = serde_json::Number::from_f64(f)
    {
        return Value::Number(n);
    }
    Value::String(text.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn decls(names: &[&str]) -> BTreeMap<String, ArgDecl> {
        names
            .iter()
            .map(|n| (n.to_string(), ArgDecl::default()))
            .collect()
    }

    fn values(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn whole_value_references_adopt_types() {
        let raw = json!({"port": "${{ kit.args.port }}", "ver": "${{kit.args.ver}}", "pad": "${{ kit.args.pad }}", "f": "${{ kit.args.f }}"});
        let out = expand_args(
            &raw,
            &decls(&["port", "ver", "pad", "f"]),
            &values(&[
                ("port", "8080"),
                ("ver", "1.0"),
                ("pad", "007"),
                ("f", "1.5"),
            ]),
        )
        .unwrap();
        assert_eq!(out["port"], json!(8080));
        assert_eq!(out["ver"], json!("1.0"));
        assert_eq!(out["pad"], json!("007"));
        assert_eq!(out["f"], json!(1.5));
    }

    #[test]
    fn embedded_references_stay_text_and_shell_vars_pass_through() {
        let raw = json!({"cmd": "echo ${{ kit.args.greeting }} $HOME ${{ kit.env.HOME }}"});
        let out = expand_args(
            &raw,
            &decls(&["greeting"]),
            &values(&[("greeting", "hi \"there\"")]),
        )
        .unwrap();
        assert_eq!(
            out["cmd"],
            json!("echo hi \"there\" $HOME ${{ kit.env.HOME }}")
        );
        let env = ContainerEnv::compose(
            &["HOME=/home/agent".into()],
            &BTreeMap::new(),
            &BTreeMap::new(),
        );
        let out = expand_env(&out, &env).unwrap();
        assert_eq!(out["cmd"], json!("echo hi \"there\" $HOME /home/agent"));
    }

    #[test]
    fn undeclared_and_missing_are_errors() {
        let raw = json!({"x": "${{ kit.args.nope }}"});
        assert!(expand_args(&raw, &decls(&[]), &values(&[])).is_err());
        let raw = json!({"x": "${{ kit.env.NOPE }}"});
        assert!(expand_env(&raw, &ContainerEnv::default()).is_err());
        let env = ContainerEnv::compose(
            &["X=${{ kit.args.a }}".into()],
            &BTreeMap::new(),
            &BTreeMap::new(),
        );
        assert!(expand_env(&json!({"x": "${{ kit.env.X }}"}), &env).is_err());
    }

    #[test]
    fn key_collisions_are_errors() {
        let raw = json!({"${{ kit.args.a }}": 1, "b": 2});
        assert!(expand_args(&raw, &decls(&["a"]), &values(&[("a", "b")])).is_err());
    }

    #[test]
    fn arg_resolution() {
        let d = Descriptor::parse(
            r#"{"schemaVersion":"3","kind":"mixin","args":{"team":{"required":true,"enum":["alpha","beta"]},"ver":{"default":"1","pattern":"^[0-9]+$"},"built":{"buildArg":"X","default":"y"}}}"#,
        )
        .unwrap();
        assert!(resolve_args(&d, &values(&[])).is_err());
        let got = resolve_args(&d, &values(&[("team", "alpha")])).unwrap();
        assert_eq!(got.get("ver").unwrap(), "1");
        assert!(!got.contains_key("built"));
        assert!(resolve_args(&d, &values(&[("team", "gamma")])).is_err());
        assert!(resolve_args(&d, &values(&[("team", "alpha"), ("ver", "x")])).is_err());
    }
}
