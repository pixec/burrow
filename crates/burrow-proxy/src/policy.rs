//! Deciding whether a sandbox may reach a host, and what happens to the
//! requests that are allowed through.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, RwLock};

/// Rules one policy may carry.
///
/// Every request on an inspected session walks this list until something
/// matches, so its length is part of the per-request cost. Far above what a
/// real policy uses.
pub const MAX_RULES: usize = 32;

/// Query or header entries one matcher may carry, and methods it may name.
///
/// The request itself is bounded elsewhere (a head is at most 16 KiB), so
/// bounding the matcher is what bounds the product of the two.
pub const MAX_MATCH_ENTRIES: usize = 8;

/// Longest pattern accepted, in bytes. A pattern is written by an operator and
/// evaluated against everything a guest sends; there is no legitimate reason
/// for one to be long.
pub const MAX_PATTERN: usize = 256;

/// Ceiling on the compiled size of one regex. The engine is linear in the
/// input, but a pattern can still be made large in the *pattern*; this is what
/// keeps a policy from costing memory instead of time.
const MAX_REGEX_BYTES: usize = 64 * 1024;

/// How much egress a sandbox has at all.
///
/// The proxy needs this and not only `allow_domains`, because the resolver is
/// reachable from every mode, including one with no egress, and a resolver that
/// answers anything is a tunnel out. Defaults to the closed end.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum NetworkMode {
    /// No egress at all.
    #[default]
    None,
    /// Egress through the proxy, restricted to `allow_domains`.
    Allowlist,
    /// NAT'd egress, audited but not filtered.
    Open,
}

/// How one string is compared against the part of a request it names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchOp {
    Exact,
    StartsWith,
    Regex,
}

/// One compiled string comparison.
///
/// Case sensitivity is the caller's to decide: paths, methods and header
/// values are compared as written, header names are not. Nothing here
/// lowercases anything on its own.
#[derive(Debug, Clone)]
pub enum Match {
    Exact(String),
    StartsWith(String),
    /// Unanchored, like every other regex API: a pattern matches if it is found
    /// anywhere in the subject. Anchor it with `^` to mean the whole string.
    Regex(Arc<regex::Regex>),
}

impl Match {
    /// Compiles one comparison, or says why it cannot be one.
    ///
    /// Called at the API door as well as when a policy is loaded, so a bad
    /// pattern is refused where the operator can still see the error.
    pub fn compile(op: MatchOp, value: &str) -> Result<Self, String> {
        if value.is_empty() {
            return Err("a match pattern may not be empty".into());
        }
        if value.len() > MAX_PATTERN {
            return Err(format!(
                "a match pattern is at most {MAX_PATTERN} bytes ({} given)",
                value.len()
            ));
        }
        Ok(match op {
            MatchOp::Exact => Match::Exact(value.to_string()),
            MatchOp::StartsWith => Match::StartsWith(value.to_string()),
            MatchOp::Regex => {
                // `regex` has no backtracking, so matching is linear in the
                // subject whatever the pattern. The size limits bound the
                // pattern's own cost, which is the only unbounded part left.
                let compiled = regex::RegexBuilder::new(value)
                    .size_limit(MAX_REGEX_BYTES)
                    .dfa_size_limit(MAX_REGEX_BYTES)
                    .build()
                    .map_err(|err| format!("{value:?} is not a usable regex: {err}"))?;
                Match::Regex(Arc::new(compiled))
            }
        })
    }

    pub fn matches(&self, subject: &str) -> bool {
        match self {
            Match::Exact(value) => subject == value,
            Match::StartsWith(value) => subject.starts_with(value.as_str()),
            Match::Regex(pattern) => pattern.is_match(subject),
        }
    }
}

/// Which requests a rule applies to.
///
/// A matcher never blocks: it selects the requests the rule's action applies
/// to, and a request matching nothing is still allowed and leaves unmodified.
/// Every dimension present must match; one left out is not examined.
#[derive(Debug, Clone, Default)]
pub struct RequestMatch {
    /// Compared against the path alone, without the query string.
    pub path: Option<Match>,
    /// Any one matching is enough; compared exactly and case-sensitively.
    pub methods: Vec<String>,
    /// Key compared exactly and case-sensitively, value with `Match`.
    pub query: Vec<(String, Match)>,
    /// Name compared case-insensitively, value case-sensitively.
    pub headers: Vec<(String, Match)>,
}

/// What one request looks like to a matcher, whatever protocol carried it.
///
/// HTTP/1.1 and HTTP/2 produce the same view deliberately: a request that
/// matches under one and not the other would make h2 the way around a rule.
#[derive(Debug, Clone, Copy)]
pub struct Request<'a> {
    pub method: &'a str,
    /// Path only, without the query string or its `?`.
    pub path: &'a str,
    /// Query string as written, without the leading `?`.
    pub query: &'a str,
    pub headers: &'a [(String, String)],
}

impl RequestMatch {
    pub fn matches(&self, request: &Request<'_>) -> bool {
        if let Some(path) = &self.path
            && !path.matches(request.path)
        {
            return false;
        }
        if !self.methods.is_empty() && !self.methods.iter().any(|m| m == request.method) {
            return false;
        }
        for (key, value) in &self.query {
            // A repeated key satisfies the entry if any of its values does,
            // which is the only reading that does not depend on which
            // occurrence a server happens to take.
            if !query_pairs(request.query)
                .any(|(name, found)| name == key.as_str() && value.matches(&found))
            {
                return false;
            }
        }
        for (name, value) in &self.headers {
            if !request
                .headers
                .iter()
                .any(|(found, text)| found.eq_ignore_ascii_case(name) && value.matches(text))
            {
                return false;
            }
        }
        true
    }
}

/// Splits a query string into its pairs, percent-decoded.
///
/// Splitting before decoding is what keeps an encoded `&` or `=` inside a value
/// from becoming a separator. A key with no `=` has an empty value.
fn query_pairs(query: &str) -> impl Iterator<Item = (String, String)> + '_ {
    query
        .split('&')
        .filter(|part| !part.is_empty())
        .map(|part| {
            let (key, value) = part.split_once('=').unwrap_or((part, ""));
            (percent_decode(key), percent_decode(value))
        })
}

/// Decodes `%XX` escapes. An escape that is not two hex digits is left as it
/// was written rather than guessed at.
fn percent_decode(text: &str) -> String {
    if !text.contains('%') {
        return text.to_string();
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        match bytes[at] {
            b'%' if at + 2 < bytes.len() => match hex(bytes[at + 1]).zip(hex(bytes[at + 2])) {
                Some((hi, lo)) => {
                    out.push(hi << 4 | lo);
                    at += 3;
                }
                None => {
                    out.push(b'%');
                    at += 1;
                }
            },
            byte => {
                out.push(byte);
                at += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// How the forward leg is carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForwardScheme {
    /// Plaintext. The shared secret is protected by where the endpoint sits and
    /// by nothing else, so this is for an endpoint only the node can reach.
    Http,
    /// TLS, verified against the same public roots as any other origin. There
    /// is no way to relax that verification.
    Https,
}

impl ForwardScheme {
    /// The port a URL that names none is dialled on.
    pub fn default_port(self) -> u16 {
        match self {
            ForwardScheme::Http => 80,
            ForwardScheme::Https => 443,
        }
    }
}

/// Where a forwarded request is sent.
///
/// Held apart from the raw URL so the parse is not redone per request, which
/// would be work on a guest's schedule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardTarget {
    pub scheme: ForwardScheme,
    pub host: String,
    pub port: u16,
    /// Path prefix, with no trailing slash. Empty for a bare origin.
    pub prefix: String,
}

impl ForwardTarget {
    /// Parses `http://host[:port][/path]` or the same over `https`.
    ///
    /// Both, and nothing else: `https` protects the secret in transit, and
    /// `http` remains legitimate for an endpoint on the node's own network. A
    /// scheme the proxy does not speak is refused rather than approximated.
    pub fn parse(url: &str) -> Result<Self, String> {
        if url.len() > MAX_PATTERN {
            return Err(format!("a forward url is at most {MAX_PATTERN} bytes"));
        }
        let (scheme, rest) = match url.strip_prefix("https://") {
            Some(rest) => (ForwardScheme::Https, rest),
            None => (
                ForwardScheme::Http,
                url.strip_prefix("http://")
                    .ok_or("a forward url must begin with http:// or https://")?,
            ),
        };
        if rest.contains('?') || rest.contains('#') {
            return Err("a forward url may not carry a query string or a fragment".into());
        }
        if rest.bytes().any(|b| b <= b' ' || b == 0x7f) {
            return Err("a forward url may not contain whitespace or control characters".into());
        }
        let (authority, path) = match rest.find('/') {
            Some(at) => (&rest[..at], &rest[at..]),
            None => (rest, ""),
        };
        if authority.contains('@') {
            return Err("a forward url may not carry userinfo".into());
        }
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) => (
                host,
                port.parse::<u16>()
                    .map_err(|_| "a forward url's port is not a number")?,
            ),
            None => (authority, scheme.default_port()),
        };
        if host.is_empty() || port == 0 {
            return Err("a forward url names no host".into());
        }
        // The relay concatenates this with the original target, so a prefix
        // that already ends in `/` would produce `//` and a path some servers
        // route differently.
        let prefix = path.trim_end_matches('/').to_string();
        Ok(ForwardTarget {
            scheme,
            host: host.to_string(),
            port,
            prefix,
        })
    }
}

/// Sending a request somewhere the operator controls instead of to the origin.
#[derive(Debug, Clone)]
pub struct Forward {
    pub target: ForwardTarget,
    /// As written by the operator, for the audit record.
    pub url: String,
    /// Shared secret, sent as `burrow-forwarded-secret`. Empty means none.
    pub secret: String,
}

/// What the proxy does to a request a rule claimed.
#[derive(Debug, Clone)]
pub enum Action {
    /// Set these headers, replacing whatever the client sent under each name.
    SetHeaders(Vec<(String, String)>),
    Forward(Forward),
    /// A rule the node could not compile. Validated at the API door, so one of
    /// these means the policy in force is not the one that was written, and the
    /// safe reading is that nothing it governed may go anywhere.
    Refuse(String),
}

/// One rule: which requests, and what happens to them.
#[derive(Debug, Clone)]
pub struct Rule {
    /// Domain glob, matched with [`matches`] like an allowlist entry.
    pub domain: String,
    /// `None` matches every request to the domain, and therefore shadows every
    /// rule after it for that domain.
    pub matcher: Option<RequestMatch>,
    pub action: Action,
}

impl Rule {
    /// Whether a request this rule claims stops going to the origin.
    ///
    /// A refusal counts, because the request does not reach the origin either
    /// way, and both need the relay that can answer without one.
    pub fn diverts(&self) -> bool {
        matches!(self.action, Action::Forward(_) | Action::Refuse(_))
    }
}

/// What the proxy knows about one sandbox.
#[derive(Debug, Clone, Default)]
pub struct SandboxPolicy {
    pub sandbox_id: String,
    /// What kind of egress this sandbox has.
    pub mode: NetworkMode,
    /// Domain globs, e.g. `pypi.org` or `*.pythonhosted.org`.
    pub allow_domains: Vec<String>,
    /// Whether this sandbox's TLS may be terminated so the host named inside
    /// the session can be checked. Off unless the caller asked for it: it
    /// trades payload privacy for closing domain fronting.
    pub inspect_tls: bool,
    /// IPv4 ranges this sandbox may never reach. Checked against the address
    /// the proxy would dial, not against the name: an allowed domain that
    /// resolves into a denied range is still denied.
    pub deny_cidrs: Vec<String>,
    /// What the host does to the requests it inspects, in policy order.
    ///
    /// Behind an `Arc` so cloning a policy per connection does not clone the
    /// compiled patterns: a rule is compiled when the policy is loaded, never
    /// on a guest's schedule.
    pub rules: Arc<Vec<Rule>>,
}

impl SandboxPolicy {
    /// Whether `address` falls in a denied range.
    ///
    /// An entry that does not parse denies everything: the daemon validates
    /// these at the door, so one arriving malformed means the policy is not
    /// the one that was written, and the safe reading of a denial is the
    /// broader one.
    pub fn denies(&self, address: Ipv4Addr) -> bool {
        self.deny_cidrs.iter().any(|entry| match parse_cidr(entry) {
            Some((network, prefix)) => contains(network, prefix, address),
            None => true,
        })
    }
}

/// Parses `a.b.c.d/len` exactly, or a bare address as a /32.
///
/// Deliberately as strict as the nftables renderer: the two must not disagree
/// about what a policy denies.
fn parse_cidr(value: &str) -> Option<(Ipv4Addr, u8)> {
    let (address, prefix) = match value.split_once('/') {
        Some((address, len)) => {
            if len.is_empty() || !len.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            let prefix: u8 = len.parse().ok()?;
            if prefix > 32 {
                return None;
            }
            (address, prefix)
        }
        None => (value, 32),
    };
    Some((address.parse::<Ipv4Addr>().ok()?, prefix))
}

fn contains(network: Ipv4Addr, prefix: u8, address: Ipv4Addr) -> bool {
    // A /0 covers everything, and shifting a u32 by 32 is undefined.
    let mask = match prefix {
        0 => 0,
        bits => u32::MAX << (32 - bits),
    };
    u32::from(network) & mask == u32::from(address) & mask
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    /// Denied, with a reason suitable for an audit record.
    Deny(&'static str),
}

impl Decision {
    pub fn allowed(&self) -> bool {
        matches!(self, Decision::Allow)
    }

    pub fn reason(&self) -> &'static str {
        match self {
            Decision::Allow => "allowed",
            Decision::Deny(reason) => reason,
        }
    }
}

/// Matches a hostname against one glob.
///
/// `*.example.com` matches any single-or-multi-label subdomain but *not*
/// `example.com` itself, matching how people read such a rule. A bare
/// `example.com` matches only itself.
pub fn matches(pattern: &str, host: &str) -> bool {
    let pattern = pattern.trim().to_ascii_lowercase();
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();

    match pattern.strip_prefix("*.") {
        Some(suffix) => host.len() > suffix.len() + 1 && host.ends_with(&format!(".{suffix}")),
        None => pattern == host,
    }
}

/// Per-sandbox egress policy, looked up by the source address of a connection.
///
/// The proxy sees only an IP, so this is the mapping that turns a packet back
/// into a sandbox identity. It is refreshed by the daemon whenever sandboxes
/// or policies change.
#[derive(Default)]
pub struct PolicyTable {
    by_ip: RwLock<HashMap<Ipv4Addr, SandboxPolicy>>,
}

impl PolicyTable {
    pub fn replace(&self, entries: HashMap<Ipv4Addr, SandboxPolicy>) {
        *self.by_ip.write().unwrap() = entries;
    }

    pub fn get(&self, ip: Ipv4Addr) -> Option<SandboxPolicy> {
        self.by_ip.read().unwrap().get(&ip).cloned()
    }

    /// Decides whether `ip` may reach `host`.
    ///
    /// An unknown source or an unknown destination is denied: the proxy only
    /// ever permits what it can positively identify and match.
    pub fn decide(&self, ip: Ipv4Addr, host: Option<&str>) -> (Option<SandboxPolicy>, Decision) {
        let Some(policy) = self.get(ip) else {
            return (None, Decision::Deny("unknown source sandbox"));
        };
        let Some(host) = host else {
            // No SNI and no Host header: could be ECH, a non-HTTP protocol, or
            // an attempt to evade the allowlist. None of those are allowable
            // when policy is written in terms of hostnames.
            return (
                Some(policy),
                Decision::Deny("destination host not identifiable"),
            );
        };
        let allowed = policy.allow_domains.iter().any(|p| matches(p, host));
        let decision = if allowed {
            Decision::Allow
        } else {
            Decision::Deny("host not in allowlist")
        };
        (Some(policy), decision)
    }

    /// Decides whether `ip` may have `name` resolved upstream.
    ///
    /// Resolution is egress: a sandbox that may not connect anywhere can still
    /// encode whatever it likes into a name and watch a public resolver receive
    /// it. The same allowlist that governs connections governs lookups, with
    /// `.internal` handled elsewhere before this is consulted.
    pub fn may_resolve(&self, ip: Ipv4Addr, name: &str) -> (Option<SandboxPolicy>, Decision) {
        let Some(policy) = self.get(ip) else {
            return (None, Decision::Deny("unknown source sandbox"));
        };
        let decision = match policy.mode {
            // Open egress is unfiltered by definition; filtering its DNS would
            // stop nothing it cannot do directly.
            NetworkMode::Open => Decision::Allow,
            NetworkMode::None => Decision::Deny("sandbox has no egress"),
            NetworkMode::Allowlist => {
                if name.is_empty() {
                    Decision::Deny("query names no host")
                } else if policy.allow_domains.iter().any(|p| matches(p, name)) {
                    Decision::Allow
                } else {
                    Decision::Deny("name not in allowlist")
                }
            }
        };
        (Some(policy), decision)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_patterns_match_only_themselves() {
        assert!(matches("pypi.org", "pypi.org"));
        assert!(!matches("pypi.org", "evil-pypi.org"));
        assert!(!matches("pypi.org", "sub.pypi.org"));
    }

    #[test]
    fn wildcard_matches_subdomains_but_not_the_apex() {
        assert!(matches("*.pythonhosted.org", "files.pythonhosted.org"));
        assert!(matches("*.pythonhosted.org", "a.b.pythonhosted.org"));
        assert!(!matches("*.pythonhosted.org", "pythonhosted.org"));
    }

    #[test]
    fn wildcard_does_not_match_a_lookalike_suffix() {
        // The classic bypass: registering evilpythonhosted.org.
        assert!(!matches("*.pythonhosted.org", "evilpythonhosted.org"));
        assert!(!matches("*.pythonhosted.org", "pythonhosted.org.evil.com"));
    }

    #[test]
    fn matching_ignores_case_and_trailing_dot() {
        assert!(matches("PyPI.org", "pypi.org."));
        assert!(matches("*.example.com", "WWW.Example.Com"));
    }

    fn table_with(mode: NetworkMode, domains: &[&str]) -> (PolicyTable, Ipv4Addr) {
        let table = PolicyTable::default();
        let ip = Ipv4Addr::new(10, 99, 0, 6);
        table.replace(HashMap::from([(
            ip,
            SandboxPolicy {
                sandbox_id: "sbx".into(),
                mode,
                allow_domains: domains.iter().map(|d| d.to_string()).collect(),
                ..Default::default()
            },
        )]));
        (table, ip)
    }

    /// A resolver that answers anything is egress: a sandbox with no network
    /// can still spell a secret out in a name and have a public resolver
    /// receive it.
    #[test]
    fn a_sandbox_without_egress_may_not_resolve_anything() {
        let (table, ip) = table_with(NetworkMode::None, &["pypi.org"]);
        assert!(!table.may_resolve(ip, "pypi.org").1.allowed());
        assert!(!table.may_resolve(ip, "secret.exfil.example").1.allowed());
    }

    #[test]
    fn allowlist_mode_resolves_only_allowlisted_names() {
        let (table, ip) = table_with(NetworkMode::Allowlist, &["pypi.org", "*.pythonhosted.org"]);
        assert!(table.may_resolve(ip, "pypi.org").1.allowed());
        assert!(table.may_resolve(ip, "files.pythonhosted.org").1.allowed());
        assert!(!table.may_resolve(ip, "evil.example").1.allowed());
        // Exfiltration by subdomain of an allowed apex is not an allowed name.
        assert!(!table.may_resolve(ip, "leak.pypi.org").1.allowed());
        assert!(!table.may_resolve(ip, "").1.allowed());
    }

    #[test]
    fn open_mode_resolves_freely_and_an_unknown_source_does_not() {
        let (table, ip) = table_with(NetworkMode::Open, &[]);
        assert!(table.may_resolve(ip, "anything.example").1.allowed());
        assert!(
            !table
                .may_resolve(Ipv4Addr::new(10, 99, 0, 7), "anything.example")
                .1
                .allowed()
        );
    }

    /// A denial is about where the connection actually goes, so it is checked
    /// against the address: an allowlisted name resolving into a denied range
    /// is the case it exists for.
    #[test]
    fn a_denied_range_covers_every_address_in_it() {
        let policy = SandboxPolicy {
            deny_cidrs: vec!["10.0.0.0/8".into(), "169.254.169.254".into()],
            ..Default::default()
        };
        assert!(policy.denies(Ipv4Addr::new(10, 1, 2, 3)));
        assert!(policy.denies(Ipv4Addr::new(169, 254, 169, 254)));
        assert!(!policy.denies(Ipv4Addr::new(169, 254, 169, 253)));
        assert!(!policy.denies(Ipv4Addr::new(11, 0, 0, 1)));

        let everything = SandboxPolicy {
            deny_cidrs: vec!["0.0.0.0/0".into()],
            ..Default::default()
        };
        assert!(everything.denies(Ipv4Addr::new(93, 184, 216, 34)));
    }

    /// The daemon validates these at the door, so a malformed entry means the
    /// policy in force is not the one that was written; the broad reading is
    /// the safe one.
    #[test]
    fn a_malformed_denial_denies_everything() {
        let policy = SandboxPolicy {
            deny_cidrs: vec!["10.0.0.0/33".into()],
            ..Default::default()
        };
        assert!(policy.denies(Ipv4Addr::new(93, 184, 216, 34)));
    }

    fn set_headers(domain: &str, matcher: Option<RequestMatch>, name: &str) -> Rule {
        Rule {
            domain: domain.into(),
            matcher,
            action: Action::SetHeaders(vec![(name.to_string(), "v".to_string())]),
        }
    }

    fn policy_with(rules: Vec<Rule>) -> SandboxPolicy {
        SandboxPolicy {
            rules: Arc::new(rules),
            ..Default::default()
        }
    }

    fn get(path: &str, query: &str) -> Request<'static> {
        // Leaked so the borrows outlive the call in a test; nothing here runs
        // long enough for it to matter.
        Request {
            method: "GET",
            path: Box::leak(path.to_string().into_boxed_str()),
            query: Box::leak(query.to_string().into_boxed_str()),
            headers: &[],
        }
    }

    /// The rule the relay would pick, as [`crate::select_rule`] picks it.
    fn selected<'a>(policy: &'a SandboxPolicy, host: &str, request: &Request<'_>) -> &'a str {
        match crate::select_rule(&policy.rules, host, request) {
            Some(Action::SetHeaders(headers)) => headers[0].0.as_str(),
            other => panic!("expected a set-headers rule, got {other:?}"),
        }
    }

    #[test]
    fn rules_apply_only_to_matching_domains() {
        let policy = policy_with(vec![
            set_headers("api.example.com", None, "Authorization"),
            set_headers("*.other.example", None, "X-Key"),
        ]);
        let request = get("/v1", "");
        assert_eq!(
            selected(&policy, "api.example.com", &request),
            "Authorization"
        );
        assert_eq!(selected(&policy, "a.other.example", &request), "X-Key");
        assert!(crate::select_rule(&policy.rules, "other.example", &request).is_none());
        assert!(crate::select_rule(&policy.rules, "evil.example", &request).is_none());
    }

    #[test]
    fn each_comparator_compares_what_it_says() {
        let exact = Match::compile(MatchOp::Exact, "/v1/users").unwrap();
        assert!(exact.matches("/v1/users"));
        assert!(!exact.matches("/v1/users/1"));

        let prefix = Match::compile(MatchOp::StartsWith, "/v1/").unwrap();
        assert!(prefix.matches("/v1/users"));
        assert!(!prefix.matches("/v2/users"));

        let pattern = Match::compile(MatchOp::Regex, r"^/v\d+/users$").unwrap();
        assert!(pattern.matches("/v1/users"));
        assert!(pattern.matches("/v22/users"));
        assert!(!pattern.matches("/v1/users/1"));
    }

    /// Vercel's rules, and the ones people get wrong in both directions: a path
    /// or a header *value* differing in case is a different string, a header
    /// *name* is not.
    #[test]
    fn case_sensitivity_runs_both_ways() {
        let matcher = RequestMatch {
            path: Some(Match::compile(MatchOp::Exact, "/V1/Users").unwrap()),
            headers: vec![(
                "X-Tenant".into(),
                Match::compile(MatchOp::Exact, "Acme").unwrap(),
            )],
            ..Default::default()
        };
        // The header name is matched however it was spelled on the wire.
        let headers = [("x-TENANT".to_string(), "Acme".to_string())];
        let hit = Request {
            method: "GET",
            path: "/V1/Users",
            query: "",
            headers: &headers,
        };
        assert!(matcher.matches(&hit));

        let wrong_path = Request {
            path: "/v1/users",
            ..hit
        };
        assert!(!matcher.matches(&wrong_path));

        let wrong_value = [("X-Tenant".to_string(), "acme".to_string())];
        let wrong_value = Request {
            headers: &wrong_value,
            ..hit
        };
        assert!(!matcher.matches(&wrong_value));
    }

    #[test]
    fn a_method_list_matches_any_of_its_entries_case_sensitively() {
        let matcher = RequestMatch {
            methods: vec!["GET".into(), "HEAD".into()],
            ..Default::default()
        };
        let base = get("/", "");
        assert!(matcher.matches(&Request {
            method: "GET",
            ..base
        }));
        assert!(matcher.matches(&Request {
            method: "HEAD",
            ..base
        }));
        assert!(!matcher.matches(&Request {
            method: "POST",
            ..base
        }));
        assert!(!matcher.matches(&Request {
            method: "get",
            ..base
        }));
    }

    /// Query and header entries are ANDed, and a repeated key is satisfied by
    /// any one of its values, the only reading that does not depend on which
    /// occurrence a server happens to take.
    #[test]
    fn query_entries_are_anded_and_a_repeated_key_matches_on_any_value() {
        let matcher = RequestMatch {
            query: vec![
                ("kind".into(), Match::compile(MatchOp::Exact, "b").unwrap()),
                (
                    "page".into(),
                    Match::compile(MatchOp::StartsWith, "2").unwrap(),
                ),
            ],
            ..Default::default()
        };
        assert!(matcher.matches(&get("/", "kind=a&kind=b&page=20")));
        assert!(!matcher.matches(&get("/", "kind=a&page=20")));
        // Missing entirely is not a match either.
        assert!(!matcher.matches(&get("/", "kind=b")));
    }

    #[test]
    fn a_query_value_is_compared_percent_decoded() {
        let matcher = RequestMatch {
            query: vec![(
                "file".into(),
                Match::compile(MatchOp::Exact, "a b&c").unwrap(),
            )],
            ..Default::default()
        };
        assert!(matcher.matches(&get("/", "file=a%20b%26c")));
        // Splitting before decoding is what keeps an encoded separator inside
        // the value instead of ending it.
        assert!(!matcher.matches(&get("/", "file=a%20b&c=")));
    }

    #[test]
    fn the_first_matching_rule_wins_and_a_matcherless_rule_shadows_the_rest() {
        let narrow = RequestMatch {
            path: Some(Match::compile(MatchOp::StartsWith, "/v1/").unwrap()),
            ..Default::default()
        };
        let policy = policy_with(vec![
            set_headers("api.example.com", Some(narrow), "X-Narrow"),
            set_headers("api.example.com", None, "X-Wide"),
            set_headers("api.example.com", None, "X-Never"),
        ]);
        assert_eq!(
            selected(&policy, "api.example.com", &get("/v1/x", "")),
            "X-Narrow"
        );
        assert_eq!(
            selected(&policy, "api.example.com", &get("/v2/x", "")),
            "X-Wide"
        );
    }

    /// The property the whole feature turns on: selecting is not blocking.
    #[test]
    fn a_request_matching_nothing_has_no_rule_at_all() {
        let matcher = RequestMatch {
            path: Some(Match::compile(MatchOp::StartsWith, "/v1/").unwrap()),
            methods: vec!["POST".into()],
            ..Default::default()
        };
        let policy = policy_with(vec![set_headers(
            "api.example.com",
            Some(matcher),
            "Authorization",
        )]);
        assert!(crate::select_rule(&policy.rules, "api.example.com", &get("/v2/x", "")).is_none());
    }

    #[test]
    fn a_pattern_that_cannot_compile_is_refused() {
        assert!(Match::compile(MatchOp::Regex, "(unclosed").is_err());
        assert!(Match::compile(MatchOp::Regex, "a{2,1}").is_err());
        assert!(Match::compile(MatchOp::Exact, "").is_err());
        assert!(Match::compile(MatchOp::Exact, &"x".repeat(MAX_PATTERN + 1)).is_err());
        assert!(Match::compile(MatchOp::Exact, &"x".repeat(MAX_PATTERN)).is_ok());
    }

    #[test]
    fn a_forward_url_is_an_origin_and_a_path() {
        let target = ForwardTarget::parse("http://gate.internal:8080/inspect/").unwrap();
        assert_eq!(target.scheme, ForwardScheme::Http);
        assert_eq!(target.host, "gate.internal");
        assert_eq!(target.port, 8080);
        assert_eq!(target.prefix, "/inspect");

        let bare = ForwardTarget::parse("http://gate.internal").unwrap();
        assert_eq!(bare.port, 80);
        assert_eq!(bare.prefix, "");

        for bad in [
            "gate.internal",
            "http://gate.internal/x?a=1",
            "http://gate.internal/x#frag",
            "http://user:pw@gate.internal/",
            "http://gate.internal:0/",
            "http://gate.internal:notaport/",
            "http:// gate.internal/",
            "http://",
            "https://",
            "https://gate.example.com/x?a=1",
            "https://gate.example.com/x#frag",
            "https:/gate.example.com/",
            "ftp://gate.example.com/",
        ] {
            assert!(
                ForwardTarget::parse(bad).is_err(),
                "{bad:?} should be refused"
            );
        }
    }

    /// `https` is accepted and carries its scheme through to the dial, which is
    /// what makes the secret's protection a property of the leg rather than of
    /// where the endpoint happens to sit.
    #[test]
    fn an_https_forward_url_keeps_its_scheme_and_its_own_default_port() {
        let target = ForwardTarget::parse("https://gate.example.com/inspect/").unwrap();
        assert_eq!(target.scheme, ForwardScheme::Https);
        assert_eq!(target.host, "gate.example.com");
        assert_eq!(target.port, 443);
        assert_eq!(target.prefix, "/inspect");

        let explicit = ForwardTarget::parse("https://gate.example.com:8443").unwrap();
        assert_eq!(explicit.scheme, ForwardScheme::Https);
        assert_eq!(explicit.port, 8443);
        assert_eq!(explicit.prefix, "");
    }

    /// A diverted request never reaches the origin, so its session needs the
    /// relay that can answer without one.
    #[test]
    fn only_forwarding_and_refusing_rules_divert() {
        let forwarding = Rule {
            domain: "api.example.com".into(),
            matcher: None,
            action: Action::Forward(Forward {
                target: ForwardTarget::parse("http://gate.internal/").unwrap(),
                url: "http://gate.internal/".into(),
                secret: "s".into(),
            }),
        };
        assert!(forwarding.diverts());

        let refusing = Rule {
            domain: "api.example.com".into(),
            matcher: None,
            action: Action::Refuse("unreadable".into()),
        };
        assert!(refusing.diverts());

        assert!(!set_headers("api.example.com", None, "X-K").diverts());
    }

    #[test]
    fn unknown_source_is_denied() {
        let table = PolicyTable::default();
        let (policy, decision) = table.decide(Ipv4Addr::new(10, 99, 0, 6), Some("pypi.org"));
        assert!(policy.is_none());
        assert_eq!(decision, Decision::Deny("unknown source sandbox"));
    }

    #[test]
    fn unidentifiable_destination_is_denied_even_with_a_permissive_policy() {
        let table = PolicyTable::default();
        let ip = Ipv4Addr::new(10, 99, 0, 6);
        table.replace(HashMap::from([(
            ip,
            SandboxPolicy {
                sandbox_id: "sbx".into(),
                mode: NetworkMode::Allowlist,
                allow_domains: vec!["*.example.com".into()],
                ..Default::default()
            },
        )]));
        let (_, decision) = table.decide(ip, None);
        assert_eq!(
            decision,
            Decision::Deny("destination host not identifiable")
        );
    }

    #[test]
    fn allowed_host_passes() {
        let table = PolicyTable::default();
        let ip = Ipv4Addr::new(10, 99, 0, 6);
        table.replace(HashMap::from([(
            ip,
            SandboxPolicy {
                sandbox_id: "sbx".into(),
                mode: NetworkMode::Allowlist,
                allow_domains: vec!["pypi.org".into(), "*.pythonhosted.org".into()],
                ..Default::default()
            },
        )]));
        assert!(table.decide(ip, Some("pypi.org")).1.allowed());
        assert!(table.decide(ip, Some("files.pythonhosted.org")).1.allowed());
        assert!(!table.decide(ip, Some("example.com")).1.allowed());
    }
}
