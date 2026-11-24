use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct Version {
    pub product: String,
    pub label: String,
    pub version: String,
    pub cycle: String,
    pub eol: String,
    pub latest: String,
    pub status: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct Advisory {
    pub id: String,
    pub title: String,
    pub cve: String,
    pub severity: String,
    pub link: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct Pkg {
    pub name: String,
    pub version: String,
    pub advisories: Vec<Advisory>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct NpmPkg {
    pub name: String,
    pub severity: String,
    pub direct: bool,
    pub fix: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct Npm {
    pub counts: Vec<(String, u64)>,
    pub packages: Vec<NpmPkg>,
}

fn s(v: &Value) -> String {
    v.as_str().map(String::from).unwrap_or_default()
}

// "v6.4.12", "^8.2 || ^8.3", "mariadb:10.6" → "6.4", "8.2", "10.6".
pub fn cycle(text: &str, parts: usize) -> Option<String> {
    let start = text.find(|c: char| c.is_ascii_digit())?;
    let v: String = text[start..].chars().take_while(|c| c.is_ascii_digit() || *c == '.').collect();
    let nums: Vec<&str> = v.split('.').filter(|p| !p.is_empty()).take(parts).collect();
    (!nums.is_empty()).then(|| nums.join("."))
}

fn after(text: &str, key: &str, parts: usize) -> Option<String> {
    text.lines().find_map(|l| {
        let at = l.find(key)?;
        let rest = &l[at + key.len()..];
        rest.starts_with(|c: char| c.is_ascii_digit()).then(|| cycle(rest, parts)).flatten()
    })
}

fn locked(lock: &Value, names: &[&str]) -> Option<String> {
    lock["packages"].as_array()?.iter().find(|p| names.contains(&p["name"].as_str().unwrap_or_default())).map(|p| s(&p["version"]))
}

pub struct Files<'a> {
    pub lando: &'a str,
    pub composer: &'a str,
    pub lock: &'a str,
    pub nvmrc: &'a str,
    pub package: &'a str,
}

// The pieces of the stack endoflife.date tracks, and the version this project runs.
pub fn versions(f: &Files) -> Vec<(&'static str, &'static str, String)> {
    let composer: Value = serde_json::from_str(f.composer).unwrap_or_default();
    let lock: Value = serde_json::from_str(f.lock).unwrap_or_default();
    let package: Value = serde_json::from_str(f.package).unwrap_or_default();
    let mut out = Vec::new();
    let php = f
        .lando
        .lines()
        .find_map(|l| l.trim().strip_prefix("php:").and_then(|v| cycle(v.trim().trim_matches(['\'', '"']), 2).filter(|_| v.trim().starts_with(|c: char| c.is_ascii_digit() || c == '\'' || c == '"'))))
        .or_else(|| composer["config"]["platform"]["php"].as_str().and_then(|v| cycle(v, 2)))
        .or_else(|| composer["require"]["php"].as_str().and_then(|v| cycle(v, 2)));
    if let Some(v) = php {
        out.push(("php", "PHP", v));
    }
    for (product, label, names) in [
        ("symfony", "Symfony", &["symfony/http-kernel", "symfony/symfony"][..]),
        ("drupal", "Drupal", &["drupal/core", "drupal/core-recommended"][..]),
        ("sylius", "Sylius", &["sylius/sylius", "sylius/core-bundle"][..]),
    ] {
        if let Some(v) = locked(&lock, names) {
            out.push((product, label, v));
        }
    }
    let node = cycle(f.nvmrc.trim(), 1)
        .filter(|_| !f.nvmrc.trim().is_empty())
        .or_else(|| after(f.lando, "node:", 1))
        .or_else(|| package["engines"]["node"].as_str().and_then(|v| cycle(v, 1)));
    if let Some(v) = node {
        out.push(("nodejs", "Node.js", v));
    }
    if let Some(v) = after(f.lando, "mariadb:", 2) {
        out.push(("mariadb", "MariaDB", v));
    } else if let Some(v) = after(f.lando, "mysql:", 2) {
        out.push(("mysql", "MySQL", v));
    }
    out
}

// `today` and dates as YYYY-MM-DD; "soon" is within 180 days.
pub fn eol(cycles: &Value, product: &str, label: &str, version: &str, today: &str, soon: &str) -> Version {
    let parts = if product == "nodejs" { 1 } else { 2 };
    let wanted = cycle(version, parts).unwrap_or_default();
    let mut v = Version { product: product.into(), label: label.into(), version: version.trim_start_matches('v').into(), cycle: wanted.clone(), status: "unknown".into(), ..Default::default() };
    let Some(c) = cycles.as_array().and_then(|a| a.iter().find(|c| c["cycle"].as_str().map(|x| x == wanted).unwrap_or(false) || c["cycle"].as_u64().map(|n| n.to_string()) == Some(wanted.clone()))) else {
        return v;
    };
    v.latest = s(&c["latest"]);
    match &c["eol"] {
        Value::Bool(true) => v.status = "eol".into(),
        Value::Bool(false) => v.status = "ok".into(),
        Value::String(d) => {
            v.eol = d.clone();
            v.status = if d.as_str() <= today { "eol" } else if d.as_str() <= soon { "soon" } else { "ok" }.into();
        }
        _ => {}
    }
    v
}

pub fn composer_audit(out: &str, lock: &str) -> Option<(Vec<Pkg>, Vec<(String, String)>)> {
    let at = out.find('{')?;
    let v: Value = serde_json::from_str(&out[at..]).ok()?;
    let lock: Value = serde_json::from_str(lock).unwrap_or_default();
    let mut pkgs: Vec<Pkg> = v["advisories"]
        .as_object()
        .map(|m| {
            m.iter()
                .map(|(name, list)| Pkg {
                    name: name.clone(),
                    version: locked(&lock, &[name.as_str()]).unwrap_or_default(),
                    advisories: list
                        .as_array()
                        .into_iter()
                        .flatten()
                        .map(|a| Advisory { id: s(&a["advisoryId"]), title: s(&a["title"]), cve: s(&a["cve"]), severity: s(&a["severity"]), link: s(&a["link"]) })
                        .collect(),
                })
                .collect()
        })
        .unwrap_or_default();
    pkgs.sort_by_key(|p| (std::cmp::Reverse(p.advisories.iter().map(|a| rank(&a.severity)).max().unwrap_or(0)), p.name.clone()));
    let abandoned = v["abandoned"].as_object().map(|m| m.iter().map(|(k, r)| (k.clone(), s(r))).collect()).unwrap_or_default();
    Some((pkgs, abandoned))
}

pub fn rank(severity: &str) -> u8 {
    match severity {
        "critical" => 4,
        "high" => 3,
        "medium" | "moderate" => 2,
        "low" => 1,
        _ => 0,
    }
}

pub fn npm_audit(out: &str) -> Option<Npm> {
    let at = out.find('{')?;
    let v: Value = serde_json::from_str(&out[at..]).ok()?;
    let meta = v["metadata"]["vulnerabilities"].as_object()?;
    let counts = ["critical", "high", "moderate", "low"].iter().map(|k| (k.to_string(), meta.get(*k).and_then(Value::as_u64).unwrap_or(0))).collect();
    let mut packages: Vec<NpmPkg> = v["vulnerabilities"]
        .as_object()
        .map(|m| m.iter().map(|(name, p)| NpmPkg { name: name.clone(), severity: s(&p["severity"]), direct: p["isDirect"] == true, fix: p["fixAvailable"] != false }).collect())
        .unwrap_or_default();
    packages.sort_by_key(|p| (std::cmp::Reverse(rank(&p.severity)), !p.direct, p.name.clone()));
    packages.truncate(40);
    Some(Npm { counts, packages })
}

// Days since 1970-01-01 to a civil date (Howard Hinnant's algorithm).
pub fn date(days: i64) -> String {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn versions_of_a_lando_symfony_project() {
        let lando = "name: km\nrecipe: symfony\nconfig:\n    php: 8.4\n    database: mariadb:10.6\nservices:\n    node:\n        type: node:20\n    php: .lando/php.ini\n";
        let lock = r#"{"packages":[{"name":"symfony/http-kernel","version":"v6.4.12"},{"name":"sylius/sylius","version":"v1.14.20"}]}"#;
        let v = versions(&Files { lando, composer: r#"{"require":{"php":"^8.2"}}"#, lock, nvmrc: "", package: "{}" });
        let got: Vec<(&str, String)> = v.iter().map(|(p, _, v)| (*p, v.clone())).collect();
        assert_eq!(got, [("php", "8.4".into()), ("symfony", "v6.4.12".into()), ("sylius", "v1.14.20".into()), ("nodejs", "20".into()), ("mariadb", "10.6".into())]);
    }

    #[test]
    fn versions_without_lando() {
        let v = versions(&Files { lando: "", composer: r#"{"require":{"php":">=8.1"}}"#, lock: r#"{"packages":[{"name":"drupal/core","version":"10.2.3"}]}"#, nvmrc: "v22.11.0\n", package: "{}" });
        let got: Vec<(&str, String)> = v.iter().map(|(p, _, v)| (*p, v.clone())).collect();
        assert_eq!(got, [("php", "8.1".into()), ("drupal", "10.2.3".into()), ("nodejs", "22".into())]);
    }

    #[test]
    fn end_of_life() {
        let php = json!([{"cycle":"8.4","eol":"2028-12-31","latest":"8.4.15"},{"cycle":"8.1","eol":"2025-12-31","latest":"8.1.33"}]);
        assert_eq!(eol(&php, "php", "PHP", "8.4", "2026-11-24", "2027-05-23").status, "ok");
        let old = eol(&php, "php", "PHP", "8.1", "2026-11-24", "2027-05-23");
        assert_eq!((old.status.as_str(), old.eol.as_str(), old.latest.as_str()), ("eol", "2025-12-31", "8.1.33"));
        let sf = json!([{"cycle":"6.4","eol":"2027-03-31","latest":"6.4.30"}]);
        assert_eq!(eol(&sf, "symfony", "Symfony", "v6.4.12", "2026-11-24", "2027-05-23").status, "soon");
        let node = json!([{"cycle":"20","eol":"2026-04-30","latest":"20.19.6"}]);
        assert_eq!(eol(&node, "nodejs", "Node.js", "20", "2026-11-24", "2027-05-23").status, "eol");
        assert_eq!(eol(&json!([{"cycle":"26.10","eol":false}]), "mysql", "MySQL", "26.10", "2026-11-24", "2027-05-23").status, "ok");
        assert_eq!(eol(&php, "php", "PHP", "5.6", "2026-11-24", "2027-05-23").status, "unknown");
    }

    #[test]
    fn composer_audit_json() {
        let out = r#"{"advisories":{"twig/twig":[{"advisoryId":"PKSA-1","title":"XSS","cve":"CVE-1","severity":"high","link":"https://x"}],"a/b":[{"advisoryId":"PKSA-2","title":"t","cve":null,"severity":null,"link":"https://y"}]},"abandoned":{"doctrine/annotations":null,"x/y":"z/w"}}"#;
        let (pkgs, abandoned) = composer_audit(out, r#"{"packages":[{"name":"twig/twig","version":"v3.8.0"}]}"#).unwrap();
        assert_eq!((pkgs[0].name.as_str(), pkgs[0].version.as_str(), pkgs[0].advisories[0].severity.as_str()), ("twig/twig", "v3.8.0", "high"));
        assert_eq!(pkgs[1].advisories[0].cve, "");
        assert_eq!(abandoned, [("doctrine/annotations".to_string(), String::new()), ("x/y".to_string(), "z/w".to_string())]);
        assert!(composer_audit("Could not open composer.lock", "").is_none());
    }

    #[test]
    fn npm_audit_json() {
        let out = r#"{"vulnerabilities":{"a":{"severity":"low","isDirect":true,"fixAvailable":true},"b":{"severity":"critical","isDirect":false,"fixAvailable":false}},"metadata":{"vulnerabilities":{"info":0,"low":1,"moderate":0,"high":0,"critical":1,"total":2}}}"#;
        let n = npm_audit(out).unwrap();
        assert_eq!(n.counts[0], ("critical".to_string(), 1));
        assert_eq!((n.packages[0].name.as_str(), n.packages[0].fix), ("b", false));
    }

    #[test]
    fn civil_dates() {
        assert_eq!(date(0), "1970-01-01");
        assert_eq!(date(20_781), "2026-11-24");
        assert_eq!(date(11_016), "2000-02-29");
    }
}
