mod stack;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use squadron_extension_api::{Agent, Extension, Request, host, squadron_extension};
use stack::{Npm, Pkg, Version};
use std::time::{SystemTime, UNIX_EPOCH};

struct Stack;

fn en() -> bool {
    host::state_get("lang").as_deref() == Some("en")
}

macro_rules! t {
    ($fr:literal, $en:literal $(, $a:expr)*) => {
        if en() { format!($en $(, $a)*) } else { format!($fr $(, $a)*) }
    };
}

#[derive(Serialize, Deserialize, Clone, Default)]
struct Report {
    at: u64,
    versions: Vec<Version>,
    composer: Option<Vec<Pkg>>,
    abandoned: Vec<(String, String)>,
    npm: Option<Npm>,
    notes: Vec<String>,
}

const DAY: u64 = 86_400_000;

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64)
}

fn get<T: serde::de::DeserializeOwned + Default>(key: &str) -> T {
    host::state_get(key).and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
}

fn put<T: Serialize>(key: &str, value: &T) {
    host::state_set(key, serde_json::to_string(value).ok().as_deref());
}

fn run(program: &str, args: &[&str], dir: Option<&str>) -> Result<squadron_extension_api::Output, String> {
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    host::exec(program, &args, dir)
}

fn git(dir: &str, args: &[&str]) -> String {
    run("git", args, Some(dir)).ok().filter(|o| o.code == 0).map(|o| o.stdout).unwrap_or_default()
}

fn first_lines(text: &str) -> String {
    text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.contains("Pulling") && !l.contains("Download") && !l.contains("Digest:") && !l.contains("Status:")).take(4).collect::<Vec<_>>().join(" ")
}

fn docker(root: &str, image: &str, command: &[&str]) -> Result<String, String> {
    let id = |flag: &str| run("id", &[flag], None).map(|o| o.stdout.trim().to_string()).unwrap_or_default();
    let user = format!("{}:{}", id("-u"), id("-g"));
    let mount = format!("{root}:/app:ro");
    let mut args = vec!["run", "--rm", "-u", &user, "-e", "HOME=/tmp", "-e", "COMPOSER_HOME=/tmp/composer", "-v", &mount, "-w", "/app", image];
    args.extend_from_slice(command);
    let out = run("docker", &args, None)?;
    Ok(format!("{}\n{}", out.stdout, out.stderr))
}

// Versions and their end of life, then what Composer and npm know of the locked packages.
fn scan(folder: &str) -> Result<Report, String> {
    let root = git(folder, &["rev-parse", "--show-toplevel"]).trim().to_string();
    if root.is_empty() {
        return Err(t!("Ce dossier n’est pas un dépôt git.", "This folder is not a git repository."));
    }
    let show = |file: &str| git(&root, &["show", &format!("HEAD:{file}")]);
    let (lando, composer, lock, nvmrc, package) = (show(".lando.yml"), show("composer.json"), show("composer.lock"), show(".nvmrc"), show("package.json"));
    let mut r = Report { at: now(), ..Default::default() };
    let found = stack::versions(&stack::Files { lando: &lando, composer: &composer, lock: &lock, nvmrc: &nvmrc, package: &package });
    let days = (now() / DAY) as i64;
    let (today, soon) = (stack::date(days), stack::date(days + 180));
    let requests: Vec<Request> = found.iter().map(|(p, _, _)| Request { method: "GET".into(), url: format!("https://endoflife.date/api/{p}.json"), headers: vec![], body: None }).collect();
    for ((product, label, version), answer) in found.iter().zip(host::fetch_many(&requests)) {
        let cycles: Value = answer.ok().filter(|a| a.status == 200).and_then(|a| serde_json::from_str(&a.body).ok()).unwrap_or_default();
        r.versions.push(stack::eol(&cycles, product, label, version, &today, &soon));
    }
    if !lock.is_empty() {
        match docker(&root, "composer:2", &["composer", "audit", "--locked", "--format=json", "--no-interaction"]) {
            Ok(out) => match stack::composer_audit(&out, &lock) {
                Some((pkgs, abandoned)) => {
                    r.composer = Some(pkgs);
                    r.abandoned = abandoned;
                }
                None => r.notes.push(t!("composer audit n’a pas pu tourner : {}", "composer audit could not run: {}", first_lines(&out))),
            },
            Err(e) => r.notes.push(t!("composer audit n’a pas pu tourner : {}", "composer audit could not run: {}", e)),
        }
    }
    if !show("package-lock.json").is_empty() {
        match docker(&root, "node:22", &["npm", "audit", "--json", "--package-lock-only"]) {
            Ok(out) => match stack::npm_audit(&out) {
                Some(n) => r.npm = Some(n),
                None => r.notes.push(t!("npm audit n’a pas pu tourner : {}", "npm audit could not run: {}", first_lines(&out))),
            },
            Err(e) => r.notes.push(t!("npm audit n’a pas pu tourner : {}", "npm audit could not run: {}", e)),
        }
    }
    Ok(r)
}

fn ids(r: &Report) -> Vec<String> {
    let mut out: Vec<String> = r.composer.iter().flatten().flat_map(|p| p.advisories.iter().map(|a| a.id.clone())).collect();
    out.extend(r.npm.iter().flat_map(|n| n.packages.iter().map(|p| format!("npm:{}:{}", p.name, p.severity))));
    out.extend(r.versions.iter().filter(|v| v.status == "eol").map(|v| format!("eol:{}:{}", v.product, v.cycle)));
    out
}

// Remembers each project's last report; a later scan notifies only what is new.
fn scan_and_save(folder: &str, notify: bool) -> Result<Report, String> {
    let report = scan(folder)?;
    let key = format!("scan:{folder}");
    let before: Option<Report> = host::state_get(&key).and_then(|s| serde_json::from_str(&s).ok());
    let mut folders: Vec<String> = get("folders");
    folders.retain(|f| f != folder);
    folders.push(folder.to_string());
    while folders.len() > 20 {
        host::state_set(&format!("scan:{}", folders.remove(0)), None);
    }
    put("folders", &folders);
    put(&key, &report);
    if let Some(before) = before.filter(|_| notify) {
        let old = ids(&before);
        let fresh = ids(&report).into_iter().filter(|i| !old.contains(i)).count();
        if fresh > 0 {
            let name = folder.rsplit('/').next().unwrap_or(folder);
            host::notify(&t!("Santé de la stack · {}", "Stack health · {}", name), &t!("{} nouvelle(s) alerte(s) : failles ou fin de vie.", "{} new alert(s): vulnerabilities or end of life.", fresh));
            let unread: u64 = get::<u64>("unread") + fresh as u64;
            put("unread", &unread);
            host::set_badge("stack", Some(&unread.to_string()));
        }
    }
    Ok(report)
}

fn tick() {
    let folders: Vec<String> = get("folders");
    let due = folders.iter().find(|f| get::<Report>(&format!("scan:{f}")).at + DAY < now()).cloned();
    if let Some(folder) = due {
        let _ = scan_and_save(&folder, true);
        host::set_timer(60);
    } else {
        host::set_timer(3600);
    }
}

fn fix_text(r: &Report) -> String {
    let mut parts = vec![t!(
        "Mets à jour ce qui suit pour corriger les failles connues et sortir des versions en fin de vie, en restant sur les mêmes versions majeures quand c’est possible. Vérifie ensuite que le projet fonctionne : tests, cache, build.",
        "Update what follows to fix the known vulnerabilities and leave the versions that reached their end of life, keeping the same major versions when possible. Then check that the project works: tests, cache, build."
    )];
    let pkgs = r.composer.as_ref().filter(|p| !p.is_empty());
    if let Some(pkgs) = pkgs {
        let lines: Vec<String> = pkgs
            .iter()
            .map(|p| {
                let a: Vec<String> = p.advisories.iter().map(|a| [a.title.clone(), a.cve.clone(), a.severity.clone()].into_iter().filter(|x| !x.is_empty()).collect::<Vec<_>>().join(", ")).collect();
                format!("- {} {} : {}", p.name, p.version, a.join(" ; "))
            })
            .collect();
        parts.push(format!("composer audit :\n{}", lines.join("\n")));
    }
    if let Some(n) = r.npm.as_ref().filter(|n| n.counts.iter().any(|(_, c)| *c > 0)) {
        let counts: Vec<String> = n.counts.iter().filter(|(_, c)| *c > 0).map(|(k, c)| format!("{c} {k}")).collect();
        let names: Vec<String> = n.packages.iter().filter(|p| p.direct).map(|p| format!("{} ({})", p.name, p.severity)).collect();
        parts.push(format!("npm audit : {}.{}", counts.join(", "), if names.is_empty() { String::new() } else { t!(" Dépendances directes : {}.", " Direct dependencies: {}.", names.join(", ")) }));
    }
    let old: Vec<String> = r.versions.iter().filter(|v| v.status == "eol" || v.status == "soon").map(|v| t!("{} {} (fin de vie le {})", "{} {} (end of life {})", v.label, v.version, if v.eol.is_empty() { "?".into() } else { v.eol.clone() })).collect();
    if !old.is_empty() {
        parts.push(t!("Versions en fin de vie ou bientôt : {}.", "Versions at or near their end of life: {}.", old.join(", ")));
    }
    parts.join("\n\n").replace(" :", "\u{a0}:")
}

fn post(message: Value) {
    host::panel_post("main", &message.to_string());
}

fn answer(kind: &str, agent: &Agent, m: &Value) -> Result<Value, String> {
    Ok(match kind {
        "ready" => {
            if let Some(lang) = m["lang"].as_str() {
                host::state_set("lang", Some(if lang.starts_with("fr") { "fr" } else { "en" }));
            }
            put("unread", &0u64);
            host::set_badge("stack", None);
            let report: Option<Report> = host::state_get(&format!("scan:{}", agent.project)).and_then(|s| serde_json::from_str(&s).ok());
            json!({ "type": "report", "report": report })
        }
        "scan" => json!({ "type": "report", "report": scan_and_save(&agent.project, false)? }),
        "fix" => {
            let report: Report = get(&format!("scan:{}", agent.project));
            let draft = json!({ "name": t!("Mise à jour de sécurité", "Security update"), "text": fix_text(&report), "goal": t!("composer audit et npm audit ne signalent plus de faille, et le projet fonctionne.", "composer audit and npm audit report no vulnerability, and the project works.") });
            host::open_new_agent(&agent.id, &draft.to_string());
            json!({ "type": "opened" })
        }
        _ => return Err(format!("Unknown request {kind}.")),
    })
}

impl Extension for Stack {
    fn on_event(name: String, agent: Option<Agent>, data: String) {
        match name.as_str() {
            "started" => host::set_timer(120),
            "timer" => tick(),
            "panel.message" => {
                let data: Value = serde_json::from_str(&data).unwrap_or_default();
                let m = &data["message"];
                let Some(agent) = agent else { return };
                let kind = m["type"].as_str().unwrap_or_default();
                let mut reply = answer(kind, &agent, m).unwrap_or_else(|e| json!({ "type": "error", "message": e }));
                reply["to"] = m["to"].clone();
                post(reply);
            }
            _ => {}
        }
    }

    fn call_tool(name: String, _input: String, agent: Option<Agent>) -> Result<String, String> {
        let agent = agent.ok_or("Call this tool from an agent started by Squadron.")?;
        if name != "report" {
            return Err(format!("Unknown tool {name}."));
        }
        let lang = host::state_get("lang");
        host::state_set("lang", Some("en"));
        let report = scan_and_save(&agent.project, false);
        let text = report.as_ref().map(fix_text);
        let versions = report.as_ref().map(|r| r.versions.iter().map(|v| format!("{} {}: {}{}", v.label, v.version, v.status, if v.eol.is_empty() { String::new() } else { format!(" (end of life {})", v.eol) })).collect::<Vec<_>>().join("\n"));
        host::state_set("lang", lang.as_deref());
        Ok(format!("Versions:\n{}\n\n{}", versions?, text?))
    }
}

squadron_extension!(Stack);
