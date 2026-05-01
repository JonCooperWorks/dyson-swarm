// Build script — compiles the swarm frontend (Vite) and generates the
// Rust asset table that embeds the bundle into the swarm binary.
//
// Mirrors Dyson's build.rs design:
//   * Outer gate: `cargo:rerun-if-changed` for every watched input — cargo
//     only re-runs build.rs when one of them changes.
//   * Inner gate: even when build.rs does run, it compares the newest
//     input mtime against the oldest dist mtime and skips `npm run build`
//     when the bundle is already fresher than every source file.
//   * node_modules has its own stamp keyed on a hash of package-lock.json.
//     If the lockfile changed (or the stamp is missing), we run `npm ci`
//     before building.
//   * If Node/npm are missing we panic with a pointed error rather than a
//     cryptic ENOENT.  The frontend is a required part of the binary —
//     there is no feature flag to skip it.
//   * The generated `web_assets.rs` is an array of
//     `(url_path, include_bytes!(absolute_path), content_type)`; assets.rs
//     pulls it in via `include!`.

use std::collections::hash_map::DefaultHasher;
use std::fmt::Write as _;
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;

const WEB_REL: &str = "src/http/web";

fn main() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let web = manifest_dir.join(WEB_REL);
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());

    watch_inputs(&web);

    assert!(
        web.join("index.html").exists(),
        "frontend source missing at {} — did the checkout preserve the web/ directory?",
        web.display(),
    );

    let dist = web.join("dist");
    if needs_rebuild(&web, &dist) {
        ensure_npm_available();
        ensure_node_modules(&web);
        run_npm_build(&web);
    } else {
        println!("cargo:warning=swarm: frontend dist/ is up to date, skipping vite build");
    }

    generate_asset_table(&dist, &out_dir.join("web_assets.rs"));
}

fn watch_inputs(web: &Path) {
    println!("cargo:rerun-if-changed=build.rs");
    for rel in [
        "index.html",
        "package.json",
        "package-lock.json",
        "vite.config.js",
        "src",
    ] {
        println!("cargo:rerun-if-changed={}", web.join(rel).display());
    }
    for entry in walk(&web.join("src")) {
        println!("cargo:rerun-if-changed={}", entry.display());
    }
}

fn needs_rebuild(web: &Path, dist: &Path) -> bool {
    let index = dist.join("index.html");
    if !index.exists() {
        return true;
    }
    let newest_input = inputs_newest_mtime(web).unwrap_or(SystemTime::UNIX_EPOCH);
    let oldest_output = dist_oldest_mtime(dist).unwrap_or(SystemTime::UNIX_EPOCH);
    newest_input > oldest_output
}

fn inputs_newest_mtime(web: &Path) -> Option<SystemTime> {
    let mut newest = None;
    for rel in [
        "index.html",
        "package.json",
        "package-lock.json",
        "vite.config.js",
    ] {
        if let Ok(m) = fs::metadata(web.join(rel)).and_then(|m| m.modified()) {
            newest = Some(newest.map_or(m, |n: SystemTime| n.max(m)));
        }
    }
    for entry in walk(&web.join("src")) {
        if let Ok(m) = fs::metadata(&entry).and_then(|m| m.modified()) {
            newest = Some(newest.map_or(m, |n: SystemTime| n.max(m)));
        }
    }
    newest
}

fn dist_oldest_mtime(dist: &Path) -> Option<SystemTime> {
    let mut oldest = None;
    for entry in walk(dist) {
        if let Ok(m) = fs::metadata(&entry).and_then(|m| m.modified()) {
            oldest = Some(oldest.map_or(m, |o: SystemTime| o.min(m)));
        }
    }
    oldest
}

fn walk(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if !root.exists() {
        return out;
    }
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for e in entries.flatten() {
            let path = e.path();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name.starts_with('.') || name == "node_modules" {
                continue;
            }
            let Ok(ft) = e.file_type() else { continue };
            if ft.is_dir() {
                stack.push(path);
            } else if ft.is_file() {
                out.push(path);
            }
        }
    }
    out
}

fn ensure_npm_available() {
    let ok = Command::new("npm")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success());
    assert!(
        ok,
        "npm is required to build the swarm frontend.  Install Node.js 20+ \
         (https://nodejs.org) and retry `cargo build`.  The frontend lives \
         at {WEB_REL}/ and is bundled into the binary."
    );
}

fn ensure_node_modules(web: &Path) {
    let stamp = web.join("node_modules").join(".swarm-lock-hash");
    let lock = web.join("package-lock.json");
    let hash = fs::read(&lock).map_or(0, hash_bytes);

    let existing = fs::read_to_string(&stamp)
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok());
    if existing == Some(hash) && web.join("node_modules").exists() {
        return;
    }

    println!("cargo:warning=swarm: installing frontend dependencies (npm install)");
    // `npm install` (not `npm ci`) so first-time builds without a
    // package-lock.json still work.  `npm ci` is stricter but requires a
    // pre-existing lockfile, which we don't ship.
    let cmd = if web.join("package-lock.json").exists() {
        "ci"
    } else {
        "install"
    };
    let status = Command::new("npm")
        .arg(cmd)
        .arg("--no-audit")
        .arg("--no-fund")
        .current_dir(web)
        .status()
        .expect("failed to spawn npm install");
    assert!(status.success(), "npm {cmd} failed in {}", web.display());
    let _ = fs::write(&stamp, hash.to_string());
}

fn run_npm_build(web: &Path) {
    println!("cargo:warning=swarm: building frontend bundle (npm run build:nocheck)");
    // `build:nocheck` skips vitest — we run that separately in CI.  The
    // build.rs path is for `cargo build`, where a vitest failure would be
    // confusing if the frontend isn't what changed.
    let status = Command::new("npm")
        .arg("run")
        .arg("build:nocheck")
        .current_dir(web)
        .status()
        .expect("failed to spawn npm run build:nocheck");
    assert!(
        status.success(),
        "npm run build:nocheck failed in {} — see stderr above.",
        web.display(),
    );
}

fn hash_bytes(bytes: Vec<u8>) -> u64 {
    let mut h = DefaultHasher::new();
    bytes.hash(&mut h);
    h.finish()
}

fn generate_asset_table(dist: &Path, out: &Path) {
    let mut entries = Vec::new();
    for path in walk(dist) {
        let rel = path.strip_prefix(dist).expect("path under dist");
        if rel.extension().and_then(|e| e.to_str()) == Some("map") {
            continue;
        }
        let url = rel.to_string_lossy().replace('\\', "/");
        let ct = content_type(&url);
        entries.push((url, path.to_string_lossy().into_owned(), ct));
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    let mut src = String::new();
    src.push_str("// Auto-generated by build.rs — do not edit.\n");
    src.push_str("// Walks src/http/web/dist/ after `npm run build` and embeds each\n");
    src.push_str("// file via include_bytes!.  Binary size follows dist/ exactly.\n\n");
    src.push_str("pub const ASSETS: &[(&str, &[u8], &str)] = &[\n");
    for (url, abs, ct) in &entries {
        writeln!(src, "    ({url:?}, include_bytes!({abs:?}), {ct:?}),").unwrap();
    }
    src.push_str("];\n");

    fs::write(out, src).expect("write web_assets.rs");
}

fn content_type(path: &str) -> &'static str {
    let ext = path.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    match ext.as_str() {
        "html" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "application/javascript; charset=utf-8",
        "json" => "application/json; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        _ => "application/octet-stream",
    }
}
