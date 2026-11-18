use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-env-changed=C2V2_PROFILE_PATH");
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let dest = out_dir.join("profile.json");
    let content = match env::var("C2V2_PROFILE_PATH") {
        Ok(p) if !p.is_empty() => {
            let path = if PathBuf::from(&p).is_absolute() {
                PathBuf::from(&p)
            } else {
                // Resolve relative to the crate root for direct cargo invocations.
                let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap_or_default());
                manifest.join(&p)
            };
            fs::read_to_string(&path).unwrap_or_else(|e| {
                panic!("C2V2_PROFILE_PATH={} unreadable: {}", path.display(), e);
            })
        }
        _ => "{}".to_string(),
    };
    // Validate embedded profile so a broken builder invocation fails the build.
    let _: serde_json::Value = serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("embedded profile is not valid JSON: {}", e));
    fs::write(&dest, content).expect("write profile.json");
    println!("cargo:rustc-env=C2V2_EMBEDDED_PROFILE=1");
}
