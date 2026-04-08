use sha2::{Digest, Sha256};
use std::{fs, io::Read, path::Path};
use walkdir::WalkDir;

fn main() {
    let mut hasher = Sha256::new();

    // Hash all Rust source files from both op4-tui/src and op4-core/src
    // so that tampering with crypto code in op4-core changes the hash.
    for src_dir in &["src", "../op4-core/src"] {
        let dir = Path::new(src_dir);
        if !dir.exists() {
            continue;
        }
        let mut paths: Vec<_> = WalkDir::new(dir)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().is_some_and(|x| x == "rs"))
            .map(|e| e.path().to_owned())
            .collect();
        paths.sort();

        for path in &paths {
            let mut f = fs::File::open(path).expect("cannot open src file");
            let mut buf = Vec::new();
            f.read_to_end(&mut buf).unwrap();
            hasher.update(&buf);
        }
    }

    // Also hash security-relevant manifests and config files.
    for extra in &[
        "Cargo.toml",
        "Cargo.lock",
        "build.rs",
        "../deny.toml",
        "../op4-core/Cargo.toml",
        "../rust-toolchain.toml",
        "../apparmor/op4.profile",
    ] {
        if let Ok(mut f) = fs::File::open(Path::new(extra)) {
            let mut buf = Vec::new();
            f.read_to_end(&mut buf).unwrap_or(0);
            hasher.update(&buf);
        }
    }

    let hash = hasher.finalize();
    let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();

    println!("cargo:rustc-env=OP4_SOURCE_HASH={hex}");
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=../op4-core/src");
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-changed=Cargo.lock");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../deny.toml");
    println!("cargo:rerun-if-changed=../op4-core/Cargo.toml");
    println!("cargo:rerun-if-changed=../rust-toolchain.toml");
    println!("cargo:rerun-if-changed=../apparmor/op4.profile");
}
