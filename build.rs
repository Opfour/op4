use sha2::{Digest, Sha256};
use std::{fs, io::Read, path::Path};
use walkdir::WalkDir;

fn main() {
    let src_dir = Path::new("src");
    let mut hasher = Sha256::new();

    let mut paths: Vec<_> = WalkDir::new(src_dir)
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

    let hash = hasher.finalize();
    let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();

    println!("cargo:rustc-env=OP4_SOURCE_HASH={hex}");
    println!("cargo:rerun-if-changed=src");
}
