use std::path::PathBuf;

fn main() {

    // Add library linking configuration
    let target = std::env::var("TARGET").unwrap_or_default();
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    
    // Set library search paths based on target
    if target.contains("windows") {
        if target.contains("x86_64") {
            let lib_path = manifest_dir.join("lib").join("win").join("x86_64").join("lib");
            println!("cargo:rustc-link-search=native={}", lib_path.display());
        } else if target.contains("i686") {
            let lib_path = manifest_dir.join("lib").join("win").join("x86").join("lib");
            println!("cargo:rustc-link-search=native={}", lib_path.display());
        }
    } else if target.contains("linux") || target.contains("musl") {
        if target.contains("x86_64") {
            let lib_path = manifest_dir.join("lib").join("linux").join("x86_64").join("lib");
            println!("cargo:rustc-link-search=native={}", lib_path.display());
        }
        // Add other architectures as needed
    } else if target.contains("android") {
        if target.contains("aarch64") {
            let lib_path = manifest_dir.join("lib").join("android").join("arm64-v8a");
            println!("cargo:rustc-link-search=native={}", lib_path.display());
        }
    }

    // Link against required libraries
    println!("cargo:rustc-link-lib=static=lzma");
}
