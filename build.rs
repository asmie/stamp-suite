fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    // Clap's generated parser needs more than Windows' default 1 MiB stack
    // in debug builds. Set the executable's reserve, not worker thread stacks.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let flag = if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
            "/STACK:4194304"
        } else {
            "-Wl,--stack,4194304"
        };
        println!("cargo:rustc-link-arg-bin=stamp-suite={flag}");
    }
}
