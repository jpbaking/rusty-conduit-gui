fn main() {
    tauri_build::build();

    // `tauri-build` compiles the Windows resource (including the Common Controls v6 manifest)
    // into `OUT_DIR` and links it into binaries only (`cargo:rustc-link-arg-bins`). On Windows,
    // `tao` and `tray-icon` import Common Controls v6 symbols from `comctl32.dll`, so test
    // binaries crash at startup with `0xc0000139` (`STATUS_ENTRYPOINT_NOT_FOUND`) unless they
    // also link that compiled resource.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
        for name in ["resource.lib", "libresource.a"] {
            let res = out_dir.join(name);
            if res.exists() {
                println!("cargo:rustc-link-arg-tests={}", res.display());
                break;
            }
        }
    }
}
