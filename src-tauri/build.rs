fn main() {
    // On Windows MSVC, `tauri-build` embeds its default Common Controls v6 manifest into
    // `resource.lib` and links it into binaries only (`cargo:rustc-link-arg-bins`), which
    // leaves `cargo test --lib` binaries crashing at startup with `0xc0000139`
    // (`STATUS_ENTRYPOINT_NOT_FOUND`). Passing the exact same dependency via MSVC
    // `/MANIFEST:EMBED` + `/MANIFESTDEPENDENCY:` applies it to every linkable target (binaries,
    // lib unit tests, and integration tests) while keeping the icon and version resources from
    // `tauri-build`.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows")
        && std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc")
    {
        tauri_build::try_build(
            tauri_build::Attributes::new()
                .windows_attributes(tauri_build::WindowsAttributes::new_without_app_manifest()),
        )
        .expect("failed to run tauri-build");
        println!("cargo:rustc-link-arg=/MANIFEST:EMBED");
        println!(
            "cargo:rustc-link-arg=/MANIFESTDEPENDENCY:type='win32' \
             name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
             processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'"
        );
    } else {
        tauri_build::build();
    }
}
