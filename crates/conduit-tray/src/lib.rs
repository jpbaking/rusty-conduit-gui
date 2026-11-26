//! UI-agnostic system tray support for Rusty Conduit GUI.
//!
//! [`TrayMenuModel`] describes the menu, and a [`TrayBackend`] shows it. Linux uses the
//! pure-Rust `ksni` backend. Windows and macOS plug in a Tauri adapter from `src-tauri`.

pub mod backend;
pub mod image;
#[cfg(target_os = "linux")]
pub mod linux_ksni;
pub mod model;

pub use backend::{MockTrayBackend, TrayBackend, TrayError};
pub use image::TrayImage;
#[cfg(target_os = "linux")]
pub use linux_ksni::KsniTrayBackend;
pub use model::{
    http_proxy_url, socks_proxy_url, ProxyTrayItem, TrayAction, TrayHostStatus, TrayIconState,
    TrayMenuEntry, TrayMenuItem, TrayMenuModel, TrayProxyEntry, TraySessionEntry, TrayState,
    TraySubmenu, TrayTunnelEntry, TunnelTrayItem, APP_TITLE, PROFILE_DIRECT,
};
