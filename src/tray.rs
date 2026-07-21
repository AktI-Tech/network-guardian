//! Windows system tray for `serve --tray` (Phase E).
//!
//! Menu: Open Dashboard · Status · Quit
//! Runs a dedicated thread with a Win32 message pump required by tray-icon.

#![cfg(windows)]

use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::Duration;

use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, TrayIcon, TrayIconBuilder, TrayIconEvent};
use windows::Win32::UI::WindowsAndMessaging::{
    DispatchMessageW, PeekMessageW, TranslateMessage, MSG, PM_REMOVE, WM_QUIT,
};

pub enum TrayCommand {
    Quit,
}

/// Spawn tray UI; returns a receiver that yields when the user chooses Quit.
pub fn spawn(dashboard_url: String) -> Receiver<TrayCommand> {
    let (tx, rx) = mpsc::channel();
    thread::Builder::new()
        .name("ng-tray".into())
        .spawn(move || {
            if let Err(e) = run_tray_loop(dashboard_url, tx) {
                eprintln!("❌ Tray error: {e}");
            }
        })
        .expect("spawn tray thread");
    rx
}

fn run_tray_loop(dashboard_url: String, tx: Sender<TrayCommand>) -> Result<(), String> {
    let icon = make_icon().map_err(|e| format!("icon: {e}"))?;

    let open_item = MenuItem::new("Open Dashboard", true, None);
    let status_item = MenuItem::new("Status / Region", true, None);
    let quit_item = MenuItem::new("Quit NetworkGuardian", true, None);
    let menu = Menu::new();
    menu.append(&open_item)
        .map_err(|e| format!("menu append: {e}"))?;
    menu.append(&status_item)
        .map_err(|e| format!("menu append: {e}"))?;
    menu.append(&PredefinedMenuItem::separator())
        .map_err(|e| format!("menu append: {e}"))?;
    menu.append(&quit_item)
        .map_err(|e| format!("menu append: {e}"))?;

    let open_id = open_item.id().clone();
    let status_id = status_item.id().clone();
    let quit_id = quit_item.id().clone();

    let _tray: TrayIcon = TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_tooltip("NetworkGuardian — Protecting the builders")
        .with_icon(icon)
        .with_title("NG")
        .build()
        .map_err(|e| format!("tray build: {e}"))?;

    println!("📌 System tray active — right-click the tray icon for menu");

    let menu_channel = MenuEvent::receiver();
    let tray_channel = TrayIconEvent::receiver();

    loop {
        // Drain tray / menu events
        while let Ok(event) = menu_channel.try_recv() {
            if event.id == open_id || event.id == status_id {
                open_url(&dashboard_url);
            } else if event.id == quit_id {
                let _ = tx.send(TrayCommand::Quit);
                return Ok(());
            }
        }
        while let Ok(_ev) = tray_channel.try_recv() {
            // Double-click / click — open dashboard
            // TrayIconEvent variants differ by version; any event opens UI
            open_url(&dashboard_url);
        }

        // Win32 message pump (required on Windows for tray-icon)
        unsafe {
            let mut msg = MSG::default();
            while PeekMessageW(&mut msg, None, 0, 0, PM_REMOVE).as_bool() {
                if msg.message == WM_QUIT {
                    let _ = tx.send(TrayCommand::Quit);
                    return Ok(());
                }
                let _ = TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }

        thread::sleep(Duration::from_millis(50));
    }
}

fn open_url(url: &str) {
    // `start` needs an empty title argument when URL is quoted.
    let result = std::process::Command::new("cmd")
        .args(["/C", "start", "", url])
        .spawn();
    if let Err(e) = result {
        eprintln!("Failed to open browser: {e}");
    }
}

fn make_icon() -> Result<Icon, String> {
    // 32×32 solid accent blue with a lighter inner square (simple shield-ish mark)
    let size = 32u32;
    let mut rgba = vec![0u8; (size * size * 4) as usize];
    for y in 0..size {
        for x in 0..size {
            let i = ((y * size + x) * 4) as usize;
            let edge = x < 2 || y < 2 || x >= size - 2 || y >= size - 2;
            let inner = (8..24).contains(&x) && (8..24).contains(&y);
            if edge {
                rgba[i] = 20;
                rgba[i + 1] = 40;
                rgba[i + 2] = 70;
                rgba[i + 3] = 255;
            } else if inner {
                rgba[i] = 167;
                rgba[i + 1] = 139;
                rgba[i + 2] = 250;
                rgba[i + 3] = 255;
            } else {
                rgba[i] = 61;
                rgba[i + 1] = 156;
                rgba[i + 2] = 240;
                rgba[i + 3] = 255;
            }
        }
    }
    Icon::from_rgba(rgba, size, size).map_err(|e| e.to_string())
}
