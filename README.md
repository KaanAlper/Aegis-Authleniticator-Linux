<p align="center">
  <img src="assets/icon.png" alt="Aegis Authenticator Linux" width="128" height="128" />
</p>

<h1 align="center">Aegis Authenticator Linux</h1>

<p align="center">
  <strong>Aegis Authenticator — Built with pure Rust for Linux.</strong><br/>
  Fast, lightweight, native 2FA desktop client for <a href="https://github.com/beemdevelopment/Aegis">Aegis</a> vaults with full Wayland, X11, and System Tray support.
</p>

---

## Why Pure Rust?

- **Built with pure Rust for Linux**: Zero Electron, zero JVM, zero browser overhead — compiles to a single native binary with minimal memory footprint and instant startup.
- **Native Wayland & X11**: Runs smoothly on Hyprland, Sway, GNOME, KDE Plasma, XFCE, and i3.
- **Full Aegis Vault Compatibility**: Open, edit, encrypt (`AES-256-GCM` + `scrypt`), and save standard Aegis `.json` vaults seamlessly.

## One-Line Install

Works automatically on **Arch Linux**, **Debian / Ubuntu**, **Fedora**, and **openSUSE** (installs Wayland/X11/D-Bus dependencies, installs Rust if missing, compiles in release mode, and sets up the `.desktop` launcher & icon):

```bash
curl -fsSL https://raw.githubusercontent.com/KaanAlper/Aegis-Authleniticator-Linux/main/install.sh | bash
```

Or from a local clone:

```bash
git clone https://github.com/KaanAlper/Aegis-Authleniticator-Linux.git
cd Aegis-Authleniticator-Linux
./install.sh
```

## Features

- **Pure Rust Cryptography & OTP Engine**:
  - **Encrypted & Plaintext Vaults**: Full `AES-256-GCM` + `scrypt` (`N=32768, r=8, p=1`) support; preserves existing biometric/raw key slots.
  - **All Aegis OTP Types**: `TOTP` (`SHA1`, `SHA256`, `SHA512`), `HOTP` (counter increment), `Steam` (5-char), `MOTP` (MD5 + PIN), and `Yandex` (YAOTP).
  - **`otpauth://` Import**: Paste one or multiple `otpauth://` URIs to add tokens in seconds.
- **Modern Responsive UI**:
  - Multi-column adaptive card grid, real-time circular countdown rings, 1-click code copy, search, group filters, favorites, drag-and-drop `.json` vault opening, and Dark / Light themes.
- **System Tray (`ksni` StatusNotifierItem)**:
  - **Show Aegis**: Restore and focus the main window anytime.
  - **Get Key ▸**: Expandable submenu listing all your entries with their icons and live OTP codes — click any entry to copy its code directly to the clipboard (with desktop notification).
  - **Lock Vault** & **Quit** (closing the window minimizes to the tray).

## Manual Build

### Arch Linux
```bash
sudo pacman -S --needed base-devel pkgconf dbus libxkbcommon wayland mesa gtk3 libnotify
cargo build --release
```

### Debian / Ubuntu
```bash
sudo apt-get install -y build-essential pkg-config libdbus-1-dev libxkbcommon-dev libwayland-dev libgl1-mesa-dev libegl1-mesa-dev libx11-dev libgtk-3-dev libnotify-bin
cargo build --release
```

### Fedora
```bash
sudo dnf install -y gcc pkgconf-pkg-config dbus-devel libxkbcommon-devel wayland-devel mesa-libGL-devel mesa-libEGL-devel libX11-devel gtk3-devel libnotify
cargo build --release
```

## Tests

```bash
cargo test
```
