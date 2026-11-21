#!/usr/bin/env bash
set -euo pipefail

APP_NAME="aegis-linux"
BIN_NAME="aegis-linux"
REPO_URL="${AEGIS_LINUX_REPO:-https://github.com/KaanAlper/Aegis-Authleniticator-Linux.git}"
INSTALL_PREFIX="${INSTALL_PREFIX:-/usr/local}"

info() { printf '\033[1;32m[aegis-linux]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*"; }
err()  { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; exit 1; }

run_root() {
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
    elif command -v sudo >/dev/null 2>&1; then
        sudo "$@"
    elif command -v doas >/dev/null 2>&1; then
        doas "$@"
    else
        err "Root privileges (sudo/doas) are required to install system packages."
    fi
}

install_system_deps() {
    if [ -f /etc/os-release ]; then
        # shellcheck disable=SC1091
        . /etc/os-release
    fi

    if command -v apt-get >/dev/null 2>&1; then
        info "Detected Debian/Ubuntu-based system (${ID:-debian}). Installing build dependencies..."
        run_root apt-get update -qq
        run_root apt-get install -y --no-install-recommends \
            build-essential pkg-config git curl ca-certificates \
            libdbus-1-dev libxkbcommon-dev libxkbcommon-x11-dev \
            libwayland-dev libgl1-mesa-dev libegl1-mesa-dev \
            libx11-dev libxcursor-dev libxrandr-dev libxi-dev \
            libgtk-3-dev libnotify-bin
    elif command -v pacman >/dev/null 2>&1; then
        info "Detected Arch-based system (${ID:-arch}). Installing build dependencies..."
        run_root pacman -Sy --needed --noconfirm \
            base-devel pkgconf git curl \
            dbus libxkbcommon libxkbcommon-x11 \
            wayland mesa libglvnd \
            libx11 libxcursor libxrandr libxi \
            gtk3 libnotify
    elif command -v dnf >/dev/null 2>&1; then
        info "Detected Fedora/RHEL-based system (${ID:-fedora}). Installing build dependencies..."
        run_root dnf install -y \
            gcc gcc-c++ make pkgconf-pkg-config git curl \
            dbus-devel libxkbcommon-devel libxkbcommon-x11-devel \
            wayland-devel mesa-libGL-devel mesa-libEGL-devel \
            libX11-devel libXcursor-devel libXrandr-devel libXi-devel \
            gtk3-devel libnotify
    elif command -v zypper >/dev/null 2>&1; then
        info "Detected openSUSE-based system (${ID:-opensuse}). Installing build dependencies..."
        run_root zypper --non-interactive install \
            gcc gcc-c++ make pkg-config git curl \
            dbus-1-devel libxkbcommon-devel libxkbcommon-x11-devel \
            wayland-devel Mesa-libGL-devel Mesa-libEGL-devel \
            libX11-devel libXcursor-devel libXrandr-devel libXi-devel \
            gtk3-devel libnotify-tools
    else
        warn "Unknown package manager. Make sure gcc, pkg-config, dbus, wayland, xkbcommon, and OpenGL dev headers are installed."
    fi
}

ensure_rust() {
    if command -v cargo >/dev/null 2>&1 && command -v rustc >/dev/null 2>&1; then
        info "Rust toolchain found: $(rustc --version)"
        return
    fi

    info "Rust toolchain not found. Installing via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
    # shellcheck disable=SC1091
    [ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
    command -v cargo >/dev/null 2>&1 || err "Failed to install cargo."
}

prepare_source() {
    if [ -f "./Cargo.toml" ] && grep -q 'name = "aegis-linux"' "./Cargo.toml"; then
        SRC_DIR="$(pwd)"
        CLEANUP_SRC=0
        info "Using local source directory: $SRC_DIR"
    else
        SRC_DIR="$(mktemp -d -t aegis-linux-XXXXXX)"
        CLEANUP_SRC=1
        info "Cloning repository into $SRC_DIR..."
        git clone --depth 1 "$REPO_URL" "$SRC_DIR"
    fi
}

install_binary_and_desktop() {
    local bin_src="$SRC_DIR/target/release/$BIN_NAME"
    local icon_src="$SRC_DIR/assets/icon.png"
    [ -f "$bin_src" ] || err "Release binary not found at $bin_src"

    if [ -w "$INSTALL_PREFIX/bin" ] || command -v sudo >/dev/null 2>&1 || [ "$(id -u)" -eq 0 ]; then
        info "Installing $BIN_NAME to $INSTALL_PREFIX/bin/$BIN_NAME..."
        run_root install -Dm755 "$bin_src" "$INSTALL_PREFIX/bin/$BIN_NAME"
        local desktop_dir="$INSTALL_PREFIX/share/applications"
        local icon_dir="$INSTALL_PREFIX/share/icons/hicolor/256x256/apps"
        run_root mkdir -p "$desktop_dir" "$icon_dir"
        if [ -f "$icon_src" ]; then
            run_root install -Dm644 "$icon_src" "$icon_dir/$APP_NAME.png"
        fi
        write_desktop_file "$INSTALL_PREFIX/bin/$BIN_NAME" | run_root tee "$desktop_dir/$APP_NAME.desktop" >/dev/null
    else
        local local_bin="$HOME/.local/bin"
        local local_apps="$HOME/.local/share/applications"
        local local_icons="$HOME/.local/share/icons/hicolor/256x256/apps"
        mkdir -p "$local_bin" "$local_apps" "$local_icons"
        install -Dm755 "$bin_src" "$local_bin/$BIN_NAME"
        if [ -f "$icon_src" ]; then
            install -Dm644 "$icon_src" "$local_icons/$APP_NAME.png"
        fi
        write_desktop_file "$local_bin/$BIN_NAME" > "$local_apps/$APP_NAME.desktop"
        info "Installed to $local_bin/$BIN_NAME (ensure ~/.local/bin is in PATH)."
    fi
}

write_desktop_file() {
    local exec_path="$1"
    cat <<EOF
[Desktop Entry]
Type=Application
Name=Aegis Authenticator
Comment=Linux Desktop Client for Aegis 2FA Vaults
Exec=$exec_path
Icon=$APP_NAME
Terminal=false
Categories=Utility;Security;
Keywords=2FA;TOTP;HOTP;OTP;Aegis;Authenticator;
StartupNotify=true
EOF
}

main() {
    install_system_deps
    ensure_rust
    prepare_source

    if [ "$CLEANUP_SRC" -eq 1 ]; then
        trap 'rm -rf "$SRC_DIR"' EXIT
    fi

    info "Building $BIN_NAME in release mode..."
    (cd "$SRC_DIR" && cargo build --release)

    install_binary_and_desktop
    info "Done! Run '$BIN_NAME' from your terminal or application launcher."
}

main "$@"
