# To produce release zip/tarball

Release builds and deployments are automated via GitHub Actions. See
[.github/workflows/release.yml](.github/workflows/release.yml) for
details. Compilation requires Rust toolchain. See
<https://www.rust-lang.org/learn/get-started>.

Windows:
1. Download `WinDivert`:
```ps
Invoke-WebRequest -Uri "https://reqrypt.org/download/WinDivert-2.2.2-A.zip" -OutFile WinDivert.zip
Expand-Archive -Path WinDivert.zip -DestinationPath .\
Remove-Item .\WinDivert.zip
```
2. `.\build.ps1 zipball`

Linux: `make tarball`

Release zip/tarball should be ready on directory `dist`.

# To produce DPIBreak Panel (Windows)

The panel lives in the `gui/` workspace crate (`dpibreak-gui`). The
single-file build embeds `dpibreak.exe` and the WinDivert files:

```ps
powershell -ExecutionPolicy Bypass -File gui\build-bundle.ps1
```

This downloads and verifies WinDivert if needed, builds `dpibreak.exe`
and the panel, and writes `dist\DPIBreak-Panel.exe`. The
`DPIBreak Panel` workflow (`.github/workflows/panel.yml`) runs the same
script plus formatting, clippy and tests, and uploads the executable
as an artifact.

For development, `cargo build -p dpibreak-gui` builds the panel
without embedded files; it then uses a `dpibreak.exe` next to it, on
`PATH`, or set in its Service card.

# To produce DPIBreak Panel (Linux)

The Linux panel is an x86-64 executable with a static musl `dpibreak`
embedded. The panel links to the host glibc and loads X11, Wayland and
OpenGL libraries at runtime. The release workflow builds on Ubuntu
22.04, which sets a glibc 2.35 baseline for Debian 12+, Ubuntu 22.04+
and Arch Linux.

On Arch Linux, install `base-devel`, `pkgconf`, `musl`, `libx11`,
`libxcursor`, `libxrandr`, `libxi`, `libxkbcommon`, `wayland` and
`libglvnd`. On Debian 12 or Ubuntu 22.04+, install `build-essential`,
`pkg-config`, `musl-tools`, `libx11-dev`, `libxcursor-dev`,
`libxrandr-dev`, `libxi-dev`, `libxkbcommon-dev`, `libwayland-dev`,
`libgl1-mesa-dev` and `libegl1-mesa-dev`.

Then build the bundled binary:

```sh
rustup target add x86_64-unknown-linux-musl
sh gui/build-bundle.sh
```

This writes `dist/DPIBreak-Panel-linux-x86_64`. The script swaps the
output atomically, which is safe while an older panel process is open.
Install a per-user application-menu entry with
`sh gui/linux/install-desktop.sh`.

# Checks

The same checks as CI:

```sh
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
cargo clippy --locked -p dpibreak-gui --all-targets -- -D warnings
DPIBREAK_BUNDLE_DIR=$PWD/target/bundle-linux cargo clippy --locked \
  -p dpibreak-gui --all-targets -- -D warnings
cargo clippy --locked -p dpibreak-gui --target x86_64-pc-windows-gnu \
  --all-targets -- -D warnings
cargo test --locked --workspace --exclude windivert-dpibreak
```
