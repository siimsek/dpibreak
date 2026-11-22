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

# Checks

The same checks as CI:

```sh
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
cargo clippy --locked -p dpibreak-gui --all-targets -- -D warnings   # Windows
cargo test --locked --workspace --exclude windivert-dpibreak
```
