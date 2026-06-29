# Construit le paquet WebAssembly du cœur pour la PWA.
#
# Prérequis : cible wasm32-unknown-unknown installée + wasm-bindgen-cli à la
# version EXACTE de la crate wasm-bindgen (voir crates/nex-wasm/Cargo.lock).
#   cargo install wasm-bindgen-cli --version =<X.Y.Z> --locked
#
# Sortie : apps/nexkeylock-pwa/src/coeur-wasm/ (nex_wasm.js + nex_wasm_bg.wasm).

$ErrorActionPreference = "Stop"
$racine = Split-Path -Parent $PSScriptRoot
$wasm = "$racine\crates\nex-wasm\target\wasm32-unknown-unknown\release\nex_wasm.wasm"
$sortie = "$racine\apps\nexkeylock-pwa\src\coeur-wasm"

Write-Output "1/2 Compilation wasm32 (release)…"
cargo build --manifest-path "$racine\crates\nex-wasm\Cargo.toml" --release --target wasm32-unknown-unknown

Write-Output "2/2 Génération des liaisons JS (wasm-bindgen --target web)…"
wasm-bindgen --target web --out-dir $sortie $wasm

Write-Output "OK -> $sortie"
