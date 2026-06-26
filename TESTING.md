# Tests — nexkeylock

> Comment lancer chaque catégorie de tests. Ce document s'enrichit à chaque jalon (squelette au Jalon 0).

## Prérequis

- Chaîne d'outils Rust **stable** épinglée par `rust-toolchain.toml` (1.95.0).
- Sous Windows : **VS C++ Build Tools** (linker MSVC + Windows SDK) requis par la cible `x86_64-pc-windows-msvc`.
- Pour le fuzzing : chaîne **nightly** + `cargo-fuzz` (isolés dans `fuzz/`).

## Commandes principales

| Objectif | Commande |
|---|---|
| Tout compiler | `cargo build --workspace` |
| Tous les tests | `cargo test --workspace --all-features` |
| Formatage | `cargo fmt --all --check` |
| Lint strict | `cargo clippy --all-targets --all-features -- -D warnings` |
| Audit des dépendances | `cargo audit` |
| Couverture (Jalon 1+) | `cargo llvm-cov --workspace --html` |
| Benchmarks (Jalon 1+) | `cargo bench -p nex-cryptographie` |
| Fuzz smoke (Jalon 1/7) | `cargo +nightly fuzz run <cible> -- -runs=100000` |

## Catégories de tests (selon la matrice de la ROADMAP §4)

- **Unitaires** — `#[cfg(test)]` dans chaque module : cas nominal, limites, erreurs.
- **Vecteurs officiels (KAT)** — Argon2id (RFC 9106), ChaCha20/XChaCha20-Poly1305 (RFC 8439 + libsodium), AES-256-GCM (NIST CAVP), HKDF-SHA256 (RFC 5869), TOTP (RFC 6238 annexe B). *Un seul vecteur en échec = implémentation fausse.*
- **Propriétés (`proptest`)** — aller-retour `decrypt(encrypt(x)) == x`, détection d'altération (1 bit), unicité des nonces, déterminisme du KDF.
- **Intégration / cycle de vie** — `nex-coffre/tests` : créer→ajouter→verrouiller→déverrouiller→…→rouvrir ; cas adversariaux (coffre corrompu, mauvais mot de passe, downgrade) sans panic.
- **E2E CLI (`assert_cmd`)** — `nex-console/tests` : scénarios réels ; vérification d'absence de fuite de secret.
- **Négatifs / adversariaux** — entrées tronquées, surdimensionnées, en-têtes falsifiés.
- **Fuzzing (`cargo-fuzz`)** — désérialiseur d'en-tête, parseur de format, routine AEAD.
- **Temps constant** — vérifier l'usage de `subtle` ; interdire `==` sur les secrets.
- **Hygiène mémoire** — vérifier `Zeroize`/`Drop` là où c'est faisable.

## Sous Windows (PowerShell)

Si `cargo` n'est pas dans le PATH de la session, préfixer :
```powershell
$env:Path = "C:\Users\<vous>\.rustup\toolchains\stable-x86_64-pc-windows-msvc\bin;" + $env:Path
```
