# nexkeylock

**Gestionnaire de mots de passe à architecture zéro-connaissance**, écrit en Rust.
*Zero-knowledge password manager written in Rust.*

> ⚠️ Projet en développement (pré-audit). Ne pas utiliser pour de vrais secrets tant qu'un audit cryptographique indépendant n'a pas été réalisé.

## Principe

Seul l'utilisateur peut déchiffrer ses données. Tout le chiffrement se fait côté client. On **assemble des primitives auditées** (projet RustCrypto) — on n'invente jamais de cryptographie.

- Dérivation de clé : **Argon2id**.
- Chiffrement authentifié : **XChaCha20-Poly1305** (défaut), **AES-256-GCM** (alternative).
- Hiérarchie de clés **KEK/DEK** : changer le mot de passe maître ne rechiffre pas tout le coffre.
- Sous-clés : **HKDF-SHA256**. Aléa : **CSPRNG système**. Secrets : `zeroize`/`secrecy`.

Voir [`SECURITY.md`](SECURITY.md) pour le modèle de menace et les choix cryptographiques, et [`ROADMAP.md`](ROADMAP.md) pour le plan et l'état d'avancement.

## Structure

```
crates/
├── nex-cryptographie/   # primitives : KDF, AEAD, HKDF, aléa, types secrets
├── nex-coffre/          # modèle du coffre, KEK/DEK, format, stockage
└── nex-console/         # interface en ligne de commande (binaire: nexkeylock)
```

## Compiler et tester

```sh
cargo build --workspace
cargo test --workspace --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all --check
```

**Windows :** la cible `x86_64-pc-windows-msvc` requiert les **VS C++ Build Tools** (linker MSVC + Windows SDK).

Voir [`TESTING.md`](TESTING.md) pour le détail des catégories de tests.

## Crédits

La liste de mots diceware embarquée provient de l'**EFF** (*EFF Large Wordlist*,
7776 mots), publiée sous licence **CC-BY 3.0 US**.

## Licence

`MIT OR Apache-2.0` (le code). La liste de mots EFF conserve sa licence CC-BY 3.0 US.
