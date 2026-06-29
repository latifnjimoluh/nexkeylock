# NexKeyLock — application de bureau

Interface graphique de NexKeyLock (Tauri v2 + React/TypeScript), bâtie sur le
cœur Rust audité (`nex-coffre`). **Aucune cryptographie n'est réimplémentée
ici** : tout passe par la couche de commandes Tauri qui délègue au cœur.

## Prérequis

- **Rust** stable (MSVC) — voir `../../rust-toolchain.toml`.
- **Node 18+** et **pnpm**.
- **tauri-cli v2** : `cargo install tauri-cli --version "^2.0" --locked`.
- Windows : **WebView2** (préinstallé sur Windows 11).

## Développement

```sh
pnpm install
pnpm tauri dev      # lance l'app (Vite + fenêtre Tauri, rechargement à chaud)
```

## Vérifications

```sh
pnpm test           # tests de composants (Vitest + Testing Library)
pnpm lint           # ESLint
pnpm format         # Prettier (vérification)
pnpm build          # tsc --noEmit + build Vite (frontend)
```

Backend (dans `src-tauri/`) :

```sh
cargo build         # compilation debug
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

## Build de distribution

```sh
pnpm tauri build
```

Les bundles sont produits dans `src-tauri/target/release/bundle/` :

| Plateforme | Sorties | Construit sur |
|------------|---------|---------------|
| **Windows** | `nsis/*-setup.exe` (et `msi/*.msi` si WiX présent) | Windows |
| **macOS** | `dmg/*.dmg`, `macos/*.app` | macOS |
| **Linux** | `appimage/*.AppImage`, `deb/*.deb`, `rpm/*.rpm` | Linux |

Tauri **ne fait pas de compilation croisée** des bundles : chaque OS se
construit sur lui-même (poste dédié ou CI matricielle). La première exécution
sous Windows télécharge l'outil NSIS automatiquement.

> Les exécutables ne sont pas signés. Comme pour la CLI, prévoir un certificat
> Authenticode (Windows) / notarisation (macOS) pour une distribution publique
> (voir `../../packaging/`).

Pour produire un binaire sans empaqueter : `pnpm tauri build --no-bundle`.

## Architecture

```
nexkeylock-bureau/
├── src/                 # frontend (TS + React + Tailwind)
│   ├── composants/      # bibliothèque de composants du design system
│   ├── ecrans/          # écrans (verrouillage, coffre, réglages…)
│   ├── theme/           # jetons de couleur, thèmes clair/sombre
│   ├── lib/             # pont vers les commandes Tauri, état, thème
│   └── tests/           # configuration de test
└── src-tauri/           # backend Rust (Tauri v2)
    ├── src/commandes.rs # couche de commandes (délègue à nex-coffre)
    ├── capabilities/    # capacités au strict minimum (core uniquement)
    └── tauri.conf.json  # CSP verrouillée, fenêtre, bundle
```

## Sécurité (rappels)

- La clé maître et la DEK **ne quittent jamais le backend** ; la webview ne
  reçoit que des métadonnées, et les secrets par champ, à la demande.
- **CSP verrouillée** (pas de script distant ni `eval`), **capacités minimales**
  (aucun shell ni accès fichier arbitraire), **aucun secret en stockage
  navigateur**, outils de développement désactivés en release.
- Voir `../../FRONTEND_ROADMAP.md` (§1 et §3) pour la frontière de sécurité.
