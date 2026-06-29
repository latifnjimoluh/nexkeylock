# NexKeyLock — PWA (iPhone / Android / navigateur)

Application web **installable** (sans App Store ni Play Store), exécutant le
**cœur Rust audité compilé en WebAssembly** : **aucune cryptographie n'est
écrite en JavaScript**. Le coffre **chiffré** est stocké localement (IndexedDB) ;
la clé ne vit qu'en mémoire WASM le temps de la session.

> ⚠️ Compromis assumé (cf. `SYNC_PWA_ROADMAP.md` §1) : une PWA recharge son code
> depuis le serveur — modèle de menace plus faible qu'une app native. À
> auto-héberger en HTTPS, CSP stricte, ressources figées.

## Prérequis & construction du cœur WASM

```sh
# 1) cible + CLI (versions : voir crates/nex-wasm/Cargo.lock)
#    (rustup absent ici : la std wasm32 a été installée manuellement)
cargo install wasm-bindgen-cli --version =0.2.126 --locked
# 2) génère src/coeur-wasm/ (nex_wasm.js + nex_wasm_bg.wasm)
pwsh scripts/construire-wasm.ps1     # depuis la racine du dépôt
```

## Développement

```sh
pnpm install
pnpm dev        # http://localhost:1430
pnpm build      # tsc + vite + génération manifeste/service worker (hors-ligne)
pnpm test       # tests de composants (Vitest)
pnpm lint
```

## État (Jalon S4)

Squelette fonctionnel : chargement du WASM, création / déverrouillage du coffre,
liste, ajout, verrouillage — prouvant la chaîne **cœur WASM + IndexedDB**. Les
écrans complets (réutilisant les composants du bureau) et la **synchronisation**
(client vers le serveur zéro-connaissance) arrivent au **Jalon S5**.

Notes :

- Argon2id (256 Mio) s'exécute dans le navigateur (quelques secondes) ; le
  passage en **Web Worker** + le réglage des paramètres pour mobile relèvent du
  Jalon S6.
- `src/coeur-wasm/` est **généré** (non versionné) : lancer le script ci-dessus.
