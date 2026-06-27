# Vérification cryptographique indépendante — journal de l'auditeur

> Ce dossier `audit/` contient les preuves de vérification produites par
> l'auditeur. Il ne modifie **aucun** code du projet (posture lecture seule).

## 1. Environnement

- Toolchain : `cargo 1.95.0`, `rustc 1.95.0` (stable, `x86_64-pc-windows-msvc`).
- Commandes exécutées par l'auditeur (PATH préfixé vers la toolchain locale) :
  - `cargo test --workspace` → **tout vert** (unitaires, KAT, propriétés,
    intégration, e2e, cycle de vie, récupération, partage, sync, passkey, urgence).
  - `cargo clippy --all-targets --all-features -- -D warnings` → **exit 0**
    (aucun avertissement ; `unwrap_used`/`expect_used` = deny en code hors tests).
  - `cargo audit` → **240 dépendances scannées, 0 vulnérabilité**.

## 2. Cross-vérification des vecteurs officiels (KAT)

Les constantes attendues codées dans la suite de tests ont été **confrontées aux
valeurs publiées** (et non simplement exécutées). Toutes correspondent :

| Primitive | Source | Valeur de référence (extrait) | Emplacement | Verdict |
|---|---|---|---|---|
| Argon2id | RFC 9106 §5.3 | tag `0d640df5…6b01e659` | `kdf.rs:163` | ✅ authentique |
| ChaCha20-Poly1305 IETF | RFC 8439 §2.8.2 | tag `1ae10b59…00691` | `aead.rs:329` | ✅ authentique |
| XChaCha20-Poly1305 | draft CFRG / libsodium | tag `c0875924…acf49` | `aead.rs:265` | ✅ authentique |
| AES-256-GCM | « Test Case 14 » (McGrew/Viega, NIST) | ct `cea7403d…9d18`, tag `d0d1c8a7…b919` | `aead.rs:286` | ✅ authentique |
| AES-256-GCM | NIST CAVP `gcmEncryptExtIV256` | tag `bdc1ac88…76f0` | `aead.rs:307` | ✅ authentique |
| HKDF-SHA256 | RFC 5869 annexe A (cas 1 & 2) | OKM `3cb25f25…865` | `hkdf_subcle.rs:84` | ✅ authentique |
| TOTP (HMAC-SHA1) | RFC 6238 annexe B | `94287082`@59, … | `totp.rs:103` | ✅ authentique |

Ces vecteurs sont exécutés **contre les crates RustCrypto réelles** (pas une
ré-implémentation maison), via l'API publique du projet, et passent.

## 3. Tests actifs de rupture (déjà présents et confirmés)

La suite contient de vrais tests adversariaux, exécutés et confirmés verts :

- altération d'un bit **quelconque** du fichier de coffre ⇒ échec, jamais de
  panic (`proprietes_coffre.rs:47`, proptest) ;
- mauvais mot de passe ⇒ `MotDePasseInvalide` sans fuite (`cycle_de_vie.rs:94`) ;
- corps corrompu ⇒ `Corrompu` ; tronqué / magie corrompue / octets résiduels ⇒
  `FormatInvalide` (`cycle_de_vie.rs`, `format.rs`) ;
- downgrade de version ⇒ `VersionNonSupportee` ; substitution d'algorithme ⇒
  rejet (`cycle_de_vie.rs:197/216`) ;
- bloc de récupération corrompu ⇒ échec **sans** affecter la voie mot de passe
  (`recuperation.rs:100`) ;
- e2e : le mot de passe maître **n'apparaît jamais** sur stdout/stderr
  (`e2e.rs`, prédicats `.not()`) ;
- intégration sync : le dépôt ne voit **aucun** nom ni mot de passe d'entrée en
  clair (`integration_sync.rs:42`).

## 4. Robustesse du parseur (analyse statique)

`format.rs::Lecteur` ne pré-alloue **jamais** un `Vec` à partir d'une longueur
déclarée non vérifiée : il lit une sous-tranche via `get(pos..fin)` (borné) avant
`to_vec()`. Une longueur démesurée (`u32::MAX`) renvoie `FormatInvalide` sans
allocation massive (`format.rs:152-176`, test `longueur_demesuree_rejetee`).
Conclusion : pas de déni de service mémoire par champ de longueur.
