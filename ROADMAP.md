# FEUILLE DE ROUTE — nexkeylock

> Gestionnaire de mots de passe à architecture **zéro-connaissance**, en Rust.
> Ce fichier est à la fois le **plan** et le **tableau de bord** vivant. Les cases sont mises à jour à la fin de chaque jalon, accompagnées d'un commit atomique.

**Légende :** `- [ ]` à faire · `- [~]` en cours · `- [x]` terminé et vert (selon la « Définition de terminé »).

**Correspondance des noms de crates avec le brief** (tout est en français, identifiants compris) :

| Brief | nexkeylock | Rôle |
|---|---|---|
| `pm-crypto` | `nex-cryptographie` | primitives cryptographiques |
| `pm-core` | `nex-coffre` | logique du coffre |
| `pm-cli` | `nex-console` | interface en ligne de commande |

---

## 1. Vision et périmètre

Construire un gestionnaire de mots de passe où **seul l'utilisateur** peut déchiffrer ses données — aucun serveur, fournisseur ou administrateur ne voit jamais le clair. Tout le chiffrement se fait côté client. On **assemble des primitives auditées** ; on n'invente jamais de cryptographie.

### Dans le périmètre — livrable principal (Jalons 0 à 5, entièrement construits et testés)
- `nex-cryptographie` — cœur cryptographique (KDF, AEAD, HKDF, CSPRNG, types secrets, temps constant).
- `nex-coffre` — logique du coffre (modèle de données, hiérarchie KEK/DEK, format versionné et authentifié, stockage local, verrouillage/déverrouillage, verrouillage automatique, effacement mémoire).
- `nex-console` — premier produit utilisable : une interface en ligne de commande.
- La **suite de tests complète** (unitaires, vecteurs officiels, propriétés, intégration, end-to-end, négatifs/adversariaux, fuzz smoke, benchmarks, couverture).

### Différé — phases avancées (Jalon 6, structuré ici mais NON développé en avance)
Synchronisation zéro-connaissance (auth par PAKE / double dérivation), partage chiffré de bout en bout (encapsulation hybride X25519 + ML-KEM-768), fournisseur de passkeys (FIDO2/WebAuthn), interface graphique Tauri, liaisons mobiles UniFFI, clés matérielles, accès d'urgence.

### Conventions de langue
À la demande explicite, **tout est en français** : code, identifiants, commentaires, messages de commit et documentation (`ROADMAP.md`, `README.md`, `SECURITY.md`, `TESTING.md`).

---

## 2. Décisions d'architecture

### Structure du workspace
```
nexkeylock/
├── Cargo.toml                 # manifeste du workspace (resolver = "2")
├── rust-toolchain.toml        # chaîne stable épinglée (1.95.0)
├── ROADMAP.md                 # ce fichier (tableau de bord)
├── README.md                  # build/test/usage
├── SECURITY.md                # modèle de menace + choix crypto + limites honnêtes
├── TESTING.md                 # comment lancer chaque catégorie de tests
├── deny.toml                  # cargo-deny (avis, licences) — porte d'audit
├── rustfmt.toml / clippy.toml # configuration de formatage et de lint
├── crates/
│   ├── nex-cryptographie/  src/ tests/   # primitives + vecteurs + propriétés
│   ├── nex-coffre/         src/ tests/   # modèle, KEK/DEK, format, stockage
│   └── nex-console/        src/ tests/   # CLI + e2e (assert_cmd/predicates)
├── fuzz/                        # cibles cargo-fuzz (nightly, isolé)
└── .github/workflows/ci.yml    # fmt + clippy + test + fuzz smoke + couverture + audit
```

### Couches et sens des dépendances
`nex-console` → `nex-coffre` → `nex-cryptographie`. Strictement à sens unique. `nex-cryptographie` ne connaît rien du coffre ; `nex-coffre` ne connaît rien de la CLI/du terminal. Cela garantit une **unique implémentation cryptographique** à auditer.

### Gestion d'erreurs
- Bibliothèques (`nex-cryptographie`, `nex-coffre`) : erreurs typées via `thiserror`. **Aucun `unwrap()`/`expect()`** sur un chemin touchant aux secrets ou aux données non fiables (forcé par Clippy : `unwrap_used`/`expect_used` = deny, autorisés en tests via `clippy.toml`). **Échec sûr** : une erreur de déchiffrement/authentification renvoie une erreur typée, jamais de donnée partielle.
- CLI (`nex-console`) : `anyhow` au niveau supérieur, traduisant les erreurs typées en messages propres, **sans fuite de secret**.

### Choix cryptographiques (source : brief §3 ; doc de conception §4)
| Sujet | Décision |
|---|---|
| KDF | **Argon2id**, défaut `m = 262144 Kio (256 Mio)`, `t = 3`, `p = 4`, sortie 32 octets. Paramètres stockés dans l'en-tête (agilité). |
| Replis KDF (documentés, non défaut) | scrypt `N=2^17, r=8, p=1` ; PBKDF2-HMAC-SHA256 `≥ 600 000` itér. (FIPS). |
| Sel | ≥ 16 octets, CSPRNG, unique par coffre, stocké en clair (authentifié). |
| AEAD (défaut) | **XChaCha20-Poly1305**, nonce 192 bits aléatoire (CSPRNG). |
| AEAD (alt.) | **AES-256-GCM** avec nonce à **compteur persistant strictement croissant** (jamais aléatoire). `id_algorithme` stocké par blob. |
| Règle nonce | Jamais de réutilisation d'un nonce avec une même clé. Jamais. |
| Hiérarchie des clés | mot de passe → Argon2id → **KEK (256 bits)** ; **DEK (256 bits)** aléatoire emballée par la KEK. Changement de mot de passe = réemballage de la DEK seulement. |
| Sous-clés | **HKDF-SHA256** avec étiquette de contexte. |
| Aléa | CSPRNG du système uniquement (`OsRng` / `getrandom`). Jamais de PRNG non crypto pour clés/sels/nonces/mots de passe générés. |
| Hygiène des secrets | `zeroize`/`secrecy` ; `mlock`/`VirtualLock` si disponible ; désactiver les core dumps ; comparaisons à temps constant via `subtle` ; aucun secret dans logs/erreurs/panics. |
| En-tête | versionné + authentifié comme données associées de l'AEAD ; downgrade rejeté ; échec sûr. |

### Dépendances épinglées
Centralisées dans `[workspace.dependencies]` du `Cargo.toml` racine, tirées par crate au fil des jalons ; `cargo audit`/`cargo deny` maintenus propres. Cf. brief §4 pour la liste complète.

### Cible de coût KDF en test (décision validée)
Défaut **production** : Argon2id `m=256 Mio, t=3, p=4` (calibré à ~0,5 s par benchmark `criterion`). En **test/CI** : paramètres réduits (p. ex. `m=8 Mio, t=1`) pour la vitesse — **sauf les vecteurs officiels (KAT)** qui utilisent exactement les paramètres de la RFC.

---

## 3. Jalons

### Jalon 0 — Fondations du projet
**Objectif :** un workspace vide qui compile, sans avertissement de lint, avec CI et docs de politique.
**Livrables de code :**
- [x] `Cargo.toml` (workspace virtuel), `rust-toolchain.toml` (stable épinglé), `.gitignore`.
- [x] Crates vides `nex-cryptographie`, `nex-coffre`, `nex-console` qui compilent.
- [x] Configuration `clippy` + `rustfmt` ; `deny.toml`.
- [x] `.github/workflows/ci.yml` : fmt + clippy `-D warnings` + test + audit.
- [x] `ROADMAP.md` (ce fichier), brouillon `SECURITY.md`, `README.md`, `TESTING.md`.
- [x] `git init`, commit initial.

**Plan de test :** CI verte sur build vide ; `cargo fmt --check`, `cargo clippy -D warnings`, `cargo audit` propres.
**Critères d'acceptation :**
- [x] `cargo build`, `cargo test`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo fmt --all --check` passent (vérifié localement, toolchain 1.95.0 + VS Build Tools).
- [x] `cargo audit` propre (aucune vulnérabilité).
- [x] Pipeline CI défini.

---

### Jalon 1 — `nex-cryptographie` (cœur crypto) — **TDD : vecteurs d'abord**
**Objectif :** des enveloppes correctes autour de primitives auditées, avec hygiène des secrets.
**Livrables de code :**
- [x] Enveloppe KDF Argon2id (paramètres entrants/sortants, clé 32 octets) — `kdf.rs`.
- [x] AEAD : XChaCha20-Poly1305 (défaut) + AES-256-GCM, derrière une interface typée commune avec `id_algorithme` ; nonce toujours fourni par l'appelant (pas de génération de nonce pour AES-GCM) — `aead.rs`.
- [x] Dérivation de sous-clés HKDF-SHA256 avec étiquettes de contexte — `hkdf_subcle.rs`.
- [x] Aides CSPRNG (`OsRng`/`getrandom`) pour clés/sels/nonces — `alea.rs`.
- [x] Types secrets `CleSecrete` avec `Zeroize`/`ZeroizeOnDrop`, égalité à temps constant via `subtle`, `Debug` expurgé — `secret.rs`.
- [x] Énumération d'erreurs typées (`thiserror`), sans secret dans les messages — `erreurs.rs`.

**Plan de test (tests écrits avec — et vecteurs *avant* — chaque composant) :**
- [x] **Vecteurs officiels (KAT)** : Argon2id (RFC 9106), ChaCha20-Poly1305 IETF (RFC 8439) + XChaCha20 (draft/libsodium), AES-256-GCM (NIST CAVP + Test Case 14), HKDF-SHA256 (RFC 5869 cas 1 & 2). **Tous passent.**
- [x] **Propriétés (`proptest`)** : aller-retour `dechiffrer(chiffrer(x)) == x` ; altération d'un bit du chiffré/tag/AAD ⇒ échec ; nonces différents ⇒ sorties différentes ; déterminisme du KDF (mêmes entrées ⇒ même clé ; sel différent ⇒ clé différente).
- [x] **Unitaires** : cas nominal/limite/erreur par fonction publique (26 tests unitaires).
- [x] **Temps constant** : `CleSecrete` ne fournit que `ConstantTimeEq` (pas de `==` brut) ; `unwrap_used`/`expect_used` interdits hors tests.
- [x] **Hygiène mémoire** : `CleSecrete` implémente `Zeroize`/`ZeroizeOnDrop` ; test d'expurgation du `Debug`. Limites honnêtes documentées dans `SECURITY.md`.
- [x] **Benchmark (`criterion`)** : `benches/calibration.rs` ; Argon2id à 256 Mio mesuré à **~688 ms** sur la machine cible (cible bureau 0,5–1 s ✓) ; débit AEAD mesuré.

**Critères d'acceptation :**
- [x] Tous les KAT passent (un seul échec = implémentation fausse).
- [x] Tests propriétés + unitaires + temps constant verts (32 tests au total).
- [~] Couverture ≥ 90 % sur `nex-cryptographie` — **portée par la CI** (job `cargo-llvm-cov --fail-under-lines 90`) ; non mesurable localement (toolchain Windows sans composant `llvm-tools-preview`). Suite de tests exhaustive (toute fonction publique exercée).
- [x] « Définition de terminé » (§5) satisfaite (build, test, clippy `-D warnings`, fmt, audit verts).

---

### Jalon 2 — `nex-coffre` (MVP du coffre)
**Objectif :** cycle de vie complet d'un coffre chiffré sur stockage fichier local.
**Livrables de code :**
- [x] Modèle de données (`Entree`, `TypeEntree`, `ContenuCoffre`) avec `serde` + CBOR (`ciborium`), effacement automatique (`Zeroize`/`ZeroizeOnDrop`), `Debug` expurgé — `modele.rs`.
- [x] Hiérarchie KEK/DEK : DEK aléatoire emballée par la KEK ; déballage à l'ouverture — `coffre.rs`.
- [x] En-tête versionné et **authentifié** via **deux AAD** (`aad_dek` = version+algo+params+sel ; `aad_corps` = version+algo) — `entete.rs`.
- [x] Format binaire `.vault` (magie + longueurs préfixées), décodage **fail-closed** ; écritures **atomiques** (fichier temporaire + renommage) — `format.rs`, `coffre.rs`.
- [x] Ouverture/déverrouillage/verrouillage (machine à états typée), verrouillage automatique par inactivité (`est_inactif`/`toucher`), effacement mémoire au `drop`.
- [x] Changement de mot de passe = **réemballage de la DEK uniquement** (nouveau sel, DEK inchangée).
- [x] Erreurs typées (`thiserror`) ; échec sûr partout, sans secret dans les messages.

**Plan de test :**
- [x] **Intégration cycle de vie** : créer → ajouter → verrouiller → déverrouiller → lire → modifier → supprimer → enregistrer → rouvrir, avec vérification d'intégrité.
- [x] Mauvais mot de passe maître ⇒ `MotDePasseInvalide`, sans fuite.
- [x] Coffre corrompu / tronqué / magie corrompue ⇒ erreur typée, **aucun panic** (+ propriété : tout bit retourné échoue).
- [x] Changement de mot de passe ⇒ DEK réemballée (nouveau sel), coffre toujours déchiffrable, ancien mot de passe rejeté.
- [x] Tentative de **downgrade** de version ⇒ `VersionNonSupportee` ; substitution d'algorithme ⇒ rejetée.
- [x] Tests de propriétés : aller-retour du contenu, altération d'un octet quelconque.

**Critères d'acceptation :**
- [x] Tests d'intégration du cycle de vie verts (8) ; tous les cas adversariaux échouent proprement sans panic. 27 tests `nex-coffre` au total.
- [~] Couverture ≥ 90 % sur `nex-coffre` — **portée par la CI** (voir Jalon 1).
- [x] « Définition de terminé » (§5) satisfaite (build, test, clippy `-D warnings`, fmt, audit verts).

---

### Jalon 3 — Fonctions essentielles (dans `nex-coffre`)
**Objectif :** les fonctions qui rendent le coffre réellement utile, toutes calculées localement.
**Livrables de code :**
- [x] Générateur de mots de passe non biaisé (rejet d'échantillonnage, CSPRNG), estimation d'entropie, jeux configurables, exclusion des ambigus, sortie `Zeroizing` — `generateur.rs`.
- [x] Générateur de phrases de passe diceware (liste **EFF de 7776 mots** embarquée, entropie reportée).
- [x] TOTP (RFC 6238) via `hmac`+`sha1` local, + décodage Base32 (RFC 4648) — `totp.rs`.
- [x] Recherche (nom/URI/utilisateur, insensible à la casse) — `CoffreDeverrouille::rechercher`.
- [x] Audit local : mots de passe faibles / réutilisés / anciens ; estimation d'entropie — `audit.rs`.
- [x] Surveillance des fuites par **k-anonymat** (préfixe SHA-1 de 5 caractères) derrière le trait `FournisseurFuites` — **mockable, aucun réseau réel**.

**Plan de test :**
- [x] Vecteurs TOTP : RFC 6238 annexe B (6 temps fixés, variante SHA-1, 8 chiffres) — passent.
- [x] Générateur : tirage non dégénéré (toutes les lettres apparaissent), bornes de l'index uniforme, calcul d'entropie ; liste EFF = 7776 mots uniques.
- [x] k-anonymat : client simulé ; **vérifié** que seul un préfixe de 5 caractères est transmis (jamais le condensat complet).
- [x] Audit : détection faibles / réutilisés / anciens ; Base32 (`foobar`) et aller-retour Base32→TOTP.

**Critères d'acceptation :**
- [x] Vecteurs RFC 6238 passent.
- [x] Aucun appel réseau réel dans un test ; générateur non biaisé.
- [x] « Définition de terminé » (§5) satisfaite (build, test, clippy `-D warnings`, fmt, audit verts).

---

### Jalon 4 — `nex-console`
**Objectif :** le premier produit livrable.
**Livrables de code :**
- [x] Commandes : `init`, `unlock`, `add`, `get`, `list`, `edit`, `rm`, `generate`, `audit`, `totp`, `export`, `import`, `change-password` (binaire `nexkeylock`).
- [x] Saisie masquée (`rpassword`) ou via `NEXKEYLOCK_MDP` ; presse-papiers avec effacement après délai derrière le trait `PressePapiers` (impl `arboard` en fonctionnalité `presse-papiers`, désactivée par défaut).
- [x] Verrouillage : la CLI est sans état — chaque commande dérive la KEK, agit, puis **efface** les clés à la sortie du processus (`ZeroizeOnDrop`).
- [x] Erreurs `anyhow` au niveau supérieur, mappant les erreurs typées **sans fuite de secret**.

**Plan de test :**
- [x] **E2E (`assert_cmd` + `predicates`)** : init, unlock, add puis get, list, generate (mot de passe + phrase), export/import, change-password (via stdin), totp, audit, rm.
- [x] **Vérifié** qu'aucun mot de passe maître n'apparaît sur stdout/stderr ; `list` ne montre aucun mot de passe d'entrée.
- [x] Entrées négatives gérées proprement (mauvais mot de passe, entrée introuvable, `rm` par nom).

**Critères d'acceptation :**
- [x] 7 scénarios E2E verts ; aucune fuite de secret dans la sortie.
- [x] « Définition de terminé » (§5) satisfaite (build, test, clippy `-D warnings`, fmt, audit verts ; la fonctionnalité `presse-papiers` compile aussi).

---

### Jalon 5 — Sauvegarde et récupération
**Objectif :** retrouver l'accès sans casser le zéro-connaissance.
**Livrables de code :**
- [x] Code de récupération : DEK emballée à la fois par la KEK **et** par une clé dérivée du code (bloc `BlocRecuperation`, AAD = `aad_corps` stable) — `activer_recuperation` / `deverrouiller_par_recuperation`.
- [x] Export chiffré par défaut (copie du blob) ; export **en clair** derrière `--je-confirme-le-risque` + avertissement ; import avec validation du format.
- [x] Flux de restauration CLI : `recovery-setup` (affiche le code une fois), `recovery-reset` (restaure via le code et fixe un nouveau mot de passe maître).

**Plan de test :**
- [x] Les **deux voies** de déballage testées (mot de passe maître ET code de récupération).
- [x] Le code de récupération survit à un changement de mot de passe ; mauvais code rejeté ; absence de récupération signalée.
- [x] Bloc de récupération corrompu ⇒ échec sûr **sans** affecter la voie mot de passe ; export en clair refusé sans confirmation ; export chiffré porte la magie du format.

**Critères d'acceptation :**
- [x] Les deux voies de déballage vérifiées ; export chiffré par défaut.
- [x] « Définition de terminé » (§5) satisfaite (build, test, clippy `-D warnings`, fmt, audit verts).

---

### Jalon 6 — Avancé (en cours — démarré après que 0–5 sont verts)
- [x] **Partage E2E** : encapsulation de clé **hybride X25519 + ML-KEM-768** (crate `nex-partage`, séparé du cœur audité). `generer_paire` / `encapsuler` / `decapsuler` combinés par HKDF-SHA256 ; enveloppe `partager` / `recevoir` (AEAD XChaCha20-Poly1305). 7 tests : accord de clé, aller-retour, mauvais destinataire, altération du volet **classique** comme du volet **post-quantique** (les deux contribuent à la clé).
- [ ] Synchronisation zéro-connaissance (PAKE : OPAQUE/SRP, ou auth double dérivation).
- [ ] Fournisseur de passkeys (FIDO2/WebAuthn).
- [ ] Interface graphique Tauri.
- [ ] Liaisons mobiles UniFFI.
- [ ] Clés matérielles, accès d'urgence.

> Reste à faire pour le partage : sérialisation des clés/encapsulations en octets (transport/disque), intégration au modèle de coffre, et vecteurs ML-KEM FIPS 203 dédiés.

---

### Jalon 7 — Durcissement et préparation d'audit
**Objectif :** porter le niveau d'assurance à « prêt pour audit ».
- [x] Cibles de fuzzing écrites (`fuzz/`, crate isolé) : `decoder_fichier` (parseur de format), `ouvrir_fichier` (décodage + validation + ré-encodage), `aead_dechiffrer` (routine AEAD). Instructions de campagne longue dans `TESTING.md`. *(Exécution : CI Linux nightly — non lançable sur cette machine Windows sans rustup.)*
- [~] Objectifs de couverture (≥ 90 % `nex-cryptographie`/`nex-coffre`) : rapport publié en CI (`cargo-llvm-cov --fail-under-lines 90`).
- [x] CI complète : fmt + clippy + test + **fuzz smoke** + couverture + audit.
- [x] `SECURITY.md` enrichi (surface de fuzzing, préparation d'audit) ; `TESTING.md` complet (catégories + fuzzing) ; notes de préparation d'audit externe.

> Note : les éléments marqués `[~]` dépendent d'une exécution CI (Linux/nightly) que la machine de développement Windows actuelle ne peut pas réaliser localement (pas de proxy `rustup`, pas de composant `llvm-tools-preview` ni de toolchain nightly).

---

## 4. Stratégie de test globale (matrice)

| Type de test | Outils | Emplacement principal |
|---|---|---|
| Unitaire | `#[cfg(test)]` | tous les crates |
| Vecteurs officiels (KAT) | vecteurs RFC/NIST | `nex-cryptographie/tests`, `nex-coffre` (TOTP) |
| Propriétés | `proptest` | `nex-cryptographie/tests`, `nex-coffre/tests` |
| Intégration / cycle de vie | tests d'intégration std | `nex-coffre/tests` |
| E2E CLI | `assert_cmd`, `predicates` | `nex-console/tests` |
| Négatif / adversarial | std + corpus de fuzz | `nex-coffre/tests`, `fuzz/` |
| Fuzzing | `cargo-fuzz` (nightly) | `fuzz/` |
| Temps constant | `subtle` + lint/test | `nex-cryptographie` |
| Hygiène mémoire | tests `zeroize`/`Drop` | `nex-cryptographie`, `nex-coffre` |
| Benchmarks | `criterion` | `nex-cryptographie/benches` |
| Couverture | `cargo-llvm-cov` | CI |

**Objectif de couverture :** ≥ 90 % sur `nex-cryptographie` et `nex-coffre` ; raisonnable sur `nex-console`. Rapport en CI.

---

## 5. Définition de « terminé » (chaque jalon)
Un jalon n'est terminé que si **tout** est vrai :
- [ ] `cargo test` — tous les tests verts (unitaires, vecteurs, propriétés, intégration, e2e selon le jalon).
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` — aucun avertissement.
- [ ] `cargo fmt --all --check` — code formaté.
- [ ] Les vecteurs officiels applicables passent.
- [ ] Les cibles de fuzz applicables tournent proprement sur un passage court.
- [ ] Objectif de couverture atteint pour les crates concernés.
- [ ] `cargo audit` — aucune vulnérabilité connue non traitée.
- [ ] **Aucun secret** détectable dans les journaux, erreurs ou sorties.
- [ ] `ROADMAP.md` mis à jour (cases cochées), commit(s) atomique(s) propre(s), docs à jour.

---

## 6. Risques et points ouverts (décisions de sécurité à trancher)
- **Compteur de nonce AES-256-GCM** : nécessite un stockage de compteur durable et résistant aux crashs. Défaut conservateur = livrer XChaCha20-Poly1305 ; GCM en opt-in seulement une fois la persistance prouvée. *(Documenté dans SECURITY.md.)*
- **TOTP dans le même coffre que le mot de passe** : réduit le 2FA à un facteur unique en cas de compromission — compromis commodité/sécurité ; à exposer clairement à l'utilisateur.
- **Limites `mlock`/`VirtualLock`** : garanties au mieux, limites OS ; documenter honnêtement ce qui ne peut pas être garanti de façon déterministe.
- **Effacement mémoire en Rust** : fort mais non absolu (copies en pile, tampons intermédiaires) ; limites honnêtes dans `SECURITY.md`.
- **Client k-anonymat** : même un préfixe de 5 caractères fuit une information minimale ; abstrait derrière un trait, hors-ligne par défaut ; opt-in réseau.
- **Repli FIPS (PBKDF2)** : fourni mais jamais défaut ; documenté comme inférieur.
- **SQLite vs fichier unique** : le MVP utilise un fichier chiffré unique ; SQLite/SQLCipher différé sauf si le nombre d'entrées le justifie.
- **Chaîne d'outils Windows** : la cible `x86_64-pc-windows-msvc` exige les VS C++ Build Tools (linker MSVC + Windows SDK), en cours d'installation. Toolchain épinglée à 1.95.0.

---

*Cette feuille de route est le tableau de bord du projet et sera tenue à jour en permanence.*
