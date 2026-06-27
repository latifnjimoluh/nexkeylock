# Rapport d'audit de sécurité — nexkeylock

> **Auditeur** : revue de sécurité indépendante (cryptographie appliquée + Rust).
> **Périmètre** : intégralité du dépôt (cœur `nex-cryptographie`, `nex-coffre`,
> CLI `nex-console`, crates avancés `nex-partage`/`nex-sync`/`nex-passkey`/
> `nex-urgence`, tests, CI, dépendances, documentation).
> **Posture** : lecture seule du code du projet ; toute affirmation est étayée
> par un emplacement précis et/ou une commande reproductible. Les preuves de
> vérification autonome sont dans [`audit/verification-crypto.md`](audit/verification-crypto.md).
> **Date** : 2026-06-27. **Toolchain** : Rust 1.95.0 (stable, MSVC).

---

## 1. Résumé exécutif

nexkeylock est un gestionnaire de mots de passe à architecture zéro-connaissance
dont le **cœur cryptographique est correct, complet et sobre**. Le projet
respecte sa règle d'or — il **assemble des primitives auditées** (RustCrypto,
dalek) sans réinventer de cryptographie — et l'assemblage est, sur les points
critiques, **correctement réalisé** : Argon2id réel avec paramètres dans
l'en-tête, AEAD partout (jamais de chiffrement non authentifié), hiérarchie
KEK/DEK avec réemballage au changement de mot de passe, en-tête authentifié via
AAD, comparaisons à temps constant, effacement mémoire, échec sûr, et absence de
réutilisation de nonce. La suite de tests est **substantielle et non
tautologique** (vecteurs officiels authentiques, propriétés, cas adversariaux,
e2e anti-fuite, fuzzing).

**Aucun constat critique ni élevé n'a été identifié.** Les constats sont de
sévérité **moyenne ou inférieure**, et concernent principalement des **écarts
entre la documentation et la réalité du code** (fonctions de durcissement
annoncées mais non implémentées) ainsi que des points de durcissement résiduels.

**Décompte des constats :** Critique 0 · Élevée 0 · Moyenne 2 · Faible 3 ·
Informative 3.

**Cinq points les plus prioritaires :**

1. **`SECURITY.md` sur-claim — verrouillage mémoire (`mlock`/`VirtualLock`)** :
   annoncé en §4, **non implémenté** (la dépendance `region` est déclarée mais
   jamais utilisée). [AUDIT-001, Moyenne]
2. **`SECURITY.md` sur-claim — désactivation des core dumps** : annoncée en §4,
   **non implémentée**. [AUDIT-002, Moyenne]
3. **`ContenuCoffre` dérive `Debug`** et ses champs `identite_partage` /
   `passkeys` portent des **clés privées brutes non expurgées** : fuite latente
   si l'objet est un jour journalisé. [AUDIT-003, Faible]
4. **Dépendances déclarées mais inutilisées** (`region`, `secrecy`, `rusqlite`)
   et `secrecy` cité dans la doc alors que seul `zeroize` est employé.
   [AUDIT-004, Faible]
5. **Conformité ML-KEM-768 (FIPS 203) déléguée** à la crate `ml-kem` 0.2, sans
   vecteur NIST ACVP en interne (seulement un test de déterminisme). À traiter
   comme **risque résiduel** documenté. [AUDIT-008, Faible]

---

## 2. Verdict

### PRÊT SOUS CONDITIONS

Le cœur livrable (Jalons 0–5) est cryptographiquement sain et conforme à la
spécification **vérifiée**. Les conditions **bloquantes** ci-dessous étaient de
nature *honnêteté documentaire / durcissement*, aucune ne touchant la correction
cryptographique. **Mise à jour : les trois conditions C1, C2 et C3 ont été levées
sur la branche `durcissement-memoire-c1`** (build/test/clippy `-D warnings`/fmt/
audit verts localement ; la branche Unix du durcissement core-dumps est vérifiée
par la CI Linux). Sous réserve de fusion de cette branche, le verdict passe à
**« CONFORME À LA SPÉCIFICATION VÉRIFIÉE »** — l'audit tiers professionnel
restant requis avant tout usage réel (cf. rappel ci-dessous).

- **C1. ✅ LEVÉE** (branche `durcissement-memoire-c1`) : durcissement
  **implémenté** — verrouillage de page best-effort des clés (`region`, compté
  par page) + désactivation des core dumps (Unix `RLIMIT_CORE=0` ; Windows
  non-op documentée), et `SECURITY.md` §4 réécrit pour décrire précisément les
  garanties et leurs limites (AUDIT-001, AUDIT-002 résolus). Vérifié :
  `cargo test`/`clippy -D warnings`/`fmt`/`audit` verts.
- **C2. ✅ LEVÉE** (branche `durcissement-memoire-c1`) : `Debug` de
  `ContenuCoffre` réimplémenté manuellement (expurgé) — les clés privées
  `identite_partage`/`passkeys` ne sont plus divulguables ; test de non-fuite
  ajouté (AUDIT-003 résolu).
- **C3. ✅ LEVÉE** (branche `durcissement-memoire-c1`) : `secrecy` et `rusqlite`
  **retirés** de `[workspace.dependencies]` (`rusqlite` documenté comme différé) ;
  mentions `secrecy` corrigées dans `SECURITY.md`, `README.md` et `ROADMAP.md`.
  `region` n'est plus inutilisée (employée par C1). `Cargo.toml`/docs reflètent
  désormais le code réel. Vérifié : `build`/`test`/`clippy`/`audit` verts
  (AUDIT-004 résolu).

> **Rappel d'honnêteté épistémique.** Cet audit **vérifie** la conformité du
> code à la spécification et l'exécution correcte des primitives ; il ne
> **certifie pas** une sécurité parfaite. Un **audit cryptographique
> professionnel par un tiers indépendant reste indispensable avant tout usage
> réel**, de même qu'une revue des points hors périmètre (appareil compromis
> coffre déverrouillé, §2 de `SECURITY.md`) et des limites d'effacement mémoire.

---

## 3. Matrice des contraintes NON NÉGOCIABLES

| Contrainte | Statut | Preuve / observation |
|---|---|---|
| **Dérivation de clé** | | |
| Argon2id réellement utilisé (pas de repli rapide) | ✅ CONFORME | `kdf.rs:84` `Argon2::new(Algorithm::Argon2id, V0x13, …)`. |
| Paramètres `m,t,p`, sel, algo lus dans l'en-tête (migration possible) | ✅ CONFORME | `entete.rs:33-48` + `coffre.rs:73` (`parametres_kdf()` depuis l'en-tête). |
| Défauts ≥ minimum recommandé, cible ~0,5 s calibrée | ✅ CONFORME | `kdf.rs:18-22` (256 Mio, t=3, p=4) ; bench `benches/calibration.rs` ; ROADMAP : ~688 ms mesuré. |
| Sel ≥ 16 o, CSPRNG, unique/coffre, en clair (non secret) | ✅ CONFORME | `coffre.rs:31,200` (`LONGUEUR_SEL=16`, `octets_aleatoires`). |
| Sortie KDF = KEK uniquement (jamais clé de données directe) | ✅ CONFORME | KEK emballe une DEK aléatoire indépendante (`coffre.rs:204-207`). |
| **Chiffrement authentifié** | | |
| Tout chiffrement est AEAD ; aucun ECB/CBC/CTR sans MAC | ✅ CONFORME | `aead.rs` : seuls XChaCha20-Poly1305 / AES-256-GCM ; aucune autre primitive de chiffrement dans le dépôt. |
| Défaut XChaCha20-Poly1305 ; `id_algorithme` par blob | ✅ CONFORME | `coffre.rs:199` ; octet d'algo dans l'en-tête (`entete.rs:37`). |
| Aucun chemin de réutilisation de nonce | ✅ CONFORME | XChaCha : nonce 192 bits CSPRNG (`aead.rs:75`). AES-GCM : **création refusée** faute de compteur persistant (`coffre.rs:461-465`) — pas de génération de nonce GCM. |
| **Hiérarchie des clés** | | |
| DEK aléatoire CSPRNG, unique, emballée par la KEK | ✅ CONFORME | `coffre.rs:205-207`. |
| Changement de mot de passe = réemballage DEK ; ancien rejeté | ✅ CONFORME | `coffre.rs:367-392` ; test `changement_de_mot_de_passe_reemballe_la_dek`. |
| HKDF-SHA256 avec étiquette de contexte ; pas de réutilisation d'usage | ✅ CONFORME | `hkdf_subcle.rs` ; contextes distincts en sync (`auth.rs:23-27`). |
| **Aléa** | | |
| CSPRNG système uniquement ; aucun PRNG non crypto pour secrets | ✅ CONFORME | `alea.rs` (`OsRng`/`getrandom`). `StdRng` n'apparaît **que** dans un test de déterminisme ML-KEM (`hybride.rs:329`). |
| **Hygiène des secrets** | | |
| Secrets en types à effacement réel | ✅ CONFORME | `CleSecrete` (`Zeroize`+`ZeroizeOnDrop`), `Zeroizing` aux frontières, `Entree`/`ContenuCoffre` `ZeroizeOnDrop`. |
| `mlock`/`VirtualLock` présent là où annoncé ; core dumps désactivés | ✅ CONFORME *(corrigé, branche `durcissement-memoire-c1`)* | Verrouillage de page best-effort des tampons `CleSecrete` (compté par page, `secret.rs::verrou_pages`) ; core dumps désactivés sous Unix (`RLIMIT_CORE=0`, `durcissement.rs`), non-op documentée sous Windows. Voir **AUDIT-001/002 (résolus)**. |
| Comparaisons de secrets à temps constant (`subtle`), jamais `==` | ✅ CONFORME | `secret.rs:68-79` (`ct_eq`) ; vérificateur sync compare des `CleSecrete` (`auth.rs:78`). |
| Aucun secret dans logs/erreurs/`Debug`/`Display` | ✅ CONFORME *(corrigé, branche `durcissement-memoire-c1`)* | `CleSecrete`, `Entree` **et désormais `ContenuCoffre`** ont un `Debug` manuel expurgé (les clés privées `identite_partage`/`passkeys` ne sont plus affichées) ; erreurs sans secret. Voir **AUDIT-003 (résolu)**. |
| Presse-papiers effacé après délai | ⚠️ PARTIEL | Implémenté derrière le trait `PressePapiers` (`presse_papiers.rs`), mais **fonctionnalité désactivée par défaut** et effacement bloquant best-effort. **AUDIT-005**. |
| **Format et robustesse** | | |
| En-tête versionné et authentifié (AAD) ; un octet falsifié ⇒ échec | ✅ CONFORME | `entete.rs` (deux AAD) ; `coffre.rs:76-85` utilise `entete_brut` exact comme AAD ; tests d'altération de bit. |
| Échec sûr : erreur typée, aucune donnée partielle, aucun panic | ✅ CONFORME | `erreurs.rs` ; `format.rs` borné ; proptest `toute_alteration_d_un_bit_echoue` ; cibles de fuzz. |
| Downgrade de version/algo rejeté | ✅ CONFORME | `entete.rs:70-79` ; tests `downgrade_de_version_rejete`, `substitution_d_algorithme_rejetee`. |
| **Architecture zéro-connaissance (sync présente)** | | |
| Mot de passe maître / hash réutilisable hors-ligne ne quitte jamais le client | ✅ CONFORME | `auth.rs` : double dérivation HKDF, seul un *hash d'authentification* part ; serveur ne stocke qu'un vérificateur salé. |
| Serveur ne voit que des blobs chiffrés ; métadonnées minimales | ✅ CONFORME | `depot.rs` (blob opaque + révision) ; test `integration_sync.rs:42` (aucun clair). |

---

## 4. Tableau récapitulatif des constats

| ID | Titre | Sévérité | Emplacement | Statut |
|---|---|---|---|---|
| AUDIT-001 | `mlock`/`VirtualLock` annoncé, non implémenté | Moyenne | `SECURITY.md:39` ; `Cargo.toml:61` | **Corrigé** (`durcissement-memoire-c1`) |
| AUDIT-002 | Désactivation des core dumps annoncée, non implémentée | Moyenne | `SECURITY.md:40` | **Corrigé** (`durcissement-memoire-c1`) |
| AUDIT-003 | `Debug` dérivé sur `ContenuCoffre` expose des clés privées | Faible | `modele.rs:89-100` | **Corrigé** (`durcissement-memoire-c1`) |
| AUDIT-004 | Dépendances inutilisées (`region`,`secrecy`,`rusqlite`) ; `secrecy` cité en doc | Faible | `Cargo.toml:59-65` ; `SECURITY.md:38` | **Corrigé** (`durcissement-memoire-c1`) |
| AUDIT-005 | Effacement presse-papiers bloquant, best-effort, off par défaut | Faible | `presse_papiers.rs:24-30` | Ouvert |
| AUDIT-006 | Combinateur KEM hybride sans liaison de transcript ; X25519 non contributif | Informative | `hybride.rs:67-81,121` | Ouvert |
| AUDIT-007 | Paramètres KDF du bloc de récupération non couverts par l'AAD | Informative | `coffre.rs:135-143` ; `format.rs:32-46` | Ouvert |
| AUDIT-008 | Conformité ML-KEM (FIPS 203) déléguée, sans KAT NIST ACVP interne | Faible | `hybride.rs:322-336` ; `SECURITY.md:71` | Accepté/documenté |

---

## 5. Constats détaillés

### AUDIT-001 — `mlock`/`VirtualLock` annoncé mais non implémenté
- **Sévérité** : Moyenne (lacune de défense en profondeur + sur-claim de doc).
- **Emplacement** : `SECURITY.md:39`, `ROADMAP.md` §choix crypto, `Cargo.toml:61`.
- **Description** : `SECURITY.md` §4 affirme « Verrouillage des pages
  (`mlock`/`VirtualLock`) lorsque la plateforme le permet ». Aucune ligne de code
  n'appelle `region`, `mlock`, `VirtualLock` ni équivalent. La dépendance
  `region = "3.0.2"` est déclarée dans `[workspace.dependencies]` mais **aucun
  crate ne la tire** (vérifié sur chaque `crates/*/Cargo.toml`).
- **Preuve** : `Grep "region|mlock|VirtualLock"` → uniquement `Cargo.toml:61` et
  le mot « region » de la liste EFF. Aucune occurrence dans `*/src/`.
- **Impact** : les pages contenant KEK/DEK/clair peuvent être paginées sur le
  disque (swap), élargissant la fenêtre d'exposition au-delà de ce que la doc
  laisse croire. Le risque réel est modéré (l'effacement `zeroize` demeure), mais
  l'écart documentation/réalité induit une **fausse assurance**.
- **Recommandation** : soit câbler `region::lock` sur les tampons sensibles
  (best-effort, en gérant les échecs OS), soit reformuler `SECURITY.md` en
  « **non implémenté à ce stade** » plutôt que « lorsque la plateforme le permet ».
- **Remédiation appliquée** (`durcissement-memoire-c1`) : `CleSecrete` alloue son
  tampon sur le tas (adresse stable) et verrouille sa page via `region`, avec un
  **registre compté par page** (`secret.rs::verrou_pages`) qui évite tout
  déverrouillage prématuré d'une page partagée par plusieurs secrets vivants.
  Échecs OS ignorés (best-effort). Effacement effectué **avant** déverrouillage.
  Tests ajoutés (clone, zeroize, stress multi-pages) ; suite verte.

### AUDIT-002 — Désactivation des core dumps annoncée mais non implémentée
- **Sévérité** : Moyenne (sur-claim de doc + défense en profondeur).
- **Emplacement** : `SECURITY.md:40`.
- **Description** : §4 affirme « Désactivation des core dumps pour le processus ».
  Aucun appel `setrlimit(RLIMIT_CORE, 0)`, `prctl(PR_SET_DUMPABLE)` ni équivalent
  Windows n'existe dans le code.
- **Preuve** : `Grep "rlimit|core.?dump|dumpable"` → aucune occurrence en `src/`.
- **Impact** : un plantage pourrait produire un vidage mémoire contenant des
  secrets. Probabilité faible, mais l'affirmation est inexacte.
- **Recommandation** : implémenter la désactivation (au moins sous Unix) ou
  retirer/atténuer l'affirmation dans `SECURITY.md`.
- **Remédiation appliquée** (`durcissement-memoire-c1`) : module
  `nex-console/src/durcissement.rs` appelé au tout début de `main`. Sous Unix,
  `setrlimit(RLIMIT_CORE, {0,0})` (unique bloc `unsafe` du crate, audité et
  documenté). Sous Windows, non-opération assumée (WER relève de la politique
  système). `SECURITY.md` §4 précise désormais cette limite plateforme.
  *Note : la branche Unix est compilée/vérifiée par la CI Linux ; non
  compilable localement sur cette machine Windows (cfg(unix)).*

### AUDIT-003 — `Debug` dérivé sur `ContenuCoffre` expose des clés privées
- **Sévérité** : Faible (latent : non imprimé en interne).
- **Emplacement** : `modele.rs:89-100`.
- **Description** : `ContenuCoffre` porte `#[derive(Debug)]`. Les entrées
  (`Entree`) ont un `Debug` **expurgé**, mais les champs `identite_partage:
  Option<Vec<u8>>` et `passkeys: Vec<Vec<u8>>` contiennent des **clés privées
  sérialisées en clair** (X25519 + ML-KEM, graines Ed25519). Le `Debug` dérivé
  les afficherait **intégralement** en octets.
- **Preuve** : `modele.rs:89` `#[derive(Debug, …)]` ; champs `identite_partage`
  (l.96) et `passkeys` (l.99) non couverts par une expurgation. `CoffreDeverrouille`
  a un `Debug` manuel qui n'imprime pas `contenu` (`coffre.rs:446-455`), donc la
  fuite n'est **pas** déclenchée aujourd'hui en interne (`Grep` : `ContenuCoffre`
  n'est `{:?}`-formaté nulle part dans `nex-console`).
- **Impact** : si un futur code (ou un consommateur de la bibliothèque) imprime
  un `ContenuCoffre` en `Debug`, les clés privées de partage et de passkeys
  fuient dans les journaux. Incohérent avec la discipline « `Debug` expurgé »
  appliquée ailleurs.
- **Recommandation** : remplacer le `Debug` dérivé par une implémentation
  manuelle expurgée (comme `Entree`), ou retirer `Debug` de `ContenuCoffre`.
- **Remédiation appliquée** (`durcissement-memoire-c1`) : `Debug` retiré du
  `derive` et **implémenté manuellement** sur `ContenuCoffre` — `entrees` passe
  par le `Debug` expurgé d'`Entree`, `identite_partage` n'affiche que `***` (ou
  son absence), `passkeys` n'expose que son nombre. Test ajouté
  (`debug_contenu_n_expose_pas_les_cles_privees`) vérifiant qu'aucun octet de clé
  ni mot de passe n'apparaît. Suite verte.

### AUDIT-004 — Dépendances déclarées inutilisées et mention `secrecy`
- **Sévérité** : Faible (hygiène / fidélité doc).
- **Emplacement** : `Cargo.toml:59,61,65` ; `SECURITY.md:38`.
- **Description** : `secrecy`, `region`, `rusqlite` figurent dans
  `[workspace.dependencies]` mais **aucun crate ne les référence**. `SECURITY.md`
  §4 mentionne « `zeroize`/`secrecy` » alors que seul `zeroize` est employé
  (le projet utilise son propre type `CleSecrete`).
- **Preuve** : `crates/*/Cargo.toml` ne listent ni `secrecy`, ni `region`, ni
  `rusqlite` ; `Grep` ne trouve aucun `use secrecy`/`use rusqlite`.
- **Impact** : surface d'audit/confusion inutile ; affirmation de doc
  partiellement inexacte. `rusqlite` est explicitement différé (MVP fichier), ce
  qui est cohérent — mais la déclaration centrale devrait le refléter.
- **Recommandation** : retirer les déclarations non utilisées (ou les commenter
  comme « réservées, non encore tirées ») et corriger la mention `secrecy`.
- **Remédiation appliquée** (`durcissement-memoire-c1`) : `secrecy` et `rusqlite`
  retirés de `[workspace.dependencies]` (un commentaire signale que `rusqlite`
  sera réintroduit au jalon SQLite) ; mentions `secrecy` corrigées dans
  `SECURITY.md`, `README.md` et `ROADMAP.md`. `region` est désormais réellement
  employée (C1). Le doc de conception (`gestionnaire-mots-de-passe-conception.md`)
  est laissé tel quel : il décrit le **design visé** (pile candidate, dont
  SQLCipher), non l'état du code. `cargo build`/`audit` toujours verts.

### AUDIT-005 — Effacement du presse-papiers bloquant et désactivé par défaut
- **Sévérité** : Faible.
- **Emplacement** : `presse_papiers.rs:24-30` ; `main.rs:558-575`.
- **Description** : `copier_temporaire` fait `definir` → `std::thread::sleep`
  (bloquant) → `effacer`. Si le processus est tué pendant l'attente, le secret
  **reste** dans le presse-papiers. De plus, la fonctionnalité `presse-papiers`
  est **désactivée par défaut** : sans elle, `--copier` échoue proprement.
- **Impact** : garantie d'effacement non déterministe (interruption) ;
  l'utilisateur par défaut n'a pas du tout d'effacement (puisque le presse-papiers
  n'est pas compilé). Risque modéré, conforme au choix conservateur documenté.
- **Recommandation** : documenter clairement la limite (effacement best-effort,
  perdu si interruption) ; envisager un effacement plus robuste (processus
  détaché) si la fonctionnalité devient un défaut.

### AUDIT-006 — Combinateur KEM hybride sans liaison de transcript
- **Sévérité** : Informative.
- **Emplacement** : `hybride.rs:67-81` (`combiner`), `:121` (X25519 DH).
- **Description** : la clé partagée est `HKDF-SHA256(ss_x25519 || ss_mlkem)` avec
  une étiquette de contexte fixe. Le combinateur **ne lie pas** explicitement la
  clé publique éphémère X25519 ni le texte chiffré ML-KEM dans l'`ikm`/`info`
  (contrairement à X-Wing). Par ailleurs, `x25519-dalek` n'effectue pas de
  contrôle de point de petit ordre (DH non contributif : une clé éphémère
  malveillante peut forcer `ss_x = 0`).
- **Impact** : pour le modèle de menace actuel (scellement vers **un**
  destinataire puis AEAD), la sécurité tient — ML-KEM (IND-CCA2) lie déjà son
  texte chiffré dans son secret, et l'AEAD échoue si la clé diffère (tests
  `alteration_du_volet_*`). Le manque de liaison de transcript pourrait importer
  pour des propriétés avancées (engagement de clé, multi-destinataires).
- **Recommandation** : suivre la construction X-Wing — inclure `ek`, `ct_mlkem`
  et `x_eph_pub` dans l'entrée du HKDF. Amélioration de robustesse, non bloquante.

### AUDIT-007 — Paramètres KDF du bloc de récupération hors AAD
- **Sévérité** : Informative.
- **Emplacement** : `coffre.rs:135-143` ; `format.rs:32-46` (`BlocRecuperation`).
- **Description** : le second emballage de la DEK (voie code de récupération) est
  authentifié par `aad_corps` (version+algo) et le tag AEAD, mais le sel et les
  paramètres Argon2id du bloc sont stockés en clair et **ne sont pas couverts par
  l'AAD**.
- **Impact** : **non exploitable**. Toute altération du sel/des paramètres change
  la clé dérivée et provoque un échec d'authentification (déni de service sur la
  seule voie récupération, sans dégrader la voie mot de passe — testé). De plus,
  le code de récupération a 160 bits d'entropie : un abaissement des paramètres
  ne rend pas la force brute praticable.
- **Recommandation** : par robustesse, inclure les paramètres du bloc de
  récupération dans l'AAD de son propre emballage.

### AUDIT-008 — Conformité ML-KEM déléguée sans KAT NIST ACVP interne
- **Sévérité** : Faible (lacune de test / risque résiduel, documenté).
- **Emplacement** : `hybride.rs:322-336` ; `SECURITY.md:64-75`.
- **Description** : le projet **délègue honnêtement** la conformité FIPS 203 /
  NIST ACVP à la crate `ml-kem = "0.2"` et ne teste en interne que le
  déterminisme (même graine ⇒ même clé). Aucun vecteur officiel ML-KEM n'est
  rejoué localement, et `ml-kem` 0.2 est une crate relativement jeune.
- **Impact** : la garantie post-quantique repose entièrement sur une dépendance
  externe non rejouée par vecteurs dans ce dépôt. Acceptable pour un crate
  *avancé* séparé du cœur, mais c'est un point de confiance externe.
- **Recommandation** : ajouter au moins un KAT ML-KEM-768 (ACVP) en test
  d'intégration ; surveiller la maturité/versions de `ml-kem` via `cargo audit`.

---

## 6. Complétude fonctionnelle — annoncé vs réel

| Fonction (ROADMAP) | Annoncé | Réel (vérifié) | Écart |
|---|---|---|---|
| KDF Argon2id + agilité | ✅ | ✅ `kdf.rs`, paramètres en-tête | — |
| AEAD XChaCha20 (défaut) + AES-GCM | ✅ | ✅ `aead.rs` (GCM non créé, opt-in déchiffrement) | conforme au choix conservateur |
| HKDF sous-clés | ✅ | ✅ `hkdf_subcle.rs` | — |
| Hiérarchie KEK/DEK + changement mdp | ✅ | ✅ `coffre.rs` | — |
| Format versionné/authentifié, fail-closed | ✅ | ✅ `format.rs`/`entete.rs` | — |
| Générateur non biaisé + entropie | ✅ | ✅ `generateur.rs` (rejet d'échantillonnage `index_uniforme`) | — |
| Phrases diceware (EFF 7776) | ✅ | ✅ liste embarquée, 7776 mots uniques | — |
| TOTP RFC 6238 + Base32 | ✅ | ✅ `totp.rs`, vecteurs annexe B | — |
| Recherche / audit local (faibles/réutilisés/anciens) | ✅ | ✅ `audit.rs` | — |
| Surveillance fuites par k-anonymat | ✅ | ✅ préfixe SHA-1 de **5 car. uniquement** (`audit.rs:51-53`), trait mockable, aucun réseau en test | — |
| Code de récupération (double emballage DEK) | ✅ | ✅ survit au changement de mdp | — |
| Export/import chiffrés par défaut | ✅ | ✅ clair derrière `--je-confirme-le-risque` | — |
| CLI complète + e2e anti-fuite | ✅ | ✅ `nex-console`, e2e vérifie absence du mdp maître | — |
| Partage E2E hybride X25519+ML-KEM | ✅ | ✅ `nex-partage` (voir AUDIT-006/008) | binding transcript à renforcer |
| Sync zéro-connaissance (double dérivation) | ✅ | ✅ `nex-sync` | — |
| Passkeys (cœur Ed25519, anti-hameçonnage) | ✅ | ✅ `nex-passkey` (signature liée rp_id+origine) | périmètre CTAP2 hors scope (documenté) |
| Accès d'urgence (scellé + délai) | ✅ | ✅ `nex-urgence` | — |
| `mlock`/core dumps | « si disponible » | ❌ non implémenté | **AUDIT-001/002** |
| Clés matérielles / GUI Tauri / mobile UniFFI | ⬜ non faits | ⬜ non faits | cohérent (cases non cochées) |

---

## 7. Qualité de la suite de tests (méta-audit)

- **Vecteurs officiels** : présents pour Argon2id, ChaCha20/XChaCha20-Poly1305,
  AES-256-GCM (×2), HKDF-SHA256, TOTP — **constantes confrontées aux valeurs
  publiées et authentiques** (cf. `audit/verification-crypto.md` §2). Non
  tautologiques : un écart d'un octet ferait échouer.
- **Propriétés (`proptest`)** : aller-retour AEAD, altération d'un bit ⇒ échec
  obligatoire, nonces différents ⇒ sorties différentes, déterminisme KDF, et —
  côté coffre — **altération d'un bit quelconque** du fichier ⇒ échec sans panic.
- **Tests négatifs/adversariaux réels** : mauvais mot de passe, corps corrompu,
  troncature, magie corrompue, downgrade version/algo, bloc de récupération
  corrompu, mauvais destinataire/origine/défi (passkey), conflit de concurrence
  sync. Ce ne sont **pas** uniquement des chemins heureux.
- **e2e CLI** : vérifient explicitement que le **mot de passe maître n'apparaît
  pas** sur stdout/stderr (prédicats `.not()`), que `list` ne révèle aucun mot de
  passe d'entrée, et que l'export en clair exige confirmation.
- **Fuzzing** : trois cibles (`decoder_fichier`, `ouvrir_fichier`,
  `aead_dechiffrer`) ; passage court câblé en CI (`-max_total_time=20`).
  *Non exécutable localement (Windows sans nightly/rustup) — porté par la CI.*
- **Couverture** : objectif ≥ 90 % (`nex-cryptographie`/`nex-coffre`) via
  `cargo-llvm-cov --fail-under-lines 90` en CI. **Non reproductible localement**
  (composant `llvm-tools-preview` indisponible). Constat : la couverture chiffrée
  n'a pas pu être confirmée par l'auditeur (cf. §8) ; la suite paraît néanmoins
  exhaustive (toute fonction publique exercée).
- **CI** (`.github/workflows/ci.yml`) : exécute bien `fmt --check`,
  `clippy -D warnings`, `cargo test --workspace`, fuzz smoke nightly, couverture
  avec seuil, et `cargo audit`. Conforme à la « définition de terminé ».

**Exécution par l'auditeur** : `cargo test --workspace` → **tout vert** ;
`cargo clippy --all-targets --all-features -- -D warnings` → **0 avertissement** ;
`cargo audit` → **0 vulnérabilité sur 240 dépendances**.

---

## 8. Risques résiduels et limites de l'audit

- **Non reproduit localement** : la mesure de **couverture** (`cargo-llvm-cov`)
  et l'**exécution du fuzzing** (nightly) — environnement Windows sans `rustup`
  ni `llvm-tools-preview`. Ces portes reposent sur la CI ; l'auditeur n'a pas pu
  confirmer le chiffre ≥ 90 % ni un run de fuzz long.
- **Confiance externe** : la correction des primitives repose sur les crates
  RustCrypto/dalek/`ml-kem` (non réauditées ici). La conformité ML-KEM FIPS 203
  n'est pas rejouée en interne (AUDIT-008).
- **Effacement mémoire** : « fort mais non absolu » (copies en pile, tampons
  `serde`/`String`) — limite intrinsèque honnêtement documentée, **aggravée** par
  l'absence de `mlock` (AUDIT-001).
- **Hors périmètre fondamental** : appareil compromis pendant que le coffre est
  déverrouillé (keylogger, lecture mémoire) — limite partagée par tous les
  produits, documentée en `SECURITY.md` §2.
- **Analyse temps constant** : la propriété est assurée par construction
  (`subtle`) mais n'a pas été mesurée empiriquement (pas de test statistique de
  timing) ; l'auditeur l'a validée par revue de code, pas par instrumentation.
- Cet audit **n'est pas** un audit tiers professionnel formel : il vérifie la
  conformité à la spécification, sans garantie d'exhaustivité.

---

## 9. Plan de remédiation priorisé

**Bloquant (lever pour passer « PRÊT ») :**
1. **AUDIT-001 / AUDIT-002** — aligner `SECURITY.md` §4 sur la réalité :
   implémenter `mlock`/`VirtualLock` + désactivation des core dumps, **ou**
   reformuler en « non implémenté ». *(Effort : faible si reformulation ;
   moyen si implémentation multiplateforme.)*
2. **AUDIT-003** — `Debug` manuel expurgé (ou suppression de `Debug`) sur
   `ContenuCoffre`. *(Effort : faible.)*
3. **AUDIT-004** — purge des dépendances inutilisées + correction de la mention
   `secrecy`. *(Effort : faible.)*

**Important (durcissement) :**
4. **AUDIT-008** — ajouter un KAT ML-KEM-768 (NIST ACVP) en test. *(Effort : faible.)*
5. **AUDIT-005** — documenter/renforcer l'effacement du presse-papiers.
   *(Effort : faible à moyen.)*

**Souhaitable (robustesse) :**
6. **AUDIT-006** — lier le transcript d'encapsulation dans le HKDF (style
   X-Wing). *(Effort : faible.)*
7. **AUDIT-007** — inclure les paramètres du bloc de récupération dans son AAD.
   *(Effort : faible.)*

**Indépendant du code :** commander un **audit cryptographique tiers
professionnel** avant tout usage réel, et faire exécuter en CL les portes
couverture + fuzz long.

---

*Fin du rapport. Conformément au brief, aucun code du projet n'a été modifié ;
seuls `SECURITY_AUDIT.md` et `audit/` ont été ajoutés. L'auditeur attend vos
instructions avant toute remédiation (qui se ferait sur une branche dédiée, avec
tests de non-régression).*
