# SYNC_PWA_ROADMAP — Synchronisation multi-appareils + PWA + second facteur

> Objectif utilisateur : **un compte, n'importe quel appareil (iPhone, Android,
> PC) → tous mes mots de passe**, gratuitement, en restant **zéro-connaissance**,
> avec une **sécurité renforcée** (second facteur).
>
> **Statut : EN ATTENTE DE VALIDATION.** Aucun code n'est écrit avant ton feu vert.

---

## 0. Décisions actées (par tes choix)

| Sujet | Décision |
|-------|----------|
| Couverture appareils | iPhone **+** Android **+** PC |
| Pas de Mac / pas de budget store | → **PWA** (web installable, sans App Store/Play Store) |
| Hébergement serveur | **Local d'abord** (déployable ensuite sur un petit VPS) |
| Second facteur | **Oui** — fichier-clé (ajouté au cœur Rust) |
| Langue | Français, identifiants compris (inchangé) |

---

## 1. Honnêteté sécurité (à lire avant tout)

Ce programme **augmente le confort** (multi-appareils) et **renforce un axe**
(second facteur), mais **introduit deux surfaces d'attaque** absentes de l'app
native locale. À assumer :

1. **PWA = code web re-téléchargé.** Un serveur compromis, un XSS ou un MITM TLS
   pourrait servir un JS modifié qui **capte le mot de passe maître à la frappe**,
   avant le WASM. Le second facteur **ne protège pas** de ça (le JS pourrait
   capter les deux). → Mitigations : **auto-hébergement**, **CSP stricte**,
   **intégrité des ressources (SRI)**, zéro CDN tiers, crypto en **WASM**,
   service worker figé. C'est le maillon le plus faible : **assumé**.
2. **Effacement mémoire** dans le navigateur : « au mieux » (GC JS).
3. **Serveur de synchro** : il ne voit que du **chiffré** + un **hash d'auth**
   (jamais le mot de passe ni la clé). En cas de fuite serveur, l'attaquant a des
   blobs chiffrés → brute-force **hors-ligne** borné par Argon2id **ET** rendu
   **inopérant par le fichier-clé** (jamais envoyé au serveur). Reste exposé :
   **métadonnées** (identité du compte, taille, horodatage, IP).

> Où chaque protection agit :
> - **App native (PC, Android)** : modèle fort conservé.
> - **PWA (surtout iPhone)** : modèle web, plus faible, mitigé.
> - **Fichier-clé** : protège le scénario « blob volé » (serveur ou fichier),
>   pas un client déjà piégé.

---

## 2. Architecture cible

```
            ┌─────────────────────────────────────────────┐
            │   Serveur de synchro zéro-connaissance        │
            │   (ne stocke que : verif. d'auth + blob        │
            │    chiffré + version)                          │
            └───────────────▲───────────────▲───────────────┘
                            │ HTTPS          │ HTTPS
              push/pull blob │                │ push/pull blob
          ┌─────────────────┴───┐      ┌──────┴──────────────────┐
          │ App native (PC,     │      │ PWA (iPhone, Android, PC │
          │ Android) — Rust      │      │ navigateur) — cœur Rust  │
          │ cœur en backend      │      │ compilé en **WASM**      │
          │ coffre fichier local │      │ coffre chiffré IndexedDB │
          └──────────────────────┘      └──────────────────────────┘

Compte = email + mot de passe maître (+ fichier-clé).
  mot de passe maître ─Argon2id─▶ (1) clé de chiffrement (reste locale)
                                  (2) hash d'authentification (→ serveur)
```

- **Même format de coffre partout** (le `.vault` chiffré actuel) → un blob unique
  synchronisé. Pas de refonte du modèle de données.
- Le serveur ne déchiffre jamais : zéro-connaissance.

---

## 3. Jalons (série S)

> Règle inchangée : tests à chaque jalon ; on n'enchaîne pas tant que le
> précédent n'est pas vert.

### S0 — Second facteur (fichier-clé) dans le cœur **[TDD]**
- `nex-cryptographie`/`nex-coffre` : dérivation de la KEK à partir de
  **mot de passe maître + secret du fichier-clé** (le fichier-clé est un secret
  aléatoire haute entropie ; combiné via HKDF après Argon2id). Génération d'un
  fichier-clé, déverrouillage à deux facteurs, compat. ascendante (coffres sans
  fichier-clé continuent de marcher).
- **Tests** : vecteurs, aller-retour, mauvais fichier-clé → échec sûr, coffre
  sans second facteur inchangé. CLI : option `--fichier-cle`.
- **Acceptation** : un coffre à deux facteurs est inviolable sans le fichier-clé.

### S1 — Serveur de synchro zéro-connaissance (`crates/nex-serveur-sync`)
- API HTTP (local) : `s_inscrire`, `se_connecter`→jeton, `tirer` (blob+version),
  `pousser` (blob+version, **409 conflit** si version périmée). Stockage des
  blobs chiffrés + vérificateur d'auth (réutilise `nex-sync`). Limitation de
  débit, journaux **sans secret**.
- **Tests d'intégration** : inscription, auth correcte/incorrecte, push/pull,
  conflit de version, le serveur **ne stocke jamais** de clair (test dédié).

### S2 — Câblage synchro dans l'app de bureau
- Compte (email + mot de passe maître), connexion, **pousser/tirer**, résolution
  de conflit (garder local / distant / fusion manuelle). Réglages : URL du
  serveur. Tests d'intégration des commandes.

### S3 — Cœur en WebAssembly
- Compiler `nex-cryptographie`/`nex-coffre` en **wasm32** (`wasm-pack`,
  `wasm-bindgen`, `getrandom` feature `js`). Surface WASM minimale (créer,
  déverrouiller, lister, révéler, ajouter…). **Tests** : `wasm-bindgen-test`
  (vecteurs crypto identiques au natif).

### S4 — Squelette PWA (`apps/nexkeylock-pwa`)
- Vite + React/TS (UI **réutilisée** des composants existants) + **manifest** +
  **service worker** (offline) + **CSP stricte / SRI**. Couche « pont-WASM »
  (remplace l'`invoke` Tauri). Coffre chiffré en **IndexedDB**.
- **Tests** : build, CSP interdit tout script distant, pont-WASM crée/ouvre un
  coffre en mémoire.

### S5 — PWA fonctionnelle
- Écrans réutilisés (création, (dé)verrouillage avec **fichier-clé**, coffre,
  ajout/édition, générateur, tableau de bord). **Client de synchro** vers le
  serveur (compte, push/pull, conflit).
- **Tests** : composants + parcours (création→sync→déverrouillage sur « autre
  appareil » simulé), aucun secret en stockage **en clair**.

### S6 — Durcissement PWA & sécurité
- CSP/SRI verrouillés, service worker épinglé, **WebAuthn** pour le déverrouillage
  biométrique (Face ID/empreinte, sans store), verrouillage auto, effacement
  presse-papiers. **Tests sécurité + axe**.

### S7 — Déploiement & doc
- Guide d'auto-hébergement (serveur + PWA servie en **HTTPS**), car le multi-
  appareils réel n'opère qu'une fois **déployé** (le « local » ne traverse pas
  Internet). Sauvegardes, rotation, signature/notarisation hors-périmètre.

---

## 4. Plan de test (récapitulatif)
- **Cœur** (S0/S3) : vecteurs crypto, fichier-clé, parité natif/WASM.
- **Serveur** (S1) : intégration API, zéro-clair stocké, conflits.
- **Desktop/PWA** (S2/S5) : intégration commandes, parcours, sécurité (pas de
  secret en clair, CSP, auto-lock), accessibilité.

## 5. Définition de « terminé »
Même compte → tous les mots de passe sur iPhone/Android/PC ; serveur zéro-
connaissance (aucun clair, testé) ; second facteur opérationnel ; PWA durcie
(CSP/SRI, WASM, offline) ; suites de tests vertes ; `clippy -D warnings`, `fmt`,
lint/format front propres ; roadmaps et docs à jour ; compromis de sécurité §1
écrits et assumés.

## 6. Questions ouvertes (à trancher avec toi)
1. **Compte** : un identifiant **email** te convient, ou un simple nom d'utilisateur ?
2. **Desktop** : l'app native doit-elle **aussi** se synchroniser via le serveur
   (recommandé, même compte partout) — ou rester purement locale, la PWA servant
   au multi-appareils ?
3. **Ordre** : je propose de commencer par **S0 (fichier-clé)** puis **S1
   (serveur)** — d'accord, ou tu préfères voir la PWA en premier ?
4. **Fichier-clé sur la PWA** : comment le fournir (import manuel du fichier à
   chaque appareil) — on en reparle au moment de S5.
```
