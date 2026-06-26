# Conception complète d'un gestionnaire de mots de passe moderne

**Document d'architecture et de mise en œuvre**
Version 1.0 — Juin 2026

---

## Table des matières

1. [Résumé exécutif](#1-résumé-exécutif)
2. [Principes de conception](#2-principes-de-conception)
3. [Modèle de menace](#3-modèle-de-menace)
4. [Architecture cryptographique](#4-architecture-cryptographique)
5. [Architecture « zéro-connaissance »](#5-architecture--zéro-connaissance-)
6. [Modèle de données et format du coffre](#6-modèle-de-données-et-format-du-coffre)
7. [Stockage et synchronisation](#7-stockage-et-synchronisation)
8. [Fonctionnalités de sécurité avancées](#8-fonctionnalités-de-sécurité-avancées)
9. [Authentification et déverrouillage](#9-authentification-et-déverrouillage)
10. [Sécurité mémoire et exécution](#10-sécurité-mémoire-et-exécution)
11. [Résistance post-quantique](#11-résistance-post-quantique)
12. [Choix technologiques](#12-choix-technologiques)
13. [Feuille de route d'implémentation](#13-feuille-de-route-dimplémentation)
14. [Tests, audit et assurance](#14-tests-audit-et-assurance)
15. [Sauvegarde et récupération](#15-sauvegarde-et-récupération)
16. [Pièges courants à éviter](#16-pièges-courants-à-éviter)
17. [Annexes](#17-annexes)

---

## 1. Résumé exécutif

Ce document décrit l'architecture complète d'un gestionnaire de mots de passe conçu selon les meilleures pratiques cryptographiques en vigueur en 2026. L'objectif est de construire un outil dans lequel **vous seul** pouvez déchiffrer vos données : aucun serveur, aucun fournisseur, aucun administrateur ne doit jamais avoir accès au contenu en clair.

Les piliers techniques retenus sont :

- **Dérivation de clé** par Argon2id (fonction mémoire-dure, lauréate de la compétition PHC 2015, normalisée RFC 9106).
- **Chiffrement authentifié** (AEAD) par XChaCha20-Poly1305 (ou AES-256-GCM) garantissant à la fois la confidentialité et l'intégrité.
- **Hiérarchie de clés à deux niveaux** (clé de chiffrement de clé / clé de chiffrement de données) permettant la rotation du mot de passe maître sans rechiffrer tout le coffre.
- **Architecture zéro-connaissance** : tout le chiffrement et le déchiffrement se font côté client.
- **Fonctions modernes** : génération de mots de passe à haute entropie, TOTP intégré, prise en charge des passkeys (FIDO2/WebAuthn), surveillance des fuites par k-anonymat, déverrouillage biométrique et clés matérielles.
- **Préparation post-quantique** : choix d'algorithmes résistants et plan de migration hybride.

> **Avertissement de principe.** La règle d'or de la cryptographie appliquée s'applique ici intégralement : **n'inventez jamais vos propres primitives cryptographiques**. Vous *concevez une architecture* et *assemblez* des primitives éprouvées au travers de bibliothèques auditées. Tout l'art réside dans l'assemblage correct, la gestion des clés et la discipline d'implémentation, pas dans l'invention d'un nouvel algorithme de chiffrement.

---

## 2. Principes de conception

Sept principes directeurs guident chaque décision technique du projet.

**Zéro-connaissance.** Le système est conçu de sorte qu'un serveur compromis, ou un opérateur malveillant, n'apprenne rien d'exploitable. Les clés de chiffrement ne quittent jamais l'appareil de l'utilisateur en clair.

**Défense en profondeur.** Aucune couche unique n'est supposée infaillible. Le chiffrement protège les données au repos ; le verrouillage automatique limite l'exposition en mémoire ; l'authentification multifacteur protège l'accès ; la séparation des clés limite l'impact d'une compromission partielle.

**Minimalisme de l'attaque de surface.** Chaque fonctionnalité ajoute du code et donc du risque. On préfère un cœur réduit, bien audité, plutôt qu'une accumulation de fonctions.

**Sécurité par défaut.** Les paramètres les plus sûrs sont activés sans action de l'utilisateur. La sécurité ne doit jamais dépendre d'un choix optionnel oublié.

**Échec sûr (*fail-safe*).** En cas d'erreur, de doute ou d'interruption, le système se verrouille plutôt que de rester ouvert. Une erreur de déchiffrement ne renvoie jamais de données partielles.

**Transparence et auditabilité.** Le code, surtout le cœur cryptographique, doit être lisible, documenté et idéalement ouvert à l'inspection. La sécurité par l'obscurité n'est pas de la sécurité.

**Agilité cryptographique.** Les algorithmes et les paramètres sont versionnés dans le format du coffre. On doit pouvoir migrer vers des paramètres plus forts (ou de nouveaux algorithmes, par exemple post-quantiques) sans casser les coffres existants.

---

## 3. Modèle de menace

Concevoir sans modèle de menace explicite revient à se protéger contre des ennemis imaginaires tout en ignorant les vrais. Voici ce que l'on protège, contre qui, et ce qui sort du périmètre.

### 3.1 Actifs à protéger

L'actif primaire est le **contenu du coffre** : identifiants, mots de passe, secrets TOTP, clés de passkeys, notes sécurisées, données de carte bancaire et d'identité. L'actif secondaire est la **métadonnée** : noms des sites, dates de modification, structure du coffre — souvent négligée, elle peut révéler beaucoup (par exemple, l'existence d'un compte chez un établissement sensible). Le **mot de passe maître** lui-même est l'actif racine dont dépendent tous les autres.

### 3.2 Adversaires considérés

| Adversaire | Capacités | Mitigation principale |
|---|---|---|
| Attaquant réseau passif | Écoute du trafic | TLS + chiffrement de bout en bout ; rien d'exploitable en transit |
| Serveur de synchronisation compromis | Lecture/écriture du coffre chiffré | Architecture zéro-connaissance ; le serveur ne voit que du chiffré |
| Vol de l'appareil (verrouillé) | Accès physique au stockage | Coffre chiffré au repos ; clé jamais persistée en clair |
| Vol de l'appareil (déverrouillé/actif) | Accès à la mémoire vive | Verrouillage automatique ; effacement mémoire ; verrouillage des pages |
| Logiciel malveillant sur l'appareil | Keylogging, lecture mémoire | Limite réelle — voir 3.3 ; durcissement et réduction de fenêtre d'exposition |
| Attaquant par force brute hors-ligne | GPU/ASIC sur le coffre volé | Argon2id mémoire-dur ; mot de passe maître à haute entropie |
| Hameçonnage | Tromper l'utilisateur | Vérification d'origine (autofill lié au domaine) ; passkeys résistants à l'hameçonnage |
| « Récolter maintenant, déchiffrer plus tard » | Stockage de données chiffrées en attendant l'ordinateur quantique | Chiffrement symétrique robuste ; plan hybride post-quantique (section 11) |

### 3.3 Hors périmètre (limites honnêtes)

Aucun gestionnaire de mots de passe ne peut protéger contre **un appareil entièrement compromis pendant que le coffre est déverrouillé**. Si un logiciel malveillant possède les privilèges suffisants pour lire la mémoire du processus ou enregistrer les frappes, il peut capturer le mot de passe maître à la saisie et les secrets une fois déchiffrés. C'est une limite fondamentale, partagée par tous les produits du marché. L'objectif n'est pas de la nier mais de **réduire la fenêtre et la surface d'exposition** : verrouillage agressif, durée de vie minimale des secrets en clair, isolation du processus.

De même, ce document ne traite pas de la **coercition physique** (l'utilisateur forcé de révéler son mot de passe), même si un mode « leurre » (*decoy vault*) peut offrir un déni plausible — fonctionnalité avancée optionnelle.

---

## 4. Architecture cryptographique

C'est le cœur du système. Chaque choix y est justifié.

### 4.1 Dérivation de la clé maître (KDF)

Le mot de passe maître saisi par l'utilisateur n'est **jamais** utilisé directement comme clé. Il est transformé par une fonction de dérivation de clé **mémoire-dure** dont le rôle est de rendre la force brute hors-ligne prohibitivement coûteuse.

**Algorithme retenu : Argon2id.** C'est la recommandation de l'OWASP et du NIST. Argon2id est un hybride : ses premières passes utilisent un accès mémoire indépendant des données (résistance aux attaques par canal auxiliaire / *side-channel*), ses dernières passes un accès dépendant des données (résistance maximale au GPU).

**Paramétrage.** Argon2 a trois paramètres : la mémoire `m`, le nombre d'itérations `t`, et le parallélisme `p`. L'OWASP fixe un **minimum** de `m = 19 Mio`, `t = 2`, `p = 1`. Mais ce minimum vise l'authentification serveur exécutée des milliers de fois par seconde. Pour un gestionnaire de mots de passe, la dérivation ne s'exécute **qu'au déverrouillage** : on peut donc être nettement plus agressif. La RFC 9106 recommande deux jeux de paramètres de référence, dont `m = 2 Gio, t = 1, p = 4` (premier choix) et `m = 64 Mio, t = 3, p = 4` (second choix).

Recommandation par défaut, à calibrer par *benchmark* sur le matériel cible :

| Profil | Mémoire (`m`) | Itérations (`t`) | Parallélisme (`p`) | Cible temps |
|---|---|---|---|---|
| Bureau / serveur puissant | 512 Mio – 1 Gio | 3–4 | 4 | 0,5 – 1 s |
| Portable standard | 256 Mio | 3 | 4 | ~0,5 s |
| Mobile (contraint) | 64 Mio | 3 | 2 | ~0,5 s |

Le principe : viser **0,5 à 1 seconde** de calcul sur l'appareil le plus faible que vous devez prendre en charge, et privilégier la mémoire à l'itération (la mémoire est ce qui neutralise les GPU et ASIC). Ces trois paramètres sont **stockés dans l'en-tête du coffre** afin de pouvoir les augmenter à l'avenir sans casser les anciens coffres.

**Le sel.** Un sel aléatoire de **16 octets minimum**, généré par un générateur cryptographiquement sûr (CSPRNG), est associé à chaque coffre. Le sel n'est **pas secret** : il est stocké en clair à côté du coffre. Son rôle est d'empêcher les tables précalculées (*rainbow tables*) et de garantir que deux coffres avec le même mot de passe maître produisent des clés différentes.

**Repli (*fallback*).** Si Argon2id n'est pas disponible sur une plateforme, le repli est scrypt (`N = 2^17, r = 8, p = 1`). Si une conformité FIPS-140 est imposée, PBKDF2-HMAC-SHA-256 avec **au moins 600 000 itérations**. Ces deux options sont inférieures à Argon2id et ne doivent servir qu'en dernier recours.

### 4.2 Hiérarchie des clés

On n'utilise **jamais** la clé dérivée du mot de passe pour chiffrer directement les données. On introduit deux niveaux :

```
┌─────────────────────┐
│  Mot de passe maître │  (saisi par l'utilisateur, jamais stocké)
└──────────┬──────────┘
           │  Argon2id(mot_de_passe, sel, m, t, p)
           ▼
┌─────────────────────┐
│  Clé maître (KEK)    │  Key-Encryption Key — 256 bits
└──────────┬──────────┘
           │  déchiffre (déballe) ...
           ▼
┌─────────────────────┐
│  Clé de coffre (DEK) │  Data-Encryption Key — 256 bits, aléatoire (CSPRNG)
└──────────┬──────────┘
           │  chiffre ...
           ▼
┌─────────────────────┐
│  Données du coffre   │  (entrées, secrets, notes...)
└─────────────────────┘
```

La **clé de coffre (DEK)** est générée une seule fois, aléatoirement, à la création du coffre. Elle est ensuite **chiffrée (« emballée »)** par la clé maître (KEK) et stockée sous cette forme protégée. À l'ouverture, la KEK est recalculée à partir du mot de passe puis sert à déballer la DEK.

L'intérêt est décisif : **changer le mot de passe maître** ne demande que de recalculer la KEK et de réemballer la DEK — une opération instantanée. Sans cette indirection, chaque changement de mot de passe imposerait de rechiffrer la totalité du coffre.

On peut pousser plus loin avec une clé **par entrée** (chaque élément a sa propre clé, elle-même emballée par la DEK), ce qui facilite le partage granulaire d'éléments individuels. C'est optionnel pour un MVP.

**Dérivation de sous-clés.** À partir de la clé maître, on peut dériver des sous-clés spécialisées avec HKDF-SHA-256 (par exemple, une sous-clé de chiffrement et une sous-clé d'authentification distinctes, ou une clé d'authentification serveur — voir section 5). HKDF est l'outil normalisé pour « étirer » une clé en plusieurs clés indépendantes avec une étiquette de contexte (*info*).

### 4.3 Chiffrement authentifié (AEAD)

On utilise exclusivement du **chiffrement authentifié avec données associées (AEAD)**. Un AEAD garantit simultanément la **confidentialité** (les données sont illisibles) et l'**intégrité/authenticité** (toute altération est détectée au déchiffrement). On ne fait **jamais** de chiffrement « nu » sans authentification : un chiffrement non authentifié est vulnérable aux attaques par manipulation (*bit-flipping*, attaques à texte chiffré choisi).

Deux candidats de premier ordre :

**XChaCha20-Poly1305 (recommandé par défaut).** Chiffrement par flot (ChaCha20) combiné au MAC Poly1305. Son atout majeur est un **nonce de 192 bits** : on peut générer les nonces purement aléatoirement sans craindre une collision, ce qui simplifie énormément l'implémentation correcte. ChaCha20 est *constant-time* par construction (résistant aux attaques temporelles) et performant en logiciel pur, sans accélération matérielle. C'est le choix idéal quand on ne contrôle pas le matériel (mobile, anciens processeurs).

**AES-256-GCM (alternative).** Très répandu, bénéficie de l'accélération matérielle AES-NI sur les processeurs modernes (donc plus rapide là où elle existe). **Attention critique** : son nonce de 96 bits impose une gestion rigoureuse. **La réutilisation d'un nonce avec la même clé est catastrophique** en GCM — elle peut révéler la clé d'authentification et compromettre la confidentialité. Si vous choisissez GCM, utilisez un nonce **à compteur** (jamais aléatoire au-delà de ~2³² messages) et stockez le compteur de façon fiable.

**Règle absolue sur les nonces.** Un nonce (*number used once*) ne doit **jamais** être réutilisé avec la même clé. Stratégies sûres : nonce aléatoire 192 bits avec XChaCha20 (collision négligeable) ; ou compteur strictement croissant et persistant. Le nonce n'est pas secret et se stocke en clair à côté du texte chiffré.

### 4.4 Format d'un enregistrement chiffré

Chaque blob chiffré stocke, en clair, les métadonnées nécessaires au déchiffrement, et en chiffré, la charge utile :

```
[ version (1 octet) ]
[ id_algorithme (1 octet) ]        # ex. 0x01 = XChaCha20-Poly1305
[ longueur_nonce | nonce ]         # 24 octets pour XChaCha20
[ texte_chiffré + tag d'authentification (16 octets) ]
```

La `version` et l'`id_algorithme` rendent le format **agile** : un futur déchiffreur reconnaît immédiatement comment traiter un ancien blob, et l'on peut introduire de nouveaux algorithmes (post-quantiques par exemple) sans ambiguïté.

### 4.5 Génération d'aléa

Toute la sécurité repose sur la qualité de l'aléa (clés, sels, nonces, mots de passe générés). On utilise **exclusivement** le CSPRNG du système d'exploitation : `getrandom`/`/dev/urandom` sous Linux, `BCryptGenRandom` sous Windows, `SecRandomCopyBytes` sous macOS/iOS. En Rust, le *crate* `getrandom` ou `OsRng` de `rand`. On n'utilise **jamais** un générateur pseudo-aléatoire non cryptographique (`rand::thread_rng` non sécurisé, `Math.random()`, `java.util.Random`, etc.) pour quoi que ce soit de sensible.

### 4.6 Exemple d'implémentation (Rust)

Illustration concrète de la chaîne KDF → AEAD avec les *crates* du projet RustCrypto. Le code est volontairement explicite ; en production, on encapsule ces opérations et on efface les secrets (voir section 10).

```rust
use argon2::{Argon2, Algorithm, Version, Params};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    XChaCha20Poly1305, XNonce,
};

/// Dérive la clé maître (KEK) à partir du mot de passe et du sel.
fn derive_master_key(password: &[u8], salt: &[u8]) -> [u8; 32] {
    // m = 256 Mio, t = 3, p = 4  (à calibrer par benchmark)
    let params = Params::new(262_144, 3, 4, Some(32)).expect("params Argon2 valides");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password, salt, &mut key)
        .expect("dérivation Argon2id");
    key
}

/// Chiffre des données en clair avec une clé 256 bits via XChaCha20-Poly1305.
/// Renvoie (nonce, texte_chiffré). Le nonce de 192 bits peut être aléatoire.
fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> (XNonce, Vec<u8>) {
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng); // 24 octets aléatoires
    let ciphertext = cipher.encrypt(&nonce, plaintext).expect("chiffrement");
    (nonce, ciphertext)
}

/// Déchiffre. Renvoie une erreur (et aucune donnée) si l'authentification échoue.
fn decrypt(key: &[u8; 32], nonce: &XNonce, ciphertext: &[u8]) -> Result<Vec<u8>, ()> {
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher.decrypt(nonce, ciphertext).map_err(|_| ())
}
```

Points clés illustrés : la clé maître ne sert qu'à *emballer* la clé de coffre (non montré ici pour la concision) ; le déchiffrement échoue proprement en cas d'altération (le `tag` Poly1305 ne valide pas) ; le nonce est généré par le CSPRNG.

---

## 5. Architecture « zéro-connaissance »

Si vous prévoyez une synchronisation entre appareils via un serveur (le cas le plus courant), le serveur ne doit **jamais** pouvoir lire le coffre ni connaître le mot de passe maître. Deux problèmes distincts se posent : (a) chiffrer les données côté client, et (b) authentifier l'utilisateur auprès du serveur **sans lui transmettre** de quoi déchiffrer.

### 5.1 Le piège : authentifier sans tout révéler

Naïvement, on enverrait le mot de passe maître au serveur pour qu'il vérifie l'identité. C'est exactement ce qu'il faut éviter : le serveur le verrait et pourrait dériver la clé. La solution est de **séparer la clé de chiffrement de la preuve d'authentification**, les deux dérivant du mot de passe mais de façon indépendante.

### 5.2 Modèle à deux dérivations (style Bitwarden)

```
mot_de_passe + sel(e-mail)
        │
        ▼ Argon2id
   clé_maître  ─────────────► sert localement à emballer/déballer la clé de coffre (DEK)
        │                      → ne quitte JAMAIS l'appareil
        ▼ secondaire (Argon2id ou PBKDF2 avec contexte différent)
 hash_d'authentification ────► envoyé au serveur pour prouver l'identité
                               → le serveur stocke un hash salé de CE hash
```

La clé maître reste sur l'appareil. Le *hash d'authentification* est dérivé séparément (sel ou contexte HKDF distinct) et c'est lui — et lui seul — qui transite vers le serveur. Même si le serveur connaît ce hash, il ne peut pas en déduire la clé maître (les deux dérivations sont indépendantes), et le serveur en stocke encore une version re-hachée. Résultat : une fuite de la base serveur n'expose ni les clés ni les coffres en clair.

### 5.3 Alternative supérieure : un protocole PAKE (SRP / OPAQUE)

Encore mieux, on peut utiliser un **PAKE** (*Password-Authenticated Key Exchange*), comme SRP-6a ou, plus moderne, **OPAQUE**. Un PAKE permet au client et au serveur de s'authentifier mutuellement à partir du mot de passe **sans que le serveur n'apprenne jamais le mot de passe ni un hash réutilisable hors-ligne**. OPAQUE est particulièrement intéressant car il résiste aux attaques par pré-calcul : le serveur ne détient aucun matériel permettant une attaque hors-ligne avant compromission. C'est l'état de l'art pour l'authentification zéro-connaissance, au prix d'une complexité d'implémentation supérieure.

### 5.4 Ce que le serveur voit (et ne voit pas)

Le serveur stocke et synchronise un **blob opaque** : la version chiffrée du coffre, plus quelques métadonnées minimales nécessaires à la synchronisation (identifiant de révision, horodatage de modification, vecteur de version pour la résolution de conflits). Il ne voit **jamais** : le mot de passe maître, les clés, les noms de sites, les identifiants. Réfléchissez bien aux métadonnées exposées : un horodatage trop fin ou un compteur d'éléments peut déjà fuiter de l'information.

---

## 6. Modèle de données et format du coffre

### 6.1 Types d'éléments

Un gestionnaire moderne stocke plus que des couples identifiant/mot de passe :

- **Connexion** : URL(s), nom d'utilisateur, mot de passe, secret TOTP, notes, passkey associée.
- **Note sécurisée** : texte libre chiffré.
- **Carte de paiement** : numéro, titulaire, date d'expiration, cryptogramme.
- **Identité** : nom, adresse, téléphone, documents d'identité.
- **Passkey** : clé privée WebAuthn et métadonnées de la *relying party* (voir 8.3).
- **Clé/secret générique** : clés SSH, jetons d'API, etc.

### 6.2 Structure logique

Le coffre déchiffré est typiquement un document structuré (JSON, CBOR, ou un schéma binaire). On chiffre soit le coffre entier comme un seul blob (simple, adapté au MVP), soit chaque élément individuellement (permet le chargement partiel, le partage granulaire et limite la quantité de données simultanément en clair en mémoire).

Schéma indicatif d'une entrée (avant chiffrement) :

```json
{
  "id": "uuid-v4",
  "type": "login",
  "name": "Banque en ligne",
  "uris": ["https://www.mabanque.example"],
  "username": "jean.dupont",
  "password": "•••••••••",
  "totp": "otpauth://totp/...",
  "notes": "...",
  "created_at": "2026-06-21T10:00:00Z",
  "updated_at": "2026-06-21T10:00:00Z",
  "password_history": [{ "value": "...", "changed_at": "..." }]
}
```

### 6.3 En-tête du coffre (non chiffré)

L'en-tête contient les paramètres nécessaires au déchiffrement, en clair, mais **authentifiés** (on les inclut comme « données associées » de l'AEAD pour qu'ils ne puissent pas être altérés sans détection) :

```
{
  "format_version": 1,
  "kdf": { "algo": "argon2id", "m": 262144, "t": 3, "p": 4, "salt": "<base64>" },
  "cipher": "xchacha20poly1305",
  "wrapped_dek": "<clé de coffre emballée, base64>",
  "wrapped_dek_nonce": "<base64>"
}
```

Le fait de stocker les paramètres KDF dans l'en-tête est ce qui rend l'**agilité cryptographique** possible : pour renforcer la sécurité, on augmente `m`/`t`, on rechiffre, on incrémente la version.

---

## 7. Stockage et synchronisation

### 7.1 Stockage local

Deux approches principales :

**Fichier chiffré unique.** Le coffre entier est un fichier (par exemple `.vault`) contenant l'en-tête en clair et le corps chiffré. Simple, portable, facile à sauvegarder. C'est l'approche idéale pour démarrer et pour un usage purement local.

**Base SQLite chiffrée.** On utilise SQLite avec les valeurs sensibles chiffrées au niveau applicatif (chaque champ secret est un blob AEAD), ou bien on s'appuie sur une extension comme SQLCipher qui chiffre toute la base. SQLite apporte l'indexation, les requêtes et la robustesse transactionnelle, utile au-delà de quelques centaines d'entrées.

Dans tous les cas : **rien de sensible n'est jamais écrit en clair sur le disque**, y compris les fichiers temporaires, les journaux, les caches et les fichiers d'échange (*swap* — voir section 10).

### 7.2 Synchronisation multi-appareils

Si vous synchronisez, le modèle est simple grâce au zéro-connaissance : le serveur n'héberge que des blobs chiffrés. Plusieurs options de transport :

- **Serveur dédié** que vous opérez (REST/gRPC + authentification PAKE).
- **Stockage cloud existant** (un dossier chiffré sur un service de fichiers) — le plus simple, mais attention aux métadonnées de fichiers exposées.
- **Synchronisation pair-à-pair** chiffrée, sans serveur central.

### 7.3 Résolution de conflits

Quand deux appareils modifient le coffre hors-ligne, il faut fusionner. Stratégies, par ordre de robustesse :

- **Dernier gagne (*last-write-wins*)** par horodatage : simple mais peut perdre des modifications.
- **Fusion au niveau de l'élément** : chaque entrée a sa propre révision ; on fusionne entrée par entrée, ce qui évite de perdre des modifications sur des entrées différentes.
- **CRDT** (*Conflict-free Replicated Data Types*) : structure de données conçue pour fusionner automatiquement sans conflit. Plus complexe, mais c'est la solution propre pour une synchronisation multi-appareils sérieuse. La fusion se fait **après déchiffrement, côté client** — le serveur ne peut pas fusionner puisqu'il ne voit que du chiffré.

---

## 8. Fonctionnalités de sécurité avancées

### 8.1 Générateur de mots de passe

Un bon générateur est essentiel. Exigences :

- Tirage **uniquement** depuis le CSPRNG du système.
- Tirage **non biaisé** : éviter le modulo naïf (`random % n`) qui favorise certains caractères ; utiliser le rejet d'échantillonnage (*rejection sampling*).
- Paramètres : longueur, jeux de caractères (minuscules, majuscules, chiffres, symboles), exclusion des caractères ambigus (`l`, `1`, `O`, `0`).
- **Phrases de passe** (style *diceware*) : tirage de mots dans une liste, plus mémorisables à entropie égale. Une phrase de 6 mots issus d'une liste de 7776 mots offre ~77 bits d'entropie.
- Affichage de l'**entropie estimée** pour éduquer l'utilisateur.

Repère d'entropie : viser **au moins 80 bits** pour un mot de passe généré (par exemple 14+ caractères aléatoires sur un jeu complet, ou 6–7 mots de *diceware*). Le mot de passe maître, lui, mérite une phrase de passe forte et mémorisable.

### 8.2 TOTP intégré (2FA)

Le gestionnaire peut générer les codes à usage unique basés sur le temps (TOTP, RFC 6238) pour les comptes de l'utilisateur. On stocke le secret TOTP (chiffré, comme tout le reste) et on calcule `HMAC-SHA1(secret, compteur_temps)` toutes les 30 secondes. **Subtilité de sécurité** : stocker le secret TOTP **dans le même coffre** que le mot de passe réduit le second facteur à un facteur unique en cas de compromission du coffre. C'est un compromis commodité/sécurité à exposer clairement à l'utilisateur ; certains préfèrent garder le TOTP dans un appareil séparé.

### 8.3 Passkeys (FIDO2 / WebAuthn)

C'est la direction majeure de l'authentification en 2026. Une *passkey* est une **clé cryptographique** (paire publique/privée) liée à un compte et à un site, qui remplace le mot de passe. La clé privée ne quitte pas l'appareil ; le site ne stocke que la clé publique. À la connexion, le site envoie un défi, l'appareil le signe avec la clé privée, le site vérifie avec la clé publique.

Les passkeys sont **résistantes à l'hameçonnage par construction** : la signature est liée à l'origine (le domaine) vérifiée cryptographiquement. Un faux site ne peut pas obtenir de signature valide pour le vrai site.

Faire de votre gestionnaire un **fournisseur de passkeys** signifie implémenter le rôle d'authentificateur FIDO2 : stocker les clés privées WebAuthn dans le coffre (chiffrées), répondre aux cérémonies de création et d'assertion via les API de la plateforme (CTAP2 côté authentificateur, WebAuthn côté navigateur). On distingue :

- **Passkeys synchronisées** (*synced*) : la clé privée est chiffrée puis synchronisée entre appareils via votre coffre — pratique, c'est ce que font la plupart des gestionnaires.
- **Passkeys liées à l'appareil** (*device-bound*) : la clé ne quitte jamais un appareil unique (typiquement une clé matérielle) — assurance maximale, mais perte de l'appareil = perte de la clé.

C'est une fonctionnalité ambitieuse ; prévoyez-la comme un jalon avancé, pas pour le MVP.

### 8.4 Surveillance des fuites par k-anonymat

Pour vérifier si un mot de passe figure dans une fuite connue (service *Have I Been Pwned*) **sans jamais transmettre le mot de passe** : on calcule le SHA-1 du mot de passe, on envoie **uniquement les 5 premiers caractères hexadécimaux** du condensat. Le service renvoie tous les suffixes correspondant à ce préfixe (parmi des centaines), et la comparaison finale se fait **localement**. Le serveur n'apprend jamais quel mot de passe est testé : c'est le principe du **k-anonymat**. À l'inverse, on n'envoie jamais le mot de passe complet ni son condensat entier.

### 8.5 Partage sécurisé

Partager une entrée avec une autre personne sans exposer le contenu au serveur nécessite de la **cryptographie à clé publique**. Modèle : chaque utilisateur possède une paire de clés ; pour partager un élément, on chiffre la clé de l'élément avec la clé publique du destinataire. Le serveur ne transporte que des données chiffrées de bout en bout. C'est ici que la question post-quantique devient pertinente (section 11), car le chiffrement à clé publique classique (RSA, courbes elliptiques) est vulnérable à un futur ordinateur quantique.

### 8.6 Audit de sécurité du coffre

Fonctions analytiques utiles, calculées **localement** : détection des mots de passe réutilisés, faibles, anciens, ou compromis (via 8.4) ; comptes sans 2FA ; sites supportant les passkeys mais non configurés. Ces analyses ne doivent jamais sortir de l'appareil.

---

## 9. Authentification et déverrouillage

### 9.1 Mot de passe maître

C'est la racine de toute la sécurité. On ne peut pas le récupérer s'il est oublié (c'est le prix du zéro-connaissance — voir section 15). On guide l'utilisateur vers une **phrase de passe forte** plutôt qu'un mot de passe complexe court, on affiche une estimation d'entropie, et on **ne stocke jamais** le mot de passe maître, même haché, là où il pourrait servir à déchiffrer.

### 9.2 Déverrouillage biométrique

La biométrie (empreinte, visage) ne « connaît » pas le mot de passe maître. Le mécanisme correct : après un premier déverrouillage par mot de passe, on stocke la clé de coffre (ou la clé maître) dans le **coffre-fort matériel sécurisé** de l'appareil (Secure Enclave sur Apple, TPM / Keystore sur Android/Windows), déverrouillable par la biométrie. La biométrie ne fait que **débloquer l'accès à une clé déjà dérivée**, conservée dans du matériel inviolable. Elle ne remplace pas la dérivation initiale et ne doit jamais contourner le verrouillage complet (au redémarrage, exiger de nouveau le mot de passe maître).

### 9.3 Clés matérielles (YubiKey, etc.)

On peut renforcer le déverrouillage avec une clé matérielle FIDO2, soit comme second facteur, soit en intégrant un secret de la clé dans la dérivation (de sorte que le coffre ne se déchiffre que si la clé physique est présente). Utile pour les profils à haute exigence.

### 9.4 Politiques de verrouillage automatique

Le coffre doit se **reverrouiller automatiquement** : après un délai d'inactivité (par défaut court, p. ex. 5–15 min), à la mise en veille, au verrouillage de session, ou à la fermeture de l'application. Le reverrouillage **efface les clés de la mémoire** (section 10). Plus la fenêtre déverrouillée est courte, plus l'exposition à une lecture mémoire est faible.

---

## 10. Sécurité mémoire et exécution

Le chiffrement au repos est inutile si les secrets traînent en clair dans la mémoire vive plus longtemps que nécessaire. Cette section est souvent négligée et pourtant cruciale.

**Effacement des secrets (*zeroization*).** Dès qu'un secret (clé, mot de passe en clair) n'est plus nécessaire, on **écrase sa mémoire avec des zéros**. En Rust, les *crates* `zeroize` et `secrecy` automatisent cela (effacement garanti à la libération, non optimisé par le compilateur). Ce n'est pas trivial dans les langages à ramasse-miettes (Java, C#, Python, JavaScript), où le moteur peut **copier** les chaînes en mémoire de façon incontrôlable — un argument fort en faveur d'un cœur en langage à gestion mémoire explicite.

**Verrouillage des pages mémoire (*memory locking*).** On empêche le système d'écrire les pages contenant des secrets dans le fichier d'échange (*swap*) sur disque, via `mlock` (POSIX) / `VirtualLock` (Windows). Sans cela, un secret peut se retrouver écrit en clair sur le disque à l'insu de tous.

**Éviter le *swap* et les vidages mémoire (*core dumps*).** On désactive les *core dumps* pour le processus (qui écriraient toute la mémoire sur disque en cas de crash) et on minimise la duplication des secrets.

**Presse-papiers.** Copier un mot de passe dans le presse-papiers est pratique mais risqué (d'autres applications peuvent le lire). On **efface le presse-papiers automatiquement** après un court délai (p. ex. 10–30 s) et, si la plateforme le permet, on marque le contenu comme sensible/transitoire.

**Protection d'écran.** Empêcher les captures d'écran de l'application (drapeau `FLAG_SECURE` sur Android, équivalents ailleurs) et masquer le contenu dans l'aperçu multitâche.

**Isolation du processus.** Réduire les privilèges, isoler le composant cryptographique, et si possible cloisonner (bac à sable) la partie interface de la partie sensible.

**Journalisation.** **Aucun secret** ne doit jamais apparaître dans un journal, un message d'erreur, un rapport de plantage ou une télémétrie. Auditer cela explicitement.

---

## 11. Résistance post-quantique

C'est l'horizon « dernières possibilités » du sujet. Un ordinateur quantique suffisamment puissant (un CRQC, attendu par certains experts vers 2030-2035, mais sans certitude) menacerait la cryptographie actuelle de façon inégale.

### 11.1 Ce qui est menacé, ce qui ne l'est pas

**La cryptographie symétrique résiste largement.** L'algorithme de Grover offre au mieux une accélération quadratique : il ramène la sécurité d'AES-256 à l'équivalent d'environ 128 bits — ce qui reste **hors de portée** en pratique. Conséquence directe : votre chiffrement de coffre (AES-256 ou XChaCha20-Poly1305) et votre KDF (Argon2id) sont **considérés comme sûrs face au quantique**. C'est rassurant : le cœur de votre gestionnaire est déjà robuste.

**La cryptographie asymétrique est vulnérable.** L'algorithme de Shor casse efficacement RSA et la cryptographie sur courbes elliptiques (ECC). Tout ce qui *dans votre système* repose sur le chiffrement ou la signature à clé publique est exposé : le **partage entre utilisateurs** (section 8.5), et certains protocoles d'authentification ou d'échange de clés.

### 11.2 La menace « récolter maintenant, déchiffrer plus tard »

Même si aucun ordinateur quantique n'existe aujourd'hui, un adversaire peut **stocker dès maintenant** des données chiffrées (par exemple des coffres partagés interceptés) pour les déchiffrer le jour venu. Pour toute donnée devant rester confidentielle plus de 5 à 10 ans, c'est une menace réelle qui justifie d'agir tôt.

### 11.3 Les standards NIST et l'approche hybride

Le NIST a finalisé en 2024 ses premiers standards post-quantiques : **ML-KEM (FIPS 203**, ex-CRYSTALS-Kyber) pour l'échange/encapsulation de clé, **ML-DSA (FIPS 204**, ex-Dilithium) et **SLH-DSA (FIPS 205**, ex-SPHINCS+) pour les signatures. ML-KEM-768 vise un niveau de sécurité équivalent à AES-192, ML-KEM-1024 équivalent à AES-256.

La pratique recommandée n'est **pas** de remplacer brutalement le classique par le post-quantique, mais d'adopter une **approche hybride** : exécuter en parallèle un algorithme classique éprouvé (p. ex. X25519) **et** un algorithme post-quantique (p. ex. ML-KEM-768), en combinant leurs sorties. Ainsi, le système reste sûr tant qu'**au moins un** des deux tient : si une faille est découverte dans le jeune algorithme post-quantique, la couche classique protège encore ; si l'ordinateur quantique arrive, la couche post-quantique protège. C'est l'architecture responsable de transition.

### 11.4 Recommandation concrète pour votre projet

- **Coffre au repos** : aucune action urgente, AES-256/XChaCha20 + Argon2id sont déjà quantum-résistants. Vous pourriez augmenter les marges de sels/clés, mais 256 bits suffisent.
- **Partage et échange de clés** : si vous implémentez le partage, concevez-le d'emblée pour une **encapsulation de clé hybride X25519 + ML-KEM-768**. La bibliothèque `liboqs` (Open Quantum Safe) et des liaisons Rust existent.
- **Agilité avant tout** : grâce au format versionné (section 4.4), vous pourrez introduire ces algorithmes progressivement. L'essentiel est de **ne pas se peindre dans un coin** avec un format rigide.

---

## 12. Choix technologiques

### 12.1 Langage du cœur cryptographique

**Recommandation forte : Rust.** Les raisons sont alignées sur les besoins du projet :

- **Sécurité mémoire** sans ramasse-miettes : pas de copies incontrôlées des secrets, effacement déterministe possible (`zeroize`).
- **Écosystème cryptographique mûr et audité** : `RustCrypto` (`aes-gcm`, `chacha20poly1305`, `argon2`, `hkdf`, `sha2`), `ring`, `dalek` (courbes elliptiques).
- **Absence de classes entières de vulnérabilités** (dépassements de tampon, usage après libération) qui sont catastrophiques dans du code de sécurité en C/C++.
- **Performances** natives, FFI propre vers les autres plateformes.

Alternatives acceptables : **Go** (bonne bibliothèque standard `crypto`, mais ramasse-miettes compliquant l'effacement mémoire). À **éviter** pour le cœur sensible : les langages où la mémoire des secrets est incontrôlable (JavaScript pur, Python) — réservez-les à l'interface, jamais aux secrets en clair durables.

### 12.2 Architecture applicative

Un modèle éprouvé : un **cœur partagé en Rust** (toute la cryptographie, le modèle de données, la logique du coffre), exposé aux différentes plateformes via FFI :

- **Bureau** : **Tauri** (cœur Rust + interface web légère) pour Windows/macOS/Linux avec une seule base de code d'interface.
- **Mobile** : liaisons via **UniFFI** (Mozilla) pour générer des interfaces Swift (iOS) et Kotlin (Android) vers le cœur Rust.
- **Navigateur** : extension communiquant avec l'application native (ne jamais mettre les secrets durables dans le contexte JavaScript de la page).

Ce découpage garantit qu'il n'existe **qu'une seule implémentation cryptographique** à auditer, partagée par toutes les plateformes — un facteur de sûreté majeur.

### 12.3 Bibliothèques à privilégier (écosystème Rust)

| Besoin | Bibliothèque |
|---|---|
| Dérivation de clé | `argon2` |
| AEAD | `chacha20poly1305`, `aes-gcm` |
| Dérivation de sous-clés | `hkdf` |
| Aléa | `getrandom`, `rand` (`OsRng`) |
| Effacement mémoire | `zeroize`, `secrecy` |
| Courbes elliptiques | `x25519-dalek`, `ed25519-dalek` |
| Post-quantique | liaisons `liboqs` / *crates* ML-KEM |
| Sérialisation | `serde` + CBOR (`ciborium`) |
| Base locale | `rusqlite` (+ SQLCipher) |
| Application bureau | `tauri` |
| FFI mobile | `uniffi` |

---

## 13. Feuille de route d'implémentation

Une progression par jalons, du plus fondamental au plus avancé. Ne sautez pas les fondations.

**Jalon 0 — Fondations cryptographiques.** Implémenter et tester isolément : dérivation Argon2id, chiffrement/déchiffrement AEAD, hiérarchie KEK/DEK, génération d'aléa, effacement mémoire. Valider avec des vecteurs de test officiels (section 14). Rien d'autre tant que cette couche n'est pas solide.

**Jalon 1 — Coffre local minimal (MVP).** Création/ouverture d'un coffre chiffré local (fichier unique), ajout/lecture/modification/suppression d'entrées de type « connexion », verrouillage/déverrouillage par mot de passe maître, verrouillage automatique. C'est un produit utilisable.

**Jalon 2 — Fonctions essentielles.** Générateur de mots de passe (avec entropie), recherche, TOTP intégré, audit local (mots de passe faibles/réutilisés), surveillance des fuites par k-anonymat, déverrouillage biométrique.

**Jalon 3 — Synchronisation zéro-connaissance.** Authentification par PAKE (ou modèle à deux dérivations), synchronisation de blobs chiffrés, résolution de conflits au niveau de l'élément, sauvegarde/restauration chiffrée.

**Jalon 4 — Multi-plateforme.** Extraction du cœur Rust partagé, applications bureau (Tauri) et mobile (UniFFI), extension navigateur avec autofill **lié au domaine** (protection anti-hameçonnage).

**Jalon 5 — Avancé.** Fournisseur de passkeys (FIDO2/WebAuthn), partage sécurisé de bout en bout (avec encapsulation hybride post-quantique), clés matérielles, accès d'urgence, codes de récupération.

**Jalon 6 — Durcissement et audit.** Tests de fuzzing, revue de sécurité externe, durcissement mémoire complet, documentation cryptographique publique.

---

## 14. Tests, audit et assurance

Le code de sécurité se teste plus sévèrement que le code ordinaire.

**Vecteurs de test officiels.** Vérifiez vos implémentations (ou vos appels de bibliothèque) contre les vecteurs de test publiés : RFC 9106 pour Argon2, RFC 8439 pour ChaCha20-Poly1305, vecteurs NIST pour AES-GCM, RFC 6238 pour TOTP. Si un seul vecteur échoue, l'implémentation est fausse.

**Tests de propriétés (*property-based*).** Au-delà des cas fixes, vérifiez des invariants : `decrypt(encrypt(x)) == x` pour tout `x` ; toute altération d'un octet du texte chiffré ou du tag **doit** faire échouer le déchiffrement ; deux chiffrements du même clair produisent des sorties différentes (nonces distincts).

**Fuzzing.** Soumettez les analyseurs de format de coffre et les routines de déchiffrement à du *fuzzing* (`cargo-fuzz`) pour débusquer les plantages et comportements indéfinis sur entrées malformées (un coffre corrompu ou malveillant ne doit jamais provoquer de plantage exploitable).

**Analyse temporelle.** Les comparaisons de secrets (tags, hachages) doivent être à **temps constant** (`subtle::ConstantTimeEq` en Rust). Une comparaison naïve (`==`) qui s'arrête au premier octet différent fuit de l'information par le temps.

**Audit externe.** Avant tout usage sérieux, faites auditer le cœur cryptographique par des spécialistes indépendants. Les gestionnaires réputés sont audités régulièrement (p. ex. par des cabinets spécialisés). Un audit n'est pas un luxe pour un outil de cette nature.

**Ne déployez jamais sans :** vecteurs de test verts, comparaisons à temps constant, effacement mémoire, gestion correcte des nonces, et au minimum une revue par un pair compétent en cryptographie.

---

## 15. Sauvegarde et récupération

### 15.1 Le dilemme fondamental

L'architecture zéro-connaissance a une conséquence inévitable : **si l'utilisateur oublie son mot de passe maître, personne ne peut récupérer le coffre.** Pas vous, pas un serveur, personne. C'est une garantie de sécurité, pas un défaut. Mais il faut concevoir des filets de sécurité **qui ne brisent pas le modèle**.

### 15.2 Codes de récupération

À la création du coffre, on peut générer un **code de récupération** : une longue chaîne aléatoire à haute entropie qui sert de seconde voie pour déballer la clé de coffre (la DEK est emballée à la fois par la KEK *et* par une clé dérivée du code de récupération). L'utilisateur conserve ce code **hors ligne**, en lieu sûr. Il permet de retrouver l'accès si le mot de passe maître est oublié, sans qu'aucun serveur ne détienne quoi que ce soit d'exploitable.

### 15.3 Sauvegardes chiffrées

Les sauvegardes du coffre sont **elles-mêmes chiffrées** (jamais d'export en clair par défaut). Si vous proposez un export en clair pour migration, exigez une confirmation explicite, avertissez du risque, et n'écrivez jamais ce fichier dans un emplacement synchronisé ou en cache.

### 15.4 Accès d'urgence

Fonction avancée : permettre à un contact de confiance d'accéder au coffre en cas d'incapacité, via un mécanisme à délai (le contact demande l'accès, l'utilisateur a N jours pour refuser, sinon l'accès est accordé). Cela repose sur du chiffrement à clé publique vers le contact, conçu pour ne jamais exposer le coffre au serveur.

---

## 16. Pièges courants à éviter

Une liste condensée des erreurs qui transforment un système « chiffré » en système vulnérable.

**Inventer sa cryptographie.** L'erreur reine. N'écrivez jamais votre propre AES, votre propre KDF, votre propre générateur d'aléa. Assemblez des primitives éprouvées.

**Chiffrement sans authentification.** Utiliser AES en mode CBC ou CTR sans MAC expose aux attaques par manipulation. Toujours de l'AEAD.

**Mode ECB.** Le mode ECB d'AES laisse transparaître les motifs des données (l'exemple classique du « pingouin chiffré » encore reconnaissable). À proscrire absolument.

**Réutilisation de nonce.** Réutiliser un nonce avec la même clé en GCM est catastrophique. C'est précisément pourquoi XChaCha20 (nonce 192 bits aléatoire) simplifie la sûreté.

**Aléa faible.** Utiliser `Math.random()`, `rand()` du C, ou tout PRNG non cryptographique pour des clés ou mots de passe. Toujours le CSPRNG du système.

**Hachage rapide pour les mots de passe.** Utiliser SHA-256 « salé » seul pour protéger un mot de passe : un GPU teste des milliards de SHA-256 par seconde. Il faut une fonction **mémoire-dure et lente** (Argon2id).

**Mot de passe maître transmis au serveur.** Briser le zéro-connaissance en envoyant le mot de passe (ou un hash réutilisable) au serveur. Utiliser un PAKE ou le modèle à double dérivation.

**Comparaisons non constantes.** Comparer des tags ou hachages avec `==` fuit par timing. Comparaison à temps constant obligatoire.

**Secrets en mémoire trop longtemps / dans les journaux.** Ne pas effacer les secrets, les laisser dans le *swap*, les inclure dans les logs ou rapports de plantage.

**Format rigide non versionné.** S'interdire toute migration future de paramètres ou d'algorithmes. Toujours versionner.

**Autofill non lié au domaine.** Remplir automatiquement les identifiants sans vérifier strictement le domaine ouvre la porte à l'hameçonnage. L'autofill doit être lié à l'origine exacte.

---

## 17. Annexes

### 17.1 Résumé des choix par défaut recommandés

| Composant | Choix recommandé |
|---|---|
| Dérivation de clé | Argon2id, `m≈256 Mio, t=3, p=4` (calibrer ~0,5 s) |
| Sel | 16 octets, CSPRNG, par coffre |
| Chiffrement | XChaCha20-Poly1305 (AEAD, nonce 192 bits) |
| Hiérarchie de clés | KEK (dérivée) emballe DEK (aléatoire) |
| Sous-clés | HKDF-SHA-256 |
| Authentification serveur | PAKE (OPAQUE/SRP) ou double dérivation |
| Aléa | CSPRNG du système (`OsRng`/`getrandom`) |
| Effacement mémoire | `zeroize` / `secrecy` + `mlock` |
| Fuites | k-anonymat (préfixe SHA-1 de 5 caractères) |
| 2FA | TOTP (RFC 6238), passkeys (FIDO2/WebAuthn) |
| Partage / PQC | Hybride X25519 + ML-KEM-768 |
| Langage du cœur | Rust |

### 17.2 Standards et références à consulter

- **RFC 9106** — Argon2 (spécification et paramètres recommandés).
- **RFC 8439** — ChaCha20 et Poly1305.
- **RFC 5869** — HKDF.
- **RFC 6238** — TOTP.
- **NIST FIPS 203 / 204 / 205** — standards post-quantiques (ML-KEM, ML-DSA, SLH-DSA).
- **OWASP** — *Password Storage Cheat Sheet*, *Cryptographic Storage Cheat Sheet*.
- **W3C WebAuthn** et **FIDO Alliance CTAP2** — passkeys.
- **NIST SP 800-63B** — lignes directrices sur l'authentification numérique.

### 17.3 Glossaire

- **AEAD** : chiffrement authentifié avec données associées (confidentialité + intégrité).
- **KDF** : fonction de dérivation de clé.
- **KEK / DEK** : clé de chiffrement de clé / clé de chiffrement de données.
- **PAKE** : échange de clé authentifié par mot de passe.
- **Nonce** : valeur unique utilisée une seule fois avec une clé donnée.
- **Sel** : valeur aléatoire publique rendant chaque dérivation unique.
- **Zéro-connaissance** : le serveur ne peut rien apprendre d'exploitable.
- **CSPRNG** : générateur pseudo-aléatoire cryptographiquement sûr.
- **HNDL** (*harvest now, decrypt later*) : récolter maintenant, déchiffrer plus tard.
- **CRQC** : ordinateur quantique cryptographiquement pertinent.

---

*Fin du document. Ce document décrit une architecture ; sa mise en œuvre sûre exige des tests rigoureux et, avant tout usage réel, un audit cryptographique indépendant.*
