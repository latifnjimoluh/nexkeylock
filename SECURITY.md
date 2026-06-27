# Sécurité — nexkeylock

> **Brouillon (Jalon 0).** Ce document sera enrichi à chaque jalon et finalisé au Jalon 7. Il décrit le modèle de menace, les choix cryptographiques et les **limites honnêtes**.

## 1. Principe directeur

nexkeylock est un gestionnaire de mots de passe **zéro-connaissance** : seul l'utilisateur, via son mot de passe maître, peut déchiffrer ses données. Aucun serveur, fournisseur ou administrateur n'a jamais accès au clair.

**Règle d'or :** on n'invente jamais de cryptographie. On assemble des primitives éprouvées et auditées (projet RustCrypto). Tout l'art est dans l'assemblage correct, la gestion des clés et la discipline d'implémentation.

## 2. Modèle de menace (résumé)

**Actifs :** contenu du coffre (identifiants, mots de passe, secrets TOTP, notes…), métadonnées (noms de sites, dates), et l'actif racine : le **mot de passe maître**.

**Adversaires couverts :** attaquant réseau passif, serveur de synchronisation compromis, vol d'appareil (verrouillé ou actif), force brute hors-ligne sur coffre volé, hameçonnage, « récolter maintenant, déchiffrer plus tard ».

**Hors périmètre (limite fondamentale, partagée par tous les produits) :** un appareil entièrement compromis **pendant que le coffre est déverrouillé**. Un logiciel malveillant avec assez de privilèges peut enregistrer les frappes ou lire la mémoire du processus. L'objectif est de **réduire la fenêtre et la surface d'exposition** (verrouillage agressif, durée de vie minimale des secrets en clair), pas de nier cette limite.

## 3. Choix cryptographiques (non négociables)

| Sujet | Décision |
|---|---|
| KDF | Argon2id, défaut `m=256 Mio, t=3, p=4`, sortie 32 octets ; paramètres dans l'en-tête (agilité). |
| Sel | ≥ 16 octets, CSPRNG, unique par coffre, en clair mais authentifié. |
| AEAD défaut | XChaCha20-Poly1305 (nonce 192 bits aléatoire). |
| AEAD alternatif | AES-256-GCM (nonce à compteur persistant strictement croissant, jamais aléatoire). |
| Hiérarchie | mot de passe → Argon2id → KEK (256 bits) ; DEK (256 bits) aléatoire emballée par la KEK. |
| Sous-clés | HKDF-SHA256 avec étiquette de contexte. |
| Aléa | CSPRNG système uniquement (`OsRng`/`getrandom`). |
| Comparaisons | temps constant via `subtle::ConstantTimeEq`. Jamais `==` sur des secrets. |
| En-tête | versionné et authentifié (données associées de l'AEAD) ; downgrade rejeté. |
| Échec | sûr (*fail-closed*) : erreur typée, jamais de donnée partielle, jamais de panic exploitable. |

**Replis documentés mais non utilisés par défaut :** scrypt (`N=2^17, r=8, p=1`) ; PBKDF2-HMAC-SHA256 (`≥ 600 000` itérations, conformité FIPS). Tous deux inférieurs à Argon2id.

## 4. Hygiène mémoire

- Effacement des secrets via `zeroize`/`secrecy` (déterministe à la libération).
- Verrouillage des pages (`mlock`/`VirtualLock`) lorsque la plateforme le permet — *au mieux*.
- Désactivation des core dumps pour le processus.
- **Aucun secret** dans les journaux, messages d'erreur, `panic!` ou rapports de plantage.

**Limites honnêtes :** en Rust, l'effacement est fort mais non absolu (copies en pile, tampons intermédiaires que le compilateur peut produire). `mlock`/`VirtualLock` dépendent des limites de l'OS. Ces limites seront documentées au fil de l'implémentation.

## 5. Décisions conservatrices prises (à valider)

- **AEAD par défaut = XChaCha20-Poly1305.** AES-256-GCM reste opt-in tant que la persistance du compteur de nonce n'est pas prouvée résistante aux crashs (un nonce réutilisé en GCM est catastrophique).
- **Stockage MVP = fichier unique chiffré.** SQLite/SQLCipher différé.
- **k-anonymat hors-ligne par défaut.** Le client réseau est abstrait derrière un trait ; aucun appel réseau en test ; opt-in explicite pour l'utilisateur.
- **Aucun export en clair par défaut.** L'export par défaut copie le blob déjà chiffré. L'export en clair exige `--je-confirme-le-risque` et émet un avertissement.
- **Code de récupération.** La DEK est emballée une seconde fois par une clé dérivée (Argon2id) d'un code aléatoire à haute entropie (160 bits). L'AAD de cet emballage est `aad_corps` (version+algorithme), stable lors d'un changement de mot de passe : le code de récupération reste donc valide après rotation du mot de passe maître. Le code n'est affiché qu'une seule fois ; sans lui ni le mot de passe maître, le coffre est irrécupérable (propriété du zéro-connaissance).

## 6. Surface de fuzzing

Les surfaces exposées à des données non fiables sont soumises au fuzzing
(`cargo-fuzz`, cf. `TESTING.md`) : le **parseur de format de coffre**
(`decoder_fichier`), le couple **décodage + validation d'en-tête**
(`ouvrir_fichier`) et la **routine de déchiffrement AEAD** (`aead_dechiffrer`).
Objectif : aucun `panic` ni comportement indéfini sur entrée arbitraire (un
coffre corrompu ou malveillant ne doit jamais provoquer de plantage
exploitable). Un passage court tourne en CI ; les campagnes longues sont
documentées.

## 6 bis. Partage chiffré de bout en bout (avancé)

Le crate `nex-partage` (séparé du cœur, Jalon 6) implémente un partage E2E
résistant au post-quantique : encapsulation de clé **hybride X25519 + ML-KEM-768
(FIPS 203)** combinée par HKDF-SHA256, puis chiffrement de la charge par
XChaCha20-Poly1305. Propriété hybride : sûr tant qu'**au moins un** des deux
volets tient (vérifié par test — altérer l'un ou l'autre casse le
déchiffrement). La conformité de ML-KEM aux vecteurs NIST ACVP est **déléguée à
la crate auditée `ml-kem`** ; nos tests couvrent l'intégration (accord de clé,
aller-retour, sérialisation, déterminisme). L'identité de partage (clés privées)
est stockée chiffrée dans le corps du coffre et effacée en mémoire à la
libération.

## 6 ter. Synchronisation zéro-connaissance (avancé)

Le crate `nex-sync` (séparé du cœur, Jalon 6) fournit deux briques :

- **Authentification par double dérivation** : depuis la clé maître (Argon2id),
  on dérive par HKDF-SHA256, avec des étiquettes de contexte **distinctes**, une
  clé de chiffrement (locale) et un hash d'authentification (envoyé au serveur).
  Les deux sont indépendants (HKDF à sens unique) : connaître le hash
  d'authentification ne révèle rien de la clé de chiffrement. Le serveur ne
  stocke qu'un **vérificateur salé** comparé à **temps constant** ; une fuite de
  sa base n'expose ni le mot de passe, ni la clé maître, ni le coffre.
- **Transport zéro-connaissance** : le dépôt distant ne voit que des **blobs
  chiffrés opaques** et une révision monotone (vérifié par test : aucun nom ni
  secret d'entrée n'apparaît en clair côté dépôt). La concurrence est gérée de
  façon **optimiste** (un envoi n'est accepté que sur la bonne révision de
  base) ; la fusion éventuelle se fait **côté client, après déchiffrement**.

## 7. Préparation à un audit externe

État au terme des jalons 0–5 : cœur cryptographique validé par vecteurs
officiels (RFC 9106, 8439, 5869, 6238, NIST AES-GCM), tests de propriétés,
cycle de vie et cas adversariaux du coffre, e2e de la CLI, fuzzing des surfaces
non fiables. Avant tout usage réel : **audit cryptographique indépendant**, plus
une revue des points hors périmètre (§2) et des limites d'effacement mémoire
(§4).

## 8. Signalement de vulnérabilité

Projet en développement (pré-audit). Ne pas utiliser pour de vrais secrets avant
audit. Vérifications minimales avant déploiement : vecteurs de test verts,
comparaisons à temps constant, effacement mémoire, gestion correcte des nonces.
