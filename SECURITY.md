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

## 6. Signalement de vulnérabilité

Projet en développement (pré-audit). Avant tout usage réel : vecteurs de test verts, comparaisons à temps constant, effacement mémoire, gestion correcte des nonces, et **audit cryptographique indépendant**.
