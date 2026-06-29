# nex-serveur-sync

Serveur de synchronisation **zéro-connaissance** de nexkeylock. Il ne stocke
**que des données chiffrées et un vérificateur d'authentification** : il ne voit
jamais le mot de passe maître, la clé de chiffrement ni le contenu du coffre.

## Lancer (développement local)

```sh
cargo run -p nex-serveur-sync
# écoute par défaut sur 127.0.0.1:8787 ; surcharger avec :
#   NEXKEYLOCK_SYNC_ADRESSE=0.0.0.0:8787 cargo run -p nex-serveur-sync
```

## API

| Méthode | Chemin | Corps | Réponse |
|---------|--------|-------|---------|
| POST | `/inscription` | `{email, hash_auth}` | 201 / 409 si existant |
| POST | `/connexion` | `{email, hash_auth}` | 200 `{jeton}` / 401 |
| GET | `/coffre` | — (Bearer jeton) | 200 `{revision, blob}` |
| POST | `/coffre` | `{base, blob}` (Bearer) | 200 `{revision}` / 409 `{actuelle}` |

- `hash_auth` et `blob` sont en **hexadécimal**. `hash_auth` est dérivé côté
  client (HKDF, indépendant de la clé de chiffrement). `blob` est le coffre
  **déjà chiffré** (opaque).
- L'envoi utilise une **concurrence optimiste** : `base` doit être la révision
  courante, sinon `409` (le client tire, fusionne, réessaie).

## Sécurité — état et limites (honnêteté)

- **Zéro-connaissance** : le serveur stocke un `Verificateur` salé (hachage à
  temps constant) et des blobs chiffrés opaques. Une fuite de sa base n'expose
  ni mot de passe maître ni contenu (force brute hors-ligne bornée par Argon2id
  côté client, et **inopérante** si un fichier-clé est utilisé).
- **Stockage en mémoire** : l'état est perdu au redémarrage (suffisant pour le
  développement). La **persistance disque** relève du déploiement (jalon S7).
- **Pas de TLS intégré** : à placer derrière un proxy TLS (Caddy/Nginx) pour un
  usage réel ; en local, l'usage reste sur la machine.
- **Métadonnées** : le serveur connaît l'email, la taille du blob et les dates
  de synchro (jamais le contenu).
