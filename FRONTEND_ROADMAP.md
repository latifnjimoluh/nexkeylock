# FRONTEND_ROADMAP — NexKeyLock (application de bureau)

> Feuille de route du **frontend visuel de bureau** de NexKeyLock, bâti sur le
> cœur Rust existant (`nex-cryptographie`, `nex-coffre`) **sans réimplémenter
> aucune cryptographie**. Cible : Windows / macOS / Linux, avec une déclinaison
> **mobile (iOS/Android) anticipée mais différée**.
>
> **Statut : VALIDÉE — construction en cours (F0→).** Décisions actées :
> frontend **français**, **vérification de fuite en ligne opt-in** (HIBP
> k-anonymat, préfixe seulement, côté Rust), **biométrie bureau dès F7 « au
> mieux »** (Windows Hello).

---

## 0. Décisions cadrantes (validées / proposées)

| Sujet | Décision | Note |
|-------|----------|------|
| Cadre | **Tauri v2** | Backend Rust unique, cibles bureau **et** mobile. |
| Frontend | **React + TypeScript (strict)** | Défaut du brief ; Vite comme bundler. |
| Style | **Tailwind CSS** + système de jetons | Aucun style ad hoc dispersé. |
| Gestionnaire de paquets | **pnpm** | Déjà présent sur la machine. |
| Langue du code | **Français, identifiants compris** | Cohérent avec tout le cœur (décision validée). |
| Actifs | **100 % locaux** | Aucun CDN, police ou script distant à l'exécution. |
| État global | Minimal (Zustand) ; **aucun secret durable** | Voir §3. |
| Outillage présent | Node 22.12, npm 10.9, pnpm, WebView2 149 | `tauri-cli` à installer au Jalon F0. |

### Conventions de nommage (FR)

- Dossier app : `apps/nexkeylock-bureau/` (`src-tauri/` + `frontend/`).
- Frontend : `composants/`, `ecrans/`, `theme/`, `lib/` (appels commandes + état).
- Commandes Tauri : verbes français (`creer_coffre`, `deverrouiller`, …).
- Commits : français, atomiques, impératif (« Ajoute l'écran de verrouillage »).

---

## 1. Architecture de sécurité de la frontière (principe directeur)

```
┌────────────────────────┐         commandes (IPC)        ┌──────────────────────────┐
│  Webview (TS/React)    │  ───────────────────────────▶  │  Backend Tauri (Rust)     │
│  — partie NON fiable    │   mdp maître à l'unlock ▶       │  — partie de CONFIANCE     │
│  — métadonnées seulement│   ◀ métadonnées, états          │  détient CoffreDeverrouille│
│  — secrets à la demande,│   ◀ secret d'UN champ, bref     │  (DEK + contenu en clair)  │
│    effacés au plus vite │                                 │  → appelle nex-coffre      │
└────────────────────────┘                                 └──────────────────────────┘
```

- **La clé maître et la DEK ne quittent JAMAIS le backend.** Le `CoffreDeverrouille`
  vit dans un état Tauri protégé (`Mutex<EtatCoffre>`).
- L'unlock transmet le mot de passe maître **une fois** au backend, qui dérive la
  KEK, déballe la DEK, et ne renvoie qu'un statut + des **métadonnées**.
- Les mots de passe / TOTP en clair sont obtenus **par champ, à la demande**
  (`reveler_champ`, `copier_champ`), affichés/copiés brièvement, puis **effacés
  de l'état de la webview**.
- **Aucun stockage navigateur** (`localStorage`/`sessionStorage`/`IndexedDB`/
  cookies) pour quoi que ce soit de sensible. Le coffre vit dans son fichier
  chiffré, géré par le cœur.

---

## 2. Couche de commandes Tauri (API minimale, FR)

Chaque commande **valide ses entrées** et **ne fuit aucun secret dans ses
erreurs** (type d'erreur dédié, messages neutres). Les commandes mutatrices
persistent via `CoffreDeverrouille::enregistrer`.

| Commande | Cœur appelé | Renvoie |
|----------|-------------|---------|
| `coffre_existe` | `Path::exists` | bool |
| `creer_coffre(mdp, options_kdf)` | `CoffreDeverrouille::creer` | statut |
| `configurer_recuperation()` | `activer_recuperation` | code (affiché 1×) |
| `deverrouiller(mdp)` | `CoffreVerrouille::deverrouiller` | statut + métadonnées |
| `deverrouiller_par_recuperation(code, nouveau_mdp)` | `deverrouiller_par_recuperation` + `changer_mot_de_passe` | statut |
| `verrouiller()` | `verrouiller` (zeroize) | — |
| `etat()` | état Tauri | verrouillé/déverrouillé |
| `lister_entrees(filtre?, tri?)` | `entrees`/`rechercher` | métadonnées (sans secrets) |
| `metadonnees_entree(id)` | `obtenir` | champs non secrets |
| `reveler_champ(id, champ)` | `obtenir` | valeur d'**un** champ |
| `copier_champ(id, champ, delai_s)` | `obtenir` + presse-papiers backend | confirmation + minuterie |
| `ajouter_entree(donnees)` | `ajouter` + `enregistrer` | id |
| `modifier_entree(id, donnees)` | `modifier` + `enregistrer` | — |
| `supprimer_entree(id)` | `supprimer` + `enregistrer` | — |
| `generer_mot_de_passe(options)` | `generateur::generer_*` | mot de passe + entropie |
| `obtenir_totp(id)` | `totp` | code + secondes restantes |
| `lancer_audit()` | `audit::auditer` | rapport (réutilisés/faibles/anciens) |
| `verifier_fuite(id?)` | `audit` k-anonymat (à compléter dans `nex-coffre`) | comptes compromis |
| `changer_mot_de_passe(actuel, nouveau)` | `changer_mot_de_passe` | — |
| `exporter_chiffre(chemin)` / `importer_chiffre(chemin)` | copie/validation | — |
| `obtenir_reglages()` / `definir_reglages(r)` | `nex-maj::Config` + réglages UI | réglages |
| `verifier_maj()` | `nex-maj::verifier` | état mise à jour |

> **Manques côté cœur à compléter (avec tests) au fil des jalons** : exposition
> propre des **métadonnées d'entrée** sans secrets ; **k-anonymat / vérification
> de fuite** en ligne (le module `audit` fait l'analyse hors-ligne ; l'appel
> réseau HIBP range-query sera ajouté à `nex-coffre` ou un crate dédié, jamais en
> JS) ; helper d'**export chiffré**. Toute fonction manquante est ajoutée à
> `nex-coffre`, pas réécrite dans l'UI.

---

## 3. Système de design (défini au Jalon F0, avant tout écran)

- **Jetons** : couleurs (sémantiques : surface, texte, accent, succès, alerte,
  danger), typographie (échelle 12→32), espacements (4-pt), rayons, ombres.
- **Thèmes** : clair, sombre (**défaut**), « système ». Bascule persistée hors
  secrets (réglages).
- **Accessibilité (objectif WCAG AA)** : contrastes ≥ 4.5:1, focus visible,
  navigation clavier complète, étiquettes ARIA, cibles ≥ 24 px.
- **Adaptatif dès le départ** : grille à points de rupture ; la barre latérale
  bureau ↔ onglets/tiroir mobile (préparation §8).
- **Bibliothèque de composants** : bouton, champ (avec afficher/masquer),
  modale, toast (« copié, effacement dans Ns »), indicateur de force,
  anneau de décompte TOTP, carte d'entrée, jauge de score de santé, écran de
  verrouillage, états vide/chargement/erreur.

---

## 4. Jalons

> Règle : **on n'entame pas un jalon tant que les tests du précédent ne sont pas
> verts.** Les tests s'écrivent **avec** chaque composant.

### Jalon F0 — Fondations et système de design
- `apps/nexkeylock-bureau/` : squelette Tauri v2 (`src-tauri` dépend de
  `nex-coffre`) + React/TS/Vite + Tailwind ; `tauri-cli` installé.
- **CSP verrouillée** (pas de script distant/`eval`/inline), **capacités Tauri
  minimales** (aucun shell, aucun FS arbitraire), **DevTools off en release**.
- Système de design (jetons, thèmes clair/sombre), ESLint + Prettier, Vitest.
- **Tests** : build debug+release OK ; lint/format propres ; test « la CSP
  interdit un script distant » ; rendu d'un composant de base.
- **Acceptation** : `pnpm build` + `cargo tauri build` réussissent ; thème
  bascule ; aucune ressource réseau chargée.

### Jalon F1 — Frontière de sécurité et état du coffre
- État backend `Mutex<EtatCoffre>` ; commandes `coffre_existe`, `creer_coffre`,
  `deverrouiller`, `verrouiller`, `etat` ; type d'erreur sans fuite.
- **Tests d'intégration (Rust)** : chaque commande contre un vrai coffre temporaire ;
  mauvais mot de passe → erreur neutre ; après `verrouiller`, l'état n'expose
  plus rien.
- **Acceptation** : un test prouve que la DEK/clé maître **ne figure dans aucune
  réponse** de commande.

### Jalon F2 — Création de coffre + verrouillage/déverrouillage (écrans 1 & 2)
- Écran d'accueil/création : **force + entropie** du mot de passe maître,
  confirmation, avertissement « irrécupérable », **code de récupération** affiché
  une fois (confirmation de sauvegarde), calibration KDF en arrière-plan.
- Écran de verrouillage/déverrouillage : saisie, déverrouillage, **mauvais mot de
  passe** géré ; écran de retour après auto-lock.
- **Tests** : composant indicateur de force ; **e2e** création→déverrouillage
  contre le vrai cœur ; mauvais mot de passe.

### Jalon F3 — Vue principale du coffre (écran 3)
- Barre latérale (Tout, Connexions, Cartes, Identités, Notes, Passkeys, Favoris,
  Tableau de bord, Réglages) ; **liste recherchable/triable** ; **recherche
  instantanée** ; panneau de détail (afficher/masquer, **copie à effacement
  auto**, **TOTP anneau en direct**).
- **Tests** : **anti-XSS** (nom/notes contenant `<script>` rendus en texte inerte) ;
  recherche ; anneau TOTP ; effacement presse-papiers.

### Jalon F4 — Ajout / édition d'entrée (écran 4)
- Formulaire par type ; **générateur intégré** ; URL, notes ; **secret TOTP**
  manuel ou par analyse d'`otpauth://`.
- **Tests** : composant formulaire ; parsing `otpauth://` (dans le cœur) ; e2e ajout.

### Jalon F5 — Générateur de mots de passe (écran 5)
- Longueur, jeux de caractères, exclusion d'ambigus, **phrase de passe**,
  **entropie en direct**, régénération, copier/utiliser.
- **Tests** : composant générateur ; entropie cohérente avec le cœur.

### Jalon F6 — Tableau de bord de sécurité (écran 6)
- Cartes : réutilisés, faibles, anciens, **compromis (k-anonymat)** ; **score de
  santé** ; éléments cliquables vers les entrées.
- **Cœur** : ajout de la vérification de fuite en ligne (k-anonymat) à `nex-coffre`
  **avec tests**, jamais en JS.
- **Tests** : composant jauge ; intégration commande `lancer_audit` / `verifier_fuite`.

### Jalon F7 — Réglages (écran 7)
- Délai auto-lock, délai presse-papiers, thème, **bascule biométrie**, **KDF
  avancé**, **export/import chiffrés**, **changement de mot de passe maître**,
  page « à propos / sécurité ». Intègre l'updater existant (`nex-maj`).
- **Tests** : intégration `changer_mot_de_passe`, export/import (aller-retour).

### Jalon F8 — Durcissement UI et verrouillage automatique
- **Auto-lock** : inactivité (configurable), **veille système**, perte de focus/
  minimisation (option) → appelle `verrouiller` (zeroize) → écran de verrouillage.
- **Presse-papiers** : effacement après délai + message clair.
- **Protection capture d'écran** / masquage en aperçu multitâche (là où l'OS le permet).
- **Tests de sécurité** : aucun secret en stockage navigateur ; presse-papiers
  effacé ; auto-lock efface les clés ; mauvais mot de passe ; anti-XSS.
- **Accessibilité** : `axe` sur les écrans principaux ; instantanés optionnels.

### Jalon F9 — Empaquetage et distribution bureau
- Bundles Windows / macOS / Linux (`cargo tauri build`) ; icônes/métadonnées
  « NexKeyLock » ; intégration de la vérification de mise à jour.
- **Doc** d'usage et de build. Mise à jour de la roadmap.
- **Acceptation** : §9 « Définition de terminé » satisfaite sur les 3 OS visés.

### Jalon M (MOBILE) — DIFFÉRÉ (jalon distinct, non développé maintenant)
- Cibles **iOS/Android** via Tauri v2 réutilisant le **même cœur** et la **même
  couche de commandes** ; navigation responsive (barre latérale ↔ onglets/tiroir) ;
  biométrie native (Face ID/Touch ID/Android). **Aucune décision des jalons F0–F9
  ne doit bloquer ce jalon.**

---

## 5. Stratégie de test (récapitulatif)

| Type | Outils | Portée |
|------|--------|--------|
| Composants | Vitest + Testing Library | force, générateur, anneau TOTP, formulaires, vide/erreur |
| Intégration commandes | tests Rust (`#[test]`) | chaque commande contre un vrai coffre |
| E2E | `tauri-driver` / Playwright | création, unlock, ajout, reveal/copy, génération, lock |
| Sécurité UI | tests dédiés | pas de secret en stockage navigateur ; presse-papiers ; auto-lock ; mauvais mdp ; anti-XSS |
| Accessibilité | `axe` | écrans principaux |

---

## 6. Décisions de sécurité conservatrices (à confirmer)

1. **Biométrie** : par défaut **désactivée**. Quand activée, l'OS (coffre-fort
   matériel : Windows Hello / Keychain) protège un **secret de déverrouillage**,
   débloqué par la biométrie — la clé maître n'est jamais stockée en clair. Sur
   **bureau**, support « au mieux » (Windows Hello) ; support complet au jalon
   mobile. *→ je signale ce compromis ; à confirmer.*
2. **Vérification de fuite (HIBP k-anonymat)** : appel réseau **opt-in**, effectué
   **côté Rust** (jamais en JS), n'envoyant qu'un **préfixe de hachage** (5 car.).
3. **Effacement presse-papiers** : minuterie **côté backend** (fiable même si la
   webview est fermée), 20 s par défaut.
4. **Auto-lock** : 5 min d'inactivité par défaut ; verrouillage immédiat à la veille.

---

## 7. Définition de « terminé » (rappel du brief)

Compile/exécute sur Windows/macOS/Linux contre le **vrai cœur** (aucune crypto JS) ;
tous les écrans §4 avec thèmes + adaptatif + états vide/chargement/erreur ;
contrôles de sécurité passants (CSP, permissions minimales, pas de secret en
stockage navigateur, auto-lock zeroize, presse-papiers, DevTools off, anti-XSS) ;
suite de tests verte ; `cargo clippy -D warnings`, `cargo fmt --check`, lint/format
frontend propres ; roadmap à jour, commits propres, doc écrite.

---

## 8. Décisions actées (validation du 2026-06-28)

1. **Construction** : démarrée après validation — F0 (fondations) → F1 → F2.
2. **Biométrie bureau** : bascule présente dès **F7**, déverrouillage effectif
   « au mieux » via Windows Hello (coffre-fort matériel) ; support complet au
   jalon mobile.
3. **Vérification de fuite en ligne** : **autorisée, opt-in** (désactivée par
   défaut), réalisée **côté Rust** (k-anonymat, envoi d'un préfixe de hachage de
   5 caractères uniquement) ; l'audit local reste disponible sans réseau.
