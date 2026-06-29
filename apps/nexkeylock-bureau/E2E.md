# Tests end-to-end (tauri-driver)

Les parcours sont d'abord couverts par les **tests d'intégration Rust** (chaque
commande contre un vrai coffre) et les **tests d'écran** Vitest (store + pont
réels, IPC `invoke` simulée) : création, déverrouillage, ajout/édition/
suppression, révélation/copie, génération, audit, fuites, réglages.

Pour un véritable **end-to-end navigateur** (l'application compilée pilotée via
WebDriver), NexKeyLock s'appuie sur **`tauri-driver`** + `msedgedriver`
(Windows) / `WebKitWebDriver` (Linux). Ce harnais dépend d'un pilote WebDriver
externe et n'est donc **pas exécuté dans l'environnement de développement
actuel** ; il est décrit ici pour être lancé là où le pilote est disponible
(poste développeur, CI dédiée).

## Prérequis

```sh
cargo install tauri-driver --locked
# Windows : msedgedriver correspondant à la version de WebView2 (Edge),
#           https://developer.microsoft.com/microsoft-edge/tools/webdriver/
# Linux   : sudo apt install webkit2gtk-driver
```

## Principe

1. `cargo tauri build` (ou `--debug`) produit l'exécutable.
2. `tauri-driver` lance un serveur WebDriver qui démarre l'application.
3. Un client (Playwright/WebdriverIO/`selenium`) pilote l'UI et vérifie les
   parcours :
   - création de coffre → écran déverrouillé ;
   - verrouillage automatique après inactivité → retour à l'écran de verrouillage ;
   - mauvais mot de passe → message neutre ;
   - ajout d'entrée → affichage/copie ;
   - génération de mot de passe.

## Contrôles de sécurité déjà automatisés (sans navigateur)

- **Aucun secret en stockage navigateur** — `src/tests/securite.test.tsx`.
- **Verrouillage automatique efface les clés** — `useVerrouillageAuto`
  (`src/lib/verrouillageAuto.test.ts`) + zeroize backend (`etat.rs`).
- **Anti-XSS** (rendu texte inerte) — `src/composants/CarteEntree.test.tsx`.
- **Accessibilité (axe)** — `src/tests/accessibilite.test.tsx`.
- **Mauvais mot de passe neutre** — `EcranVerrouillage` + tests d'intégration Rust.
- **Presse-papiers à effacement automatique** — piloté côté backend.
- **CSP verrouillée / capacités minimales / DevTools off en release** —
  `tauri.conf.json`, `capabilities/`, profil release.
