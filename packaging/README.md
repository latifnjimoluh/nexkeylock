# Empaquetage de nexkeylock (Windows)

Ce dossier produit deux livrables, déposés dans `../dist/` :

| Livrable | Fichier | Usage |
|----------|---------|-------|
| **Portable** | `nexkeylock-<version>-portable.exe` | Un seul fichier, à lancer directement (aucune installation). |
| **Installateur** | `nexkeylock-<version>-installateur.exe` | `setup.exe` classique : installe dans `Program Files`, ajoute (en option) au PATH, crée des raccourcis, et offre une désinstallation propre. |

## Prérequis

- Toolchain Rust stable (MSVC) — voir `rust-toolchain.toml`.
- [Inno Setup 6](https://www.innosetup.com/) pour l'installateur (`ISCC.exe`).

## Reconstruire

```powershell
# Préfixer le PATH si cargo n'est pas global :
$env:Path = "C:\Users\<vous>\.rustup\toolchains\stable-x86_64-pc-windows-msvc\bin;$env:Path"

# 1) Binaire portable (release, presse-papiers activé)
cargo build --release -p nex-console --features presse-papiers
Copy-Item target\release\nexkeylock.exe dist\nexkeylock-0.2.0-portable.exe

# 2) Installateur Windows
& "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" packaging\installateur.iss
```

L'installateur résultant est `dist\nexkeylock-0.2.0-installateur.exe`.

## Notes

- nexkeylock est un outil **en ligne de commande**. L'installateur propose donc
  d'ajouter le dossier d'installation au PATH machine (tâche cochée par défaut)
  et crée un raccourci « Terminal nexkeylock ».
- La version provient de `[workspace.package].version` (`Cargo.toml`) ; pensez à
  mettre à jour `MaVersion` dans `installateur.iss` lors d'un changement de
  version.
- Le dossier `../dist/` est ignoré par git (binaires non versionnés).
