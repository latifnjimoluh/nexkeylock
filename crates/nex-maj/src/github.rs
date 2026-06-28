//! Accès en lecture seule à l'API GitHub Releases.
//!
//! On n'interroge que l'endpoint public `releases/latest`, sans authentification.
//! HTTP minimal via `minreq` + TLS système (schannel sur Windows). Aucune donnée
//! sensible n'est transmise : seule la version installée est comparée localement.

use crate::ErreurMaj;
use serde::Deserialize;
use std::path::{Path, PathBuf};

/// Identifiant de l'agent envoyé à GitHub (obligatoire pour l'API).
const AGENT: &str = "nexkeylock-updater";

/// Un fichier attaché à une release (binaire portable, installateur, sommes…).
#[derive(Debug, Clone, Deserialize)]
pub struct Asset {
    pub name: String,
    #[serde(rename = "browser_download_url")]
    pub url: String,
}

/// Représentation brute renvoyée par l'API (champs utiles uniquement).
#[derive(Debug, Deserialize)]
struct ReleaseBrute {
    tag_name: String,
    #[serde(default)]
    html_url: String,
    #[serde(default)]
    assets: Vec<Asset>,
}

/// Dernière release publiée, normalisée pour notre usage.
#[derive(Debug, Clone)]
pub struct DerniereRelease {
    /// Version sans le préfixe « v » (ex. « 0.2.0 »).
    pub version: String,
    /// Étiquette d'origine (ex. « v0.2.0 »).
    pub etiquette: String,
    /// URL de la page de la release.
    pub url_page: String,
    /// Fichiers attachés.
    pub assets: Vec<Asset>,
}

impl DerniereRelease {
    /// Cherche l'asset installateur (`*installateur*.exe`).
    pub fn installateur(&self) -> Option<&Asset> {
        self.assets.iter().find(|a| {
            let n = a.name.to_ascii_lowercase();
            n.contains("installateur") && n.ends_with(".exe")
        })
    }

    /// Cherche l'asset portable (`*portable*.exe`).
    pub fn portable(&self) -> Option<&Asset> {
        self.assets.iter().find(|a| {
            let n = a.name.to_ascii_lowercase();
            n.contains("portable") && n.ends_with(".exe")
        })
    }
}

/// Analyse une charge JSON de l'API en une `DerniereRelease`.
///
/// Séparé de l'appel réseau pour être testable sans connexion.
pub(crate) fn depuis_json(json: &str) -> Result<DerniereRelease, ErreurMaj> {
    let brute: ReleaseBrute =
        serde_json::from_str(json).map_err(|e| ErreurMaj::Format(e.to_string()))?;
    let version = brute
        .tag_name
        .trim_start_matches('v')
        .trim_start_matches('V')
        .to_string();
    Ok(DerniereRelease {
        version,
        etiquette: brute.tag_name,
        url_page: brute.html_url,
        assets: brute.assets,
    })
}

/// Interroge `releases/latest` du dépôt et renvoie la dernière release.
///
/// `depot` est de la forme « proprietaire/nom ». `timeout_s` borne l'attente.
pub fn derniere_release(depot: &str, timeout_s: u64) -> Result<DerniereRelease, ErreurMaj> {
    let url = format!("https://api.github.com/repos/{depot}/releases/latest");
    let reponse = minreq::get(&url)
        .with_header("User-Agent", AGENT)
        .with_header("Accept", "application/vnd.github+json")
        .with_header("X-GitHub-Api-Version", "2022-11-28")
        .with_timeout(timeout_s)
        .send()
        .map_err(|e| ErreurMaj::Reseau(e.to_string()))?;

    if reponse.status_code != 200 {
        return Err(ErreurMaj::Reseau(format!(
            "GitHub a répondu HTTP {}",
            reponse.status_code
        )));
    }
    let corps = reponse
        .as_str()
        .map_err(|e| ErreurMaj::Format(e.to_string()))?;
    depuis_json(corps)
}

/// Télécharge un asset dans `dossier` et renvoie le chemin du fichier écrit.
pub fn telecharger(asset: &Asset, dossier: &Path, timeout_s: u64) -> Result<PathBuf, ErreurMaj> {
    let reponse = minreq::get(&asset.url)
        .with_header("User-Agent", AGENT)
        .with_max_redirects(5)
        .with_timeout(timeout_s)
        .send()
        .map_err(|e| ErreurMaj::Reseau(e.to_string()))?;

    if reponse.status_code != 200 {
        return Err(ErreurMaj::Reseau(format!(
            "téléchargement impossible (HTTP {})",
            reponse.status_code
        )));
    }
    std::fs::create_dir_all(dossier)?;
    let destination = dossier.join(&asset.name);
    std::fs::write(&destination, reponse.as_bytes())?;
    Ok(destination)
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXEMPLE: &str = r#"{
        "tag_name": "v0.2.0",
        "html_url": "https://github.com/latifnjimoluh/nexkeylock/releases/tag/v0.2.0",
        "assets": [
            {"name": "nexkeylock-0.2.0-installateur.exe", "browser_download_url": "https://example/inst.exe"},
            {"name": "nexkeylock-0.2.0-portable.exe", "browser_download_url": "https://example/port.exe"},
            {"name": "SHA256SUMS.txt", "browser_download_url": "https://example/sums.txt"}
        ]
    }"#;

    #[test]
    fn parse_la_version_sans_prefixe_v() {
        let r = depuis_json(EXEMPLE).unwrap();
        assert_eq!(r.version, "0.2.0");
        assert_eq!(r.etiquette, "v0.2.0");
        assert_eq!(r.assets.len(), 3);
    }

    #[test]
    fn trouve_installateur_et_portable() {
        let r = depuis_json(EXEMPLE).unwrap();
        assert_eq!(
            r.installateur().unwrap().name,
            "nexkeylock-0.2.0-installateur.exe"
        );
        assert_eq!(r.portable().unwrap().name, "nexkeylock-0.2.0-portable.exe");
    }

    #[test]
    fn json_invalide_echoue_proprement() {
        let e = depuis_json("pas du json").unwrap_err();
        assert!(matches!(e, ErreurMaj::Format(_)));
    }
}
