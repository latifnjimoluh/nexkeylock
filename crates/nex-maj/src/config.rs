//! Configuration persistante de nexkeylock — le « volet paramètres ».
//!
//! Stockée hors du coffre (ce ne sont pas des secrets) dans un fichier JSON :
//!   - Windows : `%APPDATA%\nexkeylock\config.json`
//!   - autres  : `$XDG_CONFIG_HOME/nexkeylock/config.json` ou `~/.config/...`
//!
//! Aucune donnée sensible n'y figure : uniquement des préférences et la date de
//! la dernière vérification de mise à jour.

use crate::ErreurMaj;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

fn vrai() -> bool {
    true
}

fn intervalle_defaut() -> u64 {
    24
}

/// Préférences de l'utilisateur, principalement liées aux mises à jour.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Vérifier automatiquement les mises à jour au lancement.
    #[serde(default = "vrai")]
    pub verification_auto: bool,
    /// Horodatage Unix de la dernière vérification (0 si jamais).
    #[serde(default)]
    pub derniere_verification_unix: u64,
    /// Dernière version vue sur le dépôt (évite de re-notifier en boucle).
    #[serde(default)]
    pub derniere_version_connue: Option<String>,
    /// Intervalle minimal entre deux vérifications automatiques, en heures.
    #[serde(default = "intervalle_defaut")]
    pub intervalle_heures: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            verification_auto: true,
            derniere_verification_unix: 0,
            derniere_version_connue: None,
            intervalle_heures: 24,
        }
    }
}

impl Config {
    /// Charge la configuration depuis le disque. Renvoie la configuration par
    /// défaut si le fichier n'existe pas encore. Échoue seulement si le fichier
    /// existe mais est illisible ou corrompu.
    pub fn charger() -> Result<Self, ErreurMaj> {
        let chemin = Self::chemin()?;
        match std::fs::read(&chemin) {
            Ok(octets) => serde_json::from_slice(&octets)
                .map_err(|e| ErreurMaj::Config(format!("config.json illisible : {e}"))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(ErreurMaj::Io(e)),
        }
    }

    /// Écrit la configuration sur le disque (crée le dossier au besoin).
    pub fn enregistrer(&self) -> Result<(), ErreurMaj> {
        let chemin = Self::chemin()?;
        if let Some(parent) = chemin.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_vec_pretty(self)
            .map_err(|e| ErreurMaj::Config(format!("sérialisation impossible : {e}")))?;
        std::fs::write(&chemin, json)?;
        Ok(())
    }

    /// Chemin du fichier de configuration.
    pub fn chemin() -> Result<PathBuf, ErreurMaj> {
        Ok(repertoire_config()?.join("nexkeylock").join("config.json"))
    }
}

/// Dossier de configuration de base, selon la plateforme.
fn repertoire_config() -> Result<PathBuf, ErreurMaj> {
    #[cfg(windows)]
    {
        std::env::var_os("APPDATA")
            .map(PathBuf::from)
            .ok_or_else(|| ErreurMaj::Config("variable APPDATA introuvable".to_string()))
    }
    #[cfg(not(windows))]
    {
        if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
            Ok(PathBuf::from(xdg))
        } else if let Some(home) = std::env::var_os("HOME") {
            Ok(PathBuf::from(home).join(".config"))
        } else {
            Err(ErreurMaj::Config(
                "ni XDG_CONFIG_HOME ni HOME ne sont définis".to_string(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaut_active_la_verification() {
        let c = Config::default();
        assert!(c.verification_auto);
        assert_eq!(c.intervalle_heures, 24);
        assert_eq!(c.derniere_verification_unix, 0);
        assert!(c.derniere_version_connue.is_none());
    }

    #[test]
    fn serde_aller_retour() {
        let c = Config {
            derniere_version_connue: Some("0.3.0".to_string()),
            derniere_verification_unix: 1_700_000_000,
            ..Config::default()
        };
        let json = serde_json::to_vec(&c).unwrap();
        let relu: Config = serde_json::from_slice(&json).unwrap();
        assert_eq!(relu.derniere_version_connue.as_deref(), Some("0.3.0"));
        assert_eq!(relu.derniere_verification_unix, 1_700_000_000);
    }

    #[test]
    fn champs_manquants_prennent_les_defauts() {
        // Un fichier minimal (ancien format) doit rester lisible.
        let relu: Config = serde_json::from_str("{}").unwrap();
        assert!(relu.verification_auto);
        assert_eq!(relu.intervalle_heures, 24);
    }
}
