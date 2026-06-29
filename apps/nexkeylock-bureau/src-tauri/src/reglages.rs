//! Réglages de l'application de bureau (préférences, **aucun secret**).
//!
//! Stockés en JSON dans `%APPDATA%\nexkeylock\reglages-bureau.json` (Windows)
//! ou `~/.config/nexkeylock/...`. Séparés des réglages de la CLI/updater.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::erreur::ErreurCommande;

fn defaut_auto_lock() -> u64 {
    5
}
fn defaut_presse_papiers() -> u64 {
    20
}

/// Préférences de l'utilisateur (délais d'inactivité et de presse-papiers).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Reglages {
    /// Délai d'inactivité avant verrouillage automatique, en minutes.
    #[serde(default = "defaut_auto_lock")]
    pub delai_auto_lock_min: u64,
    /// Délai avant effacement du presse-papiers, en secondes.
    #[serde(default = "defaut_presse_papiers")]
    pub delai_presse_papiers_s: u64,
    /// URL du serveur de synchronisation (ex. `http://127.0.0.1:8787`), le cas échéant.
    #[serde(default)]
    pub serveur_sync: Option<String>,
    /// Email du compte de synchronisation, le cas échéant.
    #[serde(default)]
    pub email_sync: Option<String>,
    /// Dernière révision synchronisée connue (concurrence optimiste).
    #[serde(default)]
    pub revision_sync: u64,
}

impl Default for Reglages {
    fn default() -> Self {
        Self {
            delai_auto_lock_min: defaut_auto_lock(),
            delai_presse_papiers_s: defaut_presse_papiers(),
            serveur_sync: None,
            email_sync: None,
            revision_sync: 0,
        }
    }
}

impl Reglages {
    /// Charge les réglages (défauts si le fichier est absent).
    pub fn charger() -> Result<Self, ErreurCommande> {
        let chemin = Self::chemin()?;
        match std::fs::read(&chemin) {
            Ok(octets) => serde_json::from_slice(&octets)
                .map_err(|_| ErreurCommande::interne("Réglages illisibles.")),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(_) => Err(ErreurCommande::interne("Lecture des réglages impossible.")),
        }
    }

    /// Valide et enregistre les réglages (bornes raisonnables).
    pub fn enregistrer(&self) -> Result<(), ErreurCommande> {
        if self.delai_auto_lock_min == 0 || self.delai_presse_papiers_s == 0 {
            return Err(ErreurCommande::interne(
                "Les délais doivent être d'au moins 1.",
            ));
        }
        let chemin = Self::chemin()?;
        if let Some(parent) = chemin.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|_| ErreurCommande::interne("Dossier de réglages inaccessible."))?;
        }
        let json = serde_json::to_vec_pretty(self)
            .map_err(|_| ErreurCommande::interne("Sérialisation des réglages impossible."))?;
        std::fs::write(&chemin, json)
            .map_err(|_| ErreurCommande::interne("Écriture des réglages impossible."))?;
        Ok(())
    }

    fn chemin() -> Result<PathBuf, ErreurCommande> {
        Ok(repertoire_config()?
            .join("nexkeylock")
            .join("reglages-bureau.json"))
    }
}

fn repertoire_config() -> Result<PathBuf, ErreurCommande> {
    #[cfg(windows)]
    {
        std::env::var_os("APPDATA")
            .map(PathBuf::from)
            .ok_or_else(|| ErreurCommande::interne("APPDATA introuvable."))
    }
    #[cfg(not(windows))]
    {
        if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
            Ok(PathBuf::from(xdg))
        } else if let Some(home) = std::env::var_os("HOME") {
            Ok(PathBuf::from(home).join(".config"))
        } else {
            Err(ErreurCommande::interne("HOME introuvable."))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defauts_coherents() {
        let r = Reglages::default();
        assert_eq!(r.delai_auto_lock_min, 5);
        assert_eq!(r.delai_presse_papiers_s, 20);
    }

    #[test]
    fn serde_camelcase_et_defauts() {
        // Champs manquants => défauts.
        let r: Reglages = serde_json::from_str("{}").unwrap();
        assert_eq!(r.delai_auto_lock_min, 5);
        // Format camelCase attendu côté interface.
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("delaiAutoLockMin"));
        assert!(json.contains("delaiPressePapiersS"));
    }
}
