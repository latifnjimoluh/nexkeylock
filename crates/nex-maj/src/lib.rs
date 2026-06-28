//! `nex-maj` — vérification et téléchargement des mises à jour de nexkeylock.
//!
//! Principe (zéro-connaissance compatible) : le client interroge l'API publique
//! GitHub Releases, compare la version installée à la dernière publiée, et ne
//! télécharge un binaire que sur demande explicite. Aucun secret n'est transmis.

mod config;
mod github;
mod notification;

pub use config::Config;
pub use github::{derniere_release, telecharger, Asset, DerniereRelease};
pub use notification::notifier;

use thiserror::Error;

/// Dépôt GitHub officiel de nexkeylock.
pub const DEPOT: &str = "latifnjimoluh/nexkeylock";

/// Délai d'attente réseau pour une vérification explicite (secondes).
pub const TIMEOUT_VERIF: u64 = 10;
/// Délai d'attente, plus court, pour la vérification automatique au lancement.
pub const TIMEOUT_AUTO: u64 = 4;
/// Délai d'attente pour un téléchargement de binaire.
pub const TIMEOUT_TELECHARGEMENT: u64 = 180;

/// Erreurs du sous-système de mise à jour. Aucune ne contient de secret.
#[derive(Debug, Error)]
pub enum ErreurMaj {
    #[error("erreur réseau : {0}")]
    Reseau(String),
    #[error("réponse du serveur illisible : {0}")]
    Format(String),
    #[error("configuration : {0}")]
    Config(String),
    #[error("numéro de version invalide : {0}")]
    Version(String),
    #[error("erreur d'entrée/sortie : {0}")]
    Io(#[from] std::io::Error),
}

/// Résultat d'une vérification de mise à jour.
#[derive(Debug)]
pub enum EtatMaj {
    /// La version installée est la plus récente.
    AJour { version: String },
    /// Une version plus récente est disponible.
    Disponible {
        version_actuelle: String,
        release: DerniereRelease,
    },
}

/// Indique si `candidate` est strictement plus récente que `actuelle` (semver).
/// Les préfixes « v » éventuels sont tolérés des deux côtés.
pub fn est_plus_recente(actuelle: &str, candidate: &str) -> Result<bool, ErreurMaj> {
    let nettoyer = |s: &str| s.trim().trim_start_matches(['v', 'V']).to_string();
    let a = semver::Version::parse(&nettoyer(actuelle))
        .map_err(|e| ErreurMaj::Version(format!("{actuelle} : {e}")))?;
    let c = semver::Version::parse(&nettoyer(candidate))
        .map_err(|e| ErreurMaj::Version(format!("{candidate} : {e}")))?;
    Ok(c > a)
}

/// Vérifie la disponibilité d'une mise à jour par rapport à `version_actuelle`.
pub fn verifier(version_actuelle: &str, timeout_s: u64) -> Result<EtatMaj, ErreurMaj> {
    let release = github::derniere_release(DEPOT, timeout_s)?;
    if est_plus_recente(version_actuelle, &release.version)? {
        Ok(EtatMaj::Disponible {
            version_actuelle: version_actuelle.to_string(),
            release,
        })
    } else {
        Ok(EtatMaj::AJour {
            version: version_actuelle.to_string(),
        })
    }
}

/// Décide si une vérification automatique est due, selon les préférences et
/// l'horloge fournie (horodatage Unix). Fonction pure → testable.
pub fn verification_due(config: &Config, maintenant_unix: u64) -> bool {
    if !config.verification_auto {
        return false;
    }
    let intervalle = config.intervalle_heures.saturating_mul(3600);
    maintenant_unix.saturating_sub(config.derniere_verification_unix) >= intervalle
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comparaison_versions() {
        assert!(est_plus_recente("0.1.0", "0.2.0").unwrap());
        assert!(est_plus_recente("0.1.0", "v0.2.0").unwrap());
        assert!(!est_plus_recente("0.2.0", "0.2.0").unwrap());
        assert!(!est_plus_recente("0.2.0", "0.1.0").unwrap());
        assert!(est_plus_recente("0.2.0", "1.0.0").unwrap());
    }

    #[test]
    fn version_invalide_est_une_erreur() {
        assert!(matches!(
            est_plus_recente("0.1.0", "pas-une-version"),
            Err(ErreurMaj::Version(_))
        ));
    }

    #[test]
    fn verification_due_respecte_le_drapeau() {
        let c = Config {
            verification_auto: false,
            ..Config::default()
        };
        assert!(!verification_due(&c, 9_999_999_999));
    }

    #[test]
    fn verification_due_respecte_l_intervalle() {
        let mut c = Config {
            verification_auto: true,
            intervalle_heures: 24,
            derniere_verification_unix: 1_000_000,
            ..Config::default()
        };
        // 23 h plus tard : pas encore dû.
        assert!(!verification_due(&c, 1_000_000 + 23 * 3600));
        // 24 h plus tard : dû.
        assert!(verification_due(&c, 1_000_000 + 24 * 3600));
        // Jamais vérifié (0) + horloge réaliste : largement dû.
        c.derniere_verification_unix = 0;
        assert!(verification_due(&c, 1_700_000_000));
    }
}
