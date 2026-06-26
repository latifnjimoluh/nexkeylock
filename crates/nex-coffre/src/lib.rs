//! # nex-coffre
//!
//! Logique du coffre zéro-connaissance de nexkeylock, bâtie sur
//! [`nex_cryptographie`] :
//!
//! - [`modele`] : modèle de données des entrées (effacement automatique) ;
//! - [`entete`] : en-tête versionné et **authentifié** (deux AAD) ;
//! - [`format`] : format binaire sur disque (décodage fail-closed) ;
//! - [`coffre`] : API verrouillé / déverrouillé, hiérarchie KEK/DEK, stockage
//!   fichier atomique, changement de mot de passe (réemballage DEK), auto-lock.
//!
//! Cette couche ne connaît rien de l'interface utilisateur.

pub mod coffre;
pub mod entete;
pub mod erreurs;
pub mod format;
pub mod modele;

pub use coffre::{maintenant_unix, nouvel_identifiant, CoffreDeverrouille, CoffreVerrouille};
pub use erreurs::ErreurCoffre;
pub use modele::{ContenuCoffre, Entree, TypeEntree};

// Réexports utiles pour configurer un coffre sans dépendre directement de
// nex-cryptographie.
pub use nex_cryptographie::aead::Algorithme;
pub use nex_cryptographie::kdf::ParametresArgon2;

/// Version de la bibliothèque, alignée sur le workspace.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn la_version_est_renseignee() {
        assert!(!VERSION.is_empty());
    }
}
