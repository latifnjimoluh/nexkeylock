//! # nex-coffre
//!
//! Logique du coffre zéro-connaissance de nexkeylock :
//!
//! - modèle de données des entrées (connexions, notes, cartes, identités…) ;
//! - hiérarchie de clés à deux niveaux **KEK** (dérivée du mot de passe) qui
//!   emballe la **DEK** (aléatoire) ;
//! - format de coffre **versionné** et **authentifié** (en-tête passé comme
//!   données associées de l'AEAD) ;
//! - stockage fichier local, ouverture/fermeture, verrouillage automatique et
//!   effacement mémoire au verrouillage.
//!
//! Cette couche ne connaît rien de l'interface utilisateur et s'appuie
//! uniquement sur [`nex_cryptographie`] pour les primitives.
//!
//! > Squelette du Jalon 0 : le modèle et le format arrivent au Jalon 2.

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
