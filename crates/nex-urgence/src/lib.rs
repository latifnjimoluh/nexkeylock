//! # nex-urgence
//!
//! **Accès d'urgence** : permettre à un contact de confiance d'accéder au coffre
//! en cas d'incapacité, sans jamais exposer le contenu au serveur.
//!
//! - **Crypto** : le matériel d'accès (p. ex. un code de récupération) est
//!   **scellé** vers le contact via le partage hybride post-quantique
//!   ([`nex_partage`]). Seul le contact, avec ses clés privées, peut l'ouvrir.
//! - **Politique** : un **mécanisme à délai** — le contact demande l'accès ;
//!   le propriétaire a N secondes pour refuser ; sinon l'accès est accordé. Le
//!   serveur (qui détient le blob scellé) ne le libère qu'à l'échéance et ne
//!   peut rien déchiffrer lui-même.
//!
//! Crate **avancé** (Jalon 6), séparé du cœur audité.

use nex_partage::{partager, recevoir, ClesPrivees, ClesPubliques, ErreurPartage, MessagePartage};
use thiserror::Error;

/// Erreur de l'accès d'urgence.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ErreurUrgence {
    /// Erreur du partage hybride sous-jacent.
    #[error("erreur de partage")]
    Partage(#[from] ErreurPartage),
}

/// État du mécanisme à délai.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EtatAcces {
    /// Aucune demande en cours.
    Inactif,
    /// Demande déposée à l'instant Unix indiqué.
    Demande {
        /// Horodatage Unix de la demande.
        depuis_unix: u64,
    },
    /// Demande refusée par le propriétaire.
    Refuse,
}

/// Accès d'urgence configuré pour un contact : matériel scellé + politique de
/// délai. Le blob scellé est typiquement détenu par le serveur.
#[derive(Debug, Clone)]
pub struct AccesUrgence {
    nom_contact: String,
    acces_scelle: Vec<u8>,
    delai_secondes: u64,
    etat: EtatAcces,
}

impl AccesUrgence {
    /// Configure un accès d'urgence : scelle `materiel_acces` vers le contact.
    ///
    /// # Erreurs
    /// [`ErreurUrgence::Partage`] si le scellement échoue.
    pub fn configurer(
        nom_contact: impl Into<String>,
        contact_public: &ClesPubliques,
        materiel_acces: &[u8],
        delai_secondes: u64,
    ) -> Result<Self, ErreurUrgence> {
        let message = partager(contact_public, materiel_acces)?;
        Ok(Self {
            nom_contact: nom_contact.into(),
            acces_scelle: message.vers_octets(),
            delai_secondes,
            etat: EtatAcces::Inactif,
        })
    }

    /// Le contact dépose une demande d'accès à l'instant `maintenant_unix`.
    pub fn demander(&mut self, maintenant_unix: u64) {
        self.etat = EtatAcces::Demande {
            depuis_unix: maintenant_unix,
        };
    }

    /// Le propriétaire refuse la demande en cours.
    pub fn refuser(&mut self) {
        self.etat = EtatAcces::Refuse;
    }

    /// Réinitialise l'état (annule une demande ou un refus).
    pub fn reinitialiser(&mut self) {
        self.etat = EtatAcces::Inactif;
    }

    /// Indique si l'accès est disponible : une demande est en cours et le délai
    /// est écoulé (et non refusée).
    pub fn acces_disponible(&self, maintenant_unix: u64) -> bool {
        match &self.etat {
            EtatAcces::Demande { depuis_unix } => {
                maintenant_unix.saturating_sub(*depuis_unix) >= self.delai_secondes
            }
            _ => false,
        }
    }

    /// Côté serveur : libère le blob scellé **uniquement** si l'accès est
    /// disponible. Le serveur ne peut pas le déchiffrer.
    pub fn liberer(&self, maintenant_unix: u64) -> Option<&[u8]> {
        if self.acces_disponible(maintenant_unix) {
            Some(&self.acces_scelle)
        } else {
            None
        }
    }

    /// Nom du contact de confiance.
    pub fn nom_contact(&self) -> &str {
        &self.nom_contact
    }

    /// État courant de la demande.
    pub fn etat(&self) -> &EtatAcces {
        &self.etat
    }
}

/// Côté contact : déchiffre le matériel d'accès libéré par le serveur.
///
/// # Erreurs
/// [`ErreurUrgence::Partage`] si le blob est malformé ou non destiné au contact.
pub fn recuperer_materiel(
    contact_prive: &ClesPrivees,
    acces_scelle: &[u8],
) -> Result<Vec<u8>, ErreurUrgence> {
    let message = MessagePartage::depuis_octets(acces_scelle)?;
    Ok(recevoir(contact_prive, &message)?)
}

/// Version de la bibliothèque, alignée sur le workspace.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;
    use nex_partage::generer_paire;

    const DELAI: u64 = 7 * 86_400; // 7 jours
    const MATERIEL: &[u8] = b"code-de-recuperation-d-urgence";

    #[test]
    fn acces_accorde_apres_le_delai() {
        let (contact_prive, contact_public) = generer_paire();
        let mut acces =
            AccesUrgence::configurer("Alice", &contact_public, MATERIEL, DELAI).unwrap();

        // Demande à t0 ; avant l'échéance, rien n'est libéré.
        acces.demander(1_000);
        assert!(acces.liberer(1_000).is_none());
        assert!(acces.liberer(1_000 + DELAI - 1).is_none());

        // À l'échéance, le blob est libéré et le contact le déchiffre.
        let scelle = acces.liberer(1_000 + DELAI).expect("accès disponible");
        let materiel = recuperer_materiel(&contact_prive, scelle).unwrap();
        assert_eq!(materiel, MATERIEL);
    }

    #[test]
    fn refus_bloque_l_acces() {
        let (_contact_prive, contact_public) = generer_paire();
        let mut acces = AccesUrgence::configurer("Bob", &contact_public, MATERIEL, DELAI).unwrap();
        acces.demander(0);
        acces.refuser();
        // Même bien après le délai, l'accès reste bloqué.
        assert!(acces.liberer(10 * DELAI).is_none());
        assert_eq!(acces.etat(), &EtatAcces::Refuse);
    }

    #[test]
    fn sans_demande_aucun_acces() {
        let (_p, contact_public) = generer_paire();
        let acces = AccesUrgence::configurer("Carol", &contact_public, MATERIEL, DELAI).unwrap();
        assert!(acces.liberer(u64::MAX).is_none());
    }

    #[test]
    fn un_autre_contact_ne_peut_pas_dechiffrer() {
        let (_contact_prive, contact_public) = generer_paire();
        let (autre_prive, _autre_public) = generer_paire();
        let mut acces = AccesUrgence::configurer("Dan", &contact_public, MATERIEL, DELAI).unwrap();
        acces.demander(0);
        let scelle = acces.liberer(DELAI).unwrap();
        // Le matériel est scellé pour le bon contact uniquement.
        assert!(recuperer_materiel(&autre_prive, scelle).is_err());
    }
}
