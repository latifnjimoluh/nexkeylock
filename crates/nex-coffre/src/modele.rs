//! Modèle de données du coffre déchiffré.
//!
//! Le contenu déchiffré vit en mémoire uniquement pendant que le coffre est
//! déverrouillé. [`ContenuCoffre`] et [`Entree`] implémentent `Zeroize` /
//! `ZeroizeOnDrop` afin d'effacer les secrets à la libération.
//!
//! Limite honnête : `serde` et les `String` peuvent produire des copies
//! intermédiaires que l'on ne contrôle pas entièrement. L'effacement est donc
//! « au mieux » — voir `SECURITY.md`.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Type d'une entrée du coffre.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum TypeEntree {
    /// Identifiants de connexion (URL, utilisateur, mot de passe, TOTP).
    Connexion,
    /// Note sécurisée (texte libre).
    NoteSecurisee,
    /// Secret générique (clé d'API, clé SSH…).
    SecretGenerique,
}

/// Une entrée du coffre. Les champs sensibles sont effacés à la libération.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Entree {
    /// Identifiant unique (hexadécimal, 128 bits aléatoires).
    pub id: String,
    /// Type de l'entrée.
    #[zeroize(skip)]
    pub type_entree: TypeEntree,
    /// Nom lisible de l'entrée.
    pub nom: String,
    /// URI(s) associées.
    pub uris: Vec<String>,
    /// Nom d'utilisateur, le cas échéant.
    pub nom_utilisateur: Option<String>,
    /// Mot de passe, le cas échéant (secret).
    pub mot_de_passe: Option<String>,
    /// Secret TOTP au format `otpauth://`/Base32, le cas échéant (secret).
    pub secret_totp: Option<String>,
    /// Notes libres (potentiellement sensibles).
    pub notes: Option<String>,
    /// Date de création (secondes Unix).
    pub cree_le: u64,
    /// Date de dernière modification (secondes Unix).
    pub maj_le: u64,
}

impl Entree {
    /// Crée une entrée minimale de type « connexion ».
    pub fn connexion(id: impl Into<String>, nom: impl Into<String>, horodatage: u64) -> Self {
        Self {
            id: id.into(),
            type_entree: TypeEntree::Connexion,
            nom: nom.into(),
            uris: Vec::new(),
            nom_utilisateur: None,
            mot_de_passe: None,
            secret_totp: None,
            notes: None,
            cree_le: horodatage,
            maj_le: horodatage,
        }
    }
}

impl core::fmt::Debug for Entree {
    /// `Debug` expurgé : aucun secret (mot de passe, TOTP, notes) n'est affiché.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Entree")
            .field("id", &self.id)
            .field("type_entree", &self.type_entree)
            .field("nom", &self.nom)
            .field("uris", &self.uris)
            .field("nom_utilisateur", &self.nom_utilisateur)
            .field("mot_de_passe", &self.mot_de_passe.as_ref().map(|_| "***"))
            .field("secret_totp", &self.secret_totp.as_ref().map(|_| "***"))
            .field("notes", &self.notes.as_ref().map(|_| "***"))
            .field("cree_le", &self.cree_le)
            .field("maj_le", &self.maj_le)
            .finish()
    }
}

/// Contenu déchiffré complet du coffre (sérialisé en CBOR avant chiffrement).
#[derive(Debug, Clone, Default, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct ContenuCoffre {
    /// Entrées du coffre.
    pub entrees: Vec<Entree>,
}

impl ContenuCoffre {
    /// Cherche une entrée par identifiant.
    pub fn obtenir(&self, id: &str) -> Option<&Entree> {
        self.entrees.iter().find(|e| e.id == id)
    }

    /// Cherche une entrée modifiable par identifiant.
    pub fn obtenir_mut(&mut self, id: &str) -> Option<&mut Entree> {
        self.entrees.iter_mut().find(|e| e.id == id)
    }

    /// Supprime une entrée par identifiant ; renvoie `true` si elle existait.
    pub fn supprimer(&mut self, id: &str) -> bool {
        let avant = self.entrees.len();
        self.entrees.retain(|e| e.id != id);
        self.entrees.len() != avant
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_expurge_les_secrets() {
        let mut e = Entree::connexion("id1", "Banque", 0);
        e.mot_de_passe = Some("super-secret".to_string());
        e.notes = Some("note confidentielle".to_string());
        let rendu = format!("{e:?}");
        assert!(!rendu.contains("super-secret"));
        assert!(!rendu.contains("confidentielle"));
        assert!(rendu.contains("***"));
        assert!(rendu.contains("Banque"));
    }

    #[test]
    fn obtenir_et_supprimer() {
        let mut c = ContenuCoffre::default();
        c.entrees.push(Entree::connexion("a", "A", 0));
        c.entrees.push(Entree::connexion("b", "B", 0));
        assert!(c.obtenir("a").is_some());
        assert!(c.supprimer("a"));
        assert!(!c.supprimer("a"));
        assert!(c.obtenir("a").is_none());
        assert_eq!(c.entrees.len(), 1);
    }
}
