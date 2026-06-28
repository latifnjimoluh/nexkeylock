//! Erreurs de la couche de commandes.
//!
//! Sérialisées vers l'interface sous forme `{ code, message }`. **Aucune ne
//! contient de secret** ; les messages sont neutres et destinés à l'affichage.

use nex_coffre::ErreurCoffre;

/// Erreur renvoyée par une commande Tauri.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ErreurCommande {
    /// Code stable, exploité par l'interface pour distinguer les cas.
    pub code: String,
    /// Message neutre, affichable tel quel.
    pub message: String,
}

impl ErreurCommande {
    fn neuve(code: &str, message: &str) -> Self {
        Self {
            code: code.to_string(),
            message: message.to_string(),
        }
    }

    /// Un coffre existe déjà à l'emplacement cible.
    pub fn coffre_existant() -> Self {
        Self::neuve("coffre_existant", "Un coffre existe déjà.")
    }

    /// Aucun coffre n'a été trouvé à l'emplacement attendu.
    pub fn introuvable() -> Self {
        Self::neuve("introuvable", "Aucun coffre trouvé.")
    }

    /// Mot de passe maître incorrect (message volontairement non discriminant).
    pub fn mot_de_passe() -> Self {
        Self::neuve("mot_de_passe", "Mot de passe maître incorrect.")
    }

    /// État interne incohérent (verrou empoisonné, etc.).
    pub fn interne(detail: &str) -> Self {
        Self::neuve("interne", detail)
    }
}

impl From<ErreurCoffre> for ErreurCommande {
    /// Convertit une erreur du cœur en erreur de commande, **sans divulguer** de
    /// détail sensible (un mot de passe invalide et un en-tête altéré renvoient
    /// le même code, par construction du cœur).
    fn from(erreur: ErreurCoffre) -> Self {
        match erreur {
            ErreurCoffre::MotDePasseInvalide => Self::mot_de_passe(),
            ErreurCoffre::RecuperationAbsente => Self::neuve(
                "recuperation_absente",
                "Aucun code de récupération configuré.",
            ),
            ErreurCoffre::Corrompu => Self::neuve("corrompu", "Le coffre est corrompu."),
            ErreurCoffre::Io(_) => Self::neuve("io", "Erreur d'accès au fichier du coffre."),
            _ => Self::interne("Erreur interne du coffre."),
        }
    }
}
