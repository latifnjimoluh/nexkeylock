//! Erreurs typées de la logique du coffre.
//!
//! **Échec sûr** : toute erreur de déchiffrement ou d'authentification renvoie
//! une erreur typée et **aucune** donnée partielle. Aucun message ne contient
//! de secret. On distingue volontairement « mot de passe invalide » (échec du
//! déballage de la DEK) de « coffre corrompu » (échec sur le corps), mais
//! aucune des deux ne fournit d'oracle exploitable sur le contenu.

use nex_cryptographie::ErreurCrypto;
use thiserror::Error;

/// Erreur renvoyée par les opérations sur le coffre.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ErreurCoffre {
    /// Erreur d'entrée/sortie (lecture/écriture du fichier de coffre).
    #[error("erreur d'entrée/sortie : {0}")]
    Io(#[from] std::io::Error),

    /// Erreur cryptographique de bas niveau (hors authentification du coffre).
    #[error("erreur cryptographique")]
    Crypto(#[from] ErreurCrypto),

    /// Échec de (dé)sérialisation du modèle ou de l'en-tête.
    #[error("données du coffre illisibles (sérialisation)")]
    Serialisation,

    /// En-tête de fichier malformé : magie absente, troncature, longueur
    /// incohérente. Détecté avant tout déchiffrement.
    #[error("format de fichier de coffre invalide")]
    FormatInvalide,

    /// Version de format non prise en charge (p. ex. fichier plus récent).
    #[error("version de format de coffre non supportée : {0}")]
    VersionNonSupportee(u16),

    /// Identifiant d'algorithme AEAD non pris en charge à la création.
    #[error("algorithme de chiffrement non supporté pour cette opération")]
    AlgorithmeNonSupporte,

    /// Mot de passe maître invalide : le déballage de la DEK a échoué.
    /// Indistinct d'une altération de l'en-tête authentifié (échec sûr).
    #[error("mot de passe maître invalide ou en-tête altéré")]
    MotDePasseInvalide,

    /// Le corps du coffre n'a pas pu être authentifié (coffre corrompu).
    #[error("coffre corrompu : authentification du contenu invalide")]
    Corrompu,

    /// Aucune entrée ne correspond à l'identifiant fourni.
    #[error("entrée introuvable")]
    EntreeIntrouvable,

    /// Options de génération de mot de passe invalides (jeu vide, longueur 0…).
    #[error("options de génération invalides")]
    OptionsGenerateur,

    /// Erreur lors du calcul TOTP (clé invalide, paramètres hors bornes).
    #[error("erreur de calcul TOTP")]
    Totp,

    /// Chaîne Base32 invalide (secret TOTP mal formé).
    #[error("chaîne Base32 invalide")]
    Base32Invalide,

    /// Échec de la consultation du service de fuites (k-anonymat).
    #[error("échec de la consultation du service de fuites")]
    Fuites,

    /// Aucun code de récupération n'est configuré pour ce coffre.
    #[error("aucun code de récupération n'est configuré")]
    RecuperationAbsente,
}
