//! Erreurs typées de la bibliothèque cryptographique.
//!
//! Règle de sécurité : **aucun message d'erreur ne contient de secret** (clé,
//! mot de passe, texte clair, nonce sensible…). Les variantes restent
//! volontairement génériques côté authentification (échec sûr) afin de ne pas
//! fournir d'oracle exploitable.

use thiserror::Error;

/// Erreur renvoyée par les primitives cryptographiques.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ErreurCrypto {
    /// La génération d'aléa par le CSPRNG du système a échoué.
    #[error("échec de la génération d'aléa du système")]
    Alea,

    /// Les paramètres fournis au KDF sont invalides (mémoire, itérations…).
    #[error("paramètres KDF invalides")]
    ParametresKdf,

    /// La dérivation de clé (Argon2id) a échoué.
    #[error("échec de la dérivation de clé")]
    DerivationKdf,

    /// La dérivation de sous-clé (HKDF) a échoué (longueur de sortie invalide).
    #[error("échec de la dérivation HKDF")]
    DerivationHkdf,

    /// Le chiffrement AEAD a échoué.
    #[error("échec du chiffrement authentifié")]
    Chiffrement,

    /// Le déchiffrement a échoué : authentification invalide ou données
    /// altérées. Volontairement indistinct (échec sûr, pas d'oracle).
    #[error("échec du déchiffrement ou de l'authentification")]
    Dechiffrement,

    /// Une longueur d'entrée ne correspond pas à la valeur attendue.
    #[error("longueur invalide : {attendu} octets attendus, {recu} reçus")]
    LongueurInvalide {
        /// Longueur attendue, en octets.
        attendu: usize,
        /// Longueur effectivement reçue, en octets.
        recu: usize,
    },

    /// Identifiant d'algorithme AEAD inconnu rencontré dans un blob.
    #[error("identifiant d'algorithme inconnu : {0:#04x}")]
    AlgorithmeInconnu(u8),
}
