//! Erreurs typées du partage chiffré.

use nex_cryptographie::ErreurCrypto;
use thiserror::Error;

/// Erreur renvoyée par les opérations de partage hybride.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ErreurPartage {
    /// Échec de l'encapsulation ML-KEM.
    #[error("échec de l'encapsulation post-quantique")]
    Encapsulation,

    /// Échec de la décapsulation ML-KEM.
    #[error("échec de la décapsulation post-quantique")]
    Decapsulation,

    /// Échec de la combinaison HKDF des secrets partagés.
    #[error("échec de la dérivation de la clé hybride")]
    Derivation,

    /// Erreur cryptographique sous-jacente (AEAD, aléa…).
    #[error("erreur cryptographique")]
    Crypto(#[from] ErreurCrypto),
}
