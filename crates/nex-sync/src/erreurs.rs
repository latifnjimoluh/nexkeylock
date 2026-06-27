//! Erreurs typées de la synchronisation.

use nex_cryptographie::ErreurCrypto;
use thiserror::Error;

/// Erreur renvoyée par les opérations de synchronisation.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ErreurSync {
    /// Erreur cryptographique sous-jacente (dérivation, aléa…).
    #[error("erreur cryptographique")]
    Crypto(#[from] ErreurCrypto),

    /// Conflit de concurrence optimiste : la révision distante a changé.
    #[error("conflit de synchronisation (révision distante {0})")]
    Conflit(u64),
}
