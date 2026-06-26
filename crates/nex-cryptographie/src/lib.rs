//! # nex-cryptographie
//!
//! Primitives cryptographiques de nexkeylock. Cette bibliothèque assemble
//! exclusivement des implémentations auditées (projet RustCrypto) :
//!
//! - dérivation de clé mémoire-dure : **Argon2id** ([`kdf`]) ;
//! - chiffrement authentifié (AEAD) : **XChaCha20-Poly1305** (défaut) et
//!   **AES-256-GCM** (alternative) ([`aead`]) ;
//! - dérivation de sous-clés : **HKDF-SHA256** ([`hkdf_subcle`]) ;
//! - génération d'aléa via le CSPRNG du système ([`alea`]) ;
//! - types secrets à effacement automatique ([`secret`]) et comparaison à
//!   temps constant.
//!
//! ## Règle d'or
//!
//! Aucune primitive n'est réécrite à la main. On ne fait qu'**assembler**
//! correctement des briques éprouvées.

pub mod aead;
pub mod alea;
pub mod erreurs;
pub mod hkdf_subcle;
pub mod kdf;
pub mod secret;

pub use erreurs::ErreurCrypto;
pub use secret::{CleSecrete, LONGUEUR_CLE};

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
