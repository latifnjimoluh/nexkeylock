//! # nex-cryptographie
//!
//! Primitives cryptographiques de nexkeylock. Cette bibliothèque assemble
//! exclusivement des implémentations auditées (projet RustCrypto) :
//!
//! - dérivation de clé mémoire-dure : **Argon2id** ;
//! - chiffrement authentifié (AEAD) : **XChaCha20-Poly1305** (défaut) et
//!   **AES-256-GCM** (alternative) ;
//! - dérivation de sous-clés : **HKDF-SHA256** ;
//! - génération d'aléa via le CSPRNG du système (`OsRng` / `getrandom`) ;
//! - types secrets à effacement automatique (`zeroize` / `secrecy`) et
//!   comparaison à temps constant (`subtle`).
//!
//! ## Règle d'or
//!
//! Aucune primitive n'est réécrite à la main. On ne fait qu'**assembler**
//! correctement des briques éprouvées. Toute tentation d'implémenter soi-même
//! un chiffrement, un KDF, un MAC ou un générateur d'aléa est une erreur.
//!
//! > Squelette du Jalon 0 : les modules cryptographiques arrivent au Jalon 1,
//! > avec leurs vecteurs de test officiels écrits **avant** l'implémentation.

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
