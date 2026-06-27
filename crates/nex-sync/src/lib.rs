//! # nex-sync
//!
//! Synchronisation **zéro-connaissance** pour nexkeylock :
//!
//! - [`auth`] : authentification par **double dérivation** (hash
//!   d'authentification indépendant de la clé de chiffrement) + vérificateur
//!   serveur salé, comparaison à temps constant ;
//! - [`depot`] : transport de **blobs chiffrés opaques** avec révision et
//!   **concurrence optimiste** (détection de conflits), via un dépôt abstrait
//!   *mockable* (aucun réseau réel).
//!
//! Crate **avancé** (Jalon 6), séparé du cœur audité.

pub mod auth;
pub mod depot;
pub mod erreurs;

pub use auth::{cle_chiffrement, hash_authentification, Verificateur};
pub use depot::{BlobRevise, DepotMemoire, DepotSync, EtatLocal, Pousser};
pub use erreurs::ErreurSync;

/// Version de la bibliothèque, alignée sur le workspace.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
