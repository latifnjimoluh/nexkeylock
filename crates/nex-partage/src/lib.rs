//! # nex-partage
//!
//! Partage chiffré de bout en bout pour nexkeylock, reposant sur une
//! **encapsulation de clé hybride X25519 + ML-KEM-768** (résistance
//! post-quantique, doc de conception §11).
//!
//! - [`hybride`] : génération de paires, encapsulation/décapsulation hybride ;
//! - [`partage`] : enveloppe d'un message partagé (encapsulation + AEAD).
//!
//! Ce crate est **avancé** (Jalon 6) et volontairement séparé du cœur audité
//! afin de garder la surface cryptographique principale minimale.

pub(crate) mod codec;
pub mod erreurs;
pub mod hybride;
pub mod partage;

pub use erreurs::ErreurPartage;
pub use hybride::{
    decapsuler, encapsuler, generer_paire, ClesPrivees, ClesPubliques, Encapsulation,
};
pub use partage::{partager, recevoir, MessagePartage};

/// Version de la bibliothèque, alignée sur le workspace.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
