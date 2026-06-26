//! Dérivation de sous-clés par **HKDF-SHA256** (RFC 5869).
//!
//! HKDF « étire » une clé maître en plusieurs sous-clés indépendantes, chacune
//! liée à une **étiquette de contexte** (`info`). On l'utilise pour séparer,
//! par exemple, une clé de chiffrement d'une clé d'authentification, sans
//! jamais réutiliser la même clé pour deux usages distincts.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::erreurs::ErreurCrypto;
use crate::secret::{CleSecrete, LONGUEUR_CLE};

/// Applique HKDF-SHA256 (extract-then-expand) sur une matière de clé brute.
///
/// Fonction de bas niveau exposée surtout pour la validation par vecteurs
/// (RFC 5869). Le code applicatif préférera [`deriver_souscle`].
///
/// # Erreurs
/// Renvoie [`ErreurCrypto::DerivationHkdf`] si la longueur de sortie demandée
/// dépasse `255 * 32` octets (limite de HKDF-SHA256).
pub fn hkdf_sha256(
    matiere: &[u8],
    sel: Option<&[u8]>,
    info: &[u8],
    sortie: &mut [u8],
) -> Result<(), ErreurCrypto> {
    let hk = Hkdf::<Sha256>::new(sel, matiere);
    hk.expand(info, sortie)
        .map_err(|_| ErreurCrypto::DerivationHkdf)
}

/// Dérive une sous-clé secrète de 256 bits à partir d'une clé maître.
///
/// `info` est l'étiquette de contexte (p. ex. `b"nexkeylock:dek-v1"`).
///
/// # Erreurs
/// Renvoie [`ErreurCrypto::DerivationHkdf`] en cas d'échec de l'expansion.
pub fn deriver_souscle(
    cle_maitre: &CleSecrete,
    sel: Option<&[u8]>,
    info: &[u8],
) -> Result<CleSecrete, ErreurCrypto> {
    let mut sortie = [0u8; LONGUEUR_CLE];
    hkdf_sha256(cle_maitre.exposer(), sel, info, &mut sortie)?;
    let cle = CleSecrete::depuis_octets(sortie);
    sortie.zeroize();
    Ok(cle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contextes_differents_donnent_souscles_differentes() {
        let maitre = CleSecrete::depuis_octets([0x11u8; LONGUEUR_CLE]);
        let a = deriver_souscle(&maitre, None, b"contexte-a").unwrap();
        let b = deriver_souscle(&maitre, None, b"contexte-b").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn deterministe() {
        let maitre = CleSecrete::depuis_octets([0x22u8; LONGUEUR_CLE]);
        let a = deriver_souscle(&maitre, Some(b"sel"), b"contexte").unwrap();
        let b = deriver_souscle(&maitre, Some(b"sel"), b"contexte").unwrap();
        assert_eq!(a, b);
    }

    /// Vecteurs officiels HKDF-SHA256 de la RFC 5869, annexe A (cas 1 et 2).
    #[test]
    fn vecteurs_officiels_rfc5869() {
        use hex_literal::hex;

        // Cas 1 : entrées courtes.
        let ikm1 = [0x0bu8; 22];
        let sel1 = hex!("000102030405060708090a0b0c");
        let info1 = hex!("f0f1f2f3f4f5f6f7f8f9");
        let mut okm1 = [0u8; 42];
        hkdf_sha256(&ikm1, Some(&sel1), &info1, &mut okm1).unwrap();
        assert_eq!(
            okm1,
            hex!("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
        );

        // Cas 2 : entrées longues, sortie de 82 octets.
        let ikm2 = hex!(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f"
        );
        let sel2 = hex!(
            "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
        );
        let info2 = hex!(
            "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
        );
        let mut okm2 = [0u8; 82];
        hkdf_sha256(&ikm2, Some(&sel2), &info2, &mut okm2).unwrap();
        assert_eq!(
            okm2,
            hex!("b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87")
        );
    }
}
