//! Génération d'aléa cryptographique.
//!
//! On utilise **exclusivement** le CSPRNG du système d'exploitation via
//! [`OsRng`] (`getrandom` : `BCryptGenRandom` sous Windows, `getrandom(2)` sous
//! Linux, `SecRandomCopyBytes` sous macOS). On n'utilise **jamais** de PRNG non
//! cryptographique pour des clés, sels, nonces ou mots de passe générés.
//!
//! On préfère les variantes `try_*` qui renvoient une erreur typée plutôt que
//! de paniquer si la source d'entropie du système est indisponible (échec sûr).

use rand::rngs::OsRng;
use rand::RngCore;

use crate::erreurs::ErreurCrypto;

/// Renvoie un tableau de `N` octets aléatoires issus du CSPRNG du système.
///
/// # Erreurs
/// Renvoie [`ErreurCrypto::Alea`] si la source d'entropie est indisponible.
pub fn octets_aleatoires<const N: usize>() -> Result<[u8; N], ErreurCrypto> {
    let mut tampon = [0u8; N];
    OsRng
        .try_fill_bytes(&mut tampon)
        .map_err(|_| ErreurCrypto::Alea)?;
    Ok(tampon)
}

/// Remplit `destination` avec des octets aléatoires issus du CSPRNG du système.
///
/// # Erreurs
/// Renvoie [`ErreurCrypto::Alea`] si la source d'entropie est indisponible.
pub fn remplir_aleatoire(destination: &mut [u8]) -> Result<(), ErreurCrypto> {
    OsRng
        .try_fill_bytes(destination)
        .map_err(|_| ErreurCrypto::Alea)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deux_tirages_different() {
        // Probabilité de collision sur 32 octets : négligeable (2^-256).
        let a: [u8; 32] = octets_aleatoires().unwrap();
        let b: [u8; 32] = octets_aleatoires().unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn remplit_la_tranche() {
        let mut tampon = [0u8; 16];
        remplir_aleatoire(&mut tampon).unwrap();
        // Au moins un octet non nul (la probabilité du tout-zéro est 2^-128).
        assert!(tampon.iter().any(|&o| o != 0));
    }

    #[test]
    fn taille_zero_est_acceptee() {
        let vide: [u8; 0] = octets_aleatoires().unwrap();
        assert_eq!(vide.len(), 0);
    }
}
