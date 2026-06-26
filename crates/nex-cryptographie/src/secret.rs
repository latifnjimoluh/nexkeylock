//! Types secrets à effacement mémoire automatique.
//!
//! Tout matériel de clé symétrique (KEK, DEK, sous-clés) est porté par
//! [`CleSecrete`], qui garantit :
//!
//! - l'**effacement déterministe** de la mémoire à la libération (`zeroize`) ;
//! - une comparaison à **temps constant** (`subtle`) — jamais de `==` qui
//!   fuirait de l'information par le temps ;
//! - un affichage `Debug` **expurgé** (aucun octet de clé n'apparaît dans les
//!   journaux, messages d'erreur ou rapports de plantage).

use core::fmt;

use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::alea::octets_aleatoires;
use crate::erreurs::ErreurCrypto;

/// Longueur d'une clé symétrique, en octets (256 bits).
pub const LONGUEUR_CLE: usize = 32;

/// Clé symétrique secrète de 256 bits, effacée automatiquement à la libération.
///
/// La valeur interne n'est jamais exposée par `Debug`, `Display`, `Clone`
/// implicite verbeux, ni `Deref`. On accède aux octets uniquement via
/// [`CleSecrete::exposer`], de façon explicite et traçable.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct CleSecrete([u8; LONGUEUR_CLE]);

impl CleSecrete {
    /// Construit une clé à partir d'un tableau de 32 octets.
    pub fn depuis_octets(octets: [u8; LONGUEUR_CLE]) -> Self {
        Self(octets)
    }

    /// Construit une clé à partir d'une tranche, en validant sa longueur.
    ///
    /// # Erreurs
    /// Renvoie [`ErreurCrypto::LongueurInvalide`] si la tranche ne fait pas
    /// exactement [`LONGUEUR_CLE`] octets.
    pub fn depuis_tranche(tranche: &[u8]) -> Result<Self, ErreurCrypto> {
        let octets: [u8; LONGUEUR_CLE] =
            tranche
                .try_into()
                .map_err(|_| ErreurCrypto::LongueurInvalide {
                    attendu: LONGUEUR_CLE,
                    recu: tranche.len(),
                })?;
        Ok(Self(octets))
    }

    /// Génère une nouvelle clé aléatoire via le CSPRNG du système.
    ///
    /// # Erreurs
    /// Renvoie [`ErreurCrypto::Alea`] si la source d'entropie est indisponible.
    pub fn aleatoire() -> Result<Self, ErreurCrypto> {
        Ok(Self(octets_aleatoires::<LONGUEUR_CLE>()?))
    }

    /// Expose les octets de la clé. À n'utiliser qu'au moment de passer la clé
    /// à une primitive ; ne pas conserver de copie durable.
    pub fn exposer(&self) -> &[u8; LONGUEUR_CLE] {
        &self.0
    }
}

impl ConstantTimeEq for CleSecrete {
    fn ct_eq(&self, autre: &Self) -> Choice {
        self.0.ct_eq(&autre.0)
    }
}

impl PartialEq for CleSecrete {
    /// Comparaison à **temps constant** (déléguée à `subtle`).
    fn eq(&self, autre: &Self) -> bool {
        self.ct_eq(autre).into()
    }
}

impl Eq for CleSecrete {}

impl fmt::Debug for CleSecrete {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Aucun octet de clé n'est divulgué.
        f.write_str("CleSecrete(***expurgé***)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aller_retour_octets() {
        let octets = [7u8; LONGUEUR_CLE];
        let cle = CleSecrete::depuis_octets(octets);
        assert_eq!(cle.exposer(), &octets);
    }

    #[test]
    fn longueur_invalide_rejetee() {
        let erreur = CleSecrete::depuis_tranche(&[0u8; 31]).unwrap_err();
        assert!(matches!(
            erreur,
            ErreurCrypto::LongueurInvalide {
                attendu: 32,
                recu: 31
            }
        ));
    }

    #[test]
    fn egalite_a_temps_constant() {
        let a = CleSecrete::depuis_octets([1u8; LONGUEUR_CLE]);
        let b = CleSecrete::depuis_octets([1u8; LONGUEUR_CLE]);
        let c = CleSecrete::depuis_octets([2u8; LONGUEUR_CLE]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn debug_n_expose_aucun_octet() {
        let cle = CleSecrete::depuis_octets([0xABu8; LONGUEUR_CLE]);
        let rendu = format!("{cle:?}");
        assert!(!rendu.contains("ab"));
        assert!(!rendu.contains("171"));
        assert!(rendu.contains("expurgé"));
    }

    #[test]
    fn deux_cles_aleatoires_different() {
        let a = CleSecrete::aleatoire().unwrap();
        let b = CleSecrete::aleatoire().unwrap();
        assert_ne!(a, b);
    }
}
