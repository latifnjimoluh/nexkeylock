//! Types secrets à effacement mémoire automatique.
//!
//! Tout matériel de clé symétrique (KEK, DEK, sous-clés) est porté par
//! [`CleSecrete`], qui garantit :
//!
//! - l'**effacement déterministe** de la mémoire à la libération (`zeroize`) ;
//! - le **verrouillage des pages** (`VirtualLock`/`mlock`) du tampon de clé via
//!   la crate `region`, afin de réduire le risque de pagination du secret vers
//!   le disque (swap). C'est un durcissement **best-effort** : si l'OS le refuse
//!   (quota `RLIMIT_MEMLOCK`, plateforme restreinte), la clé reste utilisable
//!   sans verrou (cf. limites honnêtes dans `SECURITY.md`) ;
//! - une comparaison à **temps constant** (`subtle`) — jamais de `==` qui
//!   fuirait de l'information par le temps ;
//! - un affichage `Debug` **expurgé** (aucun octet de clé n'apparaît dans les
//!   journaux, messages d'erreur ou rapports de plantage).
//!
//! Le tampon est alloué sur le **tas** (`Box`), condition nécessaire au
//! verrouillage de page : son adresse est stable, alors qu'un tableau en pile se
//! déplacerait au gré des déplacements de valeur, invalidant le verrou.
//!
//! Le verrouillage est **compté par page** ([`verrou_pages`]) : plusieurs petits
//! secrets pouvant cohabiter sur une même page, on ne demande à l'OS de
//! verrouiller une page qu'au premier secret qui l'occupe, et de la déverrouiller
//! qu'au départ du dernier — évitant tout déverrouillage prématuré d'une page
//! encore utilisée par un autre secret vivant.

use core::fmt;

use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::alea::octets_aleatoires;
use crate::erreurs::ErreurCrypto;

/// Longueur d'une clé symétrique, en octets (256 bits).
pub const LONGUEUR_CLE: usize = 32;

/// Registre de verrouillage de pages **compté par référence**.
///
/// Les allocations de clés (32 octets) partagent fréquemment une page : un
/// verrouillage/déverrouillage naïf par page provoquerait le déverrouillage de
/// la page d'un secret encore vivant lorsqu'un voisin est libéré. On compte donc
/// les occupants de chaque page : verrouillage OS au passage `0 -> 1`,
/// déverrouillage au passage `1 -> 0`. Toutes les opérations OS sont
/// **best-effort** (un échec est ignoré, jamais de panique).
mod verrou_pages {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};

    fn registre() -> &'static Mutex<HashMap<usize, usize>> {
        static REGISTRE: OnceLock<Mutex<HashMap<usize, usize>>> = OnceLock::new();
        REGISTRE.get_or_init(|| Mutex::new(HashMap::new()))
    }

    /// Adresses de début des pages couvrant `[ptr, ptr + taille)`.
    fn pages(ptr: *const u8, taille: usize) -> Vec<usize> {
        let page = region::page::size();
        let adresse = ptr as usize;
        let debut = adresse & !(page - 1);
        let fin = adresse.saturating_add(taille);
        let mut pages = Vec::new();
        let mut courante = debut;
        while courante < fin {
            pages.push(courante);
            courante = courante.saturating_add(page);
        }
        pages
    }

    /// Incrémente le compte des pages couvertes ; verrouille au passage `0 -> 1`.
    pub(super) fn verrouiller(ptr: *const u8, taille: usize) {
        let page = region::page::size();
        let mut reg = registre().lock().unwrap_or_else(|e| e.into_inner());
        for debut_page in pages(ptr, taille) {
            let compteur = reg.entry(debut_page).or_insert(0);
            if *compteur == 0 {
                if let Ok(garde) = region::lock(debut_page as *const u8, page) {
                    // On garde la page verrouillée ; le déverrouillage est géré
                    // explicitement par `deverrouiller` (passage 1 -> 0).
                    core::mem::forget(garde);
                }
            }
            *compteur += 1;
        }
    }

    /// Décrémente le compte ; déverrouille au passage `1 -> 0`.
    pub(super) fn deverrouiller(ptr: *const u8, taille: usize) {
        let page = region::page::size();
        let mut reg = registre().lock().unwrap_or_else(|e| e.into_inner());
        for debut_page in pages(ptr, taille) {
            if let Some(compteur) = reg.get_mut(&debut_page) {
                *compteur = compteur.saturating_sub(1);
                if *compteur == 0 {
                    reg.remove(&debut_page);
                    let _ = region::unlock(debut_page as *const u8, page);
                }
            }
        }
    }
}

/// Clé symétrique secrète de 256 bits : pages verrouillées (best-effort) et
/// mémoire effacée automatiquement à la libération.
///
/// La valeur interne n'est jamais exposée par `Debug`, `Display`, ni `Deref`.
/// On accède aux octets uniquement via [`CleSecrete::exposer`], de façon
/// explicite et traçable.
pub struct CleSecrete {
    // Tampon sur le tas : adresse stable requise par le verrouillage de page.
    octets: Box<[u8; LONGUEUR_CLE]>,
}

impl CleSecrete {
    /// Enveloppe un tampon déjà alloué sur le tas et verrouille sa page
    /// (best-effort, via le registre compté).
    fn nouveau(octets: Box<[u8; LONGUEUR_CLE]>) -> Self {
        verrou_pages::verrouiller(octets.as_ptr(), LONGUEUR_CLE);
        Self { octets }
    }

    /// Construit une clé à partir d'un tableau de 32 octets.
    ///
    /// Le tableau source (copié sur le tas) est effacé avant le retour.
    pub fn depuis_octets(mut octets: [u8; LONGUEUR_CLE]) -> Self {
        // `[u8; N]` est `Copy` : `Box::new` copie les octets sur le tas, la
        // copie en pile reste donc à effacer explicitement.
        let cle = Self::nouveau(Box::new(octets));
        octets.zeroize();
        cle
    }

    /// Construit une clé à partir d'une tranche, en validant sa longueur.
    ///
    /// # Erreurs
    /// Renvoie [`ErreurCrypto::LongueurInvalide`] si la tranche ne fait pas
    /// exactement [`LONGUEUR_CLE`] octets.
    pub fn depuis_tranche(tranche: &[u8]) -> Result<Self, ErreurCrypto> {
        let mut octets: [u8; LONGUEUR_CLE] =
            tranche
                .try_into()
                .map_err(|_| ErreurCrypto::LongueurInvalide {
                    attendu: LONGUEUR_CLE,
                    recu: tranche.len(),
                })?;
        let cle = Self::depuis_octets(octets);
        octets.zeroize();
        Ok(cle)
    }

    /// Génère une nouvelle clé aléatoire via le CSPRNG du système.
    ///
    /// # Erreurs
    /// Renvoie [`ErreurCrypto::Alea`] si la source d'entropie est indisponible.
    pub fn aleatoire() -> Result<Self, ErreurCrypto> {
        let mut octets = octets_aleatoires::<LONGUEUR_CLE>()?;
        let cle = Self::depuis_octets(octets);
        octets.zeroize();
        Ok(cle)
    }

    /// Expose les octets de la clé. À n'utiliser qu'au moment de passer la clé
    /// à une primitive ; ne pas conserver de copie durable.
    pub fn exposer(&self) -> &[u8; LONGUEUR_CLE] {
        &self.octets
    }
}

impl Clone for CleSecrete {
    fn clone(&self) -> Self {
        // Copie le contenu dans un nouveau tampon verrouillé indépendamment.
        Self::depuis_octets(*self.octets)
    }
}

impl Zeroize for CleSecrete {
    fn zeroize(&mut self) {
        self.octets.zeroize();
    }
}

impl Drop for CleSecrete {
    fn drop(&mut self) {
        // Efface le secret **tant que la page est encore verrouillée**, puis
        // décrémente le compte de la page (déverrouillage OS si elle se libère).
        // Le tampon (`Box`) n'est restitué qu'après le corps de `drop`.
        self.octets.zeroize();
        verrou_pages::deverrouiller(self.octets.as_ptr(), LONGUEUR_CLE);
    }
}

impl ZeroizeOnDrop for CleSecrete {}

impl ConstantTimeEq for CleSecrete {
    fn ct_eq(&self, autre: &Self) -> Choice {
        self.octets.as_ref().ct_eq(autre.octets.as_ref())
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

    #[test]
    fn clone_preserve_le_contenu() {
        let cle = CleSecrete::depuis_octets([0x5Au8; LONGUEUR_CLE]);
        let copie = cle.clone();
        assert_eq!(cle, copie);
        // Tampons distincts (adresses différentes) mais contenu identique.
        assert_ne!(cle.exposer().as_ptr(), copie.exposer().as_ptr());
    }

    #[test]
    fn zeroize_efface_le_tampon() {
        let mut cle = CleSecrete::depuis_octets([0xFFu8; LONGUEUR_CLE]);
        cle.zeroize();
        assert_eq!(cle.exposer(), &[0u8; LONGUEUR_CLE]);
    }

    #[test]
    fn nombreux_secrets_partageant_des_pages() {
        // Stresse le compteur de pages : beaucoup de clés vivent puis meurent
        // dans des ordres variés sans provoquer de double-déverrouillage.
        let mut cles: Vec<CleSecrete> = (0..256)
            .map(|i| CleSecrete::depuis_octets([i as u8; LONGUEUR_CLE]))
            .collect();
        // Libère dans un ordre entrelacé (pairs puis impairs).
        cles.retain(|c| c.exposer()[0] % 2 == 1);
        assert_eq!(cles.len(), 128);
        // Les survivantes restent cohérentes.
        for c in &cles {
            assert_eq!(c.exposer()[0] % 2, 1);
        }
    }
}
