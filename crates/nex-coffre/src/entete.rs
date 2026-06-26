//! En-tête authentifié du coffre.
//!
//! L'en-tête est stocké **en clair** mais **authentifié** : ses champs servent
//! de « données associées » (AAD) de l'AEAD, de sorte qu'aucune altération
//! (downgrade de version, substitution d'algorithme, affaiblissement des
//! paramètres KDF, échange de sel) ne puisse passer inaperçue.
//!
//! Deux AAD distinctes sont dérivées de l'en-tête :
//!
//! - [`EnteteAuth::aad_dek`] (version, algorithme, paramètres KDF, sel) protège
//!   l'**emballage de la DEK** par la KEK ;
//! - [`EnteteAuth::aad_corps`] (version, algorithme uniquement) protège le
//!   **corps** chiffré.
//!
//! Cette séparation permet à un changement de mot de passe de ne réemballer que
//! la DEK (nouveau sel ⇒ nouvelle `aad_dek`) **sans** rechiffrer le corps
//! (dont l'`aad_corps` reste stable).

use nex_cryptographie::aead::Algorithme;
use nex_cryptographie::kdf::ParametresArgon2;
use serde::{Deserialize, Serialize};

use crate::erreurs::ErreurCoffre;

/// Version maximale du format de coffre prise en charge.
pub const VERSION_FORMAT: u16 = 1;

/// Identifiant du KDF Argon2id dans l'en-tête.
pub const KDF_ARGON2ID: u8 = 0x01;

/// En-tête authentifié, sérialisé en clair dans le fichier de coffre.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnteteAuth {
    /// Version du format.
    pub version: u16,
    /// Identifiant de l'algorithme AEAD (cf. [`Algorithme::identifiant`]).
    pub algorithme: u8,
    /// Identifiant du KDF (1 = Argon2id).
    pub kdf_algo: u8,
    /// Mémoire Argon2id, en Kio.
    pub kdf_m_kio: u32,
    /// Itérations Argon2id.
    pub kdf_t: u32,
    /// Parallelisme Argon2id.
    pub kdf_p: u32,
    /// Sel du KDF (≥ 16 octets, en clair, unique par coffre).
    pub sel: Vec<u8>,
}

impl EnteteAuth {
    /// Construit un en-tête pour un nouveau coffre.
    pub fn nouveau(algorithme: Algorithme, parametres: ParametresArgon2, sel: Vec<u8>) -> Self {
        Self {
            version: VERSION_FORMAT,
            algorithme: algorithme.identifiant(),
            kdf_algo: KDF_ARGON2ID,
            kdf_m_kio: parametres.memoire_kio,
            kdf_t: parametres.iterations,
            kdf_p: parametres.parallelisme,
            sel,
        }
    }

    /// Valide la version et l'algorithme, et renvoie l'[`Algorithme`] décodé.
    ///
    /// # Erreurs
    /// - [`ErreurCoffre::VersionNonSupportee`] si la version est trop récente ;
    /// - [`ErreurCoffre::AlgorithmeNonSupporte`] si l'algorithme est inconnu ;
    /// - [`ErreurCoffre::FormatInvalide`] si le KDF est inconnu.
    pub fn valider(&self) -> Result<Algorithme, ErreurCoffre> {
        if self.version == 0 || self.version > VERSION_FORMAT {
            return Err(ErreurCoffre::VersionNonSupportee(self.version));
        }
        if self.kdf_algo != KDF_ARGON2ID {
            return Err(ErreurCoffre::FormatInvalide);
        }
        Algorithme::depuis_identifiant(self.algorithme)
            .map_err(|_| ErreurCoffre::AlgorithmeNonSupporte)
    }

    /// Paramètres Argon2id de l'en-tête.
    pub fn parametres_kdf(&self) -> ParametresArgon2 {
        ParametresArgon2::new(self.kdf_m_kio, self.kdf_t, self.kdf_p)
    }

    /// Données associées authentifiant l'**emballage de la DEK** : sérialisation
    /// CBOR déterministe de l'en-tête complet (version, algo, KDF, sel).
    ///
    /// # Erreurs
    /// [`ErreurCoffre::Serialisation`] si l'encodage CBOR échoue.
    pub fn aad_dek(&self) -> Result<Vec<u8>, ErreurCoffre> {
        let mut tampon = Vec::new();
        ciborium::into_writer(self, &mut tampon).map_err(|_| ErreurCoffre::Serialisation)?;
        Ok(tampon)
    }

    /// Données associées authentifiant le **corps** : version et algorithme
    /// uniquement, donc stables lors d'un changement de mot de passe.
    pub fn aad_corps(&self) -> Vec<u8> {
        let mut aad = Vec::with_capacity(3);
        aad.extend_from_slice(&self.version.to_le_bytes());
        aad.push(self.algorithme);
        aad
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entete() -> EnteteAuth {
        EnteteAuth::nouveau(
            Algorithme::XChaCha20Poly1305,
            ParametresArgon2::new(8, 1, 1),
            vec![0x11; 16],
        )
    }

    #[test]
    fn validation_ok() {
        assert_eq!(entete().valider().unwrap(), Algorithme::XChaCha20Poly1305);
    }

    #[test]
    fn version_trop_recente_rejetee() {
        let mut e = entete();
        e.version = VERSION_FORMAT + 1;
        assert!(matches!(
            e.valider(),
            Err(ErreurCoffre::VersionNonSupportee(_))
        ));
    }

    #[test]
    fn version_zero_rejetee() {
        let mut e = entete();
        e.version = 0;
        assert!(matches!(
            e.valider(),
            Err(ErreurCoffre::VersionNonSupportee(0))
        ));
    }

    #[test]
    fn kdf_inconnu_rejete() {
        let mut e = entete();
        e.kdf_algo = 0xFF;
        assert!(matches!(e.valider(), Err(ErreurCoffre::FormatInvalide)));
    }

    #[test]
    fn aad_corps_change_si_version_ou_algo_change() {
        let e = entete();
        let base = e.aad_corps();
        let mut e2 = e.clone();
        e2.algorithme = Algorithme::Aes256Gcm.identifiant();
        assert_ne!(base, e2.aad_corps());
        // Le sel ne doit PAS influencer l'aad_corps (stabilité au changement
        // de mot de passe).
        let mut e3 = e.clone();
        e3.sel = vec![0x99; 16];
        assert_eq!(base, e3.aad_corps());
    }

    #[test]
    fn aad_dek_change_si_sel_change() {
        let e = entete();
        let mut e2 = e.clone();
        e2.sel = vec![0x99; 16];
        assert_ne!(e.aad_dek().unwrap(), e2.aad_dek().unwrap());
    }
}
