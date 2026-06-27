//! Format binaire du fichier de coffre (encodage/décodage).
//!
//! Disposition :
//!
//! ```text
//! MAGIE (8 octets) "NEXKLCK1"
//! u32 LE  longueur en-tête | en-tête CBOR (EnteteAuth)
//! u32 LE  longueur         | nonce d'emballage de la DEK
//! u32 LE  longueur         | DEK emballée (chiffrée par la KEK)
//! u32 LE  longueur         | nonce du corps
//! u32 LE  longueur         | corps chiffré (contenu du coffre)
//! ```
//!
//! Le décodeur est **fail-closed** : magie absente, troncature, longueur
//! incohérente ou octets en trop ⇒ [`ErreurCoffre::FormatInvalide`], **sans
//! aucun `panic`** sur entrée arbitraire (cible de fuzzing au Jalon 7).
//!
//! On conserve les octets bruts de l'en-tête ([`FichierCoffre::entete_brut`])
//! pour les réutiliser tels quels comme données associées de l'AEAD, évitant
//! toute divergence de re-sérialisation.

use serde::{Deserialize, Serialize};

use crate::entete::EnteteAuth;
use crate::erreurs::ErreurCoffre;

/// Octets magiques en tête de fichier (8 octets).
pub const MAGIE: &[u8; 8] = b"NEXKLCK1";

/// Bloc de récupération : second emballage de la DEK, par une clé dérivée du
/// code de récupération (voir Jalon 5). Sérialisé en CBOR dans le fichier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlocRecuperation {
    /// Sel du KDF appliqué au code de récupération.
    pub sel: Vec<u8>,
    /// Mémoire Argon2id (Kio).
    pub kdf_m_kio: u32,
    /// Itérations Argon2id.
    pub kdf_t: u32,
    /// Parallelisme Argon2id.
    pub kdf_p: u32,
    /// Nonce d'emballage de la DEK par la clé de récupération.
    pub nonce: Vec<u8>,
    /// DEK emballée par la clé de récupération.
    pub dek_emballee: Vec<u8>,
}

/// Représentation en mémoire d'un fichier de coffre.
#[derive(Debug, Clone)]
pub struct FichierCoffre {
    /// En-tête authentifié décodé.
    pub entete: EnteteAuth,
    /// Octets CBOR exacts de l'en-tête (servent d'AAD pour la DEK).
    pub entete_brut: Vec<u8>,
    /// Nonce ayant servi à emballer la DEK.
    pub nonce_dek: Vec<u8>,
    /// DEK emballée (chiffrée par la KEK).
    pub dek_emballee: Vec<u8>,
    /// Nonce ayant servi à chiffrer le corps.
    pub nonce_corps: Vec<u8>,
    /// Corps chiffré (contenu du coffre).
    pub corps: Vec<u8>,
    /// Bloc de récupération sérialisé en CBOR (vide = aucune récupération).
    pub recuperation: Vec<u8>,
}

impl FichierCoffre {
    /// Encode le fichier en octets.
    pub fn encoder(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            MAGIE.len()
                + 20
                + self.entete_brut.len()
                + self.nonce_dek.len()
                + self.dek_emballee.len()
                + self.nonce_corps.len()
                + self.corps.len(),
        );
        out.extend_from_slice(MAGIE);
        ecrire_bloc(&mut out, &self.entete_brut);
        ecrire_bloc(&mut out, &self.nonce_dek);
        ecrire_bloc(&mut out, &self.dek_emballee);
        ecrire_bloc(&mut out, &self.nonce_corps);
        ecrire_bloc(&mut out, &self.corps);
        ecrire_bloc(&mut out, &self.recuperation);
        out
    }

    /// Décode un fichier de coffre depuis des octets arbitraires.
    ///
    /// # Erreurs
    /// [`ErreurCoffre::FormatInvalide`] sur magie absente, troncature, longueur
    /// incohérente ou octets résiduels ; [`ErreurCoffre::Serialisation`] si
    /// l'en-tête CBOR est illisible.
    pub fn decoder(donnees: &[u8]) -> Result<Self, ErreurCoffre> {
        let mut lecteur = Lecteur::new(donnees);

        let magie = lecteur.lire_octets(MAGIE.len())?;
        if magie != MAGIE {
            return Err(ErreurCoffre::FormatInvalide);
        }

        let entete_brut = lecteur.lire_bloc()?;
        let nonce_dek = lecteur.lire_bloc()?;
        let dek_emballee = lecteur.lire_bloc()?;
        let nonce_corps = lecteur.lire_bloc()?;
        let corps = lecteur.lire_bloc()?;
        let recuperation = lecteur.lire_bloc()?;

        // Aucun octet résiduel n'est toléré (rejet des fichiers tronqués/garnis).
        if !lecteur.est_termine() {
            return Err(ErreurCoffre::FormatInvalide);
        }

        let entete: EnteteAuth = ciborium::from_reader(entete_brut.as_slice())
            .map_err(|_| ErreurCoffre::Serialisation)?;

        Ok(Self {
            entete,
            entete_brut,
            nonce_dek,
            dek_emballee,
            nonce_corps,
            corps,
            recuperation,
        })
    }
}

/// Écrit un bloc « longueur u32 LE + octets ».
fn ecrire_bloc(sortie: &mut Vec<u8>, bloc: &[u8]) {
    // Les blocs proviennent de nos propres structures, bornées en pratique.
    let longueur = bloc.len() as u32;
    sortie.extend_from_slice(&longueur.to_le_bytes());
    sortie.extend_from_slice(bloc);
}

/// Lecteur à curseur, à lectures bornées (jamais de `panic`).
struct Lecteur<'a> {
    donnees: &'a [u8],
    position: usize,
}

impl<'a> Lecteur<'a> {
    fn new(donnees: &'a [u8]) -> Self {
        Self {
            donnees,
            position: 0,
        }
    }

    fn lire_octets(&mut self, n: usize) -> Result<&'a [u8], ErreurCoffre> {
        let fin = self
            .position
            .checked_add(n)
            .ok_or(ErreurCoffre::FormatInvalide)?;
        let tranche = self
            .donnees
            .get(self.position..fin)
            .ok_or(ErreurCoffre::FormatInvalide)?;
        self.position = fin;
        Ok(tranche)
    }

    fn lire_u32(&mut self) -> Result<usize, ErreurCoffre> {
        let octets: [u8; 4] = self
            .lire_octets(4)?
            .try_into()
            .map_err(|_| ErreurCoffre::FormatInvalide)?;
        Ok(u32::from_le_bytes(octets) as usize)
    }

    fn lire_bloc(&mut self) -> Result<Vec<u8>, ErreurCoffre> {
        let longueur = self.lire_u32()?;
        Ok(self.lire_octets(longueur)?.to_vec())
    }

    fn est_termine(&self) -> bool {
        self.position == self.donnees.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entete::EnteteAuth;
    use nex_cryptographie::aead::Algorithme;
    use nex_cryptographie::kdf::ParametresArgon2;

    fn exemple() -> FichierCoffre {
        let entete = EnteteAuth::nouveau(
            Algorithme::XChaCha20Poly1305,
            ParametresArgon2::new(8, 1, 1),
            vec![0x11; 16],
        );
        let entete_brut = entete.aad_dek().unwrap();
        FichierCoffre {
            entete,
            entete_brut,
            nonce_dek: vec![0x01; 24],
            dek_emballee: vec![0x02; 48],
            nonce_corps: vec![0x03; 24],
            corps: vec![0x04; 100],
            recuperation: vec![0x05; 60],
        }
    }

    #[test]
    fn aller_retour_encodage() {
        let f = exemple();
        let octets = f.encoder();
        let decode = FichierCoffre::decoder(&octets).unwrap();
        assert_eq!(decode.entete, f.entete);
        assert_eq!(decode.entete_brut, f.entete_brut);
        assert_eq!(decode.nonce_dek, f.nonce_dek);
        assert_eq!(decode.dek_emballee, f.dek_emballee);
        assert_eq!(decode.nonce_corps, f.nonce_corps);
        assert_eq!(decode.corps, f.corps);
        assert_eq!(decode.recuperation, f.recuperation);
    }

    #[test]
    fn magie_absente_rejetee() {
        let mut octets = exemple().encoder();
        octets[0] ^= 0xFF;
        assert!(matches!(
            FichierCoffre::decoder(&octets),
            Err(ErreurCoffre::FormatInvalide)
        ));
    }

    #[test]
    fn troncature_rejetee() {
        let octets = exemple().encoder();
        for n in 0..octets.len() {
            // Tout préfixe strict doit être rejeté proprement (aucun panic).
            assert!(FichierCoffre::decoder(&octets[..n]).is_err());
        }
    }

    #[test]
    fn octets_residuels_rejetes() {
        let mut octets = exemple().encoder();
        octets.push(0x00);
        assert!(matches!(
            FichierCoffre::decoder(&octets),
            Err(ErreurCoffre::FormatInvalide)
        ));
    }

    #[test]
    fn entree_vide_rejetee() {
        assert!(matches!(
            FichierCoffre::decoder(&[]),
            Err(ErreurCoffre::FormatInvalide)
        ));
    }

    #[test]
    fn longueur_demesuree_rejetee() {
        // Magie valide puis une longueur d'en-tête énorme.
        let mut octets = Vec::new();
        octets.extend_from_slice(MAGIE);
        octets.extend_from_slice(&u32::MAX.to_le_bytes());
        octets.extend_from_slice(&[0u8; 4]);
        assert!(matches!(
            FichierCoffre::decoder(&octets),
            Err(ErreurCoffre::FormatInvalide)
        ));
    }
}
