//! Chiffrement authentifié avec données associées (**AEAD**).
//!
//! On n'utilise **jamais** de chiffrement non authentifié. Deux algorithmes
//! sont pris en charge, identifiés par un octet stocké dans chaque blob :
//!
//! - `0x01` — **XChaCha20-Poly1305** (défaut) : nonce de 192 bits, qui peut
//!   être tiré aléatoirement sans risque de collision pratique ;
//! - `0x02` — **AES-256-GCM** (alternative) : nonce de 96 bits qui **doit**
//!   provenir d'un compteur strictement croissant et persistant — jamais
//!   aléatoire. La gestion du compteur incombe à l'appelant (couche coffre).
//!
//! Cette interface prend toujours le nonce en paramètre : le module ne génère
//! pas de nonce pour AES-GCM, afin d'éviter toute réutilisation accidentelle.
//! Pour XChaCha20, [`nonce_aleatoire_xchacha`] fournit un nonce sûr.

use aes_gcm::Aes256Gcm;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::XChaCha20Poly1305;

use crate::alea::octets_aleatoires;
use crate::erreurs::ErreurCrypto;
use crate::secret::CleSecrete;

/// Longueur du nonce XChaCha20-Poly1305 (192 bits).
pub const LONGUEUR_NONCE_XCHACHA: usize = 24;
/// Longueur du nonce AES-256-GCM (96 bits).
pub const LONGUEUR_NONCE_AESGCM: usize = 12;
/// Longueur du tag d'authentification Poly1305 / GCM (128 bits).
pub const LONGUEUR_TAG: usize = 16;

/// Algorithme AEAD, identifié par un octet stable stocké dans les blobs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Algorithme {
    /// XChaCha20-Poly1305 (défaut), identifiant `0x01`.
    XChaCha20Poly1305 = 0x01,
    /// AES-256-GCM (alternative), identifiant `0x02`.
    Aes256Gcm = 0x02,
}

impl Algorithme {
    /// Identifiant d'octet de l'algorithme.
    pub fn identifiant(self) -> u8 {
        self as u8
    }

    /// Reconstruit un algorithme à partir de son identifiant d'octet.
    ///
    /// # Erreurs
    /// Renvoie [`ErreurCrypto::AlgorithmeInconnu`] pour un identifiant inconnu.
    pub fn depuis_identifiant(identifiant: u8) -> Result<Self, ErreurCrypto> {
        match identifiant {
            0x01 => Ok(Self::XChaCha20Poly1305),
            0x02 => Ok(Self::Aes256Gcm),
            autre => Err(ErreurCrypto::AlgorithmeInconnu(autre)),
        }
    }

    /// Longueur de nonce attendue par l'algorithme, en octets.
    pub fn longueur_nonce(self) -> usize {
        match self {
            Self::XChaCha20Poly1305 => LONGUEUR_NONCE_XCHACHA,
            Self::Aes256Gcm => LONGUEUR_NONCE_AESGCM,
        }
    }
}

/// Génère un nonce aléatoire de 192 bits pour XChaCha20-Poly1305.
///
/// Sûr car l'espace de 192 bits rend toute collision pratiquement impossible.
/// **Ne pas** utiliser pour AES-GCM (qui exige un compteur).
///
/// # Erreurs
/// Renvoie [`ErreurCrypto::Alea`] si la source d'entropie est indisponible.
pub fn nonce_aleatoire_xchacha() -> Result<[u8; LONGUEUR_NONCE_XCHACHA], ErreurCrypto> {
    octets_aleatoires::<LONGUEUR_NONCE_XCHACHA>()
}

/// Chiffre `clair` et authentifie `donnees_associees`.
///
/// Renvoie `texte_chiffré || tag` (le tag de 16 octets est ajouté en fin). Le
/// `nonce` est fourni par l'appelant et doit avoir la longueur attendue par
/// l'algorithme ; il ne doit **jamais** être réutilisé avec la même clé.
///
/// # Erreurs
/// - [`ErreurCrypto::LongueurInvalide`] si le nonce a une longueur incorrecte ;
/// - [`ErreurCrypto::Chiffrement`] si le chiffrement échoue.
pub fn chiffrer(
    algorithme: Algorithme,
    cle: &CleSecrete,
    nonce: &[u8],
    clair: &[u8],
    donnees_associees: &[u8],
) -> Result<Vec<u8>, ErreurCrypto> {
    verifier_longueur_nonce(algorithme, nonce)?;
    let charge = Payload {
        msg: clair,
        aad: donnees_associees,
    };
    match algorithme {
        Algorithme::XChaCha20Poly1305 => {
            use chacha20poly1305::XNonce;
            let chiffreur = XChaCha20Poly1305::new_from_slice(cle.exposer())
                .map_err(|_| ErreurCrypto::Chiffrement)?;
            chiffreur
                .encrypt(XNonce::from_slice(nonce), charge)
                .map_err(|_| ErreurCrypto::Chiffrement)
        }
        Algorithme::Aes256Gcm => {
            use aes_gcm::Nonce;
            let chiffreur =
                Aes256Gcm::new_from_slice(cle.exposer()).map_err(|_| ErreurCrypto::Chiffrement)?;
            chiffreur
                .encrypt(Nonce::from_slice(nonce), charge)
                .map_err(|_| ErreurCrypto::Chiffrement)
        }
    }
}

/// Déchiffre et vérifie l'authenticité de `chiffre` (`texte_chiffré || tag`).
///
/// **Échec sûr** : en cas d'altération du texte chiffré, du tag, du nonce ou
/// des données associées, renvoie [`ErreurCrypto::Dechiffrement`] et **aucune**
/// donnée partielle.
///
/// # Erreurs
/// - [`ErreurCrypto::LongueurInvalide`] si le nonce a une longueur incorrecte ;
/// - [`ErreurCrypto::Dechiffrement`] si l'authentification échoue.
pub fn dechiffrer(
    algorithme: Algorithme,
    cle: &CleSecrete,
    nonce: &[u8],
    chiffre: &[u8],
    donnees_associees: &[u8],
) -> Result<Vec<u8>, ErreurCrypto> {
    verifier_longueur_nonce(algorithme, nonce)?;
    let charge = Payload {
        msg: chiffre,
        aad: donnees_associees,
    };
    match algorithme {
        Algorithme::XChaCha20Poly1305 => {
            use chacha20poly1305::XNonce;
            let chiffreur = XChaCha20Poly1305::new_from_slice(cle.exposer())
                .map_err(|_| ErreurCrypto::Dechiffrement)?;
            chiffreur
                .decrypt(XNonce::from_slice(nonce), charge)
                .map_err(|_| ErreurCrypto::Dechiffrement)
        }
        Algorithme::Aes256Gcm => {
            use aes_gcm::Nonce;
            let chiffreur = Aes256Gcm::new_from_slice(cle.exposer())
                .map_err(|_| ErreurCrypto::Dechiffrement)?;
            chiffreur
                .decrypt(Nonce::from_slice(nonce), charge)
                .map_err(|_| ErreurCrypto::Dechiffrement)
        }
    }
}

/// Valide que le nonce a la longueur attendue par l'algorithme.
fn verifier_longueur_nonce(algorithme: Algorithme, nonce: &[u8]) -> Result<(), ErreurCrypto> {
    let attendu = algorithme.longueur_nonce();
    if nonce.len() != attendu {
        return Err(ErreurCrypto::LongueurInvalide {
            attendu,
            recu: nonce.len(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cle() -> CleSecrete {
        CleSecrete::depuis_octets([0x24u8; 32])
    }

    fn algos() -> [Algorithme; 2] {
        [Algorithme::XChaCha20Poly1305, Algorithme::Aes256Gcm]
    }

    #[test]
    fn aller_retour_par_algorithme() {
        for algo in algos() {
            let nonce = vec![0x01u8; algo.longueur_nonce()];
            let clair = b"message secret de test";
            let aad = b"en-tete authentifiee";
            let chiffre = chiffrer(algo, &cle(), &nonce, clair, aad).unwrap();
            assert_eq!(chiffre.len(), clair.len() + LONGUEUR_TAG);
            let dechiffre = dechiffrer(algo, &cle(), &nonce, &chiffre, aad).unwrap();
            assert_eq!(dechiffre, clair);
        }
    }

    #[test]
    fn alteration_du_texte_chiffre_echoue() {
        for algo in algos() {
            let nonce = vec![0x02u8; algo.longueur_nonce()];
            let mut chiffre = chiffrer(algo, &cle(), &nonce, b"abc", b"").unwrap();
            chiffre[0] ^= 0x01;
            assert!(matches!(
                dechiffrer(algo, &cle(), &nonce, &chiffre, b""),
                Err(ErreurCrypto::Dechiffrement)
            ));
        }
    }

    #[test]
    fn alteration_des_donnees_associees_echoue() {
        for algo in algos() {
            let nonce = vec![0x03u8; algo.longueur_nonce()];
            let chiffre = chiffrer(algo, &cle(), &nonce, b"abc", b"aad-correcte").unwrap();
            assert!(matches!(
                dechiffrer(algo, &cle(), &nonce, &chiffre, b"aad-falsifiee"),
                Err(ErreurCrypto::Dechiffrement)
            ));
        }
    }

    #[test]
    fn longueur_de_nonce_invalide_rejetee() {
        let erreur = chiffrer(Algorithme::Aes256Gcm, &cle(), &[0u8; 11], b"x", b"").unwrap_err();
        assert!(matches!(
            erreur,
            ErreurCrypto::LongueurInvalide {
                attendu: 12,
                recu: 11
            }
        ));
    }

    #[test]
    fn identifiants_aller_retour() {
        for algo in algos() {
            let id = algo.identifiant();
            assert_eq!(Algorithme::depuis_identifiant(id).unwrap(), algo);
        }
        assert!(matches!(
            Algorithme::depuis_identifiant(0xFF),
            Err(ErreurCrypto::AlgorithmeInconnu(0xFF))
        ));
    }

    // --- Vecteurs officiels (Known-Answer Tests) ---------------------------
    // Le texte clair commun aux vecteurs ChaCha de la RFC 8439 / du draft
    // XChaCha (114 octets).
    const CLAIR_RFC: &[u8] = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

    /// Vecteur XChaCha20-Poly1305 du draft IRTF CFRG (libsodium), via l'API du
    /// module. `chiffrer` renvoie `texte_chiffré || tag`.
    #[test]
    fn vecteur_xchacha20poly1305_draft() {
        use hex_literal::hex;
        let cle = CleSecrete::depuis_octets(hex!(
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
        ));
        let nonce = hex!("404142434445464748494a4b4c4d4e4f5051525354555657");
        let aad = hex!("50515253c0c1c2c3c4c5c6c7");
        let attendu_ct = hex!(
            "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52e"
        );
        let tag = hex!("c0875924c1c7987947deafd8780acf49");

        let obtenu =
            chiffrer(Algorithme::XChaCha20Poly1305, &cle, &nonce, CLAIR_RFC, &aad).unwrap();
        let mut attendu = attendu_ct.to_vec();
        attendu.extend_from_slice(&tag);
        assert_eq!(obtenu, attendu);

        let dechiffre =
            dechiffrer(Algorithme::XChaCha20Poly1305, &cle, &nonce, &obtenu, &aad).unwrap();
        assert_eq!(dechiffre, CLAIR_RFC);
    }

    /// Vecteur AES-256-GCM « Test Case 14 » (McGrew & Viega / NIST), via l'API
    /// du module : clé/nonce nuls, 16 octets de clair nuls.
    #[test]
    fn vecteur_aes256gcm_test_case_14() {
        use hex_literal::hex;
        let cle = CleSecrete::depuis_octets([0u8; 32]);
        let nonce = [0u8; 12];
        let clair = [0u8; 16];
        let attendu_ct = hex!("cea7403d4d606b6e074ec5d3baf39d18");
        let tag = hex!("d0d1c8a799996bf0265b98b5d48ab919");

        let obtenu = chiffrer(Algorithme::Aes256Gcm, &cle, &nonce, &clair, &[]).unwrap();
        let mut attendu = attendu_ct.to_vec();
        attendu.extend_from_slice(&tag);
        assert_eq!(obtenu, attendu);

        let dechiffre = dechiffrer(Algorithme::Aes256Gcm, &cle, &nonce, &obtenu, &[]).unwrap();
        assert_eq!(dechiffre, clair);
    }

    /// Vecteur AES-256-GCM du jeu NIST CAVP `gcmEncryptExtIV256` (clair et AAD
    /// vides) : la sortie est uniquement le tag d'authentification.
    #[test]
    fn vecteur_aes256gcm_nist_clair_vide() {
        use hex_literal::hex;
        let cle = CleSecrete::depuis_octets(hex!(
            "b52c505a37d78eda5dd34f20c22540ea1b58963cf8e5bf8ffa85f9f2492505b4"
        ));
        let nonce = hex!("516c33929df5a3284ff463d7");
        let tag = hex!("bdc1ac884d332457a1d2664f168c76f0");

        let obtenu = chiffrer(Algorithme::Aes256Gcm, &cle, &nonce, &[], &[]).unwrap();
        assert_eq!(obtenu, tag);
        let dechiffre = dechiffrer(Algorithme::Aes256Gcm, &cle, &nonce, &obtenu, &[]).unwrap();
        assert!(dechiffre.is_empty());
    }

    /// Vecteur ChaCha20-Poly1305 IETF de la RFC 8439 §2.8.2. Exerce la primitive
    /// brute (nonce 96 bits), distincte de la variante XChaCha de l'API.
    #[test]
    fn vecteur_chacha20poly1305_ietf_rfc8439() {
        use chacha20poly1305::aead::{Aead, KeyInit, Payload};
        use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
        use hex_literal::hex;

        let cle = hex!("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        let nonce = hex!("070000004041424344454647");
        let aad = hex!("50515253c0c1c2c3c4c5c6c7");
        let attendu_ct = hex!(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116"
        );
        let tag = hex!("1ae10b594f09e26a7e902ecbd0600691");

        let chiffreur = ChaCha20Poly1305::new(Key::from_slice(&cle));
        let obtenu = chiffreur
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: CLAIR_RFC,
                    aad: &aad,
                },
            )
            .unwrap();
        let mut attendu = attendu_ct.to_vec();
        attendu.extend_from_slice(&tag);
        assert_eq!(obtenu, attendu);
    }
}
