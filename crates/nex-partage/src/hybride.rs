//! Encapsulation de clé **hybride X25519 + ML-KEM-768**.
//!
//! Conformément à la pratique recommandée (doc de conception §11), on combine un
//! échange classique (X25519) **et** une encapsulation post-quantique
//! (ML-KEM-768, FIPS 203). La clé partagée résulte de `HKDF-SHA256(ss_x25519 ||
//! ss_mlkem)` : le système reste sûr tant qu'**au moins un** des deux tient.
//!
//! Les primitives proviennent de crates auditées (dalek, RustCrypto) — on
//! n'invente rien, on assemble.

use hkdf::Hkdf;
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{KemCore, MlKem768};
use rand::rngs::OsRng;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::Zeroizing;

use nex_cryptographie::CleSecrete;

use crate::erreurs::ErreurPartage;

/// Étiquette de contexte HKDF pour la combinaison hybride.
const CONTEXTE: &[u8] = b"nexkeylock:kem-hybride:v1";

type EkMlKem = <MlKem768 as KemCore>::EncapsulationKey;
type DkMlKem = <MlKem768 as KemCore>::DecapsulationKey;
type CtMlKem = ml_kem::Ciphertext<MlKem768>;

/// Clés privées du destinataire (à conserver secrètes).
pub struct ClesPrivees {
    x: StaticSecret,
    mlkem: DkMlKem,
}

/// Clés publiques du destinataire (partageables).
pub struct ClesPubliques {
    x: PublicKey,
    mlkem: EkMlKem,
}

/// Matériel d'encapsulation transmis avec le message (clé publique éphémère
/// X25519 + texte chiffré ML-KEM).
pub struct Encapsulation {
    x_eph: PublicKey,
    mlkem_ct: CtMlKem,
}

/// Génère une paire de clés hybride pour un destinataire.
pub fn generer_paire() -> (ClesPrivees, ClesPubliques) {
    let x_sec = StaticSecret::random_from_rng(OsRng);
    let x_pub = PublicKey::from(&x_sec);
    let (dk, ek) = MlKem768::generate(&mut OsRng);
    (
        ClesPrivees {
            x: x_sec,
            mlkem: dk,
        },
        ClesPubliques {
            x: x_pub,
            mlkem: ek,
        },
    )
}

/// Combine les deux secrets partagés en une clé symétrique via HKDF-SHA256.
fn combiner(ss_x: &[u8], ss_mlkem: &[u8]) -> Result<CleSecrete, ErreurPartage> {
    let mut ikm = Zeroizing::new(Vec::with_capacity(ss_x.len() + ss_mlkem.len()));
    ikm.extend_from_slice(ss_x);
    ikm.extend_from_slice(ss_mlkem);

    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut sortie = [0u8; 32];
    hk.expand(CONTEXTE, &mut sortie)
        .map_err(|_| ErreurPartage::Derivation)?;
    let cle = CleSecrete::depuis_octets(sortie);
    use zeroize::Zeroize;
    sortie.zeroize();
    Ok(cle)
}

/// Encapsule une clé partagée vers `destinataire`. Renvoie le matériel
/// d'encapsulation (à transmettre) et la clé symétrique (à garder localement).
///
/// # Erreurs
/// [`ErreurPartage::Encapsulation`] ou [`ErreurPartage::Derivation`].
pub fn encapsuler(
    destinataire: &ClesPubliques,
) -> Result<(Encapsulation, CleSecrete), ErreurPartage> {
    // Volet classique : X25519 éphémère.
    let x_eph = EphemeralSecret::random_from_rng(OsRng);
    let x_eph_pub = PublicKey::from(&x_eph);
    let ss_x = x_eph.diffie_hellman(&destinataire.x);

    // Volet post-quantique : ML-KEM-768.
    let (mlkem_ct, ss_mlkem) = destinataire
        .mlkem
        .encapsulate(&mut OsRng)
        .map_err(|_| ErreurPartage::Encapsulation)?;

    let cle = combiner(ss_x.as_bytes(), ss_mlkem.as_slice())?;
    Ok((
        Encapsulation {
            x_eph: x_eph_pub,
            mlkem_ct,
        },
        cle,
    ))
}

/// Décapsule la clé partagée à partir du matériel d'encapsulation et des clés
/// privées du destinataire.
///
/// # Erreurs
/// [`ErreurPartage::Decapsulation`] ou [`ErreurPartage::Derivation`].
pub fn decapsuler(
    destinataire: &ClesPrivees,
    encapsulation: &Encapsulation,
) -> Result<CleSecrete, ErreurPartage> {
    let ss_x = destinataire.x.diffie_hellman(&encapsulation.x_eph);
    let ss_mlkem = destinataire
        .mlkem
        .decapsulate(&encapsulation.mlkem_ct)
        .map_err(|_| ErreurPartage::Decapsulation)?;
    combiner(ss_x.as_bytes(), ss_mlkem.as_slice())
}

#[cfg(test)]
impl Encapsulation {
    /// Accès mutable au texte chiffré ML-KEM (tests d'altération).
    pub(crate) fn ct_mut(&mut self) -> &mut CtMlKem {
        &mut self.mlkem_ct
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accord_de_cle_hybride() {
        let (prive, public) = generer_paire();
        let (encap, cle_emetteur) = encapsuler(&public).unwrap();
        let cle_destinataire = decapsuler(&prive, &encap).unwrap();
        // Les deux parties dérivent la même clé.
        assert_eq!(cle_emetteur, cle_destinataire);
    }

    #[test]
    fn mauvais_destinataire_obtient_une_cle_differente() {
        let (_prive_a, public_a) = generer_paire();
        let (prive_b, _public_b) = generer_paire();
        let (encap, cle_emetteur) = encapsuler(&public_a).unwrap();
        // B n'est pas le destinataire : sa clé diffère (pas de panic).
        let cle_b = decapsuler(&prive_b, &encap).unwrap();
        assert_ne!(cle_emetteur, cle_b);
    }

    #[test]
    fn alteration_du_volet_classique_change_la_cle() {
        let (prive, public) = generer_paire();
        let (mut encap, cle_emetteur) = encapsuler(&public).unwrap();
        // Remplace la clé éphémère X25519 par une autre.
        let autre = EphemeralSecret::random_from_rng(OsRng);
        encap.x_eph = PublicKey::from(&autre);
        let cle = decapsuler(&prive, &encap).unwrap();
        assert_ne!(cle_emetteur, cle);
    }
}
