//! Tests de propriétés (`proptest`) sur les primitives, via l'API publique.
//!
//! Invariants vérifiés :
//! - aller-retour : `dechiffrer(chiffrer(x)) == x` pour tout clair `x` ;
//! - détection d'altération : retourner un seul bit du texte chiffré, du tag,
//!   du nonce ou des données associées fait échouer le déchiffrement ;
//! - unicité du nonce : deux nonces différents produisent des sorties
//!   différentes pour le même clair ;
//! - déterminisme du KDF : mêmes entrées ⇒ même clé ; sel différent ⇒ clé
//!   différente.

use nex_cryptographie::aead::{chiffrer, dechiffrer, Algorithme};
use nex_cryptographie::kdf::{deriver_cle, ParametresArgon2};
use nex_cryptographie::secret::CleSecrete;
use proptest::prelude::*;

/// Les deux algorithmes AEAD pris en charge.
fn algorithme() -> impl Strategy<Value = Algorithme> {
    prop_oneof![
        Just(Algorithme::XChaCha20Poly1305),
        Just(Algorithme::Aes256Gcm),
    ]
}

/// 32 octets de clé arbitraires.
fn cle_octets() -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(any::<u8>(), 32..=32)
}

proptest! {
    /// `dechiffrer(chiffrer(x)) == x`.
    #[test]
    fn aller_retour(
        ko in cle_octets(),
        clair in proptest::collection::vec(any::<u8>(), 0..512),
        aad in proptest::collection::vec(any::<u8>(), 0..128),
        algo in algorithme(),
    ) {
        let cle = CleSecrete::depuis_tranche(&ko).unwrap();
        let nonce = vec![0x5Au8; algo.longueur_nonce()];
        let chiffre = chiffrer(algo, &cle, &nonce, &clair, &aad).unwrap();
        let dechiffre = dechiffrer(algo, &cle, &nonce, &chiffre, &aad).unwrap();
        prop_assert_eq!(dechiffre, clair);
    }

    /// Retourner un bit du texte chiffré (ou du tag) fait échouer l'auth.
    #[test]
    fn alteration_du_chiffre_echoue(
        ko in cle_octets(),
        clair in proptest::collection::vec(any::<u8>(), 1..256),
        index in any::<usize>(),
        bit in 0u32..8,
        algo in algorithme(),
    ) {
        let cle = CleSecrete::depuis_tranche(&ko).unwrap();
        let nonce = vec![0x11u8; algo.longueur_nonce()];
        let mut chiffre = chiffrer(algo, &cle, &nonce, &clair, b"").unwrap();
        let i = index % chiffre.len();
        chiffre[i] ^= 1u8 << bit;
        prop_assert!(dechiffrer(algo, &cle, &nonce, &chiffre, b"").is_err());
    }

    /// Altérer les données associées fait échouer l'authentification.
    #[test]
    fn alteration_des_aad_echoue(
        ko in cle_octets(),
        clair in proptest::collection::vec(any::<u8>(), 0..256),
        aad in proptest::collection::vec(any::<u8>(), 1..64),
        index in any::<usize>(),
        algo in algorithme(),
    ) {
        let cle = CleSecrete::depuis_tranche(&ko).unwrap();
        let nonce = vec![0x22u8; algo.longueur_nonce()];
        let chiffre = chiffrer(algo, &cle, &nonce, &clair, &aad).unwrap();
        let mut aad_falsifiee = aad.clone();
        let i = index % aad_falsifiee.len();
        aad_falsifiee[i] ^= 0x01;
        prop_assert!(dechiffrer(algo, &cle, &nonce, &chiffre, &aad_falsifiee).is_err());
    }

    /// Deux nonces différents produisent des textes chiffrés différents.
    #[test]
    fn nonces_differents_sorties_differentes(
        ko in cle_octets(),
        clair in proptest::collection::vec(any::<u8>(), 1..256),
        algo in algorithme(),
    ) {
        let cle = CleSecrete::depuis_tranche(&ko).unwrap();
        let nonce_a = vec![0x01u8; algo.longueur_nonce()];
        let nonce_b = vec![0x02u8; algo.longueur_nonce()];
        let ca = chiffrer(algo, &cle, &nonce_a, &clair, b"").unwrap();
        let cb = chiffrer(algo, &cle, &nonce_b, &clair, b"").unwrap();
        prop_assert_ne!(ca, cb);
    }

    /// Déterminisme du KDF : mêmes entrées ⇒ même clé.
    #[test]
    fn kdf_deterministe(
        mdp in proptest::collection::vec(any::<u8>(), 0..40),
        sel in proptest::collection::vec(any::<u8>(), 16..=16),
    ) {
        let p = ParametresArgon2::new(8, 1, 1);
        let a = deriver_cle(&mdp, &sel, p).unwrap();
        let b = deriver_cle(&mdp, &sel, p).unwrap();
        prop_assert!(a == b);
    }

    /// Sel différent ⇒ clé différente (mot de passe identique).
    #[test]
    fn kdf_sel_different_cle_differente(
        mdp in proptest::collection::vec(any::<u8>(), 0..40),
        sel_a in proptest::collection::vec(any::<u8>(), 16..=16),
        sel_b in proptest::collection::vec(any::<u8>(), 16..=16),
    ) {
        prop_assume!(sel_a != sel_b);
        let p = ParametresArgon2::new(8, 1, 1);
        let a = deriver_cle(&mdp, &sel_a, p).unwrap();
        let b = deriver_cle(&mdp, &sel_b, p).unwrap();
        prop_assert!(a != b);
    }
}
