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
use ml_kem::{Encoded, EncodedSizeUser, KemCore, MlKem768};
use rand::rngs::OsRng;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::Zeroizing;

use nex_cryptographie::CleSecrete;

use crate::codec::{ecrire_bloc, Lecteur};
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

/// Construit le **transcript** d'encapsulation à lier dans la dérivation :
/// clé publique éphémère X25519 ‖ clé publique statique du destinataire ‖ texte
/// chiffré ML-KEM. Le lier (façon X-Wing) garantit que la clé dérivée engage
/// l'intégralité du matériel d'encapsulation, et neutralise le caractère non
/// contributif de X25519 (une clé éphémère de petit ordre n'est plus
/// silencieusement « rejouable » sans changer la clé finale).
fn transcript(x_eph: &PublicKey, x_destinataire: &PublicKey, mlkem_ct: &CtMlKem) -> Vec<u8> {
    let mut t = Vec::with_capacity(32 + 32 + mlkem_ct.as_slice().len());
    t.extend_from_slice(x_eph.as_bytes());
    t.extend_from_slice(x_destinataire.as_bytes());
    t.extend_from_slice(mlkem_ct.as_slice());
    t
}

/// Combine les deux secrets partagés **et le transcript d'encapsulation** en une
/// clé symétrique via HKDF-SHA256.
fn combiner(ss_x: &[u8], ss_mlkem: &[u8], transcript: &[u8]) -> Result<CleSecrete, ErreurPartage> {
    let mut ikm = Zeroizing::new(Vec::with_capacity(
        ss_x.len() + ss_mlkem.len() + transcript.len(),
    ));
    ikm.extend_from_slice(ss_x);
    ikm.extend_from_slice(ss_mlkem);
    ikm.extend_from_slice(transcript);

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

    let transcript = transcript(&x_eph_pub, &destinataire.x, &mlkem_ct);
    let cle = combiner(ss_x.as_bytes(), ss_mlkem.as_slice(), &transcript)?;
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
    // Reconstitue le même transcript que l'émetteur (clé publique statique du
    // destinataire dérivée de sa clé privée).
    let x_destinataire = PublicKey::from(&destinataire.x);
    let transcript = transcript(
        &encapsulation.x_eph,
        &x_destinataire,
        &encapsulation.mlkem_ct,
    );
    combiner(ss_x.as_bytes(), ss_mlkem.as_slice(), &transcript)
}

// --- Sérialisation (transport / stockage) ---------------------------------

/// Reconstruit une clé publique X25519 depuis 32 octets.
fn lire_x_pub(octets: &[u8]) -> Result<PublicKey, ErreurPartage> {
    let a: [u8; 32] = octets.try_into().map_err(|_| ErreurPartage::Format)?;
    Ok(PublicKey::from(a))
}

/// Reconstruit une clé secrète X25519 depuis 32 octets.
fn lire_x_sec(octets: &[u8]) -> Result<StaticSecret, ErreurPartage> {
    let a: [u8; 32] = octets.try_into().map_err(|_| ErreurPartage::Format)?;
    Ok(StaticSecret::from(a))
}

/// Reconstruit une clé d'encapsulation ML-KEM depuis ses octets.
fn lire_ek(octets: &[u8]) -> Result<EkMlKem, ErreurPartage> {
    let enc = Encoded::<EkMlKem>::try_from(octets).map_err(|_| ErreurPartage::Format)?;
    Ok(EkMlKem::from_bytes(&enc))
}

/// Reconstruit une clé de décapsulation ML-KEM depuis ses octets.
fn lire_dk(octets: &[u8]) -> Result<DkMlKem, ErreurPartage> {
    let enc = Encoded::<DkMlKem>::try_from(octets).map_err(|_| ErreurPartage::Format)?;
    Ok(DkMlKem::from_bytes(&enc))
}

/// Reconstruit un texte chiffré ML-KEM depuis ses octets.
fn lire_ct(octets: &[u8]) -> Result<CtMlKem, ErreurPartage> {
    CtMlKem::try_from(octets).map_err(|_| ErreurPartage::Format)
}

impl ClesPubliques {
    /// Sérialise le bundle public (clé X25519 + clé d'encapsulation ML-KEM).
    pub fn vers_octets(&self) -> Vec<u8> {
        let mut out = Vec::new();
        ecrire_bloc(&mut out, self.x.as_bytes());
        ecrire_bloc(&mut out, self.mlkem.as_bytes().as_slice());
        out
    }

    /// Reconstruit un bundle public depuis ses octets.
    ///
    /// # Erreurs
    /// [`ErreurPartage::Format`] si les octets sont malformés.
    pub fn depuis_octets(donnees: &[u8]) -> Result<Self, ErreurPartage> {
        let mut lecteur = Lecteur::new(donnees);
        let x = lire_x_pub(lecteur.bloc()?)?;
        let mlkem = lire_ek(lecteur.bloc()?)?;
        if !lecteur.est_termine() {
            return Err(ErreurPartage::Format);
        }
        Ok(Self { x, mlkem })
    }
}

impl ClesPrivees {
    /// Sérialise les clés privées (effacées à la libération du tampon).
    pub fn vers_octets(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Vec::new();
        ecrire_bloc(&mut out, &self.x.to_bytes());
        ecrire_bloc(&mut out, self.mlkem.as_bytes().as_slice());
        Zeroizing::new(out)
    }

    /// Reconstruit les clés privées depuis leurs octets.
    ///
    /// # Erreurs
    /// [`ErreurPartage::Format`] si les octets sont malformés.
    pub fn depuis_octets(donnees: &[u8]) -> Result<Self, ErreurPartage> {
        let mut lecteur = Lecteur::new(donnees);
        let x = lire_x_sec(lecteur.bloc()?)?;
        let mlkem = lire_dk(lecteur.bloc()?)?;
        if !lecteur.est_termine() {
            return Err(ErreurPartage::Format);
        }
        Ok(Self { x, mlkem })
    }
}

impl Encapsulation {
    /// Sérialise le matériel d'encapsulation.
    pub fn vers_octets(&self) -> Vec<u8> {
        let mut out = Vec::new();
        ecrire_bloc(&mut out, self.x_eph.as_bytes());
        ecrire_bloc(&mut out, self.mlkem_ct.as_slice());
        out
    }

    /// Reconstruit le matériel d'encapsulation depuis ses octets.
    ///
    /// # Erreurs
    /// [`ErreurPartage::Format`] si les octets sont malformés.
    pub fn depuis_octets(donnees: &[u8]) -> Result<Self, ErreurPartage> {
        let mut lecteur = Lecteur::new(donnees);
        let x_eph = lire_x_pub(lecteur.bloc()?)?;
        let mlkem_ct = lire_ct(lecteur.bloc()?)?;
        if !lecteur.est_termine() {
            return Err(ErreurPartage::Format);
        }
        Ok(Self { x_eph, mlkem_ct })
    }
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

    #[test]
    fn serialisation_bundle_public() {
        let (prive, public) = generer_paire();
        let octets = public.vers_octets();
        let public2 = ClesPubliques::depuis_octets(&octets).unwrap();
        // Le bundle reconstruit chiffre toujours vers le même destinataire.
        let (encap, cle_s) = encapsuler(&public2).unwrap();
        let cle_r = decapsuler(&prive, &encap).unwrap();
        assert_eq!(cle_s, cle_r);
    }

    #[test]
    fn serialisation_cles_privees() {
        let (prive, public) = generer_paire();
        let octets = prive.vers_octets();
        let prive2 = ClesPrivees::depuis_octets(&octets).unwrap();
        let (encap, cle_s) = encapsuler(&public).unwrap();
        let cle_r = decapsuler(&prive2, &encap).unwrap();
        assert_eq!(cle_s, cle_r);
    }

    #[test]
    fn serialisation_encapsulation() {
        let (prive, public) = generer_paire();
        let (encap, cle_s) = encapsuler(&public).unwrap();
        let octets = encap.vers_octets();
        let encap2 = Encapsulation::depuis_octets(&octets).unwrap();
        let cle_r = decapsuler(&prive, &encap2).unwrap();
        assert_eq!(cle_s, cle_r);
    }

    #[test]
    fn deserialisation_octets_invalides() {
        assert!(matches!(
            ClesPubliques::depuis_octets(b"trop court"),
            Err(ErreurPartage::Format)
        ));
        assert!(matches!(
            ClesPrivees::depuis_octets(&[]),
            Err(ErreurPartage::Format)
        ));
        assert!(matches!(
            Encapsulation::depuis_octets(&[0u8; 10]),
            Err(ErreurPartage::Format)
        ));
    }

    #[test]
    fn tailles_conformes_fips203_ml_kem_768() {
        // Contrôle structurel de conformité FIPS 203 pour ML-KEM-768 :
        //   clé d'encapsulation (ek) = 1184 o ; clé de décapsulation (dk) = 2400 o ;
        //   texte chiffré (ct) = 1088 o ; secret partagé = 32 o.
        // La conformité ACVP complète des *valeurs* reste déléguée à la crate
        // auditée `ml-kem` (qui exécute ces vecteurs) ; on vérifie ici que
        // l'intégration en respecte la structure.
        let (prive, public) = generer_paire();
        assert_eq!(
            public.mlkem.as_bytes().as_slice().len(),
            1184,
            "taille de la clé d'encapsulation ML-KEM-768"
        );
        assert_eq!(
            prive.mlkem.as_bytes().as_slice().len(),
            2400,
            "taille de la clé de décapsulation ML-KEM-768"
        );
        let (encap, cle) = encapsuler(&public).unwrap();
        assert_eq!(
            encap.mlkem_ct.as_slice().len(),
            1088,
            "taille du texte chiffré ML-KEM-768"
        );
        assert_eq!(cle.exposer().len(), 32, "taille du secret partagé");
    }

    #[test]
    fn ml_kem_deterministe() {
        use rand::rngs::StdRng;
        use rand::SeedableRng;

        // Même graine de CSPRNG ⇒ même clé d'encapsulation ML-KEM (la primitive
        // est déterministe pour un aléa donné). La conformité aux vecteurs
        // FIPS 203 / NIST ACVP est déléguée à la crate auditée `ml-kem`.
        let (_dk1, ek1) = MlKem768::generate(&mut StdRng::from_seed([42u8; 32]));
        let (_dk2, ek2) = MlKem768::generate(&mut StdRng::from_seed([42u8; 32]));
        assert_eq!(ek1.as_bytes(), ek2.as_bytes());

        // Graine différente ⇒ clé différente.
        let (_dk3, ek3) = MlKem768::generate(&mut StdRng::from_seed([99u8; 32]));
        assert_ne!(ek1.as_bytes(), ek3.as_bytes());
    }
}
