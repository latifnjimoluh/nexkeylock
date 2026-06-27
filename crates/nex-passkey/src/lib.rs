//! # nex-passkey
//!
//! Cœur cryptographique d'un fournisseur de **passkeys** (WebAuthn / FIDO2).
//!
//! Une passkey est une **paire de clés** (ici Ed25519, EdDSA) liée à un compte
//! et à un site (*relying party*). La clé privée ne quitte pas l'appareil ; le
//! site ne stocke que la clé publique. À la connexion, le site envoie un défi,
//! l'authentificateur le signe, le site vérifie.
//!
//! **Résistance à l'hameçonnage** : la signature couvre le condensat du
//! `rp_id` (dans les données d'authentificateur) et l'origine (dans les données
//! client). Une assertion produite pour un faux site ne valide pas pour le vrai.
//!
//! Périmètre : ce crate fournit le **cœur crypto** (génération de clé par site,
//! signature/vérification d'assertion, sérialisation pour stockage chiffré dans
//! le coffre). L'intégration complète du protocole FIDO2 (CTAP2, attestation,
//! API navigateur/plateforme) sort de ce périmètre.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

use nex_cryptographie::alea::octets_aleatoires;
use nex_cryptographie::ErreurCrypto;

/// Erreur du cœur passkey.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ErreurPasskey {
    /// Erreur cryptographique (aléa).
    #[error("erreur cryptographique")]
    Crypto(#[from] ErreurCrypto),

    /// Octets sérialisés invalides.
    #[error("données de passkey invalides")]
    Format,
}

/// Drapeaux des données d'authentificateur : présence (UP) + vérification (UV).
const DRAPEAUX: u8 = 0x05;

/// Clé publique d'une passkey, telle que la stocke le site (*relying party*).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClePubliquePasskey {
    /// Identifiant du site (domaine).
    pub rp_id: String,
    /// Identifiant de la passkey.
    pub credential_id: Vec<u8>,
    /// Clé publique Ed25519 (32 octets).
    pub cle_publique: [u8; 32],
}

/// Assertion produite lors d'une cérémonie d'authentification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assertion {
    /// Données d'authentificateur (condensat rp_id + drapeaux + compteur).
    pub donnees_authentificateur: Vec<u8>,
    /// Signature Ed25519 (64 octets).
    pub signature: Vec<u8>,
    /// Valeur du compteur de signatures.
    pub compteur: u32,
}

/// Passkey complète (clé privée incluse) — à stocker **chiffrée** dans le coffre.
pub struct Passkey {
    rp_id: String,
    credential_id: Vec<u8>,
    cle_signature: SigningKey,
    compteur: u32,
}

/// Condensat SHA-256 du `rp_id`.
fn hachage_rp(rp_id: &str) -> [u8; 32] {
    Sha256::digest(rp_id.as_bytes()).into()
}

/// Encodage canonique des « données client » (type + défi + origine).
fn donnees_client(defi: &[u8], origine: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(16 + defi.len() + origine.len());
    v.extend_from_slice(b"webauthn.get");
    v.push(0x00);
    v.extend_from_slice(defi);
    v.push(0x00);
    v.extend_from_slice(origine.as_bytes());
    v
}

/// Condensat des données client.
fn hachage_donnees_client(defi: &[u8], origine: &str) -> [u8; 32] {
    Sha256::digest(donnees_client(defi, origine)).into()
}

/// Données d'authentificateur : `rpIdHash (32) || drapeaux (1) || compteur (4)`.
fn donnees_authentificateur(rp_id: &str, compteur: u32) -> Vec<u8> {
    let mut v = Vec::with_capacity(37);
    v.extend_from_slice(&hachage_rp(rp_id));
    v.push(DRAPEAUX);
    v.extend_from_slice(&compteur.to_be_bytes());
    v
}

impl Passkey {
    /// Crée une nouvelle passkey pour `rp_id`. Renvoie la passkey (privée) et la
    /// clé publique à enregistrer côté site.
    ///
    /// # Erreurs
    /// [`ErreurPasskey::Crypto`] si la source d'aléa est indisponible.
    pub fn creer(rp_id: impl Into<String>) -> Result<(Self, ClePubliquePasskey), ErreurPasskey> {
        let rp_id = rp_id.into();
        let graine = Zeroizing::new(octets_aleatoires::<32>()?);
        let cle_signature = SigningKey::from_bytes(&graine);
        let credential_id = octets_aleatoires::<16>()?.to_vec();
        let cle_publique = cle_signature.verifying_key().to_bytes();

        let publique = ClePubliquePasskey {
            rp_id: rp_id.clone(),
            credential_id: credential_id.clone(),
            cle_publique,
        };
        let passkey = Self {
            rp_id,
            credential_id,
            cle_signature,
            compteur: 0,
        };
        Ok((passkey, publique))
    }

    /// Identifiant du site.
    pub fn rp_id(&self) -> &str {
        &self.rp_id
    }

    /// Identifiant de la passkey.
    pub fn credential_id(&self) -> &[u8] {
        &self.credential_id
    }

    /// Signe une assertion pour le défi `defi` et l'origine `origine`. Incrémente
    /// le compteur de signatures.
    pub fn signer(&mut self, defi: &[u8], origine: &str) -> Assertion {
        self.compteur = self.compteur.saturating_add(1);
        let auth = donnees_authentificateur(&self.rp_id, self.compteur);
        let cdh = hachage_donnees_client(defi, origine);

        let mut message = auth.clone();
        message.extend_from_slice(&cdh);
        let signature = self.cle_signature.sign(&message);

        Assertion {
            donnees_authentificateur: auth,
            signature: signature.to_bytes().to_vec(),
            compteur: self.compteur,
        }
    }

    /// Sérialise la passkey (clé privée incluse) pour stockage chiffré. Le
    /// tampon est effacé à la libération.
    pub fn vers_octets(&self) -> Zeroizing<Vec<u8>> {
        let mut v = Vec::new();
        ecrire_bloc(&mut v, self.rp_id.as_bytes());
        ecrire_bloc(&mut v, &self.credential_id);
        ecrire_bloc(&mut v, self.cle_signature.to_bytes().as_slice());
        v.extend_from_slice(&self.compteur.to_be_bytes());
        Zeroizing::new(v)
    }

    /// Reconstruit une passkey depuis ses octets.
    ///
    /// # Erreurs
    /// [`ErreurPasskey::Format`] si les octets sont malformés.
    pub fn depuis_octets(donnees: &[u8]) -> Result<Self, ErreurPasskey> {
        let mut lecteur = Lecteur::new(donnees);
        let rp_id =
            String::from_utf8(lecteur.bloc()?.to_vec()).map_err(|_| ErreurPasskey::Format)?;
        let credential_id = lecteur.bloc()?.to_vec();
        let graine: [u8; 32] = lecteur
            .bloc()?
            .try_into()
            .map_err(|_| ErreurPasskey::Format)?;
        let compteur = u32::from_be_bytes(
            lecteur
                .reste(4)?
                .try_into()
                .map_err(|_| ErreurPasskey::Format)?,
        );
        if !lecteur.est_termine() {
            return Err(ErreurPasskey::Format);
        }
        let cle_signature = SigningKey::from_bytes(&graine);
        Ok(Self {
            rp_id,
            credential_id,
            cle_signature,
            compteur,
        })
    }
}

/// Vérifie une assertion côté site (*relying party*), à temps constant pour la
/// signature (déléguée à `ed25519-dalek`).
///
/// Vérifie que le condensat du `rp_id` correspond (liaison au domaine), puis la
/// signature sur `données d'authentificateur || condensat des données client`.
pub fn verifier_assertion(
    publique: &ClePubliquePasskey,
    rp_id_attendu: &str,
    defi: &[u8],
    origine_attendue: &str,
    assertion: &Assertion,
) -> bool {
    // Liaison au domaine : le condensat rp_id doit correspondre.
    let attendu = hachage_rp(rp_id_attendu);
    if assertion.donnees_authentificateur.get(..32) != Some(attendu.as_slice()) {
        return false;
    }

    let cdh = hachage_donnees_client(defi, origine_attendue);
    let mut message = assertion.donnees_authentificateur.clone();
    message.extend_from_slice(&cdh);

    let Ok(cle) = VerifyingKey::from_bytes(&publique.cle_publique) else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(&assertion.signature) else {
        return false;
    };
    cle.verify(&message, &signature).is_ok()
}

// --- Codec longueur-préfixée (privé) --------------------------------------

fn ecrire_bloc(sortie: &mut Vec<u8>, bloc: &[u8]) {
    sortie.extend_from_slice(&(bloc.len() as u32).to_le_bytes());
    sortie.extend_from_slice(bloc);
}

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

    fn reste(&mut self, n: usize) -> Result<&'a [u8], ErreurPasskey> {
        let fin = self.position.checked_add(n).ok_or(ErreurPasskey::Format)?;
        let t = self
            .donnees
            .get(self.position..fin)
            .ok_or(ErreurPasskey::Format)?;
        self.position = fin;
        Ok(t)
    }

    fn bloc(&mut self) -> Result<&'a [u8], ErreurPasskey> {
        let a: [u8; 4] = self
            .reste(4)?
            .try_into()
            .map_err(|_| ErreurPasskey::Format)?;
        let n = u32::from_le_bytes(a) as usize;
        self.reste(n)
    }

    fn est_termine(&self) -> bool {
        self.position == self.donnees.len()
    }
}

/// Version de la bibliothèque, alignée sur le workspace.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    const RP: &str = "exemple.com";
    const ORIGINE: &str = "https://exemple.com";

    #[test]
    fn aller_retour_assertion() {
        let (mut passkey, publique) = Passkey::creer(RP).unwrap();
        let defi = b"defi-aleatoire-du-site";
        let assertion = passkey.signer(defi, ORIGINE);
        assert!(verifier_assertion(&publique, RP, defi, ORIGINE, &assertion));
    }

    #[test]
    fn mauvais_domaine_rejete() {
        // Anti-hameçonnage : une assertion pour exemple.com ne valide pas pour
        // un autre rp_id.
        let (mut passkey, publique) = Passkey::creer(RP).unwrap();
        let assertion = passkey.signer(b"defi", ORIGINE);
        assert!(!verifier_assertion(
            &publique,
            "phishing.example",
            b"defi",
            ORIGINE,
            &assertion
        ));
    }

    #[test]
    fn mauvaise_origine_rejetee() {
        let (mut passkey, publique) = Passkey::creer(RP).unwrap();
        let assertion = passkey.signer(b"defi", ORIGINE);
        assert!(!verifier_assertion(
            &publique,
            RP,
            b"defi",
            "https://phishing.example",
            &assertion
        ));
    }

    #[test]
    fn mauvais_defi_rejete() {
        let (mut passkey, publique) = Passkey::creer(RP).unwrap();
        let assertion = passkey.signer(b"defi-original", ORIGINE);
        assert!(!verifier_assertion(
            &publique,
            RP,
            b"autre-defi",
            ORIGINE,
            &assertion
        ));
    }

    #[test]
    fn signature_alteree_rejetee() {
        let (mut passkey, publique) = Passkey::creer(RP).unwrap();
        let mut assertion = passkey.signer(b"defi", ORIGINE);
        assertion.signature[0] ^= 0x01;
        assert!(!verifier_assertion(
            &publique, RP, b"defi", ORIGINE, &assertion
        ));
    }

    #[test]
    fn autre_passkey_ne_valide_pas() {
        let (mut passkey, _pub_a) = Passkey::creer(RP).unwrap();
        let (_passkey_b, pub_b) = Passkey::creer(RP).unwrap();
        let assertion = passkey.signer(b"defi", ORIGINE);
        // La clé publique de B ne valide pas une assertion signée par A.
        assert!(!verifier_assertion(
            &pub_b, RP, b"defi", ORIGINE, &assertion
        ));
    }

    #[test]
    fn compteur_s_incremente() {
        let (mut passkey, _pub) = Passkey::creer(RP).unwrap();
        let a1 = passkey.signer(b"d", ORIGINE);
        let a2 = passkey.signer(b"d", ORIGINE);
        assert_eq!(a1.compteur, 1);
        assert_eq!(a2.compteur, 2);
    }

    #[test]
    fn serialisation_passkey() {
        let (mut passkey, publique) = Passkey::creer(RP).unwrap();
        // Avance le compteur avant sérialisation.
        let _ = passkey.signer(b"x", ORIGINE);
        let octets = passkey.vers_octets();
        let mut rechargee = Passkey::depuis_octets(&octets).unwrap();
        assert_eq!(rechargee.rp_id(), RP);
        assert_eq!(rechargee.credential_id(), publique.credential_id.as_slice());

        // La passkey rechargée signe une assertion valide (même clé privée).
        let assertion = rechargee.signer(b"defi", ORIGINE);
        assert!(verifier_assertion(
            &publique, RP, b"defi", ORIGINE, &assertion
        ));
        // Le compteur a repris après la valeur sérialisée (1 -> 2).
        assert_eq!(assertion.compteur, 2);
    }

    #[test]
    fn deserialisation_invalide_rejetee() {
        assert!(matches!(
            Passkey::depuis_octets(b"trop court"),
            Err(ErreurPasskey::Format)
        ));
        assert!(matches!(
            Passkey::depuis_octets(&[]),
            Err(ErreurPasskey::Format)
        ));
    }
}
