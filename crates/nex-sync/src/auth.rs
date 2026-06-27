//! Authentification zéro-connaissance par **double dérivation** (style Bitwarden).
//!
//! Le problème : authentifier l'utilisateur auprès d'un serveur **sans** lui
//! transmettre de quoi déchiffrer le coffre. La solution : dériver, à partir de
//! la clé maître (elle-même issue d'Argon2id), une **clé de chiffrement** (qui
//! ne quitte jamais l'appareil) **et** un **hash d'authentification** distinct,
//! via HKDF-SHA256 avec des étiquettes de contexte différentes.
//!
//! - Le *hash d'authentification* est envoyé au serveur pour prouver l'identité.
//! - Le serveur n'en stocke qu'un **vérificateur salé** ([`Verificateur`]) ; une
//!   fuite de sa base n'expose ni la clé maître, ni la clé de chiffrement, ni le
//!   coffre. Les deux dérivations étant indépendantes (HKDF est à sens unique),
//!   connaître le hash d'authentification ne révèle rien de la clé de
//!   chiffrement.

use nex_cryptographie::alea::octets_aleatoires;
use nex_cryptographie::hkdf_subcle::deriver_souscle;
use nex_cryptographie::CleSecrete;

use crate::erreurs::ErreurSync;

/// Contexte HKDF du hash d'authentification (envoyé au serveur).
const CONTEXTE_AUTH: &[u8] = b"nexkeylock:authentification:v1";
/// Contexte HKDF de la clé de chiffrement (reste locale).
pub const CONTEXTE_CHIFFREMENT: &[u8] = b"nexkeylock:chiffrement:v1";
/// Contexte HKDF du vérificateur côté serveur.
const CONTEXTE_VERIF: &[u8] = b"nexkeylock:verificateur:v1";

/// Dérive le **hash d'authentification** à partir de la clé maître. C'est la
/// seule valeur transmise au serveur.
///
/// # Erreurs
/// [`ErreurSync::Crypto`] en cas d'échec HKDF.
pub fn hash_authentification(cle_maitre: &CleSecrete) -> Result<CleSecrete, ErreurSync> {
    Ok(deriver_souscle(cle_maitre, None, CONTEXTE_AUTH)?)
}

/// Dérive la **clé de chiffrement** à partir de la clé maître (reste locale,
/// indépendante du hash d'authentification).
///
/// # Erreurs
/// [`ErreurSync::Crypto`] en cas d'échec HKDF.
pub fn cle_chiffrement(cle_maitre: &CleSecrete) -> Result<CleSecrete, ErreurSync> {
    Ok(deriver_souscle(cle_maitre, None, CONTEXTE_CHIFFREMENT)?)
}

/// Vérificateur stocké côté serveur : un sel et un haché salé du hash
/// d'authentification. Ne permet **pas** de retrouver le hash d'authentification.
#[derive(Debug, Clone)]
pub struct Verificateur {
    sel: Vec<u8>,
    valeur: Vec<u8>,
}

impl Verificateur {
    /// Crée un vérificateur à partir d'un hash d'authentification (côté serveur,
    /// à l'enregistrement).
    ///
    /// # Erreurs
    /// [`ErreurSync::Crypto`] en cas d'échec d'aléa ou de dérivation.
    pub fn creer(hash_auth: &CleSecrete) -> Result<Self, ErreurSync> {
        let sel = octets_aleatoires::<16>()?.to_vec();
        let valeur = deriver_souscle(hash_auth, Some(&sel), CONTEXTE_VERIF)?;
        Ok(Self {
            sel,
            valeur: valeur.exposer().to_vec(),
        })
    }

    /// Vérifie un hash d'authentification présenté, à **temps constant**.
    ///
    /// # Erreurs
    /// [`ErreurSync::Crypto`] en cas d'échec de dérivation.
    pub fn verifier(&self, hash_auth: &CleSecrete) -> Result<bool, ErreurSync> {
        let recalcule = deriver_souscle(hash_auth, Some(&self.sel), CONTEXTE_VERIF)?;
        let attendu = CleSecrete::depuis_tranche(&self.valeur)?;
        // Comparaison à temps constant (CleSecrete délègue à `subtle`).
        Ok(recalcule == attendu)
    }

    /// Sel du vérificateur (stocké côté serveur).
    pub fn sel(&self) -> &[u8] {
        &self.sel
    }

    /// Valeur du vérificateur (stockée côté serveur).
    pub fn valeur(&self) -> &[u8] {
        &self.valeur
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cle_maitre() -> CleSecrete {
        CleSecrete::depuis_octets([0x33; 32])
    }

    #[test]
    fn auth_et_chiffrement_sont_independants() {
        let m = cle_maitre();
        let auth = hash_authentification(&m).unwrap();
        let chiff = cle_chiffrement(&m).unwrap();
        // Les deux dérivations diffèrent et diffèrent de la clé maître.
        assert_ne!(auth, chiff);
        assert_ne!(auth, m);
        assert_ne!(chiff, m);
    }

    #[test]
    fn verificateur_accepte_le_bon_hash() {
        let auth = hash_authentification(&cle_maitre()).unwrap();
        let verif = Verificateur::creer(&auth).unwrap();
        assert!(verif.verifier(&auth).unwrap());
    }

    #[test]
    fn verificateur_rejette_un_mauvais_hash() {
        let auth = hash_authentification(&cle_maitre()).unwrap();
        let verif = Verificateur::creer(&auth).unwrap();
        let autre = hash_authentification(&CleSecrete::depuis_octets([0x44; 32])).unwrap();
        assert!(!verif.verifier(&autre).unwrap());
    }

    #[test]
    fn le_verificateur_ne_stocke_pas_le_hash_en_clair() {
        let auth = hash_authentification(&cle_maitre()).unwrap();
        let verif = Verificateur::creer(&auth).unwrap();
        // Une fuite du vérificateur n'expose pas le hash d'authentification.
        assert_ne!(verif.valeur(), auth.exposer());
    }

    #[test]
    fn deux_verificateurs_du_meme_hash_different() {
        // Sels aléatoires distincts ⇒ vérificateurs distincts.
        let auth = hash_authentification(&cle_maitre()).unwrap();
        let v1 = Verificateur::creer(&auth).unwrap();
        let v2 = Verificateur::creer(&auth).unwrap();
        assert_ne!(v1.valeur(), v2.valeur());
        // Mais les deux acceptent le bon hash.
        assert!(v1.verifier(&auth).unwrap());
        assert!(v2.verifier(&auth).unwrap());
    }
}
