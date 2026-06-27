//! Enveloppe d'un message partagé : encapsulation hybride + AEAD.
//!
//! On encapsule une clé symétrique vers le destinataire, puis on chiffre la
//! charge utile avec cette clé via XChaCha20-Poly1305. Seul le destinataire,
//! détenteur des clés privées, peut décapsuler puis déchiffrer.

use nex_cryptographie::aead::{chiffrer, dechiffrer, nonce_aleatoire_xchacha, Algorithme};

use crate::erreurs::ErreurPartage;
use crate::hybride::{decapsuler, encapsuler, ClesPrivees, ClesPubliques, Encapsulation};

/// Message chiffré de bout en bout à destination d'un utilisateur.
pub struct MessagePartage {
    /// Matériel d'encapsulation hybride.
    pub encapsulation: Encapsulation,
    /// Nonce XChaCha20-Poly1305.
    pub nonce: Vec<u8>,
    /// Texte chiffré (charge utile + tag).
    pub chiffre: Vec<u8>,
}

/// Chiffre `charge` à destination de `destinataire`.
///
/// # Erreurs
/// [`ErreurPartage`] en cas d'échec d'encapsulation, d'aléa ou de chiffrement.
pub fn partager(
    destinataire: &ClesPubliques,
    charge: &[u8],
) -> Result<MessagePartage, ErreurPartage> {
    let (encapsulation, cle) = encapsuler(destinataire)?;
    let nonce = nonce_aleatoire_xchacha()?.to_vec();
    let chiffre = chiffrer(Algorithme::XChaCha20Poly1305, &cle, &nonce, charge, b"")?;
    Ok(MessagePartage {
        encapsulation,
        nonce,
        chiffre,
    })
}

/// Déchiffre un message partagé avec les clés privées du destinataire.
///
/// **Échec sûr** : un message altéré renvoie une erreur, sans donnée partielle.
///
/// # Erreurs
/// [`ErreurPartage`] en cas d'échec de décapsulation ou d'authentification.
pub fn recevoir(
    destinataire: &ClesPrivees,
    message: &MessagePartage,
) -> Result<Vec<u8>, ErreurPartage> {
    let cle = decapsuler(destinataire, &message.encapsulation)?;
    let clair = dechiffrer(
        Algorithme::XChaCha20Poly1305,
        &cle,
        &message.nonce,
        &message.chiffre,
        b"",
    )?;
    Ok(clair)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hybride::generer_paire;

    #[test]
    fn aller_retour_partage() {
        let (prive, public) = generer_paire();
        let charge = b"mot de passe partage : tres-secret";
        let message = partager(&public, charge).unwrap();
        let recu = recevoir(&prive, &message).unwrap();
        assert_eq!(recu, charge);
    }

    #[test]
    fn message_altere_echoue() {
        let (prive, public) = generer_paire();
        let mut message = partager(&public, b"charge").unwrap();
        message.chiffre[0] ^= 0x01;
        assert!(recevoir(&prive, &message).is_err());
    }

    #[test]
    fn mauvais_destinataire_echoue() {
        let (_prive_a, public_a) = generer_paire();
        let (prive_b, _public_b) = generer_paire();
        let message = partager(&public_a, b"charge").unwrap();
        // B n'est pas le destinataire : l'authentification AEAD échoue.
        assert!(recevoir(&prive_b, &message).is_err());
    }

    #[test]
    fn alteration_du_volet_post_quantique_echoue() {
        let (prive, public) = generer_paire();
        let mut message = partager(&public, b"charge").unwrap();
        // Altère le texte chiffré ML-KEM : la clé dérivée change → échec AEAD.
        let ct = message.encapsulation.ct_mut();
        ct[0] ^= 0x01;
        assert!(recevoir(&prive, &message).is_err());
    }
}
