//! Client de **synchronisation zéro-connaissance** (vers `nex-serveur-sync`).
//!
//! Le mot de passe maître ne quitte **jamais** l'appareil : on en dérive (via
//! Argon2id, sel issu de l'email, puis HKDF) un **hash d'authentification**
//! envoyé au serveur, indépendant de toute clé de chiffrement. Le « blob » poussé
//! est le **coffre déjà chiffré** (opaque pour le serveur).

use nex_cryptographie::kdf::{deriver_cle, ParametresArgon2};
use nex_sync::hash_authentification;
use sha2::{Digest, Sha256};

use crate::erreur::ErreurCommande;

/// Résultat d'un envoi (push).
pub enum ResultatPoussee {
    /// Accepté ; nouvelle révision.
    Accepte(u64),
    /// Conflit ; révision actuelle du serveur (tirer puis réessayer/forcer).
    Conflit(u64),
}

/// Paramètres Argon2id (allégés en mode test, comme ailleurs dans l'app).
fn parametres() -> ParametresArgon2 {
    if std::env::var_os("NEXKEYLOCK_KDF_RAPIDE").is_some() {
        ParametresArgon2::new(8, 1, 1)
    } else {
        ParametresArgon2::default()
    }
}

/// Sel déterministe dérivé de l'email (≥ 16 octets) : identique sur tous les
/// appareils d'un même compte, jamais secret.
fn sel_email(email: &str) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(b"nexkeylock-sync-sel:v1");
    h.update(email.trim().to_lowercase().as_bytes());
    h.finalize()[..16].to_vec()
}

/// Dérive le hash d'authentification (hex) à partir de l'email et du mot de passe.
fn hash_auth_hex(email: &str, mot_de_passe: &str) -> Result<String, ErreurCommande> {
    let cle_maitre = deriver_cle(mot_de_passe.as_bytes(), &sel_email(email), parametres())
        .map_err(|_| ErreurCommande::interne("Dérivation impossible."))?;
    let hash = hash_authentification(&cle_maitre)
        .map_err(|_| ErreurCommande::interne("Dérivation d'authentification impossible."))?;
    Ok(hex::encode(hash.exposer()))
}

fn reseau(_e: impl std::fmt::Debug) -> ErreurCommande {
    ErreurCommande::interne("Serveur de synchronisation injoignable.")
}

/// Analyse le corps JSON d'une réponse (minreq sans la feature json).
fn parse_corps(rep: &minreq::Response) -> Result<serde_json::Value, ErreurCommande> {
    let texte = rep
        .as_str()
        .map_err(|_| ErreurCommande::interne("Réponse du serveur illisible."))?;
    serde_json::from_str(texte)
        .map_err(|_| ErreurCommande::interne("Réponse du serveur illisible."))
}

/// Inscrit un compte sur le serveur.
pub fn inscrire(base: &str, email: &str, mot_de_passe: &str) -> Result<(), ErreurCommande> {
    let hash = hash_auth_hex(email, mot_de_passe)?;
    let corps = serde_json::json!({ "email": email, "hash_auth": hash }).to_string();
    let rep = minreq::post(format!("{base}/inscription"))
        .with_header("Content-Type", "application/json")
        .with_body(corps)
        .with_timeout(15)
        .send()
        .map_err(reseau)?;
    match rep.status_code {
        201 => Ok(()),
        409 => Err(ErreurCommande::interne(
            "Un compte existe déjà pour cet email.",
        )),
        _ => Err(ErreurCommande::interne(
            "Inscription refusée par le serveur.",
        )),
    }
}

/// Se connecte et renvoie un jeton de session.
pub fn connecter(base: &str, email: &str, mot_de_passe: &str) -> Result<String, ErreurCommande> {
    let hash = hash_auth_hex(email, mot_de_passe)?;
    let corps = serde_json::json!({ "email": email, "hash_auth": hash }).to_string();
    let rep = minreq::post(format!("{base}/connexion"))
        .with_header("Content-Type", "application/json")
        .with_body(corps)
        .with_timeout(15)
        .send()
        .map_err(reseau)?;
    if rep.status_code != 200 {
        return Err(ErreurCommande::interne(
            "Identifiants de synchronisation invalides.",
        ));
    }
    let v = parse_corps(&rep)?;
    v.get("jeton")
        .and_then(|j| j.as_str())
        .map(str::to_string)
        .ok_or_else(|| ErreurCommande::interne("Jeton absent de la réponse."))
}

/// Récupère (révision, blob chiffré) du serveur ; blob vide si rien à distance.
pub fn tirer(base: &str, jeton: &str) -> Result<(u64, Vec<u8>), ErreurCommande> {
    let rep = minreq::get(format!("{base}/coffre"))
        .with_header("Authorization", format!("Bearer {jeton}"))
        .with_timeout(30)
        .send()
        .map_err(reseau)?;
    if rep.status_code != 200 {
        return Err(ErreurCommande::interne(
            "Session expirée ; reconnectez-vous.",
        ));
    }
    let v = parse_corps(&rep)?;
    let revision = v.get("revision").and_then(|r| r.as_u64()).unwrap_or(0);
    let blob_hex = v.get("blob").and_then(|b| b.as_str()).unwrap_or("");
    let blob = if blob_hex.is_empty() {
        Vec::new()
    } else {
        hex::decode(blob_hex).map_err(|_| ErreurCommande::interne("Blob distant invalide."))?
    };
    Ok((revision, blob))
}

/// Pousse `blob` (coffre chiffré) en supposant la révision de base `base_rev`.
pub fn pousser(
    base: &str,
    jeton: &str,
    base_rev: u64,
    blob: &[u8],
) -> Result<ResultatPoussee, ErreurCommande> {
    let corps = serde_json::json!({ "base": base_rev, "blob": hex::encode(blob) }).to_string();
    let rep = minreq::post(format!("{base}/coffre"))
        .with_header("Authorization", format!("Bearer {jeton}"))
        .with_header("Content-Type", "application/json")
        .with_body(corps)
        .with_timeout(30)
        .send()
        .map_err(reseau)?;
    match rep.status_code {
        200 => {
            let revision = parse_corps(&rep)?
                .get("revision")
                .and_then(|r| r.as_u64())
                .unwrap_or(0);
            Ok(ResultatPoussee::Accepte(revision))
        }
        409 => {
            let actuelle = parse_corps(&rep)?
                .get("actuelle")
                .and_then(|r| r.as_u64())
                .unwrap_or(0);
            Ok(ResultatPoussee::Conflit(actuelle))
        }
        401 => Err(ErreurCommande::interne(
            "Session expirée ; reconnectez-vous.",
        )),
        _ => Err(ErreurCommande::interne("Envoi refusé par le serveur.")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_auth_deterministe_et_sensible() {
        std::env::set_var("NEXKEYLOCK_KDF_RAPIDE", "1");
        let a = hash_auth_hex("moi@ex.fr", "motdepasse").unwrap();
        let b = hash_auth_hex("moi@ex.fr", "motdepasse").unwrap();
        assert_eq!(a, b, "déterministe pour le même couple");
        // L'email (casse/espaces) est normalisé.
        let c = hash_auth_hex("  MOI@EX.FR ", "motdepasse").unwrap();
        assert_eq!(a, c);
        // Mot de passe ou email différents => hash différent.
        assert_ne!(a, hash_auth_hex("moi@ex.fr", "autre").unwrap());
        assert_ne!(a, hash_auth_hex("autre@ex.fr", "motdepasse").unwrap());
        // 32 octets => 64 hex.
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn synchro_complete_contre_un_vrai_serveur() {
        std::env::set_var("NEXKEYLOCK_KDF_RAPIDE", "1");
        // Démarre un vrai serveur en mémoire sur un port éphémère (loopback).
        let serveur = nex_serveur_sync::lier("127.0.0.1:0").expect("liaison serveur");
        let adresse = serveur.server_addr().to_ip().expect("adresse ip");
        std::thread::spawn(move || nex_serveur_sync::servir(serveur));
        let base = format!("http://{adresse}");

        // Inscription + connexion.
        inscrire(&base, "moi@ex.fr", "motdepasse").unwrap();
        let jeton = connecter(&base, "moi@ex.fr", "motdepasse").unwrap();

        // Mauvais mot de passe rejeté.
        assert!(connecter(&base, "moi@ex.fr", "faux").is_err());

        // Premier envoi (base 0) accepté en révision 1.
        let blob = b"coffre-chiffre-opaque";
        match pousser(&base, &jeton, 0, blob).unwrap() {
            ResultatPoussee::Accepte(r) => assert_eq!(r, 1),
            ResultatPoussee::Conflit(_) => panic!("conflit inattendu"),
        }

        // Tirage : on récupère exactement le blob opaque envoyé.
        let (revision, recu) = tirer(&base, &jeton).unwrap();
        assert_eq!(revision, 1);
        assert_eq!(recu, blob);

        // Renvoi sur base périmée (0) => conflit, révision actuelle 1.
        match pousser(&base, &jeton, 0, blob).unwrap() {
            ResultatPoussee::Conflit(actuelle) => assert_eq!(actuelle, 1),
            ResultatPoussee::Accepte(_) => panic!("aurait dû être un conflit"),
        }
    }
}
