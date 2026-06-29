//! Serveur de synchronisation **zéro-connaissance** de nexkeylock.
//!
//! Le serveur ne stocke et ne manipule que :
//! - un **vérificateur d'authentification salé** par compte ([`nex_sync::Verificateur`]),
//!   qui ne permet pas de retrouver le hash d'authentification ni la clé maître ;
//! - un **blob chiffré opaque** + sa **révision** par compte ([`nex_sync::DepotMemoire`]).
//!
//! Il **ne voit jamais** le mot de passe maître, la clé de chiffrement, ni le
//! contenu du coffre. La logique réseau (HTTP) est dans `main.rs` ; ce module
//! expose [`traiter`], une fonction **pure et testable sans socket**.

use std::collections::HashMap;

use nex_cryptographie::alea::octets_aleatoires;
use nex_cryptographie::CleSecrete;
use nex_sync::{DepotMemoire, DepotSync, Pousser, Verificateur};
use serde::{Deserialize, Serialize};

/// Requête entrante normalisée (indépendante du transport).
pub struct Requete {
    pub methode: String,
    pub chemin: String,
    /// Jeton de session (`Authorization: Bearer …`), le cas échéant.
    pub jeton: Option<String>,
    pub corps: Vec<u8>,
}

/// Réponse à renvoyer (code HTTP + corps JSON).
pub struct Reponse {
    pub code: u16,
    pub corps: Vec<u8>,
}

/// Données d'un compte : vérificateur d'auth + dépôt du blob chiffré.
struct Compte {
    verificateur: Verificateur,
    depot: DepotMemoire,
}

/// État du serveur : comptes + sessions actives (jeton → email).
#[derive(Default)]
pub struct EtatServeur {
    comptes: HashMap<String, Compte>,
    sessions: HashMap<String, String>,
}

#[derive(Deserialize)]
struct Identifiants {
    email: String,
    /// Hash d'authentification (hex) dérivé côté client ; jamais le mot de passe.
    hash_auth: String,
}

#[derive(Deserialize)]
struct PousserReq {
    base: u64,
    /// Blob **chiffré** (hex) ; opaque pour le serveur.
    blob: String,
}

#[derive(Serialize)]
struct ReponseConnexion {
    jeton: String,
}

#[derive(Serialize)]
struct CoffreRep {
    revision: u64,
    blob: String,
}

#[derive(Serialize)]
struct PousserRep {
    revision: u64,
}

#[derive(Serialize)]
struct ConflitRep {
    actuelle: u64,
}

#[derive(Serialize)]
struct MessageRep {
    message: String,
}

#[derive(Serialize)]
struct ErreurRep {
    erreur: String,
}

/// Construit une réponse JSON (repli neutre si la sérialisation échoue).
fn json<T: Serialize>(code: u16, valeur: &T) -> Reponse {
    let corps =
        serde_json::to_vec(valeur).unwrap_or_else(|_| br#"{"erreur":"serialisation"}"#.to_vec());
    Reponse { code, corps }
}

fn erreur(code: u16, message: &str) -> Reponse {
    json(
        code,
        &ErreurRep {
            erreur: message.to_string(),
        },
    )
}

/// Décode un hash d'authentification hexadécimal en [`CleSecrete`] (32 octets).
fn cle_depuis_hex(hex_str: &str) -> Result<CleSecrete, Reponse> {
    let octets = hex::decode(hex_str).map_err(|_| erreur(400, "hex invalide"))?;
    CleSecrete::depuis_tranche(&octets).map_err(|_| erreur(400, "hash d'authentification invalide"))
}

/// Email associé à un jeton de session valide.
fn email_du_jeton(etat: &EtatServeur, jeton: Option<&str>) -> Option<String> {
    jeton.and_then(|j| etat.sessions.get(j)).cloned()
}

/// Traite une requête et renvoie la réponse. **Aucun secret n'est journalisé.**
pub fn traiter(etat: &mut EtatServeur, requete: &Requete) -> Reponse {
    match (requete.methode.as_str(), requete.chemin.as_str()) {
        ("POST", "/inscription") => inscription(etat, &requete.corps),
        ("POST", "/connexion") => connexion(etat, &requete.corps),
        ("GET", "/coffre") => tirer(etat, requete.jeton.as_deref()),
        ("POST", "/coffre") => pousser(etat, requete.jeton.as_deref(), &requete.corps),
        _ => erreur(404, "ressource inconnue"),
    }
}

fn inscription(etat: &mut EtatServeur, corps: &[u8]) -> Reponse {
    let id: Identifiants = match serde_json::from_slice(corps) {
        Ok(v) => v,
        Err(_) => return erreur(400, "requête invalide"),
    };
    if etat.comptes.contains_key(&id.email) {
        return erreur(409, "compte déjà existant");
    }
    let hash = match cle_depuis_hex(&id.hash_auth) {
        Ok(h) => h,
        Err(r) => return r,
    };
    let verificateur = match Verificateur::creer(&hash) {
        Ok(v) => v,
        Err(_) => return erreur(500, "erreur interne"),
    };
    etat.comptes.insert(
        id.email,
        Compte {
            verificateur,
            depot: DepotMemoire::default(),
        },
    );
    json(
        201,
        &MessageRep {
            message: "compte créé".to_string(),
        },
    )
}

fn connexion(etat: &mut EtatServeur, corps: &[u8]) -> Reponse {
    let id: Identifiants = match serde_json::from_slice(corps) {
        Ok(v) => v,
        Err(_) => return erreur(400, "requête invalide"),
    };
    let hash = match cle_depuis_hex(&id.hash_auth) {
        Ok(h) => h,
        Err(r) => return r,
    };
    // Message identique que le compte existe ou non (limite l'énumération).
    let ok = match etat.comptes.get(&id.email) {
        Some(compte) => compte.verificateur.verifier(&hash).unwrap_or(false),
        None => false,
    };
    if !ok {
        return erreur(401, "identifiants invalides");
    }
    let jeton = match octets_aleatoires::<32>() {
        Ok(o) => hex::encode(o),
        Err(_) => return erreur(500, "erreur interne"),
    };
    etat.sessions.insert(jeton.clone(), id.email);
    json(200, &ReponseConnexion { jeton })
}

fn tirer(etat: &EtatServeur, jeton: Option<&str>) -> Reponse {
    let email = match email_du_jeton(etat, jeton) {
        Some(e) => e,
        None => return erreur(401, "non authentifié"),
    };
    let Some(compte) = etat.comptes.get(&email) else {
        return erreur(401, "non authentifié");
    };
    match compte.depot.tirer() {
        Some(b) => json(
            200,
            &CoffreRep {
                revision: b.revision,
                blob: hex::encode(b.blob),
            },
        ),
        None => json(
            200,
            &CoffreRep {
                revision: 0,
                blob: String::new(),
            },
        ),
    }
}

fn pousser(etat: &mut EtatServeur, jeton: Option<&str>, corps: &[u8]) -> Reponse {
    let email = match email_du_jeton(etat, jeton) {
        Some(e) => e,
        None => return erreur(401, "non authentifié"),
    };
    let req: PousserReq = match serde_json::from_slice(corps) {
        Ok(v) => v,
        Err(_) => return erreur(400, "requête invalide"),
    };
    let blob = match hex::decode(&req.blob) {
        Ok(b) => b,
        Err(_) => return erreur(400, "blob invalide"),
    };
    let Some(compte) = etat.comptes.get_mut(&email) else {
        return erreur(401, "non authentifié");
    };
    match compte.depot.pousser(req.base, &blob) {
        Pousser::Accepte(revision) => json(200, &PousserRep { revision }),
        Pousser::Conflit { actuelle } => json(409, &ConflitRep { actuelle }),
    }
}

/// Lie le serveur HTTP à `adresse` (ex. `127.0.0.1:8787`).
pub fn lier(adresse: &str) -> Result<tiny_http::Server, String> {
    tiny_http::Server::http(adresse).map_err(|e| e.to_string())
}

/// Boucle de service **bloquante** : traite les requêtes jusqu'à l'arrêt du
/// serveur. L'état (comptes, sessions) vit en mémoire pour la durée du processus.
pub fn servir(serveur: tiny_http::Server) {
    let etat = std::sync::Mutex::new(EtatServeur::default());
    for mut requete in serveur.incoming_requests() {
        let methode = format!("{}", requete.method());
        let chemin = requete.url().split('?').next().unwrap_or("").to_string();
        let jeton = requete
            .headers()
            .iter()
            .find(|h| h.field.equiv("Authorization"))
            .and_then(|h| h.value.as_str().strip_prefix("Bearer ").map(str::to_string));

        let mut corps = Vec::new();
        if requete.as_reader().read_to_end(&mut corps).is_err() {
            let _ = requete.respond(vers_http(&Reponse {
                code: 400,
                corps: br#"{"erreur":"corps illisible"}"#.to_vec(),
            }));
            continue;
        }

        let reponse = match etat.lock() {
            Ok(mut garde) => traiter(
                &mut garde,
                &Requete {
                    methode,
                    chemin,
                    jeton,
                    corps,
                },
            ),
            Err(_) => Reponse {
                code: 500,
                corps: br#"{"erreur":"etat indisponible"}"#.to_vec(),
            },
        };
        let _ = requete.respond(vers_http(&reponse));
    }
}

/// Convertit une [`Reponse`] applicative en réponse HTTP `tiny_http`.
fn vers_http(reponse: &Reponse) -> tiny_http::Response<std::io::Cursor<Vec<u8>>> {
    let mut http = tiny_http::Response::from_data(reponse.corps.clone())
        .with_status_code(tiny_http::StatusCode(reponse.code));
    if let Ok(entete) = tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
    {
        http = http.with_header(entete);
    }
    http
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(methode: &str, chemin: &str, jeton: Option<&str>, corps: &[u8]) -> Requete {
        Requete {
            methode: methode.to_string(),
            chemin: chemin.to_string(),
            jeton: jeton.map(str::to_string),
            corps: corps.to_vec(),
        }
    }

    fn json_corps(v: serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(&v).unwrap()
    }

    /// Hash d'authentification de test (hex de 32 octets).
    fn hash_hex(octet: u8) -> String {
        hex::encode([octet; 32])
    }

    fn inscrire_et_connecter(etat: &mut EtatServeur, email: &str, hash: &str) -> String {
        let r = traiter(
            etat,
            &req(
                "POST",
                "/inscription",
                None,
                &json_corps(serde_json::json!({"email": email, "hash_auth": hash})),
            ),
        );
        assert_eq!(r.code, 201);
        let r = traiter(
            etat,
            &req(
                "POST",
                "/connexion",
                None,
                &json_corps(serde_json::json!({"email": email, "hash_auth": hash})),
            ),
        );
        assert_eq!(r.code, 200);
        let v: serde_json::Value = serde_json::from_slice(&r.corps).unwrap();
        v["jeton"].as_str().unwrap().to_string()
    }

    #[test]
    fn inscription_puis_connexion() {
        let mut etat = EtatServeur::default();
        let jeton = inscrire_et_connecter(&mut etat, "moi@exemple.fr", &hash_hex(0x11));
        assert!(!jeton.is_empty());
    }

    #[test]
    fn inscription_en_double_refusee() {
        let mut etat = EtatServeur::default();
        let corps = json_corps(serde_json::json!({"email": "a@b.fr", "hash_auth": hash_hex(0x11)}));
        assert_eq!(
            traiter(&mut etat, &req("POST", "/inscription", None, &corps)).code,
            201
        );
        assert_eq!(
            traiter(&mut etat, &req("POST", "/inscription", None, &corps)).code,
            409
        );
    }

    #[test]
    fn connexion_mauvais_hash_rejetee() {
        let mut etat = EtatServeur::default();
        let corps = json_corps(serde_json::json!({"email": "a@b.fr", "hash_auth": hash_hex(0x11)}));
        traiter(&mut etat, &req("POST", "/inscription", None, &corps));
        let mauvais =
            json_corps(serde_json::json!({"email": "a@b.fr", "hash_auth": hash_hex(0x22)}));
        assert_eq!(
            traiter(&mut etat, &req("POST", "/connexion", None, &mauvais)).code,
            401
        );
    }

    #[test]
    fn pousser_tirer_et_conflit() {
        let mut etat = EtatServeur::default();
        let jeton = inscrire_et_connecter(&mut etat, "a@b.fr", &hash_hex(0x11));

        // Premier envoi (base 0) accepté en révision 1.
        let blob = hex::encode([0xDE, 0xAD, 0xBE, 0xEF]);
        let r = traiter(
            &mut etat,
            &req(
                "POST",
                "/coffre",
                Some(&jeton),
                &json_corps(serde_json::json!({"base": 0, "blob": blob})),
            ),
        );
        assert_eq!(r.code, 200);
        let v: serde_json::Value = serde_json::from_slice(&r.corps).unwrap();
        assert_eq!(v["revision"], 1);

        // Tirage : on récupère exactement le blob opaque envoyé.
        let r = traiter(&mut etat, &req("GET", "/coffre", Some(&jeton), b""));
        assert_eq!(r.code, 200);
        let v: serde_json::Value = serde_json::from_slice(&r.corps).unwrap();
        assert_eq!(v["revision"], 1);
        assert_eq!(v["blob"].as_str().unwrap(), blob);

        // Renvoi sur une base périmée (0) → conflit, révision actuelle 1.
        let r = traiter(
            &mut etat,
            &req(
                "POST",
                "/coffre",
                Some(&jeton),
                &json_corps(serde_json::json!({"base": 0, "blob": blob})),
            ),
        );
        assert_eq!(r.code, 409);
        let v: serde_json::Value = serde_json::from_slice(&r.corps).unwrap();
        assert_eq!(v["actuelle"], 1);

        // Renvoi sur la bonne base (1) → accepté en révision 2.
        let r = traiter(
            &mut etat,
            &req(
                "POST",
                "/coffre",
                Some(&jeton),
                &json_corps(serde_json::json!({"base": 1, "blob": blob})),
            ),
        );
        assert_eq!(r.code, 200);
    }

    #[test]
    fn acces_sans_jeton_refuse() {
        let mut etat = EtatServeur::default();
        assert_eq!(
            traiter(&mut etat, &req("GET", "/coffre", None, b"")).code,
            401
        );
        assert_eq!(
            traiter(
                &mut etat,
                &req("POST", "/coffre", Some("jeton-bidon"), b"{}")
            )
            .code,
            401
        );
    }
}
