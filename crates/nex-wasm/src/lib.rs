//! Pont **WebAssembly** du cœur nexkeylock pour la PWA.
//!
//! Le cœur audité (`nex-coffre`/`nex-cryptographie`) est compilé en WASM et
//! exposé à JavaScript via `wasm-bindgen` : **aucune cryptographie n'est écrite
//! en JS**. Le coffre vit en mémoire (octets chiffrés persistés par la PWA dans
//! IndexedDB) ; l'horodatage et le minuteur d'inactivité sont fournis/gérés par
//! l'hôte JS (les API temps de `std` ne sont pas disponibles sur wasm32).

use nex_coffre::generateur::{generer_mot_de_passe, OptionsMotDePasse};
use nex_coffre::{nouvel_identifiant, CoffreDeverrouille, CoffreVerrouille, Entree};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

/// Paramètres Argon2id de production (256 Mio). La PWA pourra les abaisser pour
/// le mobile via une surcharge ultérieure ; ici on garde le défaut du cœur.
use nex_coffre::ParametresArgon2;

fn js_err(message: &str) -> JsValue {
    JsValue::from_str(message)
}

/// Métadonnées d'entrée renvoyées à JS (jamais de secret).
#[derive(Serialize)]
struct EntreeJs {
    id: String,
    nom: String,
    nom_utilisateur: Option<String>,
    uris: Vec<String>,
    a_mot_de_passe: bool,
    a_totp: bool,
}

impl EntreeJs {
    fn depuis(e: &Entree) -> Self {
        Self {
            id: e.id.clone(),
            nom: e.nom.clone(),
            nom_utilisateur: e.nom_utilisateur.clone(),
            uris: e.uris.clone(),
            a_mot_de_passe: e.mot_de_passe.is_some(),
            a_totp: e.secret_totp.is_some(),
        }
    }
}

/// Données d'une nouvelle entrée reçues de JS.
#[derive(Deserialize)]
struct DonneesJs {
    nom: String,
    nom_utilisateur: Option<String>,
    #[serde(default)]
    uris: Vec<String>,
    mot_de_passe: Option<String>,
    notes: Option<String>,
}

/// Coffre déverrouillé, manipulé par la PWA.
#[wasm_bindgen]
pub struct CoffrePwa {
    coffre: CoffreDeverrouille,
}

#[wasm_bindgen]
impl CoffrePwa {
    /// Crée un coffre **en mémoire** (avec fichier-clé optionnel).
    pub fn creer(mot_de_passe: &str, fichier_cle: Option<Vec<u8>>) -> Result<CoffrePwa, JsValue> {
        let kf = fichier_cle.unwrap_or_default();
        let (coffre, _octets) =
            CoffreDeverrouille::creer_en_memoire(mot_de_passe.as_bytes(), &kf, ParametresArgon2::default())
                .map_err(|_| js_err("création du coffre impossible"))?;
        Ok(CoffrePwa { coffre })
    }

    /// Ouvre un coffre depuis ses octets chiffrés (avec fichier-clé optionnel).
    pub fn ouvrir(
        octets: Vec<u8>,
        mot_de_passe: &str,
        fichier_cle: Option<Vec<u8>>,
    ) -> Result<CoffrePwa, JsValue> {
        let verrou =
            CoffreVerrouille::depuis_octets(&octets).map_err(|_| js_err("coffre illisible"))?;
        let kf = fichier_cle.unwrap_or_default();
        let coffre = verrou
            .deverrouiller_avec_fichier_cle(mot_de_passe.as_bytes(), &kf)
            .map_err(|_| js_err("mot de passe ou fichier-clé invalide"))?;
        Ok(CoffrePwa { coffre })
    }

    /// Octets chiffrés courants (à persister dans IndexedDB / synchroniser).
    pub fn octets(&self) -> Result<Vec<u8>, JsValue> {
        self.coffre
            .octets()
            .map_err(|_| js_err("sérialisation impossible"))
    }

    /// Entrées (métadonnées, JSON) — aucun secret.
    pub fn lister(&self) -> Result<String, JsValue> {
        let v: Vec<EntreeJs> = self.coffre.entrees().iter().map(EntreeJs::depuis).collect();
        serde_json::to_string(&v).map_err(|_| js_err("sérialisation impossible"))
    }

    /// Révèle un champ secret d'une entrée (à la demande).
    pub fn reveler(&self, id: &str, champ: &str) -> Result<String, JsValue> {
        let e = self
            .coffre
            .obtenir(id)
            .ok_or_else(|| js_err("entrée introuvable"))?;
        let valeur = match champ {
            "mot_de_passe" => e.mot_de_passe.clone(),
            "notes" => e.notes.clone(),
            _ => return Err(js_err("champ inconnu")),
        };
        valeur.ok_or_else(|| js_err("champ absent"))
    }

    /// Ajoute une entrée ; `maintenant` (Unix s) est fourni par l'hôte JS.
    pub fn ajouter(&mut self, donnees_json: &str, maintenant: u64) -> Result<String, JsValue> {
        let d: DonneesJs =
            serde_json::from_str(donnees_json).map_err(|_| js_err("données invalides"))?;
        let id = nouvel_identifiant().map_err(|_| js_err("aléa indisponible"))?;
        let mut e = Entree::connexion(&id, &d.nom, maintenant);
        e.nom_utilisateur = d.nom_utilisateur.filter(|s| !s.trim().is_empty());
        e.uris = d.uris;
        e.mot_de_passe = d.mot_de_passe.filter(|s| !s.is_empty());
        e.notes = d.notes.filter(|s| !s.trim().is_empty());
        self.coffre.ajouter(e);
        Ok(id)
    }

    /// Supprime une entrée.
    pub fn supprimer(&mut self, id: &str) -> Result<(), JsValue> {
        if self.coffre.supprimer(id) {
            Ok(())
        } else {
            Err(js_err("entrée introuvable"))
        }
    }
}

/// Indique si des octets de coffre exigent un fichier-clé (écran de déverrouillage).
#[wasm_bindgen]
pub fn fichier_cle_requis(octets: Vec<u8>) -> Result<bool, JsValue> {
    Ok(CoffreVerrouille::depuis_octets(&octets)
        .map_err(|_| js_err("coffre illisible"))?
        .entete()
        .fichier_cle_requis)
}

/// Dérive le **hash d'authentification** de synchronisation (hex) à partir de
/// l'email et du mot de passe maître — **identique au client de bureau** (même
/// sel dérivé de l'email, mêmes paramètres Argon2id de production). Le mot de
/// passe ne quitte jamais le WASM ; seul ce hash part vers le serveur.
#[wasm_bindgen]
pub fn hash_auth(email: &str, mot_de_passe: &str) -> Result<String, JsValue> {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"nexkeylock-sync-sel:v1");
    h.update(email.trim().to_lowercase().as_bytes());
    let sel = h.finalize()[..16].to_vec();

    let cle = nex_cryptographie::kdf::deriver_cle(
        mot_de_passe.as_bytes(),
        &sel,
        ParametresArgon2::default(),
    )
    .map_err(|_| js_err("dérivation impossible"))?;
    let hash = nex_sync::hash_authentification(&cle).map_err(|_| js_err("dérivation impossible"))?;
    Ok(hex::encode(hash.exposer()))
}

/// Génère un mot de passe (sans coffre).
#[wasm_bindgen]
pub fn generer(longueur: usize, symboles: bool) -> Result<String, JsValue> {
    let options = OptionsMotDePasse {
        longueur,
        symboles,
        ..OptionsMotDePasse::default()
    };
    let mdp = generer_mot_de_passe(&options).map_err(|_| js_err("options de génération invalides"))?;
    Ok(mdp.to_string())
}
