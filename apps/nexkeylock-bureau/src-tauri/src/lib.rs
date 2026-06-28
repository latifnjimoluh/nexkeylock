//! NexKeyLock — backend de l'application de bureau (Tauri v2).
//!
//! Point d'entrée partagé bureau/mobile. La logique sensible vit dans le cœur
//! (`nex-coffre`) ; ce crate n'orchestre que l'interface et les commandes.

mod commandes;
mod erreur;
mod etat;

use etat::EtatPartage;

/// Lance l'application. Annoté pour servir aussi de point d'entrée mobile
/// (préparation des cibles iOS/Android sans réécriture).
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let resultat = tauri::Builder::default()
        .manage(EtatPartage::default())
        .invoke_handler(tauri::generate_handler![
            commandes::version_coeur,
            commandes::coffre_existe,
            commandes::etat,
            commandes::creer_coffre,
            commandes::deverrouiller,
            commandes::verrouiller,
        ])
        .run(tauri::generate_context!());

    if let Err(erreur) = resultat {
        // Pas de secret dans ce message : seule l'erreur de démarrage Tauri.
        eprintln!("Erreur au lancement de NexKeyLock : {erreur}");
        std::process::exit(1);
    }
}
