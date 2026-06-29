//! NexKeyLock — backend de l'application de bureau (Tauri v2).
//!
//! Point d'entrée partagé bureau/mobile. La logique sensible vit dans le cœur
//! (`nex-coffre`) ; ce crate n'orchestre que l'interface et les commandes.

mod commandes;
mod erreur;
mod etat;
mod fuites;
mod presse_papiers;
mod reglages;

use etat::EtatPartage;

/// Lance l'application. Annoté pour servir aussi de point d'entrée mobile
/// (préparation des cibles iOS/Android sans réécriture).
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let resultat = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(EtatPartage::default())
        .invoke_handler(tauri::generate_handler![
            commandes::version_coeur,
            commandes::coffre_existe,
            commandes::etat,
            commandes::creer_coffre,
            commandes::deverrouiller,
            commandes::verrouiller,
            commandes::configurer_recuperation,
            commandes::lister_entrees,
            commandes::reveler_champ,
            commandes::copier_champ,
            commandes::obtenir_totp,
            commandes::copier_totp,
            commandes::ajouter_entree,
            commandes::modifier_entree,
            commandes::supprimer_entree,
            commandes::generer_mot_de_passe,
            commandes::copier_texte,
            commandes::lancer_audit,
            commandes::verifier_fuites,
            commandes::obtenir_reglages,
            commandes::definir_reglages,
            commandes::changer_mot_de_passe,
            commandes::exporter_coffre,
            commandes::importer_coffre,
            commandes::obtenir_kdf,
            commandes::verifier_maj,
        ])
        .run(tauri::generate_context!());

    if let Err(erreur) = resultat {
        // Pas de secret dans ce message : seule l'erreur de démarrage Tauri.
        eprintln!("Erreur au lancement de NexKeyLock : {erreur}");
        std::process::exit(1);
    }
}
