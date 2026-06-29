//! Serveur HTTP de synchronisation zéro-connaissance (binaire mince).
//!
//! Toute la logique vit dans la bibliothèque (`nex_serveur_sync`). État **en
//! mémoire** ; persistance disque et **TLS** relèvent du déploiement (à placer
//! derrière un proxy TLS pour un usage distant).

fn main() {
    let adresse =
        std::env::var("NEXKEYLOCK_SYNC_ADRESSE").unwrap_or_else(|_| "127.0.0.1:8787".to_string());

    match nex_serveur_sync::lier(&adresse) {
        Ok(serveur) => {
            eprintln!(
                "nexkeylock-serveur-sync à l'écoute sur http://{adresse} (zéro-connaissance)"
            );
            nex_serveur_sync::servir(serveur);
        }
        Err(e) => {
            eprintln!("Démarrage impossible sur {adresse} : {e}");
            std::process::exit(1);
        }
    }
}
