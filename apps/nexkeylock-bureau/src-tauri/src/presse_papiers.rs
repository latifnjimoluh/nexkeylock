//! Copie de secret dans le presse-papiers avec **effacement automatique**.
//!
//! Piloté côté backend (fiable même si la fenêtre se ferme). Après le délai, le
//! contenu n'est effacé que s'il correspond toujours à la valeur copiée, afin de
//! ne pas écraser ce que l'utilisateur aurait copié entre-temps.

use std::time::Duration;

use crate::erreur::ErreurCommande;

/// Copie `valeur` puis programme son effacement après `delai_s` secondes.
pub fn copier_avec_effacement(valeur: String, delai_s: u64) -> Result<(), ErreurCommande> {
    let mut presse = arboard::Clipboard::new()
        .map_err(|_| ErreurCommande::interne("Presse-papiers indisponible."))?;
    presse
        .set_text(valeur.clone())
        .map_err(|_| ErreurCommande::interne("Copie impossible."))?;

    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(delai_s));
        if let Ok(mut p) = arboard::Clipboard::new() {
            let inchange = p.get_text().map(|t| t == valeur).unwrap_or(false);
            if inchange {
                let _ = p.set_text(String::new());
            }
        }
    });
    Ok(())
}
