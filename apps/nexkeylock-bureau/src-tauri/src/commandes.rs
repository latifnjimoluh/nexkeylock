//! Couche de commandes Tauri exposée à l'interface.
//!
//! **Aucune cryptographie ici** : chaque commande délègue au cœur (`nex-coffre`)
//! via [`EtatPartage`] et ne renvoie jamais de secret non sollicité. Le mot de
//! passe maître reçu est immédiatement enveloppé dans `Zeroizing`.

use tauri::State;
use zeroize::Zeroizing;

use crate::erreur::ErreurCommande;
use crate::etat::{Apercu, EtatPartage};

/// Version du cœur cryptographique (`nex-coffre`). Commande de fumée.
#[tauri::command]
pub fn version_coeur() -> String {
    nex_coffre::VERSION.to_string()
}

/// Indique si un fichier de coffre existe déjà.
#[tauri::command]
pub fn coffre_existe(etat: State<'_, EtatPartage>) -> Result<bool, ErreurCommande> {
    Ok(etat.acceder()?.coffre_existe())
}

/// État courant (métadonnées, sans secret).
#[tauri::command]
pub fn etat(etat: State<'_, EtatPartage>) -> Result<Apercu, ErreurCommande> {
    Ok(etat.acceder()?.apercu())
}

/// Crée un nouveau coffre et le laisse déverrouillé.
#[tauri::command]
pub fn creer_coffre(
    mot_de_passe: String,
    etat: State<'_, EtatPartage>,
) -> Result<Apercu, ErreurCommande> {
    etat.acceder()?.creer(Zeroizing::new(mot_de_passe))
}

/// Déverrouille le coffre avec le mot de passe maître.
#[tauri::command]
pub fn deverrouiller(
    mot_de_passe: String,
    etat: State<'_, EtatPartage>,
) -> Result<Apercu, ErreurCommande> {
    etat.acceder()?.deverrouiller(Zeroizing::new(mot_de_passe))
}

/// Verrouille le coffre (efface la DEK et le contenu en mémoire).
#[tauri::command]
pub fn verrouiller(etat: State<'_, EtatPartage>) -> Result<Apercu, ErreurCommande> {
    let mut garde = etat.acceder()?;
    garde.verrouiller();
    Ok(garde.apercu())
}

/// Configure un code de récupération sur le coffre déverrouillé et le renvoie.
///
/// Le code est destiné à être **affiché une seule fois** par l'interface, puis
/// oublié : c'est sa seule raison de traverser la frontière.
#[tauri::command]
pub fn configurer_recuperation(etat: State<'_, EtatPartage>) -> Result<String, ErreurCommande> {
    let code = etat.acceder()?.configurer_recuperation()?;
    Ok(code.to_string())
}
