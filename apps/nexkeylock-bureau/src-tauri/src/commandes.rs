//! Couche de commandes Tauri exposée à l'interface.
//!
//! **Aucune cryptographie ici** : chaque commande délègue au cœur (`nex-coffre`)
//! via [`EtatPartage`] et ne renvoie jamais de secret non sollicité. Le mot de
//! passe maître reçu est immédiatement enveloppé dans `Zeroizing`.

use tauri::State;
use zeroize::Zeroizing;

use crate::erreur::ErreurCommande;
use crate::etat::{Apercu, CodeTotp, EntreeApercu, EtatPartage};
use crate::presse_papiers;

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

/// Liste les entrées (métadonnées, sans secret), filtrées par `requete`.
#[tauri::command]
pub fn lister_entrees(
    requete: Option<String>,
    etat: State<'_, EtatPartage>,
) -> Result<Vec<EntreeApercu>, ErreurCommande> {
    etat.acceder()?.lister(requete.as_deref())
}

/// Révèle la valeur d'un champ secret d'une entrée (à la demande).
#[tauri::command]
pub fn reveler_champ(
    id: String,
    champ: String,
    etat: State<'_, EtatPartage>,
) -> Result<String, ErreurCommande> {
    etat.acceder()?.reveler(&id, &champ)
}

/// Copie un champ secret dans le presse-papiers, avec effacement après `delai_s`.
#[tauri::command]
pub fn copier_champ(
    id: String,
    champ: String,
    delai_s: u64,
    etat: State<'_, EtatPartage>,
) -> Result<(), ErreurCommande> {
    let valeur = etat.acceder()?.reveler(&id, &champ)?;
    presse_papiers::copier_avec_effacement(valeur, delai_s)
}

/// Code TOTP courant d'une entrée et temps de validité restant.
#[tauri::command]
pub fn obtenir_totp(id: String, etat: State<'_, EtatPartage>) -> Result<CodeTotp, ErreurCommande> {
    etat.acceder()?.code_totp(&id)
}

/// Copie le code TOTP courant dans le presse-papiers (effacé après `delai_s`).
#[tauri::command]
pub fn copier_totp(
    id: String,
    delai_s: u64,
    etat: State<'_, EtatPartage>,
) -> Result<(), ErreurCommande> {
    let code = etat.acceder()?.code_totp(&id)?.code;
    presse_papiers::copier_avec_effacement(code, delai_s)
}
