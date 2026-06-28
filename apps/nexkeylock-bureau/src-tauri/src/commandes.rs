//! Couche de commandes Tauri exposée à l'interface.
//!
//! **Aucune cryptographie ici** : chaque commande délègue au cœur (`nex-coffre`)
//! et ne renvoie jamais de secret non sollicité. Les jalons suivants ajouteront
//! l'état du coffre et les commandes de déverrouillage.

/// Version du cœur cryptographique (`nex-coffre`).
///
/// Commande de fumée du Jalon F0 : valide le pont webview ↔ backend.
#[tauri::command]
pub fn version_coeur() -> String {
    nex_coffre::VERSION.to_string()
}
