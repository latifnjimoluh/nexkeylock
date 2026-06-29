//! Couche de commandes Tauri exposée à l'interface.
//!
//! **Aucune cryptographie ici** : chaque commande délègue au cœur (`nex-coffre`)
//! via [`EtatPartage`] et ne renvoie jamais de secret non sollicité. Le mot de
//! passe maître reçu est immédiatement enveloppé dans `Zeroizing`.

use nex_coffre::generateur::{
    entropie_bits, entropie_phrase, generer_mot_de_passe as gen_mdp, generer_phrase as gen_phrase,
    OptionsMotDePasse,
};
use tauri::State;
use zeroize::Zeroizing;

use crate::erreur::ErreurCommande;
use crate::etat::{
    Apercu, CodeTotp, DonneesEntree, ElementFuite, EntreeApercu, EtatPartage, RapportAuditApp,
};
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

/// Audit hors-ligne du coffre (réutilisés/faibles/anciens + score de santé).
#[tauri::command]
pub fn lancer_audit(etat: State<'_, EtatPartage>) -> Result<RapportAuditApp, ErreurCommande> {
    etat.acceder()?.auditer()
}

/// Vérification de fuites en ligne (k-anonymat, opt-in). Appel réseau ; ne
/// transmet que des préfixes de hachage.
#[tauri::command]
pub fn verifier_fuites(etat: State<'_, EtatPartage>) -> Result<Vec<ElementFuite>, ErreurCommande> {
    etat.acceder()?.verifier_fuites()
}

/// Copie un texte fourni (ex. mot de passe généré) dans le presse-papiers, avec
/// effacement après `delai_s`. La valeur est déjà connue de l'interface (sortie
/// du générateur) ; on passe par le backend pour l'effacement fiable.
#[tauri::command]
pub fn copier_texte(valeur: String, delai_s: u64) -> Result<(), ErreurCommande> {
    presse_papiers::copier_avec_effacement(valeur, delai_s)
}

/// Ajoute une entrée et renvoie son identifiant.
#[tauri::command]
pub fn ajouter_entree(
    donnees: DonneesEntree,
    etat: State<'_, EtatPartage>,
) -> Result<String, ErreurCommande> {
    etat.acceder()?.ajouter(donnees)
}

/// Modifie une entrée existante.
#[tauri::command]
pub fn modifier_entree(
    id: String,
    donnees: DonneesEntree,
    etat: State<'_, EtatPartage>,
) -> Result<(), ErreurCommande> {
    etat.acceder()?.modifier(&id, donnees)
}

/// Supprime une entrée.
#[tauri::command]
pub fn supprimer_entree(id: String, etat: State<'_, EtatPartage>) -> Result<(), ErreurCommande> {
    etat.acceder()?.supprimer(&id)
}

/// Options de génération reçues de l'interface.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OptionsGenerateur {
    /// Si renseigné, génère une phrase de passe de N mots (diceware).
    pub mots: Option<usize>,
    pub longueur: usize,
    pub minuscules: bool,
    pub majuscules: bool,
    pub chiffres: bool,
    pub symboles: bool,
    pub exclure_ambigus: bool,
}

/// Mot de passe généré et son entropie estimée (bits).
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MotDePasseGenere {
    pub valeur: String,
    pub entropie_bits: u32,
}

/// Génère un mot de passe ou une phrase de passe (délègue au cœur).
#[tauri::command]
pub fn generer_mot_de_passe(
    options: OptionsGenerateur,
) -> Result<MotDePasseGenere, ErreurCommande> {
    if let Some(n) = options.mots {
        let phrase = gen_phrase(n, '-')
            .map_err(|_| ErreurCommande::interne("Options de génération invalides."))?;
        return Ok(MotDePasseGenere {
            valeur: phrase.to_string(),
            entropie_bits: entropie_phrase(n).round() as u32,
        });
    }
    let opt = OptionsMotDePasse {
        longueur: options.longueur,
        minuscules: options.minuscules,
        majuscules: options.majuscules,
        chiffres: options.chiffres,
        symboles: options.symboles,
        exclure_ambigus: options.exclure_ambigus,
    };
    let mdp =
        gen_mdp(&opt).map_err(|_| ErreurCommande::interne("Options de génération invalides."))?;
    Ok(MotDePasseGenere {
        valeur: mdp.to_string(),
        entropie_bits: entropie_bits(opt.jeu().len(), opt.longueur).round() as u32,
    })
}
