//! Saisie des secrets en ligne de commande.
//!
//! Ordre de résolution du **mot de passe maître** :
//! 1. variable d'environnement `NEXKEYLOCK_MDP` (automatisation / tests) ;
//! 2. saisie **masquée** si l'entrée est un terminal (`rpassword`) ;
//! 3. lecture d'une ligne sur l'entrée standard (cas piped).
//!
//! Les secrets d'entrée (mot de passe d'un site) ne consultent **pas**
//! `NEXKEYLOCK_MDP` afin de ne pas confondre les deux.

use std::io::{BufRead, IsTerminal};

use anyhow::{bail, Result};
use zeroize::Zeroizing;

/// Nom de la variable d'environnement portant le mot de passe maître.
const VAR_MDP: &str = "NEXKEYLOCK_MDP";

/// Lit le mot de passe maître (env, terminal masqué, ou stdin).
pub fn lire_mot_de_passe(invite: &str) -> Result<Zeroizing<String>> {
    if let Ok(valeur) = std::env::var(VAR_MDP) {
        return Ok(Zeroizing::new(valeur));
    }
    if std::io::stdin().is_terminal() {
        return Ok(Zeroizing::new(rpassword::prompt_password(invite)?));
    }
    lire_ligne_stdin()
}

/// Lit un nouveau mot de passe maître, avec confirmation en mode terminal.
pub fn lire_nouveau_mot_de_passe() -> Result<Zeroizing<String>> {
    if let Ok(valeur) = std::env::var(VAR_MDP) {
        return Ok(Zeroizing::new(valeur));
    }
    if std::io::stdin().is_terminal() {
        let premier = Zeroizing::new(rpassword::prompt_password(
            "Nouveau mot de passe maître : ",
        )?);
        let second = Zeroizing::new(rpassword::prompt_password("Confirmer : ")?);
        if premier.as_str() != second.as_str() {
            bail!("les mots de passe ne correspondent pas");
        }
        return Ok(premier);
    }
    lire_ligne_stdin()
}

/// Lit un secret d'entrée (mot de passe d'un site) : terminal masqué ou stdin.
/// Ne consulte jamais `NEXKEYLOCK_MDP`.
pub fn lire_secret_entree(invite: &str) -> Result<Zeroizing<String>> {
    if std::io::stdin().is_terminal() {
        return Ok(Zeroizing::new(rpassword::prompt_password(invite)?));
    }
    lire_ligne_stdin()
}

/// Lit le code de récupération (variable `NEXKEYLOCK_CODE`, terminal masqué, ou
/// stdin).
pub fn lire_code_recuperation() -> Result<Zeroizing<String>> {
    if let Ok(valeur) = std::env::var("NEXKEYLOCK_CODE") {
        return Ok(Zeroizing::new(valeur));
    }
    if std::io::stdin().is_terminal() {
        return Ok(Zeroizing::new(rpassword::prompt_password(
            "Code de récupération : ",
        )?));
    }
    lire_ligne_stdin()
}

/// Lit une ligne sur l'entrée standard (sans le saut de ligne final).
fn lire_ligne_stdin() -> Result<Zeroizing<String>> {
    let mut ligne = String::new();
    std::io::stdin().lock().read_line(&mut ligne)?;
    while ligne.ends_with('\n') || ligne.ends_with('\r') {
        ligne.pop();
    }
    Ok(Zeroizing::new(ligne))
}
