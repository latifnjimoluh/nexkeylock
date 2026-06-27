//! Presse-papiers : copie temporaire avec effacement après délai.
//!
//! La logique de copie/effacement est abstraite derrière [`PressePapiers`] afin
//! d'être testable sans bibliothèque système. L'implémentation réelle (arboard)
//! n'est compilée qu'avec la fonctionnalité `presse-papiers` (désactivée par
//! défaut).
//!
//! **Limites honnêtes (best-effort)** :
//! - l'effacement est synchrone : le processus reste vivant pendant le délai.
//!   S'il est **interrompu** (Ctrl-C, kill, plantage, fermeture du terminal)
//!   avant l'échéance, le secret **reste** dans le presse-papiers ;
//! - un gestionnaire de presse-papiers tiers ou une autre application peut avoir
//!   **copié** la valeur entre-temps : l'effacement ne la révoque pas ;
//! - sans la fonctionnalité `presse-papiers` compilée, aucune copie n'a lieu
//!   (la commande `--copier` échoue proprement).

#[cfg(any(feature = "presse-papiers", test))]
use std::time::Duration;

#[cfg(any(feature = "presse-papiers", test))]
use anyhow::Result;

/// Abstraction d'un presse-papiers.
#[cfg(any(feature = "presse-papiers", test))]
pub trait PressePapiers {
    /// Définit le contenu du presse-papiers.
    fn definir(&mut self, valeur: &str) -> Result<()>;
    /// Efface le presse-papiers (best-effort).
    fn effacer(&mut self) -> Result<()>;
}

/// Copie `valeur` puis l'efface après `delai` (le processus reste vivant
/// pendant l'attente).
///
/// **Best-effort** : si le processus est interrompu avant l'échéance, le secret
/// n'est pas effacé (voir limites au niveau module).
#[cfg(any(feature = "presse-papiers", test))]
pub fn copier_temporaire(pp: &mut dyn PressePapiers, valeur: &str, delai: Duration) -> Result<()> {
    pp.definir(valeur)?;
    std::thread::sleep(delai);
    pp.effacer()?;
    Ok(())
}

/// Implémentation réelle reposant sur `arboard` (fonctionnalité `presse-papiers`).
#[cfg(feature = "presse-papiers")]
pub struct PressePapiersSysteme(arboard::Clipboard);

#[cfg(feature = "presse-papiers")]
impl PressePapiersSysteme {
    /// Ouvre le presse-papiers système.
    pub fn nouveau() -> Result<Self> {
        Ok(Self(arboard::Clipboard::new()?))
    }
}

#[cfg(feature = "presse-papiers")]
impl PressePapiers for PressePapiersSysteme {
    fn definir(&mut self, valeur: &str) -> Result<()> {
        self.0.set_text(valeur.to_string())?;
        Ok(())
    }
    fn effacer(&mut self) -> Result<()> {
        self.0.set_text(String::new())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct PressePapiersSimule {
        contenu: Option<String>,
        definitions: usize,
        effacements: usize,
    }

    impl PressePapiers for PressePapiersSimule {
        fn definir(&mut self, valeur: &str) -> Result<()> {
            self.contenu = Some(valeur.to_string());
            self.definitions += 1;
            Ok(())
        }
        fn effacer(&mut self) -> Result<()> {
            self.contenu = None;
            self.effacements += 1;
            Ok(())
        }
    }

    #[test]
    fn copie_puis_efface() {
        let mut pp = PressePapiersSimule::default();
        copier_temporaire(&mut pp, "secret", Duration::from_millis(0)).unwrap();
        assert_eq!(pp.definitions, 1);
        assert_eq!(pp.effacements, 1);
        assert!(pp.contenu.is_none());
    }
}
