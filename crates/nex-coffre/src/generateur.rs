//! Génération de mots de passe et de phrases de passe.
//!
//! - Tirage **uniquement** depuis le CSPRNG du système (via
//!   [`nex_cryptographie::alea`]).
//! - Tirage **non biaisé** : on évite le modulo naïf grâce au **rejet
//!   d'échantillonnage** ([`index_uniforme`]).
//! - Estimation d'**entropie** affichée pour informer l'utilisateur.
//! - Phrases de passe **diceware** à partir de la liste EFF (7776 mots).

use std::sync::OnceLock;

use nex_cryptographie::alea::octets_aleatoires;
use zeroize::Zeroizing;

use crate::erreurs::ErreurCoffre;

/// Minuscules latines.
const MINUSCULES: &str = "abcdefghijklmnopqrstuvwxyz";
/// Majuscules latines.
const MAJUSCULES: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
/// Chiffres.
const CHIFFRES: &str = "0123456789";
/// Symboles courants.
const SYMBOLES: &str = "!@#$%^&*()-_=+[]{};:,.?";
/// Caractères ambigus exclus sur demande (l, I, 1, O, 0, o…).
const AMBIGUS: &str = "lI1O0o5S2Z8B";

/// Liste de mots EFF (7776 mots), embarquée. Licence CC-BY 3.0 (EFF).
const LISTE_EFF: &str = include_str!("eff_large.txt");

/// Options de génération d'un mot de passe.
#[derive(Debug, Clone)]
pub struct OptionsMotDePasse {
    /// Longueur en caractères.
    pub longueur: usize,
    /// Inclure les minuscules.
    pub minuscules: bool,
    /// Inclure les majuscules.
    pub majuscules: bool,
    /// Inclure les chiffres.
    pub chiffres: bool,
    /// Inclure les symboles.
    pub symboles: bool,
    /// Exclure les caractères ambigus.
    pub exclure_ambigus: bool,
}

impl Default for OptionsMotDePasse {
    fn default() -> Self {
        Self {
            longueur: 20,
            minuscules: true,
            majuscules: true,
            chiffres: true,
            symboles: true,
            exclure_ambigus: true,
        }
    }
}

impl OptionsMotDePasse {
    /// Construit le jeu de caractères correspondant aux options.
    pub fn jeu(&self) -> Vec<char> {
        let mut classes = String::new();
        if self.minuscules {
            classes.push_str(MINUSCULES);
        }
        if self.majuscules {
            classes.push_str(MAJUSCULES);
        }
        if self.chiffres {
            classes.push_str(CHIFFRES);
        }
        if self.symboles {
            classes.push_str(SYMBOLES);
        }
        classes
            .chars()
            .filter(|c| !self.exclure_ambigus || !AMBIGUS.contains(*c))
            .collect()
    }
}

/// Renvoie un index uniforme dans `[0, n)` par **rejet d'échantillonnage**
/// (aucun biais de modulo).
///
/// # Erreurs
/// [`ErreurCoffre::OptionsGenerateur`] si `n == 0` ; [`ErreurCoffre::Crypto`]
/// si la source d'aléa est indisponible.
pub fn index_uniforme(n: usize) -> Result<usize, ErreurCoffre> {
    let n_u = u32::try_from(n)
        .ok()
        .filter(|&v| v != 0)
        .ok_or(ErreurCoffre::OptionsGenerateur)?;
    // Plus grand multiple de n représentable : on rejette au-dessus.
    let borne = u32::MAX - (u32::MAX % n_u);
    loop {
        let r = u32::from_le_bytes(octets_aleatoires::<4>()?);
        if r < borne {
            return Ok((r % n_u) as usize);
        }
    }
}

/// Génère un mot de passe selon `options` (effacé à la libération).
///
/// # Erreurs
/// [`ErreurCoffre::OptionsGenerateur`] si le jeu est vide ou la longueur nulle ;
/// [`ErreurCoffre::Crypto`] si l'aléa est indisponible.
pub fn generer_mot_de_passe(
    options: &OptionsMotDePasse,
) -> Result<Zeroizing<String>, ErreurCoffre> {
    let jeu = options.jeu();
    if jeu.is_empty() || options.longueur == 0 {
        return Err(ErreurCoffre::OptionsGenerateur);
    }
    let mut sortie = String::with_capacity(options.longueur);
    for _ in 0..options.longueur {
        let i = index_uniforme(jeu.len())?;
        sortie.push(jeu[i]);
    }
    Ok(Zeroizing::new(sortie))
}

/// Entropie en bits d'un tirage uniforme de `longueur` symboles parmi
/// `taille_jeu`.
pub fn entropie_bits(taille_jeu: usize, longueur: usize) -> f64 {
    if taille_jeu <= 1 || longueur == 0 {
        return 0.0;
    }
    (taille_jeu as f64).log2() * longueur as f64
}

/// Liste de mots diceware (mise en cache au premier appel).
fn liste_mots() -> &'static [&'static str] {
    static CACHE: OnceLock<Vec<&'static str>> = OnceLock::new();
    CACHE.get_or_init(|| {
        LISTE_EFF
            .trim_start_matches('\u{feff}')
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .collect()
    })
}

/// Nombre de mots dans la liste diceware (7776).
pub fn nombre_de_mots() -> usize {
    liste_mots().len()
}

/// Génère une phrase de passe diceware de `nb_mots` mots, séparés par
/// `separateur` (effacée à la libération).
///
/// # Erreurs
/// [`ErreurCoffre::OptionsGenerateur`] si `nb_mots == 0` ;
/// [`ErreurCoffre::Crypto`] si l'aléa est indisponible.
pub fn generer_phrase(nb_mots: usize, separateur: char) -> Result<Zeroizing<String>, ErreurCoffre> {
    if nb_mots == 0 {
        return Err(ErreurCoffre::OptionsGenerateur);
    }
    let mots = liste_mots();
    let mut choisis = Vec::with_capacity(nb_mots);
    for _ in 0..nb_mots {
        let i = index_uniforme(mots.len())?;
        choisis.push(mots[i]);
    }
    Ok(Zeroizing::new(choisis.join(&separateur.to_string())))
}

/// Entropie en bits d'une phrase de `nb_mots` mots issus de la liste diceware.
pub fn entropie_phrase(nb_mots: usize) -> f64 {
    entropie_bits(nombre_de_mots(), nb_mots)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn liste_a_7776_mots_uniques() {
        assert_eq!(nombre_de_mots(), 7776);
        let uniques: HashSet<_> = liste_mots().iter().collect();
        assert_eq!(uniques.len(), 7776);
        // Aucun BOM ni espace résiduel sur le premier mot.
        assert_eq!(liste_mots()[0], "abacus");
    }

    #[test]
    fn longueur_et_jeu_respectes() {
        let opt = OptionsMotDePasse {
            longueur: 64,
            minuscules: true,
            majuscules: false,
            chiffres: false,
            symboles: false,
            exclure_ambigus: true,
        };
        let mdp = generer_mot_de_passe(&opt).unwrap();
        assert_eq!(mdp.chars().count(), 64);
        let jeu: HashSet<char> = opt.jeu().into_iter().collect();
        assert!(mdp.chars().all(|c| jeu.contains(&c)));
        // Caractères ambigus exclus.
        assert!(mdp.chars().all(|c| !AMBIGUS.contains(c)));
    }

    #[test]
    fn jeu_vide_ou_longueur_nulle_rejetes() {
        let opt = OptionsMotDePasse {
            longueur: 0,
            ..OptionsMotDePasse::default()
        };
        assert!(matches!(
            generer_mot_de_passe(&opt),
            Err(ErreurCoffre::OptionsGenerateur)
        ));
        let opt = OptionsMotDePasse {
            longueur: 8,
            minuscules: false,
            majuscules: false,
            chiffres: false,
            symboles: false,
            exclure_ambigus: false,
        };
        assert!(matches!(
            generer_mot_de_passe(&opt),
            Err(ErreurCoffre::OptionsGenerateur)
        ));
    }

    #[test]
    fn tirage_non_degenere() {
        // Sur un long tirage parmi a-z, chaque lettre doit apparaître : un
        // générateur biaisé ou figé échouerait.
        let opt = OptionsMotDePasse {
            longueur: 5000,
            minuscules: true,
            majuscules: false,
            chiffres: false,
            symboles: false,
            exclure_ambigus: false,
        };
        let mdp = generer_mot_de_passe(&opt).unwrap();
        let vus: HashSet<char> = mdp.chars().collect();
        assert_eq!(vus.len(), 26);
    }

    #[test]
    fn index_uniforme_borne() {
        for _ in 0..1000 {
            let i = index_uniforme(10).unwrap();
            assert!(i < 10);
        }
        assert!(matches!(
            index_uniforme(0),
            Err(ErreurCoffre::OptionsGenerateur)
        ));
    }

    #[test]
    fn phrase_diceware() {
        let phrase = generer_phrase(6, '-').unwrap();
        let mots: Vec<&str> = phrase.split('-').collect();
        assert_eq!(mots.len(), 6);
        let liste: HashSet<&str> = liste_mots().iter().copied().collect();
        assert!(mots.iter().all(|m| liste.contains(m)));
    }

    #[test]
    fn entropies_coherentes() {
        // 14 caractères sur 94 symboles ≈ 91,7 bits.
        let e = entropie_bits(94, 14);
        assert!(e > 80.0 && e < 100.0);
        // 6 mots diceware ≈ 77,5 bits.
        let p = entropie_phrase(6);
        assert!(p > 77.0 && p < 78.0);
        assert_eq!(entropie_bits(1, 10), 0.0);
        assert_eq!(entropie_bits(94, 0), 0.0);
    }
}
