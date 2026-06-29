//! Fournisseur de fuites réel (*Have I Been Pwned*, API « range »), branché sur
//! le trait [`nex_coffre::audit::FournisseurFuites`].
//!
//! **k-anonymat** : seul un préfixe de 5 caractères du SHA-1 est transmis ; le
//! mot de passe et son condensat complet ne quittent jamais l'appareil. C'est le
//! cœur (`nex-coffre`) qui calcule le préfixe et compare les suffixes localement.

use nex_coffre::audit::FournisseurFuites;
use nex_coffre::ErreurCoffre;

/// Interroge `api.pwnedpasswords.com/range/{prefixe}` en HTTPS.
pub struct FournisseurHibp;

impl FournisseurFuites for FournisseurHibp {
    fn suffixes(&self, prefixe: &str) -> Result<Vec<(String, u64)>, ErreurCoffre> {
        let url = format!("https://api.pwnedpasswords.com/range/{prefixe}");
        let reponse = minreq::get(&url)
            .with_header("User-Agent", "nexkeylock")
            .with_timeout(10)
            .send()
            .map_err(|_| ErreurCoffre::Fuites)?;
        if reponse.status_code != 200 {
            return Err(ErreurCoffre::Fuites);
        }
        let corps = reponse.as_str().map_err(|_| ErreurCoffre::Fuites)?;
        Ok(analyser_reponse(corps))
    }
}

/// Analyse une réponse « range » HIBP (`SUFFIXE:OCCURRENCES` par ligne).
/// Séparé pour être testable sans réseau.
fn analyser_reponse(corps: &str) -> Vec<(String, u64)> {
    corps
        .lines()
        .filter_map(|ligne| {
            let (suffixe, nombre) = ligne.split_once(':')?;
            let nombre = nombre.trim().parse::<u64>().ok()?;
            Some((suffixe.trim().to_string(), nombre))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn analyse_des_lignes_suffixe_occurrences() {
        let corps = "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2\nLIGNE_INVALIDE\n";
        let liste = analyser_reponse(corps);
        assert_eq!(liste.len(), 2);
        assert_eq!(
            liste[0],
            ("0018A45C4D1DEF81644B54AB7F969B88D65".to_string(), 1)
        );
        assert_eq!(liste[1].1, 2);
    }
}
