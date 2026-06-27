//! Codage longueur-préfixée (blocs `u32 LE + octets`), décodage fail-closed.

use crate::erreurs::ErreurPartage;

/// Écrit un bloc « longueur u32 LE + octets ».
pub(crate) fn ecrire_bloc(sortie: &mut Vec<u8>, bloc: &[u8]) {
    sortie.extend_from_slice(&(bloc.len() as u32).to_le_bytes());
    sortie.extend_from_slice(bloc);
}

/// Lecteur à curseur, à lectures bornées (jamais de `panic`).
pub(crate) struct Lecteur<'a> {
    donnees: &'a [u8],
    position: usize,
}

impl<'a> Lecteur<'a> {
    pub(crate) fn new(donnees: &'a [u8]) -> Self {
        Self {
            donnees,
            position: 0,
        }
    }

    fn octets(&mut self, n: usize) -> Result<&'a [u8], ErreurPartage> {
        let fin = self.position.checked_add(n).ok_or(ErreurPartage::Format)?;
        let tranche = self
            .donnees
            .get(self.position..fin)
            .ok_or(ErreurPartage::Format)?;
        self.position = fin;
        Ok(tranche)
    }

    fn longueur(&mut self) -> Result<usize, ErreurPartage> {
        let a: [u8; 4] = self
            .octets(4)?
            .try_into()
            .map_err(|_| ErreurPartage::Format)?;
        Ok(u32::from_le_bytes(a) as usize)
    }

    /// Lit le prochain bloc longueur-préfixé.
    pub(crate) fn bloc(&mut self) -> Result<&'a [u8], ErreurPartage> {
        let n = self.longueur()?;
        self.octets(n)
    }

    /// Indique que tous les octets ont été consommés.
    pub(crate) fn est_termine(&self) -> bool {
        self.position == self.donnees.len()
    }
}
