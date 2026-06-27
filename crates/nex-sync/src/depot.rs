//! Transport de synchronisation **zéro-connaissance**.
//!
//! Le dépôt distant ne voit que des **blobs chiffrés opaques** et une
//! **révision** monotone. Il n'apprend rien du contenu. La concurrence est
//! gérée de façon **optimiste** : un envoi n'est accepté que si la révision de
//! base attendue correspond à la révision courante du dépôt ; sinon un conflit
//! est signalé et le client doit tirer, fusionner (côté client, après
//! déchiffrement), puis réessayer.

/// Blob chiffré accompagné de sa révision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobRevise {
    /// Révision associée.
    pub revision: u64,
    /// Blob chiffré opaque.
    pub blob: Vec<u8>,
}

/// Résultat d'un envoi.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pousser {
    /// Accepté ; nouvelle révision du dépôt.
    Accepte(u64),
    /// Refusé : la révision de base ne correspond plus (conflit).
    Conflit {
        /// Révision actuelle du dépôt.
        actuelle: u64,
    },
}

/// Dépôt distant de synchronisation (abstrait, *mockable*).
pub trait DepotSync {
    /// Révision courante du dépôt.
    fn revision(&self) -> u64;

    /// Récupère le dernier blob chiffré, s'il existe.
    fn tirer(&self) -> Option<BlobRevise>;

    /// Tente d'envoyer `blob` en supposant la révision de base `base`.
    /// N'accepte que si `base` correspond à la révision courante.
    fn pousser(&mut self, base: u64, blob: &[u8]) -> Pousser;
}

/// État local de synchronisation : dernière révision connue du dépôt.
#[derive(Debug, Clone, Default)]
pub struct EtatLocal {
    /// Révision de base sur laquelle le client s'appuie.
    pub base: u64,
}

impl EtatLocal {
    /// Envoie `blob` au dépôt et met à jour la base en cas d'acceptation.
    ///
    /// Renvoie le résultat de l'envoi : en cas de [`Pousser::Conflit`], le client
    /// doit tirer le dépôt, fusionner localement, puis réessayer.
    pub fn pousser(&mut self, depot: &mut dyn DepotSync, blob: &[u8]) -> Pousser {
        let resultat = depot.pousser(self.base, blob);
        if let Pousser::Accepte(nouvelle) = resultat {
            self.base = nouvelle;
        }
        resultat
    }

    /// Tire le dépôt et avance la base locale sur la révision distante.
    pub fn tirer(&mut self, depot: &dyn DepotSync) -> Option<BlobRevise> {
        let blob = depot.tirer();
        if let Some(b) = &blob {
            self.base = b.revision;
        }
        blob
    }
}

/// Dépôt en mémoire (simulé) : aucun réseau, sert aux tests et de référence.
#[derive(Debug, Default)]
pub struct DepotMemoire {
    revision: u64,
    blob: Option<Vec<u8>>,
}

impl DepotSync for DepotMemoire {
    fn revision(&self) -> u64 {
        self.revision
    }

    fn tirer(&self) -> Option<BlobRevise> {
        self.blob.as_ref().map(|b| BlobRevise {
            revision: self.revision,
            blob: b.clone(),
        })
    }

    fn pousser(&mut self, base: u64, blob: &[u8]) -> Pousser {
        if base != self.revision {
            return Pousser::Conflit {
                actuelle: self.revision,
            };
        }
        self.revision += 1;
        self.blob = Some(blob.to_vec());
        Pousser::Accepte(self.revision)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envoi_initial_puis_tirage() {
        let mut depot = DepotMemoire::default();
        let mut etat = EtatLocal::default();

        assert_eq!(
            etat.pousser(&mut depot, b"blob-chiffre-1"),
            Pousser::Accepte(1)
        );
        assert_eq!(etat.base, 1);

        let tire = depot.tirer().unwrap();
        assert_eq!(tire.revision, 1);
        assert_eq!(tire.blob, b"blob-chiffre-1");
    }

    #[test]
    fn concurrence_optimiste_detecte_le_conflit() {
        let mut depot = DepotMemoire::default();
        let mut client_a = EtatLocal::default();
        let mut client_b = EtatLocal::default();

        // A pousse en premier (base 0 -> rev 1).
        assert_eq!(
            client_a.pousser(&mut depot, b"version-A"),
            Pousser::Accepte(1)
        );

        // B pousse sur la même base 0 -> conflit (le dépôt est en rev 1).
        assert_eq!(
            client_b.pousser(&mut depot, b"version-B"),
            Pousser::Conflit { actuelle: 1 }
        );

        // B tire (fusion côté client, puis réessaie sur la base 1).
        let _ = client_b.tirer(&depot);
        assert_eq!(client_b.base, 1);
        assert_eq!(
            client_b.pousser(&mut depot, b"version-B-fusionnee"),
            Pousser::Accepte(2)
        );

        assert_eq!(depot.tirer().unwrap().blob, b"version-B-fusionnee");
    }

    #[test]
    fn le_depot_ne_voit_que_des_octets_opaques() {
        // Le dépôt restitue exactement les octets reçus, sans interprétation.
        let mut depot = DepotMemoire::default();
        let mut etat = EtatLocal::default();
        let blob = vec![0x00u8, 0xFF, 0x10, 0x42, 0x00];
        etat.pousser(&mut depot, &blob);
        assert_eq!(depot.tirer().unwrap().blob, blob);
    }
}
