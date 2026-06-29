//! API du coffre : machine à états typée verrouillé / déverrouillé.
//!
//! - [`CoffreVerrouille`] : fichier lu et décodé, **sans clé en mémoire**.
//! - [`CoffreDeverrouille`] : clé de coffre (DEK) et contenu en clair présents ;
//!   ses secrets sont effacés à la libération (`ZeroizeOnDrop`).
//!
//! Hiérarchie : `mot de passe → Argon2id → KEK` ; `KEK` emballe une `DEK`
//! aléatoire ; la `DEK` chiffre le corps. Un changement de mot de passe ne
//! **réemballe que la DEK** (voir [`CoffreDeverrouille::changer_mot_de_passe`]).
//!
//! Politique conservatrice : la **création** se restreint à XChaCha20-Poly1305
//! (nonces aléatoires sûrs sur 192 bits). Le format reste agile : un coffre
//! AES-256-GCM existant pourrait être déchiffré, mais on n'en crée pas tant que
//! la persistance d'un compteur de nonce n'est pas implémentée (cf. SECURITY.md).

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use nex_cryptographie::aead::{self, Algorithme};
use nex_cryptographie::alea::octets_aleatoires;
use nex_cryptographie::kdf::{deriver_cle, deriver_cle_avec_secret, ParametresArgon2};
use nex_cryptographie::CleSecrete;
use zeroize::Zeroizing;

use crate::entete::EnteteAuth;
use crate::erreurs::ErreurCoffre;
use crate::format::{BlocRecuperation, FichierCoffre};
use crate::modele::{ContenuCoffre, Entree};

/// Longueur du sel KDF, en octets.
const LONGUEUR_SEL: usize = 16;

/// Coffre verrouillé : données chiffrées en mémoire, aucune clé.
#[derive(Debug)]
pub struct CoffreVerrouille {
    chemin: PathBuf,
    fichier: FichierCoffre,
}

impl CoffreVerrouille {
    /// Lit et décode un fichier de coffre depuis le disque.
    ///
    /// # Erreurs
    /// - [`ErreurCoffre::Io`] si la lecture échoue ;
    /// - [`ErreurCoffre::FormatInvalide`] / [`ErreurCoffre::Serialisation`] si
    ///   le format est invalide ;
    /// - [`ErreurCoffre::VersionNonSupportee`] / [`ErreurCoffre::AlgorithmeNonSupporte`].
    pub fn ouvrir(chemin: impl AsRef<Path>) -> Result<Self, ErreurCoffre> {
        let chemin = chemin.as_ref().to_path_buf();
        let donnees = std::fs::read(&chemin)?;
        let fichier = FichierCoffre::decoder(&donnees)?;
        fichier.entete.valider()?;
        Ok(Self { chemin, fichier })
    }

    /// En-tête authentifié du coffre.
    pub fn entete(&self) -> &EnteteAuth {
        &self.fichier.entete
    }

    /// Déverrouille le coffre avec le mot de passe maître.
    ///
    /// **Échec sûr** : un mot de passe invalide ou un en-tête altéré renvoie
    /// [`ErreurCoffre::MotDePasseInvalide`] sans aucune donnée ; un corps altéré
    /// renvoie [`ErreurCoffre::Corrompu`].
    ///
    /// # Erreurs
    /// Voir ci-dessus, plus [`ErreurCoffre::Serialisation`] si le contenu
    /// déchiffré est illisible.
    pub fn deverrouiller(self, mot_de_passe: &[u8]) -> Result<CoffreDeverrouille, ErreurCoffre> {
        self.deverrouiller_avec_fichier_cle(mot_de_passe, &[])
    }

    /// Déverrouille avec un **fichier-clé** (second facteur). Le secret est mêlé
    /// à Argon2id : un secret vide équivaut à [`Self::deverrouiller`].
    ///
    /// # Erreurs
    /// [`ErreurCoffre::MotDePasseInvalide`] si le mot de passe **ou** le
    /// fichier-clé est incorrect (indistinguable, par construction).
    pub fn deverrouiller_avec_fichier_cle(
        self,
        mot_de_passe: &[u8],
        fichier_cle: &[u8],
    ) -> Result<CoffreDeverrouille, ErreurCoffre> {
        let algo = self.fichier.entete.valider()?;
        let parametres = self.fichier.entete.parametres_kdf();
        let kek = deriver_cle_avec_secret(
            mot_de_passe,
            &self.fichier.entete.sel,
            parametres,
            fichier_cle,
        )?;

        // Déballage de la DEK (authentifie l'en-tête complet via aad_dek).
        let dek_clair = Zeroizing::new(
            aead::dechiffrer(
                algo,
                &kek,
                &self.fichier.nonce_dek,
                &self.fichier.dek_emballee,
                &self.fichier.entete_brut,
            )
            .map_err(|_| ErreurCoffre::MotDePasseInvalide)?,
        );
        let dek = CleSecrete::depuis_tranche(&dek_clair)?;

        // Déchiffrement du corps (authentifie version + algorithme).
        let aad_corps = self.fichier.entete.aad_corps();
        let clair = Zeroizing::new(
            aead::dechiffrer(
                algo,
                &dek,
                &self.fichier.nonce_corps,
                &self.fichier.corps,
                &aad_corps,
            )
            .map_err(|_| ErreurCoffre::Corrompu)?,
        );
        let contenu: ContenuCoffre =
            ciborium::from_reader(clair.as_slice()).map_err(|_| ErreurCoffre::Serialisation)?;

        Ok(CoffreDeverrouille {
            chemin: self.chemin,
            entete: self.fichier.entete,
            entete_brut: self.fichier.entete_brut,
            nonce_dek: self.fichier.nonce_dek,
            dek_emballee: self.fichier.dek_emballee,
            dek,
            contenu,
            recuperation: self.fichier.recuperation,
            secret_fichier_cle: Zeroizing::new(fichier_cle.to_vec()),
            derniere_activite: Instant::now(),
        })
    }

    /// Déverrouille le coffre à l'aide du **code de récupération** (seconde voie
    /// de déballage de la DEK), si un bloc de récupération est présent.
    ///
    /// # Erreurs
    /// - [`ErreurCoffre::RecuperationAbsente`] si aucun code n'est configuré ;
    /// - [`ErreurCoffre::MotDePasseInvalide`] si le code est incorrect ;
    /// - [`ErreurCoffre::Corrompu`] si le corps est altéré.
    pub fn deverrouiller_par_recuperation(
        self,
        code: &str,
    ) -> Result<CoffreDeverrouille, ErreurCoffre> {
        let algo = self.fichier.entete.valider()?;
        if self.fichier.recuperation.is_empty() {
            return Err(ErreurCoffre::RecuperationAbsente);
        }
        let bloc: BlocRecuperation = ciborium::from_reader(self.fichier.recuperation.as_slice())
            .map_err(|_| ErreurCoffre::FormatInvalide)?;

        let canonique = canonicaliser_code(code);
        let parametres = ParametresArgon2::new(bloc.kdf_m_kio, bloc.kdf_t, bloc.kdf_p);
        let cle_rec = deriver_cle(canonique.as_bytes(), &bloc.sel, parametres)?;

        // L'emballage de récupération est authentifié par aad_corps (stable au
        // changement de mot de passe), lié au sel et aux paramètres KDF du bloc
        // (qui sont ainsi authentifiés, pas seulement « auto-cohérents »).
        let aad_corps = self.fichier.entete.aad_corps();
        let aad = aad_recuperation(
            &aad_corps,
            &bloc.sel,
            bloc.kdf_m_kio,
            bloc.kdf_t,
            bloc.kdf_p,
        );
        let dek_clair = Zeroizing::new(
            aead::dechiffrer(algo, &cle_rec, &bloc.nonce, &bloc.dek_emballee, &aad)
                .map_err(|_| ErreurCoffre::MotDePasseInvalide)?,
        );
        let dek = CleSecrete::depuis_tranche(&dek_clair)?;

        let clair = Zeroizing::new(
            aead::dechiffrer(
                algo,
                &dek,
                &self.fichier.nonce_corps,
                &self.fichier.corps,
                &aad_corps,
            )
            .map_err(|_| ErreurCoffre::Corrompu)?,
        );
        let contenu: ContenuCoffre =
            ciborium::from_reader(clair.as_slice()).map_err(|_| ErreurCoffre::Serialisation)?;

        Ok(CoffreDeverrouille {
            chemin: self.chemin,
            entete: self.fichier.entete,
            entete_brut: self.fichier.entete_brut,
            nonce_dek: self.fichier.nonce_dek,
            dek_emballee: self.fichier.dek_emballee,
            dek,
            contenu,
            recuperation: self.fichier.recuperation,
            // La récupération est **indépendante** du fichier-clé : on n'en
            // conserve aucun. Après récupération + changement de mot de passe, le
            // coffre redevient sans fichier-clé (voir `changer_mot_de_passe`).
            secret_fichier_cle: Zeroizing::new(Vec::new()),
            derniere_activite: Instant::now(),
        })
    }
}

/// Coffre déverrouillé : DEK et contenu en clair présents en mémoire.
pub struct CoffreDeverrouille {
    chemin: PathBuf,
    entete: EnteteAuth,
    entete_brut: Vec<u8>,
    nonce_dek: Vec<u8>,
    dek_emballee: Vec<u8>,
    dek: CleSecrete,
    contenu: ContenuCoffre,
    /// Bloc de récupération sérialisé (vide = aucune récupération).
    recuperation: Vec<u8>,
    /// Secret du fichier-clé (second facteur) ; **vide** si aucun fichier-clé.
    /// Conservé pour réemballer la DEK lors d'un changement de mot de passe ;
    /// effacé à la libération.
    secret_fichier_cle: Zeroizing<Vec<u8>>,
    derniere_activite: Instant,
}

impl CoffreDeverrouille {
    /// Crée un nouveau coffre vide et l'écrit sur le disque (XChaCha20-Poly1305).
    ///
    /// # Erreurs
    /// [`ErreurCoffre::Io`], [`ErreurCoffre::Crypto`] ou [`ErreurCoffre::Serialisation`]
    /// en cas d'échec d'écriture, de dérivation ou de sérialisation.
    pub fn creer(
        chemin: impl AsRef<Path>,
        mot_de_passe: &[u8],
        parametres: ParametresArgon2,
    ) -> Result<Self, ErreurCoffre> {
        Self::creer_avec_fichier_cle(chemin, mot_de_passe, &[], parametres)
    }

    /// Crée un coffre protégé par **mot de passe + fichier-clé** (second facteur).
    /// Un `fichier_cle` vide équivaut à [`Self::creer`].
    ///
    /// # Erreurs
    /// [`ErreurCoffre::Io`], [`ErreurCoffre::Crypto`] ou [`ErreurCoffre::Serialisation`].
    pub fn creer_avec_fichier_cle(
        chemin: impl AsRef<Path>,
        mot_de_passe: &[u8],
        fichier_cle: &[u8],
        parametres: ParametresArgon2,
    ) -> Result<Self, ErreurCoffre> {
        let algo = Algorithme::XChaCha20Poly1305;
        let sel = octets_aleatoires::<LONGUEUR_SEL>()?.to_vec();
        let mut entete = EnteteAuth::nouveau(algo, parametres, sel.clone());
        // Le flag doit être posé AVANT le calcul de aad_dek (qui l'authentifie).
        entete.fichier_cle_requis = !fichier_cle.is_empty();
        let entete_brut = entete.aad_dek()?;

        let kek = deriver_cle_avec_secret(mot_de_passe, &sel, parametres, fichier_cle)?;
        let dek = CleSecrete::aleatoire()?;
        let nonce_dek = nonce_neuf(algo)?;
        let dek_emballee = aead::chiffrer(algo, &kek, &nonce_dek, dek.exposer(), &entete_brut)?;

        let coffre = Self {
            chemin: chemin.as_ref().to_path_buf(),
            entete,
            entete_brut,
            nonce_dek,
            dek_emballee,
            dek,
            contenu: ContenuCoffre::default(),
            recuperation: Vec::new(),
            secret_fichier_cle: Zeroizing::new(fichier_cle.to_vec()),
            derniere_activite: Instant::now(),
        };
        let octets = coffre.vers_octets()?;
        ecrire_atomique(&coffre.chemin, &octets)?;
        Ok(coffre)
    }

    /// Active (ou remplace) un **code de récupération** : la DEK est emballée
    /// une seconde fois par une clé dérivée d'un code aléatoire à haute
    /// entropie. Renvoie le code (à conserver hors ligne ; affiché une seule
    /// fois). Le coffre est réécrit.
    ///
    /// # Erreurs
    /// [`ErreurCoffre::Io`], [`ErreurCoffre::Crypto`] ou [`ErreurCoffre::Serialisation`].
    pub fn activer_recuperation(
        &mut self,
        parametres: ParametresArgon2,
    ) -> Result<Zeroizing<String>, ErreurCoffre> {
        let algo = self.entete.valider()?;
        let code = nouveau_code_recuperation()?;
        let canonique = canonicaliser_code(&code);

        let sel = octets_aleatoires::<LONGUEUR_SEL>()?.to_vec();
        let cle_rec = deriver_cle(canonique.as_bytes(), &sel, parametres)?;
        let nonce = nonce_neuf(algo)?;
        let aad_corps = self.entete.aad_corps();
        let aad = aad_recuperation(
            &aad_corps,
            &sel,
            parametres.memoire_kio,
            parametres.iterations,
            parametres.parallelisme,
        );
        let dek_emballee = aead::chiffrer(algo, &cle_rec, &nonce, self.dek.exposer(), &aad)?;

        let bloc = BlocRecuperation {
            sel,
            kdf_m_kio: parametres.memoire_kio,
            kdf_t: parametres.iterations,
            kdf_p: parametres.parallelisme,
            nonce,
            dek_emballee,
        };
        let mut octets = Vec::new();
        ciborium::into_writer(&bloc, &mut octets).map_err(|_| ErreurCoffre::Serialisation)?;
        self.recuperation = octets;

        self.enregistrer()?;
        Ok(code)
    }

    /// Indique si un code de récupération est configuré.
    pub fn a_recuperation(&self) -> bool {
        !self.recuperation.is_empty()
    }

    /// Entrées du coffre (lecture seule).
    pub fn entrees(&self) -> &[Entree] {
        &self.contenu.entrees
    }

    /// Cherche une entrée par identifiant.
    pub fn obtenir(&self, id: &str) -> Option<&Entree> {
        self.contenu.obtenir(id)
    }

    /// Recherche les entrées dont le nom, une URI ou le nom d'utilisateur
    /// contient `requete` (sans tenir compte de la casse).
    pub fn rechercher(&self, requete: &str) -> Vec<&Entree> {
        let requete = requete.to_lowercase();
        self.contenu
            .entrees
            .iter()
            .filter(|e| {
                e.nom.to_lowercase().contains(&requete)
                    || e.nom_utilisateur
                        .as_deref()
                        .is_some_and(|u| u.to_lowercase().contains(&requete))
                    || e.uris.iter().any(|u| u.to_lowercase().contains(&requete))
            })
            .collect()
    }

    /// Accès au contenu déchiffré (pour l'audit hors-ligne).
    pub fn contenu(&self) -> &ContenuCoffre {
        &self.contenu
    }

    /// Identité de partage sérialisée stockée dans le coffre, le cas échéant
    /// (clés privées hybrides — à désérialiser avec `nex-partage`).
    pub fn identite_partage(&self) -> Option<&[u8]> {
        self.contenu.identite_partage.as_deref()
    }

    /// Définit (ou remplace) l'identité de partage. Appeler [`Self::enregistrer`]
    /// pour persister.
    pub fn definir_identite_partage(&mut self, octets: Vec<u8>) {
        self.contenu.identite_partage = Some(octets);
        self.toucher();
    }

    /// Passkeys sérialisées stockées dans le coffre.
    pub fn passkeys(&self) -> &[Vec<u8>] {
        &self.contenu.passkeys
    }

    /// Ajoute une passkey sérialisée.
    pub fn ajouter_passkey(&mut self, octets: Vec<u8>) {
        self.contenu.passkeys.push(octets);
        self.toucher();
    }

    /// Remplace l'ensemble des passkeys (p. ex. après mise à jour d'un compteur).
    pub fn definir_passkeys(&mut self, passkeys: Vec<Vec<u8>>) {
        self.contenu.passkeys = passkeys;
        self.toucher();
    }

    /// Ajoute une entrée au coffre (en mémoire ; appeler [`Self::enregistrer`]
    /// pour persister).
    pub fn ajouter(&mut self, entree: Entree) {
        self.contenu.entrees.push(entree);
        self.toucher();
    }

    /// Accès modifiable à une entrée par identifiant.
    pub fn modifier(&mut self, id: &str) -> Option<&mut Entree> {
        self.toucher();
        self.contenu.obtenir_mut(id)
    }

    /// Supprime une entrée ; renvoie `true` si elle existait.
    pub fn supprimer(&mut self, id: &str) -> bool {
        self.toucher();
        self.contenu.supprimer(id)
    }

    /// Sérialise, chiffre et écrit le coffre de façon atomique.
    ///
    /// # Erreurs
    /// [`ErreurCoffre::Io`], [`ErreurCoffre::Crypto`] ou [`ErreurCoffre::Serialisation`].
    pub fn enregistrer(&mut self) -> Result<(), ErreurCoffre> {
        let octets = self.vers_octets()?;
        ecrire_atomique(&self.chemin, &octets)?;
        self.toucher();
        Ok(())
    }

    /// Change le mot de passe maître en **réemballant uniquement la DEK**.
    ///
    /// Un nouveau sel est tiré, la KEK est recalculée et la DEK (inchangée) est
    /// réemballée. Le coffre est ensuite réécrit. L'ancien mot de passe ne
    /// déverrouille plus le coffre.
    ///
    /// # Erreurs
    /// [`ErreurCoffre::Io`], [`ErreurCoffre::Crypto`] ou [`ErreurCoffre::Serialisation`].
    pub fn changer_mot_de_passe(&mut self, nouveau: &[u8]) -> Result<(), ErreurCoffre> {
        let algo = self.entete.valider()?;
        let parametres = self.entete.parametres_kdf();

        let nouveau_sel = octets_aleatoires::<LONGUEUR_SEL>()?.to_vec();
        let mut nouvelle_entete = EnteteAuth::nouveau(algo, parametres, nouveau_sel.clone());
        // Conserve l'exigence de fichier-clé (vide après une récupération).
        nouvelle_entete.fichier_cle_requis = !self.secret_fichier_cle.is_empty();
        let nouvel_entete_brut = nouvelle_entete.aad_dek()?;

        let kek =
            deriver_cle_avec_secret(nouveau, &nouveau_sel, parametres, &self.secret_fichier_cle)?;
        let nonce_dek = nonce_neuf(algo)?;
        let dek_emballee = aead::chiffrer(
            algo,
            &kek,
            &nonce_dek,
            self.dek.exposer(),
            &nouvel_entete_brut,
        )?;

        // La DEK (self.dek) reste identique : seul son emballage change.
        self.entete = nouvelle_entete;
        self.entete_brut = nouvel_entete_brut;
        self.nonce_dek = nonce_dek;
        self.dek_emballee = dek_emballee;

        self.enregistrer()
    }

    /// Verrouille le coffre : efface les secrets (au `drop`) et renvoie un
    /// [`CoffreVerrouille`] relu depuis le disque.
    ///
    /// Les modifications non enregistrées sont **perdues** : appeler
    /// [`Self::enregistrer`] au préalable si nécessaire.
    ///
    /// # Erreurs
    /// [`ErreurCoffre::Io`] / format si la relecture échoue.
    pub fn verrouiller(self) -> Result<CoffreVerrouille, ErreurCoffre> {
        let chemin = self.chemin.clone();
        drop(self); // efface dek + contenu (ZeroizeOnDrop)
        CoffreVerrouille::ouvrir(&chemin)
    }

    /// Indique si le coffre est inactif depuis au moins `delai` (verrouillage
    /// automatique : la politique est appliquée par l'appelant).
    pub fn est_inactif(&self, delai: Duration) -> bool {
        self.derniere_activite.elapsed() >= delai
    }

    /// Réinitialise le minuteur d'inactivité.
    pub fn toucher(&mut self) {
        self.derniere_activite = Instant::now();
    }

    /// Construit les octets chiffrés du fichier (corps rechiffré avec un nonce
    /// neuf, sous la DEK courante).
    fn vers_octets(&self) -> Result<Vec<u8>, ErreurCoffre> {
        let algo = self.entete.valider()?;
        let aad_corps = self.entete.aad_corps();

        let mut clair = Vec::new();
        ciborium::into_writer(&self.contenu, &mut clair)
            .map_err(|_| ErreurCoffre::Serialisation)?;
        let clair = Zeroizing::new(clair);

        let nonce_corps = nonce_neuf(algo)?;
        let corps = aead::chiffrer(algo, &self.dek, &nonce_corps, &clair, &aad_corps)?;

        let fichier = FichierCoffre {
            entete: self.entete.clone(),
            entete_brut: self.entete_brut.clone(),
            nonce_dek: self.nonce_dek.clone(),
            dek_emballee: self.dek_emballee.clone(),
            nonce_corps,
            corps,
            recuperation: self.recuperation.clone(),
        };
        Ok(fichier.encoder())
    }
}

impl core::fmt::Debug for CoffreDeverrouille {
    /// `Debug` minimal : aucun secret ni métadonnée d'entrée n'est divulgué.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CoffreDeverrouille")
            .field("chemin", &self.chemin)
            .field("nombre_entrees", &self.contenu.entrees.len())
            .field("dek", &"***")
            .finish()
    }
}

/// Tire un nonce neuf adapté à l'algorithme.
///
/// XChaCha20-Poly1305 : nonce aléatoire de 192 bits (sûr). AES-256-GCM est
/// refusé ici car il exige un compteur persistant (jamais de nonce aléatoire).
fn nonce_neuf(algo: Algorithme) -> Result<Vec<u8>, ErreurCoffre> {
    match algo {
        Algorithme::XChaCha20Poly1305 => Ok(aead::nonce_aleatoire_xchacha()?.to_vec()),
        Algorithme::Aes256Gcm => Err(ErreurCoffre::AlgorithmeNonSupporte),
    }
}

/// Écrit `donnees` de façon atomique : fichier temporaire puis renommage.
fn ecrire_atomique(chemin: &Path, donnees: &[u8]) -> Result<(), ErreurCoffre> {
    let mut chemin_tmp = chemin.as_os_str().to_os_string();
    chemin_tmp.push(".tmp");
    let chemin_tmp = PathBuf::from(chemin_tmp);
    std::fs::write(&chemin_tmp, donnees)?;
    std::fs::rename(&chemin_tmp, chemin)?;
    Ok(())
}

/// Génère un identifiant d'entrée aléatoire (128 bits, hexadécimal).
///
/// # Erreurs
/// [`ErreurCoffre::Crypto`] si la source d'aléa est indisponible.
pub fn nouvel_identifiant() -> Result<String, ErreurCoffre> {
    let octets = octets_aleatoires::<16>()?;
    Ok(hex_minuscule(&octets))
}

/// Génère le contenu d'un **fichier-clé** : 256 bits aléatoires (CSPRNG).
///
/// L'appelant l'écrit dans un fichier, à conserver **séparément** du coffre et
/// **jamais synchronisé** avec lui. Au déverrouillage, on relit ces octets et on
/// les passe comme second facteur.
///
/// # Erreurs
/// [`ErreurCoffre::Crypto`] si la source d'aléa est indisponible.
pub fn nouveau_fichier_cle() -> Result<Zeroizing<Vec<u8>>, ErreurCoffre> {
    Ok(Zeroizing::new(octets_aleatoires::<32>()?.to_vec()))
}

/// Horodatage courant en secondes Unix (0 si l'horloge est antérieure à l'epoch).
pub fn maintenant_unix() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Encodage hexadécimal minuscule (sans dépendance externe).
fn hex_minuscule(octets: &[u8]) -> String {
    let mut s = String::with_capacity(octets.len() * 2);
    for &o in octets {
        s.push(char::from_digit(u32::from(o >> 4), 16).unwrap_or('0'));
        s.push(char::from_digit(u32::from(o & 0x0f), 16).unwrap_or('0'));
    }
    s
}

/// Génère un code de récupération aléatoire (160 bits), groupé par blocs de 5
/// caractères pour la lisibilité (p. ex. `a1b2c-3d4e5-…`).
///
/// # Erreurs
/// [`ErreurCoffre::Crypto`] si la source d'aléa est indisponible.
pub fn nouveau_code_recuperation() -> Result<Zeroizing<String>, ErreurCoffre> {
    let octets = octets_aleatoires::<20>()?;
    let hex = hex_minuscule(&octets);
    let groupes: Vec<String> = hex
        .as_bytes()
        .chunks(5)
        .map(|bloc| String::from_utf8_lossy(bloc).into_owned())
        .collect();
    Ok(Zeroizing::new(groupes.join("-")))
}

/// Canonicalise un code de récupération : caractères alphanumériques en
/// minuscules, sans séparateurs ni espaces (pour une dérivation stable).
fn canonicaliser_code(code: &str) -> String {
    code.chars()
        .filter(char::is_ascii_alphanumeric)
        .flat_map(char::to_lowercase)
        .collect()
}

/// Données associées de l'emballage de récupération : `aad_corps` (version+algo,
/// stable au changement de mot de passe) lié au **sel** et aux **paramètres
/// KDF** du bloc, afin que ces derniers soient authentifiés et non simplement
/// auto-cohérents (cf. SECURITY_AUDIT AUDIT-007).
fn aad_recuperation(aad_corps: &[u8], sel: &[u8], m_kio: u32, t: u32, p: u32) -> Vec<u8> {
    let mut aad = Vec::with_capacity(aad_corps.len() + sel.len() + 12);
    aad.extend_from_slice(aad_corps);
    aad.extend_from_slice(sel);
    aad.extend_from_slice(&m_kio.to_le_bytes());
    aad.extend_from_slice(&t.to_le_bytes());
    aad.extend_from_slice(&p.to_le_bytes());
    aad
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiant_a_la_bonne_forme() {
        let id = nouvel_identifiant().unwrap();
        assert_eq!(id.len(), 32);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn nonce_aesgcm_refuse() {
        assert!(matches!(
            nonce_neuf(Algorithme::Aes256Gcm),
            Err(ErreurCoffre::AlgorithmeNonSupporte)
        ));
    }

    #[test]
    fn code_recuperation_format() {
        let code = nouveau_code_recuperation().unwrap();
        // 40 hex en 8 groupes de 5, séparés par 7 tirets => 47 caractères.
        assert_eq!(code.len(), 47);
        assert_eq!(code.matches('-').count(), 7);
        let canon = canonicaliser_code(&code);
        assert_eq!(canon.len(), 40);
        assert!(canon.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn canonicalisation_ignore_casse_et_separateurs() {
        assert_eq!(canonicaliser_code("AB-cd EF-12"), "abcdef12");
    }

    fn params_rapides() -> ParametresArgon2 {
        ParametresArgon2::new(8, 1, 1)
    }

    #[test]
    fn fichier_cle_requis_pour_deverrouiller() {
        let dir = tempfile::tempdir().unwrap();
        let chemin = dir.path().join("c.vault");
        let kf = b"secret-fichier-cle-de-32-octets!";
        CoffreDeverrouille::creer_avec_fichier_cle(&chemin, b"mdp", kf, params_rapides()).unwrap();

        // L'en-tête signale le second facteur.
        assert!(
            CoffreVerrouille::ouvrir(&chemin)
                .unwrap()
                .entete()
                .fichier_cle_requis
        );

        // Bon mot de passe + bon fichier-clé => succès.
        assert!(CoffreVerrouille::ouvrir(&chemin)
            .unwrap()
            .deverrouiller_avec_fichier_cle(b"mdp", kf)
            .is_ok());

        // Bon mot de passe, SANS fichier-clé => échec sûr.
        assert!(matches!(
            CoffreVerrouille::ouvrir(&chemin)
                .unwrap()
                .deverrouiller(b"mdp"),
            Err(ErreurCoffre::MotDePasseInvalide)
        ));

        // Bon mot de passe, MAUVAIS fichier-clé => échec sûr.
        assert!(matches!(
            CoffreVerrouille::ouvrir(&chemin)
                .unwrap()
                .deverrouiller_avec_fichier_cle(b"mdp", b"mauvais-fichier"),
            Err(ErreurCoffre::MotDePasseInvalide)
        ));
    }

    #[test]
    fn coffre_sans_fichier_cle_reste_compatible() {
        let dir = tempfile::tempdir().unwrap();
        let chemin = dir.path().join("c.vault");
        CoffreDeverrouille::creer(&chemin, b"mdp", params_rapides()).unwrap();
        let verrou = CoffreVerrouille::ouvrir(&chemin).unwrap();
        assert!(!verrou.entete().fichier_cle_requis);
        assert!(verrou.deverrouiller(b"mdp").is_ok());
    }

    #[test]
    fn changement_mot_de_passe_conserve_le_fichier_cle() {
        let dir = tempfile::tempdir().unwrap();
        let chemin = dir.path().join("c.vault");
        let kf = b"fichier-cle-de-test-aaaaaaaaaaaa";
        let mut c =
            CoffreDeverrouille::creer_avec_fichier_cle(&chemin, b"ancien", kf, params_rapides())
                .unwrap();
        c.changer_mot_de_passe(b"nouveau").unwrap();

        assert!(CoffreVerrouille::ouvrir(&chemin)
            .unwrap()
            .deverrouiller_avec_fichier_cle(b"nouveau", kf)
            .is_ok());
        // Le fichier-clé reste exigé après le changement de mot de passe.
        assert!(CoffreVerrouille::ouvrir(&chemin)
            .unwrap()
            .deverrouiller(b"nouveau")
            .is_err());
    }
}
