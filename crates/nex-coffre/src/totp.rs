//! TOTP (mots de passe à usage unique basés sur le temps), RFC 6238.
//!
//! Implémentation locale sur **HMAC-SHA1** (RFC 4226 pour HOTP, RFC 6238 pour
//! TOTP), validée par les vecteurs de l'annexe B de la RFC 6238.
//!
//! Note de sécurité (rappel de conception) : stocker le secret TOTP dans le
//! même coffre que le mot de passe réduit le second facteur à un facteur unique
//! en cas de compromission du coffre. C'est un compromis à exposer à
//! l'utilisateur.

use hmac::{Hmac, Mac};
use sha1::Sha1;

use crate::erreurs::ErreurCoffre;

type HmacSha1 = Hmac<Sha1>;

/// Pas de temps standard, en secondes.
pub const PAS_DEFAUT: u64 = 30;
/// Nombre de chiffres standard.
pub const CHIFFRES_DEFAUT: u32 = 6;

/// Calcule un HOTP (RFC 4226) pour un `compteur` donné.
///
/// # Erreurs
/// [`ErreurCoffre::Totp`] si la clé est invalide ou `chiffres` hors bornes (1..=9).
pub fn hotp(secret: &[u8], compteur: u64, chiffres: u32) -> Result<String, ErreurCoffre> {
    if !(1..=9).contains(&chiffres) {
        return Err(ErreurCoffre::Totp);
    }
    let mut mac = HmacSha1::new_from_slice(secret).map_err(|_| ErreurCoffre::Totp)?;
    mac.update(&compteur.to_be_bytes());
    let condensat = mac.finalize().into_bytes(); // 20 octets

    // Troncature dynamique (RFC 4226 §5.3).
    let decalage = (condensat[19] & 0x0f) as usize;
    let binaire = (u32::from(condensat[decalage] & 0x7f) << 24)
        | (u32::from(condensat[decalage + 1]) << 16)
        | (u32::from(condensat[decalage + 2]) << 8)
        | u32::from(condensat[decalage + 3]);

    let modulo = 10u64.pow(chiffres);
    let code = u64::from(binaire) % modulo;
    Ok(format!("{code:0largeur$}", largeur = chiffres as usize))
}

/// Calcule un TOTP (RFC 6238) à l'instant `temps_unix`.
///
/// # Erreurs
/// [`ErreurCoffre::Totp`] si `pas == 0`, la clé est invalide ou `chiffres` est
/// hors bornes.
pub fn totp(
    secret: &[u8],
    temps_unix: u64,
    pas: u64,
    chiffres: u32,
) -> Result<String, ErreurCoffre> {
    if pas == 0 {
        return Err(ErreurCoffre::Totp);
    }
    hotp(secret, temps_unix / pas, chiffres)
}

/// Décode un secret Base32 (RFC 4648, alphabet `A-Z2-7`), insensible à la casse,
/// en ignorant le remplissage `=` et les espaces.
///
/// # Erreurs
/// [`ErreurCoffre::Base32Invalide`] sur caractère hors alphabet.
pub fn secret_depuis_base32(entree: &str) -> Result<Vec<u8>, ErreurCoffre> {
    let mut tampon: u32 = 0;
    let mut bits: u32 = 0;
    let mut sortie = Vec::new();
    for c in entree.chars() {
        if c == '=' || c.is_whitespace() || c == '-' {
            continue;
        }
        let valeur = match c.to_ascii_uppercase() {
            l @ 'A'..='Z' => (l as u8 - b'A') as u32,
            d @ '2'..='7' => (d as u8 - b'2') as u32 + 26,
            _ => return Err(ErreurCoffre::Base32Invalide),
        };
        tampon = (tampon << 5) | valeur;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            sortie.push((tampon >> bits) as u8);
        }
    }
    Ok(sortie)
}

/// Extrait le secret Base32 d'une URI `otpauth://totp/Label?secret=…` (format
/// des QR codes d'authentification). Renvoie le secret tel quel (Base32), après
/// avoir vérifié qu'il est décodable.
///
/// # Erreurs
/// [`ErreurCoffre::Totp`] si l'URI n'est pas une URI TOTP ou ne contient pas de
/// secret ; [`ErreurCoffre::Base32Invalide`] si le secret n'est pas du Base32.
pub fn secret_base32_depuis_otpauth(uri: &str) -> Result<String, ErreurCoffre> {
    let reste = uri
        .strip_prefix("otpauth://totp/")
        .ok_or(ErreurCoffre::Totp)?;
    let requete = reste.split('?').nth(1).ok_or(ErreurCoffre::Totp)?;
    let secret = requete
        .split('&')
        .find_map(|p| p.strip_prefix("secret="))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or(ErreurCoffre::Totp)?;
    // Valide que le secret est bien du Base32 décodable.
    secret_depuis_base32(secret)?;
    Ok(secret.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Graine SHA-1 de la RFC 6238 : ASCII « 12345678901234567890 ».
    const GRAINE: &[u8] = b"12345678901234567890";

    #[test]
    fn otpauth_extrait_le_secret() {
        let uri = "otpauth://totp/Exemple:moi@exemple.fr?secret=MZXW6YTBOI&issuer=Exemple&digits=6&period=30";
        assert_eq!(secret_base32_depuis_otpauth(uri).unwrap(), "MZXW6YTBOI");
        // Le secret extrait reproduit bien « foobar » une fois décodé.
        let s = secret_base32_depuis_otpauth(uri).unwrap();
        assert_eq!(secret_depuis_base32(&s).unwrap(), b"foobar");
    }

    #[test]
    fn otpauth_secret_en_dernier_parametre() {
        let uri = "otpauth://totp/Compte?issuer=X&digits=6&secret=MZXW6YTBOI";
        assert_eq!(secret_base32_depuis_otpauth(uri).unwrap(), "MZXW6YTBOI");
    }

    #[test]
    fn otpauth_non_totp_rejete() {
        assert!(matches!(
            secret_base32_depuis_otpauth("https://exemple.fr?secret=MZXW6YTBOI"),
            Err(ErreurCoffre::Totp)
        ));
        assert!(matches!(
            secret_base32_depuis_otpauth("otpauth://totp/Compte"),
            Err(ErreurCoffre::Totp)
        ));
    }

    #[test]
    fn otpauth_secret_invalide_rejete() {
        assert!(matches!(
            secret_base32_depuis_otpauth("otpauth://totp/Compte?secret=0189!"),
            Err(ErreurCoffre::Base32Invalide)
        ));
    }

    #[test]
    fn vecteurs_officiels_rfc6238() {
        // (temps Unix, TOTP attendu) — annexe B, variante SHA-1, 8 chiffres,
        // T0 = 0, pas = 30 s.
        let cas = [
            (59u64, "94287082"),
            (1_111_111_109, "07081804"),
            (1_111_111_111, "14050471"),
            (1_234_567_890, "89005924"),
            (2_000_000_000, "69279037"),
            (20_000_000_000, "65353130"),
        ];
        for (temps, attendu) in cas {
            let code = totp(GRAINE, temps, 30, 8).unwrap();
            assert_eq!(code, attendu, "TOTP à t={temps}");
        }
    }

    #[test]
    fn chiffres_hors_bornes_rejetes() {
        assert!(matches!(hotp(GRAINE, 0, 0), Err(ErreurCoffre::Totp)));
        assert!(matches!(hotp(GRAINE, 0, 10), Err(ErreurCoffre::Totp)));
        assert!(matches!(totp(GRAINE, 0, 0, 6), Err(ErreurCoffre::Totp)));
    }

    #[test]
    fn base32_decode_foobar() {
        // RFC 4648 : BASE32("foobar") = "MZXW6YTBOI======".
        assert_eq!(secret_depuis_base32("MZXW6YTBOI").unwrap(), b"foobar");
        assert_eq!(secret_depuis_base32("mzxw6ytboi").unwrap(), b"foobar");
        assert_eq!(secret_depuis_base32("MZXW 6YTB OI==").unwrap(), b"foobar");
    }

    #[test]
    fn base32_invalide_rejete() {
        assert!(matches!(
            secret_depuis_base32("0189!"),
            Err(ErreurCoffre::Base32Invalide)
        ));
    }

    #[test]
    fn base32_puis_totp() {
        // La graine RFC encodée en Base32 doit reproduire le même TOTP.
        let b32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let secret = secret_depuis_base32(b32).unwrap();
        assert_eq!(secret, GRAINE);
        assert_eq!(totp(&secret, 59, 30, 8).unwrap(), "94287082");
    }
}
