//! Notifications natives.
//!
//! Sur Windows, on affiche une vraie notification « toast » via le moteur
//! `Windows.UI.Notifications`, piloté par un court script PowerShell. Ce choix
//! évite d'ajouter la lourde pile `windows-rs` au binaire (objectif : rester
//! léger) tout en produisant une notification système authentique.
//!
//! Le titre et le message sont passés par variables d'environnement, jamais
//! interpolés dans le script : aucune injection possible.

/// Script PowerShell qui émet un toast en lisant `$env:NX_TITRE` / `$env:NX_MSG`.
/// On réutilise l'AppUserModelID de PowerShell pour que le toast s'affiche même
/// sans enregistrement préalable (cas du binaire portable).
#[cfg(windows)]
const SCRIPT_TOAST: &str = r#"
$ErrorActionPreference = 'SilentlyContinue'
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom, ContentType = WindowsRuntime] | Out-Null
$modele = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
$textes = $modele.GetElementsByTagName('text')
[void]$textes.Item(0).AppendChild($modele.CreateTextNode($env:NX_TITRE))
[void]$textes.Item(1).AppendChild($modele.CreateTextNode($env:NX_MSG))
$toast = [Windows.UI.Notifications.ToastNotification]::new($modele)
$aumid = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($aumid).Show($toast)
"#;

/// Affiche une notification système. « Au mieux » : toute erreur (PowerShell
/// absent, toasts désactivés…) est silencieusement ignorée — une notification
/// ratée ne doit jamais interrompre le programme.
pub fn notifier(titre: &str, message: &str) {
    #[cfg(windows)]
    {
        let _ = std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-WindowStyle",
                "Hidden",
                "-Command",
                SCRIPT_TOAST,
            ])
            .env("NX_TITRE", titre)
            .env("NX_MSG", message)
            .spawn();
    }
    #[cfg(not(windows))]
    {
        // Pas de toast hors Windows : on évite d'imposer libnotify/D-Bus.
        let _ = (titre, message);
    }
}
