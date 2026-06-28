; Script Inno Setup pour nexkeylock — produit un setup.exe installable.
; Compilation : "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" packaging\installateur.iss
;
; nexkeylock est un outil en ligne de commande : l'installateur propose donc
; d'ajouter le dossier d'installation au PATH machine (option cochée par défaut).

#define MonNom "nexkeylock"
#define MaVersion "0.1.0"
#define MonEditeur "Équipe nexkeylock"
#define MonExe "nexkeylock.exe"

[Setup]
AppId={{B7E4B2A1-9C3D-4F6E-A1B2-3C4D5E6F7A80}
AppName={#MonNom}
AppVersion={#MaVersion}
AppVerName={#MonNom} {#MaVersion}
AppPublisher={#MonEditeur}
DefaultDirName={autopf}\{#MonNom}
DefaultGroupName={#MonNom}
DisableProgramGroupPage=yes
LicenseFile=LICENSE.txt
InfoBeforeFile=AVANT-INSTALLATION.txt
OutputDir=..\dist
OutputBaseFilename=nexkeylock-{#MaVersion}-installateur
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
; Installe pour toutes les sessions (Program Files) → requiert l'élévation.
PrivilegesRequired=admin
ChangesEnvironment=yes
UninstallDisplayName={#MonNom} {#MaVersion}

[Languages]
Name: "francais"; MessagesFile: "compiler:Languages\French.isl"

[Tasks]
Name: "ajouterpath"; Description: "Ajouter {#MonNom} au PATH (recommandé pour un outil en ligne de commande)"; GroupDescription: "Intégration au système :"

[Files]
Source: "..\target\release\{#MonExe}"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\README.md"; DestDir: "{app}"; DestName: "README.md"; Flags: ignoreversion
Source: "..\SECURITY.md"; DestDir: "{app}"; DestName: "SECURITY.md"; Flags: ignoreversion
Source: "LICENSE.txt"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
; Raccourci qui ouvre un terminal positionné sur le dossier d'installation.
Name: "{group}\Terminal {#MonNom}"; Filename: "{cmd}"; Parameters: "/k echo nexkeylock — tapez : nexkeylock --help & cd /d ""{app}"""; WorkingDir: "{app}"
Name: "{group}\Désinstaller {#MonNom}"; Filename: "{uninstallexe}"

[Run]
Filename: "{cmd}"; Parameters: "/k ""{app}\{#MonExe}"" --help"; Description: "Lancer {#MonNom} --help maintenant"; Flags: postinstall skipifsilent

[Code]
const
  CleEnv = 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment';

function PathContientDossier(const Path, Dossier: string): Boolean;
var
  PathLower, DossierLower: string;
begin
  PathLower := ';' + Lowercase(Path) + ';';
  DossierLower := ';' + Lowercase(Dossier) + ';';
  Result := Pos(DossierLower, PathLower) > 0;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  PathActuel: string;
  Dossier: string;
begin
  if CurStep = ssPostInstall then
  begin
    if WizardIsTaskSelected('ajouterpath') then
    begin
      Dossier := ExpandConstant('{app}');
      if not RegQueryStringValue(HKEY_LOCAL_MACHINE, CleEnv, 'Path', PathActuel) then
        PathActuel := '';
      if not PathContientDossier(PathActuel, Dossier) then
      begin
        if (PathActuel <> '') and (Copy(PathActuel, Length(PathActuel), 1) <> ';') then
          PathActuel := PathActuel + ';';
        PathActuel := PathActuel + Dossier;
        RegWriteExpandStringValue(HKEY_LOCAL_MACHINE, CleEnv, 'Path', PathActuel);
      end;
    end;
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  PathActuel: string;
  Dossier, PathLower, DossierLower: string;
  P: Integer;
begin
  if CurUninstallStep = usUninstall then
  begin
    Dossier := ExpandConstant('{app}');
    if RegQueryStringValue(HKEY_LOCAL_MACHINE, CleEnv, 'Path', PathActuel) then
    begin
      PathLower := ';' + Lowercase(PathActuel) + ';';
      DossierLower := ';' + Lowercase(Dossier) + ';';
      P := Pos(DossierLower, PathLower);
      if P > 0 then
      begin
        // Retire le segment correspondant (longueur du dossier + un séparateur).
        Delete(PathActuel, P, Length(Dossier) + 1);
        RegWriteExpandStringValue(HKEY_LOCAL_MACHINE, CleEnv, 'Path', PathActuel);
      end;
    end;
  end;
end;
