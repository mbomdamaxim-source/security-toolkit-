; ============================================================================
;  Bastion - Inno Setup installer script
;
;  Build the installer on Windows after building the executable:
;
;      .\build.ps1 -Test -Installer
;
;  Requires Inno Setup 6 (free): https://jrsoftware.org/isdl.php
;  The script expects dist\Bastion.exe and assets\bastion.ico to exist.
;  Output: installer\Bastion-Setup-0.1.0.exe
; ============================================================================

#define AppName        "Bastion"
#define AppVersion     "0.1.0"
#define AppPublisher   "Bastion Project"
#define AppURL         "https://github.com/mbomdamaxim-source/security-toolkit-"
#define AppExeName     "Bastion.exe"
#define AppTagline     "Learn your system. Secure your system."

[Setup]
AppId={{B6ED4EE4-0A87-4A8B-B537-D7FE2189D367}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}
AppComments={#AppTagline}
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
LicenseFile=..\README.md
OutputDir=..\installer
OutputBaseFilename={#AppName}-Setup-{#AppVersion}
SetupIconFile=..\assets\bastion.ico
UninstallDisplayIcon={app}\{#AppExeName}
UninstallDisplayName={#AppName}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
; per-machine install needs admin; per-user does not (choose at run time)
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
DisableWelcomePage=no
MinVersion=10.0

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "french"; MessagesFile: "compiler:Languages\French.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: unchecked

[Files]
Source: "..\dist\{#AppExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\assets\bastion.ico"; DestDir: "{app}\assets"; Flags: ignoreversion
Source: "..\packaging\verify_windows_modules.py"; DestDir: "{app}\packaging"; Flags: ignoreversion

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExeName}"; Comment: "{#AppTagline}"
Name: "{group}\Uninstall {#AppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExeName}"; Tasks: desktopicon

[Run]
; Optional first run - the app starts unelevated by design.
Filename: "{app}\{#AppExeName}"; Description: "Launch {#AppName}"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
; Bastion keeps only summaries in %LOCALAPPDATA%; remove them on uninstall so no
; stale state survives a reinstall. Application data only - nothing else.
Type: filesandordirs; Name: "{localappdata}\Bastion"

[Messages]
WelcomeLabel2=This will install {#AppName} {#AppVersion} on your computer.%n%n{#AppName} is a local, educational security toolkit: {#AppTagline} It inspects this device only and never uploads your data.
