; Argus installer — Inno Setup 6 script.
; Build: ISCC.exe packaging\installer.iss   (run from the project root)

[Setup]
AppId={{5A0E1B2C-ARGU-5H00-D000-000000000001}
AppName=Argus
AppVersion=0.1.0
AppPublisher=Serge
DefaultDirName={autopf}\Argus
DefaultGroupName=Argus
UninstallDisplayIcon={app}\Argus.exe
OutputDir=..\dist\installer
OutputBaseFilename=Argus-Setup
SetupIconFile=..\dashboard\icon.ico
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin

[Files]
Source: "..\dist\Argus.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\Argus Command Center"; Filename: "{app}\Argus.exe"; Parameters: "--serve"
Name: "{autodesktop}\Argus Command Center"; Filename: "{app}\Argus.exe"; Parameters: "--serve"

[Run]
Filename: "{app}\Argus.exe"; Parameters: "--serve"; Description: "Launch the Argus Command Center"; Flags: nowait postinstall skipifsilent
