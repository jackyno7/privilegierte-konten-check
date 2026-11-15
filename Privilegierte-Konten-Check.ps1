<#
.SYNOPSIS
    Privilegierte-Konten-Check (free): shows who has administrator rights in an Active Directory and checks
    these accounts on 7 points (count, inactivity, password age, password expiry, mailbox, protection, effective
    password policy). The result is an HTML report in German.

    The full version "AD-Prüfbericht" additionally checks, among other things, disabled accounts in privileged groups,
    nested groups, service accounts with admin rights, Kerberoasting targets, krbtgt age and other points:
    https://www.etsy.com/shop/ITAdminToolsbyMM

    Deutsch:
    Privilegierte-Konten-Check (kostenlos): zeigt, wer in einem Active Directory Administratorrechte hat, und prüft
    diese Konten in 7 Punkten (Anzahl, Inaktivität, Kennwortalter, Kennwortablauf, Postfach, Schutz, wirksame
    Kennwortrichtlinie). Ergebnis ist ein HTML-Bericht auf Deutsch.

    Die Vollversion "AD-Prüfbericht" prüft darüber hinaus u. a. deaktivierte Konten in privilegierten Gruppen,
    verschachtelte Gruppen, Dienstkonten mit Adminrechten, Kerberoasting-Ziele, krbtgt-Alter und weitere Punkte:
    https://www.etsy.com/shop/ITAdminToolsbyMM

.DESCRIPTION
    The script works exclusively READ-ONLY. It changes nothing in Active Directory, creates nothing, deletes nothing and
    transfers no data. It writes exactly one HTML file (and optionally CSV files) to the specified
    output folder. Members (also via nested groups) of Domain Admins, Organization Management, Schema Admins, Administrators, Account Operators, Server Operators and Backup Operators are considered privileged.
    The groups are found by their fixed identifiers (SIDs), so the script works in any Windows language.

    Prerequisites: Windows PowerShell 5.1, the "ActiveDirectory" module (present on domain controllers, otherwise RSAT
    "Active Directory Domain Services und Lightweight Directory Services-Tools") and a domain account with read permissions.
    Administrator rights are not required. Without read permission on the password policies (Password Settings
    Container), point P7 for accounts with their own policy appears as "not checked".

    Limitations: The built-in accounts Guest, krbtgt and DefaultAccount are never listed, even if they are in a
    privileged group. Accounts whose password must be changed at the next logon do not appear
    under P3. Only the domain of the computer or the specified server is read; members from other
    domains of the forest are not captured. The finding (group) names the top-level privileged group,
    not the nesting path.

    Deutsch:
    Das Skript arbeitet ausschließlich LESEND. Es ändert nichts im Active Directory, legt nichts an, löscht nichts und
    überträgt keine Daten. Es schreibt genau eine HTML-Datei (auf Wunsch zusätzlich CSV-Dateien) in den angegebenen
    Ausgabeordner. Als privilegiert gelten Mitglieder (auch über verschachtelte Gruppen) von Domänen-Admins,
    Organisations-Admins, Schema-Admins, Administratoren, Konten-Operatoren, Server-Operatoren und Sicherungs-Operatoren.
    Die Gruppen werden über ihre festen Kennungen (SID) gefunden, das Skript arbeitet deshalb in jeder Windows-Sprache.

    Voraussetzungen: Windows PowerShell 5.1, das Modul "ActiveDirectory" (auf Domänencontrollern vorhanden, sonst RSAT
    "Active Directory Domain Services und Lightweight Directory Services-Tools") und ein Domänenkonto mit Leserechten.
    Administratorrechte sind nicht erforderlich. Ohne Leserecht auf die Kennwortrichtlinien (Password Settings
    Container) erscheint der Punkt P7 für Konten mit eigener Richtlinie als "nicht geprüft".

    Grenzen: Die eingebauten Konten Gast, krbtgt und DefaultAccount werden nie aufgeführt, auch wenn sie in einer
    privilegierten Gruppe stehen. Konten, deren Kennwort bei der nächsten Anmeldung geändert werden muss, erscheinen
    nicht unter P3. Es wird nur die Domäne des Computers bzw. des angegebenen Servers gelesen; Mitglieder aus anderen
    Domänen der Gesamtstruktur werden nicht erfasst. Die Fundstelle (Gruppe) nennt die oberste privilegierte Gruppe,
    nicht den Verschachtelungspfad.

.PARAMETER Ausgabe
    Path of the HTML file. Default: Privilegierte-Konten-Check_<Domäne>_<Datum>.html in the current folder.

    Deutsch:
    Pfad der HTML-Datei. Standard: Privilegierte-Konten-Check_<Domäne>_<Datum>.html im aktuellen Ordner.

.PARAMETER MaxAdmins
    From how many privileged accounts the count is considered suspicious (default 5).

    Deutsch:
    Ab wie vielen privilegierten Konten die Anzahl als auffällig gilt (Standard 5).

.PARAMETER InaktivTage
    Privileged accounts that have not logged on for more than this number of days are reported (default 90).

    Deutsch:
    Privilegierte Konten ohne Anmeldung seit so vielen Tagen werden gemeldet (Standard 90).

.PARAMETER KennwortAlterTage
    Privileged accounts whose password is older than this number of days are reported (default 365).

    Deutsch:
    Privilegierte Konten, deren Kennwort älter ist, werden gemeldet (Standard 365).

.PARAMETER MindestLaenge
    Minimum length of the effective password policy for privileged accounts (default 12 characters).

    Deutsch:
    Mindestlänge der wirksamen Kennwortrichtlinie für privilegierte Konten (Standard 12 Zeichen).

.PARAMETER Server
    Specific domain controller or domain (optional).

    Deutsch:
    Bestimmter Domänencontroller oder Domäne (optional).

.PARAMETER Anmeldung
    Credentials for a domain account (Get-Credential), if the script does not run as a domain user, e.g. from a
    computer outside the domain. Then also specify -Server.

    Deutsch:
    Anmeldedaten eines Domänenkontos (Get-Credential), falls das Skript nicht als Domänenbenutzer läuft, z. B. von einem
    Rechner außerhalb der Domäne. Dann zusätzlich -Server angeben.

.PARAMETER Csv
    Additionally writes a CSV alongside the report for each checkpoint with hits and for the list of privileged accounts.

    Deutsch:
    Schreibt zusätzlich je Prüfpunkt mit Treffern und die Liste der privilegierten Konten als CSV neben den Bericht.

.PARAMETER NichtOeffnen
    Does not automatically open the completed report in the browser.

    Deutsch:
    Öffnet den fertigen Bericht nicht automatisch im Browser.

.PARAMETER PassThru
    Additionally returns the findings as objects (for your own analysis).

    Deutsch:
    Gibt die Befunde zusätzlich als Objekte zurück (für eigene Auswertungen).

.PARAMETER Language
    Language of the report and the console output: 'de' (German) or 'en' (English). Default: German if the Windows display language
    is German, otherwise English.

    Deutsch:
    Sprache von Bericht und Konsolenausgabe: 'de' (Deutsch) oder 'en' (Englisch). Standard: Deutsch, wenn die Anzeigesprache von
    Windows Deutsch ist, sonst Englisch.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Privilegierte-Konten-Check.ps1

.EXAMPLE
    .\Privilegierte-Konten-Check.ps1 -InaktivTage 60 -Csv -Ausgabe C:\Berichte\admins.html

.NOTES
    IT Admin Tools by MM - Privilegierte-Konten-Check Version 1.0 (11.2026), Lizenz: MIT (siehe LICENSE)
    Kein Ersatz für eine Sicherheitsprüfung. Nutzung auf eigene Verantwortung.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateSet('de', 'en')][string]$Language = $(if ((Get-UICulture).TwoLetterISOLanguageName -eq 'de') { 'de' } else { 'en' }),
    [Alias('Output')][string]$Ausgabe,
    [ValidateRange(1, 1000)][int]$MaxAdmins = 5,
    [ValidateRange(1, 3650)][int]$InaktivTage = 90,
    [ValidateRange(1, 3650)][int]$KennwortAlterTage = 365,
    [ValidateRange(1, 64)][int]$MindestLaenge = 12,
    [string]$Server,
    [Alias('Credential')][System.Management.Automation.PSCredential]$Anmeldung,
    [switch]$Csv,
    [Alias('NoOpen')][switch]$NichtOeffnen,
    [switch]$PassThru
)
# Sprache des Berichts: de oder en (Parameter -Language). T 'deutsch' 'english' liefert den Text der gewählten Sprache.
$En = ($Language -eq 'en')
function T([string]$de, [string]$en) { if ($script:En) { $en } else { $de } }

$ErrorActionPreference = 'Stop'
$Version = '1.1'

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Host (T 'Das PowerShell-Modul "ActiveDirectory" fehlt.' 'The PowerShell module "ActiveDirectory" is missing.') -ForegroundColor Red
    Write-Host (T 'Windows 10/11: Einstellungen > Optionale Features > "RSAT: Active Directory Domain Services" hinzufügen.' 'Windows 10/11: Settings > Optional features > add "RSAT: Active Directory Domain Services".')
    Write-Host 'Windows Server:  Install-WindowsFeature RSAT-AD-PowerShell'
    exit 2
}
Import-Module ActiveDirectory

$ad = @{}
if ($Server) { $ad.Server = $Server }
if ($Anmeldung) { $ad.Credential = $Anmeldung }

#@SPRACHE@
# ------------------------------------------------------------------ Hilfsfunktionen
function Datum($d, $leer = $null) { if ($null -eq $leer) { $leer = T 'nie' 'never' }; if ($d) { ([datetime]$d).ToString((T 'dd.MM.yyyy' 'yyyy-MM-dd')) } else { $leer } }
function JaNein($b) { if ($b) { T 'Ja' 'Yes' } else { T 'Nein' 'No' } }
function Ort($dn) { ($dn -replace '^(CN|OU)=.+?(?<!\\),', '') -replace ',DC=.*$', '' }
function Html($t) { [System.Net.WebUtility]::HtmlEncode([string]$t) }
function Kurz($t, $n = 220) { $t = ([string]$t -replace '\s+', ' ').Trim(); if ($t.Length -gt $n) { $t.Substring(0, $n) + ' ...' } else { $t } }

# CSV-Dateien öffnen sich in Excel: Werte, die mit = + - @ beginnen, würden dort als Formel ausgeführt (Namen von Dateien, Ordnern, Konten oder Computern
# stammen von Benutzern). Diese Funktion ersetzt für dieses Skript den Befehl Export-Csv und setzt vor solche Werte ein Hochkomma.
function Export-Csv {
    [CmdletBinding()]
    param([Parameter(ValueFromPipeline = $true)]$InputObject, [Parameter(Mandatory)][string]$Path, [switch]$NoTypeInformation, [string]$Delimiter = ';', [string]$Encoding = 'UTF8')
    begin { $alle = New-Object System.Collections.Generic.List[object] }
    process { if ($null -ne $InputObject) { $alle.Add($InputObject) } }
    end {
        $sicher = foreach ($o in $alle) {
            $n = [ordered]@{}
            foreach ($p in $o.PSObject.Properties) { $v = $p.Value; if (($v -is [string]) -and ($v -match '^[=+@\t\r]|^-.')) { $v = "'" + $v }; $n[$p.Name] = $v }
            [pscustomobject]$n
        }
        if ($alle.Count) { $sicher | Microsoft.PowerShell.Utility\Export-Csv -Path $Path -NoTypeInformation:$NoTypeInformation -Delimiter $Delimiter -Encoding $Encoding }   # leere Liste: keine Datei (sie hätte keine Kopfzeile)
    }
}

# Tabellen: ConvertTo-Html und Export-Csv nehmen die Spalten des ersten Objekts. Haben die Zeilen einer Liste verschiedene
# Eigenschaften (z. B. Fehlzeile neben normalen Treffern), gingen Spalten verloren: alle Namen der Reihe nach vereinigen.
function Einheitlich($liste) {
    $liste = @($liste | Where-Object { $null -ne $_ })
    if ($liste.Count -ge 2) {
        $namen = New-Object System.Collections.Generic.List[string]
        foreach ($o in $liste) { foreach ($p in $o.PSObject.Properties.Name) { if (-not $namen.Contains($p)) { $namen.Add($p) } } }
        if ($namen.Count -ne @($liste[0].PSObject.Properties.Name).Count) { $liste = @($liste | Select-Object -Property $namen) }
    }
    SpaltenAnzeige $liste
}
# Englische Berichte: Spaltenüberschriften aus der Übersetzungstabelle (intern bleiben die deutschen Namen, der Code liest sie weiter)
$SpaltenEn = @{
    'Abfrage' = 'Query'
    'Administrator' = 'Administrator'
    'Adresse' = 'Address'
    'Aktiv' = 'Active'
    'Aktiv verknüpft mit' = 'Active linked to'
    'Aktive Verknüpfungen' = 'Active links'
    'Alter in Tagen' = 'Age in days'
    'Angelegt' = 'Created'
    'Anmeldung' = 'Last logon'
    'Anmeldungen' = 'Logons'
    'Anteil (%)' = 'Share (%)'
    'Anzahl' = 'Count'
    'Art' = 'Account type'
    'Auf Domänencontroller' = 'On domain controller'
    'Aufräumen' = 'Cleanup'
    'Auslastung' = 'Utilization'
    'Auslösender Rechner' = 'Triggering computer'
    'Auslösender Rechner (Anzahl)' = 'Triggering computers (count)'
    'Aussteller' = 'Issuer'
    'Beispiele' = 'Examples'
    'Belegt' = 'Used'
    'Belegt (%)' = 'Used (%)'
    'Benutzer und Computer (auch verschachtelt)' = 'Users and computers (also nested)'
    'Benutzereinstellungen' = 'User settings'
    'Benutzername' = 'Username'
    'Berechtigter' = 'Principal'
    'Bereich' = 'Scope'
    'Bereiche' = 'Scopes'
    'Beschreibung' = 'Description'
    'Besitzer' = 'Owner'
    'Betriebssystem' = 'OS'
    'Betroffene Konten' = 'Affected accounts'
    'Bewertung' = 'Rating'
    'Bis' = 'To'
    'BitLocker' = 'BitLocker'
    'Computer' = 'Computer'
    'Computereinstellungen' = 'Computer settings'
    'Darf anwenden' = 'Can apply'
    'Darf delegieren an' = 'Can delegate to'
    'Darf sich hier als Benutzer ausgeben' = 'Can log on as user'
    'Datei' = 'File'
    'Dateien' = 'Files'
    'Dateisystem' = 'File system'
    'Dateityp' = 'File type'
    'Datenbank' = 'Database'
    'Detail' = 'Detail'
    'Details' = 'Details'
    'Direkte Mitglieder' = 'Direct members'
    'Domäne' = 'Domain'
    'Domänencontroller' = 'Domain controller'
    'Domänennamenmaster' = 'Domain naming master'
    'Dynamische Updates' = 'Dynamic updates'
    'E-Mail' = 'Email'
    'Eigenschaft' = 'Property'
    'Einstellung' = 'Setting'
    'Empfohlen' = 'Recommended'
    'Enthaltene Gruppen' = 'Included groups'
    'Ereignisse' = 'Events'
    'Erreichbar' = 'Reachable'
    'Erste' = 'First'
    'Erster' = 'First'
    'Erzwungen' = 'Forced'
    'Failover' = 'Failover'
    'Falsches Kennwort' = 'Wrong password'
    'Fehlanmeldungen am DC' = 'Failed logons at DC'
    'Fehlversuche' = 'Failed attempts'
    'Feststellung' = 'Finding'
    'Fingerabdruck' = 'Fingerprint'
    'Firewall' = 'Firewall'
    'Frei' = 'Free'
    'Freigabe' = 'Share'
    'Freigaberecht' = 'Share permission'
    'Funktion' = 'Function'
    'Gelesen von' = 'Read by'
    'Geprüft' = 'Checked'
    'Gesamtgröße' = 'Total size'
    'Geschützte Benutzer' = 'Protected users'
    'Gesperrt seit' = 'Locked since'
    'Geändert' = 'Changed'
    'Gilt' = 'Applies to'
    'Gilt für' = 'Applies to'
    'Globaler Katalog' = 'Global catalog'
    'Grenze' = 'Limit'
    'Groesse' = 'Size'
    'Grund' = 'Reason'
    'Gruppe' = 'Group'
    'Gruppen' = 'Groups'
    'Gruppen (auch verschachtelt)' = 'Groups (including nested)'
    'Gruppenrichtlinie' = 'Group policy'
    'Größe' = 'Size'
    'Größe (GB)' = 'Size (GB)'
    'Gültig ab' = 'Valid from'
    'Gültig bis' = 'Valid to'
    'Herkunft' = 'Origin'
    'Hersteller' = 'Vendor'
    'Hinweis' = 'Note'
    'Häufigster Grund' = 'Most common reason'
    'IP-Adresse' = 'IP address'
    'Im AD gespeichert' = 'Stored in AD'
    'In der Domäne vorhanden' = 'Present in domain'
    'Infrastrukturmaster' = 'Infrastructure master'
    'Inhalt' = 'Content'
    'Ist' = 'Is'
    'Kennung' = 'ID'
    'Kennwort gesetzt' = 'Password set'
    'Kennwort läuft nie ab' = 'Password never expires'
    'Kerberos' = 'Kerberos'
    'Konten' = 'Accounts'
    'Konten (auch verschachtelt)' = 'Accounts (also nested)'
    'Konto' = 'Account'
    'Konto für DNS-Einträge' = 'Account for DNS entries'
    'Kopie bleibt im Postfach' = 'Copy remains in mailbox'
    'LAPS' = 'LAPS'
    'LAPS-Ablauf' = 'LAPS expiry'
    'Laufwerk' = 'Drive'
    'Lease-Dauer' = 'Lease duration'
    'Leitet weiter an' = 'Forwards to'
    'Leseweg' = 'Read path'
    'Letzte Aktualisierung' = 'Last update'
    'Letzte Anmeldung' = 'Last logon'
    'Letzte Vollsicherung' = 'Last full backup'
    'Letzte inkrementelle Sicherung' = 'Last incremental backup'
    'Letzter' = 'Last'
    'Letzter Aufräumlauf' = 'Last cleanup run'
    'Letzter Start' = 'Last start'
    'Lokale Admins' = 'Local admins'
    'Mindestlänge' = 'Minimum length'
    'Mitglied' = 'Member'
    'Mitglieder' = 'Members'
    'NLA' = 'NLA'
    'NTLM' = 'NTLM'
    'Name' = 'Name'
    'Nr.' = 'No.'
    'Objekt' = 'Object'
    'Ordner' = 'Folder'
    'Organisationseinheit' = 'OU'
    'Ort' = 'Location'
    'PDC-Emulator' = 'PDC emulator'
    'Pfad' = 'Path'
    'Postfach' = 'Mailbox'
    'Postfach-Typ' = 'Mailbox type'
    'Postfachtyp' = 'Mailbox type'
    'Postfächer' = 'Mailboxes'
    'Privilegierte Gruppen' = 'Privileged groups'
    'Programm' = 'Program'
    'Prüfpunkt' = 'Checkpoint'
    'Quelle' = 'Source'
    'Quelle (Anzahl)' = 'Sources (count)'
    'RID-Master' = 'RID master'
    'Recht' = 'Permission'
    'Rechte' = 'Permissions'
    'Regel' = 'Rule'
    'Reihenfolge' = 'Order'
    'SPN' = 'SPN'
    'Schemamaster' = 'Schema master'
    'Schlüssel' = 'Key'
    'Schreibgeschützt' = 'Read-only'
    'Sendesperre ab' = 'Send blocked from'
    'Server' = 'Server'
    'Sid' = 'SID'
    'Signatur' = 'Signature'
    'Speicher' = 'Storage'
    'Sperrungen' = 'Lockouts'
    'Stand' = 'Status'
    'Standort' = 'Site'
    'Status' = 'Status'
    'Support-Ende' = 'End of support'
    'Support-Ende (spätestes)' = 'End of support (latest)'
    'Tage bis Ablauf' = 'Days until expiry'
    'Tage her' = 'Days ago'
    'Tage ohne Anmeldung' = 'Days without logon'
    'Tage seit Ablauf' = 'Days since expiry'
    'Treffer' = 'Hits'
    'Typ' = 'Type'
    'Vererbung' = 'Inheritance'
    'Verschiedene Konten' = 'Distinct accounts'
    'Verschlüsselt' = 'Encrypted'
    'Version' = 'Version'
    'Version C/B' = 'Version C/B'
    'Verweigert für' = 'Denied for'
    'Verwendung' = 'Use'
    'Virenschutz' = 'Antivirus'
    'Von' = 'From'
    'WMI-Filter' = 'WMI filter'
    'Weg' = 'Path'
    'Weiterleitungen' = 'Forwarding'
    'Wert' = 'Value'
    'Wirksame Richtlinie' = 'Effective policy'
    'Wirksames Recht' = 'Effective permission'
    'Wirkung' = 'Effect'
    'Zeit' = 'Time'
    'Zeitpunkt' = 'Time'
    'Zeitraum' = 'Period'
    'Zertifikat' = 'Certificate'
    'Zone' = 'Zone'
    'Zonen' = 'Zones'
    'Zonenübertragung' = 'Zone transfer'
    'Zugriff für große Gruppen' = 'Access for large groups'
    'Zugriffsbasierte Aufzählung' = 'Access-based enumeration'
    'Zuletzt' = 'Last'
    'Zustand' = 'State'
    'davon Größe (GB)' = 'Of which size (GB)'
    'davon aktiv' = 'Of which active'
    'davon inaktiv' = 'Of which inactive'
    'davon unbekannte Konten' = 'Of which unknown accounts'
    'ist Mitglied von' = 'Member of'
    'Älter als 5 Jahre' = 'Older than 5 years'
    'Älter als 5 Jahren' = 'Older than 5 years'
    'Ältester Eintrag' = 'Oldest entry'
    'Über' = 'Via'
    'Überwachungsprotokoll' = 'Audit log'
}
# Werte, die der Code intern auf Deutsch vergleicht (z. B. Art = 'Benutzer'), erscheinen im englischen Bericht übersetzt (nur Anzeige und CSV)
$WerteEn = New-Object System.Collections.Specialized.OrderedDictionary([System.StringComparer]::Ordinal)   # Groß-/Kleinschreibung zählt (Verwaist / verwaist)
$WerteEn.Add('Alle erweiterten Rechte (u. a. Kennwort zurücksetzen)', 'All extended rights (including password reset)')
$WerteEn.Add('Kein Serverbetriebssystem (Support nicht bewertet)', 'No server operating system (support not assessed)')
$WerteEn.Add('Rechte je Ordner (nur dort, wo sie gesetzt werden)', 'Permissions per folder (only where set)')
$WerteEn.Add('Mehrfach freigegebene Ordner (nur einmal gezählt)', 'Folders shared multiple times (counted only once)')
$WerteEn.Add('Übersprungene Verknüpfungen (Junctions/Symlinks)', 'Skipped links (Junctions/Symlinks)')
$WerteEn.Add('Der Ordner der Freigabe existiert nicht mehr.', 'The share folder no longer exists.')
$WerteEn.Add('DHCP-Überwachungsprotokoll ist ausgeschaltet', 'DHCP audit log is disabled')
$WerteEn.Add('Vollzugriff und "Senden als" im Überblick', 'Full access and "Send as" overview')
$WerteEn.Add('Ordner der Freigabe existiert nicht mehr', 'Share folder no longer exists')
$WerteEn.Add('Enthält außer Sicherheitseinstellungen:', 'Contains except security settings:')
$WerteEn.Add('Nicht geprüft - Postfach nicht gefunden', 'Not checked - mailbox not found')
$WerteEn.Add('WMI-Filter nicht lesbar - nicht geprüft', 'WMI filter not readable - not checked')
$WerteEn.Add('Abfrage fehlgeschlagen - nicht geprüft', 'Query failed - not checked')
$WerteEn.Add('Nicht im Active Directory gespeichert', 'Not stored in Active Directory')
$WerteEn.Add('keine im Active Directory autorisiert', 'None authorized in Active Directory')
$WerteEn.Add('Zugriff auf den Ordner nicht möglich', 'Access to folder not possible')
$WerteEn.Add('Zertifikate (öffentliche Schlüssel)', 'Certificates (public keys)')
$WerteEn.Add('Domänencontroller der Organisation', 'Organization domain controllers')
$WerteEn.Add('Remotedesktop erlaubt Verbindungen', 'Remote Desktop allows connections')
$WerteEn.Add('autorisierte DHCP-Server ermitteln', 'Determine authorized DHCP servers')
$WerteEn.Add('Windows Server 2008 R2 und älter', 'Windows Server 2008 R2 and older')
$WerteEn.Add('Konto deaktiviert oder gesperrt', 'Account disabled or locked')
$WerteEn.Add('Vollzugriff (Zusatz: ObjectType', 'Full access (additional: ObjectType')
$WerteEn.Add('Kennwort oder Konto abgelaufen', 'Password or account expired')
$WerteEn.Add('Lokale Administratorengruppen', 'Local administrator groups')
$WerteEn.Add('Berechtigungen/Besitz ändern', 'Change permissions/ownership')
$WerteEn.Add('Freigabepfade nicht sichtbar', 'Share paths not visible')
$WerteEn.Add('Aktive privilegierte Konten', 'Active privileged accounts')
$WerteEn.Add('Gruppe hat keine Mitglieder', 'Group has no members')
$WerteEn.Add('Keine Verbindung zum Server', 'No connection to server')
$WerteEn.Add('unerlaubte Zeichen im Namen', 'Illegal characters in name')
$WerteEn.Add('Geprüfte Domänencontroller', 'Checked domain controllers')
$WerteEn.Add('Authentifizierte Benutzer', 'Authenticated Users')
$WerteEn.Add('Schwellen dieses Berichts', 'Thresholds of this report')
$WerteEn.Add('Benutzer (inetOrgPerson)', 'User (inetOrgPerson)')
$WerteEn.Add('Datenbestand je Freigabe', 'Data inventory per share')
$WerteEn.Add('Kontosperrungsrichtlinie', 'Account lockout policy')
$WerteEn.Add('Sicherheitseinstellungen', 'Security settings')
$WerteEn.Add('Alle erweiterten Rechte', 'All extended rights')
$WerteEn.Add('Hinweise zur Auswertung', 'Notes for evaluation')
$WerteEn.Add('Nicht abgefragte Server', 'Servers not queried')
$WerteEn.Add('Unterordner und Dateien', 'Subfolders and files')
$WerteEn.Add('Bestätigtes Schreiben:', 'Validated write:')
$WerteEn.Add('Installierte Programme', 'Installed programs')
$WerteEn.Add('Konto für DNS-Einträge', 'Account for DNS records')
$WerteEn.Add('Kontosperrungsschwelle', 'Account lockout threshold')
$WerteEn.Add('Nicht lesbare Bereiche', 'Unreadable areas')
$WerteEn.Add('Berechtigungen ändern', 'Change permissions')
$WerteEn.Add('Hinweise zum Auslesen', 'Notes for reading')
$WerteEn.Add('Windows 8.1 und älter', 'Windows 8.1 and older')
$WerteEn.Add('Überwachungsprotokoll', 'Audit log')
$WerteEn.Add('Nicht berücksichtigt', 'Not considered')
$WerteEn.Add('Anonymous-Anmeldung', 'Anonymous logon')
$WerteEn.Add('Infrastrukturmaster', 'Infrastructure master')
$WerteEn.Add('Secure Boot ist aus', 'Secure Boot is off')
$WerteEn.Add('Domänennamenmaster', 'Domain naming master')
$WerteEn.Add('Kennwortrichtlinie', 'Password policy')
$WerteEn.Add('Komponentenwartung', 'Component servicing')
$WerteEn.Add('alle Eigenschaften', 'all properties')
$WerteEn.Add('Besitz übernehmen', 'Take ownership')
$WerteEn.Add('Domänencontroller', 'Domain Controllers')
$WerteEn.Add('Falsches Kennwort', 'Incorrect password')
$WerteEn.Add('Konten-Operatoren', 'Account Operators')
$WerteEn.Add('Nur dieser Ordner', 'Only this folder')
$WerteEn.Add('Domänen-Benutzer', 'Domain Users')
$WerteEn.Add('Format unbekannt', 'Format unknown')
$WerteEn.Add('Sonstige Dateien', 'Other files')
$WerteEn.Add('Ältester Eintrag', 'Oldest entry')
$WerteEn.Add('Domänencomputer', 'Domain Computers')
$WerteEn.Add('Konto unbekannt', 'Account unknown')
$WerteEn.Add('Standard (alle)', 'Default (all)')
$WerteEn.Add('Computerkonten', 'Computer accounts')
$WerteEn.Add('Konto gesperrt', 'Account locked')
$WerteEn.Add('Nicht erreicht', 'Not reached')
$WerteEn.Add('DHCP-Bereiche', 'DHCP scopes')
$WerteEn.Add('Dieser Ordner', 'This folder')
$WerteEn.Add('Gruppe/System', 'Group/system')
$WerteEn.Add('Remotedesktop', 'Remote Desktop')
$WerteEn.Add('Arbeitsplatz', 'Workstation')
$WerteEn.Add('Schemamaster', 'Schema master')
$WerteEn.Add('DHCP-Server', 'DHCP server')
$WerteEn.Add('Datenbanken', 'Databases')
$WerteEn.Add('Sonderkonto', 'Special account')
$WerteEn.Add('Unterordner', 'Subfolders')
$WerteEn.Add('Vollzugriff', 'Full control')
$WerteEn.Add('Zugriff von', 'Access from')
$WerteEn.Add('DNS-Server', 'DNS server')
$WerteEn.Add('Inaktiv ab', 'Inactive from')
$WerteEn.Add('Schreiben:', 'Write:')
$WerteEn.Add('Verweigern', 'Deny')
$WerteEn.Add('DNS-Zonen', 'DNS zones')
$WerteEn.Add('Schreiben', 'Write')
$WerteEn.Add('Sonstiges', 'Other')
$WerteEn.Add('Standorte', 'Sites')
$WerteEn.Add('Unbekannt', 'Unknown')
$WerteEn.Add('unbekannt', 'unknown')
$WerteEn.Add('(Wurzel)', '(root)')
$WerteEn.Add('Anlegen:', 'Create:')
$WerteEn.Add('Benutzer', 'User')
$WerteEn.Add('Erlauben', 'Allow')
$WerteEn.Add('Netzwerk', 'Network')
$WerteEn.Add('Verwaist', 'Orphaned')
$WerteEn.Add('verwaist', 'orphaned')
$WerteEn.Add('Dateien', 'Files')
$WerteEn.Add('Gruppen', 'Groups')
$WerteEn.Add('Anonym', 'Anonymous')
$WerteEn.Add('Domäne', 'Domain')
$WerteEn.Add('Gruppe', 'Group')
$WerteEn.Add('Umfang', 'Scope')
$WerteEn.Add('direkt', 'direct')
$WerteEn.Add('Ändern', 'Change')
$WerteEn.Add('Lesen', 'Read')
$WerteEn.Add('über', 'via')
$WerteMuster = @()
foreach ($k in ($WerteEn.Keys | Sort-Object Length -Descending)) { $WerteMuster += , @([regex]::new('(?<![\p{L}\d])' + [regex]::Escape($k) + '(?![\p{L}\d])'), $WerteEn[$k]) }
function WertAnzeige($v) {
    if (-not $script:En -or $v -isnot [string] -or -not $v) { return $v }
    if ($v.Contains('\')) { return $v }   # Kontonamen (DOMÄNE\Name) und Pfade bleiben, wie sie sind
    foreach ($m in $WerteMuster) { $v = $m[0].Replace($v, $m[1]) }
    $v
}
function SpaltenAnzeige($liste) {
    if (-not $script:En -or -not @($liste).Count) { return $liste }
    foreach ($o in @($liste)) {
        $n = [ordered]@{}
        foreach ($p in $o.PSObject.Properties) { $k = $p.Name; if ($SpaltenEn.ContainsKey($k)) { $k = $SpaltenEn[$k] }; $i = 2; $k0 = $k; while ($n.Contains($k)) { $k = "$k0 $i"; $i++ }; $n[$k] = WertAnzeige $p.Value }
        [pscustomobject]$n
    }
}
# Sortierschluessel fuer Nummern wie K2, K10: erst Buchstaben, dann die Zahl als Zahl
function IdZahl($id) { $m = [regex]::Match([string]$id, '\d+'); if ($m.Success) { [int]$m.Value } else { 0 } }
function IdText($id) { [regex]::Replace([string]$id, '\d+', '') }

$Befunde = New-Object System.Collections.Generic.List[object]

# Platzhalterzeilen ("nicht geprüft") erkennt das Skript nur an den vollständigen, festen Texten, die es selbst erzeugt - keine Teilstring-Suche
# in Konto-, Objekt- oder Beschreibungstexten, die ein Angreifer beeinflussen könnte
# Deutsch und Englisch: Skripte erzeugen den Text je nach -Language, erkannt werden beide Fassungen
$PlatzhalterTexte = @('Abfrage fehlgeschlagen - nicht geprüft', 'Berechtigungen nicht lesbar - nicht geprüft', 'SYSVOL nicht lesbar - nicht geprüft', 'WMI-Filter nicht lesbar - nicht geprüft', 'Kein Domänencontroller ermittelbar - SYSVOL nicht geprüft', 'Inhalt des Ordners nicht lesbar - Richtlinie nicht geprüft',
    'Query failed - not checked', 'Permissions not readable - not checked', 'SYSVOL not readable - not checked', 'WMI filter not readable - not checked', 'No domain controller found - SYSVOL not checked', 'Folder content not readable - policy not checked')
function IstPlatzhalter($o) {
    # Ein Skript kann $script:PlatzhalterSpalten setzen: dann zählen nur diese Spalten (Namensspalten sind von Benutzern beeinflussbar)
    foreach ($pr in $o.PSObject.Properties) {
        if ($script:PlatzhalterSpalten -and ($pr.Name -notin $script:PlatzhalterSpalten)) { continue }
        if (($pr.Value -is [string]) -and ($PlatzhalterTexte -ccontains $pr.Value)) { return $true }
    }
    ("$($o.Feststellung)" -clike 'Nicht geprüft - *') -or ("$($o.Feststellung)" -clike 'Not checked - *')
}

# Besteht ein Prüfpunkt nur aus Platzhalterzeilen (Abfrage fehlgeschlagen), ist das kein Mangel dieses Prüfpunkts: als Info führen statt
# mit seiner Stufe, damit es in den Kacheln nicht als hoher Befund zählt. Nur für Prüfpunkte, deren Ergebnis von einer Abfrage abhängt.
function InfoWennNurNichtGeprueft([string]$IdMuster) {
    foreach ($x in ($Befunde | Where-Object { $_.Id -match $IdMuster -and $_.Anzahl -gt 0 -and $_.Stufe -ne 'Info' })) {
        if (-not @($x.Objekte | Where-Object { -not (IstPlatzhalter $_) }).Count) { $x.Stufe = 'Info' }
    }
}

# Prüfpunkte, die für einzelne Server nicht ausgewertet werden konnten (Abfrage fehlgeschlagen), dürfen nicht als "ohne Befund" erscheinen:
# je Server eine Zeile "nicht geprüft" anhängen; hatte der Prüfpunkt sonst keinen Treffer, steht er als Info statt als OK.
function NichtGeprueft([string]$IdMuster, [string[]]$Namen, [string]$Verweis, [string]$Spalte = 'Server', [string]$Grund = $(T 'Abfrage nicht möglich' 'query not possible')) {
    foreach ($x in ($Befunde | Where-Object { $_.Id -match $IdMuster })) {
        $war = $x.Anzahl
        $zeilen = @($Namen | ForEach-Object { [pscustomobject][ordered]@{ $Spalte = $_; Feststellung = (T "Nicht geprüft - $Grund (siehe $Verweis)" "Not checked - $Grund (see $Verweis)"); Details = '' } })
        $x.Objekte = @($x.Objekte) + $zeilen
        $x.Anzahl = $x.Objekte.Count
        if (-not $war) { $x.Stufe = 'Info' }
    }
}
function Befund {
    param([string]$Id, [string]$Bereich, [string]$Titel, [ValidateSet('Hoch', 'Mittel', 'Niedrig', 'Info')][string]$Stufe,
        $Objekte, [string]$Erklaerung, [string]$Empfehlung)
    $liste = @($Objekte | Where-Object { $null -ne $_ })
    $status = $Stufe
    if ($liste.Count -eq 0) { $status = 'OK' }
    $Befunde.Add([pscustomobject]@{
            Id = $Id; Bereich = $Bereich; Titel = $Titel; Stufe = $status; Anzahl = $liste.Count
            Objekte = $liste; Erklaerung = $Erklaerung; Empfehlung = $Empfehlung
        })
}

# Schreibt den HTML-Bericht (und auf Wunsch CSV-Dateien). $Abschnitte: Überschrift -> Objekte oder fertiges HTML,
# erscheinen vor den Befunden. $Anhang: Überschrift -> Text, erscheint am Ende unverändert.
function BerichtSchreiben {
    param([string]$Name, [string]$Datei, [string]$Bezug, [string]$BezugName = $(T 'Domäne' 'Domain'), [System.Collections.IDictionary]$Umgebung,
        [System.Collections.IDictionary]$Abschnitte = @{}, [System.Collections.IDictionary]$Anhang = @{}, [string]$Fuss)
    Write-Host (T '  Bericht schreiben ...' '  Writing report ...')
    $jetzt = Get-Date
    $ziel = $script:Ausgabe
    if (-not $ziel) { $ziel = Join-Path (Get-Location).Path ("{0}_{1}_{2:yyyy-MM-dd_HHmm}.html" -f $Datei, ($Bezug -replace '[^\w.\-]+', '-'), $jetzt) }
    $ziel = [System.IO.Path]::GetFullPath($ziel)
    $ordner = Split-Path $ziel -Parent
    if (-not (Test-Path $ordner)) { New-Item -ItemType Directory -Path $ordner -Force | Out-Null }

    $stufeText = @{ Hoch = (T 'Hoch' 'High'); Mittel = (T 'Mittel' 'Medium'); Niedrig = (T 'Niedrig' 'Low'); Info = 'Info'; OK = 'OK' }
    $rang = @{ Hoch = 0; Mittel = 1; Niedrig = 2; Info = 3; OK = 4 }
    $zahl = @{}
    foreach ($s in 'Hoch', 'Mittel', 'Niedrig', 'Info', 'OK') { $zahl[$s] = @($Befunde | Where-Object Stufe -eq $s).Count }
    $css = @'
body{font-family:Segoe UI,Arial,sans-serif;color:#2b2f36;margin:0;background:#f4f6fa}
.seite{max-width:1100px;margin:0 auto;padding:28px 24px 60px}
h1{color:#1f5fae;margin:0 0 4px;font-size:28px} h2{color:#1f5fae;font-size:19px;margin:34px 0 10px;border-bottom:2px solid #d0d5dd;padding-bottom:6px}
.meta{color:#6b7280;font-size:13px;margin-bottom:22px}
.kacheln{display:flex;gap:14px;flex-wrap:wrap;margin:18px 0}
.kachel{flex:1;min-width:150px;background:#fff;border-radius:10px;padding:14px 18px;border-left:8px solid #999;box-shadow:0 1px 3px rgba(0,0,0,.08)}
.kachel b{display:block;font-size:30px} .kachel span{font-size:13px;color:#6b7280}
table{border-collapse:collapse;width:100%;background:#fff;font-size:13px;margin:8px 0 4px}
th{background:#1f5fae;color:#fff;text-align:left;padding:7px 9px;font-weight:600} td{padding:6px 9px;border-bottom:1px solid #e5e7eb;vertical-align:top;overflow-wrap:break-word}
tr:nth-child(even) td{background:#f9fafb}
.marke{display:inline-block;min-width:58px;text-align:center;padding:2px 9px;border-radius:11px;color:#fff;font-size:12px;font-weight:600}
.m-Hoch{background:#d92d20}.m-Mittel{background:#f79009}.m-Niedrig{background:#ca8a04}.m-OK{background:#12b76a}.m-Info{background:#1f5fae}
.befund{background:#fff;border-radius:10px;padding:16px 20px;margin:14px 0;border-left:8px solid #999;box-shadow:0 1px 3px rgba(0,0,0,.08)}
.befund h3{margin:0 0 6px;font-size:16px} .befund p{margin:5px 0;font-size:14px;line-height:1.45} .befund .emp{color:#14532d}
.Hoch{border-color:#d92d20}.Mittel{border-color:#f79009}.Niedrig{border-color:#eab308}.OK{border-color:#12b76a}.Info{border-color:#1f5fae}
.klein{color:#6b7280;font-size:12px} a{color:#1f5fae;text-decoration:none}
pre{background:#fff;border:1px solid #d0d5dd;border-radius:8px;padding:12px 14px;font-size:12px;white-space:pre-wrap;word-break:break-word}
.fuss{margin-top:40px;color:#6b7280;font-size:12px;border-top:1px solid #d0d5dd;padding-top:12px}
@media print{body{background:#fff}.befund,.kachel{box-shadow:none;border:1px solid #d0d5dd;border-left-width:8px;break-inside:avoid}}
'@
    $h = New-Object System.Text.StringBuilder
    [void]$h.Append("<!DOCTYPE html><html lang='$Language'><head><meta charset='utf-8'><title>$(Html $Name) $(Html $Bezug)</title><style>$css</style></head><body><div class='seite'>")
    [void]$h.Append("<h1>$(Html $Name)</h1><div class='meta'>$(Html $BezugName) <b>$(Html $Bezug)</b> · $(T 'erstellt am' 'created') $($jetzt.ToString((T 'dd.MM.yyyy HH:mm' 'yyyy-MM-dd HH:mm'))) $(T 'von' 'by') $(Html "$env:USERDOMAIN\$env:USERNAME") $(T 'auf' 'on') $(Html $env:COMPUTERNAME)</div>")
    [void]$h.Append("<div class='kacheln'>")
    foreach ($s in 'Hoch', 'Mittel', 'Niedrig', 'Info', 'OK') {
        $text = @{ Hoch = (T 'Befunde mit hoher Priorität' 'findings, high priority'); Mittel = (T 'mit mittlerer Priorität' 'medium priority'); Niedrig = (T 'mit niedriger Priorität' 'low priority'); Info = (T 'Hinweise und nicht geprüft' 'notes and not checked'); OK = (T 'Prüfpunkte ohne Befund' 'checks without findings') }[$s]
        [void]$h.Append("<div class='kachel $s'><b>$($zahl[$s])</b><span>$text</span></div>")
    }
    [void]$h.Append("</div><h2>$(T 'Umgebung' 'Environment')</h2><table><tr><th>$(T 'Eigenschaft' 'Property')</th><th>$(T 'Wert' 'Value')</th></tr>")
    foreach ($k in $Umgebung.Keys) { [void]$h.Append("<tr><td>$(Html (WertAnzeige $k))</td><td>$(Html (WertAnzeige $Umgebung[$k]))</td></tr>") }
    [void]$h.Append("</table>")

    [void]$h.Append("<h2>$(T 'Übersicht der Prüfpunkte' 'Overview of checks')</h2><table><tr><th>$(T 'Nr.' 'No.')</th><th>$(T 'Bereich' 'Area')</th><th>$(T 'Prüfpunkt' 'Check')</th><th>$(T 'Treffer' 'Hits')</th><th>$(T 'Bewertung' 'Rating')</th></tr>")
    foreach ($x in $Befunde) {
        [void]$h.Append("<tr><td>$($x.Id)</td><td>$(Html $x.Bereich)</td><td><a href='#$($x.Id)'>$(Html $x.Titel)</a></td><td>$($x.Anzahl)</td><td><span class='marke m-$($x.Stufe)'>$($stufeText[$x.Stufe])</span></td></tr>")
    }
    [void]$h.Append("</table>")

    foreach ($k in $Abschnitte.Keys) {
        [void]$h.Append("<h2>$(Html (WertAnzeige $k))</h2>")
        $inhalt = $Abschnitte[$k]
        if ($inhalt -is [string]) { [void]$h.Append($inhalt) }
        elseif (@($inhalt).Count) { [void]$h.Append(((Einheitlich $inhalt | ConvertTo-Html -Fragment) -join "`n")) }
        else { [void]$h.Append("<p class='klein'>$(T 'Keine Einträge.' 'No entries.')</p>") }
    }

    [void]$h.Append("<h2>$(T 'Befunde' 'Findings')</h2>")
    $offen = @($Befunde | Where-Object { $_.Stufe -ne 'OK' } | Sort-Object { $rang[$_.Stufe] }, { IdText $_.Id }, { IdZahl $_.Id })
    foreach ($x in $offen) {
        [void]$h.Append("<div class='befund $($x.Stufe)' id='$($x.Id)'><h3><span class='marke m-$($x.Stufe)'>$($stufeText[$x.Stufe])</span> $($x.Id) · $(Html $x.Titel) <span class='klein'>($($x.Anzahl) $(T 'Treffer' 'hits'))</span></h3>")
        [void]$h.Append("<p>$(Html $x.Erklaerung)</p><p class='emp'><b>$(T 'Empfehlung' 'Recommendation'):</b> $(Html $x.Empfehlung)</p>")
        [void]$h.Append(((Einheitlich $x.Objekte | ConvertTo-Html -Fragment) -join "`n"))
        [void]$h.Append("</div>")
    }
    if (-not $offen.Count) { [void]$h.Append("<p>$(T 'Keine Auffälligkeiten gefunden.' 'No anomalies found.')</p>") }
    $ok = @($Befunde | Where-Object Stufe -eq 'OK')
    if ($ok.Count) {
        [void]$h.Append("<h2>$(T 'Ohne Befund' 'No findings')</h2><table><tr><th>$(T 'Nr.' 'No.')</th><th>$(T 'Prüfpunkt' 'Check')</th></tr>")
        foreach ($x in $ok) { [void]$h.Append("<tr id='$($x.Id)'><td>$($x.Id)</td><td>$(Html $x.Titel)</td></tr>") }
        [void]$h.Append("</table>")
    }
    foreach ($k in $Anhang.Keys) { [void]$h.Append("<h2>$(Html $k)</h2><pre>$(Html $Anhang[$k])</pre>") }
    [void]$h.Append("<div class='fuss'>$(Html $Name) Version $script:Version · IT Admin Tools by MM · $(T 'Das Skript hat ausschließlich gelesen und nichts verändert.' 'The script only read and changed nothing.') $(Html $Fuss)</div>")
    [void]$h.Append("</div></body></html>")
    [System.IO.File]::WriteAllText($ziel, $h.ToString(), (New-Object System.Text.UTF8Encoding($true)))

    $basis = [System.IO.Path]::ChangeExtension($ziel, $null).TrimEnd('.')
    if ($script:Csv) {
        foreach ($x in ($Befunde | Where-Object { $_.Anzahl -gt 0 })) {
            Einheitlich $x.Objekte | Export-Csv -Path "${basis}_$($x.Id).csv" -NoTypeInformation -Delimiter ';' -Encoding UTF8
        }
    }
    Write-Host ''
    Write-Host ((T "Fertig: {0} hoch, {1} mittel, {2} niedrig, {3} ohne Befund." "Done: {0} high, {1} medium, {2} low, {3} without findings.") -f $zahl.Hoch, $zahl.Mittel, $zahl.Niedrig, $zahl.OK) -ForegroundColor Green
    Write-Host ((T 'Bericht' 'Report') + ": $ziel")
    if (-not $script:NichtOeffnen -and [Environment]::UserInteractive) { try { Start-Process $ziel } catch { } }
    $basis
}

# ------------------------------------------------------------------ Daten lesen
Write-Host (T 'Privilegierte-Konten-Check - es wird nur gelesen, nichts verändert.' 'Privileged account check - read-only, nothing is changed.') -ForegroundColor Cyan
Write-Host (T '  Domäne ...' 'Domain ...')
$dom = Get-ADDomain @ad
$sid = $dom.DomainSID.Value
$jetzt = Get-Date
$standard = Get-ADDefaultDomainPasswordPolicy @ad

Write-Host (T '  Privilegierte Gruppen ...' 'Privileged groups ...')
$privSids = [ordered]@{
    "$sid-512"     = (T 'Domänen-Admins' 'Domain Admins')
    "$sid-519"     = (T 'Organisations-Admins' 'Organization admins')
    "$sid-518"     = (T 'Schema-Admins' 'Schema admins')
    'S-1-5-32-544' = 'Administratoren'
    'S-1-5-32-548' = 'Konten-Operatoren'
    'S-1-5-32-549' = (T 'Server-Operatoren' 'Server operators')
    'S-1-5-32-551' = (T 'Sicherungs-Operatoren' 'Backup Operators')
}
$gruppen = @()
$nichtGelesen = @()
foreach ($s in $privSids.Keys) {
    try { $g = Get-ADGroup -Identity $s @ad; $gruppen += [pscustomobject]@{ Gruppe = $g; Anzeige = $g.Name } }
    catch {
        # Gruppen anderer Domänen (z. B. Organisations-Admins in einer untergeordneten Domäne) gibt es hier nicht; alles andere ist ein Lesefehler
        if ($_.Exception.GetType().Name -ne 'ADIdentityNotFoundException') { $nichtGelesen += [pscustomobject][ordered]@{ Gruppe = $privSids[$s]; Feststellung = (T 'Nicht geprüft - Gruppe nicht lesbar (siehe Umgebung)' 'Not checked - group not readable (see environment)'); Details = $_.Exception.Message } }
    }
}
# Mitglieder inklusive verschachtelter Gruppen (LDAP_MATCHING_RULE_IN_CHAIN). Zwei Lücken schließt das Skript ausdrücklich:
#  - Konten, deren PRIMÄRE Gruppe eine privilegierte Gruppe ist (Attribut primaryGroupID), stehen nicht in der Mitgliederliste der Gruppe
#  - Computerkonten und verwaltete Dienstkonten (gMSA) können ebenfalls Mitglied sein, nicht nur Benutzerkonten
$eig = 'userAccountControl', 'pwdLastSet', 'lastLogonTimestamp', 'whenCreated', 'mail', 'objectSid', 'sAMAccountName', 'objectClass'
$klassen = '(|(objectClass=user)(objectClass=computer)(objectClass=msDS-GroupManagedServiceAccount))'
function FileTimeDatum($w) { if ($w -and [int64]$w -gt 0) { try { [datetime]::FromFileTime([int64]$w) } catch { $null } } else { $null } }
function KontoObjekt($o) {
    $uac = [int]$o.userAccountControl
    $typ = if ($o.objectClass -contains 'msDS-GroupManagedServiceAccount') { 'gMSA' } elseif ($o.objectClass -contains 'computer') { 'Computer' } else { 'Benutzer' }
    [pscustomobject]@{
        SamAccountName = [string]$o.sAMAccountName; Name = [string]$o.Name; Typ = $typ; DistinguishedName = [string]$o.DistinguishedName
        Enabled = (($uac -band 2) -eq 0); PasswordNeverExpires = (($uac -band 65536) -ne 0)
        PasswordLastSet = FileTimeDatum $o.pwdLastSet; LastLogonDate = FileTimeDatum $o.lastLogonTimestamp
        whenCreated = $o.whenCreated; mail = [string]$o.mail; SID = $o.objectSid
    }
}
$von = @{}
$konten = @{}
function Vermerken($o, [string]$gruppe) {
    $k = KontoObjekt $o
    if ($k.SID.Value -match '-(501|502|503)$') { return }   # eingebaute Sonderkonten (Gast, krbtgt, DefaultAccount)
    if (-not $von.ContainsKey($k.SamAccountName)) { $von[$k.SamAccountName] = New-Object System.Collections.Generic.List[string]; $konten[$k.SamAccountName] = $k }
    if (-not $von[$k.SamAccountName].Contains($gruppe)) { $von[$k.SamAccountName].Add($gruppe) }
}
foreach ($p in $gruppen) {
    $dn = $p.Gruppe.DistinguishedName
    foreach ($t in (Get-ADObject -LDAPFilter "(&$klassen(memberOf:1.2.840.113556.1.4.1941:=$dn))" -Properties $eig @ad)) { Vermerken $t $p.Anzeige }
    # Primäre Gruppe: für die Gruppe selbst und für jede darin verschachtelte Gruppe
    $alleGruppen = @($p.Gruppe) + @(Get-ADGroup -LDAPFilter "(memberOf:1.2.840.113556.1.4.1941:=$dn)" @ad)
    foreach ($g in $alleGruppen) {
        $rid = [int]($g.SID.Value -replace '^.*-', '')
        if ($g.SID.Value -like 'S-1-5-32-*') { continue }   # eingebaute Gruppen können keine primäre Gruppe sein
        foreach ($t in (Get-ADObject -LDAPFilter "(&$klassen(primaryGroupID=$rid))" -Properties $eig @ad)) { Vermerken $t $p.Anzeige }
    }
}
$priv = @($konten.Values | Sort-Object SamAccountName)
$aktiv = @($priv | Where-Object Enabled)

# Geschützte Benutzer (Gruppe mit der festen Endung -525); gibt es erst ab Windows Server 2012 R2
$geschuetzt = @{}
$schutzGruppe = $null
$schutzFehler = $null
try {
    $schutzGruppe = Get-ADGroup -Identity "$sid-525" @ad
    foreach ($u in (Get-ADObject -LDAPFilter "(&$klassen(memberOf:1.2.840.113556.1.4.1941:=$($schutzGruppe.DistinguishedName)))" -Properties sAMAccountName @ad)) { $geschuetzt[[string]$u.sAMAccountName] = $true }
}
catch {
    # Die Gruppe fehlt in Domänen unter Windows Server 2012 R2: das ist kein Fehler. Alles andere ist ein Lesefehler und wird gemeldet.
    if ($_.Exception.GetType().Name -ne 'ADIdentityNotFoundException') { $schutzFehler = $_.Exception.Message; $schutzGruppe = $null }
}

function Zeile($u, $zusatz = @{}) {
    $z = [ordered]@{
        Konto = $u.SamAccountName; Name = $u.Name; Typ = $u.Typ; Aktiv = JaNein $u.Enabled; 'Privilegierte Gruppen' = ($von[$u.SamAccountName] -join ', ')
        'Letzte Anmeldung' = Datum $u.LastLogonDate; 'Kennwort gesetzt' = Datum $u.PasswordLastSet
    }
    foreach ($k in $zusatz.Keys) { $z[$k] = $zusatz[$k] }
    [pscustomobject]$z
}

# ------------------------------------------------------------------ Prüfungen
Write-Host (T '  Auswertung ...' '  Evaluation ...')
$a = @()
if ($aktiv.Count -gt $MaxAdmins) { $a = [pscustomobject]@{ Einstellung = 'Aktive privilegierte Konten'; Ist = $aktiv.Count; Empfohlen = (T "höchstens $MaxAdmins" "at most $MaxAdmins") } }
Befund 'P1' (T 'Anzahl' 'Count') (T "Mehr als $MaxAdmins aktive privilegierte Konten ($($aktiv.Count))" "More than $MaxAdmins active privileged accounts ($($aktiv.Count))") 'Mittel' $a `
    (T 'Jedes Konto mit Administratorrechten ist ein Ziel. Je mehr es gibt, desto größer ist die Angriffsfläche und desto schwerer lässt sich nachvollziehen, wer wofür Rechte braucht. Gezählt werden auch Mitglieder verschachtelter Gruppen.' 'Every account with admin rights is a target. The more there are, the larger the attack surface and the harder it is to track who needs rights for what. Members of nested groups are also counted.') `
    (T 'Liste unten prüfen: Wer braucht Domänen-Adminrechte im Alltag? Rechte auf das nötige Maß senken, für selten benötigte Aufgaben delegierte Rechte oder zeitlich begrenzte Mitgliedschaft nutzen.' 'Check the list below: Who needs domain admin rights in everyday work? Reduce permissions to the necessary minimum; for rarely needed tasks, use delegated permissions or time-limited membership.')

Befund 'P2' (T 'Inaktivität' 'Inactivity') (T "Aktive privilegierte Konten ohne Anmeldung seit $InaktivTage Tagen" "Active privileged accounts without logon for $InaktivTage days") 'Mittel' `
    @($aktiv | Where-Object {
            $grenzeAnm = $jetzt.AddDays(-$InaktivTage)
            if ($_.LastLogonDate) { $_.LastLogonDate -lt $grenzeAnm }
            else { -not $_.whenCreated -or ([datetime]$_.whenCreated) -lt $grenzeAnm }   # nie angemeldet: nur melden, wenn das Konto älter als die Frist ist
        } | ForEach-Object { Zeile $_ @{ Hinweis = $(if ($_.LastLogonDate) { '' } else { (T 'nie angemeldet, angelegt am ' 'never logged on, created on') + (Datum $_.whenCreated '?') }) } }) `
    (T 'Ein Adminkonto, das niemand benutzt, wird auch nicht überwacht. Gelangt ein Angreifer an sein Kennwort, fällt die Nutzung kaum auf. Oft sind es Konten ausgeschiedener Mitarbeiter oder alte Testkonten. Der Zeitpunkt wird zwischen den Domänencontrollern nur alle 14 Tage abgeglichen.' 'An admin account that nobody uses is also not monitored. If an attacker obtains its password, its use is hardly noticed. Often these are accounts of former employees or old test accounts. The timestamp is synchronized between domain controllers only every 14 days.') `
    (T 'Konten mit den Verantwortlichen klären. Nicht mehr benötigte Konten aus den Gruppen entfernen und deaktivieren.' 'Review accounts with the responsible parties. Remove accounts that are no longer needed from groups and disable them.')

Befund 'P3' (T 'Kennwort' 'Password') (T "Privilegierte Konten mit Kennwort älter als $KennwortAlterTage Tage" "Privileged accounts with password older than $KennwortAlterTage days") 'Mittel' `
    @($aktiv | Where-Object { -not $_.PasswordNeverExpires -and $_.PasswordLastSet -and $_.PasswordLastSet -lt $jetzt.AddDays(-$KennwortAlterTage) } | ForEach-Object { Zeile $_ }) `
    (T 'Je älter ein Kennwort ist, desto länger konnte es abgegriffen, mitgelesen oder über eine Datensammlung bekannt werden. Für Administratorkonten ist ein selten gewechseltes Kennwort besonders riskant. Konten ohne Kennwortablauf stehen unter P4.' 'The older a password is, the longer it could have been intercepted, read, or become known through a data collection. For admin accounts, a rarely changed password is particularly risky. Accounts without password expiry are under P4.') `
    (T 'Kennwort ändern. Für Konten, die ein Mensch nutzt, ein langes, nur dafür verwendetes Kennwort; für Dienstkonten verwaltete Dienstkonten (gMSA) einsetzen.' 'Change password. For accounts used by people, use a long, dedicated password; for service accounts, use managed service accounts (gMSA).')

Befund 'P4' (T 'Kennwort' 'Password') (T 'Privilegierte Konten, deren Kennwort nie abläuft' 'Privileged accounts whose password never expires') 'Hoch' `
    @($aktiv | Where-Object PasswordNeverExpires | ForEach-Object { Zeile $_ }) `
    (T 'Bei diesen Konten ist der Kennwortablauf abgeschaltet. Ein einmal bekannt gewordenes Kennwort bleibt dauerhaft gültig. Bei Administratorkonten ist das die Folge von Bequemlichkeit oder von Diensten, die davon abhängen.' 'Password expiry is disabled for these accounts. Once a password has become known, it remains permanently valid. For admin accounts, this is due to convenience or services that depend on it.') `
    (T 'Kennwortablauf einschalten oder das Konto durch ein gMSA ersetzen. Bei Dienstkonten prüfen, welcher Dienst das Konto nutzt, und das Kennwort danach ändern.' 'Enable password expiration or replace the account with a gMSA. For service accounts, check which service uses the account, and then change the password.')

Befund 'P5' (T 'Trennung' 'Separation') (T 'Privilegierte Konten mit E-Mail-Adresse' 'Privileged accounts with email address') 'Mittel' `
    @($aktiv | Where-Object { $_.mail } | ForEach-Object { Zeile $_ @{ 'E-Mail' = $_.mail } }) `
    (T 'Wer mit demselben Konto Mails liest und Server verwaltet, setzt sein Adminkonto jedem Phishing-Link und jedem Anhang aus. Ein Klick genügt dann für die Übernahme der Domäne. Admin- und Alltagskonto sollten getrennt sein.' 'Using the same account to read email and manage servers exposes the admin account to every phishing link and attachment. A single click is then enough to take over the domain. Admin and everyday accounts should be separated.') `
    (T 'Je Administrator ein eigenes Konto ohne Postfach und ohne Internetnutzung anlegen und das Alltagskonto aus den privilegierten Gruppen nehmen.' 'Create a separate account for each administrator without a mailbox and without internet use, and remove the everyday account from the privileged groups.')

$p6 = @()
if ($schutzFehler) { $p6 = [pscustomobject][ordered]@{ Konto = (T 'alle' 'all'); Feststellung = (T 'Nicht geprüft - Gruppe "Geschützte Benutzer" nicht lesbar' 'Not checked - "Protected Users" group not readable'); Details = $schutzFehler } }
elseif ($schutzGruppe) {
    $p6 = @($aktiv | Where-Object { $_.Typ -eq 'Benutzer' -and -not $geschuetzt.ContainsKey($_.SamAccountName) -and $_.SID.Value -notmatch '-500$' } | ForEach-Object { Zeile $_ })
}
Befund 'P6' (T 'Schutz' 'Protection') (T 'Privilegierte Konten außerhalb der Gruppe "Geschützte Benutzer"' 'Privileged accounts outside the "Protected Users" group') 'Niedrig' $p6 `
    (T 'Mitglieder der Gruppe "Geschützte Benutzer" bekommen von Windows zusätzlichen Schutz: keine NTLM-Anmeldung, keine zwischengespeicherten Anmeldedaten, kurze Kerberos-Tickets. Das schützt Administratorkonten vor Diebstahl der Anmeldedaten. Das eingebaute Administratorkonto ist ausgenommen, ebenso Computerkonten und gMSA (für Maschinen- und Dienstkonten ist die Gruppe nicht vorgesehen).' 'Members of the "Protected Users" group receive additional protection from Windows: no NTLM logon, no cached credentials, short Kerberos tickets. This protects administrator accounts from credential theft. The built-in administrator account is excluded, as are computer accounts and gMSA (the group is not intended for machine and service accounts).') `
    (T 'Konten nach einem Test in die Gruppe aufnehmen. Vorsicht bei Konten, die sich per NTLM, mit Delegierung oder auf älteren Systemen anmelden müssen: Sie funktionieren dann nicht mehr.' 'Add accounts to the group after a test. Be careful with accounts that must log on using NTLM, with delegation, or on older systems: they will no longer work.')

$p7 = @()
$p7Fehler = @()
foreach ($u in ($aktiv | Where-Object { $_.Typ -eq 'Benutzer' })) {
    $r = $null
    try { $r = Get-ADUserResultantPasswordPolicy -Identity $u.DistinguishedName @ad }
    catch { $p7Fehler += [pscustomobject][ordered]@{ Konto = $u.SamAccountName; Feststellung = (T 'Nicht geprüft - wirksame Kennwortrichtlinie nicht lesbar' 'Not checked - effective password policy not readable'); Details = $_.Exception.Message }; continue }
    $laenge = if ($r) { $r.MinPasswordLength } else { $standard.MinPasswordLength }
    if ($laenge -lt $MindestLaenge) {
        $p7 += Zeile $u @{ 'Wirksame Richtlinie' = $(if ($r) { $r.Name } else { (T 'Standard der Domäne' 'Domain standard') }); 'Mindestlänge' = (T "$laenge Zeichen" "$laenge characters"); Empfohlen = (T "mindestens $MindestLaenge Zeichen" "at least $MindestLaenge characters") }
    }
}
$p7 += $p7Fehler
Befund 'P7' (T 'Kennwort' 'Password') (T "Wirksame Kennwortrichtlinie privilegierter Konten unter $MindestLaenge Zeichen" "Effective password policy for privileged accounts under $MindestLaenge characters") 'Mittel' $p7 `
    (T 'Für ein Konto gilt entweder die Kennwortrichtlinie der Domäne oder eine abweichende Richtlinie (Password Settings Object). Hier ist die wirksame Mindestlänge für Administratoren kürzer als empfohlen. Kurze Kennwörter lassen sich schneller erraten oder berechnen.' 'For an account, either the domain password policy or a different policy (Password Settings Object) applies. Here, the effective minimum length for administrators is shorter than recommended. Short passwords can be guessed or cracked more quickly.') `
    (T 'Für privilegierte Konten eine eigene Richtlinie mit längerem Mindestkennwort anlegen (Password Settings Object, Priorität vor der Domänenrichtlinie) oder die Domänenrichtlinie anheben.' 'Create a separate policy with a longer minimum password for privileged accounts (Password Settings Object, priority before the domain policy) or raise the domain policy.')

if ($nichtGelesen.Count) {
    Befund 'P8' (T 'Abfrage' 'Query') (T 'Privilegierte Gruppen, die nicht gelesen werden konnten' 'Privileged groups that could not be read') 'Info' $nichtGelesen `
        (T 'Für diese Gruppen fehlen die Mitglieder. Die übrigen Prüfpunkte sind dadurch unvollständig, das heißt nicht, dass dort alles in Ordnung ist.' 'These groups are missing members. The remaining checks are therefore incomplete; this does not mean that everything is fine there.') `
        (T 'Berechtigung des abfragenden Kontos und Erreichbarkeit des Domänencontrollers prüfen.' 'Check the permissions of the querying account and the reachability of the domain controller.')
}

# ------------------------------------------------------------------ Bericht
$liste = $priv | ForEach-Object {
    Zeile $_ @{ 'Kennwort läuft nie ab' = JaNein $_.PasswordNeverExpires; 'E-Mail' = $_.mail; 'Geschützte Benutzer' = $(if ($schutzGruppe) { JaNein $geschuetzt.ContainsKey($_.SamAccountName) } else { (T 'Gruppe fehlt' 'Group missing') }); Angelegt = Datum $_.whenCreated }
}
$jeGruppe = foreach ($p in $gruppen) {
    $namen = @($priv | Where-Object { $von[$_.SamAccountName] -contains $p.Anzeige } | ForEach-Object { $_.SamAccountName })
    [pscustomobject][ordered]@{ Gruppe = $p.Anzeige; 'Konten (auch verschachtelt)' = $namen.Count; 'davon aktiv' = @($priv | Where-Object { $_.Enabled -and ($von[$_.SamAccountName] -contains $p.Anzeige) }).Count; Konten = ($namen -join ', ') }
}
$umgebung = [ordered]@{
    (T 'Domäne (NetBIOS)' 'Domain (NetBIOS)')          = "$($dom.DNSRoot) ($($dom.NetBIOSName))"
    (T 'Privilegierte Konten (aktiv / gesamt)' 'Privileged accounts (active / total)') = (T "$($aktiv.Count) / $($priv.Count) (davon Computer oder gMSA: $(@($priv | Where-Object { $_.Typ -ne 'Benutzer' }).Count))" "$($aktiv.Count) / $($priv.Count) (of which computers or gMSA: $(@($priv | Where-Object { $_.Typ -ne 'Benutzer' }).Count))")
    (T 'Gruppe "Geschützte Benutzer"' 'Group "Protected Users"') = $(if ($schutzGruppe) { 'vorhanden' } else { (T 'nicht vorhanden (Domäne unter Windows Server 2012 R2)' 'not present (domain on Windows Server 2012 R2)') })
    (T 'Standard-Kennwortrichtlinie' 'Default password policy') = (T "Mindestlänge $($standard.MinPasswordLength), Komplexität $(JaNein $standard.ComplexityEnabled)" "Minimum length $($standard.MinPasswordLength), complexity $(JaNein $standard.ComplexityEnabled)")
    (T 'Schwellen dieses Berichts' 'Thresholds of this report') = (T "mehr als $MaxAdmins Konten, inaktiv ab $InaktivTage Tagen, Kennwort älter als $KennwortAlterTage Tage, Mindestlänge $MindestLaenge" "more than $MaxAdmins accounts, inactive for at least $InaktivTage days, password older than $KennwortAlterTage days, minimum length $MindestLaenge")
}
$basis = BerichtSchreiben -Name (T 'Privilegierte-Konten-Check' 'Privileged account check') -Datei 'Privilegierte-Konten-Check' -Bezug $dom.DNSRoot -Umgebung $umgebung `
    -Abschnitte ([ordered]@{ (T 'Privilegierte Gruppen' 'Privileged groups') = $jeGruppe; (T 'Alle privilegierten Konten' 'All privileged accounts') = $liste }) `
    -Fuss (T 'Grundlage sind die Angaben im Active Directory. Der Zeitpunkt der letzten Anmeldung wird zwischen Domänencontrollern nur alle 14 Tage abgeglichen. Der Bericht zeigt Auffälligkeiten anhand fester Regeln, ersetzt keine Sicherheitsprüfung und erhebt keinen Anspruch auf Vollständigkeit.' 'The basis is the information in Active Directory. The last logon time is synchronized between domain controllers only every 14 days. The report shows anomalies based on fixed rules, does not replace a security check, and makes no claim to completeness.')
if ($Csv) { SpaltenAnzeige $liste | Export-Csv -Path "${basis}_Konten.csv" -NoTypeInformation -Delimiter ';' -Encoding UTF8 }
if ($PassThru) { $Befunde }
