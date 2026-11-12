#Requires -Version 5.1
<#
.SYNOPSIS
    Privilegierte-Konten-Check (kostenlos): zeigt, wer in einem Active Directory Administratorrechte hat, und prüft
    diese Konten in 7 Punkten (Anzahl, Inaktivität, Kennwortalter, Kennwortablauf, Postfach, Schutz, wirksame
    Kennwortrichtlinie). Ergebnis ist ein HTML-Bericht auf Deutsch.

    Die Vollversion "AD-Prüfbericht" prüft darüber hinaus u. a. deaktivierte Konten in privilegierten Gruppen,
    verschachtelte Gruppen, Dienstkonten mit Adminrechten, Kerberoasting-Ziele, krbtgt-Alter und weitere Punkte:
    https://www.etsy.com/shop/ITAdminToolsbyMM

.DESCRIPTION
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
    Pfad der HTML-Datei. Standard: Privilegierte-Konten-Check_<Domäne>_<Datum>.html im aktuellen Ordner.

.PARAMETER MaxAdmins
    Ab wie vielen privilegierten Konten die Anzahl als auffällig gilt (Standard 5).

.PARAMETER InaktivTage
    Privilegierte Konten ohne Anmeldung seit so vielen Tagen werden gemeldet (Standard 90).

.PARAMETER KennwortAlterTage
    Privilegierte Konten, deren Kennwort älter ist, werden gemeldet (Standard 365).

.PARAMETER MindestLaenge
    Mindestlänge der wirksamen Kennwortrichtlinie für privilegierte Konten (Standard 12 Zeichen).

.PARAMETER Server
    Bestimmter Domänencontroller oder Domäne (optional).

.PARAMETER Anmeldung
    Anmeldedaten eines Domänenkontos (Get-Credential), falls das Skript nicht als Domänenbenutzer läuft, z. B. von einem
    Rechner außerhalb der Domäne. Dann zusätzlich -Server angeben.

.PARAMETER Csv
    Schreibt zusätzlich je Prüfpunkt mit Treffern und die Liste der privilegierten Konten als CSV neben den Bericht.

.PARAMETER NichtOeffnen
    Öffnet den fertigen Bericht nicht automatisch im Browser.

.PARAMETER PassThru
    Gibt die Befunde zusätzlich als Objekte zurück (für eigene Auswertungen).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Privilegierte-Konten-Check.ps1

.EXAMPLE
    .\Privilegierte-Konten-Check.ps1 -InaktivTage 60 -Csv -Ausgabe C:\Berichte\admins.html

.NOTES
    IT Admin Tools by MM - Privilegierte-Konten-Check Version 1.0 (11.2026), Lizenz: MIT (siehe LICENSE)
    Kein Ersatz für eine Sicherheitsprüfung. Nutzung auf eigene Verantwortung.
#>
[CmdletBinding()]
param(
    [string]$Ausgabe,
    [ValidateRange(1, 1000)][int]$MaxAdmins = 5,
    [ValidateRange(1, 3650)][int]$InaktivTage = 90,
    [ValidateRange(1, 3650)][int]$KennwortAlterTage = 365,
    [ValidateRange(1, 64)][int]$MindestLaenge = 12,
    [string]$Server,
    [System.Management.Automation.PSCredential]$Anmeldung,
    [switch]$Csv,
    [switch]$NichtOeffnen,
    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'
$Version = '1.0'

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Host 'Das PowerShell-Modul "ActiveDirectory" fehlt.' -ForegroundColor Red
    Write-Host 'Windows 10/11: Einstellungen > Optionale Features > "RSAT: Active Directory Domain Services" hinzufügen.'
    Write-Host 'Windows Server:  Install-WindowsFeature RSAT-AD-PowerShell'
    exit 2
}
Import-Module ActiveDirectory

$ad = @{}
if ($Server) { $ad.Server = $Server }
if ($Anmeldung) { $ad.Credential = $Anmeldung }

# ------------------------------------------------------------------ Hilfsfunktionen
function Datum($d, $leer = 'nie') { if ($d) { ([datetime]$d).ToString('dd.MM.yyyy') } else { $leer } }
function JaNein($b) { if ($b) { 'Ja' } else { 'Nein' } }
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
        $sicher | Microsoft.PowerShell.Utility\Export-Csv -Path $Path -NoTypeInformation:$NoTypeInformation -Delimiter $Delimiter -Encoding $Encoding
    }
}

# Tabellen: ConvertTo-Html und Export-Csv nehmen die Spalten des ersten Objekts. Haben die Zeilen einer Liste verschiedene
# Eigenschaften (z. B. Fehlzeile neben normalen Treffern), gingen Spalten verloren: alle Namen der Reihe nach vereinigen.
function Einheitlich($liste) {
    $liste = @($liste | Where-Object { $null -ne $_ })
    if ($liste.Count -lt 2) { return $liste }
    $namen = New-Object System.Collections.Generic.List[string]
    foreach ($o in $liste) { foreach ($p in $o.PSObject.Properties.Name) { if (-not $namen.Contains($p)) { $namen.Add($p) } } }
    if ($namen.Count -eq @($liste[0].PSObject.Properties.Name).Count) { return $liste }
    @($liste | Select-Object -Property $namen)
}
# Sortierschluessel fuer Nummern wie K2, K10: erst Buchstaben, dann die Zahl als Zahl
function IdZahl($id) { $m = [regex]::Match([string]$id, '\d+'); if ($m.Success) { [int]$m.Value } else { 0 } }
function IdText($id) { [regex]::Replace([string]$id, '\d+', '') }

$Befunde = New-Object System.Collections.Generic.List[object]

# Platzhalterzeilen ("nicht geprüft") erkennt das Skript nur an den vollständigen, festen Texten, die es selbst erzeugt - keine Teilstring-Suche
# in Konto-, Objekt- oder Beschreibungstexten, die ein Angreifer beeinflussen könnte
$PlatzhalterTexte = @('Abfrage fehlgeschlagen - nicht geprüft', 'Berechtigungen nicht lesbar - nicht geprüft', 'SYSVOL nicht lesbar - nicht geprüft', 'WMI-Filter nicht lesbar - nicht geprüft', 'Kein Domänencontroller ermittelbar - SYSVOL nicht geprüft', 'Inhalt des Ordners nicht lesbar - Richtlinie nicht geprüft')
function IstPlatzhalter($o) {
    # Ein Skript kann $script:PlatzhalterSpalten setzen: dann zählen nur diese Spalten (Namensspalten sind von Benutzern beeinflussbar)
    foreach ($pr in $o.PSObject.Properties) {
        if ($script:PlatzhalterSpalten -and ($pr.Name -notin $script:PlatzhalterSpalten)) { continue }
        if (($pr.Value -is [string]) -and ($PlatzhalterTexte -ccontains $pr.Value)) { return $true }
    }
    ("$($o.Feststellung)" -clike 'Nicht geprüft - *')
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
function NichtGeprueft([string]$IdMuster, [string[]]$Namen, [string]$Verweis, [string]$Spalte = 'Server', [string]$Grund = 'Abfrage nicht möglich') {
    foreach ($x in ($Befunde | Where-Object { $_.Id -match $IdMuster })) {
        $war = $x.Anzahl
        $zeilen = @($Namen | ForEach-Object { [pscustomobject][ordered]@{ $Spalte = $_; Feststellung = "Nicht geprüft - $Grund (siehe $Verweis)"; Details = '' } })
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
    param([string]$Name, [string]$Datei, [string]$Bezug, [string]$BezugName = 'Domäne', [System.Collections.IDictionary]$Umgebung,
        [System.Collections.IDictionary]$Abschnitte = @{}, [System.Collections.IDictionary]$Anhang = @{}, [string]$Fuss)
    Write-Host '  Bericht schreiben ...'
    $jetzt = Get-Date
    $ziel = $script:Ausgabe
    if (-not $ziel) { $ziel = Join-Path (Get-Location).Path ("{0}_{1}_{2:yyyy-MM-dd_HHmm}.html" -f $Datei, ($Bezug -replace '[^\w.\-]+', '-'), $jetzt) }
    $ziel = [System.IO.Path]::GetFullPath($ziel)
    $ordner = Split-Path $ziel -Parent
    if (-not (Test-Path $ordner)) { New-Item -ItemType Directory -Path $ordner -Force | Out-Null }

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
    [void]$h.Append("<!DOCTYPE html><html lang='de'><head><meta charset='utf-8'><title>$(Html $Name) $(Html $Bezug)</title><style>$css</style></head><body><div class='seite'>")
    [void]$h.Append("<h1>$(Html $Name)</h1><div class='meta'>$(Html $BezugName) <b>$(Html $Bezug)</b> · erstellt am $($jetzt.ToString('dd.MM.yyyy HH:mm')) von $(Html "$env:USERDOMAIN\$env:USERNAME") auf $(Html $env:COMPUTERNAME)</div>")
    [void]$h.Append("<div class='kacheln'>")
    foreach ($s in 'Hoch', 'Mittel', 'Niedrig', 'Info', 'OK') {
        $text = @{ Hoch = 'Befunde mit hoher Priorität'; Mittel = 'mit mittlerer Priorität'; Niedrig = 'mit niedriger Priorität'; Info = 'Hinweise und nicht geprüft'; OK = 'Prüfpunkte ohne Befund' }[$s]
        [void]$h.Append("<div class='kachel $s'><b>$($zahl[$s])</b><span>$text</span></div>")
    }
    [void]$h.Append("</div><h2>Umgebung</h2><table><tr><th>Eigenschaft</th><th>Wert</th></tr>")
    foreach ($k in $Umgebung.Keys) { [void]$h.Append("<tr><td>$(Html $k)</td><td>$(Html $Umgebung[$k])</td></tr>") }
    [void]$h.Append("</table>")

    [void]$h.Append("<h2>Übersicht der Prüfpunkte</h2><table><tr><th>Nr.</th><th>Bereich</th><th>Prüfpunkt</th><th>Treffer</th><th>Bewertung</th></tr>")
    foreach ($x in $Befunde) {
        [void]$h.Append("<tr><td>$($x.Id)</td><td>$(Html $x.Bereich)</td><td><a href='#$($x.Id)'>$(Html $x.Titel)</a></td><td>$($x.Anzahl)</td><td><span class='marke m-$($x.Stufe)'>$($x.Stufe)</span></td></tr>")
    }
    [void]$h.Append("</table>")

    foreach ($k in $Abschnitte.Keys) {
        [void]$h.Append("<h2>$(Html $k)</h2>")
        $inhalt = $Abschnitte[$k]
        if ($inhalt -is [string]) { [void]$h.Append($inhalt) }
        elseif (@($inhalt).Count) { [void]$h.Append(((Einheitlich $inhalt | ConvertTo-Html -Fragment) -join "`n")) }
        else { [void]$h.Append("<p class='klein'>Keine Einträge.</p>") }
    }

    [void]$h.Append("<h2>Befunde</h2>")
    $offen = @($Befunde | Where-Object { $_.Stufe -ne 'OK' } | Sort-Object { $rang[$_.Stufe] }, { IdText $_.Id }, { IdZahl $_.Id })
    foreach ($x in $offen) {
        [void]$h.Append("<div class='befund $($x.Stufe)' id='$($x.Id)'><h3><span class='marke m-$($x.Stufe)'>$($x.Stufe)</span> $($x.Id) · $(Html $x.Titel) <span class='klein'>($($x.Anzahl) Treffer)</span></h3>")
        [void]$h.Append("<p>$(Html $x.Erklaerung)</p><p class='emp'><b>Empfehlung:</b> $(Html $x.Empfehlung)</p>")
        [void]$h.Append(((Einheitlich $x.Objekte | ConvertTo-Html -Fragment) -join "`n"))
        [void]$h.Append("</div>")
    }
    if (-not $offen.Count) { [void]$h.Append("<p>Keine Auffälligkeiten gefunden.</p>") }
    $ok = @($Befunde | Where-Object Stufe -eq 'OK')
    if ($ok.Count) {
        [void]$h.Append("<h2>Ohne Befund</h2><table><tr><th>Nr.</th><th>Prüfpunkt</th></tr>")
        foreach ($x in $ok) { [void]$h.Append("<tr id='$($x.Id)'><td>$($x.Id)</td><td>$(Html $x.Titel)</td></tr>") }
        [void]$h.Append("</table>")
    }
    foreach ($k in $Anhang.Keys) { [void]$h.Append("<h2>$(Html $k)</h2><pre>$(Html $Anhang[$k])</pre>") }
    [void]$h.Append("<div class='fuss'>$(Html $Name) Version $script:Version · IT Admin Tools by MM · Das Skript hat ausschließlich gelesen und nichts verändert. $(Html $Fuss)</div>")
    [void]$h.Append("</div></body></html>")
    [System.IO.File]::WriteAllText($ziel, $h.ToString(), (New-Object System.Text.UTF8Encoding($true)))

    $basis = [System.IO.Path]::ChangeExtension($ziel, $null).TrimEnd('.')
    if ($script:Csv) {
        foreach ($x in ($Befunde | Where-Object { $_.Anzahl -gt 0 })) {
            Einheitlich $x.Objekte | Export-Csv -Path "${basis}_$($x.Id).csv" -NoTypeInformation -Delimiter ';' -Encoding UTF8
        }
    }
    Write-Host ''
    Write-Host ("Fertig: {0} hoch, {1} mittel, {2} niedrig, {3} ohne Befund." -f $zahl.Hoch, $zahl.Mittel, $zahl.Niedrig, $zahl.OK) -ForegroundColor Green
    Write-Host "Bericht: $ziel"
    if (-not $script:NichtOeffnen -and [Environment]::UserInteractive) { try { Start-Process $ziel } catch { } }
    $basis
}

# ------------------------------------------------------------------ Daten lesen
Write-Host 'Privilegierte-Konten-Check - es wird nur gelesen, nichts verändert.' -ForegroundColor Cyan
Write-Host '  Domäne ...'
$dom = Get-ADDomain @ad
$sid = $dom.DomainSID.Value
$jetzt = Get-Date
$standard = Get-ADDefaultDomainPasswordPolicy @ad

Write-Host '  Privilegierte Gruppen ...'
$privSids = [ordered]@{
    "$sid-512"     = 'Domänen-Admins'
    "$sid-519"     = 'Organisations-Admins'
    "$sid-518"     = 'Schema-Admins'
    'S-1-5-32-544' = 'Administratoren'
    'S-1-5-32-548' = 'Konten-Operatoren'
    'S-1-5-32-549' = 'Server-Operatoren'
    'S-1-5-32-551' = 'Sicherungs-Operatoren'
}
$gruppen = @()
$nichtGelesen = @()
foreach ($s in $privSids.Keys) {
    try { $g = Get-ADGroup -Identity $s @ad; $gruppen += [pscustomobject]@{ Gruppe = $g; Anzeige = $g.Name } }
    catch {
        # Gruppen anderer Domänen (z. B. Organisations-Admins in einer untergeordneten Domäne) gibt es hier nicht; alles andere ist ein Lesefehler
        if ($_.Exception.GetType().Name -ne 'ADIdentityNotFoundException') { $nichtGelesen += [pscustomobject][ordered]@{ Gruppe = $privSids[$s]; Feststellung = 'Nicht geprüft - Gruppe nicht lesbar (siehe Umgebung)'; Details = $_.Exception.Message } }
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
Write-Host '  Auswertung ...'
$a = @()
if ($aktiv.Count -gt $MaxAdmins) { $a = [pscustomobject]@{ Einstellung = 'Aktive privilegierte Konten'; Ist = $aktiv.Count; Empfohlen = "höchstens $MaxAdmins" } }
Befund 'P1' 'Anzahl' "Mehr als $MaxAdmins aktive privilegierte Konten ($($aktiv.Count))" 'Mittel' $a `
    'Jedes Konto mit Administratorrechten ist ein Ziel. Je mehr es gibt, desto größer ist die Angriffsfläche und desto schwerer lässt sich nachvollziehen, wer wofür Rechte braucht. Gezählt werden auch Mitglieder verschachtelter Gruppen.' `
    'Liste unten prüfen: Wer braucht Domänen-Adminrechte im Alltag? Rechte auf das nötige Maß senken, für selten benötigte Aufgaben delegierte Rechte oder zeitlich begrenzte Mitgliedschaft nutzen.'

Befund 'P2' 'Inaktivität' "Aktive privilegierte Konten ohne Anmeldung seit $InaktivTage Tagen" 'Mittel' `
    @($aktiv | Where-Object {
            $grenzeAnm = $jetzt.AddDays(-$InaktivTage)
            if ($_.LastLogonDate) { $_.LastLogonDate -lt $grenzeAnm }
            else { -not $_.whenCreated -or ([datetime]$_.whenCreated) -lt $grenzeAnm }   # nie angemeldet: nur melden, wenn das Konto älter als die Frist ist
        } | ForEach-Object { Zeile $_ @{ Hinweis = $(if ($_.LastLogonDate) { '' } else { 'nie angemeldet, angelegt am ' + (Datum $_.whenCreated '?') }) } }) `
    'Ein Adminkonto, das niemand benutzt, wird auch nicht überwacht. Gelangt ein Angreifer an sein Kennwort, fällt die Nutzung kaum auf. Oft sind es Konten ausgeschiedener Mitarbeiter oder alte Testkonten. Der Zeitpunkt wird zwischen den Domänencontrollern nur alle 14 Tage abgeglichen.' `
    'Konten mit den Verantwortlichen klären. Nicht mehr benötigte Konten aus den Gruppen entfernen und deaktivieren.'

Befund 'P3' 'Kennwort' "Privilegierte Konten mit Kennwort älter als $KennwortAlterTage Tage" 'Mittel' `
    @($aktiv | Where-Object { -not $_.PasswordNeverExpires -and $_.PasswordLastSet -and $_.PasswordLastSet -lt $jetzt.AddDays(-$KennwortAlterTage) } | ForEach-Object { Zeile $_ }) `
    'Je älter ein Kennwort ist, desto länger konnte es abgegriffen, mitgelesen oder über eine Datensammlung bekannt werden. Für Administratorkonten ist ein selten gewechseltes Kennwort besonders riskant. Konten ohne Kennwortablauf stehen unter P4.' `
    'Kennwort ändern. Für Konten, die ein Mensch nutzt, ein langes, nur dafür verwendetes Kennwort; für Dienstkonten verwaltete Dienstkonten (gMSA) einsetzen.'

Befund 'P4' 'Kennwort' 'Privilegierte Konten, deren Kennwort nie abläuft' 'Hoch' `
    @($aktiv | Where-Object PasswordNeverExpires | ForEach-Object { Zeile $_ }) `
    'Bei diesen Konten ist der Kennwortablauf abgeschaltet. Ein einmal bekannt gewordenes Kennwort bleibt dauerhaft gültig. Bei Administratorkonten ist das die Folge von Bequemlichkeit oder von Diensten, die davon abhängen.' `
    'Kennwortablauf einschalten oder das Konto durch ein gMSA ersetzen. Bei Dienstkonten prüfen, welcher Dienst das Konto nutzt, und das Kennwort danach ändern.'

Befund 'P5' 'Trennung' 'Privilegierte Konten mit E-Mail-Adresse' 'Mittel' `
    @($aktiv | Where-Object { $_.mail } | ForEach-Object { Zeile $_ @{ 'E-Mail' = $_.mail } }) `
    'Wer mit demselben Konto Mails liest und Server verwaltet, setzt sein Adminkonto jedem Phishing-Link und jedem Anhang aus. Ein Klick genügt dann für die Übernahme der Domäne. Admin- und Alltagskonto sollten getrennt sein.' `
    'Je Administrator ein eigenes Konto ohne Postfach und ohne Internetnutzung anlegen und das Alltagskonto aus den privilegierten Gruppen nehmen.'

$p6 = @()
if ($schutzFehler) { $p6 = [pscustomobject][ordered]@{ Konto = 'alle'; Feststellung = 'Nicht geprüft - Gruppe "Geschützte Benutzer" nicht lesbar'; Details = $schutzFehler } }
elseif ($schutzGruppe) {
    $p6 = @($aktiv | Where-Object { $_.Typ -eq 'Benutzer' -and -not $geschuetzt.ContainsKey($_.SamAccountName) -and $_.SID.Value -notmatch '-500$' } | ForEach-Object { Zeile $_ })
}
Befund 'P6' 'Schutz' 'Privilegierte Konten außerhalb der Gruppe "Geschützte Benutzer"' 'Niedrig' $p6 `
    'Mitglieder der Gruppe "Geschützte Benutzer" bekommen von Windows zusätzlichen Schutz: keine NTLM-Anmeldung, keine zwischengespeicherten Anmeldedaten, kurze Kerberos-Tickets. Das schützt Administratorkonten vor Diebstahl der Anmeldedaten. Das eingebaute Administratorkonto ist ausgenommen, ebenso Computerkonten und gMSA (für Maschinen- und Dienstkonten ist die Gruppe nicht vorgesehen).' `
    'Konten nach einem Test in die Gruppe aufnehmen. Vorsicht bei Konten, die sich per NTLM, mit Delegierung oder auf älteren Systemen anmelden müssen: Sie funktionieren dann nicht mehr.'

$p7 = @()
$p7Fehler = @()
foreach ($u in ($aktiv | Where-Object { $_.Typ -eq 'Benutzer' })) {
    $r = $null
    try { $r = Get-ADUserResultantPasswordPolicy -Identity $u.DistinguishedName @ad }
    catch { $p7Fehler += [pscustomobject][ordered]@{ Konto = $u.SamAccountName; Feststellung = 'Nicht geprüft - wirksame Kennwortrichtlinie nicht lesbar'; Details = $_.Exception.Message }; continue }
    $laenge = if ($r) { $r.MinPasswordLength } else { $standard.MinPasswordLength }
    if ($laenge -lt $MindestLaenge) {
        $p7 += Zeile $u @{ 'Wirksame Richtlinie' = $(if ($r) { $r.Name } else { 'Standard der Domäne' }); 'Mindestlänge' = "$laenge Zeichen"; Empfohlen = "mindestens $MindestLaenge Zeichen" }
    }
}
$p7 += $p7Fehler
Befund 'P7' 'Kennwort' "Wirksame Kennwortrichtlinie privilegierter Konten unter $MindestLaenge Zeichen" 'Mittel' $p7 `
    'Für ein Konto gilt entweder die Kennwortrichtlinie der Domäne oder eine abweichende Richtlinie (Password Settings Object). Hier ist die wirksame Mindestlänge für Administratoren kürzer als empfohlen. Kurze Kennwörter lassen sich schneller erraten oder berechnen.' `
    'Für privilegierte Konten eine eigene Richtlinie mit längerem Mindestkennwort anlegen (Password Settings Object, Priorität vor der Domänenrichtlinie) oder die Domänenrichtlinie anheben.'

if ($nichtGelesen.Count) {
    Befund 'P8' 'Abfrage' 'Privilegierte Gruppen, die nicht gelesen werden konnten' 'Info' $nichtGelesen `
        'Für diese Gruppen fehlen die Mitglieder. Die übrigen Prüfpunkte sind dadurch unvollständig, das heißt nicht, dass dort alles in Ordnung ist.' `
        'Berechtigung des abfragenden Kontos und Erreichbarkeit des Domänencontrollers prüfen.'
}

# ------------------------------------------------------------------ Bericht
$liste = $priv | ForEach-Object {
    Zeile $_ @{ 'Kennwort läuft nie ab' = JaNein $_.PasswordNeverExpires; 'E-Mail' = $_.mail; 'Geschützte Benutzer' = $(if ($schutzGruppe) { JaNein $geschuetzt.ContainsKey($_.SamAccountName) } else { 'Gruppe fehlt' }); Angelegt = Datum $_.whenCreated }
}
$jeGruppe = foreach ($p in $gruppen) {
    $namen = @($priv | Where-Object { $von[$_.SamAccountName] -contains $p.Anzeige } | ForEach-Object { $_.SamAccountName })
    [pscustomobject][ordered]@{ Gruppe = $p.Anzeige; 'Konten (auch verschachtelt)' = $namen.Count; 'davon aktiv' = @($priv | Where-Object { $_.Enabled -and ($von[$_.SamAccountName] -contains $p.Anzeige) }).Count; Konten = ($namen -join ', ') }
}
$umgebung = [ordered]@{
    'Domäne (NetBIOS)'          = "$($dom.DNSRoot) ($($dom.NetBIOSName))"
    'Privilegierte Konten (aktiv / gesamt)' = "$($aktiv.Count) / $($priv.Count) (davon Computer oder gMSA: $(@($priv | Where-Object { $_.Typ -ne 'Benutzer' }).Count))"
    'Gruppe "Geschützte Benutzer"' = $(if ($schutzGruppe) { 'vorhanden' } else { 'nicht vorhanden (Domäne unter Windows Server 2012 R2)' })
    'Standard-Kennwortrichtlinie' = "Mindestlänge $($standard.MinPasswordLength), Komplexität $(JaNein $standard.ComplexityEnabled)"
    'Schwellen dieses Berichts' = "mehr als $MaxAdmins Konten, inaktiv ab $InaktivTage Tagen, Kennwort älter als $KennwortAlterTage Tage, Mindestlänge $MindestLaenge"
}
$basis = BerichtSchreiben -Name 'Privilegierte-Konten-Check' -Datei 'Privilegierte-Konten-Check' -Bezug $dom.DNSRoot -Umgebung $umgebung `
    -Abschnitte ([ordered]@{ 'Privilegierte Gruppen' = $jeGruppe; 'Alle privilegierten Konten' = $liste }) `
    -Fuss 'Grundlage sind die Angaben im Active Directory. Der Zeitpunkt der letzten Anmeldung wird zwischen Domänencontrollern nur alle 14 Tage abgeglichen. Der Bericht zeigt Auffälligkeiten anhand fester Regeln, ersetzt keine Sicherheitsprüfung und erhebt keinen Anspruch auf Vollständigkeit.'
if ($Csv) { $liste | Export-Csv -Path "${basis}_Konten.csv" -NoTypeInformation -Delimiter ';' -Encoding UTF8 }
if ($PassThru) { $Befunde }
