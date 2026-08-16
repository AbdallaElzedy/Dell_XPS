<#
.SYNOPSIS
    Finds the software bleeding power while a Windows laptop is in Modern Standby.

.DESCRIPTION
    Runs the full diagnostic pass in one go and prints a ranked report:

      1. What is currently pinning the machine awake      (powercfg /requests)
      2. Armed wake timers and wake-capable devices
      3. How much standby the machine actually got
      4. Hardware DRIPS residency
      5. THE BLEEDING SOFTWARE, ranked by share of standby time held
      6. Measured standby drain in milliwatts
      7. Recent standby sessions from the event log
      8. A verdict against known-good thresholds

    Step 5 is the one no other tool gives you. It parses the sleep study report's
    embedded JSON and attributes standby time down to individual application
    packages, which is where vendor bloatware shows up.

.PARAMETER Days
    Days of history to request from the sleep study. Default 7.

.PARAMETER ReportPath
    Where to write the sleep study HTML. Defaults to a temp file that is deleted
    afterwards unless -KeepReport is set.

.PARAMETER KeepReport
    Keep the generated sleep study HTML instead of deleting it.

.EXAMPLE
    .\Find-PowerBleed.ps1

.EXAMPLE
    .\Find-PowerBleed.ps1 -Days 14 -KeepReport

.NOTES
    Author    : Abdalla Elzedy
    Version   : 1.1
    Published : 2026-08-15
    License   : MIT

    Requires an elevated (Administrator) session.
    Works on Windows PowerShell 5.1 and PowerShell 7+.
    Read-only: this script changes nothing.

    Copyright (c) 2026 Abdalla Elzedy. Released under the MIT License.
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 28)][int]$Days = 7,
    [string]$ReportPath,
    [switch]$KeepReport
)

$ErrorActionPreference = 'Stop'

# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
function Write-Head {
    param([string]$Text)
    Write-Host ''
    Write-Host ('-' * 74) -ForegroundColor DarkGray
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host ('-' * 74) -ForegroundColor DarkGray
}

function Write-Good { param([string]$T) Write-Host "  $T" -ForegroundColor Green }
function Write-Bad  { param([string]$T) Write-Host "  $T" -ForegroundColor Red }
function Write-Warn { param([string]$T) Write-Host "  $T" -ForegroundColor Yellow }
function Write-Dim  { param([string]$T) Write-Host "  $T" -ForegroundColor DarkGray }

# Appx package full names look like  Publisher.App_1.2.3.0_x64__hash
function Get-ShortName {
    param([string]$Name)
    if ($Name -match '^(?<fam>[^_]+)_[\d.]+_[^_]+__[a-z0-9]+$') { return $Matches['fam'] }
    return $Name
}

# Resolve powercfg.exe by absolute path rather than trusting PATH. A broken or
# truncated PATH is common on machines that need this script in the first place,
# and a diagnostic tool should not die of the thing it might be diagnosing.
function Resolve-PowerCfg {
    $candidates = @()
    if (-not [Environment]::Is64BitProcess -and [Environment]::Is64BitOperatingSystem) {
        # 32-bit process on 64-bit Windows: System32 silently redirects to
        # SysWOW64, which has no powercfg.exe. Sysnative reaches the real one.
        $candidates += (Join-Path $env:SystemRoot 'Sysnative\powercfg.exe')
    }
    $candidates += (Join-Path $env:SystemRoot 'System32\powercfg.exe')
    $candidates += 'C:\Windows\System32\powercfg.exe'
    foreach ($c in $candidates) {
        if ($c -and (Test-Path -LiteralPath $c)) { return $c }
    }
    $viaPath = Get-Command powercfg.exe -ErrorAction SilentlyContinue
    if ($viaPath) { return $viaPath.Source }
    return $null
}

# --------------------------------------------------------------------------
# elevation
# --------------------------------------------------------------------------
$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning 'This session is not elevated.'
    Write-Warning 'powercfg /requests, /waketimers and /sleepstudy all need Administrator.'
    Write-Warning 'Re-run from an Administrator terminal.'
    return
}

$PowerCfg = Resolve-PowerCfg
if ($null -eq $PowerCfg) {
    Write-Warning 'powercfg.exe could not be found, not even at C:\Windows\System32.'
    Write-Warning 'That is a broken Windows installation, not a power problem.'
    return
}

Write-Host ''
Write-Host '  POWER BLEED REPORT' -ForegroundColor White
Write-Host ("  {0}  |  {1}" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyy-MM-dd HH:mm')) -ForegroundColor DarkGray
Write-Host '  Find-PowerBleed 1.1  |  Abdalla Elzedy  |  MIT' -ForegroundColor DarkGray

# A missing System32 on PATH is a real machine fault worth surfacing, even
# though this script routes around it.
$system32 = Join-Path $env:SystemRoot 'System32'
$onPath = @($env:PATH -split ';' | Where-Object { $_.TrimEnd('\') -ieq $system32.TrimEnd('\') })
if ($onPath.Count -eq 0) {
    Write-Host ''
    Write-Warning "$system32 is not on this session's PATH."
    Write-Warning 'Unrelated to power, but it breaks ping, ipconfig, sfc and most system tools.'
    Write-Warning 'Check: (Get-Item "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment").GetValueNames()'
    Write-Warning 'If the machine PATH value is missing there, restore it and restart explorer.exe.'
    Write-Host   '  Continuing anyway, this script calls powercfg by absolute path.' -ForegroundColor DarkGray
}

# --------------------------------------------------------------------------
# 1. what is pinning the machine awake right now
# --------------------------------------------------------------------------
Write-Head '1. AWAKE BLOCKERS  (powercfg /requests)'

$category = $null
$requests = @()
foreach ($line in @(& $PowerCfg /requests)) {
    $t = $line.Trim()
    if ($t -match '^[A-Z]+:$')          { $category = $t.TrimEnd(':'); continue }
    if ($t -eq '' -or $t -eq 'None.')   { continue }
    $requests += [pscustomobject]@{ Category = $category; Requester = $t }
}

if ($requests.Count -eq 0) {
    Write-Good 'Clear. Nothing is holding the machine awake.'
} else {
    Write-Bad ('{0} active power request(s):' -f $requests.Count)
    foreach ($r in $requests) {
        Write-Host ('    [{0}] {1}' -f $r.Category, $r.Requester) -ForegroundColor Red
    }
    Write-Host ''
    Write-Warn 'A SYSTEM request defeats the idle sleep timeout completely.'
    Write-Dim  'It does NOT block an explicit lid close, which is why a machine can'
    Write-Dim  'sleep on the lid yet never once sleep on its own.'
}

# --------------------------------------------------------------------------
# 2. wake timers and wake-armed devices
# --------------------------------------------------------------------------
Write-Head '2. WAKE SOURCES'

$timers = @(& $PowerCfg /waketimers) | Where-Object { $_.Trim() -ne '' }
if (($timers -join ' ') -match 'no active wake timers') {
    Write-Good 'No armed wake timers.'
} else {
    Write-Warn 'Armed wake timers:'
    foreach ($t in $timers) { Write-Host ('    ' + $t.Trim()) -ForegroundColor Yellow }
}

Write-Host ''
$armed = @(& $PowerCfg /devicequery wake_armed) | Where-Object { $_.Trim() -ne '' }
if ($armed.Count -eq 0 -or ($armed -join ' ').Trim() -eq 'NONE') {
    Write-Good 'No devices are armed to wake the machine.'
} else {
    Write-Warn 'Devices armed to wake the machine:'
    foreach ($d in $armed) { Write-Host ('    ' + $d.Trim()) -ForegroundColor Yellow }
    Write-Dim 'Disarming a Thunderbolt controller also stops a dock from waking it.'
}

Write-Host ''
Write-Dim 'Note: powercfg /lastwake reports 0 on Modern Standby machines no matter'
Write-Dim 'what happened. It reads an S3-era structure that S0ix never populates.'

# --------------------------------------------------------------------------
# 3. generate and parse the sleep study
# --------------------------------------------------------------------------
Write-Head ('3. STANDBY COVERAGE  (sleep study, last {0} days)' -f $Days)

$temp = $false
if (-not $ReportPath) {
    $ReportPath = Join-Path $env:TEMP ('powerbleed-{0}.html' -f [guid]::NewGuid().ToString('N'))
    $temp = $true
}

Write-Dim 'Generating sleep study, this takes a few seconds...'
& $PowerCfg /sleepstudy /output $ReportPath /duration $Days | Out-Null
if (-not (Test-Path $ReportPath)) { throw "Sleep study was not created at $ReportPath" }

# The V3 report is template-driven. Every number lives in a JS object called
# LocalSprData; the visible HTML is only scaffolding. Read with an explicit
# UTF-8 decode, because PowerShell 5.1 assumes ANSI for files without a BOM.
$raw = [System.IO.File]::ReadAllText($ReportPath, [System.Text.Encoding]::UTF8)

$anchor = $raw.IndexOf('LocalSprData')
if ($anchor -lt 0) { throw 'LocalSprData not found. Unexpected sleep study format.' }

$start  = $raw.IndexOf('{', $anchor)
$depth  = 0
$i      = $start
$inStr  = $false
$escape = $false
while ($i -lt $raw.Length) {
    $c = $raw[$i]
    if ($inStr) {
        if ($escape)          { $escape = $false }
        elseif ($c -eq '\')   { $escape = $true }
        elseif ($c -eq '"')   { $inStr = $false }
    } else {
        if     ($c -eq '"')   { $inStr = $true }
        elseif ($c -eq '{')   { $depth++ }
        elseif ($c -eq '}')   { $depth--; if ($depth -eq 0) { break } }
    }
    $i++
}

try {
    $spr = $raw.Substring($start, $i - $start + 1) | ConvertFrom-Json
} catch {
    throw ("Could not parse the sleep study JSON ({0}). Try PowerShell 7, which " +
           "handles large JSON documents better." -f $_.Exception.Message)
}

if ($temp -and -not $KeepReport) { Remove-Item $ReportPath -Force -ErrorAction SilentlyContinue }
elseif ($KeepReport)             { Write-Dim ("Sleep study kept at {0}" -f $ReportPath) }

# Type 2 = Sleep. Duration is in 100-nanosecond ticks.
$sleepSessions = @($spr.ScenarioInstances | Where-Object { $_.Type -eq 2 })
$totalTicks    = 0
foreach ($s in $sleepSessions) { $totalTicks += $s.Duration }

$windowStart = [datetime]$spr.ReportInformation.ReportStartTime
$windowEnd   = [datetime]$spr.ReportInformation.ScanTime
$windowHours = ($windowEnd - $windowStart).TotalHours

Write-Host ('    Machine        : {0} {1}' -f $spr.SystemInformation.SystemManufacturer,
                                              $spr.SystemInformation.SystemProductName)
Write-Host ('    Report window  : {0:n1} hours' -f $windowHours)
Write-Host ('    Standby sessions: {0}' -f $sleepSessions.Count)

if ($totalTicks -le 0) {
    Write-Host ''
    Write-Bad 'THE MACHINE NEVER ENTERED STANDBY during this window.'
    Write-Warn 'That is a configuration fault, not an efficiency one. Check the lid'
    Write-Warn 'close action and the idle sleep timeout before anything else:'
    Write-Dim  '  powercfg /q SCHEME_CURRENT SUB_BUTTONS 5ca83367-6e45-459f-a27b-476b1d01c936'
    Write-Dim  '  powercfg /q SCHEME_CURRENT SUB_SLEEP   STANDBYIDLE'
    Write-Dim  'A setting that is missing from that output is hidden, not absent.'
    return
}

$standbyHours = [TimeSpan]::FromTicks($totalTicks).TotalHours
$coverage     = 100 * $standbyHours / $windowHours

Write-Host ('    Time in standby : {0:n1} hours' -f $standbyHours)
if ($coverage -lt 10) {
    Write-Bad ('Standby coverage: {0:n1}% of the window. Very low.' -f $coverage)
} else {
    Write-Host ('    Standby coverage: {0:n1}% of the window' -f $coverage)
}

# --------------------------------------------------------------------------
# 4. hardware DRIPS residency
# --------------------------------------------------------------------------
Write-Head '4. HARDWARE DRIPS RESIDENCY'

$noDripsTicks = 0
foreach ($s in $sleepSessions) {
    $soc = $s.BlockerGroups | Where-Object { $_.Name -eq 'SOC Subsystems' }
    foreach ($b in @($soc.Blockers)) { $noDripsTicks += $b.ActiveTime }
}
$drips = 100 * (1 - ($noDripsTicks / $totalTicks))

if     ($drips -ge 90) { Write-Good ('{0:n1}% - the silicon is idling correctly.' -f $drips) }
elseif ($drips -ge 70) { Write-Warn ('{0:n1}% - marginal.' -f $drips) }
else                   { Write-Bad  ('{0:n1}% - something is holding hardware awake.' -f $drips) }

Write-Dim 'Good DRIPS does not mean good standby. A machine can hold 97% DRIPS'
Write-Dim 'while burning five times its power budget. Keep reading.'

# --------------------------------------------------------------------------
# 5. THE BLEEDING SOFTWARE
# --------------------------------------------------------------------------
Write-Head '5. BLEEDING SOFTWARE  (ranked by share of standby time held)'

$agg = @{}
function Add-Bleeder {
    param([string]$Name, [string]$Group, [long]$Ticks, [int]$Level)
    if (-not $agg.ContainsKey($Name)) {
        $agg[$Name] = [pscustomobject]@{
            Name = $Name; Group = $Group; Ticks = [long]0; Sessions = 0; Level = 0
        }
    }
    $agg[$Name].Ticks    += $Ticks
    $agg[$Name].Sessions += 1
    if ($Level -gt $agg[$Name].Level) { $agg[$Name].Level = $Level }
}

foreach ($s in $sleepSessions) {
    foreach ($g in @($s.BlockerGroups)) {
        if ($g.Name -eq 'SOC Subsystems') { continue }   # hardware, covered above
        foreach ($b in @($g.Blockers)) {
            $kids = @($b.Children)
            if ($kids.Count -gt 0) {
                # Children carry the real application identity. Broker
                # Infrastructure in particular reports per-package children.
                foreach ($c in $kids) {
                    Add-Bleeder -Name ('{0} -> {1}' -f $b.Name, (Get-ShortName $c.Name)) `
                                -Group $g.Name -Ticks $c.ActiveTime -Level $b.ActivityLevel
                }
            } else {
                Add-Bleeder -Name (Get-ShortName $b.Name) -Group $g.Name `
                            -Ticks $b.ActiveTime -Level $b.ActivityLevel
            }
        }
    }
}

$ranked = $agg.Values |
    Where-Object { $_.Ticks -gt 0 } |
    Sort-Object Ticks -Descending |
    Select-Object -First 15 |
    ForEach-Object {
        $share = 100 * $_.Ticks / $totalTicks
        if     ($share -ge 25) { $verdict = 'CULPRIT' }
        elseif ($share -ge 5)  { $verdict = 'suspect' }
        else                   { $verdict = 'noise'   }
        [pscustomobject]@{
            Share    = '{0,6:n1}%' -f $share
            Active   = '{0,8:n1}s' -f [TimeSpan]::FromTicks($_.Ticks).TotalSeconds
            Sessions = $_.Sessions
            Verdict  = $verdict
            Component = $_.Name
        }
    }

if ($ranked.Count -eq 0) {
    Write-Good 'No software activators recorded. Nothing is bleeding.'
} else {
    $ranked | Format-Table -AutoSize | Out-String -Width 200 | Write-Host
    $culprits = @($ranked | Where-Object { $_.Verdict -eq 'CULPRIT' })
    if ($culprits.Count -gt 0) {
        Write-Bad 'Anything marked CULPRIT is holding the software stack awake for a'
        Write-Bad 'quarter or more of every standby session. That is your bleed.'
        Write-Host ''
        Write-Dim 'To remove a Store-packaged offender:'
        Write-Dim '  Get-AppxPackage -AllUsers | Where-Object Name -match ''<part-of-name>'''
        Write-Dim '  Get-AppxPackage -AllUsers -Name ''<exact.name>'' | Remove-AppxPackage -AllUsers'
    } else {
        Write-Good 'No single component dominates standby. Nothing obvious to remove.'
    }
    Write-Host ''
    Write-Dim 'BI = Broker Infrastructure (background app runtime). WNS = push'
    Write-Dim 'notifications. NCSI = network connectivity checks. TCPIP = network'
    Write-Dim 'stack. WU = Windows Update. The first is where bloatware lives; the'
    Write-Dim 'rest are normal at low single-digit percentages.'
    Write-Host ''
    Write-Dim 'This table is historical. An app you removed today keeps appearing'
    Write-Dim 'until it ages out of the report window, so re-run with a smaller'
    Write-Dim '-Days after a removal to confirm the bleed actually stopped.'
}

# --------------------------------------------------------------------------
# 6. measured standby drain
# --------------------------------------------------------------------------
Write-Head '6. MEASURED DRAIN'

# Note the spelling of StartChargeCapcity. That typo is in the report format.
$intervals = @()
foreach ($d in @($spr.EnergyDrains | Where-Object { -not $_.OnAc })) {
    $h = ([datetime]$d.EndTimestamp - [datetime]$d.StartTimestamp).TotalHours
    if ($h -ge 0.5) {
        $mwh = $d.StartChargeCapcity - $d.EndChargeCapacity
        if ($mwh -gt 0) {
            $intervals += [pscustomobject]@{
                Start = ([datetime]$d.StartTimestamp).ToLocalTime()
                Hours = [math]::Round($h, 1)
                mWh   = $mwh
                mW    = [math]::Round($mwh / $h, 0)
            }
        }
    }
}

if ($intervals.Count -eq 0) {
    Write-Dim 'No battery intervals long enough to measure. Run the machine on'
    Write-Dim 'battery with the lid closed for a few hours, then re-run this.'
} else {
    $longest = $intervals | Sort-Object Hours -Descending | Select-Object -First 5
    $longest | Format-Table -AutoSize | Out-String -Width 200 | Write-Host
    Write-Dim 'Longest interval first. Short intervals include active use, so a'
    Write-Dim 'high figure on a sub-hour row is normal. Judge by the top row.'
    Write-Host ''

    $worst = ($longest | Select-Object -First 1).mW
    if     ($worst -gt 300) { Write-Bad  ('{0} mW. Broken. Budget is 50-100 mW.' -f $worst) }
    elseif ($worst -gt 150) { Write-Warn ('{0} mW. High. Budget is 50-100 mW.'   -f $worst) }
    else                    { Write-Good ('{0} mW. Within budget.'               -f $worst) }
    Write-Dim 'Above 500 mW is what cooks a laptop sealed in a bag.'
}

# --------------------------------------------------------------------------
# 7. recent standby sessions from the event log
# --------------------------------------------------------------------------
Write-Head '7. RECENT STANDBY SESSIONS  (Kernel-Power 507)'

# Only these two exit reason codes are verified; others print as raw codes.
$reasons = @{ 15 = 'Lid'; 28 = 'Power source changed' }

$events = @(Get-WinEvent -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Microsoft-Windows-Kernel-Power'
    Id           = 507
    StartTime    = (Get-Date).AddDays(-$Days)
} -ErrorAction SilentlyContinue | Select-Object -First 10)

if ($events.Count -eq 0) {
    Write-Warn 'No standby exit events. The machine is not entering standby at all.'
} else {
    $rows = foreach ($e in $events) {
        $d = @{}
        foreach ($node in ([xml]$e.ToXml()).Event.EventData.Data) { $d[$node.Name] = $node.'#text' }

        $dur = [double]$d['DurationInUs']
        if ($dur -gt 0) { $res = 100 * [double]$d['DripsResidencyInUs'] / $dur } else { $res = 0 }

        $code = [int]$d['Reason']
        if ($reasons.ContainsKey($code)) { $why = $reasons[$code] } else { $why = "code $code" }

        [pscustomobject]@{
            When    = $e.TimeCreated.ToString('MM-dd HH:mm')
            Slept   = $d['SleepEntered']
            Minutes = '{0,6:n1}' -f ($dur / 60000000)
            DRIPS   = '{0,5:n1}%' -f $res
            Drained = $d['EnergyDrain']
            ExitWhy = $why
        }
    }
    $rows | Format-Table -AutoSize | Out-String -Width 200 | Write-Host
    Write-Dim 'SleepEntered=false means it never actually reached standby.'
    Write-Dim 'Before blaming a spurious wake, check ExitWhy: moving the charger'
    Write-Dim 'ends a standby session and looks identical to one.'
}

# --------------------------------------------------------------------------
# 8. verdict
# --------------------------------------------------------------------------
Write-Head '8. VERDICT'

$problems = @()
if ($requests.Count -gt 0) { $problems += 'Something is holding a power request (blocks idle sleep).' }
if ($coverage -lt 10)      { $problems += ('Standby coverage is only {0:n1}% of the window.' -f $coverage) }
if ($drips -lt 70)         { $problems += ('DRIPS residency is {0:n1}%, hardware is not idling.' -f $drips) }
$top = $ranked | Where-Object { $_.Verdict -eq 'CULPRIT' } | Select-Object -First 1
if ($null -ne $top)        { $problems += ('{0} holds {1} of standby time.' -f $top.Component, $top.Share.Trim()) }
if ($intervals.Count -gt 0) {
    $w = ($intervals | Sort-Object Hours -Descending | Select-Object -First 1).mW
    if ($w -gt 300)        { $problems += ('Standby drain measured at {0} mW against a 50-100 mW budget.' -f $w) }
}

if ($problems.Count -eq 0) {
    Write-Good 'Nothing found. Standby is behaving.'
} else {
    Write-Bad ('{0} problem(s) found:' -f $problems.Count)
    $n = 0
    foreach ($p in $problems) { $n++; Write-Host ('    {0}. {1}' -f $n, $p) -ForegroundColor Red }
}
Write-Host ''
