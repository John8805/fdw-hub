#Requires -Version 5.1
<#
  fdw-hub 憑證保護與啟動包裝

    .\dbhub.ps1 init      把 .env 裡的帳密加密成 .env.enc，並從 .env 移除
    .\dbhub.ps1 show      解密列出目前保存的變數
    .\dbhub.ps1 set       新增或修改單一變數（互動輸入，不回顯）
    .\dbhub.ps1 apply     完整套用流程 build -> check -> tunnel -> apply -> dbhub
    .\dbhub.ps1 up        啟動全部服務
    .\dbhub.ps1 stop      停止全部服務
    .\dbhub.ps1 check     只驗證設定檔
    .\dbhub.ps1 <args>    其餘參數原樣傳給 docker compose

  加密方式：AES-128-CBC，密文前 16 bytes 是 IV，整體以 Base64 存放。
  金鑰在 ssh\hub.key（32 個十六進位字元），首次 init 時隨機產生。
  容器透過 /ssh-src/hub.key 讀同一把金鑰。

  防護等級：擋不經意讀取，擋不住同時拿到 hub.key 的人。
  .env.enc 與 ssh\ 目錄都不要進版控。
#>

$ErrorActionPreference = 'Stop'

$Root     = $PSScriptRoot
$EnvFile  = Join-Path $Root '.env'
$EncFile  = Join-Path $Root '.env.enc'
$KeyFile  = Join-Path $Root 'ssh\hub.key'

# 不加密的設定項，維持留在 .env
$PlainKeys = @('HUB_PORT', 'DBHUB_PORT', 'HUB_BIND')


function New-Key {
    $b = [byte[]]::new(16)
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($b) } finally { $rng.Dispose() }
    $hex = ($b | ForEach-Object { $_.ToString('x2') }) -join ''
    $hex | Set-Content $KeyFile -Encoding ascii -NoNewline
}

function Get-Key {
    if (-not (Test-Path $KeyFile)) { throw "$KeyFile 不存在，先執行 .\dbhub.ps1 init" }
    $hex = (Get-Content $KeyFile -Raw).Trim()
    if ($hex.Length -ne 32) { throw "$KeyFile 格式錯誤，應為 32 個十六進位字元" }
    $k = [byte[]]::new(16)
    for ($i = 0; $i -lt 16; $i++) {
        $k[$i] = [Convert]::ToByte($hex.Substring($i * 2, 2), 16)
    }
    return $k
}

function Protect-Text([string]$Text) {
    $aes = [System.Security.Cryptography.Aes]::Create()
    try {
        $aes.Key = Get-Key
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.GenerateIV()
        $plain = [Text.Encoding]::UTF8.GetBytes($Text)
        $enc = $aes.CreateEncryptor()
        try { $cipher = $enc.TransformFinalBlock($plain, 0, $plain.Length) }
        finally { $enc.Dispose() }
        return [Convert]::ToBase64String([byte[]]($aes.IV + $cipher))
    } finally { $aes.Dispose() }
}

function Unprotect-Text([string]$B64) {
    $raw = [Convert]::FromBase64String($B64)
    $aes = [System.Security.Cryptography.Aes]::Create()
    try {
        $aes.Key = Get-Key
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.IV = $raw[0..15]
        $dec = $aes.CreateDecryptor()
        try { $plain = $dec.TransformFinalBlock($raw, 16, $raw.Length - 16) }
        finally { $dec.Dispose() }
        return [Text.Encoding]::UTF8.GetString($plain)
    } finally { $aes.Dispose() }
}

function Read-Secrets {
    if (-not (Test-Path $EncFile)) {
        throw "$EncFile 不存在。先執行：.\dbhub.ps1 init"
    }
    $json = Unprotect-Text (Get-Content $EncFile -Raw).Trim()
    $obj = $json | ConvertFrom-Json
    $h = @{}
    foreach ($p in $obj.PSObject.Properties) { $h[$p.Name] = $p.Value }
    return $h
}

function Write-Secrets([hashtable]$Secrets) {
    $json = $Secrets | ConvertTo-Json -Compress
    Protect-Text $json | Set-Content $EncFile -Encoding ascii -NoNewline
}

function Import-ComposeEnv {
    # 只有 hub 容器的 POSTGRES_PASSWORD 走 compose 插值，其餘由 hubctl 在容器內自己解密
    $s = Read-Secrets
    if (-not $s.ContainsKey('HUB_ADMIN_PASSWORD')) { throw '.env.enc 缺少 HUB_ADMIN_PASSWORD' }
    [Environment]::SetEnvironmentVariable('HUB_ADMIN_PASSWORD', $s['HUB_ADMIN_PASSWORD'], 'Process')
}

function Invoke-Init {
    if (-not (Test-Path $EnvFile)) { throw ".env 不存在，沒有東西可以加密" }
    if (-not (Test-Path $KeyFile)) {
        New-Key
        Write-Host "已產生金鑰 $KeyFile"
    }
    if (Test-Path $EncFile) {
        $a = Read-Host "$EncFile 已存在，覆蓋？(y/N)"
        if ($a -ne 'y') { Write-Host '取消'; return }
    }

    $secrets = @{}
    $keep = [System.Collections.Generic.List[string]]::new()
    foreach ($line in (Get-Content $EnvFile -Encoding UTF8)) {
        if ($line -match '^\s*#' -or $line -notmatch '=') { $keep.Add($line); continue }
        $parts = $line -split '=', 2
        $k = $parts[0].Trim()
        $v = $parts[1].Trim().Trim("'").Trim('"')
        if ($PlainKeys -contains $k -or -not $v) { $keep.Add($line); continue }
        $secrets[$k] = $v
        $keep.Add("# $k  -> .env.enc")
    }

    if ($secrets.Count -eq 0) { Write-Host '.env 裡沒有找到需要加密的值'; return }

    Write-Host "將加密下列 $($secrets.Count) 個變數（值不顯示）："
    $secrets.Keys | Sort-Object | ForEach-Object { Write-Host "  $_" }
    $a = Read-Host '確定並從 .env 移除這些值？(y/N)'
    if ($a -ne 'y') { Write-Host '取消'; return }

    Write-Secrets $secrets
    # 5.1 的 -Encoding utf8 會加 BOM，docker compose 讀 .env 會出錯，改用不帶 BOM 的寫法
    [IO.File]::WriteAllLines($EnvFile, [string[]]$keep, [Text.UTF8Encoding]::new($false))
    Write-Host "`n完成。密碼已移到 $EncFile，.env 只剩埠號設定。"
    Write-Host "往後用 .\dbhub.ps1 apply / up / check 操作，不要直接下 docker compose。"
}

function Invoke-Show {
    $s = Read-Secrets
    foreach ($k in ($s.Keys | Sort-Object)) {
        "{0,-24} {1}" -f $k, $s[$k]
    }
}

function Invoke-Set {
    if (-not (Test-Path $KeyFile)) {
        New-Key
        Write-Host "已產生金鑰 $KeyFile"
    }
    $name = Read-Host '變數名稱'
    if (-not $name) { Write-Host '取消'; return }
    $sec = Read-Host "值（不回顯）" -AsSecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
    try { $val = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }

    $s = if (Test-Path $EncFile) { Read-Secrets } else { @{} }
    $s[$name] = $val
    Write-Secrets $s
    Write-Host "已寫入 $name（共 $($s.Count) 個變數）"
}

function Invoke-Compose([string[]]$ComposeArgs) {
    & docker compose --project-directory $Root @ComposeArgs
    if ($LASTEXITCODE -ne 0) { throw "docker compose 失敗（exit $LASTEXITCODE）" }
}

function Invoke-Apply {
    Invoke-Compose @('build')
    Invoke-Compose @('run', '--rm', '--no-deps', 'apply', 'check')
    Invoke-Compose @('up', '-d', 'hub', 'tunnel')
    Invoke-Compose @('restart', 'tunnel')
    Invoke-Compose @('run', '--rm', 'apply')
    Invoke-Compose @('up', '-d', '--no-deps', '--force-recreate', 'dbhub')
}


$cmd = if ($args.Count -gt 0) { $args[0] } else { 'help' }
$rest = if ($args.Count -gt 1) { $args[1..($args.Count - 1)] } else { @() }

switch ($cmd) {
    'init' { Invoke-Init }
    'show' { Invoke-Show }
    'set'  { Invoke-Set }
    'help' { Get-Help $PSCommandPath -Detailed }
    default {
        Import-ComposeEnv
        switch ($cmd) {
            'apply' { Invoke-Apply }
            'check' { Invoke-Compose @('run', '--rm', '--no-deps', 'apply', 'check') }
            # up 不帶其他參數時補 -d；帶了就原樣轉交，例如 up -d --force-recreate tunnel
            'up'    { if ($rest.Count) { Invoke-Compose $args } else { Invoke-Compose @('up', '-d') } }
            default { Invoke-Compose $args }
        }
    }
}
