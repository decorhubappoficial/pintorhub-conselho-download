[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$allowedFiles = @(
    '.gitignore'
    'README.md'
    'council/PintorHUB-Gestor-Conselho.apk'
    'council/PintorHUB-Gestor-Conselho.apk.sha256'
    'scripts/validate-public-repo.ps1'
    '.github/workflows/validate-public-repo.yml'
)

Push-Location $root
try {
    $trackedFiles = @(git ls-files)
    if ($LASTEXITCODE -ne 0) {
        throw 'Nao foi possivel listar os arquivos versionados.'
    }

    $unexpectedFiles = @($trackedFiles | Where-Object { $_ -notin $allowedFiles })
    if ($unexpectedFiles.Count -gt 0) {
        throw ('Arquivos nao permitidos neste repositorio: ' + ($unexpectedFiles -join ', '))
    }

    $missingFiles = @($allowedFiles | Where-Object { $_ -notin $trackedFiles })
    if ($missingFiles.Count -gt 0) {
        throw ('Arquivos publicos obrigatorios ausentes: ' + ($missingFiles -join ', '))
    }

    $historyInventory = @(git log --all --format='%H %s' --name-only)
    if ($LASTEXITCODE -ne 0) {
        throw 'Nao foi possivel verificar o historico Git.'
    }

    $forbiddenHistoryTerms = @(
        ('ad' + 'min')
        ('emis' + 'sor')
        ('is' + 'suer')
        ('PH' + 'ADM1')
    )
    foreach ($term in $forbiddenHistoryTerms) {
        if ($historyInventory -match [regex]::Escape($term)) {
            throw 'O historico Git contem uma referencia interna proibida.'
        }
    }

    $publicText = @(
        Get-Content -LiteralPath (Join-Path $root 'README.md') -Raw
        Get-Content -LiteralPath (Join-Path $root 'council/PintorHUB-Gestor-Conselho.apk.sha256') -Raw
    ) -join "`n"
    $sensitiveTextPatterns = @(
        '-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'
        'gh[pousr]_[A-Za-z0-9]{30,}'
        'github_pat_[A-Za-z0-9_]{30,}'
        '(?:AKIA|ASIA)[A-Z0-9]{16}'
        'AIza[0-9A-Za-z_-]{30,}'
        'sk-(?:proj-)?[A-Za-z0-9_-]{20,}'
        'sk_(?:live|test)_[0-9A-Za-z]{16,}'
        'xox[baprs]-[0-9A-Za-z-]{10,}'
    )
    foreach ($pattern in $sensitiveTextPatterns) {
        if ($publicText -match $pattern) {
            throw 'Um arquivo publico de texto contem um padrao de credencial proibido.'
        }
    }

    $apkPath = Join-Path $root 'council/PintorHUB-Gestor-Conselho.apk'
    $checksumPath = "$apkPath.sha256"
    $checksumLine = (Get-Content -LiteralPath $checksumPath -Raw).Trim()
    if ($checksumLine -notmatch '^(?<hash>[0-9a-fA-F]{64})\s+\*?PintorHUB-Gestor-Conselho\.apk$') {
        throw 'O arquivo SHA-256 nao possui o formato esperado.'
    }

    $actualHash = (Get-FileHash -LiteralPath $apkPath -Algorithm SHA256).Hash
    if ($actualHash -ne $Matches.hash) {
        throw 'O SHA-256 do APK nao corresponde ao arquivo publicado.'
    }

    $apkBytes = [System.IO.File]::ReadAllBytes($apkPath)
    if ($apkBytes.Length -lt 4 -or $apkBytes[0] -ne 0x50 -or $apkBytes[1] -ne 0x4B) {
        throw 'O arquivo publicado nao possui a assinatura ZIP esperada de um APK.'
    }

    $apkText = [System.Text.Encoding]::ASCII.GetString($apkBytes)
    $forbiddenApkMarkers = @(
        ('br.com.pintorhub.licencas.' + 'ad' + 'min')
        ('PintorHUB-' + 'Emis' + 'sor-Licencas')
        ('PH' + 'ADM1')
        ('BEGIN ' + 'PRIVATE KEY')
        ('BEGIN RSA ' + 'PRIVATE KEY')
        ('BEGIN EC ' + 'PRIVATE KEY')
        ('github_' + 'pat_')
        ('gh' + 'p_')
        ('AK' + 'IA')
        ('sk-' + 'proj-')
        ('xo' + 'xb-')
    )
    foreach ($marker in $forbiddenApkMarkers) {
        if ($apkText.Contains($marker)) {
            throw 'O APK contem um marcador interno ou sensivel proibido.'
        }
    }

    Write-Host 'Repositorio publico validado com sucesso.' -ForegroundColor Green
}
finally {
    Pop-Location
}
