#Requires -Version 5.1
<#
.SYNOPSIS
    IR-O365 - Office 365 Incident Response Script - MITRE ATT&CK Mapped

.DESCRIPTION
    Script completo de Incident Response para ambientes Microsoft 365/Office 365.
    Mapeado contra a matriz MITRE ATT&CK Enterprise - Office Suite Platform v18.
    23 modulos: Initial Access, Execution, Persistence, Privilege Escalation,
    Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection,
    Exfiltration, Impact.

    CHANGELOG v3.0.0:
    - FIX BUG_GRAPH_SUBMOD  : Import-Module explicito de todos os sub-modulos Graph
    - FIX BUG_UAL_NULL      : Invoke-UALSearch wrapped com @() - fix .Count em $null
    - FIX BUG_FWD_FALSEPOS  : Forwarding interno ao mesmo dominio excluido de CRITICAL
    - FIX BUG_MBXLOOP       : Get-Mailbox chamado apenas 1x por modulo (reutilizacao)
    - FIX BUG_NULLCOALESCE  : Operador ?? substituido por if/else (compatibilidade PS5.1)
    - FIX BUG_AUDITJSON     : try/catch em todos os ConvertFrom-Json de AuditData
    - FIX NET_TLS           : TLS 1.2 forcado no inicio do script
    - FIX Execution Policy  : Detetado e avisado antes de iniciar
    - NOVO: OutputPath inclui nome do tenant automaticamente

.AUTHOR
    IR Team | MITRE ATT&CK v18 Mapped

.REQUIREMENTS
    - ExchangeOnlineManagement v3+
    - Microsoft.Graph v2+ (sub-modulos: Authentication, Identity.DirectoryManagement,
      Identity.SignIns, Reports, Users, Applications, Security, Identity.Governance)
    - Permissions: Global Reader + Security Reader (minimo) | Exchange Admin para regras

.NOTES
    Output: Pasta timestampada com CSVs por categoria + HTML Report + JSON summary
    Recomendado: PowerShell 7+ (pwsh.exe) para melhor compatibilidade

.EXAMPLE
    .\IR-O365.ps1 -DaysBack 30
    .\IR-O365.ps1 -DaysBack 7 -WatchlistIPs @("1.2.3.4","5.6.7.8") -ExportJSON
    .\IR-O365.ps1 -DaysBack 90 -SkipExchange -ExportJSON
    pwsh.exe -File .\IR-O365.ps1 -DaysBack 30
    .\IR-O365.ps1 -DaysBack 30 -SkipConnect    # quando ja conectado manualmente
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [int]$DaysBack = 30,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".\reports\IR-O365-$(Get-Date -Format 'yyyyMMdd_HHmmss')",

    [Parameter(Mandatory = $false)]
    [switch]$SkipExchange,

    [Parameter(Mandatory = $false)]
    [switch]$SkipGraph,

    [Parameter(Mandatory = $false)]
    [switch]$SkipUAL,

    [Parameter(Mandatory = $false)]
    [string[]]$WatchlistIPs = @(),

    [Parameter(Mandatory = $false)]
    [string[]]$WatchlistUsers = @(),

    [Parameter(Mandatory = $false)]
    [switch]$ExportJSON,

    [Parameter(Mandatory = $false)]
    [switch]$SkipConnect,     # Reutiliza sessoes ja existentes sem pedir login

    [Parameter(Mandatory = $false)]
    [switch]$DebugIR          # Modo debug: mostra erros silenciosos, tempos por modulo, stack traces
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"
$WarningPreference = "SilentlyContinue"

# ============================================================
# FIX NET_TLS: Forcar TLS 1.2 (Graph API requer TLS 1.2+)
# SystemDefault em PS5.1 pode nao incluir TLS 1.2 por omissao
# ============================================================
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# ============================================================
# FIX BUG_GRAPH_SUBMOD: Importar sub-modulos Graph explicitamente
# Connect-MgGraph carrega apenas Authentication - sub-modulos
# (Reports, Users, SignIns, etc.) precisam de Import-Module explicito
# ============================================================
$Script:GraphSubModules = @(
    "Microsoft.Graph.Authentication",
    "Microsoft.Graph.Identity.DirectoryManagement",
    "Microsoft.Graph.Identity.SignIns",
    "Microsoft.Graph.Reports",
    "Microsoft.Graph.Users",
    "Microsoft.Graph.Applications",
    "Microsoft.Graph.Security",
    "Microsoft.Graph.Identity.Governance",
    "Microsoft.Graph.Devices.CloudManagement"
)

foreach ($gmod in $Script:GraphSubModules) {
    try {
        Import-Module $gmod -Force -ErrorAction SilentlyContinue
    } catch { <# modulo opcional nao disponivel - ignorar #> }
}

# ============================================================
# CONFIGURACAO & INICIALIZACAO
# ============================================================

$Script:Version         = "5.0.1"
$Script:TenantName      = "Unknown"
$Script:TenantId        = "Unknown"
$Script:OutputPath      = $Script:OutputPath
$Script:PrimaryDomain   = ""
$Script:UserDomains     = @()
$Script:AcceptedDomains = @()
$Script:StartTime       = Get-Date
$Script:Findings        = [System.Collections.Generic.List[hashtable]]::new()
$Script:DebugLog        = [System.Collections.Generic.List[hashtable]]::new()
$Script:ModuleTimes     = @{}
$Script:ModuleOrder = [System.Collections.Generic.List[string]]::new()
$Script:Stats       = @{ CRITICAL = 0; HIGH = 0; MEDIUM = 0; LOW = 0; INFO = 0 }
$Script:StartDate   = (Get-Date).AddDays(-$DaysBack)
$Script:EndDate     = Get-Date

# FIX BUG_SCOPE_ALL_SKIPS: Promover todos os parametros Skip para script-scope
# Assim funcoes que fazem $Script:SkipX = $true afetam todas as leituras subsequentes
$Script:SkipExchange = $Script:SkipExchange
$Script:SkipGraph    = $Script:SkipGraph
$Script:SkipUAL      = $Script:SkipUAL
$Script:SkipConnect  = $Script:SkipConnect
$Script:ExportJSON   = $Script:ExportJSON

# FIX BUG_FILTERDATE_RECALC: Calcular uma vez e reutilizar
$Script:FilterDate   = $Script:StartDate.ToString("yyyy-MM-ddTHH:mm:ssZ")

# FIX BUG_GET_COMMAND_HOT: Cache de disponibilidade de cmdlets (evita Get-Command em cada modulo)
$Script:EXOAvailable = $false
$Script:UALAvailable = $false

$Colors = @{
    CRITICAL = "Red"
    HIGH     = "DarkYellow"
    MEDIUM   = "Yellow"
    LOW      = "Cyan"
    INFO     = "Gray"
    SUCCESS  = "Green"
    HEADER   = "Magenta"
    SECTION  = "White"
}

function Write-IRLog {
    param(
        [string]$Message,
        [string]$Severity = "INFO",
        [string]$MITRETechnique = "",
        [string]$MITRETactic = "",
        [object]$Data = $null,
        [string]$DebugDetail = ""
    )

    $timestamp = Get-Date -Format "HH:mm:ss"
    $color     = $Colors[$Severity]

    $prefix = switch ($Severity) {
        "CRITICAL" { "[!!!]" }
        "HIGH"     { "[!!] " }
        "MEDIUM"   { "[!]  " }
        "LOW"      { "[*]  " }
        "INFO"     { "[i]  " }
        "SUCCESS"  { "[OK] " }
        default    { "[?]  " }
    }

    Write-Host "$timestamp $prefix $Message" -ForegroundColor $color

    # Debug mode: mostrar detalhe extra imediatamente
    if ($Script:DebugIR -and $DebugDetail) {
        Write-Host "         [DBG] $DebugDetail" -ForegroundColor DarkCyan
    }

    # Registar no debug log sempre (visivel no report com -DebugIR)
    $dbgEntry = @{
        Timestamp   = (Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff")
        Severity    = $Severity
        Message     = $Message
        Technique   = $MITRETechnique
        DebugDetail = $DebugDetail
    }
    if ($Script:DebugLog) { $Script:DebugLog.Add($dbgEntry) }

    if ($Severity -in @("CRITICAL","HIGH","MEDIUM","LOW")) {
        $Script:Stats[$Severity]++
        $finding = @{
            Timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            Severity  = $Severity
            Message   = $Message
            Technique = $MITRETechnique
            Tactic    = $MITRETactic
            Data      = $Data
        }
        $Script:Findings.Add($finding)
    }
}

# Helper para registar erros silenciosos com contexto completo
function Write-DebugError {
    param([string]$Module, [string]$Context, [System.Management.Automation.ErrorRecord]$Err)
    if (-not $Script:DebugLog) { return }
    $msg = if ($Err) { $Err.Exception.Message } else { "Erro desconhecido" }
    $stack = if ($Err) { $Err.ScriptStackTrace } else { "" }
    $entry = @{
        Timestamp   = (Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff")
        Severity    = "DEBUG_ERROR"
        Message     = "[$Module] $Context"
        Technique   = ""
        DebugDetail = "$msg | Stack: $($stack -replace '
',' | ')"
    }
    $Script:DebugLog.Add($entry)
    if ($Script:DebugIR) {
        Write-Host "  [DBG-ERR] [$Module] $Context" -ForegroundColor DarkRed
        Write-Host "            $msg" -ForegroundColor DarkRed
        if ($stack) { Write-Host "            Stack: $($stack.Split([char]10)[0])" -ForegroundColor DarkGray }
    }
}

# Helper para medir tempo de execucao de cada modulo
function Start-ModuleTimer {
    param([string]$ModuleName)
    $Script:ModuleTimes[$ModuleName] = @{ Start = (Get-Date); End = $null; DurationSec = 0 }
    if (-not $Script:ModuleOrder.Contains($ModuleName)) { $Script:ModuleOrder.Add($ModuleName) }
}

function Stop-ModuleTimer {
    param([string]$ModuleName)
    if ($Script:ModuleTimes.ContainsKey($ModuleName)) {
        $Script:ModuleTimes[$ModuleName].End         = Get-Date
        $Script:ModuleTimes[$ModuleName].DurationSec = [math]::Round(((Get-Date) - $Script:ModuleTimes[$ModuleName].Start).TotalSeconds, 1)
        if ($Script:DebugIR) {
            Write-Host "  [DBG] $ModuleName concluido em $($Script:ModuleTimes[$ModuleName].DurationSec)s" -ForegroundColor DarkGray
        }
    }
}

function Write-Section {
    param([string]$Title, [string]$Technique = "", [string]$Tactic = "")
    Write-Host ""
    Write-Host "==========================================================" -ForegroundColor DarkGray
    Write-Host "  $Title" -ForegroundColor White
    if ($Technique) { Write-Host "  MITRE: $Tactic | $Technique" -ForegroundColor DarkGray }
    Write-Host "==========================================================" -ForegroundColor DarkGray
}

function Export-IRData {
    param([string]$FileName, [object]$Data)
    if ($null -eq $Data) { return }
    $path = Join-Path $OutputPath "$FileName.csv"
    try {
        $Data | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8 -Force
    } catch {
        Write-IRLog "Erro ao exportar $FileName`: $_" -Severity "INFO"
    }
}

# FIX BUG_UAL_NULL: Invoke-UALSearch retorna $null (nao array vazio)
# quando nao ha resultados. .Count em $null lanca excepcao em PS5.1.
# Este wrapper garante SEMPRE um array - nunca $null.
function Invoke-UALSearch {
    param(
        [datetime]$StartDate,
        [datetime]$EndDate,
        [string[]]$Operations  = @(),
        [int]$ResultSize       = 1000,
        [string]$RecordType    = "",
        [string]$FreeText      = ""
    )
    try {
        $params = @{
            StartDate   = $StartDate
            EndDate     = $EndDate
            ResultSize  = $ResultSize
            ErrorAction = "SilentlyContinue"
        }
        if ($Operations.Count -gt 0) { $params.Operations  = $Operations  }
        if ($RecordType)              { $params.RecordType  = $RecordType  }
        if ($FreeText)                { $params.FreeText    = $FreeText    }

        $raw = Search-UnifiedAuditLog @params
        # Garantir sempre array - nunca $null - fix BUG_UAL_NULL
        return [array]($raw | Where-Object { $_ -ne $null })
    } catch {
        Write-IRLog "UAL Search falhou [$($Operations -join ',')]: $_" -Severity "INFO"
        return @()
    }
}

function New-OutputDirectory {
    # Garantir que a pasta reports existe antes de criar subpasta
    $reportsRoot = Join-Path (Split-Path $OutputPath -Parent) ""
    if (-not (Test-Path $reportsRoot)) {
        New-Item -ItemType Directory -Path $reportsRoot -Force | Out-Null
    }
    if (-not (Test-Path $Script:OutputPath)) {
        New-Item -ItemType Directory -Path $Script:OutputPath -Force | Out-Null
        New-Item -ItemType Directory -Path "$Script:OutputPath\raw" -Force | Out-Null
        New-Item -ItemType Directory -Path "$Script:OutputPath\findings" -Force | Out-Null
    }
}

# FIX BUG_GET_COMMAND_HOT: Usar cache em vez de Get-Command a cada chamada
function Test-EXOAvailable {
    if ($Script:EXOAvailable) { return $true }
    $ok = ($null -ne (Get-Command "Get-Mailbox" -ErrorAction SilentlyContinue))
    if ($ok) { $Script:EXOAvailable = $true }
    return $ok
}

function Test-UALAvailable {
    if ($Script:UALAvailable) { return $true }
    $ok = ($null -ne (Get-Command "Search-UnifiedAuditLog" -ErrorAction SilentlyContinue))
    if ($ok) { $Script:UALAvailable = $true }
    return $ok
}

# ============================================================
# BANNER
# ============================================================

function Show-Banner {
    Clear-Host
    Write-Host @"

  +===============================================================+
  |              IR-O365  v5.0.0                                  |
  |         MITRE ATT&CK Enterprise - Office Suite Mapped         |
  +===============================================================+
  |  Taticas: Initial Access | Persistence | Defense Evasion      |
  |           Credential Access | Collection | Exfiltration        |
  +===============================================================+

"@ -ForegroundColor Cyan

    # Avisos de ambiente
    if ($PSVersionTable.PSVersion.Major -lt 7) {
        Write-Host "  [WARN] PS $($PSVersionTable.PSVersion) detetado - recomendado PS7+" -ForegroundColor Yellow
        Write-Host "         pwsh.exe -File .\IR-O365.ps1 para melhor compatibilidade" -ForegroundColor DarkYellow
        Write-Host ""
    }

    $ep = Get-ExecutionPolicy -Scope CurrentUser
    if ($ep -notin @("RemoteSigned","Unrestricted","Bypass")) {
        Write-Host "  [WARN] Execution Policy: $ep - pode causar problemas" -ForegroundColor Yellow
        Write-Host "         Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned" -ForegroundColor DarkYellow
        Write-Host ""
    }

    Write-Host "  Periodo de analise : $($Script:StartDate.ToString('yyyy-MM-dd')) >> $($Script:EndDate.ToString('yyyy-MM-dd')) ($Script:DaysBack dias)" -ForegroundColor Gray
    Write-Host "  Output path        : $Script:OutputPath" -ForegroundColor Gray
    Write-Host "  Watchlist IPs      : $($WatchlistIPs.Count) entradas" -ForegroundColor Gray
    Write-Host "  Watchlist Users    : $($WatchlistUsers.Count) entradas" -ForegroundColor Gray
    Write-Host "  PowerShell         : v$($PSVersionTable.PSVersion)" -ForegroundColor Gray
    Write-Host "  TLS                : $([Net.ServicePointManager]::SecurityProtocol)" -ForegroundColor Gray
    Write-Host ""
}

# ============================================================
# MODULO 0: PRE-REQUISITOS & CONEXAO
# ============================================================

function Test-Prerequisites {
    Write-Section "PRE-REQUISITOS"
    
    $modules = @("ExchangeOnlineManagement", "Microsoft.Graph.Authentication")
    foreach ($mod in $modules) {
        if (Get-Module -ListAvailable -Name $mod) {
            Write-IRLog "Modulo $mod disponivel" -Severity "SUCCESS"
        } else {
            Write-IRLog "Modulo $mod NAO encontrado - Install-Module $mod" -Severity "HIGH"
        }
    }
}


# ============================================================
# ============================================================
# AUTENTICACAO - Modern Auth, sem reutilizacao de sessoes
# Autentica no inicio, fecha no fim. Sem menus, sem estados.
# ============================================================

function Connect-IRServices {
    Write-Section "AUTENTICACAO O365"

    $graphScopes = @(
        "AuditLog.Read.All","Directory.Read.All","Policy.Read.All",
        "IdentityRiskyUser.Read.All","SecurityEvents.Read.All",
        "Application.Read.All","RoleManagement.Read.Directory",
        "IdentityRiskEvent.Read.All","UserAuthenticationMethod.Read.All",
        "Reports.Read.All"
    )

    # ---- Limpar sessoes anteriores ----
    Write-Host "  >> A limpar sessoes anteriores..." -ForegroundColor Gray
    try { Disconnect-MgGraph -ErrorAction SilentlyContinue } catch {}
    try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue } catch {}
    $Script:EXOAvailable = $false
    $Script:UALAvailable = $false

    # ---- Microsoft Graph (obrigatorio) ----
    Write-Host "  >> A autenticar Microsoft Graph..." -ForegroundColor Gray
    Write-Host "  Sera aberta uma janela de autenticacao no browser." -ForegroundColor DarkGray
    Write-Host ""

    $graphOk = $false
    $attempt = 0
    while (-not $graphOk -and $attempt -lt 3) {
        $attempt++
        try {
            Connect-MgGraph -Scopes $graphScopes -NoWelcome -ErrorAction Stop
            $ctx = Get-MgContext -ErrorAction SilentlyContinue
            if ($ctx -and $ctx.Account) {
                Write-IRLog "Microsoft Graph: Conectado como $($ctx.Account) (tenant: $($ctx.TenantId))" -Severity "SUCCESS"
                $graphOk = $true
            } else {
                throw "Contexto Graph invalido apos autenticacao"
            }
        } catch {
            $errMsg = $_.Exception.Message
            Write-IRLog "Graph tentativa $attempt falhou: $($errMsg.Split([char]10)[0])" -Severity "HIGH"

            # Fallback: Device Code (nao precisa de browser embebido)
            if ($attempt -eq 1) {
                Write-Host "  Autenticacao interativa falhou. A tentar Device Code..." -ForegroundColor Yellow
                Write-Host "  Vai a: https://microsoft.com/devicelogin" -ForegroundColor Cyan
                try {
                    Connect-MgGraph -Scopes $graphScopes -UseDeviceAuthentication -NoWelcome -ErrorAction Stop
                    $ctx = Get-MgContext -ErrorAction SilentlyContinue
                    if ($ctx -and $ctx.Account) {
                        Write-IRLog "Microsoft Graph: Conectado via Device Code como $($ctx.Account)" -Severity "SUCCESS"
                        $graphOk = $true
                    }
                } catch {
                    Write-IRLog "Device Code falhou: $($_.Exception.Message.Split([char]10)[0])" -Severity "HIGH"
                }
            }

            if (-not $graphOk -and $attempt -lt 3) {
                Write-Host "  Tentar novamente? [s/n] " -NoNewline -ForegroundColor Yellow
                $retry = (Read-Host).Trim().ToLower()
                if ($retry -ne "s" -and $retry -ne "y") { break }
            }
        }
    }

    if (-not $graphOk) {
        Write-Host ""
        Write-Host "  Nao foi possivel autenticar no Microsoft Graph." -ForegroundColor Red
        Write-Host "  O Graph e obrigatorio para a maioria dos modulos." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  [1] Continuar sem Graph (apenas Exchange se disponivel)" -ForegroundColor Yellow
        Write-Host "  [2] Sair" -ForegroundColor Gray
        $ans = ""
        while ($ans -notin @("1","2")) { $ans = (Read-Host "  Opcao [1/2]").Trim() }
        if ($ans -eq "2") { exit 0 }
        $Script:SkipGraph = $true
    }

    # ---- Exchange Online (opcional - tenta, continua se falhar) ----
    Write-Host ""
    Write-Host "  >> A autenticar Exchange Online..." -ForegroundColor Gray

    # Verificar se -UseDeviceAuthentication existe nesta build
    $exoCmd          = Get-Command Connect-ExchangeOnline -ErrorAction SilentlyContinue
    $hasDeviceParam  = $exoCmd -and $exoCmd.Parameters -and $exoCmd.Parameters.ContainsKey("UseDeviceAuthentication")

    # Tentar primeiro autenticacao interactiva normal
    $exoConnected = $false
    try {
        Write-Host "  A aguardar autenticacao..." -ForegroundColor DarkGray
        Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
        Write-IRLog "Exchange Online: Conectado" -Severity "SUCCESS"
        $exoConnected = $true
    } catch {
        $err = $_.Exception.Message
        $isBrokerError = $err -match "WithBroker|MissingMethodException|BrokerExtension|NullReferenceException|RuntimeBroker|Object reference"
        if ($isBrokerError) {
            # Broker falhou (PS5.1 WAM ou PS7 headless) - tentar Device Code se disponivel
            if ($hasDeviceParam) {
                Write-Host "  Broker incompativel - a tentar Device Code..." -ForegroundColor Yellow
                Write-Host "  Vai a: https://microsoft.com/devicelogin" -ForegroundColor Cyan
                try {
                    Connect-ExchangeOnline -ShowBanner:$false -UseDeviceAuthentication -ErrorAction Stop
                    Write-IRLog "Exchange Online: Conectado via Device Code" -Severity "SUCCESS"
                    $exoConnected = $true
                } catch {
                    Write-IRLog "Exchange Online: Device Code falhou - $($_.Exception.Message.Split([char]10)[0])" -Severity "MEDIUM"
                }
            } else {
                $exoVer = (Get-Module ExchangeOnlineManagement -ErrorAction SilentlyContinue).Version
                Write-IRLog "Exchange Online: Broker incompativel (EXO v${exoVer})" -Severity "MEDIUM"
                Write-Host "  Broker incompativel e Device Code nao suportado nesta build." -ForegroundColor Yellow
                Write-Host "  Actualizar: Update-Module ExchangeOnlineManagement -Force" -ForegroundColor DarkGray
            }
        } else {
            Write-IRLog "Exchange Online: $($err.Split([char]10)[0])" -Severity "MEDIUM"
        }
    }

    if (-not $exoConnected) {
        Write-Host ""
        Write-Host "  EXO nao disponivel - modulos Exchange e UAL serao ignorados." -ForegroundColor Yellow
        Write-Host "  A continuar com modulos Graph apenas." -ForegroundColor Gray
        $Script:SkipExchange = $true
        $Script:SkipUAL      = $true
    }

    Write-Host ""
}

function Close-IRSessions {
    # Chamada no fim do script - fechar todas as sessoes
    Write-Host "  >> A fechar sessoes..." -ForegroundColor Gray
    try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch {}
    try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue } catch {}
    Write-IRLog "Sessoes terminadas" -Severity "INFO"
}


# ============================================================
# MODULO 1: BASELINE DO TENANT
# ============================================================

function Get-TenantBaseline {
    Write-Section "TENANT BASELINE" "T1538" "Discovery"
    
    try {
        $org = Get-MgOrganization -ErrorAction Stop
        # ---- Capturar dominios do tenant ----
        $allDomains = @(Get-MgDomain -ErrorAction SilentlyContinue)

        $Script:AcceptedDomains = @($allDomains | Where-Object { $_.IsVerified } | ForEach-Object { $_.Id })
        $defaultDom = $allDomains | Where-Object { $_.IsDefault } | Select-Object -First 1
        $Script:PrimaryDomain   = if ($defaultDom) { $defaultDom.Id } else { $Script:AcceptedDomains | Select-Object -First 1 }
        # Dominios de utilizadores = verificados, excluindo dominios geridos pela Microsoft
        $Script:UserDomains     = @($allDomains | Where-Object {
            $_.IsVerified -and $_.Id -notmatch "\.onmicrosoft\.com$"
        } | ForEach-Object { $_.Id })

        $Script:TenantName = $org.DisplayName.Trim()
        $Script:TenantId   = $org.Id
        Write-IRLog "Tenant: $($Script:TenantName) | ID: $($Script:TenantId)" -Severity "INFO"
        Write-IRLog "Dominio principal: $($Script:PrimaryDomain)" -Severity "INFO"
        if ($Script:UserDomains.Count -gt 1) {
            Write-IRLog "Dominios de utilizadores ($($Script:UserDomains.Count)): $($Script:UserDomains -join ', ')" -Severity "INFO"
        }

        $tenantInfo = [PSCustomObject]@{
            TenantId       = $org.Id
            DisplayName    = $org.DisplayName
            PrimaryDomain  = $Script:PrimaryDomain
            UserDomains    = $Script:UserDomains -join ", "
            AllDomains     = $Script:AcceptedDomains -join ", "
            CreatedDate    = $org.CreatedDateTime
        }
        Export-IRData -FileName "00_tenant_baseline" -Data @($tenantInfo)
        
        # Verificar Security Defaults
        try {
            $secDefaults = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy -ErrorAction SilentlyContinue
            if ($secDefaults.IsEnabled -eq $false) {
                Write-IRLog "Security Defaults DESATIVADO - verifique Conditional Access policies [T1562.008]" `
                    -Severity "HIGH" -MITRETechnique "T1562.008" -MITRETactic "Defense Evasion" `
                    -Data "Security Defaults disabled"
            } else {
                Write-IRLog "Security Defaults: ATIVO" -Severity "INFO"
            }
        } catch { Write-IRLog "Nao foi possivel verificar Security Defaults" -Severity "INFO" }
        
    } catch {
        Write-IRLog "Erro ao obter baseline do tenant: $_" -Severity "INFO"
    }
}

# ============================================================
# MODULO 2: INITIAL ACCESS - CONTAS E AUTENTICACAO
# ============================================================

function Get-SuspiciousSignIns {
    # T1078 - Valid Accounts | T1110 - Brute Force | T1566 - Phishing
    Write-Section "SIGN-IN LOGS SUSPEITOS" "T1078/T1110" "Initial Access / Credential Access"
    
    try {
        $filterDate = $Script:FilterDate
        
        # Sign-ins falhados em volume (Brute Force / Password Spray)
        Write-Host "  >> Analisando tentativas de brute force..." -ForegroundColor Gray
        $failedSignins = @(Get-MgAuditLogSignIn -Filter `
            "createdDateTime ge $filterDate and status/errorCode ne 0" `
            -Top 5000 -ErrorAction SilentlyContinue)
        
        if ($failedSignins) {
            # Password Spray: muitos users com poucas tentativas do mesmo IP
            $sprayGroups = @($failedSignins | Group-Object { $_.IPAddress } |
                Where-Object { $_.Count -gt 20 }) |
                Select-Object @{N="IP";E={$_.Name}},
                              @{N="FailedAttempts";E={$_.Count}},
                              @{N="UniqueUsers";E={($_.Group.UserPrincipalName | Sort-Object -Unique).Count}},
                              @{N="FirstSeen";E={($_.Group.CreatedDateTime | Sort-Object)[0]}},
                              @{N="LastSeen";E={($_.Group.CreatedDateTime | Sort-Object -Descending)[0]}}
            
            foreach ($spray in $sprayGroups) {
                $severity = if ($spray.UniqueUsers -gt 10) { "CRITICAL" }
                            elseif ($spray.UniqueUsers -gt 5) { "HIGH" }
                            else { "MEDIUM" }
                Write-IRLog "Password Spray: IP $($spray.IP) >> $($spray.FailedAttempts) tentativas em $($spray.UniqueUsers) utilizadores [T1110.003]" `
                    -Severity $severity -MITRETechnique "T1110.003" -MITRETactic "Credential Access" -Data $spray
            }
            Export-IRData -FileName "01_brute_force_by_ip" -Data $sprayGroups
            
            # Credential Stuffing: 1 user, muitas tentativas
            $stuffing = @($failedSignins | Group-Object UserPrincipalName |
                Where-Object { $_.Count -gt 50 }) |
                Select-Object @{N="User";E={$_.Name}},
                              @{N="FailedAttempts";E={$_.Count}},
                              @{N="UniqueIPs";E={($_.Group.IPAddress | Sort-Object -Unique).Count}}
            
            foreach ($s in $stuffing) {
                Write-IRLog "Credential Stuffing: $($s.User) >> $($s.FailedAttempts) tentativas [T1110.004]" `
                    -Severity "HIGH" -MITRETechnique "T1110.004" -MITRETactic "Credential Access" -Data $s
            }
            Export-IRData -FileName "01_credential_stuffing" -Data $stuffing
        }
        
        # Sign-ins com sucesso suspeitos
        Write-Host "  >> Analisando sign-ins com sucesso suspeitos..." -ForegroundColor Gray
        $successSignins = @(Get-MgAuditLogSignIn -Filter `
            "createdDateTime ge $filterDate and status/errorCode eq 0" `
            -Top 5000 -ErrorAction SilentlyContinue)
        
        if ($successSignins) {
            # Legacy Authentication (bypass MFA) - T1078
            $legacyAuth = @($successSignins | Where-Object {
                $_.ClientAppUsed -in @(
                    "IMAP","POP3","SMTP","Exchange ActiveSync",
                    "Exchange Web Services","Other clients; IMAP",
                    "Other clients; POP3","Authenticated SMTP",
                    "Exchange Online PowerShell"
                )
            } | Select-Object UserPrincipalName, ClientAppUsed, IPAddress,
                               CreatedDateTime, Location, DeviceDetail)
            
            if ($legacyAuth.Count -gt 0) {
                Write-IRLog "Legacy Authentication em uso: $($legacyAuth.Count) sign-ins - BYPASSA MFA [T1078]" `
                    -Severity "HIGH" -MITRETechnique "T1078.004" -MITRETactic "Initial Access" -Data @{Count=$legacyAuth.Count}
                Export-IRData -FileName "01_legacy_auth_signins" -Data $legacyAuth
            }
            
            # Impossible Travel
            Write-Host "  >> Analisando impossible travel..." -ForegroundColor Gray
            $userSignins = $successSignins | Group-Object UserPrincipalName
            $impossibleTravel = [System.Collections.Generic.List[PSObject]]::new()
            
            foreach ($userGroup in $userSignins) {
                $sorted = $userGroup.Group | Sort-Object CreatedDateTime
                for ($i = 1; $i -lt $sorted.Count; $i++) {
                    $prev = $sorted[$i-1]
                    $curr = $sorted[$i]
                    $prevCountry = $prev.Location.CountryOrRegion
                    $currCountry = $curr.Location.CountryOrRegion
                    
                    if ($prevCountry -and $currCountry -and $prevCountry -ne $currCountry) {
                        $timeDiff = ($curr.CreatedDateTime - $prev.CreatedDateTime).TotalMinutes
                        if ($timeDiff -lt 120 -and $timeDiff -gt 0) {
                            $record = [PSCustomObject]@{
                                User            = $userGroup.Name
                                PreviousCountry = $prevCountry
                                CurrentCountry  = $currCountry
                                PreviousIP      = $prev.IPAddress
                                CurrentIP       = $curr.IPAddress
                                TimeDiffMinutes = [math]::Round($timeDiff, 1)
                                FirstSignIn     = $prev.CreatedDateTime
                                SecondSignIn    = $curr.CreatedDateTime
                            }
                            $impossibleTravel.Add($record)
                            Write-IRLog "Impossible Travel: $($userGroup.Name) >> $prevCountry>>$currCountry em $([math]::Round($timeDiff,0))min" `
                                -Severity "HIGH" -MITRETechnique "T1078.004" -MITRETactic "Initial Access" -Data $record
                        }
                    }
                }
            }
            Export-IRData -FileName "01_impossible_travel" -Data $impossibleTravel
            
            # Watchlist IPs
            if ($Script:WatchlistIPs.Count -gt 0) {
                $watchlistHits = @($successSignins | Where-Object { $_.IPAddress -in $Script:WatchlistIPs })
                if ($watchlistHits.Count -gt 0) {
                    foreach ($hit in $watchlistHits) {
                        Write-IRLog "WATCHLIST IP: $($hit.IPAddress) autenticou como $($hit.UserPrincipalName)" `
                            -Severity "CRITICAL" -MITRETechnique "T1078" -MITRETactic "Initial Access" -Data $hit
                    }
                    Export-IRData -FileName "01_watchlist_ip_hits" -Data $watchlistHits
                }
            }
            
            # Watchlist Users
            if ($Script:WatchlistUsers.Count -gt 0) {
                $watchlistUserHits = @($successSignins | Where-Object { $_.UserPrincipalName -in $Script:WatchlistUsers })
                if ($watchlistUserHits.Count -gt 0) {
                    Export-IRData -FileName "01_watchlist_user_signins" -Data $watchlistUserHits
                    Write-IRLog "WATCHLIST USERS: $($watchlistUserHits.Count) sign-ins de utilizadores monitorizados" `
                        -Severity "CRITICAL" -MITRETechnique "T1078" -MITRETactic "Initial Access"
                }
            }
            
            # Token Reuse / Session Theft indicators
            $tokenSuspect = @($successSignins | Where-Object {
                $_.ConditionalAccessStatus -eq "notApplied"
            } | Select-Object UserPrincipalName, CreatedDateTime, IPAddress,
                               ClientAppUsed, ConditionalAccessStatus, Location)
            
            if ($tokenSuspect.Count -gt 0) {
                Write-IRLog "Possivel Token Reuse: $($tokenSuspect.Count) sign-ins com CA nao aplicado [T1550.001]" `
                    -Severity "HIGH" -MITRETechnique "T1550.001" -MITRETactic "Defense Evasion"
                Export-IRData -FileName "01_token_reuse_suspect" -Data $tokenSuspect
            }
        }
        
        # Risky Sign-ins (Identity Protection)
        Write-Host "  >> Verificando risky sign-ins..." -ForegroundColor Gray
        try {
            $riskySignins = @(Get-MgAuditLogSignIn -Filter `
                "createdDateTime ge $filterDate and riskState eq 'atRisk'" `
                -Top 1000 -ErrorAction SilentlyContinue)
            
            if ($riskySignins.Count -gt 0) {
                Write-IRLog "Risky Sign-ins ativos: $($riskySignins.Count) eventos [T1078]" `
                    -Severity "HIGH" -MITRETechnique "T1078.004" -MITRETactic "Initial Access"
                Export-IRData -FileName "01_risky_signins" -Data ($riskySignins | Select-Object UserPrincipalName, CreatedDateTime, RiskLevel, RiskState, RiskDetail, IPAddress, Location)
            }
        } catch {
            Write-IRLog "Identity Protection P2 indisponivel - a usar fallback de sign-ins basico [T1078]" -Severity "INFO"
            # FIX: Fallback sem filtro de risco - apanhar sign-ins suspeitos por outros criterios
            try {
                $basicSignins = @(Get-MgAuditLogSignIn -Filter `
                    "createdDateTime ge $filterDate and status/errorCode eq 0" `
                    -Top 1000 -ErrorAction SilentlyContinue)
                if ($basicSignins.Count -gt 0) {
                    # Paises incomuns sem P2
                    $highRiskCC = @("CN","RU","KP","IR","SY","BY","CU","VE","MM","PK","AF")
                    $suspectGeo = @($basicSignins | Where-Object { $_.Location.CountryOrRegion -in $highRiskCC })
                    if ($suspectGeo.Count -gt 0) {
                        Write-IRLog "Sign-ins de paises de alto risco (sem P2): $($suspectGeo.Count) [T1078.004]" `
                            -Severity "HIGH" -MITRETechnique "T1078.004" -MITRETactic "Initial Access"
                        Export-IRData -FileName "01_high_risk_country_signins_basic" -Data ($suspectGeo | Select-Object UserPrincipalName, CreatedDateTime, IPAddress, @{N="Country";E={$_.Location.CountryOrRegion}}, ClientAppUsed)
                    }
                    # Legacy auth sem P2
                    $legacyFallback = @($basicSignins | Where-Object { $_.ClientAppUsed -in @("IMAP","POP3","SMTP","Exchange ActiveSync","Authenticated SMTP") })
                    if ($legacyFallback.Count -gt 0) {
                        Write-IRLog "Legacy Auth sign-ins (fallback P2): $($legacyFallback.Count) - MFA bypassavel [T1078]" `
                            -Severity "HIGH" -MITRETechnique "T1078.004" -MITRETactic "Initial Access"
                        Export-IRData -FileName "01_legacy_auth_fallback" -Data ($legacyFallback | Select-Object UserPrincipalName, CreatedDateTime, IPAddress, ClientAppUsed, Location)
                    }
                }
            } catch { Write-IRLog "Fallback sign-in: $_ " -Severity "INFO" }
        }
        
        # Risky Users
        try {
            $riskyUsers = @(Get-MgRiskyUser -Filter "riskState eq 'atRisk' or riskState eq 'confirmedCompromised'" -ErrorAction SilentlyContinue)
            if ($riskyUsers.Count -gt 0) {
                foreach ($ru in $riskyUsers) {
                    $sev = if ($ru.RiskState -eq "confirmedCompromised") { "CRITICAL" } else { "HIGH" }
                    Write-IRLog "Risky User: $($ru.UserPrincipalName) | State: $($ru.RiskState) | Level: $($ru.RiskLevel)" `
                        -Severity $sev -MITRETechnique "T1078.004" -MITRETactic "Initial Access"
                }
                Export-IRData -FileName "01_risky_users" -Data ($riskyUsers | Select-Object UserPrincipalName, RiskLevel, RiskState, RiskLastUpdatedDateTime)
            }
        } catch { Write-IRLog "Risky Users: Requer licenca P2" -Severity "INFO" }
        
    } catch {
        Write-IRLog "Erro no modulo Sign-In: $_" -Severity "INFO"
    }
}

# ============================================================
# MODULO 3: MFA & AUTENTICACAO
# ============================================================

function Get-MFAStatus {
    # T1556.006 - Modify Authentication Process: Multi-Factor Authentication
    Write-Section "MFA STATUS & CONDITIONAL ACCESS" "T1556.006" "Credential Access / Defense Evasion"
    
    try {
        # Admins sem MFA
        $mfaDomainCtx = if ($Script:UserDomains.Count -gt 0) { $Script:UserDomains -join ", " } else { "tenant" }
        Write-Host "  >> Verificando admins sem MFA (dominios: $mfaDomainCtx)..." -ForegroundColor Gray
        $privilegedRoles = @(
            "62e90394-69f5-4237-9190-012177145e10",  # Global Administrator
            "194ae4cb-b126-40b2-bd5b-6091b380977d",  # Security Administrator
            "9360feb5-f418-4baa-8175-e2a00bac4301",  # Exchange Administrator
            "f2ef992c-3afb-46b9-b7cf-a126ee74c451",  # Global Reader
            "e8611ab8-c189-46e8-94e1-60213ab1f814"   # Privileged Role Administrator
        )
        
        $adminsMFAResults = [System.Collections.Generic.List[PSObject]]::new()

        foreach ($roleId in $privilegedRoles) {
            try {
                $roleMembers = @()
                try {
                    $roleMembers = @(Get-MgDirectoryRoleMember -DirectoryRoleId $roleId -ErrorAction Stop)
                } catch {
                    try {
                        $activeRole = Get-MgDirectoryRole -Filter "roleTemplateId eq '$roleId'" -ErrorAction SilentlyContinue
                        if ($activeRole) {
                            $roleMembers = @(Get-MgDirectoryRoleMember -DirectoryRoleId $activeRole.Id -ErrorAction SilentlyContinue)
                        }
                    } catch {
                        Write-DebugError "MFAStatus" "Role lookup $roleId" $_
                    }
                }
                if ($null -eq $roleMembers) { $roleMembers = @() }
                $roleMembers = @($roleMembers)

                foreach ($member in $roleMembers) {
                    if ($member.AdditionalProperties["@odata.type"] -ne "#microsoft.graph.user") { continue }
                    $uid = $member.Id
                    $upn = $member.AdditionalProperties["userPrincipalName"]

                    # --- Metodo 1: Get-MgUserAuthenticationMethod (requer UserAuthenticationMethod.Read.All)
                    $hasMFA    = $false
                    $mfaMethods= @()
                    $methodSrc = "N/A"
                    try {
                        $authMethods = @(Get-MgUserAuthenticationMethod -UserId $uid -ErrorAction Stop)
                        $mfaTypes = @(
                            "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod",
                            "#microsoft.graph.phoneAuthenticationMethod",
                            "#microsoft.graph.fido2AuthenticationMethod",
                            "#microsoft.graph.windowsHelloForBusinessAuthenticationMethod",
                            "#microsoft.graph.softwareOathAuthenticationMethod",
                            "#microsoft.graph.temporaryAccessPassAuthenticationMethod"
                        )
                        $mfaMethods = @($authMethods | Where-Object {
                            $_.AdditionalProperties["@odata.type"] -in $mfaTypes
                        })
                        $hasMFA    = $mfaMethods.Count -gt 0
                        $methodSrc = "AuthenticationMethod API"
                        Write-DebugError "MFAStatus" "User $upn - $($authMethods.Count) methods found, $($mfaMethods.Count) MFA" $null
                    } catch {
                        Write-DebugError "MFAStatus" "AuthMethod API falhou para $upn" $_
                    }

                    # --- Metodo 2 (fallback): verificar via User StrongAuthenticationRequirements (MSOL-style via Graph)
                    if (-not $hasMFA -and $methodSrc -eq "N/A") {
                        try {
                            $userDetail = Get-MgUser -UserId $uid `
                                -Property "Id,UserPrincipalName,StrongAuthenticationDetail" `
                                -ErrorAction SilentlyContinue
                            if ($userDetail -and $userDetail.AdditionalProperties.ContainsKey("strongAuthenticationDetail")) {
                                $sad = $userDetail.AdditionalProperties["strongAuthenticationDetail"]
                                if ($sad -and $sad.methods -and $sad.methods.Count -gt 0) {
                                    $hasMFA    = $true
                                    $methodSrc = "StrongAuthDetail"
                                }
                            }
                        } catch { Write-DebugError "MFAStatus" "StrongAuth check $upn" $_ }
                    }

                    # --- Metodo 3 (fallback): verificar via Reports API - per-user MFA state
                    if (-not $hasMFA -and $methodSrc -eq "N/A") {
                        try {
                            $regDetail = Get-MgReportAuthenticationMethodUserRegistrationDetail `
                                -UserRegistrationDetailsId $uid -ErrorAction Stop
                            if ($regDetail) {
                                $hasMFA    = $regDetail.IsMfaRegistered -or $regDetail.IsMfaCapable
                                $methodSrc = "RegistrationDetail (isMfaRegistered=$($regDetail.IsMfaRegistered))"
                            }
                        } catch { Write-DebugError "MFAStatus" "RegistrationDetail $upn" $_ }
                    }

                    $record = [PSCustomObject]@{
                        UserId        = $uid
                        UPN           = $upn
                        RoleId        = $roleId
                        MFAConfigured = $hasMFA
                        MethodCount   = $mfaMethods.Count
                        DetectionSrc  = $methodSrc
                    }
                    $adminsMFAResults.Add($record)

                    if (-not $hasMFA -and $methodSrc -ne "N/A") {
                        # So reportar como sem MFA se conseguimos verificar E nao tem
                        Write-IRLog "ADMIN SEM MFA VERIFICADO: $upn (via $methodSrc) [T1556.006]" `
                            -Severity "CRITICAL" -MITRETechnique "T1556.006" -MITRETactic "Defense Evasion" -Data $record
                    } elseif ($methodSrc -eq "N/A") {
                        Write-IRLog "MFA nao verificavel para $upn - scope UserAuthenticationMethod.Read.All pode estar em falta" `
                            -Severity "INFO"
                    } else {
                        Write-IRLog "Admin com MFA: $upn ($methodSrc)" -Severity "INFO"
                    }
                }
            } catch { Write-DebugError "MFAStatus" "Role loop $roleId" $_ }
        }
        Export-IRData -FileName "02_admin_mfa_status" -Data $adminsMFAResults
        
        # Conditional Access Policies
        Write-Host "  >> Analisando Conditional Access policies..." -ForegroundColor Gray
        $caPolicies = @(Get-MgIdentityConditionalAccessPolicy -ErrorAction SilentlyContinue)
        $disabledPolicies = @($caPolicies | Where-Object { $_.State -eq "disabled" })
        $reportOnlyPolicies = @($caPolicies | Where-Object { $_.State -eq "enabledForReportingButNotEnforced" })
        
        Write-IRLog "CA Policies: $($caPolicies.Count) total | $($disabledPolicies.Count) desativadas | $($reportOnlyPolicies.Count) report-only" -Severity "INFO"

        # FIX: 0 CA policies e um gap CRITICO - tenant depende apenas de Security Defaults
        if ($caPolicies.Count -eq 0) {
            Write-IRLog "ZERO Conditional Access policies - tenant usa apenas Security Defaults. Sem MFA por risco, sem bloqueio legacy auth, sem device compliance [T1562.008]" `
                -Severity "CRITICAL" -MITRETechnique "T1562.008" -MITRETactic "Defense Evasion" `
                -Data "Criar policies: Block Legacy Auth + Require MFA for Admins + Sign-in Risk"
        }

        if ($disabledPolicies.Count -gt 0) {
            Write-IRLog "Politicas CA DESATIVADAS: $($disabledPolicies.Count) - verificar alteracoes recentes [T1562.008]" `
                -Severity "MEDIUM" -MITRETechnique "T1562.008" -MITRETactic "Defense Evasion"
            Export-IRData -FileName "02_ca_disabled_policies" -Data ($disabledPolicies | Select-Object DisplayName, State, CreatedDateTime, ModifiedDateTime)
        }
        
    } catch {
        Write-IRLog "Erro no modulo MFA: $_" -Severity "INFO"
    }
}

# ============================================================
# MODULO 4: CONTAS PRIVILEGIADAS & GESTAO DE ROLES
# ============================================================

function Get-PrivilegedAccountChanges {
    # T1098.003 - Additional Cloud Roles | T1136.003 - Create Cloud Account | T1548.005 - Temp Elevated Access
    Write-Section "CONTAS PRIVILEGIADAS & ROLE CHANGES" "T1098.003/T1136.003" "Persistence / Privilege Escalation"
    
    # Contas criadas recentemente
    Write-Host "  >> Verificando contas criadas recentemente..." -ForegroundColor Gray
    try {
        $filterDate = $Script:FilterDate
        $newAccounts = @(Get-MgUser -Filter "createdDateTime ge $filterDate" `
            -Property "Id,DisplayName,UserPrincipalName,CreatedDateTime,AccountEnabled,AssignedLicenses" `
            -ErrorAction SilentlyContinue)
        
        if ($newAccounts.Count -gt 0) {
            Write-IRLog "Contas criadas nos ultimos $DaysBack dias: $($newAccounts.Count) [T1136.003]" `
                -Severity "MEDIUM" -MITRETechnique "T1136.003" -MITRETactic "Persistence"
            Export-IRData -FileName "03_new_accounts" -Data ($newAccounts | Select-Object DisplayName, UserPrincipalName, CreatedDateTime, AccountEnabled)
        }
        
        # Guest accounts recentes
        $guestAccounts = Get-MgUser -Filter "userType eq 'Guest'" `
            -Property "Id,DisplayName,UserPrincipalName,CreatedDateTime,ExternalUserState" `
            -ErrorAction SilentlyContinue
        $recentGuests = @($guestAccounts | Where-Object { $_.CreatedDateTime -ge $Script:StartDate })
        
        if ($recentGuests.Count -gt 0) {
            Write-IRLog "Guest accounts criados recentemente: $($recentGuests.Count) [T1136.003]" `
                -Severity "MEDIUM" -MITRETechnique "T1136.003" -MITRETactic "Persistence"
            Export-IRData -FileName "03_recent_guest_accounts" -Data ($recentGuests | Select-Object DisplayName, UserPrincipalName, CreatedDateTime, ExternalUserState)
        }
        
    } catch { Write-IRLog "Erro ao verificar contas: $_" -Severity "INFO" }
    
    # Audit Log: Role assignments
    Write-Host "  >> Auditando role assignments..." -ForegroundColor Gray
    if (-not $Script:SkipUAL) {
        try {
            $roleAudit = Invoke-UALSearch `
                -StartDate $Script:StartDate `
                -EndDate $Script:EndDate `
                -Operations @("Add member to role","Remove member from role","Add eligible member to role") `
                -ResultSize 1000 `
                -ErrorAction SilentlyContinue
            
            if ($roleAudit.Count -gt 0) {
                Write-IRLog "Role Changes: $($roleAudit.Count) no periodo [T1098.003]" `
                    -Severity "HIGH" -MITRETechnique "T1098.003" -MITRETactic "Privilege Escalation"
                
                $roleData = $roleAudit | ForEach-Object {
                    # FIX BUG_AUDITJSON + BUG_AUDIT_NULL_USE: safe parse com null guard
                    $audit = [PSCustomObject]@{ UserId = "N/A"; ObjectId = "N/A"; ClientIP = "N/A"; ModifiedProperties = $null }
                    try { 
                        $parsed = $_ | Select-Object -ExpandProperty AuditData | ConvertFrom-Json -ErrorAction Stop
                        if ($parsed) { $audit = $parsed }
                    } catch { }
                    # FIX BUG_FOREACHOBJ_CONTINUE: 'continue' dentro de ForEach-Object termina
                    # toda a pipeline (nao apenas o item atual) - usar 'return' para saltar
                    if (-not $audit) { return }
                    [PSCustomObject]@{
                        Timestamp      = $_.CreationDate
                        Operation      = $_.Operations
                        Actor          = $audit.UserId
                        TargetUser     = if ($audit.ObjectId) { $audit.ObjectId } else { "N/A" }
                        RoleName       = if ($audit.ModifiedProperties) {
                                            ($audit.ModifiedProperties | Where-Object {$_.Name -eq "Role.DisplayName"}).NewValue
                                         } else { "N/A" }
                        ClientIP       = $audit.ClientIP
                    }
                }
                Export-IRData -FileName "03_role_changes" -Data $roleData
            }
            
            # PIM activations
            $pimAudit = Invoke-UALSearch `
                -StartDate $Script:StartDate `
                -EndDate $Script:EndDate `
                -Operations @("Add member to role completed (PIM activation)") `
                -ResultSize 500 `
                -ErrorAction SilentlyContinue
            
            if ($pimAudit.Count -gt 0) {
                Write-IRLog "PIM Activations: $($pimAudit.Count) ativacoes [T1548.005]" -Severity "INFO"
                Export-IRData -FileName "03_pim_activations" -Data ($pimAudit | Select-Object CreationDate, Operations, UserIds, AuditData)
            }
            
        } catch { Write-IRLog "UAL Role Audit: $_" -Severity "INFO" }
    }
}

# ============================================================
# MODULO 5: EXCHANGE - EMAIL RULES & FORWARDING
# ============================================================

function Get-ExchangeSuspiciousActivity {
    # T1114.003 - Email Forwarding Rule | T1564.008 - Email Hiding Rules | T1098.002 - Delegate Perms
    Write-Section "EXCHANGE: REGRAS & FORWARDING SUSPEITO" "T1114.003/T1564.008" "Collection / Defense Evasion"
    
    if ($Script:SkipExchange) { Write-IRLog "Exchange module skipped por parametro" -Severity "INFO"; return }

    # FIX: verificar se cmdlets EXO estao disponiveis (falha quando EXO nao conectou)
    if (-not (Test-EXOAvailable)) {
        Write-IRLog "Exchange cmdlets indisponiveis - EXO nao conectou (broker MSAL bug em PS5.1/.NET4.8)" -Severity "HIGH"
        Write-IRLog "FIX: Executar em PS7 (pwsh.exe) ou: Connect-ExchangeOnline -Device" -Severity "INFO"
        return
    }
    Write-Host "  >> Auditando inbox rules (todos os mailboxes)..." -ForegroundColor Gray
    try {
        $allMailboxes = @(Get-Mailbox -ResultSize Unlimited -ErrorAction SilentlyContinue)
        if ($allMailboxes.Count -eq 0) {
            Write-IRLog "Sem mailboxes encontrados ou sem permissao Get-Mailbox" -Severity "MEDIUM"
            return
        }
        $suspiciousRules = [System.Collections.Generic.List[PSObject]]::new()
        
        $mbxTotal = $allMailboxes.Count
        $mbxIdx   = 0
        foreach ($mbx in $allMailboxes) {
            $mbxIdx++
            if ($mbxIdx % 10 -eq 0 -or $mbxIdx -eq 1) {
                Write-Host "    [$mbxIdx/$mbxTotal] $($mbx.UserPrincipalName.Split('@')[0])..." -ForegroundColor DarkGray
            }
            $rules = Get-InboxRule -Mailbox $mbx.UserPrincipalName -ErrorAction SilentlyContinue
            foreach ($rule in $rules) {
                $isSuspicious = $false
                $reason = @()
                
                if ($rule.ForwardTo) {
                    $externalFwd = $rule.ForwardTo | Where-Object { $_ -notmatch $mbx.PrimarySmtpAddress.Split("@")[1] }
                    if ($externalFwd) { $isSuspicious = $true; $reason += "ForwardTo:External" }
                }
                if ($rule.ForwardAsAttachmentTo) { $isSuspicious = $true; $reason += "ForwardAsAttachment" }
                if ($rule.RedirectTo) {
                    $externalRedir = $rule.RedirectTo | Where-Object { $_ -notmatch $mbx.PrimarySmtpAddress.Split("@")[1] }
                    if ($externalRedir) { $isSuspicious = $true; $reason += "RedirectTo:External" }
                }
                if ($rule.DeleteMessage -eq $true) { $isSuspicious = $true; $reason += "DeleteMessage" }
                if ($rule.MoveToFolder -match "RSS|Trash|Deleted|Junk") { $isSuspicious = $true; $reason += "MoveToHiddenFolder" }
                if ($rule.MarkAsRead -eq $true -and ($rule.DeleteMessage -or $rule.MoveToFolder)) {
                    $isSuspicious = $true; $reason += "MarkRead+Delete"
                }
                
                if ($isSuspicious) {
                    $record = [PSCustomObject]@{
                        Mailbox         = $mbx.UserPrincipalName
                        RuleName        = $rule.Name
                        RuleEnabled     = $rule.Enabled
                        ForwardTo       = $rule.ForwardTo -join ";"
                        RedirectTo      = $rule.RedirectTo -join ";"
                        DeleteMessage   = $rule.DeleteMessage
                        MoveToFolder    = $rule.MoveToFolder
                        Reasons         = $reason -join " | "
                    }
                    $suspiciousRules.Add($record)
                    
                    $sev = if ($reason -match "Forward|Redirect") { "CRITICAL" } else { "HIGH" }
                    Write-IRLog "Inbox Rule Suspeita: $($mbx.UserPrincipalName) >> '$($rule.Name)' [$($reason -join ', ')] [T1114.003]" `
                        -Severity $sev -MITRETechnique "T1114.003" -MITRETactic "Collection" -Data $record
                }
            }
        }
        Export-IRData -FileName "04_suspicious_inbox_rules" -Data $suspiciousRules
        
    } catch { Write-IRLog "Erro ao verificar inbox rules: $_" -Severity "INFO" }
    
    # External Mail Forwarding (Mailbox level)
    # FIX BUG_FWD_FALSEPOS: filtrar forwardings internos ao mesmo dominio
    Write-Host "  >> Verificando forwarding externo ao nivel do mailbox..." -ForegroundColor Gray
    try {
        # Obter dominios aceites do tenant para comparacao
        $acceptedDomainsList = @()
        try {
            $acceptedDomainsList = (Get-AcceptedDomain -ErrorAction SilentlyContinue).DomainName
        } catch { }

        $forwardingMailboxes = Get-Mailbox -ResultSize Unlimited -Filter {
            DeliverToMailboxAndForward -eq $true -or ForwardingSMTPAddress -ne $null
        } -ErrorAction SilentlyContinue

        $forwarding = foreach ($mbx in $forwardingMailboxes) {
            $fwdAddr = $mbx.ForwardingSMTPAddress -replace "smtp:","" -replace "SMTP:",""
            $fwdDomain = if ($fwdAddr -match "@") { $fwdAddr.Split("@")[1] } else { "" }
            $isExternal = $fwdDomain -and ($fwdDomain -notin $acceptedDomainsList)

            [PSCustomObject]@{
                UserPrincipalName         = $mbx.UserPrincipalName
                ForwardingAddress         = $mbx.ForwardingAddress
                ForwardingSMTPAddress     = $mbx.ForwardingSMTPAddress
                DeliverToMailboxAndForward = $mbx.DeliverToMailboxAndForward
                ForwardDomain             = $fwdDomain
                IsExternalForward         = $isExternal
            }
        }

        if ($forwarding) {
            foreach ($fwd in $forwarding) {
                if ($fwd.IsExternalForward) {
                    Write-IRLog "Mailbox Forwarding EXTERNO (dominio externo): $($fwd.UserPrincipalName) >> $($fwd.ForwardingSMTPAddress) [T1114.003]" `
                        -Severity "CRITICAL" -MITRETechnique "T1114.003" -MITRETactic "Collection" -Data $fwd
                } elseif ($fwd.ForwardingSMTPAddress) {
                    Write-IRLog "Mailbox Forwarding interno: $($fwd.UserPrincipalName) >> $($fwd.ForwardingSMTPAddress) (mesmo tenant)" `
                        -Severity "LOW" -MITRETechnique "T1114.003" -MITRETactic "Collection" -Data $fwd
                } else {
                    # ForwardingAddress sem SMTP (AD contact) - verificar manualmente
                    Write-IRLog "Mailbox Forwarding (AD Contact): $($fwd.UserPrincipalName) >> $($fwd.ForwardingAddress) - verificar destino [T1114.003]" `
                        -Severity "MEDIUM" -MITRETechnique "T1114.003" -MITRETactic "Collection" -Data $fwd
                }
            }
            Export-IRData -FileName "04_mailbox_forwarding" -Data $forwarding
        }
    } catch { Write-IRLog "Erro ao verificar mailbox forwarding: $_" -Severity "INFO" }
    
    # Transport Rules (Tenant Level)
    Write-Host "  >> Analisando transport rules do tenant..." -ForegroundColor Gray
    try {
        $transportRules = @(Get-TransportRule -ErrorAction SilentlyContinue)
        $suspiciousTransport = @($transportRules | Where-Object {
            $_.BlindCopyTo -or
            $_.RedirectMessageTo -or
            $_.CopyTo
        })
        
        if ($suspiciousTransport.Count -gt 0) {
            foreach ($rule in $suspiciousTransport) {
                Write-IRLog "Transport Rule suspeita: '$($rule.Name)' - BCC/Forward/Redirect ativo [T1114.003]" `
                    -Severity "HIGH" -MITRETechnique "T1114.003" -MITRETactic "Collection"
            }
            Export-IRData -FileName "04_suspicious_transport_rules" -Data ($suspiciousTransport | Select-Object Name, BlindCopyTo, RedirectMessageTo, CopyTo, State, WhenChanged)
        }
        Export-IRData -FileName "04_all_transport_rules" -Data ($transportRules | Select-Object Name, State, Priority, WhenChanged, WhenCreated)
    } catch { Write-IRLog "Erro ao verificar transport rules: $_" -Severity "INFO" }
    
    # Mailbox Delegations
    # FIX BUG_MBXLOOP: reutilizar $allMailboxes ja obtido acima - sem segundo Get-Mailbox
    Write-Host "  >> Verificando delegacoes de mailbox..." -ForegroundColor Gray
    try {
        $delegations = [System.Collections.Generic.List[PSObject]]::new()
        
        foreach ($mbx in $allMailboxes) {
            $perms = Get-MailboxPermission -Identity $mbx.UserPrincipalName -ErrorAction SilentlyContinue |
                Where-Object { $_.User -notmatch "NT AUTHORITY|SELF" -and $_.IsInherited -eq $false }
            
            foreach ($perm in $perms) {
                $record = [PSCustomObject]@{
                    Mailbox      = $mbx.UserPrincipalName
                    DelegatedTo  = $perm.User
                    AccessRights = $perm.AccessRights -join ";"
                    IsInherited  = $perm.IsInherited
                }
                $delegations.Add($record)
            }
        }
        
        if ($delegations.Count -gt 0) {
            Write-IRLog "Delegacoes de mailbox: $($delegations.Count) entradas [T1098.002]" `
                -Severity "MEDIUM" -MITRETechnique "T1098.002" -MITRETactic "Persistence"
            Export-IRData -FileName "04_mailbox_delegations" -Data $delegations
        }
    } catch { Write-IRLog "Erro ao verificar delegacoes: $_" -Severity "INFO" }
    
    # Send-As permissions
    Write-Host "  >> Verificando Send-As grants..." -ForegroundColor Gray
    try {
        $sendAsPerms = @(Get-RecipientPermission -ResultSize Unlimited -ErrorAction SilentlyContinue |
            Where-Object { $_.Trustee -notmatch "NT AUTHORITY|SELF" })
        
        if ($sendAsPerms.Count -gt 0) {
            Write-IRLog "Send-As permissions: $($sendAsPerms.Count) grants [T1098.002]" `
                -Severity "MEDIUM" -MITRETechnique "T1098.002" -MITRETactic "Persistence"
            Export-IRData -FileName "04_send_as_permissions" -Data ($sendAsPerms | Select-Object Identity, Trustee, AccessControlType, AccessRights)
        }
    } catch { Write-IRLog "Erro ao verificar Send-As: $_" -Severity "INFO" }
}

# ============================================================
# MODULO 6: OAUTH APPS & SERVICE PRINCIPALS
# ============================================================

function Get-SuspiciousOAuthApps {
    # T1550.001 - Application Access Token | T1098.003 - Cloud App Integration | T1528 - Steal App Access Token
    Write-Section "OAUTH APPS & SERVICE PRINCIPALS" "T1550.001/T1528/T1098.003" "Persistence / Credential Access"
    
    try {
        # OAuth Consent Grants
        Write-Host "  >> Analisando OAuth consent grants..." -ForegroundColor Gray
        $oauthGrants = @(Get-MgOauth2PermissionGrant -All -ErrorAction SilentlyContinue)
        
        $highRiskScopes = @(
            "Mail.ReadWrite","Mail.Read","Mail.Send",
            "Files.ReadWrite.All","Files.Read.All",
            "Calendars.ReadWrite","Contacts.ReadWrite",
            "MailboxSettings.ReadWrite","full_access_as_user",
            "offline_access","Directory.ReadWrite.All","User.ReadWrite.All"
        )
        
        $riskyGrants = @($oauthGrants | Where-Object {
            $scopes = $_.Scope -split " "
            $scopes | Where-Object { $_ -in $highRiskScopes }
        })

        if ($riskyGrants.Count -gt 0) {
            # FIX: Resolver ClientId para nome da app para melhor legibilidade
            $riskyGrantsDetail = foreach ($grant in $riskyGrants) {
                $appName = "Unknown"
                try {
                    $sp = Get-MgServicePrincipal -ServicePrincipalId $grant.ClientId -ErrorAction SilentlyContinue
                    if ($sp) { $appName = $sp.DisplayName }
                } catch { }
                $userName = "N/A"
                try {
                    if ($grant.PrincipalId) {
                        $u = Get-MgUser -UserId $grant.PrincipalId -Property "UserPrincipalName" -ErrorAction SilentlyContinue
                        if ($u) { $userName = $u.UserPrincipalName }
                    }
                } catch { }
                [PSCustomObject]@{
                    AppName     = $appName
                    ClientId    = $grant.ClientId
                    ConsentType = $grant.ConsentType
                    GrantedTo   = $userName
                    Scopes      = $grant.Scope
                    ResourceId  = $grant.ResourceId
                }
            }
            Write-IRLog "OAuth Grants ALTO RISCO: $($riskyGrants.Count) - Apps: $(($riskyGrantsDetail.AppName | Sort-Object -Unique) -join ', ') [T1550.001]" `
                -Severity "HIGH" -MITRETechnique "T1550.001" -MITRETactic "Defense Evasion"
            Export-IRData -FileName "05_risky_oauth_grants" -Data $riskyGrantsDetail
        }
        
        # Service Principals criados recentemente
        Write-Host "  >> Verificando service principals recentes..." -ForegroundColor Gray
        $filterDate = $Script:FilterDate
        $recentSPs = @(Get-MgServicePrincipal -Filter "createdDateTime ge $filterDate" `
            -Property "Id,DisplayName,AppId,CreatedDateTime,ServicePrincipalType,AppOwnerOrganizationId" `
            -ErrorAction SilentlyContinue)
        
        if ($recentSPs.Count -gt 0) {
            Write-IRLog "Service Principals criados recentemente: $($recentSPs.Count) [T1098.003]" `
                -Severity "MEDIUM" -MITRETechnique "T1098.003" -MITRETactic "Persistence"
            Export-IRData -FileName "05_recent_service_principals" -Data ($recentSPs | Select-Object DisplayName, AppId, CreatedDateTime, ServicePrincipalType, AppOwnerOrganizationId)
        }
        
        # Credenciais adicionadas a apps existentes
        Write-Host "  >> Verificando credenciais em applications..." -ForegroundColor Gray
        $apps = @(Get-MgApplication -Property "Id,DisplayName,AppId,CreatedDateTime,KeyCredentials,PasswordCredentials" `
            -All -ErrorAction SilentlyContinue)
        
        $appsWithRecentCreds = [System.Collections.Generic.List[PSObject]]::new()
        foreach ($app in $apps) {
            $recentKeys = @($app.KeyCredentials | Where-Object { $_.StartDateTime -ge $Script:StartDate })
            $recentPwds = @($app.PasswordCredentials | Where-Object { $_.StartDateTime -ge $Script:StartDate })
            
            if ($recentKeys -or $recentPwds) {
                $record = [PSCustomObject]@{
                    AppName           = $app.DisplayName
                    AppId             = $app.AppId
                    RecentKeyCount    = $recentKeys.Count
                    RecentSecretCount = $recentPwds.Count
                    NewCertExpiry     = ($recentKeys | Select-Object -First 1).EndDateTime
                    NewSecretExpiry   = ($recentPwds | Select-Object -First 1).EndDateTime
                }
                $appsWithRecentCreds.Add($record)
                Write-IRLog "Credenciais adicionadas a app '$($app.DisplayName)': $($recentKeys.Count) certs + $($recentPwds.Count) secrets [T1528]" `
                    -Severity "HIGH" -MITRETechnique "T1528" -MITRETactic "Credential Access" -Data $record
            }
        }
        Export-IRData -FileName "05_apps_recent_credentials" -Data $appsWithRecentCreds
        
        # App Role Assignments perigosos
        Write-Host "  >> Verificando app role assignments elevados..." -ForegroundColor Gray
        $dangerousRoles = @(
            "RoleManagement.ReadWrite.Directory","Directory.ReadWrite.All",
            "User.ReadWrite.All","Mail.ReadWrite","Files.ReadWrite.All","full_access_as_app"
        )
        
        $dangerousAssignments = [System.Collections.Generic.List[PSObject]]::new()
        $reportedDangerPerms  = @{}
        $sps = @(Get-MgServicePrincipal -All -Property "Id,DisplayName,AppId" -ErrorAction SilentlyContinue)
        
        $spTotal = $sps.Count
        $spIdx   = 0
        foreach ($sp in $sps) {
            $spIdx++
            if ($spIdx % 25 -eq 0) {
                Write-Host "    [$spIdx/$spTotal] verificando $($sp.DisplayName)..." -ForegroundColor DarkGray
            }
            try {
                $assignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -ErrorAction SilentlyContinue
                foreach ($assignment in $assignments) {
                    $resource = Get-MgServicePrincipal -ServicePrincipalId $assignment.ResourceId -ErrorAction SilentlyContinue
                    if ($resource) {
                        $roleDef = $resource.AppRoles | Where-Object { $_.Id -eq $assignment.AppRoleId }
                        if ($roleDef -and $roleDef.Value -in $dangerousRoles) {
                            $dedupKey = "$($sp.DisplayName)|$($roleDef.Value)"
                            if ($reportedDangerPerms.ContainsKey($dedupKey)) { continue }
                            $reportedDangerPerms[$dedupKey] = $true
                            $record = [PSCustomObject]@{
                                ServicePrincipal = $sp.DisplayName
                                Resource         = $resource.DisplayName
                                Role             = $roleDef.Value
                                AssignedDate     = $assignment.CreatedDateTime
                            }
                            $dangerousAssignments.Add($record)
                            Write-IRLog "App com permissao PERIGOSA: '$($sp.DisplayName)' tem '$($roleDef.Value)' [T1550.001]" `
                                -Severity "HIGH" -MITRETechnique "T1550.001" -MITRETactic "Defense Evasion" -Data $record
                        }
                    }
                }
            } catch { }
        }
        Export-IRData -FileName "05_dangerous_app_permissions" -Data $dangerousAssignments
        
    } catch {
        Write-IRLog "Erro no modulo OAuth: $_" -Severity "INFO"
    }
}

# ============================================================
# MODULO 7: UNIFIED AUDIT LOG - OPERACOES CRITICAS
# ============================================================

function Get-CriticalAuditEvents {
    # T1562.008 - Disable Cloud Logs | T1070.004 - Clear Mailbox | T1137 - Office App Startup
    Write-Section "UNIFIED AUDIT LOG - EVENTOS CRITICOS" "T1562.008/T1070" "Defense Evasion"
    
    if ($Script:SkipUAL) { Write-IRLog "UAL skipped por parametro" -Severity "INFO"; return }

    # FIX: verificar se Search-UnifiedAuditLog esta disponivel
    if (-not (Test-UALAvailable)) {
        Write-IRLog "Search-UnifiedAuditLog indisponivel - requer Exchange Online conectado" -Severity "HIGH"
        Write-IRLog "FIX: Connect-ExchangeOnline antes de executar, ou usar -SkipUAL" -Severity "INFO"
        return
    }

    # Verificar se UAL esta ativo
    try {
        $adminAuditLog = Get-AdminAuditLogConfig -ErrorAction SilentlyContinue
        if ($adminAuditLog.UnifiedAuditLogIngestionEnabled -ne $true) {
            Write-IRLog "UNIFIED AUDIT LOG DESATIVADO - evidencias podem estar em falta! [T1562.008]" `
                -Severity "CRITICAL" -MITRETechnique "T1562.008" -MITRETactic "Defense Evasion"
        } else {
            Write-IRLog "Unified Audit Log: ATIVO" -Severity "SUCCESS"
        }
    } catch { Write-IRLog "Nao foi possivel verificar status do UAL" -Severity "INFO" }
    
    $auditQueries = @(
        @{ Ops = @("Set-AdminAuditLogConfig","Disable-AdminAuditLogConfig");              Label = "Audit_Config_Changes";       MITRE = "T1562.008"; Sev = "CRITICAL" },
        @{ Ops = @("New-ApplicationAccessPolicy","Remove-ApplicationAccessPolicy");       Label = "App_Access_Policy";          MITRE = "T1098.003";     Sev = "HIGH" },
        @{ Ops = @("Add-MailboxPermission","Remove-MailboxPermission");                   Label = "Mailbox_Permission_Changes"; MITRE = "T1098.002"; Sev = "HIGH" },
        @{ Ops = @("Set-Mailbox");                                                        Label = "Mailbox_Config_Changes";     MITRE = "T1114.003"; Sev = "MEDIUM" },
        @{ Ops = @("New-TransportRule","Set-TransportRule","Remove-TransportRule");       Label = "Transport_Rule_Changes";     MITRE = "T1114.003"; Sev = "HIGH" },
        @{ Ops = @("Add-RoleGroupMember","New-RoleGroup");                               Label = "Exchange_Role_Changes";      MITRE = "T1098.003"; Sev = "HIGH" },
        @{ Ops = @("New-InboxRule","Set-InboxRule","Remove-InboxRule");                   Label = "Inbox_Rule_Operations";      MITRE = "T1564.008"; Sev = "HIGH" },
        @{ Ops = @("HardDelete","SoftDelete");                                            Label = "Email_Hard_Deletions";       MITRE = "T1070.004"; Sev = "HIGH" },
        @{ Ops = @("Update application","Add service principal credentials");             Label = "App_Credential_Updates";     MITRE = "T1528";     Sev = "HIGH" },
        @{ Ops = @("Add app role assignment to service principal");                       Label = "App_Role_Assignments";       MITRE = "T1550.001"; Sev = "HIGH" },
        @{ Ops = @("Consent to application","Add OAuth2PermissionGrant");                 Label = "OAuth_Consent_Events";       MITRE = "T1550.001"; Sev = "MEDIUM" },
        @{ Ops = @("FileDownloaded","FileSyncDownloadedFull");                            Label = "Bulk_File_Downloads";        MITRE = "T1530";     Sev = "MEDIUM" },
        @{ Ops = @("AnonymousLinkCreated","SharingInvitationCreated");                    Label = "Anonymous_External_Sharing"; MITRE = "T1567";     Sev = "MEDIUM" },
        @{ Ops = @("ManagedSyncClientAllowed","AddedToSecureLink");                       Label = "SPO_Sync_Events";            MITRE = "T1213.002"; Sev = "INFO" },
        @{ Ops = @("Set-MsolPasswordPolicy","Set-MsolDomainFederationSettings");          Label = "Auth_Policy_Changes";        MITRE = "T1556.007"; Sev = "CRITICAL" }
    )
    
    foreach ($query in $auditQueries) {
        Write-Host "  >> Querying: $($query.Label -replace '_',' ')..." -ForegroundColor Gray
        try {
            $results = Invoke-UALSearch `
                -StartDate $Script:StartDate `
                -EndDate $Script:EndDate `
                -Operations $query.Ops `
                -ResultSize 1000 `
                -ErrorAction SilentlyContinue
            
            if ($results.Count -gt 0) {
                Write-IRLog "$($query.Label -replace '_',' '): $($results.Count) eventos [MITRE $($query.MITRE)]" `
                    -Severity $query.Sev -MITRETechnique $query.MITRE -MITRETactic "Various"
                Export-IRData -FileName "06_ual_$($query.Label.ToLower())" -Data ($results | Select-Object CreationDate, UserIds, Operations, ResultStatus, ClientIP, AuditData)
            }
        } catch { Write-IRLog "UAL Query '$($query.Label)': $_" -Severity "INFO" }
    }
    
    # Bulk download analysis - exfiltracao
    Write-Host "  >> Analisando bulk downloads (indicador de exfiltracao)..." -ForegroundColor Gray
    try {
        $downloads = Invoke-UALSearch `
            -StartDate $Script:StartDate `
            -EndDate $Script:EndDate `
            -Operations @("FileDownloaded","FileSyncDownloadedFull","FileAccessed") `
            -ResultSize 5000 `
            -ErrorAction SilentlyContinue
        
        if ($downloads) {
            $bulkUsers = $downloads | Group-Object UserIds |
                Where-Object { $_.Count -gt 100 } |
                Select-Object @{N="User";E={$_.Name}}, @{N="FileOps";E={$_.Count}}
            
            foreach ($bu in $bulkUsers) {
                Write-IRLog "Bulk Download: $($bu.User) >> $($bu.FileOps) operacoes [T1530]" `
                    -Severity "HIGH" -MITRETechnique "T1530" -MITRETactic "Collection" -Data $bu
            }
        }
    } catch { Write-IRLog "Bulk download analysis: $_" -Severity "INFO" }
}

# ============================================================
# MODULO 8: SHAREPOINT & ONEDRIVE
# ============================================================

function Get-SharePointActivity {
    # T1213.002 - SharePoint | T1530 - Data from Cloud Storage | T1537 - Transfer to Cloud Account
    Write-Section "SHAREPOINT/ONEDRIVE - PARTILHA & ACESSO" "T1213.002/T1530" "Collection / Exfiltration"
    
    if ($Script:SkipUAL) { Write-IRLog "SPO audit via UAL skipped" -Severity "INFO"; return }
    
    # Anonymous sharing
    Write-Host "  >> Verificando partilha anonima..." -ForegroundColor Gray
    try {
        $anonShare = Invoke-UALSearch `
            -StartDate $Script:StartDate `
            -EndDate $Script:EndDate `
            -Operations @("AnonymousLinkCreated","AnonymousLinkUpdated") `
            -ResultSize 1000 `
            -ErrorAction SilentlyContinue
        
        if ($anonShare.Count -gt 0) {
            Write-IRLog "Partilhas Anonimas criadas: $($anonShare.Count) [T1567.002]" `
                -Severity "HIGH" -MITRETechnique "T1567.002" -MITRETactic "Exfiltration"
            Export-IRData -FileName "07_anonymous_shares" -Data ($anonShare | Select-Object CreationDate, UserIds, ObjectId, ClientIP)
        }
        
        # External sharing invitations
        $extShare = Invoke-UALSearch `
            -StartDate $Script:StartDate `
            -EndDate $Script:EndDate `
            -Operations @("SharingInvitationCreated","AddedToSecureLink") `
            -ResultSize 1000 `
            -ErrorAction SilentlyContinue
        
        if ($extShare.Count -gt 0) {
            Write-IRLog "External Sharing: $($extShare.Count) convites criados [T1213.002]" `
                -Severity "MEDIUM" -MITRETechnique "T1213.002" -MITRETactic "Collection"
            Export-IRData -FileName "07_external_sharing" -Data ($extShare | Select-Object CreationDate, UserIds, ObjectId, ClientIP, AuditData)
        }
        
        # Webhook / Flow criados (exfiltration via automation)
        $webhookEvents = Invoke-UALSearch `
            -StartDate $Script:StartDate `
            -EndDate $Script:EndDate `
            -Operations @("CreateConnector","CreateFlow","AddWebhook") `
            -ResultSize 500 `
            -ErrorAction SilentlyContinue
        
        if ($webhookEvents.Count -gt 0) {
            Write-IRLog "Webhooks/Flows criados: $($webhookEvents.Count) [T1567.002 - Exfiltration over Webhook]" `
                -Severity "HIGH" -MITRETechnique "T1567.002" -MITRETactic "Exfiltration"
            Export-IRData -FileName "07_webhook_flow_created" -Data ($webhookEvents | Select-Object CreationDate, UserIds, Operations, AuditData)
        }
        
    } catch { Write-IRLog "Erro SharePoint module: $_" -Severity "INFO" }
}

# ============================================================
# MODULO 9: OUTLOOK FORMS, ADD-INS, HOMEPAGE
# ============================================================

function Get-OutlookPersistenceMechanisms {
    # T1137 - Office Application Startup (Forms, Home Page, Outlook Rules, Add-ins)
    Write-Section "OFFICE PERSISTENCE: FORMS/ADD-INS/HOMEPAGE" "T1137" "Persistence"
    
    if ($Script:SkipExchange) { Write-IRLog "Exchange module skipped" -Severity "INFO"; return }
    
    # Outlook Home Page (explorada em ataques BEC avancados)
    Write-Host "  >> Verificando Outlook Home Page configs..." -ForegroundColor Gray
    try {
        $allMailboxes = Get-Mailbox -ResultSize Unlimited -ErrorAction SilentlyContinue
        $homepageResults = [System.Collections.Generic.List[PSObject]]::new()
        
        foreach ($mbx in $allMailboxes) {
            try {
                $folders = Get-MailboxFolder -Identity "$($mbx.UserPrincipalName):\Inbox" -ErrorAction SilentlyContinue
                if ($folders -and $folders.HomePageURL) {
                    $record = [PSCustomObject]@{
                        Mailbox     = $mbx.UserPrincipalName
                        FolderPath  = $folders.FolderPath
                        HomePageURL = $folders.HomePageURL
                    }
                    $homepageResults.Add($record)
                    Write-IRLog "Outlook Home Page URL configurada em $($mbx.UserPrincipalName): $($folders.HomePageURL) [T1137.004]" `
                        -Severity "CRITICAL" -MITRETechnique "T1137.004" -MITRETactic "Persistence" -Data $record
                }
            } catch { }
        }
        
        if ($homepageResults.Count -gt 0) {
            Export-IRData -FileName "08_outlook_homepage" -Data $homepageResults
        }
    } catch { Write-IRLog "Erro Outlook Home Page check: $_" -Severity "INFO" }
    
    # Add-ins via UAL
    Write-Host "  >> Verificando add-ins instalados..." -ForegroundColor Gray
    if (-not $Script:SkipUAL) {
        try {
            $addins = Invoke-UALSearch `
                -StartDate $Script:StartDate `
                -EndDate $Script:EndDate `
                -Operations @("Install","New-App","Set-App") `
                -ResultSize 500 `
                -ErrorAction SilentlyContinue
            
            if ($addins.Count -gt 0) {
                Write-IRLog "Add-ins instalados/modificados: $($addins.Count) [T1137.006]" `
                    -Severity "MEDIUM" -MITRETechnique "T1137.006" -MITRETactic "Persistence"
                Export-IRData -FileName "08_addins_activity" -Data ($addins | Select-Object CreationDate, UserIds, Operations, AuditData)
            }
        } catch { Write-IRLog "Erro UAL Add-ins: $_" -Severity "INFO" }
    }
    
    # Outlook Forms via Mailbox Folders
    Write-Host "  >> Verificando custom forms em mailboxes..." -ForegroundColor Gray
    try {
        # IPM.Note.Custom = custom Outlook form (vetor de persistencia T1137.003)
        $customForms = Invoke-UALSearch `
            -StartDate $Script:StartDate `
            -EndDate $Script:EndDate `
            -Operations @("Bind","Create") `
            -ResultSize 1000 `
            -ErrorAction SilentlyContinue | Where-Object {
                $_.AuditData -match "IPM.Note." -and $_.AuditData -notmatch "IPM.Note\b"
            }
        
        if ($customForms -and $customForms.Count -gt 0) {
            Write-IRLog "Custom Outlook Forms detetados: $($customForms.Count) [T1137.003]" `
                -Severity "HIGH" -MITRETechnique "T1137.003" -MITRETactic "Persistence"
            Export-IRData -FileName "08_custom_outlook_forms" -Data ($customForms | Select-Object CreationDate, UserIds, Operations, AuditData)
        }
    } catch { Write-IRLog "Erro custom forms check: $_" -Severity "INFO" }
}

# ============================================================
# MODULO 10: DISCOVERY & SERVERLESS EXECUTION
# ============================================================

function Get-TenantDiscoveryActivity {
    # T1087 - Account Discovery | T1069 - Permission Groups | T1648 - Serverless Execution | T1059.009 - Cloud API
    Write-Section "DISCOVERY & EXECUTION" "T1087/T1069/T1648/T1059.009" "Discovery / Execution"
    
    if ($Script:SkipUAL) { Write-IRLog "UAL skipped" -Severity "INFO"; return }
    
    # Power Automate flows suspeitos
    Write-Host "  >> Analisando Power Automate flows..." -ForegroundColor Gray
    try {
        $flowAudit = Invoke-UALSearch `
            -StartDate $Script:StartDate `
            -EndDate $Script:EndDate `
            -RecordType "MicrosoftFlow" `
            -ResultSize 1000 `
            -ErrorAction SilentlyContinue
        
        if ($flowAudit.Count -gt 0) {
            Write-IRLog "Power Automate flows: $($flowAudit.Count) eventos [T1648]" `
                -Severity "INFO" -MITRETechnique "T1648" -MITRETactic "Execution"
            Export-IRData -FileName "09_power_automate_flows" -Data ($flowAudit | Select-Object CreationDate, UserIds, Operations, AuditData)
            
            # Flows criados vs modificados
            $newFlows = @($flowAudit | Where-Object { $_.Operations -match "CreateFlow|EnableFlow" })
            if ($newFlows.Count -gt 0) {
                Write-IRLog "Novos Flows criados/ativados: $($newFlows.Count) [T1648]" `
                    -Severity "MEDIUM" -MITRETechnique "T1648" -MITRETactic "Execution"
            }
        }
    } catch { Write-IRLog "Erro Power Automate: $_" -Severity "INFO" }
    
    # PowerShell / Graph API access remoto
    Write-Host "  >> Verificando acessos PowerShell/API remotos..." -ForegroundColor Gray
    try {
        $psAccess = Invoke-UALSearch `
            -StartDate $Script:StartDate `
            -EndDate $Script:EndDate `
            -Operations @("Connect-ExchangeOnline") `
            -ResultSize 500 `
            -ErrorAction SilentlyContinue
        
        if ($psAccess.Count -gt 0) {
            Write-IRLog "Sessions PowerShell remotas ao Exchange: $($psAccess.Count) [T1059.009]" -Severity "INFO"
            Export-IRData -FileName "09_remote_powershell_sessions" -Data ($psAccess | Select-Object CreationDate, UserIds, ClientIP, AuditData)
        }
    } catch { Write-IRLog "Erro PS access check: $_" -Severity "INFO" }
}

# ============================================================
# MODULO 11: TEAMS - CREDENTIAL & DATA EXPOSURE
# ============================================================

function Get-TeamsSuspiciousActivity {
    # T1552.008 - Credentials in Chat | T1534 - Internal Spearphishing | T1213.005 - Messaging Apps
    Write-Section "MICROSOFT TEAMS - EXPOSICAO & LATERAL MOVEMENT" "T1552.008/T1534/T1213.005" "Credential Access / Lateral Movement"
    
    if ($Script:SkipUAL) { Write-IRLog "UAL skipped" -Severity "INFO"; return }
    
    try {
        # Teams external access changes
        $teamsGuest = Invoke-UALSearch `
            -StartDate $Script:StartDate `
            -EndDate $Script:EndDate `
            -RecordType "MicrosoftTeams" `
            -Operations @("TeamGuestEnabled","MemberAdded","GuestAdded") `
            -ResultSize 500 `
            -ErrorAction SilentlyContinue
        
        if ($teamsGuest.Count -gt 0) {
            Write-IRLog "Teams External/Guest changes: $($teamsGuest.Count) [T1534 - Internal Spearphishing]" `
                -Severity "MEDIUM" -MITRETechnique "T1534" -MITRETactic "Lateral Movement"
            Export-IRData -FileName "10_teams_guest_changes" -Data ($teamsGuest | Select-Object CreationDate, UserIds, Operations, AuditData)
        }
        
        # Teams DLP - mensagens com dados sensiveis
        $teamsDLP = Invoke-UALSearch `
            -StartDate $Script:StartDate `
            -EndDate $Script:EndDate `
            -RecordType "MicrosoftTeams" `
            -ResultSize 500 `
            -ErrorAction SilentlyContinue | Where-Object {
                $_.Operations -match "MessageCreatedHasLink|MessageCreatedHasLinkToFile"
            }
        
        if ($teamsDLP.Count -gt 0) {
            Write-IRLog "Teams mensagens com links a ficheiros: $($teamsDLP.Count) [T1080 - Taint Shared Content]" `
                -Severity "MEDIUM" -MITRETechnique "T1080" -MITRETactic "Lateral Movement"
            Export-IRData -FileName "10_teams_file_links" -Data ($teamsDLP | Select-Object CreationDate, UserIds, Operations, AuditData)
        }
        
    } catch { Write-IRLog "Erro Teams module: $_" -Severity "INFO" }
}

# ============================================================
# MODULO 12: IMPACT INDICATORS
# ============================================================

function Get-ImpactIndicators {
    # T1531 - Account Access Removal | T1657 - Financial Theft | T1531 - Email Bombing
    Write-Section "INDICADORES DE IMPACTO" "T1531/T1657/T1531" "Impact"
    
    try {
        if (-not $Script:SkipUAL) {
            # Account changes em bulk
            $accountDisables = Invoke-UALSearch `
                -StartDate $Script:StartDate `
                -EndDate $Script:EndDate `
                -Operations @("Disable account","Block sign-in","Reset user password","Delete user") `
                -ResultSize 500 `
                -ErrorAction SilentlyContinue
            
            if ($accountDisables.Count -gt 0) {
                Write-IRLog "Account changes (disable/block/reset/delete): $($accountDisables.Count) [T1531]" `
                    -Severity "MEDIUM" -MITRETechnique "T1531" -MITRETactic "Impact"
                Export-IRData -FileName "11_account_impact_events" -Data ($accountDisables | Select-Object CreationDate, UserIds, Operations, AuditData)
            }
            
            # Bulk password resets (Account Takeover indicator)
            $passwordResetOps = Invoke-UALSearch `
                -StartDate $Script:StartDate `
                -EndDate $Script:EndDate `
                -Operations @("Reset user password","Change user password","Set force change user password") `
                -ResultSize 1000 `
                -ErrorAction SilentlyContinue
            
            $bulkResets = $passwordResetOps | Group-Object UserIds |
                Where-Object { $_.Count -gt 5 } |
                Select-Object @{N="Actor";E={$_.Name}}, @{N="PasswordResets";E={$_.Count}}
            
            foreach ($br in $bulkResets) {
                Write-IRLog "Bulk Password Resets: $($br.Actor) >> $($br.PasswordResets) resets [T1531]" `
                    -Severity "HIGH" -MITRETechnique "T1531" -MITRETactic "Impact" -Data $br
            }
            
            # Email volume anomalo (Email Bombing)
            $emailSend = Invoke-UALSearch `
                -StartDate $Script:StartDate `
                -EndDate $Script:EndDate `
                -Operations @("Send") `
                -ResultSize 5000 `
                -ErrorAction SilentlyContinue
            
            $highSenders = $emailSend | Group-Object UserIds |
                Where-Object { $_.Count -gt 500 } |
                Select-Object @{N="User";E={$_.Name}}, @{N="EmailsSent";E={$_.Count}}
            
            foreach ($hs in $highSenders) {
                Write-IRLog "Possivel Email Bombing/BEC: $($hs.User) >> $($hs.EmailsSent) emails enviados [T1531]" `
                    -Severity "HIGH" -MITRETechnique "T1531" -MITRETactic "Impact" -Data $hs
            }
        }
        
    } catch { Write-IRLog "Erro Impact module: $_" -Severity "INFO" }
}

# ============================================================
# MODULO 13: DEFENSE EVASION CHECKS
# ============================================================

function Get-DefenseEvasionIndicators {
    # T1562.008 - Disable Cloud Logs | T1070.004 - Clear Mailbox | T1606 - SAML Tokens
    Write-Section "DEFENSE EVASION" "T1562.008/T1070.004/T1550/T1606" "Defense Evasion"
    
    try {
        # SAML token anomalias (Golden SAML)
        Write-Host "  >> Verificando SAML/Federation anomalias..." -ForegroundColor Gray
        if (-not $Script:SkipGraph) {
            $filterDate = $Script:FilterDate
            $samlSignins = Get-MgAuditLogSignIn -Filter `
                "createdDateTime ge $filterDate and authenticationProtocol eq 'saml20'" `
                -Top 500 -ErrorAction SilentlyContinue
            
            if ($samlSignins) {
                $suspectSAML = @($samlSignins | Where-Object {
                    $_.ConditionalAccessStatus -ne "success" -or
                    $_.RiskLevel -ne "none"
                })
                if ($suspectSAML.Count -gt 0) {
                    Write-IRLog "SAML sign-ins suspeitos (potencial Golden SAML): $($suspectSAML.Count) [T1606.002]" `
                        -Severity "HIGH" -MITRETechnique "T1606.002" -MITRETactic "Defense Evasion"
                    Export-IRData -FileName "12_saml_suspicious" -Data ($suspectSAML | Select-Object UserPrincipalName, CreatedDateTime, IPAddress, RiskLevel, ConditionalAccessStatus)
                }
            }
        }
        
        # Federation/Domain changes (Hybrid Identity attack)
        if (-not $Script:SkipUAL) {
            $federationChanges = Invoke-UALSearch `
                -StartDate $Script:StartDate `
                -EndDate $Script:EndDate `
                -Operations @("Set federation settings on domain","Set domain authentication") `
                -ResultSize 100 `
                -ErrorAction SilentlyContinue
            
            if ($federationChanges.Count -gt 0) {
                Write-IRLog "FEDERATION CHANGES: $($federationChanges.Count) alteracoes - potencial Hybrid Identity attack [T1556.007]!" `
                    -Severity "CRITICAL" -MITRETechnique "T1556.007" -MITRETactic "Defense Evasion"
                Export-IRData -FileName "12_federation_changes" -Data ($federationChanges | Select-Object CreationDate, UserIds, Operations, ClientIP, AuditData)
            }
            
            # Indicator Removal - Clear Mailbox Data
            $mailboxCleared = Invoke-UALSearch `
                -StartDate $Script:StartDate `
                -EndDate $Script:EndDate `
                -Operations @("HardDelete","MoveToDeletedItems","Purge") `
                -ResultSize 2000 `
                -ErrorAction SilentlyContinue
            
            $bulkDelete = $mailboxCleared | Group-Object UserIds |
                Where-Object { $_.Count -gt 50 } |
                Select-Object @{N="User";E={$_.Name}}, @{N="DeletedItems";E={$_.Count}}
            
            foreach ($bd in $bulkDelete) {
                Write-IRLog "Bulk Delete/Purge: $($bd.User) >> $($bd.DeletedItems) items eliminados [T1070.004]" `
                    -Severity "HIGH" -MITRETechnique "T1070.004" -MITRETactic "Defense Evasion" -Data $bd
            }
        }
        
        # Email Spoofing indicators (DKIM/SPF bypass)
        if (-not $Script:SkipExchange) {
            Write-Host "  >> Verificando DKIM/DMARC/SPF config..." -ForegroundColor Gray
            try {
                $dkimConfig = Get-DkimSigningConfig -ErrorAction SilentlyContinue
                $dkimDisabled = @($dkimConfig | Where-Object { $_.Enabled -eq $false })
                if ($dkimDisabled.Count -gt 0) {
                    Write-IRLog "DKIM desativado para dominios: $($dkimDisabled.Domain -join ', ') [T1566.002 - Email Spoofing]" `
                        -Severity "MEDIUM" -MITRETechnique "T1566.002" -MITRETactic "Defense Evasion"
                    Export-IRData -FileName "12_dkim_disabled_domains" -Data $dkimDisabled
                }
            } catch { Write-IRLog "Erro DKIM check: $_" -Severity "INFO" }
        }
        
    } catch { Write-IRLog "Erro Defense Evasion module: $_" -Severity "INFO" }
}

# ============================================================
# RELATORIO FINAL - HTML
# ============================================================

function New-HTMLReport {
    Write-Section "GERANDO RELATORIO HTML"

    $critCount     = $Script:Stats.CRITICAL
    $highCount     = $Script:Stats.HIGH
    $medCount      = $Script:Stats.MEDIUM
    $lowCount      = $Script:Stats.LOW
    $totalFindings = $critCount + $highCount + $medCount + $lowCount
    $duration      = [math]::Round(((Get-Date) - $Script:StartTime).TotalMinutes, 1)

    function hx([string]$s,[int]$max=300) {
        if (-not $s) { return "" }
        $t = if ($s.Length -gt $max) { $s.Substring(0,$max)+"..." } else { $s }
        return [System.Web.HttpUtility]::HtmlEncode($t)
    }

    function evHtmlFrom($data) {
        if ($null -eq $data) { return "" }
        $rows = ""
        try {
            # Suporte a string simples
            if ($data -is [string]) {
                if ($data) { return "<div class='ev-str'>$(hx $data)</div>" }
                return ""
            }
            # Suporte a array/lista
            if ($data -is [System.Collections.IEnumerable] -and $data -isnot [string] -and $data -isnot [hashtable]) {
                $arr = @($data)
                if ($arr.Count -gt 0 -and $arr.Count -le 10) {
                    foreach ($item in $arr) {
                        $rows += "<tr><td colspan='2' class='ev'>$(hx ($item | Out-String).Trim())</td></tr>"
                    }
                }
                if ($rows) { return "<table class='etbl'>$rows</table>" }
                return ""
            }
            $props = if ($data -is [hashtable]) {
                $data.GetEnumerator() | Sort-Object Key
            } else {
                $data.PSObject.Properties | Sort-Object Name
            }
            foreach ($p in $props) {
                $v = ($p.Value | Out-String).Trim()
                if ($v -and $v -ne "") {
                    $rows += "<tr><td class='ek'>$(hx $p.Name)</td><td class='ev'>$(hx $v 400)</td></tr>"
                }
            }
        } catch {}
        if ($rows) { return "<table class='etbl'>$rows</table>" }
        return ""
    }

    # ---- Finding rows ----
    $findingRows = foreach ($f in $Script:Findings) {
        $sevClass = switch ($f.Severity) {
            "CRITICAL" { "sc" } "HIGH" { "sh" } "MEDIUM" { "sm" } "LOW" { "sl" } default { "si" }
        }
        $rid   = "r$([guid]::NewGuid().ToString('N').Substring(0,8))"
        $emsg  = hx $f.Message
        $mlink = if ($f.Technique) {
            # MITRE URL format: T1562.008 -> /techniques/T1562/008/
            $techUrl = $f.Technique.Split('/')[0] -replace '\.','/'
            "<a class='ml' href='https://attack.mitre.org/techniques/$techUrl/' target='_blank'>$($f.Technique)</a>"
        } else { "" }
        $ev    = evHtmlFrom $f.Data
        $hasEv = $ev -ne ""

        $csvFiles = @(Get-ChildItem -Path $Script:OutputPath -Filter "*.csv" -ErrorAction SilentlyContinue)
        $csvPfx = switch -Wildcard ($f.Technique) {
            "T1114*" {"04_"} "T1110*" {"01_"} "T1078*" {"01_"} "T1550*" {"05_"} "T1528*" {"05_"}
            "T1098*" {"04_"} "T1136*" {"03_"} "T1562*" {"06_"} "T1530*" {"07_"} default {""}
        }
        $csvLnk = ""
        if ($csvPfx) {
            $cm = $csvFiles | Where-Object { $_.Name.StartsWith($csvPfx) } | Select-Object -First 1
            if ($cm) { $csvLnk = "<a class='cl' href='$($cm.Name)'>CSV</a>" }
        }
        $evBtn  = if ($hasEv) { "<button class='eb' onclick='te(`"$rid`")''>+</button>" } else { "" }
        $tact   = hx $f.Tactic
        $ts     = if ($f.Timestamp.Length -ge 16) { $f.Timestamp.Substring(11,5) } else { $f.Timestamp }

        @"
<tr class='fr $sevClass' data-sev='$($f.Severity)' data-tac='$tact'>
<td class='sc-cell'><span class='sp $sevClass'>$($f.Severity)</span></td>
<td class='tc'>$ts</td>
<td class='mc'><span class='mt'>$emsg</span><span class='ra'>$evBtn $csvLnk $mlink</span></td>
<td class='tac'>$tact</td>
</tr>
$(if ($hasEv) { "<tr id='$rid' class='er' style='display:none'><td colspan='4'><div class='ed'>$ev</div></td></tr>" })
"@
    }
    $findingsHTML = $findingRows -join ""

    # ---- Pivot de findings CRITICAL/HIGH por entidade (user, app, dominio) ----
    $entityMap = @{}
    foreach ($f in $Script:Findings) {
        if ($f.Severity -notin @("CRITICAL","HIGH")) { continue }

        $entities = @()
        # 1. UPNs / emails
        [regex]::Matches($f.Message, '[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}') | ForEach-Object {
            $entities += @{ Key = $_.Value; Type = "user" }
        }
        # 2. Nomes de apps entre aspas simples: 'AppName'
        [regex]::Matches($f.Message, "'([^']{3,50})'") | ForEach-Object {
            $entities += @{ Key = $_.Groups[1].Value; Type = "app" }
        }
        # 3. Dominios mencionados explicitamente
        [regex]::Matches($f.Message, "dominio[s]?\s+([\w.\-]+)", [System.Text.RegularExpressions.RegexOptions]::IgnoreCase) | ForEach-Object {
            $entities += @{ Key = $_.Groups[1].Value; Type = "domain" }
        }
        # Fallback: se nenhuma entidade encontrada, usar primeiros 60 chars do finding
        if ($entities.Count -eq 0) {
            $shortMsg = if ($f.Message.Length -gt 60) { $f.Message.Substring(0,60) + "..." } else { $f.Message }
            $entities += @{ Key = $shortMsg; Type = "finding" }
        }
        foreach ($e in $entities) {
            $k = $e.Key
            if (-not $entityMap.ContainsKey($k)) {
                $entityMap[$k] = @{
                    Type     = $e.Type
                    Findings = [System.Collections.ArrayList]::new()
                }
            }
            [void]$entityMap[$k].Findings.Add($f)
        }
    }

    $uRows = ""
    foreach ($k in ($entityMap.Keys | Sort-Object)) {
        $entry = $entityMap[$k]
        $fs    = $entry.Findings
        $cc    = @($fs | Where-Object { $_.Severity -eq "CRITICAL" }).Count
        $hc    = @($fs | Where-Object { $_.Severity -eq "HIGH" }).Count
        if ($cc -eq 0 -and $hc -eq 0) { continue }
        $rs    = $cc*10 + $hc*5
        $rsc   = if ($cc -gt 0) { "sc" } elseif ($hc -gt 2) { "sh" } else { "sm" }
        $tacs  = ($fs.Tactic | Sort-Object -Unique) -join " &middot; "
        $tecs  = ($fs.Technique | Where-Object {$_} | Sort-Object -Unique) -join " "
        if     ($entry.Type -eq "user")   { $typeIcon = "&#128100;" }
        elseif ($entry.Type -eq "app")    { $typeIcon = "&#128196;" }
        elseif ($entry.Type -eq "domain") { $typeIcon = "&#127760;" }
        else                              { $typeIcon = "&#9888;"   }
        $uRows += "<tr><td class='upn'>$typeIcon $(hx $k)</td><td class='n sc'>$cc</td><td class='n sh'>$hc</td><td><span class='rs $rsc'>$rs</span></td><td class='sm-txt'>$tacs</td><td class='sm-txt mono'>$tecs</td></tr>"
    }
    $usersSection = if ($uRows) {
        "<table class='ut'><thead><tr><th>Entidade</th><th>CRIT</th><th>HIGH</th><th>Score</th><th>Taticas</th><th>Tecnicas</th></tr></thead><tbody>$uRows</tbody></table>"
    } else { "<p class='empty'>Sem entidades com findings CRITICAL ou HIGH identificadas.</p>" }

    # ---- Module status ----
    $mods = @(
        @{N="Tenant Baseline";         F="00_tenant_baseline.csv"},
        @{N="Sign-in / Brute Force";   F="01_brute_force_by_ip.csv"},
        @{N="MFA / Cond. Access";      F="02_admin_mfa_status.csv"},
        @{N="Privileged Accounts";     F="03_role_changes.csv"},
        @{N="Exchange Rules";          F="04_suspicious_inbox_rules.csv"},
        @{N="Mailbox Forwarding";      F="04_mailbox_forwarding.csv"},
        @{N="OAuth / Service Princ.";  F="05_risky_oauth_grants.csv"},
        @{N="Unified Audit Log";       F="06_ual_audit_config_changes.csv"},
        @{N="SharePoint / OneDrive";   F="07_anonymous_shares.csv"},
        @{N="Outlook Persistence";     F="08_outlook_homepage.csv"},
        @{N="Defender Alerts";         F="15_defender_alerts.csv"},
        @{N="Privileged Identity";     F="17_privileged_identity_inventory.csv"},
        @{N="Stale Devices";           F="20_stale_devices.csv"},
        @{N="MFA Fatigue";             F="24_mfa_fatigue_suspects.csv"},
        @{N="Impersonation";           F="25_impersonation_matches.csv"},
        @{N="Enumeration";             F="26_enumeration_candidates.csv"},
        @{N="Attack Timeline";         F="21_attack_timeline.csv"}
    )
    $modCards = ""
    foreach ($m in $mods) {
        $cp  = Join-Path $Script:OutputPath $m.F
        $ex  = Test-Path $cp
        $cnt = if ($ex) { [math]::Max(0, (@(Get-Content $cp -ErrorAction SilentlyContinue).Count - 1)) } else { -1 }
        if (-not $ex)     { $cls="ms"; $lbl="skipped" }
        elseif ($cnt -le 0){ $cls="mw"; $lbl="0 resultados" }
        else               { $cls="mo"; $lbl="$cnt registos" }
        $lnk = if ($ex -and $cnt -gt 0) { " &middot; <a class='cl' href='$($m.F)'>CSV</a>" } else { "" }
        $modCards += "<div class='mc2'><span class='md $cls'></span><span class='mn'>$([System.Web.HttpUtility]::HtmlEncode($m.N))</span><span class='ml2'>$lbl$lnk</span></div>"
    }

    # ---- Build report path info ----
    $graphAcc = try { (Get-MgContext -ErrorAction SilentlyContinue).Account } catch { "N/A" }
    $exoSt    = if (Test-EXOAvailable) { "Conectado" } else { "Nao disponivel" }
    $psVer    = "v$($PSVersionTable.PSVersion)"

    $html = @"
<!DOCTYPE html>
<html lang="pt">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>IR-O365 | $(hx $Script:TenantName) | $(Get-Date -Format 'yyyy-MM-dd')</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Inter:wght@300;400;500;600&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#080b10;--s1:#0d1117;--s2:#131820;--s3:#1a2233;--s4:#212d42;
  --b1:#1e2a3d;--b2:#253347;--b3:#2d3f5a;
  --tx:#dce4f0;--t2:#8899b0;--t3:#4a5a72;--t4:#2e3e55;
  --red:#ff5f5f;--red-d:#1a0808;--red-b:#3d1212;
  --ora:#ff8c42;--ora-d:#1a0e05;--ora-b:#3d2010;
  --yel:#f5c842;--yel-d:#1a1500;--yel-b:#3d3200;
  --blu:#4d9fff;--blu-d:#060e1a;--blu-b:#0e2040;
  --grn:#3dd68c;--grn-d:#04160c;
  --teal:#26d0ce;--pur:#9d7dff;
  --mono:'JetBrains Mono',monospace;
  --sans:'Inter',system-ui,sans-serif;
  --r:5px;
}
*{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth;font-size:14px}
body{background:var(--bg);color:var(--tx);font-family:var(--sans);line-height:1.6;min-height:100vh}
a{color:var(--teal);text-decoration:none}a:hover{text-decoration:underline}
code,pre,.mono{font-family:var(--mono);font-size:.85em}

/* Top bar */
#bar{background:var(--s1);border-bottom:1px solid var(--b1);height:44px;display:flex;align-items:center;padding:0 1.5rem;gap:.75rem;position:sticky;top:0;z-index:200}
#bar-logo{font-family:var(--mono);font-weight:600;font-size:.85rem;color:var(--tx);letter-spacing:.08em}
#bar-ver{font-family:var(--mono);font-size:.68rem;color:var(--t3);border:1px solid var(--b2);padding:.1rem .45rem;border-radius:3px}
#bar-tenant{font-size:.78rem;color:var(--t2);margin-left:auto;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:400px}

/* Main layout */
#layout{display:grid;grid-template-columns:220px 1fr;min-height:calc(100vh - 44px)}

/* Sidebar */
#sidebar{background:var(--s1);border-right:1px solid var(--b1);padding:1.25rem 0;position:sticky;top:44px;height:calc(100vh - 44px);overflow-y:auto}
.nav-section{padding:.5rem 1rem .25rem;font-size:.65rem;font-weight:600;letter-spacing:.12em;text-transform:uppercase;color:var(--t3)}
.nav-item{display:flex;align-items:center;gap:.6rem;padding:.45rem 1.25rem;font-size:.8rem;color:var(--t2);cursor:pointer;border-left:2px solid transparent;transition:all .12s;user-select:none}
.nav-item:hover{color:var(--tx);background:var(--s2)}
.nav-item.active{color:var(--tx);border-left-color:var(--blu);background:var(--s2)}
.nav-dot{width:6px;height:6px;border-radius:50%;flex-shrink:0}
.nav-badge{margin-left:auto;font-family:var(--mono);font-size:.65rem;background:var(--s3);color:var(--t2);padding:.1rem .4rem;border-radius:3px}
.nav-badge.red{background:var(--red-d);color:var(--red)}

/* Content */
#content{padding:1.5rem 2rem;overflow-y:auto}
.panel{display:none}.panel.active{display:block}

/* Summary cards row */
.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:.6rem;margin-bottom:1.25rem}
.card{background:var(--s2);border:1px solid var(--b1);border-radius:var(--r);padding:.9rem 1.1rem;position:relative;overflow:hidden}
.card::before{content:'';position:absolute;left:0;top:0;bottom:0;width:2px}
.card-n{font-family:var(--mono);font-size:2rem;font-weight:600;line-height:1;margin-bottom:.2rem}
.card-l{font-size:.68rem;letter-spacing:.1em;text-transform:uppercase;color:var(--t2)}
.c-crit::before{background:var(--red)} .c-crit .card-n{color:var(--red)}
.c-high::before{background:var(--ora)} .c-high .card-n{color:var(--ora)}
.c-med::before {background:var(--yel)} .c-med  .card-n{color:var(--yel)}
.c-low::before {background:var(--blu)} .c-low  .card-n{color:var(--blu)}

/* Risk bar */
.rbar{height:4px;background:var(--s3);border-radius:2px;overflow:hidden;display:flex;margin-bottom:1.25rem}
.rbar-s{height:100%}

/* Section heading */
.sh{font-size:.7rem;font-weight:600;letter-spacing:.1em;text-transform:uppercase;color:var(--t3);margin-bottom:.6rem;display:flex;align-items:center;gap:.5rem}
.sh::after{content:'';flex:1;height:1px;background:var(--b1)}

/* Toolbar */
.tb{display:flex;gap:.4rem;margin-bottom:.65rem;align-items:center;flex-wrap:wrap}
.fb{background:var(--s2);border:1px solid var(--b1);color:var(--t2);border-radius:3px;padding:.22rem .65rem;font-size:.72rem;cursor:pointer;font-family:var(--sans);transition:all .12s;white-space:nowrap}
.fb:hover{color:var(--tx);border-color:var(--b3)}
.fb.on{color:var(--tx);border-color:var(--b2);background:var(--s3)}
.fb.fc.on{color:var(--red);border-color:var(--red-b);background:var(--red-d)}
.fb.fh.on{color:var(--ora);border-color:var(--ora-b);background:var(--ora-d)}
.fb.fm.on{color:var(--yel);border-color:var(--yel-b);background:var(--yel-d)}
.fb.fl.on{color:var(--blu);border-color:var(--blu-b);background:var(--blu-d)}
.srch{background:var(--s2);border:1px solid var(--b1);color:var(--tx);border-radius:3px;padding:.22rem .65rem;font-size:.75rem;font-family:var(--sans);width:200px;margin-left:auto}
.srch:focus{outline:none;border-color:var(--b3)}
.srch::placeholder{color:var(--t4)}
.cnt{font-family:var(--mono);font-size:.68rem;color:var(--t3);padding:.1rem .4rem;background:var(--s3);border-radius:3px}

/* Findings table */
.ftbl{width:100%;border-collapse:collapse;font-size:.8rem}
.ftbl thead th{background:var(--s2);padding:.5rem .75rem;text-align:left;font-size:.65rem;font-weight:600;letter-spacing:.08em;text-transform:uppercase;color:var(--t3);border-bottom:1px solid var(--b1);white-space:nowrap}
.fr{border-bottom:1px solid var(--s2);transition:background .1s}
.fr:hover>td{background:var(--s2)}
.fr>td{padding:.5rem .75rem;vertical-align:top}
.er>td{padding:0;background:var(--bg)}
.ed{padding:.6rem .75rem .6rem 2.5rem;border-left:2px solid var(--b2);margin:.25rem .75rem .35rem 2.75rem}

/* Severity pills */
.sp{font-family:var(--mono);font-size:.63rem;font-weight:600;letter-spacing:.08em;padding:.15rem .5rem;border-radius:3px;display:inline-block;white-space:nowrap}
.sc{background:var(--red-d);color:var(--red);border:1px solid var(--red-b)}
.sh{background:var(--ora-d);color:var(--ora);border:1px solid var(--ora-b)}
.sm{background:var(--yel-d);color:var(--yel);border:1px solid var(--yel-b)}
.sl{background:var(--blu-d);color:var(--blu);border:1px solid var(--blu-b)}

.tc{color:var(--t3);font-family:var(--mono);font-size:.7rem;white-space:nowrap;vertical-align:top;padding-top:.6rem}
.mt{color:var(--tx);display:block;line-height:1.5;max-width:540px}
.ra{display:flex;gap:.5rem;align-items:center;margin-top:.3rem;flex-wrap:wrap}
.tac{color:var(--t2);font-size:.72rem;white-space:nowrap}
.eb{background:none;border:1px solid var(--b2);color:var(--t2);border-radius:3px;width:20px;height:20px;cursor:pointer;font-size:.75rem;font-family:var(--mono);display:flex;align-items:center;justify-content:center;transition:all .1s;flex-shrink:0}
.eb:hover{border-color:var(--b3);color:var(--tx)}
.cl{font-family:var(--mono);font-size:.68rem;color:var(--grn);border:1px solid var(--grn-d);padding:.1rem .4rem;border-radius:3px}
.cl:hover{background:var(--grn-d)}
.ml{font-family:var(--mono);font-size:.7rem;color:var(--teal)}

/* Evidence table */
.etbl{border-collapse:collapse;font-size:.75rem;min-width:320px}
.etbl td{padding:.22rem .6rem;border-bottom:1px solid var(--s3);vertical-align:top}
.ek{color:var(--t3);font-family:var(--mono);white-space:nowrap;padding-right:1rem;font-size:.7rem}
.ev{color:var(--t2);word-break:break-all;font-family:var(--mono);font-size:.72rem}

/* Users table */
.ut{width:100%;border-collapse:collapse;font-size:.8rem}
.ut thead th{background:var(--s2);padding:.45rem .75rem;text-align:left;font-size:.65rem;font-weight:600;letter-spacing:.08em;text-transform:uppercase;color:var(--t3);border-bottom:1px solid var(--b1)}
.ut tbody tr{border-bottom:1px solid var(--s2)}
.ut tbody td{padding:.45rem .75rem}
.upn{font-family:var(--mono);font-size:.75rem;color:var(--tx)}
.n{font-family:var(--mono);font-weight:600}
.n.sc{color:var(--red)} .n.sh{color:var(--ora)}
.rs{font-family:var(--mono);font-size:.72rem;padding:.15rem .5rem;border-radius:3px;font-weight:600}
.rs.sc{background:var(--red-d);color:var(--red)}
.rs.sh{background:var(--ora-d);color:var(--ora)}
.rs.sm{background:var(--yel-d);color:var(--yel)}
.sm-txt{font-size:.72rem;color:var(--t2)}

/* Module grid */
.mgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:.5rem}
.mc2{background:var(--s2);border:1px solid var(--b1);border-radius:var(--r);padding:.6rem .85rem;display:flex;align-items:center;gap:.6rem}
.md{width:7px;height:7px;border-radius:50%;flex-shrink:0}
.mo{background:var(--grn)} .mw{background:var(--yel)} .ms{background:var(--t4)}
.mn{font-size:.78rem;color:var(--tx);flex:1}
.ml2{font-size:.68rem;color:var(--t3);font-family:var(--mono);white-space:nowrap}

/* Run info */
.rgrid{display:grid;grid-template-columns:1fr 1fr;gap:.5rem}
.rrow{display:flex;justify-content:space-between;padding:.4rem .75rem;background:var(--s2);border:1px solid var(--b1);border-radius:var(--r);font-size:.78rem;gap:1rem}
.rk{color:var(--t2)} .rv{font-family:var(--mono);color:var(--tx);text-align:right;font-size:.72rem;word-break:break-all}

/* MITRE */
.mitre-wrap{display:grid;grid-template-columns:repeat(auto-fill,minmax(110px,1fr));gap:.4rem}
.mt-cell{background:var(--s2);border:1px solid var(--b1);border-radius:var(--r);padding:.5rem .65rem;text-align:center}
.mt-cell.hit{background:var(--red-d);border-color:var(--red-b)}
.mt-cell.par{background:var(--ora-d);border-color:var(--ora-b)}
.mt-cell.nt {border-color:var(--b1)}
.mt-name{font-size:.65rem;font-weight:500;margin-bottom:.2rem}
.mt-cell.hit .mt-name{color:var(--red)} .mt-cell.par .mt-name{color:var(--ora)} .mt-cell.nt .mt-name{color:var(--t3)}
.mt-count{font-family:var(--mono);font-size:.75rem;font-weight:600}
.mt-cell.hit .mt-count{color:var(--red)} .mt-cell.par .mt-count{color:var(--ora)} .mt-cell.nt .mt-count{color:var(--t4)}

.empty{color:var(--t3);font-size:.8rem;padding:1.5rem 0;text-align:center}

@keyframes fi{from{opacity:0;transform:translateY(3px)}to{opacity:1;transform:none}}
.panel.active{animation:fi .15s ease}
</style>
</head>
<body>

<div id="bar">
  <span id="bar-logo">IR&#x2013;O365</span>
  <span id="bar-ver">v$($Script:Version)</span>
  <span id="bar-tenant">$(hx $Script:TenantName) &nbsp;&middot;&nbsp; $(hx $Script:TenantId)</span>
</div>

<div id="layout">

<!-- Sidebar -->
<nav id="sidebar">
  <div class="nav-section">Relatorio</div>
  <div class="nav-item active" onclick="sw(this,'findings')">
    <span class="nav-dot" style="background:var(--blu)"></span>
    Findings
    <span class="nav-badge$(if($critCount -gt 0){' red'} else {''})" id="fc">$totalFindings</span>
  </div>
  <div class="nav-item" onclick="sw(this,'users')">
    <span class="nav-dot" style="background:var(--pur)"></span>
    Utilizadores em Risco
  </div>
  <div class="nav-item" onclick="sw(this,'modules')">
    <span class="nav-dot" style="background:var(--teal)"></span>
    Modulos
  </div>
  <div class="nav-item" onclick="sw(this,'mitre')">
    <span class="nav-dot" style="background:var(--grn)"></span>
    MITRE ATT&amp;CK
  </div>
  <div class="nav-item" onclick="sw(this,'runinfo')">
    <span class="nav-dot" style="background:var(--t2)"></span>
    Execucao
  </div>
  <div class="nav-section" style="margin-top:1rem">Severidade</div>
  <div class="nav-item" onclick="flt(this,'CRITICAL')" id="nc" style="gap:.5rem">
    <span style="font-family:var(--mono);color:var(--red);font-size:.7rem;font-weight:600">CRITICAL</span>
    <span class="nav-badge red">$critCount</span>
  </div>
  <div class="nav-item" onclick="flt(this,'HIGH')" style="gap:.5rem">
    <span style="font-family:var(--mono);color:var(--ora);font-size:.7rem;font-weight:600">HIGH</span>
    <span class="nav-badge">$highCount</span>
  </div>
  <div class="nav-item" onclick="flt(this,'MEDIUM')" style="gap:.5rem">
    <span style="font-family:var(--mono);color:var(--yel);font-size:.7rem;font-weight:600">MEDIUM</span>
    <span class="nav-badge">$medCount</span>
  </div>
  <div class="nav-item" onclick="flt(this,'LOW')" style="gap:.5rem">
    <span style="font-family:var(--mono);color:var(--blu);font-size:.7rem;font-weight:600">LOW</span>
    <span class="nav-badge">$lowCount</span>
  </div>
</nav>

<!-- Content -->
<main id="content">

<!-- PANEL: Findings -->
<div class="panel active" id="p-findings">
  <div class="sh">Overview</div>
  <div class="cards">
    <div class="card c-crit"><div class="card-n">$critCount</div><div class="card-l">Critical</div></div>
    <div class="card c-high"><div class="card-n">$highCount</div><div class="card-l">High</div></div>
    <div class="card c-med"> <div class="card-n">$medCount</div><div class="card-l">Medium</div></div>
    <div class="card c-low"> <div class="card-n">$lowCount</div><div class="card-l">Low</div></div>
  </div>
  <div class="rbar" id="rb"></div>

  <div class="sh" style="margin-top:.75rem">Findings ($totalFindings)</div>
  <div class="tb">
    <button class="fb on" onclick="flt(this,'ALL')">Todos</button>
    <button class="fb fc" onclick="flt(this,'CRITICAL')">CRITICAL</button>
    <button class="fb fh" onclick="flt(this,'HIGH')">HIGH</button>
    <button class="fb fm" onclick="flt(this,'MEDIUM')">MEDIUM</button>
    <button class="fb fl" onclick="flt(this,'LOW')">LOW</button>
    <input class="srch" type="text" placeholder="Pesquisar findings..." oninput="srch(this.value)">
    <span class="cnt" id="vc">$totalFindings</span>
  </div>
  <table class="ftbl">
    <thead><tr>
      <th style="width:82px">Severity</th>
      <th style="width:48px">Hora</th>
      <th>Finding</th>
      <th style="width:120px">Tatica</th>
    </tr></thead>
    <tbody id="fb">$findingsHTML</tbody>
  </table>
</div>

<!-- PANEL: Users -->
<div class="panel" id="p-users">
  <div class="sh">Utilizadores com Findings CRITICAL / HIGH</div>
  $usersSection
</div>

<!-- PANEL: Modules -->
<div class="panel" id="p-modules">
  <div class="sh">Estado dos Modulos</div>
  <div class="mgrid">$modCards</div>
</div>

<!-- PANEL: MITRE -->
<div class="panel" id="p-mitre">
  <div class="sh">MITRE ATT&amp;CK Office Suite v18</div>
  <p style="font-size:.75rem;color:var(--t2);margin-bottom:.85rem">Taticas com findings detetados nesta analise. Vermelho = findings; Laranja = 1-2 findings; Cinzento = sem cobertura.</p>
  <div class="mitre-wrap" id="mg"></div>
</div>

<!-- PANEL: Run info -->
<div class="panel" id="p-runinfo">
  <div class="sh">Informacao de Execucao</div>
  <div class="rgrid">
    <div class="rrow"><span class="rk">Tenant</span><span class="rv">$(hx $Script:TenantName)</span></div>
    <div class="rrow"><span class="rk">Dominio principal</span><span class="rv">$(hx $Script:PrimaryDomain)</span></div>
    <div class="rrow"><span class="rk">Dominios analisados</span><span class="rv" style="font-size:.68rem">$(hx ($Script:UserDomains -join ' | '))</span></div>
    <div class="rrow"><span class="rk">Tenant ID</span><span class="rv">$(hx $Script:TenantId)</span></div>
    <div class="rrow"><span class="rk">Periodo</span><span class="rv">$($Script:StartDate.ToString('yyyy-MM-dd')) / $($Script:EndDate.ToString('yyyy-MM-dd'))</span></div>
    <div class="rrow"><span class="rk">Dias analisados</span><span class="rv">$Script:DaysBack</span></div>
    <div class="rrow"><span class="rk">Duracao</span><span class="rv">${duration} min</span></div>
    <div class="rrow"><span class="rk">Script</span><span class="rv">IR-O365 v$($Script:Version)</span></div>
    <div class="rrow"><span class="rk">PowerShell</span><span class="rv">$psVer</span></div>
    <div class="rrow"><span class="rk">Exchange Online</span><span class="rv">$exoSt</span></div>
    <div class="rrow"><span class="rk">Microsoft Graph</span><span class="rv">$(hx $graphAcc)</span></div>
    <div class="rrow"><span class="rk">Total findings</span><span class="rv">$totalFindings</span></div>
    <div class="rrow" style="grid-column:1/-1"><span class="rk">Output path</span><span class="rv" style="font-size:.65rem">$(hx $Script:OutputPath)</span></div>
  </div>
</div>

</main>
</div>

<script>
var FR = Array.from(document.querySelectorAll('tr.fr'));
var curS = 'ALL', curQ = '';

function sw(btn, id) {
  document.querySelectorAll('.nav-item').forEach(function(b){ b.classList.remove('active'); });
  document.querySelectorAll('.panel').forEach(function(p){ p.classList.remove('active'); });
  btn.classList.add('active');
  document.getElementById('p-' + id).classList.add('active');
  if (id === 'findings') buildMitre();
}

function flt(btn, sev) {
  if (btn.classList.contains('nav-item')) {
    sw(document.querySelector('.nav-item'), 'findings');
    document.querySelector('.nav-item').classList.remove('active');
    document.querySelector('[onclick*="findings"]').classList.add('active');
  }
  document.querySelectorAll('.tb .fb').forEach(function(b){ b.classList.remove('on'); });
  if (btn.classList.contains('fb')) btn.classList.add('on');
  curS = sev; apply();
}

function srch(q){ curQ = q.toLowerCase(); apply(); }

function apply() {
  var v = 0;
  FR.forEach(function(r) {
    var er = r.nextElementSibling;
    var ok = (curS === 'ALL' || r.dataset.sev === curS) && (!curQ || r.textContent.toLowerCase().includes(curQ));
    r.style.display = ok ? '' : 'none';
    if (er && er.classList.contains('er') && !ok) er.style.display = 'none';
    if (ok) v++;
  });
  document.getElementById('vc').textContent = v;
  document.getElementById('fc').textContent = v;
}

function te(id) {
  var r = document.getElementById(id);
  var b = r.previousElementSibling.querySelector('.eb');
  var open = r.style.display !== 'none';
  r.style.display = open ? 'none' : '';
  if (b) b.textContent = open ? '+' : '-';
}

(function riskBar(){
  var c=$critCount,h=$highCount,m=$medCount,l=$lowCount,t=c+h+m+l||1;
  var rb=document.getElementById('rb');
  if(c) rb.innerHTML+='<div class="rbar-s" style="width:'+(c/t*100)+'%;background:var(--red)"></div>';
  if(h) rb.innerHTML+='<div class="rbar-s" style="width:'+(h/t*100)+'%;background:var(--ora)"></div>';
  if(m) rb.innerHTML+='<div class="rbar-s" style="width:'+(m/t*100)+'%;background:var(--yel)"></div>';
  if(l) rb.innerHTML+='<div class="rbar-s" style="width:'+(l/t*100)+'%;background:var(--blu)"></div>';
})();

function buildMitre(){
  var tacs={'Initial Access':0,'Execution':0,'Persistence':0,'Privilege Escalation':0,
    'Defense Evasion':0,'Credential Access':0,'Discovery':0,'Lateral Movement':0,
    'Collection':0,'Exfiltration':0,'Impact':0};
  FR.forEach(function(r){ var t=r.dataset.tac; if(t&&tacs.hasOwnProperty(t)) tacs[t]++; });
  var g=document.getElementById('mg'); g.innerHTML='';
  Object.keys(tacs).forEach(function(t){
    var n=tacs[t];
    var cls=n>2?'hit':n>0?'par':'nt';
    g.innerHTML+='<div class="mt-cell '+cls+'"><div class="mt-name">'+t+'</div><div class="mt-count">'+(n||'&#x2013;')+'</div></div>';
  });
}
buildMitre();

window.addEventListener('load',function(){
  FR.filter(function(r){return r.dataset.sev==='CRITICAL';}).forEach(function(r){
    var er=r.nextElementSibling;
    if(er&&er.classList.contains('er')){er.style.display='';var b=r.querySelector('.eb');if(b)b.textContent='-';}
  });
});
</script>
</body>
</html>
"@

    $reportPath = Join-Path $Script:OutputPath "IR_REPORT.html"
    $html | Out-File -FilePath $reportPath -Encoding UTF8

    $reportFullPath = (Resolve-Path $reportPath -ErrorAction SilentlyContinue).Path
    if (-not $reportFullPath) { $reportFullPath = [System.IO.Path]::GetFullPath($reportPath) }
    $reportUri = "file:///" + $reportFullPath.Replace("\", "/")

    Write-Host ""
    Write-Host "  HTML Report gerado:" -ForegroundColor Green
    Write-Host "  $reportUri" -ForegroundColor Cyan
    Write-Host ""
    Write-IRLog "HTML Report: $reportUri" -Severity "SUCCESS"
}


function New-DebugLog {
    # Exportar debug log completo - sempre gerado, independente de -ExportJSON
    if (-not $Script:DebugLog -or $Script:DebugLog.Count -eq 0) { return }

    $logPath = Join-Path $Script:OutputPath "IR_DEBUG.log"
    $lines   = @()
    $lines  += "=" * 70
    $lines  += "IR-O365 DEBUG LOG - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    $lines  += "PowerShell: v$($PSVersionTable.PSVersion) | DebugMode: $($Script:DebugIR)"
    $lines  += "=" * 70
    $lines  += ""

    # Secao 1: Tempos por modulo
    $lines  += "TEMPOS POR MODULO:"
    $lines  += "-" * 40
    foreach ($mod in $Script:ModuleOrder) {
        if ($Script:ModuleTimes.ContainsKey($mod)) {
            $t = $Script:ModuleTimes[$mod]
            $dur = if ($t.DurationSec) { "$($t.DurationSec)s" } else { "N/A" }
            $lines += "  $($mod.PadRight(45)) $dur"
        }
    }
    $lines += ""

    # Secao 2: Todos os eventos (incluindo INFO e DEBUG_ERROR)
    $lines += "LOG COMPLETO ($($Script:DebugLog.Count) entradas):"
    $lines += "-" * 40
    foreach ($e in $Script:DebugLog) {
        $lines += "[$($e.Timestamp)] [$($e.Severity.PadRight(12))] $($e.Message)"
        if ($e.DebugDetail) {
            $lines += "  >> $($e.DebugDetail)"
        }
    }
    $lines += ""

    # Secao 3: Erros silenciosos capturados
    $debugErrors = @($Script:DebugLog | Where-Object { $_.Severity -eq "DEBUG_ERROR" })
    if ($debugErrors.Count -gt 0) {
        $lines += "ERROS SILENCIOSOS CAPTURADOS ($($debugErrors.Count)):"
        $lines += "-" * 40
        foreach ($e in $debugErrors) {
            $lines += "  $($e.Timestamp): $($e.Message)"
            if ($e.DebugDetail) { $lines += "    $($e.DebugDetail)" }
        }
    }

    $lines | Out-File -FilePath $logPath -Encoding UTF8
    Write-IRLog "Debug log exportado: $logPath ($($Script:DebugLog.Count) entradas)" -Severity "SUCCESS"

    # Imprimir sumario de tempos no ecra se -DebugIR
    if ($Script:DebugIR) {
        Write-Host ""
        Write-Host "  TEMPOS POR MODULO:" -ForegroundColor DarkGray
        foreach ($mod in $Script:ModuleOrder) {
            if ($Script:ModuleTimes.ContainsKey($mod)) {
                $t = $Script:ModuleTimes[$mod]
                if ($t.DurationSec) {
                    $bar   = "#" * [math]::Min([int]($t.DurationSec / 2), 30)
                    $color = if ($t.DurationSec -gt 30) { "Red" } elseif ($t.DurationSec -gt 10) { "Yellow" } else { "DarkGray" }
                    Write-Host "  $($mod.PadRight(42)) $($t.DurationSec.ToString().PadLeft(6))s  $bar" -ForegroundColor $color
                }
            }
        }
        Write-Host ""
        $errCount = @($Script:DebugLog | Where-Object { $_.Severity -eq "DEBUG_ERROR" }).Count
        if ($errCount -gt 0) {
            Write-Host "  ERROS SILENCIOSOS: $errCount (ver IR_DEBUG.log)" -ForegroundColor Red
        } else {
            Write-Host "  ERROS SILENCIOSOS: 0" -ForegroundColor Green
        }
    }
}

function New-JSONSummary {
    if (-not $Script:ExportJSON) { return }
    
    $summary = @{
        metadata = @{
            scriptVersion = $Script:Version
            generatedAt   = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
            periodStart   = $Script:StartDate.ToString("yyyy-MM-ddTHH:mm:ssZ")
            periodEnd     = $Script:EndDate.ToString("yyyy-MM-ddTHH:mm:ssZ")
            executionTime = "$([math]::Round(((Get-Date) - $Script:StartTime).TotalMinutes, 1))min"
        }
        statistics = $Script:Stats
        findings   = $Script:Findings | ForEach-Object {
            @{
                timestamp      = $_.Timestamp
                severity       = $_.Severity
                message        = $_.Message
                mitreTechnique = $_.Technique
                mitreTactic    = $_.Tactic
            }
        }
    }
    
    $jsonPath = Join-Path $Script:OutputPath "IR_SUMMARY.json"
    $summary | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
    Write-IRLog "JSON Summary gerado: $jsonPath" -Severity "SUCCESS"
}

# ============================================================
# FUNCAO PRINCIPAL
# ============================================================

# ============================================================
# MODULOS AVANCADOS (14-23) + ENTRY POINT ABAIXO
# ============================================================

# ============================================================
# MODULO 14: ENTRA ID - CONDITIONAL ACCESS GAP ANALYSIS
# ============================================================

function Get-ConditionalAccessGapAnalysis {
    # T1078 - Valid Accounts | T1562.008 - Impair Defenses | T1556 - Modify Auth Process
    Write-Section "CONDITIONAL ACCESS GAP ANALYSIS" "T1078/T1562.008/T1556" "Defense Evasion / Initial Access"

    if ($Script:SkipGraph) { Write-IRLog "Graph skipped" -Severity "INFO"; return }

    try {
        $caPolicies = @(Get-MgIdentityConditionalAccessPolicy -ErrorAction SilentlyContinue)
        if (-not $caPolicies) { Write-IRLog "Sem CA policies encontradas" -Severity "INFO"; return }

        # --- Gap 1: Existe policy que bloqueie Legacy Auth? ---
        Write-Host "  >> Gap: Legacy Authentication bloqueada..." -ForegroundColor Gray
        $legacyBlock = $caPolicies | Where-Object {
            $_.State -eq "enabled" -and (
                $_.Conditions.ClientAppTypes -contains "exchangeActiveSync" -or
                $_.Conditions.ClientAppTypes -contains "other"
            )
        }
        if (-not $legacyBlock) {
            Write-IRLog "GAP: Nenhuma CA policy bloqueia Legacy Authentication - MFA bypassavel via SMTP/IMAP/POP3 [T1078]" `
                -Severity "CRITICAL" -MITRETechnique "T1078.004" -MITRETactic "Initial Access"
        } else {
            Write-IRLog "Legacy Auth block policy: encontrada ($($legacyBlock.DisplayName -join ', '))" -Severity "INFO"
        }

        # --- Gap 2: Existe policy que force MFA para admins? ---
        Write-Host "  >> Gap: MFA obrigatoria para admins..." -ForegroundColor Gray
        $adminMFAPolicy = @($caPolicies | Where-Object {
            $_.State -eq "enabled" -and
            ($_.GrantControls.BuiltInControls -contains "mfa") -and
            ($_.Conditions.Users.IncludeRoles.Count -gt 0 -or
             $_.Conditions.Users.IncludeUsers -contains "All")
        })
        if (-not $adminMFAPolicy) {
            Write-IRLog "GAP: Nenhuma CA policy enforces MFA para roles administrativas [T1556.006]" `
                -Severity "CRITICAL" -MITRETechnique "T1556.006" -MITRETactic "Credential Access"
        }

        # --- Gap 3: Existe policy para device compliance? ---
        Write-Host "  >> Gap: Device compliance enforced..." -ForegroundColor Gray
        $compliancePolicy = $caPolicies | Where-Object {
            $_.State -eq "enabled" -and
            $_.GrantControls.BuiltInControls -contains "compliantDevice"
        }
        if (-not $compliancePolicy) {
            Write-IRLog "GAP: Sem CA policy para device compliance - acesso permitido de devices nao geridos" `
                -Severity "MEDIUM" -MITRETechnique "T1078" -MITRETactic "Initial Access"
        }

        # --- Gap 4: Existe policy para Sign-in Risk? ---
        Write-Host "  >> Gap: Sign-in risk-based policy..." -ForegroundColor Gray
        $riskPolicy = $caPolicies | Where-Object {
            $_.State -eq "enabled" -and
            $_.Conditions.SignInRiskLevels.Count -gt 0
        }
        if (-not $riskPolicy) {
            Write-IRLog "GAP: Sem CA policy baseada em Sign-in Risk - risky sign-ins nao sao bloqueados automaticamente [T1078]" `
                -Severity "HIGH" -MITRETechnique "T1078.004" -MITRETactic "Initial Access"
        }

        # --- Gap 5: Existe policy para User Risk? ---
        $userRiskPolicy = $caPolicies | Where-Object {
            $_.State -eq "enabled" -and
            $_.Conditions.UserRiskLevels.Count -gt 0
        }
        if (-not $userRiskPolicy) {
            Write-IRLog "GAP: Sem CA policy baseada em User Risk - contas comprometidas nao sao bloqueadas automaticamente [T1078]" `
                -Severity "HIGH" -MITRETechnique "T1078.004" -MITRETactic "Initial Access"
        }

        # --- Gap 6: Gestao de Tokens - Sign-in Frequency ---
        Write-Host "  >> Gap: Token lifetime e sign-in frequency..." -ForegroundColor Gray
        $tokenPolicy = $caPolicies | Where-Object {
            $_.State -eq "enabled" -and
            $_.SessionControls.SignInFrequency -ne $null
        }
        if (-not $tokenPolicy) {
            Write-IRLog "GAP: Sem CA policy com Sign-in Frequency - tokens podem ser reutilizados indefinidamente [T1550.001]" `
                -Severity "MEDIUM" -MITRETechnique "T1550.001" -MITRETactic "Defense Evasion"
        }

        # --- Gap 7: Persistent Browser Session desativado? ---
        $persistentBrowser = $caPolicies | Where-Object {
            $_.State -eq "enabled" -and
            $_.SessionControls.PersistentBrowser.IsEnabled -eq $true -and
            $_.SessionControls.PersistentBrowser.Mode -eq "never"
        }
        if (-not $persistentBrowser) {
            Write-IRLog "GAP: Sem CA policy a bloquear Persistent Browser Sessions [T1539 - Steal Web Session Cookie]" `
                -Severity "MEDIUM" -MITRETechnique "T1539" -MITRETactic "Credential Access"
        }

        # Export de todas as policies com estado detalhado
        $caDetail = $caPolicies | Select-Object DisplayName, State, CreatedDateTime, ModifiedDateTime,
            @{N="IncludeUsers";E={$_.Conditions.Users.IncludeUsers -join ";"}},
            @{N="ExcludeUsers";E={$_.Conditions.Users.ExcludeUsers -join ";"}},
            @{N="IncludeRoles";E={$_.Conditions.Users.IncludeRoles -join ";"}},
            @{N="ClientAppTypes";E={$_.Conditions.ClientAppTypes -join ";"}},
            @{N="GrantControls";E={$_.GrantControls.BuiltInControls -join ";"}},
            @{N="SignInRiskLevels";E={$_.Conditions.SignInRiskLevels -join ";"}},
            @{N="UserRiskLevels";E={$_.Conditions.UserRiskLevels -join ";"}}

        Export-IRData -FileName "14_ca_gap_analysis" -Data $caDetail

        Write-IRLog "CA Gap Analysis: $($caPolicies.Count) policies analisadas" -Severity "INFO"

    } catch {
        Write-IRLog "Erro CA Gap Analysis: $_" -Severity "INFO"
    }
}

# ============================================================
# MODULO 15: MICROSOFT DEFENDER / MCAS INTEGRATION
# ============================================================

function Get-DefenderAlerts {
    # T1078, T1530, T1114 - correlacao com alertas do Defender for Cloud Apps / MDO
    Write-Section "MICROSOFT DEFENDER FOR O365 - ALERTAS" "T1078/T1114/T1530" "All Tactics"

    if ($Script:SkipGraph) { Write-IRLog "Graph skipped" -Severity "INFO"; return }

    try {
        # Security Alerts via Graph Security API
        Write-Host "  >> Recolhendo alertas do Microsoft Defender..." -ForegroundColor Gray
        $filterDate = $Script:FilterDate

        $alerts = @(Get-MgSecurityAlert -Filter "createdDateTime ge $filterDate" `
            -Top 500 -ErrorAction SilentlyContinue)

        if ($alerts.Count -gt 0) {
            $critAlerts = @($alerts | Where-Object { $_.Severity -eq "high" -or $_.Severity -eq "critical" })
            $medAlerts  = @($alerts | Where-Object { $_.Severity -eq "medium" })

            Write-IRLog "Defender Alerts: $($alerts.Count) total | $($critAlerts.Count) HIGH/CRITICAL | $($medAlerts.Count) MEDIUM" `
                -Severity $(if ($critAlerts.Count -gt 0) { "HIGH" } else { "MEDIUM" }) `
                -MITRETechnique "Various" -MITRETactic "Various"

            foreach ($alert in $critAlerts) {
                Write-IRLog "Defender Alert [HIGH]: '$($alert.Title)' - $($alert.Description)" `
                    -Severity "HIGH" -MITRETechnique ($alert.MitreTechniques -join ",") -MITRETactic "Various" `
                    -Data @{ AlertId = $alert.Id; Status = $alert.Status; AssignedTo = $alert.AssignedTo }
            }

            $alertData = $alerts | Select-Object Id, Title, Severity, Status, Category,
                CreatedDateTime, ResolvedDateTime, AssignedTo, Description,
                @{N="MitreTechniques";E={$_.MitreTechniques -join ";"}},
                @{N="AffectedUsers";E={($_.UserStates | ForEach-Object { $_.UserPrincipalName }) -join ";"}},
                @{N="AffectedHosts";E={($_.HostStates | ForEach-Object { $_.Fqdn }) -join ";"}}

            Export-IRData -FileName "15_defender_alerts" -Data $alertData

        } else {
            Write-IRLog "Defender Alerts: Sem alertas no periodo (ou permissoes insuficientes)" -Severity "INFO"
        }

        # Secure Score
        Write-Host "  >> Verificando Secure Score..." -ForegroundColor Gray
        try {
            $secureScore = Get-MgSecuritySecureScore -Top 1 -ErrorAction SilentlyContinue
            if ($secureScore) {
                $score      = $secureScore | Select-Object -First 1
                $pct        = if ($score.MaxScore -gt 0) { [math]::Round(($score.CurrentScore / $score.MaxScore) * 100, 1) } else { 0 }
                $sevScore   = if ($pct -lt 40) { "CRITICAL" } elseif ($pct -lt 60) { "HIGH" } elseif ($pct -lt 75) { "MEDIUM" } else { "INFO" }

                Write-IRLog "Microsoft Secure Score: $($score.CurrentScore)/$($score.MaxScore) ($pct%)" `
                    -Severity $sevScore -MITRETechnique "Various" -MITRETactic "Baseline"
            }
        } catch { Write-IRLog "Secure Score: permissoes insuficientes ou nao disponivel" -Severity "INFO" }

        # Secure Score Control Profiles - o que esta a falhar
        try {
            $scoreProfiles = @(Get-MgSecuritySecureScoreControlProfile -Top 100 -ErrorAction SilentlyContinue)
            # FIX: Graph SDK v2 retorna ControlCategory/ActionType nao ImplementationStatus
            # Usar -ExpandProperty para inspecionar estrutura real
            $failedControls = @($scoreProfiles | Where-Object {
                # Tentar multiplos nomes de propriedade para compatibilidade
                $status = if ($null -ne $_.ImplementationStatus) { $_.ImplementationStatus }
                          elseif ($null -ne $_.AdditionalProperties) {
                              $_.AdditionalProperties["implementationStatus"]
                          } else { "notImplemented" }
                $status -ne "implemented" -and $null -ne $_.Rank -and $_.Rank -le 20
            } | Sort-Object { if ($_.Rank) { $_.Rank } else { 99 } } |
              Select-Object -First 15 |
              ForEach-Object {
                [PSCustomObject]@{
                    Title                = $_.Title
                    Rank                 = $_.Rank
                    MaxScore             = $_.MaxScore
                    ImplementationStatus = if ($_.ImplementationStatus) { $_.ImplementationStatus } else { $_.AdditionalProperties["implementationStatus"] }
                    Category             = if ($_.ControlCategory) { $_.ControlCategory } else { $_.Category }
                }
              })

            if ($failedControls) {
                Export-IRData -FileName "15_secure_score_gaps" -Data $failedControls
                Write-IRLog "Top controles de seguranca NAO implementados: $($failedControls.Count) (ver 15_secure_score_gaps.csv)" `
                    -Severity "MEDIUM" -MITRETechnique "Various" -MITRETactic "Baseline"
            }
        } catch { Write-IRLog "Secure Score Controls: $_" -Severity "INFO" }

    } catch {
        Write-IRLog "Erro Defender module: $_" -Severity "INFO"
    }
}

# ============================================================
# MODULO 16: CONTENCAO AUTOMATICA (QUARANTINE MODE)
# ============================================================

function Invoke-AutoContainment {
    # Executado APENAS quando chamado explicitamente com -AutoContain
    # Acoes: revogar sessoes, bloquear conta, remover forwarding, desativar inbox rules
    param(
        [Parameter(Mandatory = $false)]
        [string[]]$UsersToContain = @(),

        [Parameter(Mandatory = $false)]
        [switch]$RevokeSessionsOnly,

        [Parameter(Mandatory = $false)]
        [switch]$DisableAccounts,

        [Parameter(Mandatory = $false)]
        [switch]$RemoveSuspiciousRules
    )

    Write-Section "AUTO-CONTENCAO" "RESPONSE" "Incident Response"
    Write-IRLog "CONTENCAO iniciada para $($UsersToContain.Count) utilizadores" -Severity "INFO"

    $containmentLog = [System.Collections.Generic.List[PSObject]]::new()

    foreach ($upn in $UsersToContain) {
        Write-Host "  >> Contendo: $upn ..." -ForegroundColor Red

        # 1. Revogar todas as sessoes ativas (tokens)
        try {
            Revoke-MgUserSignInSession -UserId $upn -ErrorAction Stop
            $record = [PSCustomObject]@{
                Timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                User      = $upn
                Action    = "RevokeAllSessions"
                Status    = "SUCCESS"
                Details   = "Todos os refresh tokens revogados"
            }
            $containmentLog.Add($record)
            Write-IRLog "CONTENCAO: Sessions revogadas para $upn" -Severity "INFO"
        } catch {
            $containmentLog.Add([PSCustomObject]@{ Timestamp=(Get-Date -Format "yyyy-MM-dd HH:mm:ss"); User=$upn; Action="RevokeAllSessions"; Status="FAILED"; Details=$_.ToString() })
        }

        # 2. Bloquear sign-in (se -DisableAccounts)
        if ($DisableAccounts) {
            try {
                Update-MgUser -UserId $upn -AccountEnabled:$false -ErrorAction Stop
                $containmentLog.Add([PSCustomObject]@{
                    Timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                    User      = $upn
                    Action    = "BlockSignIn"
                    Status    = "SUCCESS"
                    Details   = "AccountEnabled = false"
                })
                Write-IRLog "CONTENCAO: Sign-in bloqueado para $upn" -Severity "INFO"
            } catch {
                $containmentLog.Add([PSCustomObject]@{ Timestamp=(Get-Date -Format "yyyy-MM-dd HH:mm:ss"); User=$upn; Action="BlockSignIn"; Status="FAILED"; Details=$_.ToString() })
            }
        }

        # 3. Remover regras de inbox suspeitas (se -RemoveSuspiciousRules)
        if ($RemoveSuspiciousRules -and -not $Script:SkipExchange) {
            try {
                $rules = Get-InboxRule -Mailbox $upn -ErrorAction SilentlyContinue
                foreach ($rule in $rules) {
                    $isSuspicious = $false
                    if ($rule.ForwardTo -or $rule.ForwardAsAttachmentTo -or $rule.RedirectTo -or $rule.DeleteMessage) {
                        $isSuspicious = $true
                    }
                    if ($isSuspicious) {
                        Remove-InboxRule -Mailbox $upn -Identity $rule.Identity -Confirm:$false -ErrorAction Stop
                        $containmentLog.Add([PSCustomObject]@{
                            Timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                            User      = $upn
                            Action    = "RemoveInboxRule"
                            Status    = "SUCCESS"
                            Details   = "Rule '$($rule.Name)' removida"
                        })
                        Write-IRLog "CONTENCAO: Inbox rule '$($rule.Name)' removida de $upn" -Severity "INFO"
                    }
                }
            } catch {
                $containmentLog.Add([PSCustomObject]@{ Timestamp=(Get-Date -Format "yyyy-MM-dd HH:mm:ss"); User=$upn; Action="RemoveInboxRule"; Status="FAILED"; Details=$_.ToString() })
            }

            # 4. Remover forwarding externo
            try {
                $mbx = Get-Mailbox -Identity $upn -ErrorAction SilentlyContinue
                if ($mbx.ForwardingSMTPAddress -or $mbx.ForwardingAddress) {
                    Set-Mailbox -Identity $upn -ForwardingSMTPAddress $null -ForwardingAddress $null -DeliverToMailboxAndForward $false -ErrorAction Stop
                    $containmentLog.Add([PSCustomObject]@{
                        Timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                        User      = $upn
                        Action    = "RemoveMailboxForwarding"
                        Status    = "SUCCESS"
                        Details   = "Forwarding removido"
                    })
                    Write-IRLog "CONTENCAO: Forwarding removido do mailbox $upn" -Severity "INFO"
                }
            } catch {
                $containmentLog.Add([PSCustomObject]@{ Timestamp=(Get-Date -Format "yyyy-MM-dd HH:mm:ss"); User=$upn; Action="RemoveForwarding"; Status="FAILED"; Details=$_.ToString() })
            }
        }
    }

    Export-IRData -FileName "16_containment_log" -Data $containmentLog
    Write-IRLog "Auto-Contencao completa: $($containmentLog.Count) acoes executadas" -Severity "INFO"
}

# ============================================================
# MODULO 17: ENTRA ID - PRIVILEGED IDENTITY DEEP DIVE
# ============================================================

function Get-PrivilegedIdentityDeepDive {
    # T1098.003, T1548.005, T1078 - analise profunda de identidades privilegiadas
    Write-Section "PRIVILEGED IDENTITY DEEP DIVE" "T1098.003/T1548.005" "Privilege Escalation / Persistence"

    if ($Script:SkipGraph) { Write-IRLog "Graph skipped" -Severity "INFO"; return }

    try {
        # Todos os utilizadores com roles administrativas (diretas + via grupo)
        Write-Host "  >> Enumerando todas as identidades com roles privilegiadas..." -ForegroundColor Gray

        $allAdminRoles = @(
            @{ Id = "62e90394-69f5-4237-9190-012177145e10"; Name = "Global Administrator" },
            @{ Id = "194ae4cb-b126-40b2-bd5b-6091b380977d"; Name = "Security Administrator" },
            @{ Id = "9360feb5-f418-4baa-8175-e2a00bac4301"; Name = "Exchange Administrator" },
            @{ Id = "e8611ab8-c189-46e8-94e1-60213ab1f814"; Name = "Privileged Role Administrator" },
            @{ Id = "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9"; Name = "Conditional Access Administrator" },
            @{ Id = "29232cdf-9323-42fd-ade2-1d097af3e4de"; Name = "Exchange Recipient Administrator" },
            @{ Id = "f28a1f50-f6e7-4571-818b-6a12f2af6b6c"; Name = "SharePoint Administrator" },
            @{ Id = "75941009-915a-4869-abe7-691bff18279e"; Name = "Skype for Business Administrator" },
            @{ Id = "0964bb5e-9bdb-4d7b-ac29-58e794862a40"; Name = "Search Administrator" },
            @{ Id = "7be44c8a-adaf-4e2a-84d6-ab2649e08a13"; Name = "Privileged Authentication Administrator" },
            @{ Id = "c4e39bd9-1100-46d3-8c65-fb160da0071f"; Name = "Authentication Administrator" }
        )

        $privilegedInventory = [System.Collections.Generic.List[PSObject]]::new()

        foreach ($role in $allAdminRoles) {
            try {
                $members = @(Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -ErrorAction SilentlyContinue)
                foreach ($m in $members) {
                    $upn  = $m.AdditionalProperties["userPrincipalName"]
                    $type = $m.AdditionalProperties["@odata.type"]

                    # Verificar se e conta externa / guest
                    $isGuest = $upn -match "#EXT#"

                    # Verificar ultima atividade
                    $lastSignIn = $null
                    try {
                        $signInData = Get-MgUser -UserId $m.Id `
                            -Property "SignInActivity,UserPrincipalName,AccountEnabled,CreatedDateTime" `
                            -ErrorAction SilentlyContinue
                        $lastSignIn = $signInData.SignInActivity.LastSignInDateTime
                    } catch { }

                    $record = [PSCustomObject]@{
                        RoleName     = $role.Name
                        UPN          = $upn
                        ObjectType   = $type -replace "#microsoft.graph.",""
                        IsGuest      = $isGuest
                        LastSignIn   = $lastSignIn
                        DaysSinceLogin = if ($lastSignIn) { [math]::Round(((Get-Date) - $lastSignIn).TotalDays, 0) } else { "Never/Unknown" }
                        ObjectId     = $m.Id
                    }
                    $privilegedInventory.Add($record)

                    # Alertas especificos
                    if ($isGuest) {
                        Write-IRLog "GUEST com role admin: $upn tem '$($role.Name)' [T1098.003]" `
                            -Severity "CRITICAL" -MITRETechnique "T1098.003" -MITRETactic "Privilege Escalation" -Data $record
                    }

                    if ($lastSignIn -and ((Get-Date) - $lastSignIn).TotalDays -gt 90) {
                        Write-IRLog "Admin inativo ha $([math]::Round(((Get-Date) - $lastSignIn).TotalDays,0)) dias: $upn com '$($role.Name)' [T1078]" `
                            -Severity "MEDIUM" -MITRETechnique "T1078" -MITRETactic "Initial Access" -Data $record
                    }

                    if ($type -eq "#microsoft.graph.servicePrincipal") {
                        Write-IRLog "Service Principal com role admin: $upn tem '$($role.Name)' [T1098.003]" `
                            -Severity "HIGH" -MITRETechnique "T1098.003" -MITRETactic "Privilege Escalation" -Data $record
                    }
                }
            } catch { }
        }

        Export-IRData -FileName "17_privileged_identity_inventory" -Data $privilegedInventory

        # Global Admins count (> 5 e considerado risco)
        $globalAdmins = @($privilegedInventory | Where-Object { $_.RoleName -eq "Global Administrator" })
        if ($globalAdmins.Count -gt 5) {
            Write-IRLog "Demasiados Global Admins: $($globalAdmins.Count) (best practice: max 4-5) [T1098.003]" `
                -Severity "MEDIUM" -MITRETechnique "T1098.003" -MITRETactic "Privilege Escalation"
        }

        # Break-glass accounts (should exist, should NOT be used regularly)
        Write-Host "  >> Verificando break-glass accounts..." -ForegroundColor Gray
        $breakGlass = @($privilegedInventory | Where-Object {
            $_.RoleName -eq "Global Administrator" -and
            ($_.UPN -match "break|glass|emergency|breakglass|bga" -or $_.UPN -match "admin.*admin")
        })
        if ($breakGlass.Count -gt 0) {
            foreach ($bg in $breakGlass) {
                if ($bg.DaysSinceLogin -ne "Never/Unknown" -and [int]$bg.DaysSinceLogin -lt 30) {
                    Write-IRLog "BREAK-GLASS ACCOUNT utilizada recentemente ($($bg.DaysSinceLogin) dias): $($bg.UPN) [T1078]" `
                        -Severity "CRITICAL" -MITRETechnique "T1078" -MITRETactic "Initial Access" -Data $bg
                }
            }
        }

    } catch {
        Write-IRLog "Erro Privileged Identity Deep Dive: $_" -Severity "INFO"
    }
}

# ============================================================
# MODULO 18: EXFILTRATION CORRELATION ENGINE
# ============================================================

function Get-ExfiltrationCorrelation {
    # T1048, T1537, T1567, T1114.002, T1530 - correlacao multi-sinal de exfiltracao
    Write-Section "EXFILTRATION CORRELATION ENGINE" "T1048/T1537/T1567/T1114" "Exfiltration / Collection"

    if ($Script:SkipUAL) { Write-IRLog "UAL skipped" -Severity "INFO"; return }

    try {
        Write-Host "  >> Correlacionando sinais de exfiltracao..." -ForegroundColor Gray

        # Recolher eventos de multiplos vetores no mesmo periodo
        $exfilSignals = @{}

        # Sinal 1: Downloads SPO/ODB
        $downloads = Invoke-UALSearch -StartDate $Script:StartDate -EndDate $Script:EndDate `
            -Operations @("FileDownloaded","FileSyncDownloadedFull") -ResultSize 5000 -ErrorAction SilentlyContinue
        foreach ($d in $downloads) { $exfilSignals[$d.UserIds] = (if ($exfilSignals.ContainsKey($d.UserIds)) { $exfilSignals[$d.UserIds] } else { 0 }) + 1 }

        # Sinal 2: Email forwarding criado
        $fwdCreated = Invoke-UALSearch -StartDate $Script:StartDate -EndDate $Script:EndDate `
            -Operations @("New-InboxRule","Set-InboxRule","Set-Mailbox") -ResultSize 1000 -ErrorAction SilentlyContinue
        foreach ($f in $fwdCreated) { $exfilSignals[$f.UserIds] = (if ($exfilSignals.ContainsKey($f.UserIds)) { $exfilSignals[$f.UserIds] } else { 0 }) + 5 }

        # Sinal 3: Partilhas anonimas
        $anonLinks = Invoke-UALSearch -StartDate $Script:StartDate -EndDate $Script:EndDate `
            -Operations @("AnonymousLinkCreated") -ResultSize 1000 -ErrorAction SilentlyContinue
        foreach ($a in $anonLinks) { $exfilSignals[$a.UserIds] = (if ($exfilSignals.ContainsKey($a.UserIds)) { $exfilSignals[$a.UserIds] } else { 0 }) + 3 }

        # Sinal 4: External sharing
        $extShare = Invoke-UALSearch -StartDate $Script:StartDate -EndDate $Script:EndDate `
            -Operations @("SharingInvitationCreated","SharingSet") -ResultSize 1000 -ErrorAction SilentlyContinue
        foreach ($e in $extShare) { $exfilSignals[$e.UserIds] = (if ($exfilSignals.ContainsKey($e.UserIds)) { $exfilSignals[$e.UserIds] } else { 0 }) + 2 }

        # Sinal 5: Webhooks / Flows criados
        $webhooks = Invoke-UALSearch -StartDate $Script:StartDate -EndDate $Script:EndDate `
            -Operations @("CreateFlow","AddWebhook","CreateConnector") -ResultSize 500 -ErrorAction SilentlyContinue
        foreach ($w in $webhooks) { $exfilSignals[$w.UserIds] = (if ($exfilSignals.ContainsKey($w.UserIds)) { $exfilSignals[$w.UserIds] } else { 0 }) + 8 }

        # Sinal 6: OAuth consent com Mail/Files scope
        $oauthConsent = Invoke-UALSearch -StartDate $Script:StartDate -EndDate $Script:EndDate `
            -Operations @("Consent to application","Add OAuth2PermissionGrant") -ResultSize 500 -ErrorAction SilentlyContinue
        foreach ($o in $oauthConsent) { $exfilSignals[$o.UserIds] = (if ($exfilSignals.ContainsKey($o.UserIds)) { $exfilSignals[$o.UserIds] } else { 0 }) + 10 }

        # Calcular risk score por utilizador
        $exfilRiskScores = $exfilSignals.GetEnumerator() |
            Where-Object { $_.Value -ge 5 } |
            Sort-Object Value -Descending |
            Select-Object -First 20 |
            ForEach-Object {
                $riskLevel = if ($_.Value -ge 20) { "CRITICAL" }
                             elseif ($_.Value -ge 10) { "HIGH" }
                             elseif ($_.Value -ge 5)  { "MEDIUM" }
                             else { "LOW" }
                [PSCustomObject]@{
                    User            = $_.Key
                    ExfilRiskScore  = $_.Value
                    RiskLevel       = $riskLevel
                }
            }

        foreach ($r in $exfilRiskScores) {
            Write-IRLog "Exfiltration Risk Score: $($r.User) = $($r.ExfilRiskScore) pts [$($r.RiskLevel)]" `
                -Severity $r.RiskLevel -MITRETechnique "T1048/T1567/T1114" -MITRETactic "Exfiltration" -Data $r
        }

        Export-IRData -FileName "18_exfiltration_risk_scores" -Data $exfilRiskScores
        Write-IRLog "Exfiltration Correlation: $($exfilSignals.Count) utilizadores com sinais detetados" -Severity "INFO"

    } catch {
        Write-IRLog "Erro Exfiltration Correlation: $_" -Severity "INFO"
    }
}

# ============================================================
# MODULO 19: NAMED LOCATIONS & IP REPUTATION
# ============================================================

function Get-NamedLocationsAndIPAnalysis {
    # T1078 - Valid Accounts | T1566 - Phishing - analise de Named Locations e IPs suspeitos
    Write-Section "NAMED LOCATIONS & IP ANALYSIS" "T1078/T1566" "Initial Access"

    if ($Script:SkipGraph) { Write-IRLog "Graph skipped" -Severity "INFO"; return }

    try {
        # Named Locations configuradas
        Write-Host "  >> Verificando Named Locations no CA..." -ForegroundColor Gray
        $namedLocations = @(Get-MgIdentityConditionalAccessNamedLocation -ErrorAction SilentlyContinue)

        if ($namedLocations.Count -eq 0) {
            Write-IRLog "Sem Named Locations configuradas - CA baseada em localizacao nao e possivel [T1078]" `
                -Severity "MEDIUM" -MITRETechnique "T1078" -MITRETactic "Initial Access"
        } else {
            Write-IRLog "Named Locations: $($namedLocations.Count) configuradas" -Severity "INFO"
            $nlData = $namedLocations | Select-Object DisplayName, CreatedDateTime, ModifiedDateTime,
                @{N="Type";E={ $_.AdditionalProperties["@odata.type"] -replace "#microsoft.graph.",""} },
                @{N="IsTrusted";E={ $_.AdditionalProperties["isTrusted"] }}
            Export-IRData -FileName "19_named_locations" -Data $nlData
        }

        # Sign-ins de paises de alto risco (configura de acordo com o teu contexto)
        Write-Host "  >> Verificando sign-ins de paises de alto risco..." -ForegroundColor Gray
        $highRiskCountries = @("CN","RU","KP","IR","SY","BY","CU","VE","MM","PK","AF","IQ","LY","YE","SD","SO","ZW")

        $filterDate = $Script:FilterDate
        $signins = Get-MgAuditLogSignIn -Filter "createdDateTime ge $filterDate and status/errorCode eq 0" `
            -Top 5000 -ErrorAction SilentlyContinue

        if ($signins) {
            $riskyCountrySignins = @($signins | Where-Object {
                $_.Location.CountryOrRegion -in $highRiskCountries
            } | Select-Object UserPrincipalName, CreatedDateTime, IPAddress,
                               @{N="Country";E={$_.Location.CountryOrRegion}},
                               @{N="City";E={$_.Location.City}},
                               ClientAppUsed, DeviceDetail)

            if ($riskyCountrySignins.Count -gt 0) {
                Write-IRLog "Sign-ins de paises de ALTO RISCO: $($riskyCountrySignins.Count) [T1078.004]" `
                    -Severity "HIGH" -MITRETechnique "T1078.004" -MITRETactic "Initial Access"
                Export-IRData -FileName "19_high_risk_country_signins" -Data $riskyCountrySignins
            }

            # Sign-ins de Tor/VPN (AS names comuns)
            $torVpnSignins = @($signins | Where-Object {
                $_.IPAddress -and (
                    $_.AuthenticationDetails.AuthenticationStepResultDetail -match "Anonymous proxy" -or
                    $_.RiskState -match "atRisk" -or
                    $_.TokenIssuerType -eq "AzureAD" -and $_.DeviceDetail.IsCompliant -eq $false
                )
            })
            if ($torVpnSignins.Count -gt 0) {
                Write-IRLog "Possiveis sign-ins via Tor/Proxy Anonimo: $($torVpnSignins.Count) [T1078]" `
                    -Severity "HIGH" -MITRETechnique "T1078.004" -MITRETactic "Initial Access"
                Export-IRData -FileName "19_tor_proxy_signins" -Data ($torVpnSignins | Select-Object UserPrincipalName, CreatedDateTime, IPAddress, RiskState, Location)
            }
        }

    } catch {
        Write-IRLog "Erro Named Locations: $_" -Severity "INFO"
    }
}

# ============================================================
# MODULO 20: DEVICE & ENDPOINT CORRELATION
# ============================================================

function Get-DeviceAnomalies {
    # T1078, T1550 - correlacao de devices com sign-ins suspeitos
    Write-Section "DEVICE ANOMALIES & COMPLIANCE" "T1078/T1550" "Initial Access / Defense Evasion"

    if ($Script:SkipGraph) { Write-IRLog "Graph skipped" -Severity "INFO"; return }

    try {
        # Devices nao conformes com acesso recente
        Write-Host "  >> Verificando devices nao geridos com acesso..." -ForegroundColor Gray

        $filterDate = $Script:FilterDate
        $rawSignins = @(Get-MgAuditLogSignIn -Filter `
            "createdDateTime ge $filterDate and status/errorCode eq 0" `
            -Top 3000 -ErrorAction SilentlyContinue)
        $signinsNonCompliant = @($rawSignins |
            Where-Object {
                $_.DeviceDetail.IsCompliant -eq $false -or
                $_.DeviceDetail.IsManaged -eq $false
            } |
            Group-Object UserPrincipalName |
            Where-Object { $_.Count -gt 5 } |
            Select-Object @{N="User";E={$_.Name}},
                          @{N="NonCompliantSignIns";E={$_.Count}},
                          @{N="DeviceNames";E={($_.Group.DeviceDetail.DisplayName | Sort-Object -Unique) -join ";"}})

        if ($signinsNonCompliant) {
            foreach ($s in $signinsNonCompliant) {
                Write-IRLog "Device nao gerido/conforme: $($s.User) >> $($s.NonCompliantSignIns) sign-ins [T1078]" `
                    -Severity "MEDIUM" -MITRETechnique "T1078" -MITRETactic "Initial Access" -Data $s
            }
            Export-IRData -FileName "20_non_compliant_device_signins" -Data $signinsNonCompliant
        }

        # Novos devices registados recentemente
        Write-Host "  >> Verificando novos devices registados..." -ForegroundColor Gray
        $newDevices = @(Get-MgDevice -Filter "registrationDateTime ge $filterDate" `
            -Property "DisplayName,OperatingSystem,RegisteredOwners,RegistrationDateTime,IsCompliant,IsManaged,TrustType" `
            -ErrorAction SilentlyContinue |
            Select-Object DisplayName, OperatingSystem, RegistrationDateTime, IsCompliant, IsManaged, TrustType)

        if ($newDevices.Count -gt 0) {
            Write-IRLog "Novos devices registados: $($newDevices.Count) no periodo" -Severity "INFO"
            Export-IRData -FileName "20_new_devices_registered" -Data $newDevices

            # Devices pessoais (BYO) com acesso privilegiado - risco elevado
            $byodDevices = @($newDevices | Where-Object {
                $_.TrustType -eq "Workplace" -and $_.IsManaged -eq $false
            })
            if ($byodDevices.Count -gt 0) {
                Write-IRLog "BYOD devices nao geridos registados: $($byodDevices.Count) [T1550]" `
                    -Severity "MEDIUM" -MITRETechnique "T1550" -MITRETactic "Defense Evasion"
            }
        }

        # Stale devices (> 90 dias sem check-in, mas com acesso recente = anomalia)
        Write-Host "  >> Verificando stale devices com atividade recente..." -ForegroundColor Gray
        $staleDate = (Get-Date).AddDays(-90).ToString("yyyy-MM-ddTHH:mm:ssZ")
        $staleDevices = @(Get-MgDevice -Filter "approximateLastSignInDateTime le $staleDate" `
            -Property "DisplayName,OperatingSystem,ApproximateLastSignInDateTime,IsCompliant,IsManaged" `
            -Top 100 -ErrorAction SilentlyContinue)

        if ($staleDevices.Count -gt 0) {
            Write-IRLog "Stale devices (sem check-in > 90 dias): $($staleDevices.Count) - potencial device hijacking" `
                -Severity "LOW" -MITRETechnique "T1078" -MITRETactic "Initial Access"
            Export-IRData -FileName "20_stale_devices" -Data ($staleDevices | Select-Object DisplayName, OperatingSystem, ApproximateLastSignInDateTime, IsCompliant, IsManaged)
        }

    } catch {
        Write-IRLog "Erro Device Anomalies: $_" -Severity "INFO"
    }
}

# ============================================================
# MODULO 21: ATTACK TIMELINE RECONSTRUCTION
# ============================================================

# ============================================================
# MODULO 24: MFA FATIGUE / PUSH BOMBING DETECTION (T1621)
# ============================================================

function Get-MFAFatigueHunting {
    # T1621 - Multi-Factor Authentication Request Generation
    # Atacante envia multiplos pedidos MFA ate utilizador aceitar por exaustao
    Write-Section "MFA FATIGUE / PUSH BOMBING" "T1621" "Credential Access"

    if ($Script:SkipGraph) { Write-IRLog "Graph skipped" -Severity "INFO"; return }

    try {
        Write-Host "  >> A analisar padroes de MFA fatigue..." -ForegroundColor Gray

        $filterDate = $Script:FilterDate

        # Obter sign-ins com MFA nos ultimos N dias
        $mfaSignins = @(Get-MgAuditLogSignIn -Filter `
            "createdDateTime ge $filterDate" `
            -Top 5000 -ErrorAction SilentlyContinue |
            Where-Object { $_.AuthenticationRequirement -eq "multiFactorAuthentication" -or
                           $_.ConditionalAccessStatus -ne $null })

        if ($mfaSignins.Count -eq 0) {
            Write-IRLog "MFA Fatigue: sem sign-ins MFA no periodo (ou licenca P2 necessaria para detalhe)" -Severity "INFO"
            return
        }

        # Agrupar por utilizador e procurar padroes de fadiga:
        # Muitas tentativas MFA num curto espaco de tempo -> eventual sucesso
        $fatigueUsers = [System.Collections.Generic.List[PSObject]]::new()
        $byUser = $mfaSignins | Group-Object UserPrincipalName

        foreach ($userGrp in $byUser) {
            $userEvents = @($userGrp.Group | Sort-Object CreatedDateTime)
            if ($userEvents.Count -lt 3) { continue }

            # Janela deslizante de 30 minutos
            for ($i = 0; $i -lt $userEvents.Count - 2; $i++) {
                $window = @($userEvents | Where-Object {
                    $_.CreatedDateTime -ge $userEvents[$i].CreatedDateTime -and
                    $_.CreatedDateTime -le $userEvents[$i].CreatedDateTime.AddMinutes(30)
                })

                $failures = @($window | Where-Object { $_.Status.ErrorCode -ne 0 })
                $successes = @($window | Where-Object { $_.Status.ErrorCode -eq 0 })

                # Indicador: 3+ falhas MFA seguidas de sucesso na mesma janela
                if ($failures.Count -ge 3 -and $successes.Count -ge 1) {
                    $lastFail    = ($failures | Sort-Object CreatedDateTime -Descending)[0]
                    $firstSucess = ($successes | Sort-Object CreatedDateTime)[0]

                    # Sucesso deve ser APOS as falhas
                    if ($firstSucess.CreatedDateTime -gt $lastFail.CreatedDateTime) {
                        $record = [PSCustomObject]@{
                            UserPrincipalName = $userGrp.Name
                            MFAFailures       = $failures.Count
                            EventualSuccess   = $true
                            WindowMinutes     = 30
                            FailureIPs        = ($failures.IPAddress | Sort-Object -Unique) -join ";"
                            SuccessIP         = $firstSucess.IPAddress
                            FirstEvent        = $userEvents[$i].CreatedDateTime
                            SuccessAt         = $firstSucess.CreatedDateTime
                            SameIP            = (($failures.IPAddress | Sort-Object -Unique) -contains $firstSucess.IPAddress)
                        }
                        $fatigueUsers.Add($record)
                        $sev = if ($record.MFAFailures -ge 10) { "CRITICAL" } else { "HIGH" }
                        Write-IRLog "MFA Fatigue detectado: $($userGrp.Name) -> $($failures.Count) falhas + sucesso em 30min [T1621]" `
                            -Severity $sev -MITRETechnique "T1621" -MITRETactic "Credential Access" -Data $record
                        break
                    }
                }
            }
        }

        if ($fatigueUsers.Count -gt 0) {
            Export-IRData -FileName "24_mfa_fatigue_suspects" -Data $fatigueUsers
        } else {
            Write-IRLog "MFA Fatigue: sem padroes de fadiga detetados" -Severity "INFO"
        }

        # Adicionalmente: Device Code Phishing (tokens emitidos via device flow de IPs suspeitos)
        Write-Host "  >> A verificar Device Code phishing..." -ForegroundColor Gray
        $deviceCodeSignins = @(Get-MgAuditLogSignIn -Filter `
            "createdDateTime ge $filterDate and authenticationProtocol eq 'deviceCode'" `
            -Top 500 -ErrorAction SilentlyContinue)

        if ($deviceCodeSignins.Count -gt 0) {
            $highRiskCountries = @("CN","RU","KP","IR","SY","BY","MM","AF")
            $suspectDeviceCode = @($deviceCodeSignins | Where-Object {
                $_.Location.CountryOrRegion -in $highRiskCountries -or
                $_.RiskLevelDuringSignIn -ne "none"
            })
            if ($suspectDeviceCode.Count -gt 0) {
                Write-IRLog "Device Code Phishing: $($suspectDeviceCode.Count) sign-ins via Device Code de paises de risco [T1078/T1621]" `
                    -Severity "HIGH" -MITRETechnique "T1621" -MITRETactic "Credential Access"
                Export-IRData -FileName "24_device_code_suspicious" -Data ($suspectDeviceCode | `
                    Select-Object UserPrincipalName, CreatedDateTime, IPAddress, `
                    @{N="Country";E={$_.Location.CountryOrRegion}}, RiskLevelDuringSignIn)
            } else {
                Write-IRLog "Device Code: $($deviceCodeSignins.Count) sign-ins, sem indicadores de phishing" -Severity "INFO"
            }
            Export-IRData -FileName "24_device_code_all" -Data ($deviceCodeSignins | `
                Select-Object UserPrincipalName, CreatedDateTime, IPAddress, `
                @{N="Country";E={$_.Location.CountryOrRegion}}, AppDisplayName)
        }

    } catch {
        Write-DebugError "MFAFatigue" "Erro no modulo" $_
    }
}

# ============================================================
# MODULO 25: DISPLAY NAME IMPERSONATION HUNTING (T1656)
# ============================================================

function Get-ImpersonationHunting {
    # T1656 - Impersonation
    # Atacantes criam contas/guests com display names identicos a utilizadores internos
    Write-Section "IMPERSONATION / DISPLAY NAME SPOOFING" "T1656" "Defense Evasion"

    if ($Script:SkipGraph) { Write-IRLog "Graph skipped" -Severity "INFO"; return }

    try {
        $domainContext = if ($Script:UserDomains.Count -gt 0) { $Script:UserDomains -join ", " } else { "todos os dominios" }
        Write-Host "  >> A recolher utilizadores internos (dominios: $domainContext)..." -ForegroundColor Gray

        # Todos os utilizadores internos (todos os dominios do tenant)
        $internalUsers = @(Get-MgUser -All `
            -Property "Id,DisplayName,UserPrincipalName,UserType,Mail" `
            -Filter "userType eq 'Member'" `
            -ErrorAction SilentlyContinue)

        # Todos os guests
        $guestUsers = @(Get-MgUser -All `
            -Property "Id,DisplayName,UserPrincipalName,UserType,Mail,CreatedDateTime" `
            -Filter "userType eq 'Guest'" `
            -ErrorAction SilentlyContinue)

        Write-Host "  >> A comparar display names ($($internalUsers.Count) internos, $($guestUsers.Count) guests)..." -ForegroundColor Gray

        $spoofMatches = [System.Collections.Generic.List[PSObject]]::new()

        # Construir set de nomes internos para lookup rapido
        $internalNames = @{}
        foreach ($u in $internalUsers) {
            if ($u.DisplayName) {
                $key = $u.DisplayName.Trim().ToLower()
                $internalNames[$key] = $u.UserPrincipalName
            }
        }

        foreach ($guest in $guestUsers) {
            if (-not $guest.DisplayName) { continue }
            $guestName = $guest.DisplayName.Trim().ToLower()

            # Match exacto
            if ($internalNames.ContainsKey($guestName)) {
                $record = [PSCustomObject]@{
                    GuestUPN      = $guest.UserPrincipalName
                    GuestDisplay  = $guest.DisplayName
                    MatchedInternal = $internalNames[$guestName]
                    MatchType     = "Exact"
                    CreatedDate   = $guest.CreatedDateTime
                }
                $spoofMatches.Add($record)
                Write-IRLog "Impersonation EXACT: Guest '$($guest.DisplayName)' = interno '$($internalNames[$guestName])' [T1656]" `
                    -Severity "HIGH" -MITRETechnique "T1656" -MITRETactic "Defense Evasion" -Data $record
                continue
            }

            # Match aproximado: remover espacos/pontos e comparar
            $guestNorm = $guestName -replace '[\s\.\-_]',''
            foreach ($intName in $internalNames.Keys) {
                $intNorm = $intName -replace '[\s\.\-_]',''
                if ($guestNorm -eq $intNorm -and $guestNorm.Length -gt 4) {
                    $record = [PSCustomObject]@{
                        GuestUPN        = $guest.UserPrincipalName
                        GuestDisplay    = $guest.DisplayName
                        MatchedInternal = $internalNames[$intName]
                        MatchType       = "Normalized"
                        CreatedDate     = $guest.CreatedDateTime
                    }
                    $spoofMatches.Add($record)
                    Write-IRLog "Impersonation APPROX: Guest '$($guest.DisplayName)' ~= interno '$($internalNames[$intName])' [T1656]" `
                        -Severity "MEDIUM" -MITRETechnique "T1656" -MITRETactic "Defense Evasion" -Data $record
                    break
                }
            }
        }

        # Verificar tambem Service Principals com nomes suspeitos
        Write-Host "  >> A verificar Service Principals com nomes de utilizadores..." -ForegroundColor Gray
        $sps = @(Get-MgServicePrincipal -All -Property "Id,DisplayName,AppId,CreatedDateTime" `
            -ErrorAction SilentlyContinue | Where-Object {
                $_.DisplayName -and $internalNames.ContainsKey($_.DisplayName.Trim().ToLower())
            })

        foreach ($sp in $sps) {
            Write-IRLog "SP com nome de utilizador interno: '$($sp.DisplayName)' [T1656/T1098.003]" `
                -Severity "HIGH" -MITRETechnique "T1656" -MITRETactic "Defense Evasion" `
                -Data @{ SPName = $sp.DisplayName; AppId = $sp.AppId; Created = $sp.CreatedDateTime }
        }

        if ($spoofMatches.Count -gt 0) {
            Export-IRData -FileName "25_impersonation_matches" -Data $spoofMatches
        } else {
            Write-IRLog "Impersonation: sem display name spoofing detetado" -Severity "INFO"
        }

        # Verificar tambem OAuth apps de tenants externos (consent phishing refinado)
        Write-Host "  >> A verificar OAuth apps de tenants externos..." -ForegroundColor Gray
        $oauthGrants = @(Get-MgOauth2PermissionGrant -All -ErrorAction SilentlyContinue)
        $externalApps = [System.Collections.Generic.List[PSObject]]::new()

        $highRiskScopes = @("Mail.ReadWrite","Mail.Read","Files.ReadWrite.All",
                            "Calendars.ReadWrite","MailboxSettings.ReadWrite","full_access_as_user")

        $seenApps = @{}
        foreach ($grant in $oauthGrants) {
            $hasRiskyScope = ($grant.Scope -split " ") | Where-Object { $_ -in $highRiskScopes }
            if (-not $hasRiskyScope) { continue }

            try {
                $sp = Get-MgServicePrincipal -ServicePrincipalId $grant.ClientId -ErrorAction SilentlyContinue
                if ($sp -and $sp.AppOwnerOrganizationId) {
                    # App de tenant externo com permissoes de alto risco
                    $org = Get-MgOrganization -ErrorAction SilentlyContinue
                    if ($sp.AppOwnerOrganizationId -ne $org.Id) {
                        $record = [PSCustomObject]@{
                            AppName            = $sp.DisplayName
                            AppId              = $sp.AppId
                            OwnerTenantId      = $sp.AppOwnerOrganizationId
                            GrantedScopes      = $grant.Scope
                            ConsentType        = $grant.ConsentType
                        }
                        $externalApps.Add($record)
                        Write-IRLog "Consent Phishing: App externa '$($sp.DisplayName)' de tenant $($sp.AppOwnerOrganizationId) com scopes de alto risco [T1550.001]" `
                            -Severity "HIGH" -MITRETechnique "T1550.001" -MITRETactic "Defense Evasion" -Data $record
                    }
                }
            } catch { Write-DebugError "ImpersonationHunting" "SP lookup para $($grant.ClientId)" $_ }
        }

        if ($externalApps.Count -gt 0) {
            Export-IRData -FileName "25_external_tenant_apps" -Data $externalApps
        }

    } catch {
        Write-DebugError "ImpersonationHunting" "Erro no modulo" $_
    }
}

# ============================================================
# MODULO 26: CLOUD SERVICE ENUMERATION HUNTING (T1526)
# ============================================================

function Get-EnumerationHunting {
    # T1526 - Cloud Service Discovery
    # Detetar reconhecimento e enumeracao do tenant apos compromisso inicial
    Write-Section "CLOUD ENUMERATION / RECONNAISSANCE HUNTING" "T1526/T1087" "Discovery"

    if ($Script:SkipGraph) { Write-IRLog "Graph skipped" -Severity "INFO"; return }

    try {
        Write-Host "  >> A analisar padroes de enumeracao via Graph API..." -ForegroundColor Gray

        # Analisar sign-ins de aplicacoes (nao interativos) com volume alto de operacoes
        # Indicador de script/tool a enumerar o tenant
        $filterDate = $Script:FilterDate

        $appSignins = @(Get-MgAuditLogSignIn -Filter `
            "createdDateTime ge $filterDate and isInteractive eq false" `
            -Top 3000 -ErrorAction SilentlyContinue)

        if ($appSignins.Count -gt 0) {
            # Agrupar por app + IP - volume alto indica enumeracao
            $enumCandidates = @($appSignins | Group-Object { "$($_.AppId)|$($_.IPAddress)" } |
                Where-Object { $_.Count -gt 100 } |
                Select-Object @{N="App";E={$_.Group[0].AppDisplayName}},
                              @{N="AppId";E={$_.Group[0].AppId}},
                              @{N="IP";E={$_.Group[0].IPAddress}},
                              @{N="Country";E={$_.Group[0].Location.CountryOrRegion}},
                              @{N="RequestCount";E={$_.Count}},
                              @{N="UniqueUsers";E={($_.Group.UserPrincipalName | Sort-Object -Unique).Count}},
                              @{N="FirstSeen";E={($_.Group.CreatedDateTime | Sort-Object)[0]}},
                              @{N="LastSeen";E={($_.Group.CreatedDateTime | Sort-Object -Descending)[0]}})

            foreach ($c in $enumCandidates) {
                $sev = if ($c.RequestCount -gt 1000) { "HIGH" } else { "MEDIUM" }
                Write-IRLog "Enumeracao suspeita: App '$($c.App)' de IP $($c.IP) -> $($c.RequestCount) chamadas non-interactive [T1526]" `
                    -Severity $sev -MITRETechnique "T1526" -MITRETactic "Discovery" -Data $c
            }

            if ($enumCandidates.Count -gt 0) {
                Export-IRData -FileName "26_enumeration_candidates" -Data $enumCandidates
            }
        }

        # Verificar Service Principals com muitos app role assignments recentes
        # Indicador: SP criado recentemente com muitas permissoes adicionadas rapidamente
        Write-Host "  >> A verificar Service Principals com comportamento de enum..." -ForegroundColor Gray
        $recentSPs = @(Get-MgServicePrincipal -Filter "createdDateTime ge $filterDate" `
            -Property "Id,DisplayName,AppId,CreatedDateTime,AppOwnerOrganizationId" `
            -ErrorAction SilentlyContinue)

        $org = Get-MgOrganization -ErrorAction SilentlyContinue
        $suspectSPs = @($recentSPs | Where-Object {
            # SP externo (nao do proprio tenant)
            $_.AppOwnerOrganizationId -and $_.AppOwnerOrganizationId -ne $org.Id
        })

        if ($suspectSPs.Count -gt 0) {
            Write-IRLog "Service Principals externos criados recentemente: $($suspectSPs.Count) [T1526/T1098.003]" `
                -Severity "MEDIUM" -MITRETechnique "T1526" -MITRETactic "Discovery"
            Export-IRData -FileName "26_external_sp_recent" -Data ($suspectSPs | `
                Select-Object DisplayName, AppId, CreatedDateTime, AppOwnerOrganizationId)
        }

        # Password Policy Discovery - verificar se alguma conta listou politicas de password
        # Via Graph: leitura de /domains com authenticationType
        Write-Host "  >> A verificar Password Policy Discovery..." -ForegroundColor Gray
        $domains = @(Get-MgDomain -ErrorAction SilentlyContinue)
        $passwordPolicyExposed = @($domains | Where-Object {
            $_.PasswordNotificationWindowInDays -ne $null -or
            $_.PasswordValidityPeriodInDays -ne $null
        })

        if ($passwordPolicyExposed.Count -gt 0) {
            $policyData = $passwordPolicyExposed | Select-Object Id, AuthenticationType,
                PasswordNotificationWindowInDays, PasswordValidityPeriodInDays

            Write-IRLog "Password Policy exposta: $($passwordPolicyExposed.Count) dominios com politica visivel [T1201]" `
                -Severity "LOW" -MITRETechnique "T1201" -MITRETactic "Discovery" -Data $policyData
            Export-IRData -FileName "26_password_policy_exposure" -Data $policyData

            # Verificar se a politica e fraca
            foreach ($d in $passwordPolicyExposed) {
                if ($d.PasswordValidityPeriodInDays -eq 2147483647) {
                    Write-IRLog "Password sem expiracao configurada no dominio $($d.Id) [T1201]" `
                        -Severity "MEDIUM" -MITRETechnique "T1201" -MITRETactic "Discovery"
                }
            }
        }

        # Verificar grupos com membros suspeitos (enum de grupos privilegiados)
        Write-Host "  >> A verificar grupos criticos e membros suspeitos..." -ForegroundColor Gray
        $criticalGroups = @(Get-MgGroup -Filter `
            "startsWith(displayName,'Admin') or startsWith(displayName,'Security') or startsWith(displayName,'Global')" `
            -Property "Id,DisplayName,CreatedDateTime,GroupTypes,MembershipRule" `
            -Top 20 -ErrorAction SilentlyContinue)

        if ($criticalGroups.Count -gt 0) {
            $groupReport = [System.Collections.Generic.List[PSObject]]::new()
            foreach ($grp in $criticalGroups) {
                try {
                    $members = @(Get-MgGroupMember -GroupId $grp.Id -Top 50 -ErrorAction SilentlyContinue)
                    $guestMembers = @($members | Where-Object {
                        $_.AdditionalProperties["userType"] -eq "Guest"
                    })
                    $record = [PSCustomObject]@{
                        GroupName    = $grp.DisplayName
                        TotalMembers = $members.Count
                        GuestMembers = $guestMembers.Count
                        CreatedDate  = $grp.CreatedDateTime
                    }
                    $groupReport.Add($record)
                    if ($guestMembers.Count -gt 0) {
                        Write-IRLog "Grupo critico '$($grp.DisplayName)' tem $($guestMembers.Count) guest(s) como membro [T1069.002]" `
                            -Severity "HIGH" -MITRETechnique "T1069.002" -MITRETactic "Discovery" -Data $record
                    }
                } catch { Write-DebugError "EnumerationHunting" "Group members $($grp.DisplayName)" $_ }
            }
            Export-IRData -FileName "26_critical_groups" -Data $groupReport
        }

    } catch {
        Write-DebugError "EnumerationHunting" "Erro no modulo" $_
    }
}

function Build-AttackTimeline {
    # Correlacao cruzada de todos os findings para reconstruir cadeia de ataque
    Write-Section "ATTACK TIMELINE RECONSTRUCTION" "CORRELATION" "All Tactics"

    Write-Host "  >> Construindo timeline de ataque correlacionada..." -ForegroundColor Gray

    if ($Script:Findings.Count -eq 0) {
        Write-IRLog "Sem findings para correlacionar" -Severity "INFO"
        return
    }

    # Agrupar findings por utilizador mencionado na mensagem
    $timelineByUser = @{}

    foreach ($f in $Script:Findings) {
        # Extrair UPNs mencionados nos findings (pattern: xxx@xxx.xxx)
        $upnMatches = [regex]::Matches($f.Message, '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
        foreach ($match in $upnMatches) {
            $upn = $match.Value
            if (-not $timelineByUser.ContainsKey($upn)) { $timelineByUser[$upn] = @() }
            $timelineByUser[$upn] += $f
        }
    }

    $timelineData = [System.Collections.Generic.List[PSObject]]::new()

    foreach ($user in $timelineByUser.Keys) {
        $userFindings = $timelineByUser[$user] | Sort-Object { $_.Timestamp }

        # Detectar padroes de ataque conhecidos
        $tactics = $userFindings.Tactic | Sort-Object -Unique
        $techniques = $userFindings.Technique | Sort-Object -Unique

        # Padroes BEC (Business Email Compromise)
        $isBEC = @($userFindings | Where-Object { $_.Technique -match "T1078|T1110" }).Count -gt 0 -and
                 @($userFindings | Where-Object { $_.Technique -match "T1114|T1564" }).Count -gt 0

        # Padroes de Account Takeover
        $isATO = @($userFindings | Where-Object { $_.Technique -match "T1078|T1110" }).Count -gt 0 -and
                 @($userFindings | Where-Object { $_.Technique -match "T1098|T1531" }).Count -gt 0

        # Padroes de Exfiltracao
        $isExfil = @($userFindings | Where-Object { $_.Technique -match "T1530|T1048|T1567|T1114" }).Count -gt 0

        $attackPattern = @()
        if ($isBEC)   { $attackPattern += "BEC (Business Email Compromise)" }
        if ($isATO)   { $attackPattern += "ATO (Account Takeover)" }
        if ($isExfil) { $attackPattern += "Data Exfiltration" }
        if ($attackPattern.Count -eq 0) { $attackPattern += "Suspicious Activity" }

        $record = [PSCustomObject]@{
            User            = $user
            FindingsCount   = $userFindings.Count
            CriticalCount   = @($userFindings | Where-Object { $_.Severity -eq "CRITICAL" }).Count
            HighCount       = @($userFindings | Where-Object { $_.Severity -eq "HIGH" }).Count
            TacticsObserved = $tactics -join " >> "
            TechniquesUsed  = $techniques -join ";"
            AttackPattern   = $attackPattern -join " + "
            FirstObserved   = ($userFindings.Timestamp | Sort-Object)[0]
            LastObserved    = ($userFindings.Timestamp | Sort-Object -Descending)[0]
        }
        $timelineData.Add($record)

        if ($isBEC -or $isATO) {
            Write-IRLog "ATTACK CHAIN DETECTED: $user - $($attackPattern -join ' + ') [Multi-Technique]" `
                -Severity "CRITICAL" -MITRETechnique ($techniques -join ";") -MITRETactic "Kill Chain" -Data $record
        }
    }

    Export-IRData -FileName "21_attack_timeline" -Data ($timelineData | Sort-Object CriticalCount -Descending)
    Write-IRLog "Attack Timeline: $($timelineData.Count) utilizadores com atividade suspeita correlacionada" -Severity "INFO"
}

# ============================================================
# MODULO 22: EXTERNAL IDENTITY & FEDERATION AUDIT
# ============================================================

function Get-FederationAndExternalIdentityAudit {
    # T1556.007 - Hybrid Identity | T1199 - Trusted Relationship | T1606.002 - SAML Tokens
    Write-Section "FEDERATION & EXTERNAL IDENTITY AUDIT" "T1556.007/T1199/T1606.002" "Defense Evasion / Initial Access"

    if ($Script:SkipGraph) { Write-IRLog "Graph skipped" -Severity "INFO"; return }

    try {
        # Dominios federados
        Write-Host "  >> Auditando dominios e configuracao de federation..." -ForegroundColor Gray
        $org = Get-MgOrganization -ErrorAction SilentlyContinue
        $domains = @(Get-MgDomain -ErrorAction SilentlyContinue)

        $federatedDomains = @($domains | Where-Object { $_.AuthenticationType -eq "Federated" })
        if ($federatedDomains.Count -gt 0) {
            Write-IRLog "Dominios federados: $($federatedDomains.Id -join ', ') - verificar configuracao ADFS/AAD Connect [T1556.007]" `
                -Severity "MEDIUM" -MITRETechnique "T1556.007" -MITRETactic "Defense Evasion"
            Export-IRData -FileName "22_federated_domains" -Data ($federatedDomains | Select-Object Id, AuthenticationType, IsVerified, IsDefault, SupportedServices)
        }

        # Cross-Tenant Access Settings (B2B)
        Write-Host "  >> Verificando Cross-Tenant Access policies..." -ForegroundColor Gray
        try {
            $crossTenant = Get-MgPolicyCrossTenantAccessPolicy -ErrorAction SilentlyContinue
            if ($crossTenant) {
                Write-IRLog "Cross-Tenant Access Policy configurada - auditar parceiros B2B" -Severity "INFO"
            }

            $partners = @(Get-MgPolicyCrossTenantAccessPolicyPartner -ErrorAction SilentlyContinue)
            if ($partners.Count -gt 0) {
                Write-IRLog "Cross-Tenant Partners: $($partners.Count) tenants com acesso B2B configurado [T1199]" `
                    -Severity "MEDIUM" -MITRETechnique "T1199" -MITRETactic "Initial Access"
                Export-IRData -FileName "22_cross_tenant_partners" -Data ($partners | Select-Object TenantId, IsServiceProvider, AutomaticUserConsentSettings)
            }
        } catch { Write-IRLog "Cross-Tenant Access: permissoes insuficientes ou nao disponivel" -Severity "INFO" }

        # Verificar se AAD Connect / Entra Connect esta configurado
        Write-Host "  >> Verificando Entra Connect (Hybrid Identity)..." -ForegroundColor Gray
        $onPremSync = $org | ForEach-Object { $_.OnPremisesSyncEnabled }
        if ($onPremSync -eq $true) {
            Write-IRLog "Entra Connect (Hybrid Identity) ATIVO - vetor de Golden SAML/Pass-the-Hash e relevante [T1556.007]" `
                -Severity "MEDIUM" -MITRETechnique "T1556.007" -MITRETactic "Defense Evasion"

            # Verificar ultima sincronizacao
            $lastSync = $org | ForEach-Object { $_.OnPremisesLastSyncDateTime }
            if ($lastSync) {
                $syncAge = [math]::Round(((Get-Date) - $lastSync).TotalHours, 1)
                if ($syncAge -gt 3) {
                    Write-IRLog "Ultima sincronizacao Entra Connect: $syncAge horas atras (normal = < 3h) - possivel disrupcao [T1562]" `
                        -Severity "HIGH" -MITRETechnique "T1562" -MITRETactic "Defense Evasion"
                }
            }
        }

    } catch {
        Write-IRLog "Erro Federation Audit: $_" -Severity "INFO"
    }
}

# ============================================================
# MODULO 23: EMAIL THREAT ANALYSIS (MDO)
# ============================================================

function Get-EmailThreatAnalysis {
    Write-Section "EMAIL SECURITY - DMARC/SPF/DKIM & THREAT ANALYSIS" "T1566/T1566.002" "Initial Access / Defense Evasion"

    $emailReport    = [System.Collections.Generic.List[PSObject]]::new()
    $allRiskFactors = [System.Collections.Generic.List[PSObject]]::new()
    $domainScores   = @{}

    # ---- Obter dominios do tenant ----
    $domains = @()
    try {
        $domains = @(Get-MgDomain -ErrorAction Stop)
        Write-Host "  >> A analisar $($domains.Count) dominios via DNS..." -ForegroundColor Gray
    } catch {
        Write-DebugError "EmailThreatAnalysis" "Get-MgDomain falhou" $_
        return
    }

    foreach ($domain in $domains) {
        $dom         = $domain.Id
        $isDefault   = $domain.IsDefault
        $isVerified  = $domain.IsVerified
        $domFactors  = [System.Collections.Generic.List[PSObject]]::new()

        Write-Host "  [*] $dom" -ForegroundColor DarkGray

        # Dominios .onmicrosoft.com sao geridos pela Microsoft internamente
        # DMARC/DKIM nao sao configurados pelo tenant - excluir desta analise
        $isMsManaged = $dom -match "\.onmicrosoft\.com$"

        $spfValid = $false; $spfRaw   = ""
        $dmarcValid = $false; $dmarcRaw = ""; $dmarcPolicy = "none"
        $dkimStatus = "N/A"

        # --- SPF ---
        try {
            $spfResult = Resolve-DnsName -Name $dom -Type TXT -ErrorAction Stop
            $spfTxt    = $spfResult | Where-Object { $_.Strings -match "v=spf1" } | Select-Object -First 1
            if ($spfTxt) {
                $spfRaw   = ($spfTxt.Strings -join "") -replace "\s+"," "
                $spfValid = $true
                if ($spfRaw -match "\+all") {
                    $domFactors.Add([PSCustomObject]@{Factor="SPF '+all' (aceita tudo)";RiskScore=30;Severity="CRITICAL";Recommendation="Alterar para -all imediatamente"})
                    Write-IRLog "SPF '$dom' usa +all - qualquer servidor pode enviar email (+30 pts)" -Severity "CRITICAL" -MITRETechnique "T1566.002" -MITRETactic "Defense Evasion"
                } elseif ($spfRaw -match "~all") {
                    $domFactors.Add([PSCustomObject]@{Factor="SPF softfail (~all)";RiskScore=10;Severity="MEDIUM";Recommendation="Alterar para -all"})
                    Write-IRLog "SPF '$dom': ~all (softfail - nao rejeita emails invalidos) (+10 pts)" -Severity "MEDIUM" -MITRETechnique "T1566.002" -MITRETactic "Defense Evasion"
                } elseif ($spfRaw -match "\-all") {
                    Write-IRLog "SPF '$dom': -all (strictfail) - configuracao segura" -Severity "INFO"
                } elseif ($spfRaw -notmatch "all") {
                    $domFactors.Add([PSCustomObject]@{Factor="SPF sem directiva 'all'";RiskScore=20;Severity="HIGH";Recommendation="Adicionar -all ao final do SPF"})
                    Write-IRLog "SPF '$dom' sem directiva 'all' (+20 pts)" -Severity "HIGH" -MITRETechnique "T1566.002" -MITRETactic "Defense Evasion"
                }
                $lookups = ([regex]::Matches($spfRaw,"include:|redirect=|a:|mx:") | Measure-Object).Count
                if ($lookups -gt 8) {
                    $domFactors.Add([PSCustomObject]@{Factor="SPF com $lookups lookups DNS (limite: 10)";RiskScore=15;Severity="MEDIUM";Recommendation="Simplificar SPF para <10 lookups"})
                }
            } else {
                $domFactors.Add([PSCustomObject]@{Factor="SPF em falta";RiskScore=25;Severity="HIGH";Recommendation="Criar: v=spf1 include:spf.protection.outlook.com -all"})
                Write-IRLog "SPF em falta para '$dom' (+25 pts)" -Severity "HIGH" -MITRETechnique "T1566.002" -MITRETactic "Defense Evasion"
            }
        } catch {
            $domFactors.Add([PSCustomObject]@{Factor="SPF DNS lookup falhou";RiskScore=10;Severity="MEDIUM";Recommendation="Verificar DNS do dominio"})
            Write-DebugError "EmailThreatAnalysis" "SPF DNS $dom" $_
        }

        # --- DMARC ---
        if ($isMsManaged) {
            Write-IRLog "DMARC '$dom': dominio gerido pela Microsoft - analise ignorada" -Severity "INFO"
            $dmarcValid = $true; $dmarcPolicy = "ms-managed"
        } else {
        try {
            $dmarcResult = Resolve-DnsName -Name "_dmarc.$dom" -Type TXT -ErrorAction Stop
            $dmarcTxt    = $dmarcResult | Where-Object { $_.Strings -match "v=DMARC1" } | Select-Object -First 1
            if ($dmarcTxt) {
                $dmarcRaw   = ($dmarcTxt.Strings -join "") -replace "\s+"," "
                $dmarcValid = $true
                $pMatch     = [regex]::Match($dmarcRaw, "p=(\w+)")
                if ($pMatch.Success) { $dmarcPolicy = $pMatch.Groups[1].Value }
                switch ($dmarcPolicy) {
                    "none" {
                        $domFactors.Add([PSCustomObject]@{Factor="DMARC policy=none (so monitoriza)";RiskScore=20;Severity="HIGH";Recommendation="Alterar para p=quarantine depois p=reject"})
                        Write-IRLog "DMARC '$dom': policy=none - nao rejeita emails falsos (+20 pts)" -Severity "HIGH" -MITRETechnique "T1566.002" -MITRETactic "Defense Evasion"
                    }
                    "quarantine" {
                        $domFactors.Add([PSCustomObject]@{Factor="DMARC policy=quarantine (recomendado: reject)";RiskScore=5;Severity="LOW";Recommendation="Alterar para p=reject"})
                        Write-IRLog "DMARC '$dom': policy=quarantine - bom, considerar reject" -Severity "LOW"
                    }
                    "reject" { Write-IRLog "DMARC '$dom': policy=reject - configuracao otima" -Severity "INFO" }
                }
                if ($dmarcRaw -notmatch "rua=") {
                    $domFactors.Add([PSCustomObject]@{Factor="DMARC sem reporting URI (rua=)";RiskScore=5;Severity="LOW";Recommendation="Adicionar rua=mailto:dmarc-reports@$dom"})
                }
                $pctMatch = [regex]::Match($dmarcRaw, "pct=(\d+)")
                if ($pctMatch.Success -and [int]$pctMatch.Groups[1].Value -lt 100) {
                    $domFactors.Add([PSCustomObject]@{Factor="DMARC pct=$($pctMatch.Groups[1].Value) (nao 100%)";RiskScore=10;Severity="MEDIUM";Recommendation="Aumentar para pct=100"})
                    Write-IRLog "DMARC '$dom' pct=$($pctMatch.Groups[1].Value) (+10 pts)" -Severity "MEDIUM" -MITRETechnique "T1566.002" -MITRETactic "Defense Evasion"
                }
            } else {
                $domFactors.Add([PSCustomObject]@{Factor="DMARC em falta";RiskScore=30;Severity="HIGH";Recommendation="Criar: _dmarc.$dom TXT v=DMARC1; p=quarantine; rua=mailto:dmarc@$dom"})
                Write-IRLog "DMARC nao configurado para '$dom' (+30 pts)" -Severity "HIGH" -MITRETechnique "T1566.002" -MITRETactic "Defense Evasion"
            }
        } catch {
            $domFactors.Add([PSCustomObject]@{Factor="DMARC nao encontrado";RiskScore=30;Severity="HIGH";Recommendation="Criar registo _dmarc.$dom TXT com v=DMARC1; p=reject"})
            Write-IRLog "DMARC nao configurado para '$dom' (+30 pts)" -Severity "HIGH" -MITRETechnique "T1566.002" -MITRETactic "Defense Evasion"
        }
        } # end if -not isMsManaged (DMARC)

        # --- DKIM ---
        if ($isMsManaged) {
            Write-IRLog "DKIM '$dom': dominio gerido pela Microsoft - analise ignorada" -Severity "INFO"
            $dkimStatus = "MS-managed"
        } elseif (Test-EXOAvailable) {
            try {
                $dkimConf = Get-DkimSigningConfig -Identity $dom -ErrorAction SilentlyContinue
                if ($dkimConf) {
                    $dkimStatus = if ($dkimConf.Enabled) { "Enabled (EXO)" } else { "Disabled (EXO)" }
                    if (-not $dkimConf.Enabled) {
                        $domFactors.Add([PSCustomObject]@{Factor="DKIM desativado no EXO";RiskScore=25;Severity="HIGH";Recommendation="Enable-DkimSigningConfig -Identity $dom"})
                        Write-IRLog "DKIM desativado para '$dom' via EXO (+25 pts)" -Severity "HIGH" -MITRETechnique "T1566.002" -MITRETactic "Defense Evasion"
                    } else { Write-IRLog "DKIM '$dom': Enabled via EXO" -Severity "INFO" }
                } else {
                    $domFactors.Add([PSCustomObject]@{Factor="DKIM nao configurado no EXO";RiskScore=25;Severity="HIGH";Recommendation="New-DkimSigningConfig -DomainName $dom -Enabled `$true"})
                }
            } catch { Write-DebugError "EmailThreatAnalysis" "DKIM EXO $dom" $_ }
        } else {
            $dkimFound = $false
            foreach ($sel in @("selector1","selector2")) {
                try {
                    if (Resolve-DnsName -Name "$sel._domainkey.$dom" -Type CNAME -ErrorAction Stop) {
                        $dkimFound = $true; $dkimStatus = "Enabled (DNS: $sel)"
                    }
                } catch { }
            }
            if (-not $dkimFound) {
                try {
                    if (Resolve-DnsName -Name "selector1._domainkey.$dom" -Type TXT -ErrorAction Stop) {
                        $dkimFound = $true; $dkimStatus = "Enabled (TXT)"
                    }
                } catch { }
            }
            if (-not $dkimFound) {
                $dkimStatus = "Not Found (DNS)"
                $domFactors.Add([PSCustomObject]@{Factor="DKIM nao encontrado via DNS";RiskScore=20;Severity="HIGH";Recommendation="Configurar DKIM no M365 Admin > Security > Email Auth"})
                Write-IRLog "DKIM nao encontrado via DNS para '$dom' (+20 pts)" -Severity "HIGH" -MITRETechnique "T1566.002" -MITRETactic "Defense Evasion"
            } else { Write-IRLog "DKIM '$dom': $dkimStatus" -Severity "INFO" }
        } # end elseif EXO / DNS DKIM check

        # --- Score por dominio ---
        if ($domFactors.Count -gt 0) {
            $domMeasure = $domFactors | Measure-Object -Property RiskScore -Sum
            $domScore   = if ($domMeasure -and $domMeasure.Sum) { $domMeasure.Sum } else { 0 }
        } else { $domScore = 0 }

        if     ($domScore -ge 60) { $domLevel = "CRITICAL" }
        elseif ($domScore -ge 35) { $domLevel = "HIGH"     }
        elseif ($domScore -ge 15) { $domLevel = "MEDIUM"   }
        elseif ($domScore -ge 5 ) { $domLevel = "LOW"      }
        else                      { $domLevel = "OK"       }

        $domainScores[$dom] = $domScore

        # Adicionar factores deste dominio ao acumulador global
        foreach ($f in $domFactors) { $allRiskFactors.Add($f) }

        # Finding por dominio (apenas se tem problemas)
        if ($domScore -gt 0) {
            $domProblems = ($domFactors | ForEach-Object { $_.Factor }) -join "; "
            $sevForDom   = if ($domLevel -eq "OK") { "INFO" } else { $domLevel }
            Write-IRLog "Email Security '$dom': $domLevel (score $domScore) - $domProblems" `
                -Severity $sevForDom -MITRETechnique "T1566.002" -MITRETactic "Defense Evasion" `
                -Data ($domFactors | Select-Object Factor, RiskScore, Severity, Recommendation)
        }

        $emailReport.Add([PSCustomObject]@{
            Domain       = $dom
            IsDefault    = $isDefault
            IsVerified   = $isVerified
            SPF_Valid    = $spfValid
            SPF_Record   = $spfRaw
            DMARC_Valid  = $dmarcValid
            DMARC_Policy = $dmarcPolicy
            DMARC_Record = $dmarcRaw
            DKIM_Status  = $dkimStatus
            DomainScore  = $domScore
            DomainLevel  = $domLevel
        })

        # Banner por dominio
        if ($domLevel -eq "OK") {
            Write-Host "    Score: 0 - Configuracao segura" -ForegroundColor Green
        } else {
            if ($domLevel -eq "CRITICAL") { $dc = "Red" } elseif ($domLevel -eq "HIGH") { $dc = "DarkYellow" } else { $dc = "Yellow" }
            Write-Host "    Score: $domScore pts - $domLevel" -ForegroundColor $dc
        }
    }

    # --- Sumario global ---
    if ($allRiskFactors.Count -gt 0) {
        $totalMeasure = $allRiskFactors | Measure-Object -Property RiskScore -Sum
        $totalRisk    = if ($totalMeasure -and $totalMeasure.Sum) { $totalMeasure.Sum } else { 0 }
    } else { $totalRisk = 0 }

    $worstDomain = $domainScores.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 1
    $secureDomains= @($domainScores.GetEnumerator() | Where-Object { $_.Value -eq 0 }).Count
    $riskyDomains = @($domainScores.GetEnumerator() | Where-Object { $_.Value -gt 0 }).Count

    if     ($totalRisk -ge 80) { $globalLevel = "CRITICAL" }
    elseif ($totalRisk -ge 50) { $globalLevel = "HIGH"     }
    elseif ($totalRisk -ge 25) { $globalLevel = "MEDIUM"   }
    elseif ($totalRisk -ge 10) { $globalLevel = "LOW"      }
    else                       { $globalLevel = "MINIMAL"  }

    if ($globalLevel -eq "CRITICAL") { $gColor = "Red" } elseif ($globalLevel -eq "HIGH") { $gColor = "DarkYellow" } else { $gColor = "Yellow" }

    Write-Host ""
    Write-Host "  +==============================================+" -ForegroundColor $gColor
    Write-Host "  |  EMAIL SECURITY RISK ASSESSMENT             |" -ForegroundColor White
    Write-Host "  |  Nivel global : $($globalLevel.PadRight(31))|" -ForegroundColor $gColor
    Write-Host "  |  Score total  : $("$totalRisk pts".PadRight(31))|" -ForegroundColor White
    Write-Host "  |  Dominios OK  : $("$secureDomains/$($domains.Count)".PadRight(31))|" -ForegroundColor Green
    if ($worstDomain) {
        Write-Host "  |  Pior dominio : $("$($worstDomain.Key) ($($worstDomain.Value) pts)".Substring(0,[math]::Min("$($worstDomain.Key) ($($worstDomain.Value) pts)".Length,31)).PadRight(31))|" -ForegroundColor $gColor
    }
    Write-Host "  +==============================================+" -ForegroundColor $gColor
    Write-Host ""

    $sevLog = if ($globalLevel -eq "MINIMAL") { "INFO" } else { $globalLevel }
    Write-IRLog "Email Security Global: $globalLevel (score $totalRisk, $riskyDomains/$($domains.Count) dominios com problemas)" `
        -Severity $sevLog -MITRETechnique "T1566.002" -MITRETactic "Defense Evasion"

    Export-IRData -FileName "23_email_security_report" -Data $emailReport
    Export-IRData -FileName "23_email_risk_factors"    -Data $allRiskFactors
}



# ============================================================
# ATUALIZAR FUNCAO PRINCIPAL COM NOVOS MODULOS
# ============================================================

function Start-O365IRScriptFull {
    Show-Banner
    New-OutputDirectory
    Test-Prerequisites
    Connect-IRServices

    Write-Host ""
    Write-Host "  Iniciando analise IR completa (23 modulos)..." -ForegroundColor Cyan

    # Modulos base
    $Script:_modules = @(
        "Get-TenantBaseline","Get-SuspiciousSignIns","Get-MFAStatus",
        "Get-PrivilegedAccountChanges","Get-ExchangeSuspiciousActivity",
        "Get-SuspiciousOAuthApps","Get-CriticalAuditEvents","Get-SharePointActivity",
        "Get-OutlookPersistenceMechanisms","Get-TenantDiscoveryActivity",
        "Get-TeamsSuspiciousActivity","Get-ImpactIndicators","Get-DefenseEvasionIndicators",
        "Get-ConditionalAccessGapAnalysis","Get-DefenderAlerts","Get-PrivilegedIdentityDeepDive",
        "Get-ExfiltrationCorrelation","Get-NamedLocationsAndIPAnalysis","Get-DeviceAnomalies",
        "Get-FederationAndExternalIdentityAudit","Get-EmailThreatAnalysis",
        "Get-MFAFatigueHunting","Get-ImpersonationHunting","Get-EnumerationHunting",
        "Build-AttackTimeline"
    )
    foreach ($mod in $Script:_modules) {
        Start-ModuleTimer $mod
        try {
            & $mod
        } catch {
            Write-DebugError $mod "Excecao nao tratada" $_
            if ($Script:DebugIR) {
                Write-Host "  [DBG-FATAL] $mod lancou excecao: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
        Stop-ModuleTimer $mod
    }

    # Relatorios
    New-HTMLReport
    New-JSONSummary
    New-DebugLog   # sempre gerado (tamanho zero se sem eventos)

    # Sumario
    Write-Host ""
    Write-Host "==========================================================" -ForegroundColor DarkGray
    Write-Host "  SUMARIO FINAL - O365 IR COMPLETO" -ForegroundColor White
    Write-Host "==========================================================" -ForegroundColor DarkGray
    Write-Host "  CRITICAL : $($Script:Stats.CRITICAL)" -ForegroundColor Red
    Write-Host "  HIGH     : $($Script:Stats.HIGH)" -ForegroundColor DarkYellow
    Write-Host "  MEDIUM   : $($Script:Stats.MEDIUM)" -ForegroundColor Yellow
    Write-Host "  LOW      : $($Script:Stats.LOW)" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Output   : $Script:OutputPath" -ForegroundColor Green
    Write-Host "  Duracao  : $([math]::Round(((Get-Date) - $Script:StartTime).TotalMinutes, 1)) minutos" -ForegroundColor Gray
    Write-Host "==========================================================" -ForegroundColor DarkGray

    if ($Script:Stats.CRITICAL -gt 0) {
        Write-Host ""
        Write-Host "  [!!!] $($Script:Stats.CRITICAL) CRITICAL findings requerem acao IMEDIATA!" -ForegroundColor Red
        Write-Host "  [i]   Usa Invoke-AutoContainment para contencao rapida" -ForegroundColor Yellow
    }

    Write-Host ""
    # Fechar sessoes
    Close-IRSessions

    Write-Host "  CSVs gerados:" -ForegroundColor Gray
    Get-ChildItem -Path $Script:OutputPath -File -Filter "*.csv" | Sort-Object Name | ForEach-Object {
        $size = [math]::Round($_.Length / 1KB, 1)
        Write-Host "    $($_.Name) ($size KB)" -ForegroundColor DarkGray
    }
}

# ============================================================
# ENTRY POINT
# ============================================================
Start-O365IRScriptFull
