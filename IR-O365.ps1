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

$Script:Version     = "4.1.0"
$Script:TenantName  = "Unknown"
$Script:TenantId    = "Unknown"
$Script:OutputPath  = $Script:OutputPath
$Script:StartTime   = Get-Date
$Script:Findings    = [System.Collections.Generic.List[hashtable]]::new()
$Script:DebugLog    = [System.Collections.Generic.List[hashtable]]::new()
$Script:ModuleTimes = @{}
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
  |              IR-O365  v4.1.0                                  |
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
# AUTENTICACAO - Funcoes de suporte (fora de Connect-IRServices
# para compatibilidade com PS5.1 StrictMode)
# ============================================================

$Script:GraphScopes = @(
    "AuditLog.Read.All", "Directory.Read.All", "Policy.Read.All",
    "IdentityRiskyUser.Read.All", "SecurityEvents.Read.All",
    "Application.Read.All", "RoleManagement.Read.Directory",
    "IdentityRiskEvent.Read.All", "UserAuthenticationMethod.Read.All"
)

function Get-SessionState {
    # Retorna hashtable com estado das sessoes activas
    $state = @{
        EXOConnected   = $false
        EXOAccount     = ""
        GraphConnected = $false
        GraphAccount   = ""
        GraphScopes    = @()
    }
    # EXO
    try {
        Get-OrganizationConfig -ErrorAction Stop | Out-Null
        $state.EXOConnected = $true
        try {
            $conn = Get-ConnectionInformation -ErrorAction SilentlyContinue
            if ($conn -and $conn.UserPrincipalName) {
                $state.EXOAccount = $conn.UserPrincipalName
            } else {
                $state.EXOAccount = "sessao activa"
            }
        } catch { $state.EXOAccount = "sessao activa" }
    } catch { }
    # Graph
    try {
        $ctx = Get-MgContext -ErrorAction SilentlyContinue
        if ($ctx -and $ctx.Account) {
            $state.GraphConnected = $true
            $state.GraphAccount   = $ctx.Account
            $state.GraphScopes    = @($ctx.Scopes)
        }
    } catch { }
    return $state
}

function Connect-EXO {
    # Tenta ligar ao Exchange Online com fallback progressivo
    # Retorna $true se conectado, $false caso contrario
    Write-Host "  >> A conectar ao Exchange Online..." -ForegroundColor Gray

    # Tentativa 1: OAuth interativo (PS7 / ambiente com WAM)
    try {
        Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
        Write-IRLog "Exchange Online: Conectado" -Severity "SUCCESS"
        return $true
    } catch {
        $err = $_.Exception.Message
        if ($err -notmatch "WithBroker|MissingMethodException|BrokerExtension|WAM") {
            Write-IRLog "Exchange Online: $($err.Split([char]10)[0])" -Severity "HIGH"
            return $false
        }
    }

    # Broker WAM falhou - apresentar alternativas OAuth
    Write-Host ""
    Write-Host "  O broker WAM e incompativel com .NET 4.8 + PS5.1." -ForegroundColor Yellow
    Write-Host "  Solucao permanente: instalar PS7" -ForegroundColor White
    Write-Host "  winget install --id Microsoft.PowerShell" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Metodos disponiveis:" -ForegroundColor White
    Write-Host "  [1] Device Code OAuth  (browser em microsoft.com/devicelogin)" -ForegroundColor Cyan
    Write-Host "  [2] App-Only + Cert    (App Registration no Entra, sem browser)" -ForegroundColor Cyan
    Write-Host "  [3] Access Token       (token Bearer ja obtido externamente)" -ForegroundColor Cyan
    Write-Host "  [4] Sem Exchange       (continuar apenas com modulos Graph)" -ForegroundColor Yellow
    Write-Host "  [5] Sair" -ForegroundColor Gray
    Write-Host ""

    $opt = ""
    while ($opt -notin @("1","2","3","4","5")) {
        $opt = (Read-Host "  Opcao [1-5]").Trim()
    }

    switch ($opt) {
        "1" {
            Write-Host "  A verificar suporte a Device Code neste ambiente..." -ForegroundColor Gray
            # Verificar se o parametro existe nesta versao do EXO
            $hasDeviceParam = $null -ne (Get-Command Connect-ExchangeOnline -ErrorAction SilentlyContinue |
                Select-Object -ExpandProperty Parameters -ErrorAction SilentlyContinue |
                Where-Object { $_.Keys -contains "UseDeviceAuthentication" })

            if (-not $hasDeviceParam) {
                Write-IRLog "EXO v$((Get-Module ExchangeOnlineManagement).Version) nao suporta -UseDeviceAuthentication" -Severity "HIGH"
                Write-Host ""
                Write-Host "  Este metodo requer EXO v3.2.0+." -ForegroundColor Red
                Write-Host "  A tua versao: $((Get-Module ExchangeOnlineManagement).Version)" -ForegroundColor Red
                Write-Host "  Update-Module ExchangeOnlineManagement -Force" -ForegroundColor Yellow
                Write-Host "  OU instala PS7 para resolver definitivamente." -ForegroundColor Green
                return $false
            }

            Write-Host "  A aguardar autenticacao Device Code..." -ForegroundColor Gray
            Write-Host "  Vai a: https://microsoft.com/devicelogin" -ForegroundColor Cyan
            try {
                Connect-ExchangeOnline -ShowBanner:$false -UseDeviceAuthentication -ErrorAction Stop
                Write-IRLog "Exchange Online: Conectado via Device Code" -Severity "SUCCESS"
                return $true
            } catch {
                $devErr = $_.Exception.Message
                Write-IRLog "Device Code falhou: $($devErr.Split([char]10)[0])" -Severity "HIGH"
                Write-Host "  Falhou. Tenta opcao [2] ou instala PS7." -ForegroundColor Red
                return $false
            }
        }
        "2" {
            Write-Host "  Necessario: App Registration + Exchange.ManageAsApp + cert instalado" -ForegroundColor Gray
            Write-Host "  Guia: https://aka.ms/exo-app-only-auth" -ForegroundColor DarkGray
            Write-Host ""
            $appId = (Read-Host "  App (Client) ID").Trim()
            $org   = (Read-Host "  Organization (ex: contoso.onmicrosoft.com)").Trim()
            $thumb = (Read-Host "  Certificate Thumbprint").Trim()
            if (-not ($appId -and $org -and $thumb)) {
                Write-Host "  Parametros incompletos." -ForegroundColor Red
                return $false
            }
            try {
                Connect-ExchangeOnline -AppId $appId -Organization $org `
                    -CertificateThumbprint $thumb -ShowBanner:$false -ErrorAction Stop
                Write-IRLog "Exchange Online: Conectado via App-Only OAuth" -Severity "SUCCESS"
                return $true
            } catch {
                Write-IRLog "App-Only falhou: $($_.Exception.Message.Split([char]10)[0])" -Severity "HIGH"
                return $false
            }
        }
        "3" {
            Write-Host "  Scope necessario: https://outlook.office365.com/.default" -ForegroundColor Gray
            Write-Host "  Obter token: Get-MsalToken (modulo MSAL.PS) ou az account get-access-token" -ForegroundColor DarkGray
            Write-Host ""
            $token = (Read-Host "  Access Token Bearer").Trim()
            if ($token.Length -lt 100) {
                Write-Host "  Token invalido ou vazio." -ForegroundColor Red
                return $false
            }
            try {
                Connect-ExchangeOnline -AccessToken $token -ShowBanner:$false -ErrorAction Stop
                Write-IRLog "Exchange Online: Conectado via Access Token" -Severity "SUCCESS"
                return $true
            } catch {
                Write-IRLog "Access Token falhou: $($_.Exception.Message.Split([char]10)[0])" -Severity "HIGH"
                return $false
            }
        }
        "4" {
            Write-IRLog "Exchange: ignorado pelo utilizador" -Severity "INFO"
            return $false
        }
        "5" {
            Write-Host "  A sair." -ForegroundColor Gray
            exit 0
        }
    }
    return $false
}

function Connect-Graph {
    # Tenta ligar ao Microsoft Graph com fallback para Device Code
    # Retorna $true se conectado, $false caso contrario
    Write-Host "  >> A conectar ao Microsoft Graph..." -ForegroundColor Gray

    # Tentativa 1: autenticacao interativa normal
    try {
        Connect-MgGraph -Scopes $Script:GraphScopes -ErrorAction Stop -NoWelcome
        $ctx = Get-MgContext -ErrorAction SilentlyContinue
        Write-IRLog "Microsoft Graph: Conectado como $($ctx.Account)" -Severity "SUCCESS"
        return $true
    } catch {
        $err = $_.Exception.Message
        Write-IRLog "Graph auth interativo falhou: $($err.Split([char]10)[0])" -Severity "INFO"
    }

    # Tentativa 2: Device Code
    Write-Host "  Autenticacao interativa falhou - a tentar Device Code..." -ForegroundColor Gray
    Write-Host "  Vai a: https://microsoft.com/devicelogin" -ForegroundColor Cyan
    try {
        Connect-MgGraph -Scopes $Script:GraphScopes -UseDeviceAuthentication -ErrorAction Stop -NoWelcome
        $ctx = Get-MgContext -ErrorAction SilentlyContinue
        Write-IRLog "Microsoft Graph: Conectado via Device Code como $($ctx.Account)" -Severity "SUCCESS"
        return $true
    } catch {
        Write-IRLog "Graph Device Code falhou: $($_.Exception.Message.Split([char]10)[0])" -Severity "HIGH"
    }

    # Ambas falharam
    Write-Host ""
    Write-Host "  Nao foi possivel conectar ao Graph." -ForegroundColor Red
    Write-Host "  [1] Tentar novamente" -ForegroundColor Cyan
    Write-Host "  [2] Continuar sem Graph (apenas Exchange/UAL)" -ForegroundColor Yellow
    Write-Host "  [3] Sair" -ForegroundColor Gray
    $opt = ""
    while ($opt -notin @("1","2","3")) { $opt = (Read-Host "  Opcao [1-3]").Trim() }
    switch ($opt) {
        "1"  { return Connect-Graph }
        "2"  { $Script:SkipGraph = $true; return $false }
        "3"  { exit 0 }
    }
    return $false
}

function Connect-IRServices {
    Write-Section "CONECTAR A SERVICOS O365"

    # ---- Detectar sessoes activas ----
    Write-Host "  >> A verificar sessoes activas..." -ForegroundColor Gray
    $state = Get-SessionState

    # ---- Apresentar estado ----
    Write-Host ""
    if ($state.EXOConnected) {
        Write-Host "  [EXO]   Conectado  : $($state.EXOAccount)" -ForegroundColor Green
    } else {
        Write-Host "  [EXO]   Sem sessao activa" -ForegroundColor DarkGray
    }
    if ($state.GraphConnected) {
        Write-Host "  [Graph] Conectado  : $($state.GraphAccount) ($($state.GraphScopes.Count) scopes)" -ForegroundColor Green
    } else {
        Write-Host "  [Graph] Sem sessao activa" -ForegroundColor DarkGray
    }

    # ---- Menu dinamico ----
    Write-Host ""
    Write-Host "  Opcoes:" -ForegroundColor White

    # Construir opcoes como array simples de strings para evitar hashtable + StrictMode
    $menuLabels  = [System.Collections.Generic.List[string]]::new()
    $menuActions = [System.Collections.Generic.List[string]]::new()

    if ($state.EXOConnected -and $state.GraphConnected) {
        $menuLabels.Add("Usar sessoes activas: EXO ($($state.EXOAccount)) + Graph ($($state.GraphAccount))")
        $menuActions.Add("USE_BOTH")
    }
    if ($state.EXOConnected -and -not $state.GraphConnected) {
        $menuLabels.Add("Usar EXO activo + autenticar Graph")
        $menuActions.Add("USE_EXO_AUTH_GRAPH")
        $menuLabels.Add("Usar apenas EXO (sem Graph)")
        $menuActions.Add("USE_EXO_ONLY")
    }
    if ($state.GraphConnected -and -not $state.EXOConnected) {
        $menuLabels.Add("Usar Graph activo + autenticar EXO")
        $menuActions.Add("USE_GRAPH_AUTH_EXO")
        $menuLabels.Add("Usar apenas Graph (sem Exchange)")
        $menuActions.Add("USE_GRAPH_ONLY")
    }
    $menuLabels.Add("Nova autenticacao EXO + Graph")
    $menuActions.Add("AUTH_BOTH")
    $menuLabels.Add("Autenticar apenas Graph (sem Exchange)")
    $menuActions.Add("AUTH_GRAPH_ONLY")
    $menuLabels.Add("Sair")
    $menuActions.Add("EXIT")

    for ($i = 0; $i -lt $menuLabels.Count; $i++) {
        $label  = $menuLabels[$i]
        $action = $menuActions[$i]
        $color  = switch -Wildcard ($action) {
            "USE_BOTH"  { "Green"  }
            "EXIT"      { "Gray"   }
            "USE_*ONLY" { "Yellow" }
            default     { "Cyan"   }
        }
        Write-Host "  [$($i+1)] $label" -ForegroundColor $color
    }
    Write-Host ""

    $max = $menuLabels.Count
    $choice = ""
    while ($choice -notmatch "^\d+$" -or [int]$choice -lt 1 -or [int]$choice -gt $max) {
        $choice = (Read-Host "  Opcao [1-$max]").Trim()
    }
    $action = $menuActions[[int]$choice - 1]

    # ---- Executar accao ----
    switch ($action) {
        "USE_BOTH" {
            Write-IRLog "EXO: a usar sessao activa ($($state.EXOAccount))" -Severity "SUCCESS"
            Write-IRLog "Graph: a usar sessao activa ($($state.GraphAccount))" -Severity "SUCCESS"
            # Verificar scopes Graph
            $needed  = @("AuditLog.Read.All","Directory.Read.All","Application.Read.All")
            $missing = @($needed | Where-Object { $_ -notin $state.GraphScopes })
            if ($missing.Count -gt 0) {
                Write-IRLog "Graph: scopes em falta ($($missing -join ', ')) - alguns modulos podem falhar" -Severity "MEDIUM"
            }
        }
        "USE_EXO_AUTH_GRAPH" {
            Write-IRLog "EXO: a usar sessao activa ($($state.EXOAccount))" -Severity "SUCCESS"
            if (-not (Connect-Graph)) { $Script:SkipGraph = $true }
        }
        "USE_EXO_ONLY" {
            Write-IRLog "EXO: a usar sessao activa ($($state.EXOAccount))" -Severity "SUCCESS"
            $Script:SkipGraph = $true
            Write-IRLog "Graph: ignorado (opcao do utilizador)" -Severity "INFO"
        }
        "USE_GRAPH_AUTH_EXO" {
            Write-IRLog "Graph: a usar sessao activa ($($state.GraphAccount))" -Severity "SUCCESS"
            if (-not (Connect-EXO)) {
                $Script:SkipExchange = $true
                $Script:SkipUAL      = $true
            }
        }
        "USE_GRAPH_ONLY" {
            Write-IRLog "Graph: a usar sessao activa ($($state.GraphAccount))" -Severity "SUCCESS"
            $Script:SkipExchange = $true
            $Script:SkipUAL      = $true
            Write-IRLog "Exchange: ignorado (opcao do utilizador)" -Severity "INFO"
        }
        "AUTH_BOTH" {
            if (-not (Connect-EXO)) {
                $Script:SkipExchange = $true
                $Script:SkipUAL      = $true
            }
            if (-not (Connect-Graph)) {
                $Script:SkipGraph = $true
            }
        }
        "AUTH_GRAPH_ONLY" {
            $Script:SkipExchange = $true
            $Script:SkipUAL      = $true
            if (-not (Connect-Graph)) {
                $Script:SkipGraph = $true
            }
        }
        "EXIT" {
            Write-Host "  A sair." -ForegroundColor Gray
            exit 0
        }
    }
}

# ============================================================
# MODULO 1: BASELINE DO TENANT
# ============================================================

function Get-TenantBaseline {
    Write-Section "TENANT BASELINE" "T1538" "Discovery"
    
    try {
        $org = Get-MgOrganization -ErrorAction Stop
        $tenantInfo = [PSCustomObject]@{
            TenantId         = $org.Id
            DisplayName      = $org.DisplayName
            Domains          = ($org.VerifiedDomains | ForEach-Object { $_.Name }) -join ", "
            CreatedDate      = $org.CreatedDateTime
        }
                # Display name completo com acentos (para HTML report e logs)
        $Script:TenantName = $org.DisplayName.Trim()
        $Script:TenantId   = $org.Id
        Write-IRLog "Tenant: $($Script:TenantName) | ID: $($Script:TenantId)" -Severity "INFO"

        # Renomear pasta de output para incluir nome do tenant (dentro de reports\)
        if ($Script:TenantName) {
            # Transliteracao para ASCII seguro no nome da pasta
            $safeName = $Script:TenantName `
                -replace '[\xE0-\xE5]','a' -replace '[\xE8-\xEB]','e' -replace '[\xEC-\xEF]','i' `
                -replace '[\xF2-\xF6]','o' -replace '[\xF9-\xFC]','u' -replace '\xE7','c'          `
                -replace '[\xC0-\xC5]','A' -replace '[\xC8-\xCB]','E' -replace '[\xCC-\xCF]','I' `
                -replace '[\xD2-\xD6]','O' -replace '[\xD9-\xDC]','U' -replace '\xC7','C'          `
                -replace '\s+','-'           -replace '[^a-zA-Z0-9\-\.]','' -replace '-{2,}','-'
            $safeName   = $safeName.Trim('-').Trim('.')
            $reportRoot = Split-Path $Script:OutputPath -Parent
            $newFolder  = "IR-O365-$safeName-$(Get-Date -Format 'yyyyMMdd_HHmmss')"
            $newPath    = Join-Path $reportRoot $newFolder
            if (-not (Test-Path $newPath)) {
                $Script:OutputPath = $newPath
                $OutputPath        = $newPath
                New-OutputDirectory
            }
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
        Write-Host "  >> Verificando admins sem MFA..." -ForegroundColor Gray
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
                # FIX: DirectoryRoleId lookup falha se role nao foi activada no tenant
                # Tentar por template ID primeiro, fallback para listar todas as roles
                $roleMembers = @()
                try {
                    $roleMembers = @(Get-MgDirectoryRoleMember -DirectoryRoleId $roleId -ErrorAction Stop)
                } catch {
                    # Role pode nao existir se nunca foi activada - tentar via roleTemplateId
                    try {
                        $activeRole = Get-MgDirectoryRole -Filter "roleTemplateId eq '$roleId'" -ErrorAction SilentlyContinue
                        if ($activeRole) {
                            $roleMembers = @(Get-MgDirectoryRoleMember -DirectoryRoleId $activeRole.Id -ErrorAction SilentlyContinue)
                        }
                    } catch {
                        Write-DebugError "PrivilegedIdentity" "Role lookup falhou para $roleId" $_
                    }
                }
                # FIX: garantir array mesmo quando Get-MgDirectoryRoleMember retorna objeto unico
                if ($null -eq $roleMembers) { $roleMembers = @() }
                $roleMembers = @($roleMembers)
                foreach ($member in $roleMembers) {
                    if ($member.AdditionalProperties["@odata.type"] -eq "#microsoft.graph.user") {
                        $authMethods = @(Get-MgUserAuthenticationMethod -UserId $member.Id -ErrorAction SilentlyContinue)
                        $hasMFA = $authMethods | Where-Object {
                            $_.AdditionalProperties["@odata.type"] -in @(
                                "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod",
                                "#microsoft.graph.phoneAuthenticationMethod",
                                "#microsoft.graph.fido2AuthenticationMethod",
                                "#microsoft.graph.windowsHelloForBusinessAuthenticationMethod"
                            )
                        }
                        
                        $record = [PSCustomObject]@{
                            UserId         = $member.Id
                            UPN            = $member.AdditionalProperties["userPrincipalName"]
                            RoleId         = $roleId
                            MFAConfigured  = if ($hasMFA) { $true } else { $false }
                            MethodCount    = $authMethods.Count
                        }
                        $adminsMFAResults.Add($record)
                        
                        if (-not $hasMFA) {
                            Write-IRLog "ADMIN SEM MFA: $($member.AdditionalProperties['userPrincipalName']) [T1556.006]" `
                                -Severity "CRITICAL" -MITRETechnique "T1556.006" -MITRETactic "Defense Evasion" -Data $record
                        }
                    }
                }
            } catch { <# Role pode nao existir #> }
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
                    if (-not $audit) { continue }
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
        $transportRules = Get-TransportRule -ErrorAction SilentlyContinue
        $suspiciousTransport = $transportRules | Where-Object {
            $_.BlindCopyTo -or
            $_.RedirectMessageTo -or
            $_.CopyTo
        }
        
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
        $sendAsPerms = Get-RecipientPermission -ResultSize Unlimited -ErrorAction SilentlyContinue |
            Where-Object { $_.Trustee -notmatch "NT AUTHORITY|SELF" }
        
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
    # T1550.001 - Application Access Token | T1671 - Cloud App Integration | T1528 - Steal App Access Token
    Write-Section "OAUTH APPS & SERVICE PRINCIPALS" "T1550.001/T1528/T1671" "Persistence / Credential Access"
    
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
            Write-IRLog "Service Principals criados recentemente: $($recentSPs.Count) [T1671]" `
                -Severity "MEDIUM" -MITRETechnique "T1671" -MITRETactic "Persistence"
            Export-IRData -FileName "05_recent_service_principals" -Data ($recentSPs | Select-Object DisplayName, AppId, CreatedDateTime, ServicePrincipalType, AppOwnerOrganizationId)
        }
        
        # Credenciais adicionadas a apps existentes
        Write-Host "  >> Verificando credenciais em applications..." -ForegroundColor Gray
        $apps = @(Get-MgApplication -Property "Id,DisplayName,AppId,CreatedDateTime,KeyCredentials,PasswordCredentials" `
            -All -ErrorAction SilentlyContinue)
        
        $appsWithRecentCreds = [System.Collections.Generic.List[PSObject]]::new()
        foreach ($app in $apps) {
            $recentKeys = $app.KeyCredentials | Where-Object { $_.StartDateTime -ge $Script:StartDate }
            $recentPwds = $app.PasswordCredentials | Where-Object { $_.StartDateTime -ge $Script:StartDate }
            
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
        $sps = @(Get-MgServicePrincipal -All -Property "Id,DisplayName" -ErrorAction SilentlyContinue)
        
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
    # T1562.008 - Disable Cloud Logs | T1070.008 - Clear Mailbox | T1137 - Office App Startup
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
        @{ Ops = @("New-ApplicationAccessPolicy","Remove-ApplicationAccessPolicy");       Label = "App_Access_Policy";          MITRE = "T1671";     Sev = "HIGH" },
        @{ Ops = @("Add-MailboxPermission","Remove-MailboxPermission");                   Label = "Mailbox_Permission_Changes"; MITRE = "T1098.002"; Sev = "HIGH" },
        @{ Ops = @("Set-Mailbox");                                                        Label = "Mailbox_Config_Changes";     MITRE = "T1114.003"; Sev = "MEDIUM" },
        @{ Ops = @("New-TransportRule","Set-TransportRule","Remove-TransportRule");       Label = "Transport_Rule_Changes";     MITRE = "T1114.003"; Sev = "HIGH" },
        @{ Ops = @("Add-RoleGroupMember","New-RoleGroup");                               Label = "Exchange_Role_Changes";      MITRE = "T1098.003"; Sev = "HIGH" },
        @{ Ops = @("New-InboxRule","Set-InboxRule","Remove-InboxRule");                   Label = "Inbox_Rule_Operations";      MITRE = "T1564.008"; Sev = "HIGH" },
        @{ Ops = @("HardDelete","SoftDelete");                                            Label = "Email_Hard_Deletions";       MITRE = "T1070.008"; Sev = "HIGH" },
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
            Write-IRLog "Partilhas Anonimas criadas: $($anonShare.Count) [T1567.004]" `
                -Severity "HIGH" -MITRETechnique "T1567.004" -MITRETactic "Exfiltration"
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
            Write-IRLog "Webhooks/Flows criados: $($webhookEvents.Count) [T1567.004 - Exfiltration over Webhook]" `
                -Severity "HIGH" -MITRETechnique "T1567.004" -MITRETactic "Exfiltration"
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
    # T1531 - Account Access Removal | T1657 - Financial Theft | T1667 - Email Bombing
    Write-Section "INDICADORES DE IMPACTO" "T1531/T1657/T1667" "Impact"
    
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
                Write-IRLog "Possivel Email Bombing/BEC: $($hs.User) >> $($hs.EmailsSent) emails enviados [T1667]" `
                    -Severity "HIGH" -MITRETechnique "T1667" -MITRETactic "Impact" -Data $hs
            }
        }
        
    } catch { Write-IRLog "Erro Impact module: $_" -Severity "INFO" }
}

# ============================================================
# MODULO 13: DEFENSE EVASION CHECKS
# ============================================================

function Get-DefenseEvasionIndicators {
    # T1562.008 - Disable Cloud Logs | T1070.008 - Clear Mailbox | T1606 - SAML Tokens
    Write-Section "DEFENSE EVASION" "T1562.008/T1070.008/T1550/T1606" "Defense Evasion"
    
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
                Write-IRLog "Bulk Delete/Purge: $($bd.User) >> $($bd.DeletedItems) items eliminados [T1070.008]" `
                    -Severity "HIGH" -MITRETechnique "T1070.008" -MITRETactic "Defense Evasion" -Data $bd
            }
        }
        
        # Email Spoofing indicators (DKIM/SPF bypass)
        if (-not $Script:SkipExchange) {
            Write-Host "  >> Verificando DKIM/DMARC/SPF config..." -ForegroundColor Gray
            try {
                $dkimConfig = Get-DkimSigningConfig -ErrorAction SilentlyContinue
                $dkimDisabled = @($dkimConfig | Where-Object { $_.Enabled -eq $false })
                if ($dkimDisabled.Count -gt 0) {
                    Write-IRLog "DKIM desativado para dominios: $($dkimDisabled.Domain -join ', ') [T1672 - Email Spoofing]" `
                        -Severity "MEDIUM" -MITRETechnique "T1672" -MITRETactic "Defense Evasion"
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

    # Helper: encode HTML e truncar strings longas
    function ConvertTo-SafeHtml ([string]$str, [int]$maxLen = 200) {
        if (-not $str) { return "" }
        $s = if ($str.Length -gt $maxLen) { $str.Substring(0, $maxLen) + "..." } else { $str }
        return [System.Web.HttpUtility]::HtmlEncode($s)
    }

    # Helper: converter $Data (hashtable/PSCustomObject) em tabela HTML de evidencias
    function ConvertTo-EvidenceHtml ($data) {
        if ($null -eq $data) { return "" }
        $rows = ""
        try {
            $props = if ($data -is [hashtable]) {
                $data.GetEnumerator() | Sort-Object Key
            } elseif ($data -is [PSCustomObject]) {
                $data.PSObject.Properties | Sort-Object Name
            } else {
                # Escalar simples
                return "<div class='ev-scalar'>$(ConvertTo-SafeHtml $data.ToString())</div>"
            }
            foreach ($p in $props) {
                $key = ConvertTo-SafeHtml $p.Name
                $val = ConvertTo-SafeHtml ($p.Value | Out-String).Trim()
                if ($val -and $val -ne "") {
                    $rows += "<tr><td class='ev-key'>$key</td><td class='ev-val'>$val</td></tr>"
                }
            }
        } catch { }
        if ($rows) { return "<table class='ev-table'>$rows</table>" }
        return ""
    }

    # Construir linhas de findings com evidencias inline
    $findingRows = foreach ($f in $Script:Findings) {
        $color = switch ($f.Severity) {
            "CRITICAL" { "#ff4444" }
            "HIGH"     { "#ff8c00" }
            "MEDIUM"   { "#ffc107" }
            "LOW"      { "#17a2b8" }
            default    { "#6c757d" }
        }
        $rowId        = "r$([guid]::NewGuid().ToString('N').Substring(0,8))"
        $escapedMsg   = ConvertTo-SafeHtml $f.Message
        $mitreLink    = if ($f.Technique) {
            $techBase = $f.Technique.Split('/')[0]
            "<a class='mitre-link' href='https://attack.mitre.org/techniques/$techBase' target='_blank'><code>$($f.Technique)</code></a>"
        } else { "" }

        # Evidencias estruturadas
        $evHtml = ConvertTo-EvidenceHtml $f.Data
        $hasEvidence = $evHtml -ne ""

        # CSV link - tentar inferir qual CSV corresponde
        $csvLink = ""
        if ($f.Technique) {
            $csvFiles = @(Get-ChildItem -Path $Script:OutputPath -Filter "*.csv" -ErrorAction SilentlyContinue)
            # Mapear tecnica para prefixo de ficheiro
            $csvPrefix = switch -Wildcard ($f.Technique) {
                "T1114*"  { "04_" }
                "T1110*"  { "01_brute" }
                "T1078*"  { "01_" }
                "T1550*"  { "05_risky_oauth" }
                "T1528*"  { "05_apps" }
                "T1098*"  { "04_mailbox" }
                "T1136*"  { "03_new" }
                "T1562*"  { "06_ual_audit" }
                "T1070*"  { "06_ual_email" }
                "T1530*"  { "07_" }
                "T1213*"  { "07_" }
                default   { "" }
            }
            if ($csvPrefix) {
                $match = $csvFiles | Where-Object { $_.Name.StartsWith($csvPrefix) } | Select-Object -First 1
                if ($match) {
                    $csvLink = "<a class='csv-link' href='$($match.Name)' title='Abrir evidencias CSV'>[CSV] $($match.Name)</a>"
                }
            }
        }

        $expandBtn = if ($hasEvidence) {
            "<button class='expand-btn' onclick='toggleEvidence(`"$rowId`")'>+ evidencias</button>"
        } else { "" }

        @"
        <tr class='finding-row sev-$($f.Severity.ToLower())'>
            <td><span class='badge' style='background:$color'>$($f.Severity)</span></td>
            <td class='ts-col'>$($f.Timestamp)</td>
            <td class='msg-col'>
                $escapedMsg
                <div class='finding-actions'>$expandBtn $csvLink</div>
            </td>
            <td>$mitreLink</td>
            <td class='tactic-col'>$($f.Tactic)</td>
        </tr>
        $(if ($hasEvidence) {
"        <tr id='$rowId' class='evidence-row' style='display:none'>
            <td colspan='5' class='evidence-cell'>
                <div class='evidence-header'>Evidencias recolhidas</div>
                $evHtml
            </td>
        </tr>"
        })
"@
    }
    $findingsHTML = $findingRows -join ""

    # Secao de threat summary por utilizador (pivot dos findings)
    $userThreats = @{}
    foreach ($f in $Script:Findings) {
        if ($f.Severity -in @("CRITICAL","HIGH")) {
            $upnMatches = [regex]::Matches($f.Message, '[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')
            foreach ($m in $upnMatches) {
                $upn = $m.Value
                if (-not $userThreats.ContainsKey($upn)) { $userThreats[$upn] = @() }
                $userThreats[$upn] += $f
            }
        }
    }

    $threatRows = ""
    foreach ($upn in ($userThreats.Keys | Sort-Object)) {
        $findings  = $userThreats[$upn]
        $critC     = ($findings | Where-Object { $_.Severity -eq "CRITICAL" }).Count
        $highC     = ($findings | Where-Object { $_.Severity -eq "HIGH" }).Count
        $tactics   = ($findings.Tactic | Sort-Object -Unique) -join ", "
        $techniques= ($findings.Technique | Where-Object { $_ } | Sort-Object -Unique) -join " "
        $riskScore = ($critC * 10) + ($highC * 5)
        $riskColor = if ($critC -gt 0) { "#ff4444" } elseif ($highC -gt 2) { "#ff8c00" } else { "#ffc107" }
        $threatRows += @"
        <tr>
            <td><code style='color:#c9d1d9'>$([System.Web.HttpUtility]::HtmlEncode($upn))</code></td>
            <td style='color:#ff4444;font-weight:700'>$critC</td>
            <td style='color:#ff8c00;font-weight:700'>$highC</td>
            <td><span style='background:$riskColor;color:#fff;padding:.2rem .5rem;border-radius:4px;font-size:.75rem'>$riskScore</span></td>
            <td style='font-size:.8rem;color:#8b949e'>$([System.Web.HttpUtility]::HtmlEncode($tactics))</td>
            <td style='font-size:.75rem'>$([System.Web.HttpUtility]::HtmlEncode($techniques))</td>
        </tr>
"@
    }

    $threatSummarySection = if ($threatRows) { @"
<h2 style='margin:2rem 0 .5rem'>Utilizadores em Risco ($($userThreats.Count))</h2>
<p style='color:#8b949e;font-size:.85rem;margin-bottom:1rem'>Utilizadores com findings CRITICAL ou HIGH - ordenados por UPN</p>
<table>
  <thead>
    <tr>
      <th>Utilizador</th>
      <th>CRITICAL</th>
      <th>HIGH</th>
      <th>Risk Score</th>
      <th>Taticas</th>
      <th>Tecnicas</th>
    </tr>
  </thead>
  <tbody>$threatRows</tbody>
</table>
"@ } else { "" }

    # Secao de modulos executados (status de cada um)
    $moduleStatus = @(
        @{ Name = "Tenant Baseline";          CSV = "00_tenant_baseline.csv" },
        @{ Name = "Sign-in Analysis";         CSV = "01_brute_force_by_ip.csv" },
        @{ Name = "MFA / Conditional Access"; CSV = "02_admin_mfa_status.csv" },
        @{ Name = "Privileged Accounts";      CSV = "03_role_changes.csv" },
        @{ Name = "Exchange Rules";           CSV = "04_suspicious_inbox_rules.csv" },
        @{ Name = "Mailbox Forwarding";       CSV = "04_mailbox_forwarding.csv" },
        @{ Name = "OAuth / Service Principals";CSV = "05_risky_oauth_grants.csv" },
        @{ Name = "Unified Audit Log";        CSV = "06_ual_audit_config_changes.csv" },
        @{ Name = "SharePoint / OneDrive";    CSV = "07_anonymous_shares.csv" },
        @{ Name = "Outlook Persistence";      CSV = "08_outlook_homepage.csv" },
        @{ Name = "Defender Alerts";          CSV = "15_defender_alerts.csv" },
        @{ Name = "Attack Timeline";          CSV = "21_attack_timeline.csv" }
    )

    $moduleRows = foreach ($mod in $moduleStatus) {
        $csvPath = Join-Path $Script:OutputPath $mod.CSV
        $exists  = Test-Path $csvPath
        $lines   = if ($exists) { @(Get-Content $csvPath -ErrorAction SilentlyContinue).Count - 1 } else { -1 }
        $status  = if (-not $exists)   { "<span style='color:#8b949e'>Nao executado</span>" }
                   elseif ($lines -le 0){ "<span style='color:#ffc107'>Executado - 0 resultados</span>" }
                   else                 { "<span style='color:#3fb950'>$lines registos</span>" }
        $link    = if ($exists -and $lines -gt 0) { "<a class='csv-link' href='$($mod.CSV)'>[CSV] $($mod.CSV)</a>" } else { "" }
        "<tr><td>$($mod.Name)</td><td>$status</td><td>$link</td></tr>"
    }
    $moduleStatusHTML = $moduleRows -join ""

    $html = @"
<!DOCTYPE html>
<html lang="pt">
<head>
<meta charset="UTF-8">
<title>IR-O365 | $([System.Web.HttpUtility]::HtmlEncode($Script:TenantName)) | $(Get-Date -Format 'yyyy-MM-dd')</title>
<style>
  :root { --bg:#0d1117; --surface:#161b22; --border:#30363d; --text:#c9d1d9; --accent:#58a6ff; }
  *  { margin:0; padding:0; box-sizing:border-box; }
  body { background:var(--bg); color:var(--text); font-family:'Segoe UI',monospace; padding:2rem; max-width:1400px; margin:0 auto; }
  h1  { color:var(--accent); font-size:1.8rem; margin-bottom:.4rem; }
  h2  { color:var(--accent); font-size:1.15rem; }
  .subtitle  { color:#8b949e; margin-bottom:.5rem; font-size:.85rem; }
  .tenant-badge { display:inline-block; background:#21262d; border:1px solid #30363d; border-radius:6px;
                  padding:.3rem .8rem; font-size:.8rem; color:#8b949e; margin-bottom:1.5rem; font-family:monospace; }
  /* Stats */
  .stats { display:grid; grid-template-columns:repeat(4,1fr); gap:1rem; margin-bottom:2rem; }
  .stat-card { background:var(--surface); border:1px solid var(--border); border-radius:8px; padding:1.2rem; text-align:center; }
  .stat-card .num { font-size:2.5rem; font-weight:700; }
  .stat-card .label { font-size:.8rem; color:#8b949e; margin-top:.3rem; }
  .critical .num { color:#ff4444; } .high .num { color:#ff8c00; }
  .medium .num   { color:#ffc107; } .low .num  { color:#17a2b8; }
  /* Meta cards */
  .meta { display:grid; grid-template-columns:1fr 1fr; gap:1rem; margin-bottom:2rem; }
  .meta-card { background:var(--surface); border:1px solid var(--border); border-radius:8px; padding:1rem; }
  .meta-card h3 { font-size:.9rem; color:var(--accent); margin-bottom:.5rem; }
  .meta-card p  { font-size:.82rem; color:#8b949e; line-height:1.8; }
  /* Tables */
  table { width:100%; border-collapse:collapse; background:var(--surface); border-radius:8px; overflow:hidden; margin-top:.5rem; }
  thead { background:#21262d; }
  th  { padding:.75rem 1rem; text-align:left; font-size:.82rem; color:#8b949e; border-bottom:1px solid var(--border); }
  td  { padding:.65rem 1rem; font-size:.83rem; border-bottom:1px solid #21262d; vertical-align:top; }
  tr.finding-row:hover > td { background:#1c2128; }
  /* Severity row accent */
  tr.sev-critical td:first-child { border-left:3px solid #ff4444; }
  tr.sev-high     td:first-child { border-left:3px solid #ff8c00; }
  tr.sev-medium   td:first-child { border-left:3px solid #ffc107; }
  tr.sev-low      td:first-child { border-left:3px solid #17a2b8; }
  /* Badge */
  .badge { padding:.2rem .55rem; border-radius:4px; font-size:.73rem; font-weight:600; color:#fff; white-space:nowrap; }
  code { background:#21262d; padding:.1rem .4rem; border-radius:3px; font-size:.78rem; color:#79c0ff; }
  /* Column widths */
  .ts-col     { white-space:nowrap; color:#8b949e; font-size:.78rem; width:130px; }
  .msg-col    { max-width:500px; }
  .tactic-col { white-space:nowrap; font-size:.78rem; color:#8b949e; }
  /* Finding actions */
  .finding-actions { margin-top:.4rem; display:flex; gap:.6rem; flex-wrap:wrap; }
  /* Expand button */
  .expand-btn { background:none; border:1px solid #30363d; color:#58a6ff; border-radius:4px;
                padding:.15rem .5rem; font-size:.73rem; cursor:pointer; font-family:inherit; }
  .expand-btn:hover { background:#21262d; }
  /* Evidence row */
  .evidence-row td { background:#0d1117; padding:0; }
  .evidence-cell { padding:.8rem 1rem 1rem 2rem !important; }
  .evidence-header { font-size:.75rem; color:#8b949e; text-transform:uppercase; letter-spacing:.05em;
                     margin-bottom:.5rem; border-bottom:1px solid #21262d; padding-bottom:.3rem; }
  /* Evidence table */
  .ev-table { width:auto; min-width:400px; max-width:900px; border-radius:6px; font-size:.8rem; margin:0; }
  .ev-table tr:last-child td { border-bottom:none; }
  .ev-key { color:#8b949e; width:180px; padding:.35rem .7rem; white-space:nowrap; }
  .ev-val { color:#c9d1d9; padding:.35rem .7rem; word-break:break-all; font-family:monospace; }
  .ev-scalar { color:#c9d1d9; font-family:monospace; font-size:.8rem; }
  /* CSV link */
  .csv-link { color:#3fb950; font-size:.75rem; text-decoration:none; }
  .csv-link:hover { text-decoration:underline; }
  /* MITRE link */
  .mitre-link { color:#79c0ff; text-decoration:none; font-size:.78rem; }
  .mitre-link:hover { text-decoration:underline; }
  /* Filter bar */
  .filter-bar { display:flex; gap:.5rem; margin-bottom:.75rem; flex-wrap:wrap; align-items:center; }
  .filter-btn { background:#21262d; border:1px solid #30363d; color:#c9d1d9; border-radius:6px;
                padding:.3rem .8rem; font-size:.8rem; cursor:pointer; font-family:inherit; }
  .filter-btn.active { border-color:#58a6ff; color:#58a6ff; }
  .filter-btn:hover { background:#2d333b; }
  .search-box { background:#21262d; border:1px solid #30363d; color:#c9d1d9; border-radius:6px;
                padding:.3rem .7rem; font-size:.8rem; font-family:inherit; width:240px; }
  .search-box:focus { outline:none; border-color:#58a6ff; }
  /* Footer */
  .footer { margin-top:1.5rem; font-size:.75rem; color:#8b949e; }
  /* Section divider */
  .section-divider { border:none; border-top:1px solid #21262d; margin:2rem 0; }
</style>
</head>
<body>

<h1>IR-O365 &mdash; Incident Response Report</h1>
<p class="tenant-badge">$([System.Web.HttpUtility]::HtmlEncode($Script:TenantName)) &nbsp;&nbsp;|&nbsp;&nbsp; $([System.Web.HttpUtility]::HtmlEncode($Script:TenantId))</p>
<p class="subtitle">MITRE ATT&amp;CK Enterprise v18 &nbsp;|&nbsp; Gerado: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') &nbsp;|&nbsp; Periodo: $($Script:StartDate.ToString('yyyy-MM-dd')) &rarr; $($Script:EndDate.ToString('yyyy-MM-dd')) &nbsp;|&nbsp; IR-O365 v$($Script:Version)</p>

<div class="stats">
  <div class="stat-card critical"><div class="num">$critCount</div><div class="label">CRITICAL</div></div>
  <div class="stat-card high"><div class="num">$highCount</div><div class="label">HIGH</div></div>
  <div class="stat-card medium"><div class="num">$medCount</div><div class="label">MEDIUM</div></div>
  <div class="stat-card low"><div class="num">$lowCount</div><div class="label">LOW</div></div>
</div>

$threatSummarySection

<hr class="section-divider">

<h2 style="margin-bottom:.75rem">Findings ($totalFindings total)</h2>

<div class="filter-bar">
  <button class="filter-btn active" onclick="filterSev('ALL')">Todos</button>
  <button class="filter-btn" onclick="filterSev('CRITICAL')" style="border-color:#ff444444">CRITICAL</button>
  <button class="filter-btn" onclick="filterSev('HIGH')"     style="border-color:#ff8c0044">HIGH</button>
  <button class="filter-btn" onclick="filterSev('MEDIUM')"   style="border-color:#ffc10744">MEDIUM</button>
  <button class="filter-btn" onclick="filterSev('LOW')"      style="border-color:#17a2b844">LOW</button>
  <input class="search-box" type="text" placeholder="Filtrar findings..." oninput="searchFindings(this.value)">
</div>

<table id="findings-table">
  <thead>
    <tr>
      <th style="width:90px">Severity</th>
      <th style="width:130px">Timestamp</th>
      <th>Finding</th>
      <th style="width:130px">MITRE</th>
      <th style="width:150px">Tactic</th>
    </tr>
  </thead>
  <tbody id="findings-body">
    $findingsHTML
  </tbody>
</table>

<hr class="section-divider">

<h2 style="margin-bottom:.75rem">Estado dos Modulos</h2>
<table>
  <thead><tr><th>Modulo</th><th>Estado</th><th>Evidencias</th></tr></thead>
  <tbody>$moduleStatusHTML</tbody>
</table>

<div class="meta" style="margin-top:2rem">
  <div class="meta-card">
    <h3>Cobertura MITRE ATT&amp;CK</h3>
    <p>
      Initial Access: T1078, T1110, T1566<br>
      Execution: T1059.009, T1648<br>
      Persistence: T1098, T1136, T1137, T1671<br>
      Defense Evasion: T1562, T1070, T1550, T1606, T1556, T1672<br>
      Credential Access: T1528, T1539, T1552, T1621<br>
      Collection: T1114, T1213, T1530<br>
      Exfiltration: T1048, T1537, T1567<br>
      Impact: T1531, T1657, T1667
    </p>
  </div>
  <div class="meta-card">
    <h3>Notas de Execucao</h3>
    <p>
      Exchange Online: $(if (Test-EXOAvailable) { 'Conectado' } else { 'Nao disponivel (EXO broker bug)' })<br>
      Microsoft Graph: $(try { $ctx = Get-MgContext -ErrorAction SilentlyContinue; if ($ctx) { $ctx.Account } else { 'Nao conectado' } } catch { 'N/A' })<br>
      Entra ID P2: $(if (($Script:Stats.CRITICAL + $Script:Stats.HIGH) -gt 0 -and $critCount -gt 0) { 'Verificar licenca' } else { 'Nao determinado' })<br>
      Duracao total: $duration minutos<br>
      PS Version: v$($PSVersionTable.PSVersion)<br>
      Output: $([System.Web.HttpUtility]::HtmlEncode($Script:OutputPath))
    </p>
  </div>
</div>

<p class="footer">IR-O365 v$($Script:Version) &nbsp;|&nbsp; MITRE ATT&amp;CK Enterprise (Office Suite) v18 &nbsp;|&nbsp; Duracao: $duration min</p>

<script>
function toggleEvidence(id) {
  var row = document.getElementById(id);
  var btn = row.previousElementSibling.querySelector('.expand-btn');
  if (row.style.display === 'none') {
    row.style.display = 'table-row';
    if (btn) btn.textContent = '- evidencias';
  } else {
    row.style.display = 'none';
    if (btn) btn.textContent = '+ evidencias';
  }
}

function filterSev(sev) {
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  event.target.classList.add('active');
  var rows = document.querySelectorAll('#findings-body tr.finding-row');
  rows.forEach(function(row) {
    var evRow = row.nextElementSibling;
    var show = sev === 'ALL' || row.classList.contains('sev-' + sev.toLowerCase());
    row.style.display = show ? '' : 'none';
    if (evRow && evRow.classList.contains('evidence-row')) {
      if (!show) evRow.style.display = 'none';
    }
  });
}

function searchFindings(q) {
  var query = q.toLowerCase();
  var rows = document.querySelectorAll('#findings-body tr.finding-row');
  rows.forEach(function(row) {
    var text = row.textContent.toLowerCase();
    var evRow = row.nextElementSibling;
    var show = !query || text.includes(query);
    row.style.display = show ? '' : 'none';
    if (evRow && evRow.classList.contains('evidence-row')) {
      if (!show) evRow.style.display = 'none';
    }
  });
}

// Auto-expand CRITICAL findings on load
window.addEventListener('load', function() {
  document.querySelectorAll('tr.sev-critical').forEach(function(row) {
    var evRow = row.nextElementSibling;
    if (evRow && evRow.classList.contains('evidence-row')) {
      evRow.style.display = 'table-row';
      var btn = row.querySelector('.expand-btn');
      if (btn) btn.textContent = '- evidencias';
    }
  });
});
</script>

</body>
</html>
"@

    $reportPath = Join-Path $Script:OutputPath "IR_REPORT.html"
    $html | Out-File -FilePath $reportPath -Encoding UTF8
    Write-IRLog "HTML Report gerado: $reportPath" -Severity "SUCCESS"
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
            $_.State -eq "enabled" -and
            $_.Conditions.ClientAppTypes -contains "exchangeActiveSync" -or
            $_.Conditions.ClientAppTypes -contains "other"
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
            $critAlerts = $alerts | Where-Object { $_.Severity -eq "high" -or $_.Severity -eq "critical" }
            $medAlerts  = $alerts | Where-Object { $_.Severity -eq "medium" }

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
        $globalAdmins = $privilegedInventory | Where-Object { $_.RoleName -eq "Global Administrator" }
        if ($globalAdmins.Count -gt 5) {
            Write-IRLog "Demasiados Global Admins: $($globalAdmins.Count) (best practice: max 4-5) [T1098.003]" `
                -Severity "MEDIUM" -MITRETechnique "T1098.003" -MITRETactic "Privilege Escalation"
        }

        # Break-glass accounts (should exist, should NOT be used regularly)
        Write-Host "  >> Verificando break-glass accounts..." -ForegroundColor Gray
        $breakGlass = $privilegedInventory | Where-Object {
            $_.RoleName -eq "Global Administrator" -and
            ($_.UPN -match "break|glass|emergency|breakglass|bga" -or $_.UPN -match "admin.*admin")
        }
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
            $riskyCountrySignins = $signins | Where-Object {
                $_.Location.CountryOrRegion -in $highRiskCountries
            } | Select-Object UserPrincipalName, CreatedDateTime, IPAddress,
                               @{N="Country";E={$_.Location.CountryOrRegion}},
                               @{N="City";E={$_.Location.City}},
                               ClientAppUsed, DeviceDetail

            if ($riskyCountrySignins.Count -gt 0) {
                Write-IRLog "Sign-ins de paises de ALTO RISCO: $($riskyCountrySignins.Count) [T1078.004]" `
                    -Severity "HIGH" -MITRETechnique "T1078.004" -MITRETactic "Initial Access"
                Export-IRData -FileName "19_high_risk_country_signins" -Data $riskyCountrySignins
            }

            # Sign-ins de Tor/VPN (AS names comuns)
            $torVpnSignins = $signins | Where-Object {
                $_.IPAddress -and (
                    $_.AuthenticationDetails.AuthenticationStepResultDetail -match "Anonymous proxy" -or
                    $_.RiskState -match "atRisk" -or
                    $_.TokenIssuerType -eq "AzureAD" -and $_.DeviceDetail.IsCompliant -eq $false
                )
            }
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
            $byodDevices = $newDevices | Where-Object {
                $_.TrustType -eq "Workplace" -and $_.IsManaged -eq $false
            }
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
        $isBEC = ($userFindings | Where-Object { $_.Technique -match "T1078|T1110" }).Count -gt 0 -and
                 ($userFindings | Where-Object { $_.Technique -match "T1114|T1564" }).Count -gt 0

        # Padroes de Account Takeover
        $isATO = ($userFindings | Where-Object { $_.Technique -match "T1078|T1110" }).Count -gt 0 -and
                 ($userFindings | Where-Object { $_.Technique -match "T1098|T1531" }).Count -gt 0

        # Padroes de Exfiltracao
        $isExfil = ($userFindings | Where-Object { $_.Technique -match "T1530|T1048|T1567|T1114" }).Count -gt 0

        $attackPattern = @()
        if ($isBEC)   { $attackPattern += "BEC (Business Email Compromise)" }
        if ($isATO)   { $attackPattern += "ATO (Account Takeover)" }
        if ($isExfil) { $attackPattern += "Data Exfiltration" }
        if ($attackPattern.Count -eq 0) { $attackPattern += "Suspicious Activity" }

        $record = [PSCustomObject]@{
            User            = $user
            FindingsCount   = $userFindings.Count
            CriticalCount   = ($userFindings | Where-Object { $_.Severity -eq "CRITICAL" }).Count
            HighCount       = ($userFindings | Where-Object { $_.Severity -eq "HIGH" }).Count
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
    # T1566 - Phishing | T1656 - Impersonation | T1672 - Email Spoofing
    Write-Section "EMAIL THREAT ANALYSIS" "T1566/T1656/T1672" "Initial Access / Defense Evasion"

    if ($Script:SkipExchange) { Write-IRLog "Exchange skipped" -Severity "INFO"; return }

    try {
        # Anti-Phishing policies
        Write-Host "  >> Verificando Anti-Phishing policies..." -ForegroundColor Gray
        try {
            $antiPhish = Get-AntiPhishPolicy -ErrorAction SilentlyContinue
            $defaultPolicy = $antiPhish | Where-Object { $_.IsDefault -eq $true }

            if ($defaultPolicy) {
                $issues = @()
                if ($defaultPolicy.Enabled -eq $false)                          { $issues += "Policy DESATIVADA" }
                if ($defaultPolicy.EnableMailboxIntelligence -eq $false)        { $issues += "Mailbox Intelligence OFF" }
                if ($defaultPolicy.EnableSpoofIntelligence -eq $false)          { $issues += "Spoof Intelligence OFF" }
                if ($defaultPolicy.EnableUnauthenticatedSender -eq $false)      { $issues += "Unauth Sender indicator OFF" }
                if ($defaultPolicy.PhishThresholdLevel -lt 2)                   { $issues += "Phish Threshold demasiado baixo" }

                if ($issues.Count -gt 0) {
                    Write-IRLog "Anti-Phishing gaps: $($issues -join ' | ') [T1566]" `
                        -Severity "HIGH" -MITRETechnique "T1566" -MITRETactic "Initial Access"
                }
                Export-IRData -FileName "23_anti_phish_policy" -Data ($antiPhish | Select-Object Name, Enabled, EnableMailboxIntelligence, EnableSpoofIntelligence, PhishThresholdLevel, EnableTargetedUserProtection)
            }
        } catch { Write-IRLog "Anti-Phish: permissoes ou MDO nao disponivel" -Severity "INFO" }

        # Safe Links / Safe Attachments
        Write-Host "  >> Verificando Safe Links e Safe Attachments..." -ForegroundColor Gray
        try {
            $safeLinks = Get-SafeLinksPolicy -ErrorAction SilentlyContinue
            $safeAttach = Get-SafeAttachmentPolicy -ErrorAction SilentlyContinue

            $slDisabled = $safeLinks | Where-Object { $_.IsEnabled -eq $false -or $_.EnableSafeLinksForOffice -eq $false }
            $saDisabled = $safeAttach | Where-Object { $_.Enable -eq $false }

            if ($slDisabled.Count -gt 0) {
                Write-IRLog "Safe Links DESATIVADO em $($slDisabled.Count) policies [T1566]" `
                    -Severity "HIGH" -MITRETechnique "T1566" -MITRETactic "Initial Access"
            }
            if ($saDisabled.Count -gt 0) {
                Write-IRLog "Safe Attachments DESATIVADO em $($saDisabled.Count) policies [T1566]" `
                    -Severity "HIGH" -MITRETechnique "T1566" -MITRETactic "Initial Access"
            }

            Export-IRData -FileName "23_safe_links_policies" -Data ($safeLinks | Select-Object Name, IsEnabled, EnableSafeLinksForOffice, TrackClicks, AllowClickThrough)
            Export-IRData -FileName "23_safe_attachments_policies" -Data ($safeAttach | Select-Object Name, Enable, Action, QuarantineTag)
        } catch { Write-IRLog "Safe Links/Attachments: MDO P1 requerido" -Severity "INFO" }

        # Quarantine - mensagens libertadas recentemente (indicador de tampering)
        Write-Host "  >> Verificando releases de quarentena recentes..." -ForegroundColor Gray
        if (-not $Script:SkipUAL) {
            $quarantineReleases = Invoke-UALSearch `
                -StartDate $Script:StartDate -EndDate $Script:EndDate `
                -Operations @("QuarantineReleaseMessage","QuarantineRelease") `
                -ResultSize 500 -ErrorAction SilentlyContinue

            if ($quarantineReleases.Count -gt 0) {
                Write-IRLog "Mensagens libertadas de quarentena: $($quarantineReleases.Count) - verificar se legitimas [T1566]" `
                    -Severity "MEDIUM" -MITRETechnique "T1566" -MITRETactic "Initial Access"
                Export-IRData -FileName "23_quarantine_releases" -Data ($quarantineReleases | Select-Object CreationDate, UserIds, Operations, AuditData)
            }
        }

        # DMARC / DKIM / SPF por dominio
        Write-Host "  >> Verificando DMARC/DKIM/SPF configs..." -ForegroundColor Gray
        try {
            $acceptedDomains = Get-AcceptedDomain -ErrorAction SilentlyContinue
            $dkimConfigs     = Get-DkimSigningConfig -ErrorAction SilentlyContinue

            $emailSecReport = $acceptedDomains | ForEach-Object {
                $domain   = $_.DomainName
                $dkimConf = $dkimConfigs | Where-Object { $_.Domain -eq $domain }
                [PSCustomObject]@{
                    Domain      = $domain
                    DomainType  = $_.DomainType
                    DKIMEnabled = if ($dkimConf) { $dkimConf.Enabled } else { "Not Configured" }
                    DKIMStatus  = if ($dkimConf) { $dkimConf.Status } else { "N/A" }
                }
            }
            Export-IRData -FileName "23_email_security_config" -Data $emailSecReport

            $dkimOff = $emailSecReport | Where-Object { $_.DKIMEnabled -eq $false }
            if ($dkimOff.Count -gt 0) {
                Write-IRLog "DKIM desativado para: $($dkimOff.Domain -join ', ') - risco de spoofing [T1672]" `
                    -Severity "HIGH" -MITRETechnique "T1672" -MITRETactic "Defense Evasion"
            }
        } catch { Write-IRLog "DMARC/DKIM check: $_" -Severity "INFO" }

    } catch {
        Write-IRLog "Erro Email Threat Analysis: $_" -Severity "INFO"
    }
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
        "Get-FederationAndExternalIdentityAudit","Get-EmailThreatAnalysis","Build-AttackTimeline"
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
