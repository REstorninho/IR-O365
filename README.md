# IR-O365 — Office 365 Incident Response Script

**Versão actual: 5.6.0**  
Ferramenta de Incident Response para Microsoft 365 / Entra ID, mapeada contra a matriz [MITRE ATT&CK Enterprise — Office Suite Platform v18](https://attack.mitre.org/matrices/enterprise/cloud/officesuite/).

---

## Requisitos

| Componente | Mínimo | Recomendado |
|---|---|---|
| PowerShell | 5.1 | **7.x** (`pwsh.exe`) |
| .NET Framework | 4.8 | — |
| ExchangeOnlineManagement | 3.x | 3.2.0+ |
| Microsoft.Graph | qualquer | — |
| Permissões Graph | ver abaixo | — |
| Ligação à internet | obrigatória | — |

> **Nota:** PS 5.1 + .NET 4.8 + EXO 3.9.x têm um conflito de broker WAM que impede autenticação interactiva no Exchange Online. Para cobertura completa (módulos EXO + UAL) instalar PS7:
> ```
> winget install --id Microsoft.PowerShell
> ```

### Scopes Graph necessários

```
AuditLog.Read.All
Directory.Read.All
Policy.Read.All
IdentityRiskyUser.Read.All
SecurityEvents.Read.All
Application.Read.All
RoleManagement.Read.Directory
IdentityRiskEvent.Read.All
UserAuthenticationMethod.Read.All
Reports.Read.All
```

### Instalar módulos

```powershell
Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force
Install-Module Microsoft.Graph -Scope CurrentUser -Force
```

---

## Utilização

```powershell
# Execução básica (abre browser para autenticação)
powershell.exe -ExecutionPolicy Bypass -File ".\IR-O365.ps1"

# Com PS7 (recomendado — suporta EXO completo)
pwsh.exe -File ".\IR-O365.ps1"

# Análise de 90 dias com debug
.\IR-O365.ps1 -DaysBack 90 -DebugIR

# Apenas módulos Graph (sem Exchange)
.\IR-O365.ps1 -SkipExchange

# Com exportação JSON e watchlists
.\IR-O365.ps1 -ExportJSON -WatchlistIPs @("1.2.3.4","5.6.7.8") -WatchlistUsers @("user@dominio.com")

# Com conta-isco (honeytoken) - qualquer atividade gera CRITICAL
.\IR-O365.ps1 -HoneytokenUsers @("canary@dominio.com")
```

### Parâmetros

| Parâmetro | Tipo | Default | Descrição |
|---|---|---|---|
| `-DaysBack` | int | 30 | Período de análise em dias |
| `-OutputPath` | string | `.\reports\IR-O365-YYYYMMDD_HHMMSS` | Pasta de output |
| `-SkipExchange` | switch | — | Ignorar módulos Exchange/UAL |
| `-SkipGraph` | switch | — | Ignorar módulos Graph |
| `-SkipUAL` | switch | — | Ignorar Unified Audit Log |
| `-WatchlistIPs` | string[] | `@()` | IPs a monitorizar especificamente |
| `-WatchlistUsers` | string[] | `@()` | Utilizadores a monitorizar especificamente |
| `-HoneytokenUsers` | string[] | `@()` | Contas-isco (canary) - qualquer atividade (sucesso ou falha) gera finding CRITICAL |
| `-ExportJSON` | switch | — | Exportar sumário em JSON |
| `-DebugIR` | switch | — | Modo debug: tempos, erros silenciosos, stack traces |

---

## Fluxo de execução

```
1. Limpar sessões anteriores (sempre — multi-tenant seguro)
2. Autenticar Microsoft Graph → browser interactivo → fallback Device Code
3. Autenticar Exchange Online → Device Code → fallback interactivo
4. Executar 25 módulos de análise (ver lista abaixo)
5. Gerar IR_REPORT.html + CSVs
6. Fechar todas as sessões
```

O path do report HTML é apresentado como `file:///C:/...` — copiar e colar directamente no browser.

---

## Módulos de análise

| # | Módulo | Cobertura | MITRE |
|---|---|---|---|
| 01 | Tenant Baseline | Org info, Security Defaults, licenças | T1538 |
| 02 | Sign-in Logs | Brute force, password spray, impossible travel, legacy auth | T1078, T1110 |
| 03 | MFA Status | Admin MFA, CA policies, gaps | T1556.006 |
| 04 | Privileged Accounts | Role changes, novas contas, guests privilegiados | T1098.003, T1136.003 |
| 05 | Exchange Rules | Inbox rules suspeitas, forwarding externo, transport rules | T1114.003, T1564.008 |
| 06 | OAuth / Service Principals | Grants de alto risco, SPs recentes, permissões perigosas | T1550.001, T1528 |
| 07 | Unified Audit Log | 15 categorias de eventos críticos | T1562.008, T1070.004 |
| 08 | SharePoint / OneDrive | Links anónimos, partilha externa, webhooks | T1213.002, T1530 |
| 09 | Outlook Persistence | HomePage URLs, add-ins, custom forms | T1137 |
| 10 | Discovery & Execution | Power Automate flows, remote PS | T1087, T1648 |
| 11 | Microsoft Teams | Guests suspeitos, file links | T1552.008, T1534 |
| 12 | Impact Indicators | Remoções de conta, bulk deletes | T1531 |
| 13 | Defense Evasion | SAML anomalias, federation changes | T1562.008, T1606.002 |
| 14 | CA Gap Analysis | 7 gaps de Conditional Access | T1078, T1562.008 |
| 15 | Defender Alerts | Security alerts, Secure Score | T1078, T1114 |
| 16 | Privileged Identity | 11 roles admin, guests admin, break-glass | T1098.003, T1548.005 |
| 17 | Exfiltration Correlation | Risk scoring por 6 sinais | T1048, T1537 |
| 18 | Named Locations & IPs | Named locations, países de alto risco | T1078, T1566 |
| 19 | Device Anomalies | Dispositivos não geridos, stale, novos | T1078, T1550 |
| 20 | Federation & External | Domínios federados, B2B, Entra Connect | T1556.007, T1199 |
| 21 | Email Security | DMARC/SPF/DKIM por domínio + Risk Assessment | T1566.002 |
| 22 | MFA Fatigue | Push bombing (T1621), Device Code phishing | T1621 |
| 23 | Impersonation | Display name spoofing, consent phishing refinado | T1656, T1550.001 |
| 24 | Enumeration | Reconhecimento via Graph API, password policy | T1526, T1087, T1201 |
| 25 | Mailbox Access Forensics | MailItemsAccessed/Send/SearchQueryInitiated para utilizadores em risco (requer E5) | T1114.002, T1213 |
| 26 | Attack Timeline | Correlação cross-finding, padrões BEC/ATO | todos |

---

## Output

```
.\reports\
└── IR-O365-YYYYMMDD_HHMMSS\
    ├── IR_REPORT.html              ← report principal (abrir no browser)
    ├── IR_DEBUG.log                ← log completo com tempos por módulo
    ├── IR_SUMMARY.json             ← com -ExportJSON
    ├── 00_tenant_baseline.csv
    ├── 02_admin_mfa_status.csv
    ├── 05_risky_oauth_grants.csv
    ├── 05_dangerous_app_permissions.csv
    ├── 20_stale_devices.csv
    ├── 23_email_security_report.csv
    ├── 23_email_risk_factors.csv
    ├── 25_external_tenant_apps.csv
    └── ... (mais CSVs por módulo)
```

### Report HTML

O report tem navegação lateral com 5 secções:

- **Findings** — tabela completa com filtros por severidade e pesquisa. Findings CRITICAL expandem automaticamente com evidências. Cada finding tem link directo para o CSV e para a técnica MITRE.
- **Entidades em Risco** — pivot automático por utilizador, app e domínio dos findings CRITICAL/HIGH com risk score.
- **Módulos** — estado de cada módulo (executado, skipped, 0 resultados).
- **MITRE ATT&CK** — heatmap de tácticas com contagem de findings.
- **Execução** — detalhes do run (tenant, período, duração, versão PS).

---

## Email Security Risk Assessment

Para cada domínio do tenant, o módulo verifica via DNS:

| Check | Pontos se falhar |
|---|---|
| SPF em falta | +25 |
| SPF `+all` (aceita tudo) | +30 |
| SPF `~all` (softfail) | +10 |
| DMARC em falta | +30 |
| DMARC `p=none` | +20 |
| DMARC `p=quarantine` | +5 |
| DMARC sem `rua=` | +5 |
| DMARC `pct<100` | +10 |
| DKIM não encontrado | +20 |
| DKIM desactivado (EXO) | +25 |

Níveis por domínio: `OK` (0) → `LOW` (5+) → `MEDIUM` (15+) → `HIGH` (35+) → `CRITICAL` (60+)

---

## Modo Debug

```powershell
.\IR-O365.ps1 -DebugIR
```

Com `-DebugIR` activo:
- Tempo de execução de cada módulo em tempo real
- Erros silenciosos (catch vazios) mostrados a vermelho com stack trace
- `IR_DEBUG.log` com log completo + tabela de tempos

```
  [DBG] Get-SuspiciousOAuthApps concluido em 86.4s
  [DBG-ERR] [MFAStatus] AuthMethod API falhou para user@domain.com
             The request to ... returned 403 Forbidden
```

---

## Limitações conhecidas

| Limitação | Causa | Workaround |
|---|---|---|
| EXO indisponível em PS5.1 + .NET 4.8 | Broker WAM incompatível com EXO 3.9.x | Instalar PS7 |
| UAL skipped sem EXO | Requer cmdlets Exchange | PS7 resolve |
| Sign-in risk limitado sem P2 | `IdentityRiskyUser` requer Entra ID P2 | Análise básica disponível |
| MFA Fatigue requer P2 | Sign-in detail com MFA requer P2 | Informativo |
| Secure Score `ImplementationStatus` | SDK Graph v2 usa `AdditionalProperties` | A corrigir |

---

## Multi-tenant

Cada execução começa com `Disconnect-MgGraph` + `Disconnect-ExchangeOnline` antes de autenticar. Para analisar um tenant diferente basta correr o script de novo — sem estado entre runs.

---

## Known Issues (v4.9.2)

- `17_privileged_identity_inventory.csv` pode estar vazio se as roles não estiverem activadas no tenant
- `SharePoint Online Web Client Extensibility` pode aparecer duplicado no Consent Phishing (múltiplos grants OAuth)
- Secure Score `ImplementationStatus` usa fallback via `AdditionalProperties` mas pode falhar em alguns SDK builds
- `briciadumar.onmicrosoft.com` (domínio gerido pela Microsoft) reporta DMARC/DKIM em falta — comportamento esperado, a Microsoft gere estes registos internamente

---

## Changelog resumido

| Versão | Alterações principais |
|---|---|
| 5.6.0 | Novo check no módulo 22 `Get-FederationAndExternalIdentityAudit`: Cross-Tenant Access Inbound Trust (`Get-MgPolicyCrossTenantAccessPolicyDefault`) - deteta se o tenant aceita claims de MFA/compliant device/hybrid Azure AD join de tenants externos por defeito (T1556.009, MEDIUM - uma conta comprometida noutro tenant pode herdar estes claims e contornar CA policies locais); novo parâmetro `-HoneytokenUsers` e check correspondente no módulo 02 `Get-SuspiciousSignIns` - qualquer sign-in (sucesso ou falha) de uma conta-isco gera finding CRITICAL (T1078), exportado para `01_honeytoken_activity.csv` |
| 5.5.0 | Novas entradas na tabela `$auditQueries` do módulo 07 `Get-CriticalAuditEvents` (UAL): `eDiscovery_Export_Jobs` (`PurviewSearchExportJobSubmitted`/`ReviewSetExportJobSubmitted`/`SearchExported`, T1213, HIGH - exportações em massa via eDiscovery são um vetor de exfiltração pouco monitorizado), `eDiscovery_Case_Hold_Changes` (`HoldCreated`/`HoldRemoved`/`CaseRemoved`, T1070, MEDIUM - remoção de holds pode indicar anti-forense), `PIM_Role_Activations` (`Add member to role completed (PIM activation)`/`Add member to role outside of PIM (permanent)`, T1098.003, MEDIUM - ativações de roles privilegiadas, incluindo atribuições permanentes fora do fluxo PIM) |
| 5.4.0 | Novo check no módulo 06 `Get-SuspiciousOAuthApps`: deteção via UAL de `Add service principal credentials` (T1098.001) - identifica quem (Actor) adicionou credenciais a um service principal, incluindo SPs sem objeto Application local (apps multi-tenant), exportado para `05_sp_credentials_added_ual.csv`; novo check no módulo 14 `Get-ConditionalAccessGapAnalysis`: deteção via UAL de alterações a políticas de Conditional Access e Security Defaults (`Add/Update/Delete Conditional Access policy`, `Update security defaults`) - delete/security defaults é HIGH (T1562.008), update é MEDIUM (T1556.009, pede revisão de exclusões), exportado para `14_ca_policy_changes.csv` |
| 5.3.0 | Novo check no módulo 05 `Get-ExchangeSuspiciousActivity`: deteção de Mailbox Audit Bypass / Audit Disabled (T1562.008) via `AuditEnabled=$false` (HIGH) e `Get-MailboxAuditBypassAssociation` com `AuditBypassEnabled=$true` (CRITICAL), exportado para `04_mailbox_audit_bypass.csv`; novo check no módulo 03 `Get-MFAStatus`: deteção de novos registos de métodos de autenticação via UAL (`Admin/User registered security info`) - admin a registar MFA para outro utilizador é HIGH (T1098.002), auto-registo por utilizador em watchlist é MEDIUM (T1556.006), exportado para `02_auth_method_registrations.csv`; fix `BUG_PARALLEL_EMPTY` em `Invoke-IRParallelForEach` - parâmetro `InputObject` deixou de ser `Mandatory` (rejeitava `@()` na ligação de parâmetros antes do guard de coleção vazia correr, abortando todo o módulo 03 quando não havia membros de roles privilegiadas) |
| 5.2.0 | Novo helper `Invoke-IRParallelForEach`: paraleliza (PS7+, `ForEach-Object -Parallel`, fallback sequencial em PS5.1) o loop de verificação de MFA por admin no módulo 03 (até 3 chamadas Graph por utilizador) - reduz significativamente o tempo deste módulo em tenants com muitos admins, sem alterar findings/CSV gerados |
| 5.1.0 | Novo módulo 25 `Get-MailboxAccessForensics` (T1114.002, T1213) - correlaciona eventos `MailItemsAccessed`/`Send`/`SearchQueryInitiated` do Advanced Audit (requer E5) para utilizadores já marcados como CRITICAL/HIGH ou em watchlist, identificando acesso a mailbox, envio por terceiros (SendAs/SendOnBehalf) e pesquisas suspeitas pós-compromisso; novo helper `Get-JsonProperty` para acesso seguro a propriedades JSON variáveis sob StrictMode |
| 5.0.1 | Fix `.Count` em `$null` (Where-Object sem matches) em vários módulos - causava abort total do `Build-AttackTimeline` e de secções de Defender Alerts, OAuth Apps, Transport Rules, Send-As, Named Locations e Device Anomalies sob StrictMode; fix precedência `-and`/`-or` no gap de Legacy Auth CA; fix `continue` dentro de `ForEach-Object` (BUG_FOREACHOBJ_CONTINUE) |
| 4.9.2 | Fix `Measure-Object .Sum` em colecção vazia (PS5.1 StrictMode) |
| 4.9.1 | Email scoring por domínio; sumário global com pior domínio |
| 4.9.0 | Fix `filter Add-RF` scope PS5.1; pivot entidades no report; dedup app permissions |
| 4.8.0 | Risk Assessment por domínio; pivot utilizadores/apps/domínios no report |
| 4.7.0 | Autenticação simplificada: autentica → corre → fecha sessões |
| 4.6.0 | Multi-tenant disconnect; URLs MITRE corrigidas; `evHtmlFrom` melhorado |
| 4.5.x | Fix device code param check; MFA 3 métodos de detecção; false positive guard |
| 4.4.0 | DMARC/SPF/DKIM via DNS real; Risk Assessment email; multi-tenant |
| 4.3.0 | Report HTML redesenhado (sidebar, JetBrains Mono, MITRE heatmap) |
| 4.2.0 | Módulos MFA Fatigue (T1621), Impersonation (T1656), Enumeration (T1526) |
| 4.1.0 | Sistema debug `-DebugIR`; timers por módulo; `IR_DEBUG.log` |
| 4.0.0 | Autenticação reconstruída; funções aninhadas eliminadas |
