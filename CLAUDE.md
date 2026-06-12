# CLAUDE.md

Guidance for AI assistants (and future contributors) working on this repository.

## What this is

`IR-O365.ps1` is a single, self-contained PowerShell **Incident Response** script for
Microsoft 365 / Entra ID tenants. It authenticates to Microsoft Graph and Exchange
Online, runs ~25 analysis modules mapped to the MITRE ATT&CK Enterprise — Office Suite
Platform matrix (v18), and produces an HTML report + CSVs + optional JSON summary.

The repo has **no build system, package manifest, or test suite** — it is one
~4000-line `.ps1` file plus `README.md`. There is nothing to compile/install beyond
the PowerShell modules listed in the README.

## Repository layout

```
IR-O365.ps1   # the entire tool (single file, ~3985 lines)
README.md     # user-facing docs (PT-PT): requirements, usage, module list, changelog
```

Everything — config, helpers, auth, all 25 modules, HTML/JSON/debug report generation,
and the entry point — lives in `IR-O365.ps1`. There are no other source files,
no `src/`, no test directory, no CI config.

## ⚠️ Versioning note

`$Script:Version` (near the top of the script, "CONFIGURACAO & INICIALIZACAO" region)
and the version stated in `README.md` ("Versão actual: ...") can drift out of sync.
**When you bump the version, update BOTH**, and add an entry to the "Changelog
resumido" table in `README.md`.

## High-level structure of `IR-O365.ps1`

The file is organized into clearly marked `# ====...====` regions, in this order:

1. **Header / param block** (`param(...)`) — `-DaysBack`, `-OutputPath`,
   `-SkipExchange`, `-SkipGraph`, `-SkipUAL`, `-WatchlistIPs`, `-WatchlistUsers`,
   `-ExportJSON`, `-SkipConnect`, `-DebugIR`.
2. **Init / config** — `$Script:` scoped globals (Version, TenantName/Id, dates,
   findings list, stats, module timers, etc.), TLS 1.2 enforcement, explicit
   `Import-Module` of Graph sub-modules.
3. **Core helper functions** — `Write-IRLog`, `Write-DebugError`,
   `Start-ModuleTimer` / `Stop-ModuleTimer`, `Write-Section`, `Export-IRData`,
   `Get-JsonProperty`, `Invoke-IRParallelForEach`, `Invoke-UALSearch`,
   `New-OutputDirectory`, `Test-EXOAvailable`, `Test-UALAvailable`.
4. **Banner & prerequisites** — `Show-Banner`, `Test-Prerequisites`.
5. **Authentication** — `Connect-IRServices`, `Close-IRSessions`.
6. **Modules 1–26** — each `Get-*` / `Build-*` function is one numbered IR module
   (see README's "Módulos de análise" table for the canonical list and MITRE
   mapping). Modules are separated by `# ====...====` region comment blocks
   numbered "MODULO N: ...".
7. **Reporting** — `New-HTMLReport` (generates `IR_REPORT.html`, includes inline
   JS for filtering/search/MITRE heatmap around lines ~2300–2390),
   `New-DebugLog`, `New-JSONSummary`.
8. **Containment helper** — `Invoke-AutoContainment` (manual-use helper for
   rapid response to CRITICAL findings; not run automatically).
9. **Entry point** — `Start-O365IRScriptFull`, called unconditionally as the
   last line of the file. This drives the whole run: banner → output dir →
   prerequisites → connect → run `$Script:_modules` in order → generate
   reports → close sessions → print summary.

## Key conventions to follow when editing or adding modules

### Module shape
Each analysis module is a parameterless function named `Get-<Thing>` (or
`Build-<Thing>` for the timeline/correlation modules). A module typically:

```powershell
function Get-SomethingSuspicious {
    Write-Section "TITLE" "T1234" "Tactic Name"
    try {
        # ... Graph / EXO / UAL calls ...
        Write-IRLog "Human-readable finding" -Severity "HIGH" `
            -MITRETechnique "T1234" -MITRETactic "Defense Evasion" -Data $someObject
        Export-IRData -FileName "NN_some_name" -Data @($resultsArray)
    } catch {
        Write-IRLog "Erro ao ..." -Severity "INFO"
    }
}
```

- New modules must be **registered** in `$Script:_modules` inside
  `Start-O365IRScriptFull` (near the end of the file), otherwise they never run.
- CSV exports use `Export-IRData -FileName "NN_descriptive_name" -Data @(...)`
  where `NN` is the module number prefix (matches README's CSV naming, e.g.
  `05_risky_oauth_grants.csv`). Always wrap data in `@(...)` to force array.
- Findings are logged via `Write-IRLog -Severity <CRITICAL|HIGH|MEDIUM|LOW|INFO|SUCCESS>`.
  Only `CRITICAL/HIGH/MEDIUM/LOW` increment `$Script:Stats` and get added to
  `$Script:Findings` (shown in the HTML report's Findings table).
- Always pass `-MITRETechnique` / `-MITRETactic` for actionable findings so they
  show up correctly in the MITRE heatmap and Entities-at-Risk pivot.
- Wrap external calls (`Get-Mg*`, `Search-UnifiedAuditLog`, EXO cmdlets) in
  `try/catch`; log failures with `Write-IRLog ... -Severity "INFO"` or
  `Write-DebugError $ModuleName $Context $_` so they surface under `-DebugIR`
  without aborting the whole run (the caller in `Start-O365IRScriptFull` also
  catches per-module exceptions, but modules should fail gracefully internally).

### PowerShell 5.1 compatibility (important!)
The script must run under PowerShell 5.1 + `Set-StrictMode -Version Latest`. Known
landmines that have been fixed before and must not be reintroduced:

- **No `??` null-coalescing operator** — use `if/else` instead (PS5.1 doesn't
  support it).
- **`Search-UnifiedAuditLog` / similar can return `$null`** — always wrap in
  `[array](...)` or use the `Invoke-UALSearch` helper, which already guarantees
  an array. Calling `.Count` on `$null` throws under StrictMode.
- **`Measure-Object -Sum` on an empty collection** throws under StrictMode/PS5.1
  — guard with a count check first (see changelog 4.9.2 fix).
- **`filter` blocks defined inside a function** can have scope issues in PS5.1
  (see changelog 4.9.0 "Fix `filter Add-RF` scope PS5.1") — prefer normal
  functions/script blocks over `filter` unless you've verified scoping.
- Avoid calling `Get-Mailbox`/EXO cmdlets without checking `Test-EXOAvailable`
  first, and `Search-UnifiedAuditLog` without `Test-UALAvailable` /
  `$Script:SkipUAL`.
- Respect `$Script:SkipExchange`, `$Script:SkipGraph`, `$Script:SkipUAL` —
  modules should no-op (or skip the relevant sub-section) when these are set.

### Parallelizing heavy per-item Graph loops

`Invoke-IRParallelForEach` (defined near `Get-JsonProperty`) parallelizes loops that
make one (or a few) Microsoft Graph calls per item: on PS7+ it uses
`ForEach-Object -ThrottleLimit N -Parallel`, relying on the fact that the
Microsoft.Graph SDK's authentication context (`GraphSession`) is process-wide static
state, so parallel runspaces reuse the session set up by the initial
`Connect-MgGraph` — no per-thread reconnect needed. On PS5.1, or if `-Parallel`
throws, it falls back to a plain sequential `ForEach-Object`. See `Get-MFAStatus`
(module 03, admin MFA check) for the reference usage.

Rules when using it:
- The `-ScriptBlock` must be **read-only** (`Get-Mg*` calls) and return plain data
  objects (e.g. `[PSCustomObject]`). **Never** call `Write-IRLog`/`Write-DebugError`
  or mutate `$Script:*` state from inside the scriptblock — shared mutable state is
  not thread-safe across parallel runspaces.
- If a per-item Graph call can fail, catch it inside the scriptblock and return the
  error message as a string field (e.g. `DebugMsgs`); the caller then calls
  `Write-DebugError`/`Write-IRLog` sequentially over the returned results.
- Add `Import-Module Microsoft.Graph.<SubModule> -ErrorAction SilentlyContinue` at
  the top of the scriptblock for any Graph submodules it calls, so cmdlets resolve
  reliably in the new runspace.
- **Do not** use this for Exchange Online (EXO) cmdlets (`Get-InboxRule`,
  `Get-MailboxPermission`, etc.) — EXO's implicit-remoting session is tied to the
  runspace that ran `Connect-ExchangeOnline` and does not carry over to parallel
  runspaces, and the script's interactive/device-code auth can't be silently
  re-run per thread.

### Language / tone
- Log messages, comments, and README are written in **Portuguese (PT-PT)**.
  Keep new user-facing strings and comments consistent with this (technical
  identifiers, MITRE IDs, cmdlet names stay in English as-is).
- Inline comments often reference `FIX BUG_<NAME>` tags describing historical
  bug fixes — this is the project's convention for documenting non-obvious
  workarounds. Follow it for new non-obvious fixes (short tag + 1-line reason).

### Authentication & multi-tenant behavior
- Every run starts with `Disconnect-MgGraph` / `Disconnect-ExchangeOnline` —
  do not remove this; it's what makes the script safe to re-run against a
  different tenant without leftover state.
- `Connect-IRServices` tries interactive browser auth first, then falls back to
  Device Code for both Graph and Exchange Online. Don't assume a GUI/browser is
  always available.
- Sessions are closed at the end via `Close-IRSessions`, including on the
  normal completion path in `Start-O365IRScriptFull`.

## HTML report (`New-HTMLReport`)
- Contains inline CSS/JS (filtering by severity, search, MITRE heatmap —
  `sw`, `flt`, `srch`, `apply`, `te`, `buildMitre` JS functions around
  lines ~2300–2390). When editing the report, keep CSS/JS inline (no external
  asset files — the report must be a single portable `.html`).
- The report links out to per-module CSVs and to MITRE technique pages, so CSV
  filenames referenced in `Export-IRData` calls must stay consistent with what
  `New-HTMLReport` expects.

## Output layout (produced at runtime, not checked into the repo)
```
.\reports\IR-O365-<TenantName>-YYYYMMDD_HHMMSS\
├── IR_REPORT.html
├── IR_DEBUG.log
├── IR_SUMMARY.json        (with -ExportJSON)
├── raw\
├── findings\
└── NN_*.csv               (one or more per module)
```

## Testing / verification
There is no automated test suite. To validate changes:
- At minimum, run `powershell -NoProfile -Command "Set-StrictMode -Version Latest; . .\IR-O365.ps1 -SkipExchange -SkipGraph -SkipUAL"` style smoke checks are **not**
  straightforward because the script auto-runs `Start-O365IRScriptFull` and
  requires live Graph/EXO auth — there's no dry-run/mock mode.
- Use a PowerShell linter (`Invoke-ScriptAnalyzer` from `PSScriptAnalyzer`, if
  available) to catch syntax issues, especially `Set-StrictMode` violations
  (undefined variables, `.Count` on `$null`, etc.) before relying on a live run.
- If you can run against a real/test tenant, use `-DaysBack 1 -DebugIR
  -ExportJSON` for a fast, verbose pass and inspect `IR_DEBUG.log` for
  `[DBG-ERR]`/`[DBG-FATAL]` entries.

## Documentation conventions
- Update `README.md` (PT-PT) when: adding/removing a module (update the
  "Módulos de análise" table and module count mentioned in
  `Start-O365IRScriptFull`'s banner text), changing required Graph scopes,
  changing output files/CSV names, or bumping the version (update the
  changelog table too).
- Keep the module count consistent across: `README.md` header description, the
  "Módulos de análise" table, the script's `.DESCRIPTION` comment header, and
  the `Write-Host "Iniciando analise IR completa (N modulos)..."` line plus
  `$Script:_modules` array length in `Start-O365IRScriptFull`.
