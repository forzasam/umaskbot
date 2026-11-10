# umask — Incident Response & Disaster Recovery Plan

**Version:** 1.0 (10 November 2026)  
**Status:** Operational runbook; recovery steps require a live rehearsal before they can be treated as verified.  
**Applies to:** The official umask Discord bot, its supporting services, and the data it processes.

umask aims to reduce the time Discord staff hold elevated permissions. **It does not make servers immune to account compromise or misuse.** During a bot, hosting, database, or Discord outage, an elevated role may remain assigned beyond its intended expiry. This plan prioritises keeping affected server owners informed, reducing ongoing exposure, and recovering without accidentally restoring revoked access.

This is a **public, non-secret runbook**. Keep account recovery codes, private contact numbers, server IDs, passwords, encryption keys, SFTP credentials, and detailed incident evidence in a separate, access-restricted location **outside GitHub**.

## 1. Responsibility and contact

- **Incident lead:** The official umask operator. Responsible for triage, containment, decisions, communications, and recovery approval.
- **Report an issue:** [support@umask.app](mailto:support@umask.app), or a private ticket in the official support server linked at [umask.app](https://umask.app).
- **Infrastructure:** PebbleHost (Python bot and SQLite files); Cloudflare Pages (static website); Discord (application, interactions, roles and notifications); GitHub (source code).
- **Authoritative state:** Discord has the actual role assignments. SQLite has the bot's recorded credentials, configurations and session state. **Both must be checked during recovery.**
- **Private operator controls:** The application-owner `/status` panel and, for reviewed data requests, `/privacy_ops` in the configured private admin guild. These interfaces are useful only while the bot and Discord are functioning.

**Incident record:** Create a private case with an ID, first-known time (UTC), reporter, affected guilds/users, observed symptoms, evidence locations, decisions, actions, failed actions, and close-out date. Never post phrases, tokens, database dumps, or sensitive member histories into a public GitHub issue, Discord channel, or status announcement.

## 2. Severity and initial response

| Level | Examples | Initial response |
| --- | --- | --- |
| **Critical (P0)** | Confirmed or suspected bot-token compromise; unauthorised elevated role assignment; sensitive database/secret exposure; widespread unsafe revocation failure | Contain immediately. Prioritise owner warnings and manual role removal; restrict or suspend new elevations. Assess notification duties. |
| **High (P1)** | Bot or Discord disconnected with active elevated sessions; database lost/corrupt; persistent role-removal errors; maintenance-state or privacy-ledger missing | Enter or preserve maintenance where possible, investigate, notify potentially affected owners promptly, recover carefully. |
| **Moderate (P2)** | Isolated command failure, transient API error with successful retry, a missed notification, recoverable website issue | Log, fix or roll back, check for affected sessions, follow up as needed. |

Severity can change as more information becomes available. Treat an incident as potentially critical if you cannot establish whether elevated roles remain assigned.

### Immediate checklist — any security or availability incident

1. **Record:** Note the earliest known occurrence and what is *known*, *suspected* and *unknown*. Save relevant logs securely without exposing secrets.
2. **Determine exposure:** Is the bot connected? Can it access SQLite? Are tracked elevated sessions still assigned in Discord? Are the bot's token or other secrets at risk?
3. **Contain:** Where the bot is responsive and trustworthy, use `/status` → **Maintenance / shutdown** to persistently block new elevations and attempt to revoke tracked roles. Review any remaining failures. If the bot may be compromised, prioritise token revocation and direct server-owner intervention instead of trusting its output.
4. **Contact affected owners:** Explain what they must check, including **manual removal of elevated roles** if Umask cannot remove them. The built-in maintenance notice reaches *only* configured, accessible alert channels and is best-effort. Use other support channels as appropriate.
5. **Preserve evidence:** Retain relevant timestamps, anonymised error details, configuration/version and private incident records. Limit access. Avoid collecting unnecessary member data.
6. **Investigate and recover:** Follow the applicable scenario below. Do not claim success until you have verified Discord's actual role state.
7. **Assess disclosure:** Evaluate Discord contractual requirements and applicable personal-data-breach obligations, and document the result even where no regulator notice is necessary.

> **If the bot is offline, it cannot send maintenance notices or remove roles.** In that case, affected guild owners must remove outstanding elevated roles themselves and review other permission bypasses. Stopping PebbleHost alone does not revoke Discord roles.

## 3. Scenario playbooks

### A. Bot outage, PebbleHost restart, or Discord API unavailability

1. Determine the outage start, cause, affected guilds, and whether any sessions were active or due to expire.
2. If bot controls work, enter maintenance and attempt the role drain. **Do not assume graceful shutdown succeeds** if hosting or Discord is unavailable.
3. If controls do not work, advise affected server owners to manually remove Umask-managed elevated roles and, where necessary, temporarily adjust role arrangements. Do not recommend leaving the elevated roles assigned while waiting for recovery.
4. Restore the existing bot instance and database, not an uncontrolled second live instance. Check the console for database, token and API errors.
5. Confirm the 60-second reconciler resumes, inspect pending sessions and exceptions, and verify role removal on Discord. Reconciliation can be delayed by rate limits, connection failures or hierarchy changes.
6. Resume new authentication **only after** relevant session cleanup and health checks. Notify owners when service is stable.

### B. An elevated role is not removed when expected

1. Check the member's role in Discord, the stored session's expiry/termination status and whether Umask is online.
2. Examine errors for `Forbidden`, missing `Manage Roles`, or the bot's role having moved below the elevated role.
3. Ask the server owner to correct the hierarchy or manually remove the role. Do not report a session as ended merely because its database expiry timestamp has passed.
4. Allow reconciliation to retry; verify the role is absent in Discord and the session record is closed.
5. If repeated or widespread, enter maintenance, contact affected owners, and treat as P0/P1 according to exposure.

### C. Suspected Discord bot-token compromise

1. Treat as **P0**. Record the suspected exposure period and whether unauthorised bot actions occurred.
2. **Reset the token in the Discord Developer Portal** and replace `DISCORD_TOKEN` in PebbleHost's private `.env`. Restart only a trusted deployment. The old token must no longer be usable.
3. If the existing process cannot be trusted, do not rely on its maintenance or cleanup output. Inform affected server owners to inspect roles and perform manual revocation; temporarily remove or restrict the bot's server access if needed to contain harm.
4. Inspect Git commits, exposed logs, CI/deployment access, PebbleHost account sessions and who could read `.env`. Rotate any other potentially exposed secrets; remove their source of exposure.
5. Audit changes to relevant Discord roles and any suspicious moderation actions. A new token **does not reverse actions already performed**.
6. Once the bot and host are trusted again, verify all tracked sessions and actual Discord roles before resuming normal operations. Assess user/Discord notification duties.

### D. Suspected database exposure or encryption-key exposure

1. Preserve evidence and restrict access to the affected PebbleHost account, backups, GitHub credentials and any shared storage. Determine *which* data and secrets were potentially accessed.
2. Understand the distinction: the active credential verifier uses Argon2id hashes; newly issued, uncollected phrases may temporarily exist in encrypted escrow. Compromise of the relevant database **and** `ESCROW_FERNET_KEY` could expose these pending phrases. A database leak may also expose identifiers and session history.
3. If confidentiality of issued credentials or database integrity cannot be trusted, **consider all affected credentials compromised** and arrange owner-led revocation/reissuance. Never assume rotating the Fernet key invalidates stored credential hashes; it does not.
4. Secure the cause, rotate affected access credentials and Fernet key where appropriate, and take care not to make pending escrow unreadable without a deliberate reissue plan.
5. Check for evidence of modified, inserted or resurrected session/credential records. Use the recovery procedure below if integrity is uncertain.
6. Assess whether personal data was breached and which notifications are required. Do not disclose sensitive rows in public reports.

### E. SQLite corruption, database deletion, or loss of PebbleHost files

1. **Stop the bot** through PebbleHost if it might be writing to a damaged database. Prevent automatic restart against incomplete or inconsistent restored data.
2. Obtain the latest **known-good, integrity-checked SQLite snapshot** from encrypted off-host storage, not merely an arbitrary live `.sqlite3` copy. Record the snapshot time and expected data-loss window.
3. Retrieve the **current** `private/erasure-ledger.jsonl`, `private/maintenance.json` and necessary private settings/keys **from separately protected copies**. A SQLite snapshot alone is insufficient.
4. Restore into an **isolated, non-production environment** first. Keep the Discord bot offline during inspection. Verify SQLite integrity, schema compatibility, configurations, pending sessions and credential records.
5. Reapply every surviving privacy-erasure instruction and reconcile with records of credential revocations since the backup. **Do not start a restored bot if the ledger is missing or stale.** A 30-day-old snapshot can reintroduce credentials revoked after that snapshot; if the revocation timeline cannot be verified, arrange precautionary reissuance rather than trusting restored credentials.
6. Identify sessions that were active between the snapshot and the incident but are **not present in the restored database**. They cannot be reliably recovered from that snapshot alone. Work with affected owners to inspect **actual Discord elevated-role assignments** and remove any roles that should no longer be active.
7. Restore one trusted production instance, with maintenance enabled, and verify startup, ledger application, reconciliation and owner-visible state. Preserve `PRIVACY_LEDGER_REQUIRE_EXISTING=1` and `MAINTENANCE_REQUIRE_EXISTING=1` if already configured; do not disable these checks to make an unsafe restore boot.
8. Manually verify role cleanup in affected guilds. Only then resume authentication and send a recovery notice.

**Never deploy an old SQLite snapshot on top of a running bot. Never launch two live copies with the same Discord bot token and database.**

### F. Missing privacy ledger or maintenance-state file

These files live **outside** SQLite (`private/erasure-ledger.jsonl`, `private/maintenance.json`) by design. Restore them from the latest trusted off-host copy; investigate why they disappeared. If the ledger is lost, previous erasures may no longer be enforceable on restore. If the maintenance file is lost, an old snapshot could be resumed in an unsafe state. **Treat either loss as a stop-and-review event** rather than clearing safety settings or creating fresh empty files.

### G. Vulnerability, malicious code, or compromised GitHub/deployment access

1. Disable affected release/deployment credentials; preserve the relevant commit IDs, change history and logs.
2. Contain live impact with trusted maintenance or manual owner action, depending on whether the running code is trustworthy.
3. Review the suspicious code and dependencies; deploy a pinned, previously verified release after confirming it is compatible with the current data schema. **Source rollback is not necessarily database rollback.**
4. Rotate secrets that could have been read. Verify no unexpected credentials or role assignments remain.
5. Privately coordinate disclosure until mitigations are available; publish an appropriately scoped advisory afterwards.

## 4. Backups and restore readiness

**Current implementation (SQLite on PebbleHost):**

| Item | Location / practice | Recovery importance |
| --- | --- | --- |
| Live SQLite database | `DB_PATH` (normally `./data/gatekeeper.sqlite3`) | Credentials, configuration, active sessions and history |
| Automatic local snapshots | `backups/umask-YYYY-MM-DD.sqlite3`, generated daily and locally retained ~7 days | Consistent SQLite copies, but **same-host** failure remains a risk |
| Encrypted off-site snapshots | **Operator-managed**, target rolling retention of 30 days | Recovery if PebbleHost files are lost; **not automated by the bot** |
| Privacy erasure ledger | `private/erasure-ledger.jsonl` | Prevents approved deletions being undone by restoration, within its maintained coverage |
| Maintenance state | `private/maintenance.json` | Preserves a planned halt to new elevated sessions across restarts |
| Fernet key, bot configuration | Private `.env`, with a separately secured recovery copy of necessary secrets | Reconfigure a trusted deployment; escrow-key mismatch can affect uncollected phrases |
| Source code | Private or public GitHub repository, pinned to a tested commit/release | Rebuild bot software; Git is **not** a database backup |

**Download procedure:** Use PebbleHost **File Manager → SFTP Details**, or File Manager downloads, to copy an already generated snapshot. Do not copy the active WAL-mode SQLite file by itself while the bot is running; it may omit committed changes. Verify backup integrity and transfer to encrypted off-host storage. Include the two `private/` state files in a protected recovery bundle, while protecting them from public sharing. If the application cannot access its encrypted off-site storage automatically, perform these exports on a documented regular schedule.

**Recovery point objective (RPO):** No guaranteed RPO is established. With one verified snapshot each 24 hours, loss of up to roughly a day of *database records* is possible, plus any period after the last successful copy. **Discord's actual role assignments are not rolled back with SQLite.**

**Recovery time objective (RTO):** No guaranteed RTO is established. Restoration depends on provider availability, completeness of backups, Discord access and manual checks by affected owners.

**Test quarterly and after material changes:** In an isolated environment, restore a recent snapshot plus current state files; check integrity, replay a known deletion, identify a known revoked credential, inspect session recovery and demonstrate that no old privileges are silently re-enabled. Record the result and remediation actions. Never rehearse destructive restores against production.

## 5. Communications and disclosure

**Be specific about what is confirmed.** Do not claim an attack, personal-data breach or complete recovery until the evidence supports it. When affected server owners may have stale elevated roles, send an operational warning promptly even if the root cause is still unknown.

### Short operational notice to affected server owners

> **umask service issue**  
> We are investigating a problem that may delay removal of temporary elevated roles. Please check your server's elevated staff role assignments and manually remove any access that should have expired. We will share a further update when we can confirm recovery. Contact support@umask.app if you need assistance.

### Recovery notice

> **umask service restored**  
> Service has resumed and we have completed the checks available to us. Please review elevated role assignments in your server, especially for sessions active during the disruption. We cannot guarantee that roles were removed while the service was unavailable. Contact support@umask.app if anything appears incorrect.

### Reporting and data protection

- **Discord:** Discord's Developer Terms require prompt notification to Discord of certain actual or reasonably likely security incidents affecting API Data or systems that process it. Assess and make that notification through Discord's official developer/support channels; don't wait for a complete forensic report when prompt notification is required.
- **United Kingdom:** If UK GDPR applies and a personal-data breach is likely to create a risk to individuals' rights and freedoms, notify the ICO without undue delay and, where feasible, **within 72 hours of becoming aware**. If the risk to people is high, inform affected individuals without undue delay. Document **all** personal-data breaches and the assessment of whether notification was required.
- **Other jurisdictions:** Assess additional obligations based on affected users and the service's actual legal footprint. Obtain appropriate legal advice for complex or significant incidents.
- Keep a private record of communications, timestamps, reasons for decisions and who received updates. Don't promise that every security incident will trigger regulatory notification; obligations depend on the facts and applicable law.

References: [Discord Developer Terms](https://support-dev.discord.com/hc/en-us/articles/8562894815383-Discord-Developer-Terms-of-Service), [ICO personal data breach guidance](https://ico.org.uk/for-organisations/report-a-breach/personal-data-breach/personal-data-breaches-a-guide/), [SQLite Online Backup API](https://sqlite.org/backup.html), [SQLite WAL documentation](https://www.sqlite.org/wal.html), [PebbleHost Python/SFTP documentation](https://help.pebblehost.com/en/article/how-to-setup-yo).

## 6. Closing an incident

Close the incident only after documenting:

- What happened, what was affected and what remains uncertain.
- The duration of any increased risk, including sessions potentially left elevated.
- Steps taken to revoke or verify roles, and any remaining owner-led action.
- Secrets rotated and the point at which old credentials became unusable (where applicable).
- Verified restoration status and results of backup checks.
- Privacy / Discord reporting decisions and communications sent.
- Root cause, regression tests, prevention measures and owner for any follow-up.

A public post-incident summary should avoid exposing authentication phrases, private user data, precise secrets or unpatched exploit details.

## 7. Readiness tasks before relying on this plan

- [ ] Test the operator maintenance flow in a non-production guild, including an active session and failed role removal.
- [ ] Establish independent monitoring of **successful reconciliation**, not just bot process uptime.
- [ ] Verify PebbleHost account security, backup protection and **encryption at rest** for Discord API data, including backups.
- [ ] Schedule encrypted off-host snapshot exports and maintain a separately secured copy of the latest ledger and maintenance state.
- [ ] Rehearse a complete isolated restore, including stale credentials, previously erased data, and orphaned Discord role assignments.
- [ ] Record private recovery contacts, incident-document location, access delegation and outbound communication arrangements.
- [ ] Verify operator ownership restrictions remain correct if Discord app ownership moves to a team.
- [ ] Confirm that the support mailbox can **send replies**, not just receive forwarded emails.
- [ ] Review this runbook after significant bot changes and at least every six months.

**Bottom line:** A successful database restore is not, by itself, a safe return to service. Umask is recovered only when new elevations are appropriately controlled, the integrity of credentials and privacy records is established, and Discord role assignments have been checked or explicitly handed back to the affected server owners for manual verification.
