# Umask threat model (MVP)

## What it is designed to do

Reduce the time a compromised staff **Discord session** can access sensitive permissions. When signed out, a staff member should not have the protected guild-level permissions. Owner-authorised, ten-word credentials are required before a limited-duration active role can be assigned.

The credential is a reusable secret (not MFA or a passkey). Security assumes the real staff member keeps it outside Discord, and that an attacker does **not** obtain it along with the Discord session.

## Deliberately out of scope

- Compromised **server owner** accounts. Owners can change roles or remove Umask.
- Compromised computers, malicious browser extensions, clipboard capture, or stolen phrase documents.
- Abuse during an **already active** elevated session.
- Other moderation bots, permissions assigned independently, and role-management bypasses.
- Guaranteed expiration while the bot or Discord API is unavailable.
- Punishing, monitoring, or reading ordinary messages. No Message Content or Server Members privileged intents.
- Security assurances regarding channel-specific permission overwrites; this MVP checks guild-level role permissions for common bypasses, not every Discord configuration interaction.

## Authentication and enrolment

1. Only the Discord `guild.owner_id` may run `/issue`, `/setup`, `/revoke`.
2. Owner chooses the target user with an existing permanent staff role.
3. Ten independent words from a bundled 1,024-word list are selected using Python `secrets` (100 bits theoretical entropy).
4. The owner sees the phrase in a short-lived ephemeral response. Its Argon2id verifier is persisted; a Fernet-encrypted copy is held **for at most 15 minutes**, so the target may `/receive` it once through a separate ephemeral interaction.
5. After one-time collection or expiry, the encrypted copy is erased; only the salted hash remains. A real database backup taken during that 15-minute window can retain it; protect backup copies and the Fernet key separately.
6. The server owner must independently verify the staff member during initial issue and reset. A compromised Discord account **during** `/receive` can collect the phrase.
7. A slash command launches a modal. The phrase is transmitted to Discord and the bot, but is never intentionally logged by the application. Discord's processing/retention is outside the bot's control.
8. At most five failed attempts per credential before a 15-minute lockout; an account holder can also be maliciously locked out temporarily by someone controlling that account.

## Permission safety

- Bot requests **`Manage Roles` only** to assign or remove the existing elevated role, and its top role must be higher than the elevated role. It does **not** need the elevated role’s other permissions, and it should never have `Administrator`.
- Active roles containing `Administrator` or `Manage Roles` are refused in v0.1.
- Bot role must be above the active role. Owner must manually remove protected permissions from all permanent staff roles.
- Authentication checks the user's staff role on Discord via fetch, their other role flags, and the current bot/active-role configuration.
- At least once a minute, tracked sessions are checked for expiration, removed staff roles, unsafe active-role changes, and Discord role state.
- Security bots or moderators who can apply the active role manually can bypass this system. Umask does not claim to block that.

## Availability and durability

- SQLite is on persistent disk with WAL and FULL synchronous mode. Only run **one** Umask process against the database.
- Session records are written **before** role assignment. Incomplete grants reconcile on reconnect. Discord API failures are retried; sessions are not marked finished unless the role is removed or no longer assigned.
- Graceful process shutdown attempts to revoke roles and send optional maintenance notices. SIGKILL, process crashes, host failures, Discord outages and forced shutdown can leave roles active past their expiry until service resumes.
- Anyone operating this bot must monitor health, back up the database and secret key securely, and explain downtime limitations to server owners.
- A leaked bot token could let an attacker directly exercise the bot's permissions. The bot is itself a trusted security principal.

## Before public deployment

Perform a full code/security review, test Discord API failures, role-hierarchy changes, command replay and credential-delivery edge cases, verify actual permissions using test accounts, deploy with reliable storage, add monitoring/alerts, and write a privacy/data deletion policy. This is a prototype, not an audited security product.


## Owner-only session audit (v0.2)

`/sessions` is restricted to the actual server owner (compared against the Discord guild owner ID), and reports are ephemeral. `/status` only exposes other members' session data to that owner. Session-history data (guild ID, member ID, role ID, timestamps and outcome) is held locally in SQLite. It never contains authentication phrases. Operators must protect DB backups and choose a retention policy before public deployment. A successful API role revocation is archived atomically with removal of its active-session database row; failed revocations remain tracked for retry and are not falsely shown as completed. Existing sessions from older releases are retained during database migration.

## Application-owner graceful shutdown (v0.3)

`/shutdown` checks the bot application's owner identity via `Bot.is_owner`, *not* the Discord server owner. The confirmation button checks the same identity again and is bound to the initiating user; it expires after 45 seconds. Only the application's owner can request a cross-server shutdown through this command. A separate lock prevents new role grants from racing with shutdown confirmation. The existing close path attempts to revoke all tracked elevated roles before disconnecting. If the Discord API is unavailable or revocation fails, elevated roles may remain assigned, and sessions stay recorded for recovery on the next restart. The confirmation is not itself an authentication factor against a compromised application-owner Discord session.

## Interactive setup (v0.4)

The owner-only `/setup` form is ephemeral and checks server ownership on every component interaction. Changes are only persisted after selecting Save setup, with role and bot-permission checks repeated at save time. Changes to the staff/elevated role pair are blocked while tracked sessions exist and invalidate credentials once saved; changes only to the session lengths and notifications preserve them. The form cannot modify Discord role permissions. A compromised server owner remains outside Umask's threat model.
