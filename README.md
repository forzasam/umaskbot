# Umask — timed Discord staff access

A focused Discord security bot that temporarily assigns a **protected staff role** after a moderator supplies an owner-issued, ten-word phrase. Built for small-to-medium communities that want a simple precaution against stolen Discord sessions without a large moderation dashboard.

**Status:** runnable MVP / unreviewed prototype. **Do not treat as a security guarantee until tested and independently reviewed.**

## What you get

- Owner-only setup: select a permanent staff role, a separate active role, allowed session durations and an optional staff alert channel.
- Owner-only `/issue @user`: 10 random English words; each phrase is specific to one user and one server.
- One-time `/receive`: authorised staff may privately collect their phrase during the next 15 minutes.
- `/authenticate [duration_minutes]`: a private text-entry modal validates the phrase and temporarily grants the active role. Default 60 minutes, if allowed.
- `/signout`: return to ordinary staff permissions early.
- `/shutdown`: **Discord application owner only** (not server owner): private Confirm/Cancel prompt, followed by graceful role cleanup and bot disconnect.
- `/revoke @user`: owner invalidates the credential and removes the active role.
- `/status`: one private view of Umask. Staff see their own access; the server owner gets a four-tab overview of setup, issued credentials, current sessions and session history, with pagination and refresh. The read-only `/credentials` and `/sessions` commands are retired.
- SQLite records the absolute UTC expiry; reconciliation runs at startup and every minute. Completed sessions are archived when access is actually removed (or the member/role is gone).
- No `Administrator`, message-content privileged intent, or server-member privileged intent.

## New in v0.7: reliable names and credential collection status

**Readable staff names:** The owner-only `/status` dashboard now resolves Discord
server nicknames for credential, active-session and historical records instead
of displaying raw `<@user-id>` strings inside embed titles. For former members,
it falls back to their global Discord user name, then to `Unknown user` alongside
the ID. No privileged member-list intent is required. Remote lookups are
performed concurrently, and dashboard interactions acknowledge immediately.

**Staff credential status:** Personal `/status` now distinguishes between
collected credentials, issued credentials still available through `/receive`,
credentials whose collection window expired without collection, and older
records whose collection status is unknown. The bot tells users what to do in
each case. Note: a collection window ending does not revoke a valid phrase; the
owner may have supplied it through a separate channel.

**Upgrade from v0.6:** Replace `gatekeeper/bot.py` only. Keep the existing
`.env`, SQLite database and logo assets. No database migration is necessary.

## v0.6: unified status dashboard and branded embeds

`/status` opens the private owner dashboard with four tabs: **Overview**,
**Credentials**, **Active** and **History**. Owners can browse six records per
page with **Previous**, **Next** and **Refresh**. The bot never displays stored
secret phrases or password hashes. The dashboard uses the official Umask logo
and lavender accent colour. Discord controls embed backgrounds and buttons.

## v0.4: guided `/setup` form

`/setup` takes **no arguments**. The actual Discord server owner receives a private, interactive configuration form with explanatory text next to each choice:

1. **Permanent staff role** — staff identity role that is present even when signed out, without protected moderation powers.
2. **Elevated permissions role** — separate temporary role with the permissions staff may access when authenticated. It must be beneath the Umask bot role.
3. **Allowed session lengths** — multi-select the durations staff may choose. The existing default of 15, 60, and 240 minutes remains available; staff choose 60 minutes by default if allowed.
4. **Shutdown notification channel** — optional, with a button to clear existing alerts.

Choose **Save setup** to apply the configuration. **Cancel** or letting the form expire makes no changes. Existing configuration is loaded automatically for edits. Umask validates the role hierarchy, bot permission coverage, and risky permission overlaps before saving. Changing the protected role pair is refused while any tracked session is active; once changed, earlier staff credentials are invalidated. Changing only durations or the alert channel preserves credentials. Umask never silently adds, removes, or changes Discord roles during setup.

**Upgrading from a version older than v0.5:** Use the full v0.7 source and retain your original `.env` and database. The internal Python package remains named `gatekeeper` to avoid breaking your launch command.

## Install / connect to your Discord bot

### 1. Create a Discord application

1. Visit the [Discord Developer Portal](https://discord.com/developers/applications), create an application, and create/reset its **bot token**. Keep the token private.
2. On **Installation**, enable **Guild Install**. Set scopes to `bot` and `applications.commands`. The bot needs **Manage Roles** and its highest role positioned above the temporary elevated role. It does **not** need the permissions contained in the elevated role (for example, **Ban Members**) merely to assign it. Do not grant Administrator.
3. Disable privileged intents in **Bot** settings. This app uses the `GUILDS` intent only, not `MESSAGE_CONTENT` or `GUILD_MEMBERS`.
4. Use the Developer Portal's install link to add the bot to a **test server**.
5. In **Server Settings → Roles**, move Umask's bot role **above** your chosen active role. Keep it below server-owner/admin roles where practical.

You cannot use a user-only install here: assigning guild roles requires a server-installed bot with `Manage Roles`.

### 2. Install Python dependencies

Use Python **3.11+** in a virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\\Scripts\\activate
pip install -r requirements.txt
```

### 3. Configure secrets

```bash
cp .env.example .env
python -m gatekeeper.keygen
```

Put the generated `ESCROW_FERNET_KEY` and your `DISCORD_TOKEN` into `.env`. Use `DEV_GUILD_ID=<your test guild ID>` for immediate command updates in that guild. Remove it for public/global command registration.

**Never** commit `.env`, the SQLite database, or copied authentication phrases. Keep the encryption key stable across restarts. Changing it invalidates still-pending one-time delivery but **not** already-issued hash verifiers.

### 4. Start the bot

```bash
python -m gatekeeper
```

Alternative container deployment:

```bash
docker compose up -d --build
```

The Compose file uses a **persistent named Docker volume** for the SQLite database. Back it up securely. For local Python runs, `./data` is used instead. Run **one process/replica** only; never host the database on an ephemeral filesystem.

### 5. Set up roles in Discord

Example role layout:

- `@Staff` — permanent identity/staff channel role, **without** the powers being protected.
- `@Staff-Active` — ordinary role holding Ban Members (or another protected set), held only during active sessions.
- `@Umask` — the bot's role, with Manage Roles and enough of the protected permissions to assign `@Staff-Active`, positioned **above** `@Staff-Active`.

As the real server owner, open the **private guided setup form**:

```text
/setup
# Choose both roles and session lengths in the form, then click Save setup.
/issue member:@Moderator
```

Use the dropdowns in `/setup` to select the permanent staff role, temporary elevated role, allowed session lengths, and optionally an alert channel. The form explains each setting and shows your current configuration. Press **Save setup** to apply it; nothing changes before that. Then run `/issue` for a staff member.

The owner sees the issued words once. The moderator runs `/receive` within **15 minutes** to view them **once** in their own ephemeral response. These secret-bearing responses are best-effort deleted after about **60 seconds** while the bot is connected. They are not guaranteed to disappear from screenshots, local caches or Discord's own systems.

The moderator securely saves the phrase **outside Discord**, then:

```text
/authenticate
/authenticate duration_minutes:15
/status
/signout
```

To revoke or replace a code, the owner uses `/revoke @Moderator` and then `/issue @Moderator`.

### Graceful shutdown (v0.3)

For a locally running Python process, **Ctrl+C** in its terminal normally invokes `Umask.close()`, which attempts to revoke all tracked elevated roles before disconnecting.

You may also run `/shutdown` from inside a server where Umask is installed. Only the **Discord application owner** (or a qualifying owner of a team-owned application, per discord.py's `Bot.is_owner()`) can invoke and confirm it. The private confirmation expires in 45 seconds. Once confirmed, the bot waits for any in-progress role grant, stops accepting new sessions, attempts revocation of tracked elevated roles **across all installed servers**, records successful revocations in session history, sends optional configured shutdown notifications and disconnects. **No additional `.env` variable is necessary.**

If Discord cannot remove a role, that session stays pending in SQLite and will be retried at startup. The bot may still disconnect; `close()` is best effort and not a hard safety guarantee. Check the console for cleanup failures and, if necessary, remove roles manually before shutting down the host. If your hosting provider automatically restarts crashed/stopped processes, you may also need to stop the service at the host level to keep it offline.

### Private status dashboard

**One read-only command:** `/status`. The actual Discord server owner receives
an ephemeral, branded dashboard with four tabs:

- **Overview:** issued credential count, tracked sessions, recent activity and
  protected role configuration.
- **Credentials:** which accounts have a credential, issue date and whether the
  one-time phrase has been collected. **Never** shows codes, hashes or stored secrets.
- **Active:** all tracked sessions, including role removal pending.
- **History:** paginated completed sessions and termination reasons.

The four tabs use buttons in one ephemeral message. **Previous / Next** browse
six records per page, **Refresh** rereads live database state, and **Close**
removes the controls. The view expires after 5 minutes. All button interactions
re-check that the caller is still the server owner and that the guild is unchanged.

For ordinary staff, `/status` displays their own credential **collection state** and session:

- **Collected:** The phrase was retrieved through `/receive`.
- **Awaiting collection:** The one-time phrase is still available, with a reminder to run `/receive` before its deadline.
- **Not collected:** The collection window has passed without `/receive`; ask the owner to replace the phrase if you do not have it.
- **Unknown:** An older phrase issued before collection tracking was introduced. Existing phrase verification still works.

The owner dashboard resolves staff usernames and server nicknames, rather than inserting raw `<@user-id>` markup into embed field titles. Where a member has left the server, Umask attempts to show their global Discord username; otherwise it displays an explicit unknown-user label and the Discord user ID. This lookup does not require the privileged members intent.

For ordinary staff, `/status` is still private and never shows another member's information.
The former read-only `/credentials` and `/sessions` commands have been removed;
Discord will remove them from the registered command list on the next sync.

**Branded embeds:** The owner dashboard and setup wizard use Umask's official U
mark as a local attachment and match its lavender and graphite palette. Other
private command replies use matching embed accents. Discord controls the
underlying embed background and native component button colours.

### Updating without losing your data

1. **Stop the running bot.** Allow it to finish its graceful shutdown before replacing files.
2. Back up your current `.env` and `data/gatekeeper.sqlite3` (plus any `-wal`/`-shm` sidecars if present; ideally use SQLite's backup API). Never share these files publicly.
3. For an upgrade from **v0.6**, replace only `gatekeeper/bot.py`. For older versions, use the full source archive while retaining your existing `.env` and `data/` directory.
4. Restart with `python -m gatekeeper`. SQLite preserves existing credentials and active sessions. There are no schema changes from v0.6 to v0.7.
5. In Discord, run `/status` as server owner, then switch between Credentials, Active and History. If `DEV_GUILD_ID` is configured, updated commands should sync to your test server upon startup.

Sessions that ended **before** the update cannot be reconstructed from v0.1 because the previous version deleted them without keeping a log. Existing active sessions will enter the history when they eventually end under v0.2 or later.

**Important:** The owner should verify the real staff member is in control of the account before issuing/reissuing. An attacker who already controls the moderator's Discord session during `/receive` may collect the code. You may use the owner-only display to hand off the code through an independently verified method instead.

## Important limitations

- Elevated roles may not have `Administrator` or `Manage Roles` in this version.
- The bot checks for obvious dangerous permissions already granted by permanent roles; it does **not** remove existing permissions on your behalf or audit every channel overwrite and third-party moderation bot.
- This is **not passkey-based authentication or MFA**. It is a second, reusable secret, intended to stay separate from Discord.
- During an active session, someone who steals that Discord session can use the elevated permissions.
- If the bot is unexpectedly offline at expiry, Discord **keeps the role** until a running bot removes it; automatic cleanup resumes at reconnect. A graceful `SIGTERM`/shutdown attempts early removal first, but isn't guaranteed.
- A moderator who already has `Manage Roles`/`Administrator` through another permanent role cannot be protected by this design.
- No automatically created roles, no hidden role changes, no moderator bans, no message scanning.
- Deletion/revocation of stored account records is owner-triggered. Session-history records contain Discord user IDs and are stored indefinitely in this version; for public deployment, define retention/deletion policies and add user-accessible data removal requests and a privacy notice.

Read [THREAT_MODEL.md](THREAT_MODEL.md) before using this in a real community.

## Testing

```bash
pip install pytest
python -m pytest -q
```

The tests cover secret generation, hashing, one-time delivery and SQLite recovery semantics. They do **not** constitute an end-to-end Discord permissions or penetration test. Test in a disposable server with two accounts (owner and moderator) before trusting production permissions.

## Architecture

```text
gatekeeper/
  bot.py         Discord commands, permission checks, background reconciliation
  store.py       SQLite persistence
  crypto.py      100-bit ten-word phrases, Argon2id, encrypted short-term delivery
  words.txt      Bundled 1,024-word random-selection vocabulary
  keygen.py      Fernet key generation
```

For the MVP, credentials aren't synced to cloud accounts, there is no dashboard, and no external authentication service is required.
