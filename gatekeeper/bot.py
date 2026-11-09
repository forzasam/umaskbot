"""Discord application commands and durable role/session reconciliation."""
import asyncio
import logging
import os
import signal
import time
from collections import defaultdict
from pathlib import Path

import discord
from discord import app_commands
from discord.ext import commands, tasks
from dotenv import load_dotenv
from cryptography.fernet import InvalidToken

from .crypto import build_fernet, generate_phrase, hash_phrase, verify_phrase
from .store import Store
from .mysql_store import MySQLStore
from .privacy import PrivacyLedger, backup_sqlite
from .privacy_ops import register_privacy_ops
from .operator_state import MaintenanceState, human_uptime, support_invite, maintenance_announcement

log = logging.getLogger("gatekeeper")
load_dotenv()

# Umask's official artwork uses a soft lilac mark on near-black charcoal.
# Discord controls the card background and button colours; embed accent lines
# are the part we can set to the brand palette.
LAVENDER = 0xB0A8FF
SLATE = 0x56566B
SOFT_WARNING = 0xC88FA8
LOGO_FILE = Path(__file__).resolve().parent / "assets" / "umask-mark.png"


def brand_embed(title: str, description: str = "", *, accent: str = "primary",
                logo: bool = False) -> discord.Embed:
    colours = {"primary": LAVENDER, "muted": SLATE, "warning": SOFT_WARNING}
    embed = discord.Embed(title=f"umask · {title}", description=description,
                          colour=colours.get(accent, LAVENDER))
    if logo and LOGO_FILE.is_file():
        embed.set_thumbnail(url="attachment://umask-mark.png")
    return embed


def logo_attachment() -> discord.File | None:
    return discord.File(LOGO_FILE, filename="umask-mark.png") if LOGO_FILE.is_file() else None


# These guild-level powers are meaningful to protect from a compromised session.
SENSITIVE = discord.Permissions(
    ban_members=True, kick_members=True, moderate_members=True,
    manage_channels=True, manage_guild=True, manage_webhooks=True,
    manage_messages=True, manage_threads=True, manage_events=True,
    move_members=True, mute_members=True, deafen_members=True,
).value


def parse_durations(raw: str) -> tuple[int, ...]:
    try:
        values = sorted({int(s.strip()) for s in raw.split(",")})
    except ValueError as e:
        raise ValueError("Enter comma-separated minutes, e.g. `15,60,240`.") from e
    if not values or len(values) > 8 or any(v < 5 or v > 1440 for v in values):
        raise ValueError("Choose 1–8 durations between 5 and 1,440 minutes.")
    return tuple(values)


def permissions_issue(member: discord.Member, staff_role_id: int, elevated: discord.Role) -> str | None:
    """Check obvious permanent role bypasses before allowing elevation.

    Guild-level role checks intentionally do not model all channel overwrites or
    permissions through other bots; see THREAT_MODEL.md.
    """
    ids = {r.id for r in member.roles}
    if staff_role_id not in ids:
        return "You no longer have the permanent staff role."
    elevated_sensitive = elevated.permissions.value & SENSITIVE
    if not elevated_sensitive:
        return "The active role no longer has protected moderation powers. Ask the owner to review setup."
    others = 0
    for role in member.roles:
        if role.id != elevated.id:
            others |= role.permissions.value
    if others & discord.Permissions(administrator=True, manage_roles=True).value:
        return "A permanent role grants Administrator or Manage Roles, bypassing protected access."
    duplicated = others & elevated_sensitive
    if duplicated:
        return "A permanent role already grants some protected permissions. Remove overlapping powers before using Umask."
    return None


class Umask(commands.Bot):
    def __init__(self):
        intents = discord.Intents.none()
        intents.guilds = True
        super().__init__(command_prefix=commands.when_mentioned, intents=intents,
                         allowed_mentions=discord.AllowedMentions.none())
        backend = os.getenv('DB_BACKEND', 'sqlite').strip().lower()
        if backend == 'mysql':
            self.store = MySQLStore.from_env()
        elif backend == 'sqlite':
            self.store = Store(os.environ.get('DB_PATH', './data/gatekeeper.sqlite3'))
        else:
            raise ValueError('DB_BACKEND must be sqlite or mysql')
        self.fernet = build_fernet(os.environ["ESCROW_FERNET_KEY"])
        self.privacy_ledger = PrivacyLedger(
            os.getenv('PRIVACY_LEDGER_PATH', './private/erasure-ledger.jsonl'),
            require_existing=os.getenv('PRIVACY_LEDGER_REQUIRE_EXISTING', '0') == '1')
        # Apply erasures BEFORE connecting to Discord; restored credentials must
        # never become usable during startup even if reconciliation later fails.
        self.privacy_ledger.apply(self.store)
        self.locks: dict[tuple[int, int], asyncio.Lock] = defaultdict(asyncio.Lock)
        self.reconcile_lock = asyncio.Lock()
        self.deletion_tasks: set[asyncio.Task] = set()
        self._closing_gatekeeper = False
        self._shutdown_requested = False
        self.shutdown_lock = asyncio.Lock()
        self.process_started = time.monotonic()
        self.last_reconciliation_at: int | None = None
        self.last_maintenance_at: int | None = None
        self.maintenance_state = MaintenanceState(
            os.getenv('MAINTENANCE_STATE_PATH', './private/maintenance.json'),
            require_existing=os.getenv('MAINTENANCE_REQUIRE_EXISTING', '0') == '1')
        self.maintenance_mode = self.maintenance_state.enabled

    async def setup_hook(self):
        dev_guild = os.environ.get("DEV_GUILD_ID")
        if dev_guild:
            guild = discord.Object(id=int(dev_guild))
            self.tree.copy_global_to(guild=guild)
            await self.tree.sync(guild=guild)
            log.info("Synced commands to development guild %s", dev_guild)
        else:
            await self.tree.sync()
            log.info("Synced global commands (Discord may take time to display them)")
        ops_id = os.getenv('PRIVACY_ADMIN_GUILD_ID', '').strip()
        if ops_id:
            register_privacy_ops(self, int(ops_id))
            # Never expose operator commands globally.
            if ops_id == dev_guild:
                await self.tree.sync(guild=discord.Object(id=int(ops_id)))
            else:
                await self.tree.sync(guild=discord.Object(id=int(ops_id)))
            log.info('Installed private operator commands in guild=%s', ops_id)
        self.reconciler.start()
        self.maintenance_loop.start()
        # Docker normally sends SIGTERM. Allow time to revoke tracked roles
        # before terminating; SIGKILL and network outages remain unpreventable.
        try:
            asyncio.get_running_loop().add_signal_handler(
                signal.SIGTERM, lambda: asyncio.create_task(self.close()))
        except (NotImplementedError, RuntimeError):
            log.warning("SIGTERM graceful shutdown is unavailable on this platform")

    async def on_ready(self):
        log.info("Connected as %s (%s)", self.user, self.user.id if self.user else "unknown")
        try:
            await self.reconcile()
        except Exception:
            log.exception("Startup reconciliation failed; the regular retry loop will retry")

    async def on_guild_remove(self, guild: discord.Guild):
        try:
            self.store.mark_guild_removed(guild.id, int(time.time()))
            log.info('Guild removed Umask; scheduled privacy cleanup after grace period guild=%s', guild.id)
        except Exception:
            log.exception('Could not record guild removal; manual follow-up required')

    async def on_guild_join(self, guild: discord.Guild):
        try:
            self.store.mark_guild_joined(guild.id)
        except Exception:
            log.exception('Could not clear departed-guild record')

    async def bot_member(self, guild: discord.Guild) -> discord.Member:
        me = guild.me
        if me is None:
            me = await guild.fetch_member(self.user.id)
        return me

    async def verify_bot_role(self, guild: discord.Guild, elevated: discord.Role):
        me = await self.bot_member(guild)
        if not me.guild_permissions.manage_roles:
            raise ValueError("Give the bot **Manage Roles** (not Administrator).")
        if elevated.is_default() or elevated.managed or elevated >= me.top_role:
            raise ValueError("Move the bot's role **above** the active role, and use a normal assignable role.")
        if elevated.permissions.administrator or elevated.permissions.manage_roles:
            raise ValueError("For safety, active roles may not contain **Administrator** or **Manage Roles** in this version.")
        if not elevated.permissions.value & SENSITIVE:
            raise ValueError("The active role needs a moderation permission (e.g. Ban Members).")
        # Discord allows assigning an existing role below the bot's top role
        # with MANAGE_ROLES, even when the bot lacks the role's permissions.
        # The permission-subset restriction applies to *editing* role permissions.

    async def get_member(self, guild: discord.Guild, user_id: int) -> discord.Member | None:
        try:
            return await guild.fetch_member(user_id)
        except discord.NotFound:
            return None

    def lock(self, guild_id: int, user_id: int) -> asyncio.Lock:
        return self.locks[(guild_id, user_id)]

    def schedule_secret_deletion(self, interaction: discord.Interaction):
        # Best-effort deletion; cannot delete if the process is offline.
        async def delete_later():
            await asyncio.sleep(60)
            try:
                await interaction.delete_original_response()
            except (discord.HTTPException, discord.NotFound):
                pass
        t = asyncio.create_task(delete_later())
        self.deletion_tasks.add(t)
        t.add_done_callback(self.deletion_tasks.discard)

    async def reconcile(self):
        if self._closing_gatekeeper:
            return
        async with self.reconcile_lock:
            now = int(time.time())
            self.privacy_ledger.apply(self.store, now=now)
            self.store.purge_pending(now)
            for row in self.store.all_sessions():
                if self.maintenance_mode and not row['termination_reason']:
                    self.store.force_expire(row['guild_id'], row['user_id'], 'operator_maintenance')
                await self.reconcile_one(row['guild_id'], row['user_id'], now)
            # Role revocation may have just created a final history row.
            self.privacy_ledger.apply(self.store, now=now)
            self.last_reconciliation_at = int(time.time())

    async def reconcile_one(self, guild_id: int, user_id: int, now: int | None = None):
        now = int(time.time()) if now is None else now
        async with self.lock(guild_id, user_id):
            row = self.store.session(guild_id, user_id)
            if not row:
                return
            guild = self.get_guild(guild_id)
            if guild is None:
                return  # Bot removed/offline for that guild; retry on rejoin.
            role = guild.get_role(row['role_id'])
            if role is None:
                self.store.end_session(guild_id, user_id, "role_deleted", now)
                return
            try:
                member = await self.get_member(guild, user_id)
                if member is None:
                    self.store.end_session(guild_id, user_id, "member_left", now)
                    return
                has_role = role.id in {r.id for r in member.roles}
                if not has_role:
                    reason = (row['termination_reason'] or
                              ("grant_not_completed" if row['state'] == 'granting' else "role_removed_externally"))
                    self.store.end_session(guild_id, user_id, reason, now)
                    return
                cfg = self.store.config(guild_id)
                staff_still_authorised = bool(cfg and cfg['staff_role_id'] in {r.id for r in member.roles}
                                               and cfg['elevated_role_id'] == role.id)
                unsafe_role = role.permissions.administrator or role.permissions.manage_roles
                if row['termination_reason'] or row['expires_at'] <= now or not staff_still_authorised or unsafe_role:
                    reason = (row['termination_reason'] or
                              ("expired" if row['expires_at'] <= now else
                               "staff_access_removed" if not staff_still_authorised else "unsafe_role"))
                    await member.remove_roles(role, reason=f"Umask: {reason}")
                    self.store.end_session(guild_id, user_id, reason, now)
                    log.info("Ended staff session in guild=%s user=%s reason=%s", guild_id, user_id, reason)
                elif row['state'] == 'granting':
                    # Crash between Discord role assignment and DB acknowledgement.
                    self.store.mark_granted(guild_id, user_id)
            except (discord.Forbidden, discord.HTTPException):
                # Never forget the session when Discord could still have the role.
                log.exception("Failed to reconcile staff role in guild=%s user=%s", guild_id, user_id)

    @tasks.loop(seconds=60)
    async def reconciler(self):
        # A temporary network/database outage must not permanently stop expiry
        # reconciliation. Active roles may still remain during the outage.
        try:
            await self.reconcile()
        except Exception:
            log.exception("Session reconciliation failed; retrying on next cycle")

    @reconciler.before_loop
    async def before_reconcile(self):
        await self.wait_until_ready()

    @tasks.loop(hours=24)
    async def maintenance_loop(self):
        # Daily housekeeping runs in the bot process (PebbleHost has no shell).
        # This does NOT approve or process incoming privacy requests.
        try:
            await self.reconcile()
            now = int(time.time())
            removed = self.store.purge_history(now - 90 * 86400, now)
            departed_removed = self.store.purge_departed_guilds(now - 7 * 86400, now)
            self.privacy_ledger.apply(self.store, now=now)
            pruned = self.privacy_ledger.rotate(self.store, now=now, retention_days=365)
            if pruned:
                log.info('Pruned %s resolved privacy ledger entries beyond 12 months', pruned)
            if isinstance(self.store, Store):
                snapshot = backup_sqlite(self.store, os.getenv('LOCAL_BACKUP_DIR', './backups'),
                                         now=now, keep_days=7)
                log.info('Daily SQLite snapshot verified: %s', snapshot.name)
            else:
                log.warning('MySQL selected: built-in SQLite snapshots unavailable; configure provider backups')
            self.last_maintenance_at = int(time.time())
            log.info('Maintenance completed; expired history=%s cleared departed servers=%s',
                     removed, departed_removed)
        except Exception:
            log.exception('Daily maintenance failed; will retry next cycle')

    @maintenance_loop.before_loop
    async def before_maintenance(self):
        await self.wait_until_ready()

    async def _drain_roles(self, reason: str = 'bot_shutdown') -> tuple[int, int]:
        """Mark all tracked grants for removal and attempt each Discord revocation.

        The DB records remain until an API-confirmed removal. This method never
        sends community notices: only an operator-confirmed maintenance event
        sends a notice, avoiding announcements on ordinary PebbleHost restarts.
        """
        records = list(self.store.all_sessions())
        for row in records:
            self.store.force_expire(row['guild_id'], row['user_id'], reason)
        for row in records:
            try:
                await self.reconcile_one(row['guild_id'], row['user_id'])
            except Exception:
                log.exception('Could not reconcile a role during %s guild=%s user=%s',
                              reason, row['guild_id'], row['user_id'])
        return len(records), len(self.store.all_sessions())

    async def prepare_maintenance(self, custom_message: str) -> dict[str, int]:
        """Persist the deny-new-sessions gate BEFORE scanning or notifying.

        The shutdown_lock also serialises grants in AuthenticationModal. Never
        await per-user locks while holding it (would deadlock with auth).
        """
        async with self.shutdown_lock:
            if self.maintenance_mode or self._closing_gatekeeper:
                raise ValueError('Umask is already in maintenance mode or stopping.')
            self.maintenance_state.activate()
            self.maintenance_mode = True
        log.warning('Operator activated persistent maintenance mode')
        try:
            _, outstanding = await self._drain_roles('operator_maintenance')
        except Exception:
            log.exception('Maintenance role drain encountered a database failure')
            outstanding = -1
        notices_sent = notices_failed = 0
        # Announce to EVERY configured and currently accessible guild, not just
        # those with an active staff session. Never impersonate its owner.
        for guild in list(self.guilds):
            try:
                cfg = self.store.config(guild.id)
                channel_id = cfg['alert_channel_id'] if cfg else None
                channel = guild.get_channel(channel_id) if channel_id else None
                if not channel_id:
                    continue
                if not isinstance(channel, discord.TextChannel):
                    notices_failed += 1
                    continue
                text = maintenance_announcement(discord.utils.escape_mentions(custom_message),
                    outstanding=max(0, outstanding))
                if outstanding < 0:
                    text += ('\n**Warning:** Session-revocation status could not be verified '
                             'because of a storage error.')
                await channel.send(text, allowed_mentions=discord.AllowedMentions.none())
                notices_sent += 1
            except (discord.HTTPException, discord.Forbidden):
                notices_failed += 1
                log.warning('Could not deliver maintenance notice guild=%s', guild.id)
            except Exception:
                notices_failed += 1
                log.exception('Unexpected failure sending maintenance notice guild=%s', guild.id)
        return {'pending': outstanding, 'sent': notices_sent, 'failed': notices_failed}

    async def resume_from_maintenance(self) -> None:
        async with self.shutdown_lock:
            if not self.maintenance_mode:
                return
            # A tracked grant that could not be revoked must not become active
            # again when maintenance ends. Remaining rows need manual action.
            if self.store.all_sessions():
                raise ValueError('Tracked elevated roles still need cleanup. Check and remove them before resuming.')
            self.maintenance_state.deactivate()
            self.maintenance_mode = False
        log.warning('Operator manually resumed Umask from maintenance mode')

    async def close(self):
        if not self._closing_gatekeeper:
            self._closing_gatekeeper = True
            if self.reconciler.is_running():
                self.reconciler.cancel()
            if self.maintenance_loop.is_running():
                self.maintenance_loop.cancel()
            if self.is_ready():
                try:
                    await asyncio.wait_for(self._drain_roles(), timeout=25)
                except (Exception, asyncio.TimeoutError):
                    log.exception("Graceful session revocation incomplete; restart reconciliation required")
            for task in list(self.deletion_tasks):
                task.cancel()
            self.store.close()
        await super().close()


bot = Umask()


async def reply(interaction: discord.Interaction, message: str, *, secret: bool = False,
                title: str = "Notice", accent: str = "primary"):
    """Private response with a consistent brand accent. Secrets are never logged."""
    embed = brand_embed(title, message, accent=accent)
    if interaction.response.is_done():
        await interaction.edit_original_response(content=None, embed=embed)
    else:
        await interaction.response.send_message(embed=embed, ephemeral=True)
    if secret:
        bot.schedule_secret_deletion(interaction)


def require_owner(interaction: discord.Interaction) -> bool:
    return interaction.guild is not None and interaction.user.id == interaction.guild.owner_id


@bot.tree.command(name="support", description="Get Umask's support server and contact email")
async def support(interaction: discord.Interaction):
    url = support_invite(os.getenv('SUPPORT_SERVER_URL', ''))
    e = brand_embed('Support', 'Need help setting up Umask or reporting an issue?')
    e.add_field(name='Support email', value='support@umask.app', inline=False)
    e.add_field(name='Support server',
                value=f'[Join the Umask support server]({url})' if url else
                'Invite link not configured yet. Email us for an invite.', inline=False)
    await interaction.response.send_message(embed=e, ephemeral=True)


# The setup wizard deliberately uses a standard ephemeral View rather than a
# modal. Discord role and channel dropdowns are native View components, and an
# owner can understand the effect of each choice before saving anything.
SETUP_DURATION_CHOICES = (5, 15, 30, 60, 120, 240, 480, 1440)


def pretty_duration(minutes: int) -> str:
    if minutes == 1440:
        return "24 hours"
    if minutes >= 60 and minutes % 60 == 0:
        hours = minutes // 60
        return f"{hours} hour{'s' if hours != 1 else ''}"
    return f"{minutes} minutes"


def validate_setup_roles(staff_role: discord.Role, active_role: discord.Role) -> None:
    if staff_role == active_role or staff_role.is_default() or staff_role.managed:
        raise ValueError("Choose two different, normal roles. The permanent staff role cannot be @everyone or an integration role.")
    if staff_role.permissions.administrator or staff_role.permissions.manage_roles:
        raise ValueError("The permanent staff role grants Administrator or Manage Roles and could bypass authentication.")
    overlapping = staff_role.permissions.value & active_role.permissions.value & SENSITIVE
    if overlapping:
        raise ValueError("The permanent staff role already includes permissions protected by the elevated role. Remove those permissions from the permanent role first.")


class SetupRoleSelect(discord.ui.RoleSelect):
    def __init__(self, field: str, current: discord.Role | None, row: int):
        label = ("1 · Permanent staff role" if field == "staff_role_id" else
                 "2 · Temporary elevated role")
        kwargs = {"placeholder": label, "min_values": 1, "max_values": 1, "row": row}
        if current is not None:
            kwargs["default_values"] = [current]
        super().__init__(**kwargs)
        self.field = field

    async def callback(self, interaction: discord.Interaction):
        selected = self.values[0]
        setattr(self.view, self.field, selected.id)
        self.default_values = [selected]
        await self.view.refresh(interaction)


class SetupDurationSelect(discord.ui.Select):
    def __init__(self, selected: tuple[int, ...]):
        available = sorted(set(SETUP_DURATION_CHOICES) | set(selected))
        options = [discord.SelectOption(
            label=pretty_duration(minutes), value=str(minutes),
            description=f"{minutes} minutes", default=minutes in selected,
        ) for minutes in available]
        super().__init__(placeholder="3 · Allowed session lengths (choose one or more)",
                         options=options, min_values=1, max_values=min(8, len(options)), row=2)

    async def callback(self, interaction: discord.Interaction):
        selected = tuple(sorted(int(value) for value in self.values))
        # Existing duration validator caps the number of allowed choices at 8.
        if len(selected) > 8:
            return await interaction.response.send_message(
                "Choose at most eight session lengths.", ephemeral=True)
        self.view.durations = selected
        for option in self.options:
            option.default = int(option.value) in selected
        await self.view.refresh(interaction)


class SetupChannelSelect(discord.ui.ChannelSelect):
    def __init__(self, current: discord.TextChannel | None):
        kwargs = {"placeholder": "4 · Optional shutdown alert channel",
                  "channel_types": [discord.ChannelType.text],
                  "min_values": 0, "max_values": 1, "row": 3}
        if current is not None:
            kwargs["default_values"] = [current]
        super().__init__(**kwargs)

    async def callback(self, interaction: discord.Interaction):
        channel = self.values[0] if self.values else None
        self.view.alert_channel_id = channel.id if channel else None
        # Use a fresh default when the owner clears the channel selection.
        resolved = interaction.guild.get_channel(channel.id) if channel else None
        self.default_values = [resolved] if resolved else []
        await self.view.refresh(interaction)


class SetupWizard(discord.ui.View):
    def __init__(self, guild: discord.Guild, requester_id: int, cfg):
        super().__init__(timeout=300)
        self._guild = guild
        self.guild_id = guild.id
        self.requester_id = requester_id
        self.staff_role_id = cfg['staff_role_id'] if cfg else None
        self.elevated_role_id = cfg['elevated_role_id'] if cfg else None
        self.durations = parse_durations(cfg['durations']) if cfg else (15, 60, 240)
        self.alert_channel_id = cfg['alert_channel_id'] if cfg else None
        self.config_snapshot = (tuple(cfg[k] for k in ('staff_role_id', 'elevated_role_id', 'durations', 'alert_channel_id', 'updated_at')) if cfg else None)
        self.message: discord.InteractionMessage | None = None

        self.add_item(SetupRoleSelect("staff_role_id", guild.get_role(self.staff_role_id), 0))
        self.add_item(SetupRoleSelect("elevated_role_id", guild.get_role(self.elevated_role_id), 1))
        self.add_item(SetupDurationSelect(self.durations))
        channel = guild.get_channel(self.alert_channel_id) if self.alert_channel_id else None
        self.add_item(SetupChannelSelect(channel if isinstance(channel, discord.TextChannel) else None))

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if (interaction.guild_id != self.guild_id or
            interaction.user.id != self.requester_id or
            not require_owner(interaction)):
            await interaction.response.send_message(
                "Only the server owner who opened this setup form can use it.", ephemeral=True)
            return False
        return True

    def render(self, *, error: str | None = None) -> discord.Embed:
        def role_name(role_id):
            role = self._guild.get_role(role_id) if role_id else None
            return role.mention if role else "**Not selected**"

        embed = brand_embed(
            "Server setup",
            "Configure staff access below. **Nothing changes until you select Save setup.**\n\n"
            "Umask never creates roles or changes their permissions automatically.",
            logo=True,
        )
        embed.add_field(name="1 · Permanent staff role",
                        value="Identifies who is allowed to authenticate. This role stays assigned **all the time**, but should **not** include the powers you're protecting.\n"
                              f"Selected: {role_name(self.staff_role_id)}", inline=False)
        embed.add_field(name="2 · Elevated permissions role",
                        value="Contains the permissions staff get **only while signed in**. Create it in Server Settings → Roles, and put Umask's role above it.\n"
                              f"Selected: {role_name(self.elevated_role_id)}", inline=False)
        embed.add_field(name="3 · Allowed session lengths",
                        value="Staff choose one of these when using `/authenticate`. Their role is removed on sign-out or expiry.\n"
                              "Selected: **" + ", ".join(map(pretty_duration, self.durations)) + "**", inline=False)
        ch = f"<#{self.alert_channel_id}>" if self.alert_channel_id else "None"
        embed.add_field(name="4 · Shutdown notifications (optional)",
                        value="Where Umask can announce a planned shutdown. The bot needs View Channel and Send Messages there.\n"
                              f"Selected: **{ch}** (use Clear alerts to disable)", inline=False)
        if error:
            embed.add_field(name="⚠️ Configuration not saved", value=error[:1000], inline=False)
            embed.colour = SOFT_WARNING
        embed.set_footer(text="Private to the server owner · Form expires after 5 minutes")
        return embed

    async def refresh(self, interaction: discord.Interaction):
        await interaction.response.edit_message(embed=self.render(), view=self)

    @discord.ui.button(label="Save setup", style=discord.ButtonStyle.success, row=4)
    async def save(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.defer()  # Defer the message update during API permission checks.
        try:
            if bot._closing_gatekeeper or bot._shutdown_requested or bot.maintenance_mode:
                raise ValueError("Umask is in maintenance; setup changes are unavailable until the operator resumes service.")
            guild = interaction.guild
            if guild is None:
                raise ValueError("This setup form is available only inside a server.")
            staff = guild.get_role(self.staff_role_id) if self.staff_role_id else None
            elevated = guild.get_role(self.elevated_role_id) if self.elevated_role_id else None
            if not staff or not elevated:
                raise ValueError("Select both a permanent staff role and a temporary elevated role.")
            validate_setup_roles(staff, elevated)
            if staff.guild.id != guild.id or elevated.guild.id != guild.id:
                raise ValueError("Both roles must belong to this server.")
            allowed = parse_durations(",".join(map(str, self.durations)))
            await bot.verify_bot_role(guild, elevated)
            channel = guild.get_channel(self.alert_channel_id) if self.alert_channel_id else None
            if self.alert_channel_id and not isinstance(channel, discord.TextChannel):
                raise ValueError("The selected notification channel no longer exists or is not a text channel.")
            if channel:
                me = await bot.bot_member(guild)
                permissions = channel.permissions_for(me)
                if not permissions.view_channel or not permissions.send_messages:
                    raise ValueError("Give Umask View Channel and Send Messages in the selected alert channel.")
            current = bot.store.config(guild.id)
            current_snapshot = (tuple(current[k] for k in ('staff_role_id', 'elevated_role_id', 'durations', 'alert_channel_id', 'updated_at')) if current else None)
            if current_snapshot != self.config_snapshot:
                raise ValueError("Setup has changed since this form was opened. Run `/setup` again to review the latest configuration.")
            if (current and bot.privacy_ledger.guild_pending_erasure(guild.id, current['updated_at'])
                    and bot.store.count_sessions(guild.id)):
                raise ValueError("This server's privacy deletion is awaiting role cleanup. Wait until all tracked sessions are safely removed before reconfiguring.")
            changed = bot.store.set_config(guild.id, staff.id, elevated.id, allowed,
                                           channel.id if channel else None)
        except (ValueError, discord.HTTPException) as exc:
            return await interaction.edit_original_response(embed=self.render(error=str(exc)), view=self)

        self.stop()
        confirmation = brand_embed(
            "Setup saved",
            f"**Permanent staff:** {staff.mention}\n"
            f"**Elevated role:** {elevated.mention}\n"
            f"**Allowed sessions:** {', '.join(map(pretty_duration, allowed))}\n"
            f"**Shutdown alerts:** {channel.mention if channel else 'Disabled'}\n\n"
            "Umask will **not** change role permissions for you. "
            "Remove protected powers from permanent roles, then use `/issue` to authorise staff.",
            logo=True,
        )
        if changed:
            confirmation.add_field(name="Important: roles changed",
                                   value="Existing staff credentials were invalidated. Issue new credentials with `/issue`.",
                                   inline=False)
        await interaction.edit_original_response(embed=confirmation, view=None)

    @discord.ui.button(label="Clear alerts", style=discord.ButtonStyle.secondary, row=4)
    async def clear_alerts(self, interaction: discord.Interaction, button: discord.ui.Button):
        self.alert_channel_id = None
        for item in self.children:
            if isinstance(item, SetupChannelSelect):
                item.default_values = []
        await self.refresh(interaction)

    @discord.ui.button(label="Cancel", style=discord.ButtonStyle.danger, row=4)
    async def cancel(self, interaction: discord.Interaction, button: discord.ui.Button):
        self.stop()
        await interaction.response.edit_message(content=None,
                                                embed=brand_embed("Setup cancelled", "No changes were saved."),
                                                view=None)

    async def on_timeout(self):
        if self.message:
            try:
                await self.message.edit(content=None,
                                        embed=brand_embed("Setup expired", "Run `/setup` to open a new form."),
                                        view=None)
            except discord.HTTPException:
                pass


@bot.tree.command(name="setup", description="Owner: configure Umask using a guided setup form")
@app_commands.guild_only()
async def setup(interaction: discord.Interaction):
    if bot.maintenance_mode:
        return await reply(interaction, 'Umask is in maintenance mode. Setup changes are temporarily disabled.')
    if not require_owner(interaction):
        return await reply(interaction, "Only the **server owner** can configure Umask.")
    cfg = bot.store.config(interaction.guild_id)
    view = SetupWizard(interaction.guild, interaction.user.id, cfg)
    attachment = logo_attachment()
    kwargs = {"embed": view.render(), "view": view, "ephemeral": True}
    if attachment:
        kwargs["file"] = attachment
    await interaction.response.send_message(**kwargs)
    try:
        view.message = await interaction.original_response()
    except discord.HTTPException:
        pass


@bot.tree.command(name="issue", description="Owner: issue or replace a 10-word staff credential")
@app_commands.guild_only()
async def issue(interaction: discord.Interaction, member: discord.Member):
    if bot.maintenance_mode:
        return await reply(interaction, 'Umask is in maintenance mode. New credentials cannot be issued.')
    if not require_owner(interaction):
        return await reply(interaction, "Only the server owner can issue credentials.")
    await interaction.response.defer(ephemeral=True, thinking=True)
    cfg = bot.store.config(interaction.guild_id)
    if not cfg:
        return await reply(interaction, "Run `/setup` first.")
    if bot.privacy_ledger.guild_pending_erasure(interaction.guild_id, cfg['updated_at']):
        return await reply(interaction, "This server's previous Umask setup is being removed under a verified privacy request. Reconfigure only after pending roles are cleared.")
    if member.bot or member.id == interaction.guild.owner_id:
        return await reply(interaction, "Choose a human staff member who is not the server owner.")
    async with bot.lock(interaction.guild_id, member.id):
        try:
            member = await bot.get_member(interaction.guild, member.id)
            role = interaction.guild.get_role(cfg['elevated_role_id'])
            if not member or not role:
                raise ValueError("Staff member or configured active role is missing.")
            await bot.verify_bot_role(interaction.guild, role)
            problem = permissions_issue(member, cfg['staff_role_id'], role)
            if problem:
                raise ValueError(problem)
            if bot.store.session(interaction.guild_id, member.id):
                raise ValueError("This member still has a tracked active session. Use `/revoke` first to end it and replace the key.")
            if role.id in {r.id for r in member.roles}:
                raise ValueError("The member already has the active role outside a tracked session. Remove it manually first.")
            phrase = generate_phrase()
            digest = await asyncio.to_thread(hash_phrase, phrase)
            cipher = bot.fernet.encrypt(phrase.encode('utf-8'))
            async with bot.shutdown_lock:
                if bot.maintenance_mode or bot._closing_gatekeeper or bot._shutdown_requested:
                    raise ValueError('Umask entered maintenance while issuing this credential. No credential was issued.')
                bot.store.issue(interaction.guild_id, member.id, digest, cipher, int(time.time())+900)
        except (ValueError, discord.HTTPException) as e:
            return await reply(interaction, f"Cannot issue credential: {e}")
    await reply(interaction,
        f"**Credential issued for {member.display_name}** (`{member.id}`) in this server.\n"
        f"`{phrase}`\n\n"
        "**Shown once to you.** The staff member can run `/receive` within 15 minutes to view it privately once. "
        "Only deliver a replacement if you've verified the real person controls the account. "
        "If the account is already compromised, an attacker may collect the new key. "
        "This confirmation will be deleted after approximately 60 seconds while the bot is online.",
        secret=True, title="Credential issued")


@bot.tree.command(name="receive", description="Staff: collect your newly issued phrase once")
@app_commands.guild_only()
async def receive(interaction: discord.Interaction):
    if bot.maintenance_mode:
        return await reply(interaction, 'Umask is in maintenance mode. Credential collection is temporarily disabled.')
    async with bot.lock(interaction.guild_id, interaction.user.id):
        cfg = bot.store.config(interaction.guild_id)
        if not cfg:
            return await reply(interaction, "Umask is not configured in this server.")
        try:
            member = await bot.get_member(interaction.guild, interaction.user.id)
            if not member or cfg['staff_role_id'] not in {r.id for r in member.roles}:
                return await reply(interaction, "You must currently hold the permanent staff role to collect a phrase.")
        except discord.HTTPException:
            return await reply(interaction, "Could not verify your current staff role. Try again.")
        cipher = bot.store.consume_pending(interaction.guild_id, interaction.user.id, int(time.time()))
        if cipher is None:
            return await reply(interaction, "No unclaimed phrase is available. Ask the owner to issue a new one if needed.")
        try:
            phrase = bot.fernet.decrypt(cipher).decode("utf-8")
        except InvalidToken:
            log.error("Pending secret could not be decrypted for guild=%s user=%s", interaction.guild_id, interaction.user.id)
            return await reply(interaction, "Your phrase could not be recovered. Ask the owner to replace it.")
    await reply(interaction,
        "**Your Umask phrase (shown once):**\n"
        f"`{phrase}`\n\n"
        "Write it down or store it somewhere outside Discord. This message is scheduled for deletion in ~60 seconds. "
        "Anyone controlling your Discord session **during collection** could potentially obtain it.",
        secret=True, title="Your authentication phrase")


class AuthenticationModal(discord.ui.Modal, title="Umask — Authenticate"):
    phrase = discord.ui.TextInput(label="Your 10-word authentication phrase",
                                  placeholder="Enter the ten words in order", style=discord.TextStyle.paragraph,
                                  min_length=10, max_length=160, required=True)

    def __init__(self, duration: int):
        super().__init__(timeout=180)
        self.duration = duration

    async def on_submit(self, interaction: discord.Interaction):
        if interaction.guild is None:
            return await reply(interaction, "Use this inside your server.")
        await interaction.response.defer(ephemeral=True, thinking=True)
        gid, uid = interaction.guild_id, interaction.user.id
        async with bot.lock(gid, uid):
            now = int(time.time())
            cfg = bot.store.config(gid)
            if not cfg:
                return await reply(interaction, "Umask is not configured.")
            if bot.privacy_ledger.guild_pending_erasure(gid, cfg['updated_at']):
                return await reply(interaction, "This server's Umask setup is pending deletion; authentication is disabled until it is reconfigured.")
            allowed = parse_durations(cfg['durations'])
            if self.duration not in allowed:
                return await reply(interaction, f"The owner permits: {', '.join(map(str, allowed))} minutes.")
            cred = bot.store.credential(gid, uid)
            if not cred:
                return await reply(interaction, "No credential exists for you. Ask the server owner.")
            if cred['locked_until'] > now:
                return await reply(interaction, "Too many incorrect attempts. Try again after the temporary lockout, or ask the owner to reissue your credential.")
            valid = await asyncio.to_thread(verify_phrase, cred['phrase_hash'], str(self.phrase.value))
            if not valid:
                locked = bot.store.failed_attempt(gid, uid, now)
                return await reply(interaction, "Incorrect phrase. " + ("Further attempts are temporarily locked." if locked else "Please try again."))
            bot.store.reset_attempts(gid, uid)
            role = interaction.guild.get_role(cfg['elevated_role_id'])
            if not role:
                return await reply(interaction, "The active role was deleted. Ask the owner to reconfigure the bot.")
            try:
                await bot.verify_bot_role(interaction.guild, role)
                member = await bot.get_member(interaction.guild, uid)
                if member is None:
                    raise ValueError("You are no longer in the server.")
                problem = permissions_issue(member, cfg['staff_role_id'], role)
                if problem:
                    raise ValueError(problem)
                current = bot.store.session(gid, uid)
                if current:
                    if current['expires_at'] > now:
                        raise ValueError("You already have an active session. Use `/signout` before authenticating again.")
                    raise ValueError("An earlier session is awaiting cleanup; try again in a minute.")
                if role.id in {r.id for r in member.roles}:
                    raise ValueError("Your active role is already assigned outside a tracked session. Ask the owner to investigate.")
                expiry = now + self.duration * 60
                # Serialise role grants with the persistent maintenance gate.
                # Otherwise a grant could finish after maintenance scans sessions.
                async with bot.shutdown_lock:
                    if bot._closing_gatekeeper or bot._shutdown_requested or bot.maintenance_mode:
                        raise ValueError("Umask is in maintenance or shutting down. New sessions are unavailable.")
                    # Persist BEFORE granting, so a crash leaves a record to reconcile.
                    bot.store.put_session(gid, uid, role.id, expiry, now, 'granting')
                    try:
                        await member.add_roles(role, reason=f"Umask verified session ({self.duration}m)")
                    except (discord.Forbidden, discord.HTTPException):
                        # Could be an ambiguous API/network failure: leave expired row for
                        # reconciliation rather than risking an untracked role.
                        bot.store.force_expire(gid, uid, "grant_failed")
                        raise
                    bot.store.mark_granted(gid, uid)
            except (ValueError, discord.HTTPException) as e:
                return await reply(interaction, f"Authentication succeeded but elevation was not completed: {e}")
        until = f"<t:{expiry}:R>"
        await reply(interaction, f"**Signed in.** {role.mention} granted until {until} "
                    f"({pretty_duration(self.duration)}). Use `/signout` to end early.",
                    title="Session active")


@bot.tree.command(name="authenticate", description="Staff: verify your phrase and request a timed active role")
@app_commands.guild_only()
@app_commands.describe(duration_minutes="Allowed number of minutes; leave blank for server default")
async def authenticate(interaction: discord.Interaction, duration_minutes: int | None = None):
    if bot._closing_gatekeeper or bot._shutdown_requested or bot.maintenance_mode:
        return await reply(interaction, "Umask is in maintenance or shutting down. New sessions are unavailable.")
    cfg = bot.store.config(interaction.guild_id)
    if not cfg:
        return await reply(interaction, "Umask is not configured on this server.")
    if bot.privacy_ledger.guild_pending_erasure(interaction.guild_id, cfg['updated_at']):
        return await reply(interaction, "The server's previous Umask setup is pending deletion.")
    allowed = parse_durations(cfg['durations'])
    duration = duration_minutes if duration_minutes is not None else (60 if 60 in allowed else allowed[0])
    if duration not in allowed:
        return await reply(interaction, f"Allowed durations: {', '.join(map(str, allowed))} minutes.")
    if not bot.store.credential(interaction.guild_id, interaction.user.id):
        return await reply(interaction, "You have no staff credential. Ask the server owner to run `/issue`.")
    await interaction.response.send_modal(AuthenticationModal(duration))


@bot.tree.command(name="signout", description="Staff: immediately relinquish your active permissions")
@app_commands.guild_only()
async def signout(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True, thinking=True)
    gid, uid = interaction.guild_id, interaction.user.id
    async with bot.lock(gid, uid):
        session = bot.store.session(gid, uid)
        if not session:
            return await reply(interaction, "You have no tracked active session.")
        role = interaction.guild.get_role(session['role_id'])
        try:
            member = await bot.get_member(interaction.guild, uid)
            if member and role and role.id in {r.id for r in member.roles}:
                await member.remove_roles(role, reason="Umask: voluntary staff sign-out")
            bot.store.end_session(gid, uid, "signed_out")
        except (discord.Forbidden, discord.HTTPException):
            bot.store.force_expire(gid, uid, "signed_out")
            return await reply(interaction, "Sign-out could not remove the role. The bot will retry every minute; contact the server owner immediately.")
    await reply(interaction, "Elevated permissions removed.", title="Signed out")


@bot.tree.command(name="revoke", description="Owner: invalidate someone's credential and remove any active role")
@app_commands.guild_only()
async def revoke(interaction: discord.Interaction, user: discord.User):
    if not require_owner(interaction):
        return await reply(interaction, "Only the server owner can revoke staff credentials.")
    await interaction.response.defer(ephemeral=True, thinking=True)
    gid, uid = interaction.guild_id, user.id
    async with bot.lock(gid, uid):
        # Fail closed immediately: even if Discord role removal fails, no login.
        bot.store.revoke_credential(gid, uid)
        session = bot.store.session(gid, uid)
        cfg = bot.store.config(gid)
        role_id = session['role_id'] if session else (cfg['elevated_role_id'] if cfg else None)
        role = interaction.guild.get_role(role_id) if role_id else None
        try:
            member = await bot.get_member(interaction.guild, uid)
            if member and role and role.id in {r.id for r in member.roles}:
                await member.remove_roles(role, reason="Umask: revoked by server owner")
            bot.store.end_session(gid, uid, "owner_revoked")
        except (discord.Forbidden, discord.HTTPException):
            if session:
                bot.store.force_expire(gid, uid, "owner_revoked")
            return await reply(interaction, "Credential invalidated, but Discord refused role removal. **Remove the role manually.** The bot will retry if a session was tracked.")
    await reply(interaction, f"Credential revoked for {safe_display_label(user.display_name, uid)}. "
                "Their tracked active role was removed if present.", title="Access revoked")


# Owner-only views are always ephemeral. No session reports are posted publicly.
# The store queries are scoped to interaction.guild_id, not a user-supplied guild.
HISTORY_REASONS = {
    "expired": "Expired",
    "signed_out": "Signed out",
    "owner_revoked": "Owner revoked",
    "bot_shutdown": "Bot shutdown",
    "operator_maintenance": "Operator maintenance",
    "staff_access_removed": "Staff role removed",
    "unsafe_role": "Unsafe role configuration",
    "role_deleted": "Elevated role deleted",
    "member_left": "Member left server",
    "role_removed_externally": "Role removed outside Umask",
    "grant_not_completed": "Grant not completed",
    "grant_failed": "Grant failed",
    "removed": "Removed",
}


def safe_display_label(name: str | None, user_id: int) -> str:
    """Human-readable audit label, never a raw mention or a ping.

    Embed field titles do not reliably resolve <@...> mention markup. Use
    a real display name (escaped as text) and keep the ID for disambiguation.
    """
    display = " ".join(str(name or "Unknown user").split())[:80] or "Unknown user"
    display = discord.utils.escape_markdown(discord.utils.escape_mentions(display))
    return f"{display} (`{user_id}`)"


async def resolve_user_label(guild: discord.Guild, user_id: int) -> str:
    """Find a server nickname without depending on the privileged members intent.

    For past members, fall back to global Discord user information, then ID.
    Errors here should never prevent a security dashboard from displaying.
    """
    member = guild.get_member(user_id)
    if member is None:
        try:
            member = await guild.fetch_member(user_id)
        except (discord.NotFound, discord.Forbidden, discord.HTTPException):
            pass
    if member is not None:
        return safe_display_label(member.display_name, user_id)
    user = bot.get_user(user_id)
    if user is None:
        try:
            user = await bot.fetch_user(user_id)
        except (discord.NotFound, discord.Forbidden, discord.HTTPException):
            pass
    name = (getattr(user, "global_name", None) or getattr(user, "name", None)) if user else None
    return safe_display_label(name, user_id)


# A single read-only command provides all owner-facing information. Each view is
# ephemeral and anchored to the guild and the Discord server owner who opened it.
# /setup, /issue, /revoke intentionally remain separate write operations.
STATUS_PAGE_SIZE = 6
STATUS_SECTIONS = ("overview", "credentials", "active", "history")


def paginate_total(total: int, page: int, per_page: int = STATUS_PAGE_SIZE) -> tuple[int, int]:
    """Return (clamped current page, total pages), including for empty lists."""
    pages = max(1, (total + per_page - 1) // per_page)
    return max(1, min(page, pages)), pages


class OwnerStatusView(discord.ui.View):
    def __init__(self, guild: discord.Guild, requester_id: int):
        super().__init__(timeout=300)
        self.guild = guild
        self.guild_id = guild.id
        self.requester_id = requester_id
        self.section = "overview"
        self.page = 1
        self.message: discord.InteractionMessage | None = None
        self._update_controls(1)

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if (interaction.guild_id != self.guild_id
                or interaction.user.id != self.requester_id
                or not require_owner(interaction)):
            await interaction.response.send_message(
                "This dashboard is private to the server owner who opened it.", ephemeral=True)
            return False
        return True

    def _update_controls(self, pages: int) -> None:
        for component in self.children:
            if isinstance(component, discord.ui.Button):
                if component.custom_id == "umask:previous":
                    component.disabled = self.section == "overview" or self.page <= 1
                elif component.custom_id == "umask:next":
                    component.disabled = self.section == "overview" or self.page >= pages
                elif component.custom_id.startswith("umask:tab:"):
                    current = component.custom_id.rsplit(":", 1)[1]
                    component.style = (discord.ButtonStyle.primary if current == self.section
                                       else discord.ButtonStyle.secondary)
                    component.disabled = current == self.section

    async def _labels(self, user_ids) -> dict[int, str]:
        ids = sorted(set(int(uid) for uid in user_ids))
        labels = await asyncio.gather(*(resolve_user_label(self.guild, uid) for uid in ids))
        return dict(zip(ids, labels))

    async def render(self) -> discord.Embed:
        cfg = bot.store.config(self.guild_id)
        gid = self.guild_id
        now = int(time.time())
        if not cfg:
            self.section = "overview"
            self.page = 1
            self._update_controls(1)
            e = brand_embed("Server overview", "Not configured yet. Run `/setup` to start.", logo=True)
            e.set_footer(text="Owner-only dashboard · private to you")
            return e
        if self.section == "overview":
            self.page = 1
            active = bot.store.count_sessions(gid)
            credentials = bot.store.count_credentials(gid)
            completed = bot.store.count_history(gid)
            e = brand_embed("Server overview", "Staff access and authentication activity at a glance.", logo=True)
            e.add_field(name="Issued credentials", value=f"**{credentials}**", inline=True)
            e.add_field(name="Tracked sessions", value=f"**{active}**", inline=True)
            e.add_field(name="Completed sessions", value=f"**{completed}**", inline=True)
            staff = self.guild.get_role(cfg['staff_role_id'])
            elevated = self.guild.get_role(cfg['elevated_role_id'])
            e.add_field(name="Permanent staff role", value=staff.mention if staff else "⚠️ Missing role", inline=True)
            e.add_field(name="Elevated role", value=elevated.mention if elevated else "⚠️ Missing role", inline=True)
            try:
                duration_text = ", ".join(pretty_duration(x) for x in parse_durations(cfg['durations']))
            except ValueError:
                duration_text = "Invalid configuration — review `/setup`"
            e.add_field(name="Allowed sessions", value=duration_text, inline=False)
            current = bot.store.sessions_for_guild(gid, 3)
            if current:
                lines = []
                labels = await self._labels(r['user_id'] for r in current)
                for r in current:
                    if r['termination_reason'] or r['expires_at'] <= now:
                        state = "**Removal pending**"
                    elif r['state'] == 'granting':
                        state = "**Grant pending**"
                    else:
                        state = f"ends <t:{r['expires_at']}:R>"
                    lines.append(f"{labels[r['user_id']]} · {state}")
                e.add_field(name="Current sessions", value="\n".join(lines), inline=False)
            e.set_footer(text="Owner-only · Select a section below to browse records")
            pages = 1
        elif self.section == "credentials":
            total = bot.store.count_credentials(gid)
            self.page, pages = paginate_total(total, self.page)
            entries = bot.store.credentials_for_guild(gid, STATUS_PAGE_SIZE,
                                                       (self.page - 1) * STATUS_PAGE_SIZE)
            e = brand_embed("Issued credentials",
                            "Staff authorised to sign in. **Secret phrases and hashes are never displayed.**",
                            logo=True)
            if entries:
                labels = await self._labels(r['user_id'] for r in entries)
                for r in entries:
                    e.add_field(name=labels[r['user_id']],
                                value=(f"Issued <t:{r['issued_at']}:f>\n{credential_state(r, now)}"),
                                inline=False)
            else:
                e.description += "\n\nNo credentials issued. Use `/issue` to authorise staff."
            e.set_footer(text=f"{total} issued · Page {self.page}/{pages} · Owner only")
        elif self.section == "active":
            total = bot.store.count_sessions(gid)
            self.page, pages = paginate_total(total, self.page)
            entries = bot.store.sessions_for_guild(gid, STATUS_PAGE_SIZE,
                                                    (self.page - 1) * STATUS_PAGE_SIZE)
            e = brand_embed("Active sessions", "Includes sessions awaiting role removal.", logo=True)
            if entries:
                labels = await self._labels(r['user_id'] for r in entries)
                for r in entries:
                    reason = r['termination_reason']
                    if reason or r['expires_at'] <= now:
                        state = f"Removal pending · {HISTORY_REASONS.get(reason, reason or 'Expired')}"
                    elif r['state'] == "granting":
                        state = "Role assignment pending"
                    else:
                        state = f"Expires <t:{r['expires_at']}:R>"
                    e.add_field(name=labels[r['user_id']],
                                value=f"{state}\nStarted <t:{r['started_at']}:f> · Scheduled end <t:{r['expires_at']}:f>",
                                inline=False)
            else:
                e.description += "\n\nNo tracked active sessions."
            e.set_footer(text=f"{total} tracked · Page {self.page}/{pages} · Owner only")
        else:
            total = bot.store.count_history(gid)
            self.page, pages = paginate_total(total, self.page)
            entries = bot.store.history_for_guild(gid, STATUS_PAGE_SIZE,
                                                   (self.page - 1) * STATUS_PAGE_SIZE)
            e = brand_embed("Session history", "Completed sessions and how they ended.", logo=True)
            if entries:
                labels = await self._labels(r['user_id'] for r in entries)
                for r in entries:
                    reason = HISTORY_REASONS.get(r['end_reason'],
                                                 r['end_reason'].replace("_", " ").title())
                    e.add_field(name=f"{labels[r['user_id']]} · {reason}",
                                value=f"Started <t:{r['started_at']}:f>\nEnded <t:{r['ended_at']}:f>",
                                inline=False)
            else:
                e.description += "\n\nNo completed sessions recorded yet."
            e.set_footer(text=f"{total} completed · Page {self.page}/{pages} · Owner only")
        self._update_controls(pages)
        return e

    async def switch(self, interaction: discord.Interaction, section: str):
        self.section = section
        self.page = 1
        await interaction.response.defer()
        await interaction.edit_original_response(content=None, embed=await self.render(), view=self)

    @discord.ui.button(label="Overview", style=discord.ButtonStyle.primary,
                       row=0, custom_id="umask:tab:overview")
    async def overview(self, interaction: discord.Interaction, button: discord.ui.Button):
        await self.switch(interaction, "overview")

    @discord.ui.button(label="Credentials", style=discord.ButtonStyle.secondary,
                       row=0, custom_id="umask:tab:credentials")
    async def credentials_tab(self, interaction: discord.Interaction, button: discord.ui.Button):
        await self.switch(interaction, "credentials")

    @discord.ui.button(label="Active", style=discord.ButtonStyle.secondary,
                       row=0, custom_id="umask:tab:active")
    async def active_tab(self, interaction: discord.Interaction, button: discord.ui.Button):
        await self.switch(interaction, "active")

    @discord.ui.button(label="History", style=discord.ButtonStyle.secondary,
                       row=0, custom_id="umask:tab:history")
    async def history_tab(self, interaction: discord.Interaction, button: discord.ui.Button):
        await self.switch(interaction, "history")

    @discord.ui.button(label="Previous", style=discord.ButtonStyle.secondary,
                       row=1, custom_id="umask:previous")
    async def previous(self, interaction: discord.Interaction, button: discord.ui.Button):
        self.page = max(1, self.page - 1)
        await interaction.response.defer()
        await interaction.edit_original_response(content=None, embed=await self.render(), view=self)

    @discord.ui.button(label="Next", style=discord.ButtonStyle.secondary,
                       row=1, custom_id="umask:next")
    async def next(self, interaction: discord.Interaction, button: discord.ui.Button):
        self.page += 1
        await interaction.response.defer()
        await interaction.edit_original_response(content=None, embed=await self.render(), view=self)

    @discord.ui.button(label="Refresh", style=discord.ButtonStyle.secondary,
                       row=1, custom_id="umask:refresh")
    async def refresh(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.defer()
        await interaction.edit_original_response(content=None, embed=await self.render(), view=self)

    @discord.ui.button(label="Close", style=discord.ButtonStyle.secondary,
                       row=1, custom_id="umask:close")
    async def close(self, interaction: discord.Interaction, button: discord.ui.Button):
        self.stop()
        await interaction.response.edit_message(
            content=None, embed=brand_embed("Dashboard closed", "Run `/status` to open it again."),
            view=None, attachments=[])

    async def on_timeout(self):
        # Rendering updates tab styles and pagination, which may re-enable buttons.
        # Render first, then disable every control before sending the final edit.
        embed = await self.render()
        for item in self.children:
            item.disabled = True
        if self.message:
            try:
                await self.message.edit(embed=embed, view=self)
            except discord.HTTPException:
                pass


def credential_state(row, now: int, *, personal: bool = False) -> str:
    """Describe collection *separately* from credential validity.

    Older databases use NULL for unknown collection state. Zero indicates
    that the current issued phrase was never collected through /receive.
    """
    collected_at = row['collected_at']
    if collected_at is not None and collected_at > 0:
        return f"Collected <t:{collected_at}:R>"
    pending_copy = (row['has_pending_copy'] if 'has_pending_copy' in row.keys()
                    else row['pending_secret'] is not None)
    deadline = row['pending_until']
    if pending_copy and deadline and deadline > now:
        return (f"Issued — not yet collected. Run `/receive` before <t:{deadline}:R>."
                if personal else f"Awaiting collection · available until <t:{deadline}:R>")
    if collected_at == 0:
        return ("Issued, but never collected through `/receive`. The collection window has expired. "
                "Ask the server owner to issue a replacement if you don't have the phrase."
                if personal else "Not collected · collection window expired")
    return ("Issued — collection status unknown (older credential). "
            "If you don't have your phrase, ask the owner to replace it."
            if personal else "Collection status unknown · older credential")



# Discord application owner only. Every interaction including modals and
# confirmation buttons checks the invoker's identity again; buttons are not
# trusted merely because they originated in an ephemeral message.
class GuildOwnershipModal(discord.ui.Modal, title='Verify Discord server owner'):
    guild_id_text = discord.ui.TextInput(label='Server ID', placeholder='Discord guild ID', max_length=20)
    owner_id_text = discord.ui.TextInput(label='User ID to check', placeholder='Discord user ID', max_length=20)

    def __init__(self, requester_id: int):
        super().__init__(timeout=180)
        self.requester_id = requester_id

    async def on_submit(self, interaction: discord.Interaction):
        if interaction.user.id != self.requester_id or not await bot.is_owner(interaction.user):
            return await reply(interaction, 'Only the Discord application owner may verify guild ownership.')
        try:
            gid = int(str(self.guild_id_text.value).strip())
            uid = int(str(self.owner_id_text.value).strip())
            if gid <= 0 or uid <= 0:
                raise ValueError()
        except ValueError:
            return await reply(interaction, 'Enter valid numeric Discord server and user IDs.')
        guild = bot.get_guild(gid)
        if guild is None:
            return await reply(interaction, 'Umask is not currently in that server (or it is not available in the bot cache).', title='Ownership check')
        match = guild.owner_id == uid
        e = brand_embed('Ownership check',
                        f'Server: **{discord.utils.escape_markdown(discord.utils.escape_mentions(guild.name))}** (`{gid}`)\n'
                        f'User ID: `{uid}`\n\n'
                        + ('**Match — this is the server owner.**' if match else '**Not a match — that user is not the server owner.**'),
                        accent='primary' if match else 'warning')
        await interaction.response.send_message(embed=e, ephemeral=True)


class MaintenanceConfirmation(discord.ui.View):
    def __init__(self, requester_id: int, custom_message: str):
        super().__init__(timeout=60)
        self.requester_id = requester_id
        self.custom_message = custom_message

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id != self.requester_id or not await bot.is_owner(interaction.user):
            await interaction.response.send_message('This confirmation is restricted to the application owner.', ephemeral=True)
            return False
        return True

    @discord.ui.button(label='Confirm maintenance', style=discord.ButtonStyle.danger)
    async def confirm(self, interaction: discord.Interaction, button: discord.ui.Button):
        self.stop()
        await interaction.response.defer(ephemeral=True, thinking=True)
        try:
            result = await bot.prepare_maintenance(self.custom_message)
            pending = ('Could not verify; check storage and role assignments.' if result['pending'] < 0
                       else str(result['pending']))
            e = brand_embed('Maintenance enabled',
                'New elevations are blocked, including after a PebbleHost restart.\n'
                f'Tracked sessions still needing confirmation: **{pending}**\n'
                f'Server notices delivered: **{result["sent"]}**; failed: **{result["failed"]}**.\n\n'
                '**To stop the process, use PebbleHost’s Stop button.** '
                'Use `/status` to resume manually after checking pending roles.', accent='warning')
        except ValueError as exc:
            e = brand_embed('Cannot enter maintenance', str(exc), accent='warning')
        except Exception:
            log.exception('Unexpected maintenance activation failure')
            e = brand_embed('Maintenance error',
                            'Check the PebbleHost console. Maintenance may already be enabled; '
                            'verify with `/status` before taking further action.', accent='warning')
        await interaction.edit_original_response(embed=e, view=None)

    @discord.ui.button(label='Cancel', style=discord.ButtonStyle.secondary)
    async def cancel(self, interaction: discord.Interaction, button: discord.ui.Button):
        self.stop()
        await interaction.response.edit_message(
            embed=brand_embed('Cancelled', 'Umask remains unchanged.'), view=None)


class MaintenanceMessageModal(discord.ui.Modal, title='Prepare Umask for maintenance'):
    note = discord.ui.TextInput(label='Optional message to all configured servers',
                                placeholder='Short operator notice (optional)',
                                style=discord.TextStyle.paragraph,
                                required=False, max_length=500)

    def __init__(self, requester_id: int):
        super().__init__(timeout=180)
        self.requester_id = requester_id

    async def on_submit(self, interaction: discord.Interaction):
        if interaction.user.id != self.requester_id or not await bot.is_owner(interaction.user):
            return await reply(interaction, 'This maintenance action is restricted to the application owner.')
        if bot.maintenance_mode:
            return await reply(interaction, 'Umask is already in maintenance mode.')
        note = str(self.note.value or '').strip()
        view = MaintenanceConfirmation(interaction.user.id, note)
        preview = discord.utils.escape_mentions(discord.utils.escape_markdown(note))[:550] if note else 'No custom message.'
        e = brand_embed('Confirm service-wide maintenance',
            'This will persistently **block new elevated sessions**, attempt to revoke '
            '**all tracked roles**, and post a notice to **every configured alert channel**.\n\n'
            'This does **not** shut down the PebbleHost process. Any unresolved roles '
            'must be removed manually; the bot will keep retrying.\n\n'
            f'**Your additional operator message:**\n{preview}', accent='warning')
        await interaction.response.send_message(embed=e, view=view, ephemeral=True)


class ResumeConfirmation(discord.ui.View):
    def __init__(self, requester_id: int):
        super().__init__(timeout=45)
        self.requester_id = requester_id

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id != self.requester_id or not await bot.is_owner(interaction.user):
            await interaction.response.send_message('Only the application owner may resume service.', ephemeral=True)
            return False
        return True

    @discord.ui.button(label='Resume Umask', style=discord.ButtonStyle.danger)
    async def confirm(self, interaction: discord.Interaction, button: discord.ui.Button):
        self.stop()
        try:
            await bot.resume_from_maintenance()
            e = brand_embed('Umask resumed', 'New staff authentication sessions are available again.')
        except ValueError as exc:
            e = brand_embed('Cannot resume', str(exc), accent='warning')
        await interaction.response.edit_message(embed=e, view=None)

    @discord.ui.button(label='Cancel', style=discord.ButtonStyle.secondary)
    async def cancel(self, interaction: discord.Interaction, button: discord.ui.Button):
        self.stop()
        await interaction.response.edit_message(embed=brand_embed('Unchanged', 'Umask remains in maintenance.'), view=None)


class OperatorStatusView(discord.ui.View):
    def __init__(self, guild: discord.Guild, requester_id: int):
        super().__init__(timeout=300)
        self.guild = guild
        self.requester_id = requester_id
        self.section = 'overview'
        self.message: discord.InteractionMessage | None = None
        self._sync_buttons()

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id != self.requester_id or not await bot.is_owner(interaction.user):
            await interaction.response.send_message('This dashboard is private to the Discord application owner.', ephemeral=True)
            return False
        return True

    def _sync_buttons(self):
        for item in self.children:
            if isinstance(item, discord.ui.Button):
                if item.custom_id in {'umask:operator:overview', 'umask:operator:maintenance'}:
                    selected = item.custom_id.rsplit(':', 1)[-1] == self.section
                    item.style = discord.ButtonStyle.primary if selected else discord.ButtonStyle.secondary
                if item.custom_id == 'umask:operator:prepare':
                    item.disabled = bot.maintenance_mode
                elif item.custom_id == 'umask:operator:resume':
                    item.disabled = not bot.maintenance_mode
                elif item.custom_id == 'umask:operator:server':
                    item.disabled = self.guild.owner_id != self.requester_id

    async def render(self) -> discord.Embed:
        self._sync_buttons()
        if self.section == 'maintenance':
            state = '**Enabled**' if bot.maintenance_mode else '**Normal operation**'
            e = brand_embed('Service maintenance',
                f'Status: {state}\n'
                'Preparation blocks new sign-ins, attempts to revoke all tracked roles, '
                'and announces maintenance to configured channels.\n\n'
                'Stopping the process is done in **PebbleHost → Stop**; '
                'restarting the process does not turn maintenance off.\n\n'
                '**Resume** must be explicitly confirmed after any pending roles are cleared.', accent='warning')
            if bot.maintenance_state.activated_at:
                e.add_field(name='Enabled at', value=f'<t:{bot.maintenance_state.activated_at}:f>')
            try:
                e.add_field(name='Tracked roles still pending', value=str(len(bot.store.all_sessions())))
            except Exception:
                e.add_field(name='Tracked roles still pending', value='Storage unavailable')
            return e
        e = brand_embed('Application overview', 'Private operational status across Umask servers.')
        e.add_field(name='Connected servers', value=str(len(bot.guilds)), inline=True)
        e.add_field(name='Process uptime', value=human_uptime(time.monotonic()-bot.process_started), inline=True)
        e.add_field(name='Gateway latency',
                    value=f'{bot.latency * 1000:.0f} ms' if bot.latency >= 0 and bot.is_ready() else 'Not connected',
                    inline=True)
        try:
            configs = len(set(bot.store.configured_guild_ids()) & {guild.id for guild in bot.guilds})
            tracked = bot.store.all_sessions()
            e.add_field(name='Configured servers', value=str(configs), inline=True)
            e.add_field(name='Tracked active / pending', value=str(len(tracked)), inline=True)
        except Exception:
            e.add_field(name='Database', value='Unavailable — check logs', inline=False)
        e.add_field(name='Database backend', value=('MySQL' if isinstance(bot.store, MySQLStore) else 'SQLite'), inline=True)
        e.add_field(name='Maintenance', value='ON — sign-ins disabled' if bot.maintenance_mode else 'Off', inline=True)
        e.add_field(name='Session reconciliation',
                    value=f'<t:{bot.last_reconciliation_at}:R>' if bot.last_reconciliation_at else 'Not completed yet', inline=True)
        e.add_field(name='Daily housekeeping',
                    value=f'<t:{bot.last_maintenance_at}:R>' if bot.last_maintenance_at else 'Not completed yet', inline=True)
        if isinstance(bot.store, Store):
            snapshots = sorted(Path(os.getenv('LOCAL_BACKUP_DIR', './backups')).glob('umask-????-??-??.sqlite3'))
            e.add_field(name='Latest local SQLite snapshot',
                        value=(snapshots[-1].stem.removeprefix('umask-') if snapshots else 'None found yet'), inline=True)
        e.set_footer(text='Application owner only · Data available from this running process')
        return e

    async def switch(self, interaction: discord.Interaction, section: str):
        self.section = section
        await interaction.response.defer()
        await interaction.edit_original_response(embed=await self.render(), view=self)

    @discord.ui.button(label='Overview', style=discord.ButtonStyle.primary,
                       row=0, custom_id='umask:operator:overview')
    async def overview(self, interaction: discord.Interaction, button: discord.ui.Button):
        await self.switch(interaction, 'overview')

    @discord.ui.button(label='Maintenance / shutdown', style=discord.ButtonStyle.secondary,
                       row=0, custom_id='umask:operator:maintenance')
    async def maintenance(self, interaction: discord.Interaction, button: discord.ui.Button):
        await self.switch(interaction, 'maintenance')

    @discord.ui.button(label='Check guild owner', style=discord.ButtonStyle.secondary,
                       row=0, custom_id='umask:operator:check-owner')
    async def check_owner(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.send_modal(GuildOwnershipModal(interaction.user.id))

    @discord.ui.button(label='This server', style=discord.ButtonStyle.secondary,
                       row=0, custom_id='umask:operator:server')
    async def server_dashboard(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not require_owner(interaction):
            return await reply(interaction, 'You do not own this Discord server.')
        view = OwnerStatusView(interaction.guild, interaction.user.id)
        await interaction.response.defer(ephemeral=True, thinking=True)
        await interaction.followup.send(embed=await view.render(), view=view, ephemeral=True)

    @discord.ui.button(label='Prepare shutdown', style=discord.ButtonStyle.danger,
                       row=1, custom_id='umask:operator:prepare')
    async def prepare(self, interaction: discord.Interaction, button: discord.ui.Button):
        if bot.maintenance_mode:
            return await reply(interaction, 'Umask is already in maintenance mode.')
        await interaction.response.send_modal(MaintenanceMessageModal(interaction.user.id))

    @discord.ui.button(label='Resume service', style=discord.ButtonStyle.secondary,
                       row=1, custom_id='umask:operator:resume')
    async def resume(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.send_message(
            embed=brand_embed('Confirm resume', 'Resume issuing and granting elevated sessions? '
                             'Make sure all previously tracked roles have been cleared.', accent='warning'),
            view=ResumeConfirmation(interaction.user.id), ephemeral=True)

    @discord.ui.button(label='Refresh', style=discord.ButtonStyle.secondary,
                       row=1, custom_id='umask:operator:refresh')
    async def refresh(self, interaction: discord.Interaction, button: discord.ui.Button):
        await self.switch(interaction, self.section)

    @discord.ui.button(label='Close', style=discord.ButtonStyle.secondary,
                       row=1, custom_id='umask:operator:close')
    async def close(self, interaction: discord.Interaction, button: discord.ui.Button):
        self.stop()
        await interaction.response.edit_message(embed=brand_embed('Dashboard closed',
                                                 'Run `/status` to open it again.'), view=None)

    async def on_timeout(self):
        for item in self.children:
            item.disabled = True
        if self.message:
            try:
                await self.message.edit(view=self)
            except discord.HTTPException:
                pass


@bot.tree.command(name="status", description="Your access, or the owner's private server dashboard")
@app_commands.guild_only()
async def status(interaction: discord.Interaction):
    if await bot.is_owner(interaction.user):
        view = OperatorStatusView(interaction.guild, interaction.user.id)
        await interaction.response.defer(ephemeral=True, thinking=True)
        attachment = logo_attachment()
        await interaction.edit_original_response(
            embed=await view.render(), view=view,
            attachments=[attachment] if attachment else [])
        try:
            view.message = await interaction.original_response()
        except discord.HTTPException:
            pass
        return
    cfg = bot.store.config(interaction.guild_id)
    if require_owner(interaction):
        view = OwnerStatusView(interaction.guild, interaction.user.id)
        await interaction.response.defer(ephemeral=True, thinking=True)
        e = await view.render()
        attachment = logo_attachment()
        await interaction.edit_original_response(
            embed=e, view=view, attachments=[attachment] if attachment else [])
        try:
            view.message = await interaction.original_response()
        except discord.HTTPException:
            pass
        return
    if not cfg:
        return await reply(interaction, "This server has not configured Umask yet. Ask its owner to run `/setup`.")
    sess = bot.store.session(interaction.guild_id, interaction.user.id)
    credential = bot.store.credential(interaction.guild_id, interaction.user.id)
    role = interaction.guild.get_role(cfg['elevated_role_id'])
    embed = brand_embed("Your access", "Your staff authentication status is private to you.")
    now = int(time.time())
    if credential is None:
        credential_label = "Not issued — ask the owner to run `/issue`."
    else:
        credential_label = credential_state(credential, now, personal=True)
    embed.add_field(name="Credential", value=credential_label, inline=False)
    if sess and not sess['termination_reason'] and sess['expires_at'] > now and sess['state'] == 'active':
        session_label = f"Active · expires <t:{sess['expires_at']}:R>"
    elif sess:
        session_label = "Pending cleanup"
    else:
        session_label = "Not signed in"
    embed.add_field(name="Session", value=session_label, inline=True)
    embed.add_field(name="Elevated role", value=role.mention if role else "Missing role", inline=False)
    embed.set_footer(text="/authenticate to sign in · /signout to end a session")
    await interaction.response.send_message(embed=embed, ephemeral=True)


@bot.tree.error
async def command_error(interaction: discord.Interaction, error: app_commands.AppCommandError):
    # Never print command inputs: future commands may include secrets.
    log.error("Command error in guild=%s user=%s type=%s", interaction.guild_id, interaction.user.id, type(error).__name__)
    try:
        await reply(interaction, "Something went wrong. No successful permission change was confirmed. Check the bot logs and use `/status`.")
    except discord.HTTPException:
        pass


def main():
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s %(message)s")
    token = os.environ.get("DISCORD_TOKEN")
    if not token:
        raise RuntimeError("Set DISCORD_TOKEN in .env (see .env.example)")
    bot.run(token, log_handler=None)


if __name__ == "__main__":
    main()
