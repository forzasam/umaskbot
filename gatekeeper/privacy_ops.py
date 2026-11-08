"""Application-owner-only privacy case tools, installed in a designated private guild.

These tools are NOT a user-facing request method. Site form/email/tickets
produce requests that a human verifies and reviews before touching this UI.
"""
import re
import time
import discord
from discord import app_commands


SNOWFLAKE = re.compile(r'^\d{15,21}$')
CASE_REF = re.compile(r'^[A-Za-z0-9_-]{4,64}$')


def parsed_id(text: str) -> int:
    if not SNOWFLAKE.fullmatch(text.strip()):
        raise ValueError('Enter a Discord numeric ID (not a username or mention).')
    value = int(text)
    if value >= 2**64:
        raise ValueError('Discord ID out of range')
    return value


def checked_ref(reference: str) -> str:
    if not CASE_REF.fullmatch(reference):
        raise ValueError('Use a 4–64 character private ticket reference (letters, numbers, - or _).')
    return reference


def register_privacy_ops(bot, guild_id: int):
    ops = app_commands.Group(name='privacy_ops', description='Private operator privacy case tools')

    async def permitted(interaction):
        if interaction.guild_id != guild_id or not await bot.is_owner(interaction.user):
            await interaction.response.send_message('Not authorised.', ephemeral=True)
            return False
        return True

    async def rejection(interaction, error):
        await interaction.response.send_message(str(error), ephemeral=True)

    @ops.command(name='review_user', description='Count and inspect identifiers for a verified user request')
    async def review_user(interaction: discord.Interaction, user_id: str, guild_id: str = ''):
        if not await permitted(interaction): return
        try:
            uid = parsed_id(user_id); gid = parsed_id(guild_id) if guild_id else None
            data = bot.store.privacy_counts(guild_id=gid, user_id=uid)
            text = f'User {uid}; server {gid or "ALL"}\n' + '\n'.join(f'{k}: {v}' for k,v in data.items())
            if gid is not None:
                rows = bot.store.history_rows_for_review(gid,uid)
                text += '\nRecent history IDs: ' + (', '.join(str(r['id']) for r in rows) or 'none')
            await interaction.response.send_message(f'```{text}```',ephemeral=True)
        except ValueError as exc:
            await rejection(interaction, exc)

    @ops.command(name='review_guild', description='Count records for a proposed server-wide deletion')
    async def review_guild(interaction: discord.Interaction, guild_id: str):
        if not await permitted(interaction): return
        try:
            gid=parsed_id(guild_id)
            data=bot.store.privacy_counts(guild_id=gid)
            guild=bot.get_guild(gid)
            extra=f'Known owner ID: {guild.owner_id}' if guild else 'Bot is not in this guild — ownership cannot be verified live'
            await interaction.response.send_message(
                f'Guild {gid}\n{extra}\n'+ '\n'.join(f'{k}: {v}' for k,v in data.items()),ephemeral=True)
        except ValueError as exc:
            await rejection(interaction,exc)

    @ops.command(name='hold_history', description='Hold one record after a documented case-by-case review')
    async def hold_history(interaction: discord.Interaction, guild_id: str, user_id: str,
                           history_id: int, days: int, case_ref: str):
        if not await permitted(interaction): return
        try:
            gid=parsed_id(guild_id); uid=parsed_id(user_id); ref=checked_ref(case_ref)
            if not 1 <= days <= 180:
                raise ValueError('Holds must last 1–180 days; any extension needs fresh review.')
            ok=bot.store.hold_history(history_id,gid,uid,int(time.time())+days*86400,ref)
            await interaction.response.send_message(
                'Time-limited hold recorded for one history record. Review necessity before extending.' if ok
                else 'No matching history row found.',ephemeral=True)
        except ValueError as exc:
            await rejection(interaction,exc)

    @ops.command(name='release_history', description='Release a previously approved case-specific hold')
    async def release_history(interaction: discord.Interaction, guild_id: str, user_id: str, history_id: int):
        if not await permitted(interaction): return
        try:
            gid=parsed_id(guild_id); uid=parsed_id(user_id)
            ok=bot.store.release_history(history_id,gid,uid)
            bot.privacy_ledger.apply(bot.store)
            await interaction.response.send_message('Hold released; pending erasures reapplied.' if ok else
                                                    'No matching row found.',ephemeral=True)
        except ValueError as exc:
            await rejection(interaction,exc)

    @ops.command(name='erase_user', description='Execute a verified, reviewed user erasure (not a request form)')
    async def erase_user(interaction: discord.Interaction, user_id: str, case_ref: str,
                         confirmation: str, guild_id: str = ''):
        if not await permitted(interaction): return
        try:
            uid=parsed_id(user_id); gid=parsed_id(guild_id) if guild_id else None
            ref=checked_ref(case_ref)
            if confirmation != f'ERASE USER {uid}':
                raise ValueError(f'Type exactly: ERASE USER {uid}')
            await interaction.response.defer(ephemeral=True, thinking=True)
            bot.privacy_ledger.append('erase_user',user_id=uid,guild_id=gid,case_ref=ref)
            await bot.reconcile()
            counts=bot.store.privacy_counts(user_id=uid,guild_id=gid)
            await interaction.followup.send(
                'Erasure instruction recorded and applied where safe. '
                'Any remaining active sessions require successful role revocation; '
                'case-specific history holds remain pending review. '\
                + f'Current counts: {counts}. Review these before replying to requester.',ephemeral=True)
        except ValueError as exc:
            await rejection(interaction,exc)

    @ops.command(name='erase_history', description='Erase eligible history only, preserving credentials and sessions')
    async def erase_history(interaction: discord.Interaction, user_id: str, case_ref: str,
                            confirmation: str, guild_id: str = ''):
        if not await permitted(interaction): return
        try:
            uid=parsed_id(user_id); gid=parsed_id(guild_id) if guild_id else None
            ref=checked_ref(case_ref)
            if confirmation != f'ERASE HISTORY {uid}':
                raise ValueError(f'Type exactly: ERASE HISTORY {uid}')
            await interaction.response.defer(ephemeral=True, thinking=True)
            bot.privacy_ledger.append('erase_history',user_id=uid,guild_id=gid,case_ref=ref)
            bot.privacy_ledger.apply(bot.store)
            counts=bot.store.privacy_counts(user_id=uid,guild_id=gid)
            await interaction.followup.send(
                f'History-only erasure recorded. Current counts: {counts}. '
                'Credential and active sessions were not affected; valid case holds are preserved.',ephemeral=True)
        except ValueError as exc:
            await rejection(interaction,exc)

    @ops.command(name='erase_guild', description='Execute a verified owner-approved guild erasure')
    async def erase_guild(interaction: discord.Interaction, guild_id: str,
                          verified_owner_id: str, case_ref: str, confirmation: str):
        if not await permitted(interaction): return
        try:
            gid=parsed_id(guild_id); owner=parsed_id(verified_owner_id); ref=checked_ref(case_ref)
            guild=bot.get_guild(gid)
            if guild is None or guild.owner_id != owner:
                raise ValueError('Cannot confirm live guild owner ID; do not execute this operation.')
            if confirmation != f'ERASE GUILD {gid}':
                raise ValueError(f'Type exactly: ERASE GUILD {gid}')
            await interaction.response.defer(ephemeral=True, thinking=True)
            bot.privacy_ledger.append('erase_guild',guild_id=gid,case_ref=ref)
            await bot.reconcile()
            counts=bot.store.privacy_counts(guild_id=gid)
            await interaction.followup.send(
                f'Server erasure instruction recorded. Current counts: {counts}. '
                'Do not report full deletion until pending sessions are zero and holds are assessed.',ephemeral=True)
        except ValueError as exc:
            await rejection(interaction,exc)

    bot.tree.add_command(ops, guild=discord.Object(id=guild_id))
