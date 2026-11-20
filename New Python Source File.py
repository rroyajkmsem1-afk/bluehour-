import asyncio
from collections import defaultdict, deque
from datetime import datetime, timezone
import time
import discord
from discord import app_commands
from discord.ext import commands

# --- CONFIGURATION DEFAULTS ---
TOKEN = "MTU2MjQ2MDM0ODIzNjQzNTQ2Ng.GVu5Jf.0Um2-ifrR8Jdg3LEaIFPuG9Dzq13h4vJ6A2NiY"
LOG_CHANNEL_ID = 1569424448862556220  # Dedicated audit log channel ID

# Thresholds: (Max actions, Time window in seconds)
LIMITS = {
    "channel_delete": (3, 60),
    "role_delete": (3, 60),
    "member_ban": (3, 60),
    "member_kick": (3, 60),
}

# Beast Mode Configuration
GLOBAL_SCORE_THRESHOLD = 5
GLOBAL_SCORE_WINDOW = 60  # seconds

# Anti-Raid Thresholds
MIN_ACCOUNT_AGE_DAYS = 3
JOIN_BURST_WINDOW = 10
JOIN_BURST_MAX = 5

intents = discord.Intents.default()
intents.members = True
intents.message_content = True
intents.guilds = True

# Disable default prefix handling to enforce Slash Commands ONLY
bot = commands.Bot(command_prefix=[], intents=intents, help_command=None)

# In-memory stores
action_tracker = defaultdict(lambda: defaultdict(deque))
recent_joins = deque()
global_threat_scores = deque()
whitelisted_users = set()


# =====================================================================
#                          CORE DEFENSE ENGINE
# =====================================================================

async def send_security_log(guild: discord.Guild, title: str, description: str, color: discord.Color):
    """Sends embeds to the designated security log channel."""
    channel = guild.get_channel(LOG_CHANNEL_ID)
    if channel:
        embed = discord.Embed(
            title=title,
            description=description,
            color=color,
            timestamp=datetime.now(timezone.utc)
        )
        embed.set_footer(text="Aegis Security Engine")
        await channel.send(embed=embed)


async def execute_punishment(guild: discord.Guild, user: discord.Member, reason: str):
    """Strips administrative roles and applies a quarantine timeout."""
    if user.id in whitelisted_users or user.id == guild.owner_id:
        return

    try:
        # Strip roles granting hazardous administrative permissions
        dangerous_roles = [
            r for r in user.roles 
            if r.permissions.administrator or r.permissions.manage_guild or 
               r.permissions.ban_members or r.permissions.manage_channels or 
               r.permissions.manage_roles
        ]
        if dangerous_roles:
            await user.remove_roles(*dangerous_roles, reason=f"[SECURITY] {reason}")

        # Maximum possible isolation timeout (28 days)
        await user.timeout(discord.utils.utcnow() + discord.timedelta(days=28), reason=reason)
        
        await send_security_log(
            guild,
            "CRITICAL: Anti-Nuke Enforcement",
            f"**Offender:** {user.mention} (`{user.id}`)\n"
            f"**Reason:** {reason}\n"
            f"**Action:** Removed administrative roles & placed in 28-day quarantine.",
            discord.Color.red()
        )
    except discord.Forbidden:
        await send_security_log(
            guild,
            "WARNING: Insufficient Permissions",
            f"Failed to punish {user.mention}. Move the bot's role higher in Server Settings.",
            discord.Color.gold()
        )


def check_rate_limit(user_id: int, action_type: str) -> bool:
    """Sliding-window limiter per user with Beast Mode score escalation."""
    now = time.time()
    max_count, window = LIMITS[action_type]
    timestamps = action_tracker[user_id][action_type]

    while timestamps and now - timestamps[0] > window:
        timestamps.popleft()

    timestamps.append(now)

    # Global Beast Mode tracking
    global_threat_scores.append(now)
    while global_threat_scores and now - global_threat_scores[0] > GLOBAL_SCORE_WINDOW:
        global_threat_scores.popleft()

    return len(timestamps) > max_count or len(global_threat_scores) >= GLOBAL_SCORE_THRESHOLD


# =====================================================================
#                          ANTI-NUKE MONITORS
# =====================================================================

@bot.event
async def on_guild_channel_delete(channel: discord.abc.GuildChannel):
    guild = channel.guild
    async for entry in guild.audit_logs(action=discord.AuditLogAction.channel_delete, limit=1):
        actor = entry.user
        if actor.id == bot.user.id or actor.id in whitelisted_users or actor.id == guild.owner_id:
            return

        if check_rate_limit(actor.id, "channel_delete"):
            member = guild.get_member(actor.id)
            if member:
                await execute_punishment(guild, member, "Exceeded Channel Deletion Threshold")


@bot.event
async def on_guild_role_delete(role: discord.Role):
    guild = role.guild
    async for entry in guild.audit_logs(action=discord.AuditLogAction.role_delete, limit=1):
        actor = entry.user
        if actor.id == bot.user.id or actor.id in whitelisted_users or actor.id == guild.owner_id:
            return

        if check_rate_limit(actor.id, "role_delete"):
            member = guild.get_member(actor.id)
            if member:
                await execute_punishment(guild, member, "Exceeded Role Deletion Threshold")


@bot.event
async def on_member_ban(guild: discord.Guild, user: discord.User):
    async for entry in guild.audit_logs(action=discord.AuditLogAction.ban, limit=1):
        actor = entry.user
        if actor.id == bot.user.id or actor.id in whitelisted_users or actor.id == guild.owner_id:
            return

        if check_rate_limit(actor.id, "member_ban"):
            member = guild.get_member(actor.id)
            if member:
                await execute_punishment(guild, member, "Exceeded Mass Ban Threshold")


@bot.event
async def on_member_remove(member: discord.Member):
    guild = member.guild
    async for entry in guild.audit_logs(action=discord.AuditLogAction.kick, limit=1):
        if entry.target.id == member.id and (discord.utils.utcnow() - entry.created_at).total_seconds() < 5:
            actor = entry.user
            if actor.id == bot.user.id or actor.id in whitelisted_users or actor.id == guild.owner_id:
                return

            if check_rate_limit(actor.id, "member_kick"):
                staff_member = guild.get_member(actor.id)
                if staff_member:
                    await execute_punishment(guild, staff_member, "Exceeded Mass Kick Threshold")


# =====================================================================
#                     ANTI-RAID & GHOST-PING AUTOMOD
# =====================================================================

@bot.event
async def on_member_join(member: discord.Member):
    guild = member.guild
    now = time.time()

    recent_joins.append(now)
    while recent_joins and now - recent_joins[0] > JOIN_BURST_WINDOW:
        recent_joins.popleft()

    if len(recent_joins) >= JOIN_BURST_MAX:
        await send_security_log(
            guild,
            "ANTI-RAID TRIGGERED",
            f"**Attack Vector:** Mass join flood ({len(recent_joins)} joins in {JOIN_BURST_WINDOW}s).\n"
            "Enable strict verification or lockdown immediately.",
            discord.Color.dark_red()
        )

    # Risk Scoring
    risk_score = 0
    account_age = (datetime.now(timezone.utc) - member.created_at).days
    if account_age < MIN_ACCOUNT_AGE_DAYS:
        risk_score += 45
    if member.avatar is None:
        risk_score += 25

    if risk_score >= 60:
        try:
            await member.timeout(discord.utils.utcnow() + discord.timedelta(days=7), reason="High-Risk Join Profile")
            await send_security_log(
                guild,
                "Quarantine: Suspicious Join",
                f"**User:** {member.mention} (`{member.id}`)\n"
                f"**Risk Score:** `{risk_score}/100`\n"
                f"**Age:** {account_age} days | **Default Avatar:** {member.avatar is None}",
                discord.Color.orange()
            )
        except discord.Forbidden:
            pass


@bot.event
async def on_message_delete(message: discord.Message):
    """Ghost Ping Interceptor."""
    if message.author.bot or not message.guild:
        return

    if message.mentions and message.author.id not in whitelisted_users:
        pings = ", ".join(u.mention for u in message.mentions)
        await send_security_log(
            message.guild,
            "Ghost Ping Intercepted",
            f"**Author:** {message.author.mention} (`{message.author.id}`)\n"
            f"**Channel:** {message.channel.mention}\n"
            f"**Target(s):** {pings}\n"
            f"**Message Content:** `{message.clean_content}`",
            discord.Color.yellow()
        )


@bot.event
async def on_message(message: discord.Message):
    if message.author.bot or not message.guild:
        return

    # Anti-Invite
    if ("discord.gg/" in message.content.lower() or "discord.com/invite/" in message.content.lower()):
        if message.author.id not in whitelisted_users and not message.author.guild_permissions.manage_guild:
            await message.delete()
            await message.channel.send(f"{message.author.mention}, invite links are blocked.", delete_after=4)
            return

    # Anti-Mass Mention
    if len(message.mentions) >= 5 or message.mention_everyone:
        if message.author.id not in whitelisted_users and not message.author.guild_permissions.mention_everyone:
            await message.delete()
            await message.channel.send(f"{message.author.mention}, mass mentions are prohibited.", delete_after=4)
            return


# =====================================================================
#                     INTERACTIVE /HELP SELECT MENU
# =====================================================================

class HelpDropdown(discord.ui.Select):
    def __init__(self):
        options = [
            discord.SelectOption(
                label="Anti-Nuke & Defense",
                description="Thresholds, Beast Mode, and auto-punishments.",
                emoji="🛡️"
            ),
            discord.SelectOption(
                label="Anti-Raid & Automod",
                description="Join gatekeeping, risk scoring, links, and ghost pings.",
                emoji="🚨"
            ),
            discord.SelectOption(
                label="Moderation & Whitelist",
                description="Slash commands for manual lockdown and whitelist control.",
                emoji="⚙️"
            ),
        ]
        super().__init__(placeholder="Select a module to view its slash commands...", min_values=1, max_values=1, options=options)

    async def callback(self, interaction: discord.Interaction):
        if self.values[0] == "Anti-Nuke & Defense":
            embed = discord.Embed(
                title="Anti-Nuke Protection",
                description=(
                    "Monitors actions taken by moderators and rogue bots in real time.\n\n"
                    "• **Channel Delete:** Max 3 / 60s\n"
                    "• **Role Delete:** Max 3 / 60s\n"
                    "• **Mass Ban:** Max 3 / 60s\n"
                    "• **Mass Kick:** Max 3 / 60s\n"
                    "• **Beast Mode:** Global trigger if 5+ dangerous actions occur across the server within 60s.\n\n"
                    "**Punishment:** Immediate removal of dangerous roles and a 28-day quarantine isolation."
                ),
                color=discord.Color.red()
            )
        elif self.values[0] == "Anti-Raid & Automod":
            embed = discord.Embed(
                title="Anti-Raid & Automod Engine",
                description=(
                    "Automated gates intercepting raids and malicious messages.\n\n"
                    "• **Join Rate Limiter:** Triggers alert if 5+ members join in 10s.\n"
                    "• **Risk Scoring:** Accounts < 3 days old or lacking avatars get scored; score >= 60 results in automatic timeout.\n"
                    "• **Anti-Invite:** Strips unauthorized invite links instantly.\n"
                    "• **Anti-Mass Mention:** Blocks messages mentioning 5+ members or @everyone.\n"
                    "• **Ghost Ping Detector:** Logs deleted messages containing member pings."
                ),
                color=discord.Color.orange()
            )
        else:
            embed = discord.Embed(
                title="Moderation & Setup Commands",
                description=(
                    "All features use Discord Slash Commands exclusively:\n\n"
                    "• `/help` — Opens this interactive help dashboard.\n"
                    "• `/lockdown` — Closes the current channel to the default role.\n"
                    "• `/unlock` — Restores normal permissions to the channel.\n"
                    "• `/quarantine <user> <hours>` — Manually isolates a suspect account.\n"
                    "• `/whitelist add <user>` — Exempts an administrator from anti-nuke limits.\n"
                    "• `/whitelist remove <user>` — Removes immunity.\n"
                    "• `/whitelist list` — Displays current immunity roster.\n"
                    "• `/security status` — Displays system health, uptime, and limits."
                ),
                color=discord.Color.blue()
            )
        embed.set_footer(text="Aegis Security Engine • Slash-Only Interface")
        await interaction.response.edit_message(embed=embed, view=self.view)


class HelpView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=120)
        self.add_item(HelpDropdown())


# =====================================================================
#                          SLASH COMMANDS
# =====================================================================

@bot.tree.command(name="help", description="Displays the interactive Security Bot command and feature guide.")
async def help_command(interaction: discord.Interaction):
    embed = discord.Embed(
        title="Aegis Security Engine",
        description="Select a security category from the menu below to review features and slash commands.",
        color=discord.Color.blue()
    )
    embed.add_field(name="Current Engine State", value="Active & Monitoring Gateway", inline=False)
    await interaction.response.send_message(embed=embed, view=HelpView(), ephemeral=True)


@bot.tree.command(name="lockdown", description="Locks the current channel to prevent members from sending messages.")
@app_commands.checks.has_permissions(manage_channels=True)
async def lockdown(interaction: discord.Interaction):
    channel = interaction.channel
    default_role = interaction.guild.default_role
    overwrites = channel.overwrites_for(default_role)

    if overwrites.send_messages is False:
        await interaction.response.send_message("Channel is already locked.", ephemeral=True)
        return

    overwrites.send_messages = False
    await channel.set_permissions(default_role, overwrite=overwrites, reason="Emergency /lockdown invoked")
    await interaction.response.send_message(f"🔒 **{channel.name}** has been locked down.")
    await send_security_log(interaction.guild, "Manual Channel Lockdown", f"{interaction.user.mention} locked {channel.mention}.", discord.Color.red())


@bot.tree.command(name="unlock", description="Unlocks a previously locked channel.")
@app_commands.checks.has_permissions(manage_channels=True)
async def unlock(interaction: discord.Interaction):
    channel = interaction.channel
    default_role = interaction.guild.default_role
    overwrites = channel.overwrites_for(default_role)

    overwrites.send_messages = None
    await channel.set_permissions(default_role, overwrite=overwrites, reason="Manual /unlock invoked")
    await interaction.response.send_message(f"🔓 **{channel.name}** is now unlocked.")
    await send_security_log(interaction.guild, "Manual Channel Unlock", f"{interaction.user.mention} unlocked {channel.mention}.", discord.Color.green())


@bot.tree.command(name="quarantine", description="Manually quarantines a member for a set number of hours.")
@app_commands.describe(member="The member to isolate", hours="Isolation duration in hours (1-168)")
@app_commands.checks.has_permissions(moderate_members=True)
async def quarantine(interaction: discord.Interaction, member: discord.Member, hours: int):
    if hours < 1 or hours > 168:
        await interaction.response.send_message("Duration must be between 1 and 168 hours (7 days).", ephemeral=True)
        return

    until = discord.utils.utcnow() + discord.timedelta(hours=hours)
    await member.timeout(until, reason=f"Quarantined by {interaction.user.name}")
    await interaction.response.send_message(f"Quarantined {member.mention} for {hours} hour(s).")
    await send_security_log(interaction.guild, "Manual Quarantine", f"{interaction.user.mention} quarantined {member.mention} for {hours}h.", discord.Color.orange())


# Whitelist Management Group
class WhitelistGroup(app_commands.Group):
    def __init__(self):
        super().__init__(name="whitelist", description="Manage trusted administrator immunity.")

    @app_commands.command(name="add", description="Grants immunity from Anti-Nuke limits.")
    @app_commands.checks.has_permissions(administrator=True)
    async def add(self, interaction: discord.Interaction, user: discord.User):
        whitelisted_users.add(user.id)
        await interaction.response.send_message(f"Added {user.mention} to the security whitelist.")

    @app_commands.command(name="remove", description="Revokes Anti-Nuke immunity.")
    @app_commands.checks.has_permissions(administrator=True)
    async def remove(self, interaction: discord.Interaction, user: discord.User):
        whitelisted_users.discard(user.id)
        await interaction.response.send_message(f"Removed {user.mention} from the security whitelist.")

    @app_commands.command(name="list", description="Lists all whitelisted users.")
    @app_commands.checks.has_permissions(administrator=True)
    async def list_users(self, interaction: discord.Interaction):
        if not whitelisted_users:
            await interaction.response.send_message("No users are currently whitelisted.", ephemeral=True)
            return
        mentions = ", ".join(f"<@{uid}>" for uid in whitelisted_users)
        await interaction.response.send_message(f"**Whitelisted Members:** {mentions}", ephemeral=True)

bot.tree.add_command(WhitelistGroup())


@bot.tree.command(name="security", description="Shows current security module status and configured thresholds.")
async def security_status(interaction: discord.Interaction):
    embed = discord.Embed(title="Security System Diagnostics", color=discord.Color.green())
    embed.add_field(name="Anti-Nuke Limits", value="3 actions per 60 seconds", inline=True)
    embed.add_field(name="Beast Mode Status", value=f"{len(global_threat_scores)}/5 events in buffer", inline=True)
    embed.add_field(name="Active Joins Monitored", value=f"{len(recent_joins)} in last 10s", inline=True)
    embed.add_field(name="Whitelisted Admins", value=str(len(whitelisted_users)), inline=True)
    await interaction.response.send_message(embed=embed, ephemeral=True)


# =====================================================================
#                          LIFECYCLE
# =====================================================================

@bot.event
async def on_ready():
    await bot.tree.sync()
    print(f"Logged in as {bot.user} (ID: {bot.user.id})")
    print("Slash command registry synchronized.")


if __name__ == "__main__":
    bot.run(TOKEN)