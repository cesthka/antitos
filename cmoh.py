"""
================================================================================
  BOT D'AUTO-MODERATION DISCORD
================================================================================
Filtre et supprime automatiquement le contenu problematique pour proteger le
serveur : invitations externes, scams/phishing, gros mots/slurs, spam (mentions
en masse, flood de messages), majuscules abusives. Systeme d'escalade des
sanctions (suppression -> avertissement -> timeout -> kick) et journal des
actions dans un salon de logs.

⚠️  Ce bot COMPLETE l'AutoMod natif de Discord, il ne le remplace pas.
    Active aussi l'AutoMod natif (Parametres du serveur > AutoMod) : il tourne
    cote Discord, sans risque de rate-limit, et reste actif meme si le bot est
    hors-ligne. Le bot ajoute les invites, les scams, l'escalade et les logs.

⚠️  Un bot ne detecte PAS de façon fiable les images NSFW ni les propos haineux
    subtils. Pour ça, repose-toi sur l'AutoMod natif + le signalement + une
    bonne moderation humaine.

------------------------------------------------------------------------------
  PERMISSIONS DU BOT a cocher dans l'invitation :
    - Gerer les messages   (supprimer)
    - Expulser les membres / Kick Members
    - Moderer les membres / Timeout Members
    - Voir les salons, Lire l'historique, Envoyer des messages, Integrer des liens
  + Active MESSAGE CONTENT INTENT et SERVER MEMBERS INTENT dans le portail dev.
================================================================================
"""

import os
import re
import time
import datetime
import sqlite3
from collections import defaultdict, deque

import discord
from discord.ext import commands

# Filtre de gros mots (anglais). Les mots FR s'ajoutent via !badword add.
try:
    from better_profanity import profanity
    profanity.load_censor_words()
    PROFANITY_OK = True
except ImportError:
    PROFANITY_OK = False

# ==============================================================================
#  REGLAGES DE BASE
# ==============================================================================

TOKEN = os.environ.get("DISCORD_TOKEN", "COLLE_TON_TOKEN_ICI_SI_TU_VEUX")
DB_PATH = os.environ.get("DB_PATH", "automod.db")

# Buyer : toi, en dur, immuable. Seul lui peut ajouter/retirer des owners.
# (Remplace par ton ID si tu utilises un autre compte.)
BUYER_ID = 142365250803466240

# Valeurs par defaut (modifiables en base via les commandes).
DEFAUTS = {
    "modlog":        "0",     # salon de logs des sanctions
    "f_invites":     "on",    # bloquer les invitations Discord externes
    "f_scam":        "on",    # bloquer les arnaques / phishing courants
    "f_badwords":    "on",    # bloquer gros mots / slurs
    "f_mentions":    "on",    # bloquer le spam de mentions
    "f_flood":       "on",    # bloquer le flood de messages
    "f_caps":        "off",   # bloquer les majuscules abusives
    "f_grabber":     "on",    # bloquer les liens IP-grabber / logger
    "f_selling":     "on",    # bloquer la vente de comptes/serveurs/invites Discord (interdit par les ToS)
    "f_links":       "off",   # MODE STRICT : bloquer TOUT lien externe
    "mentions_max":  "4",     # nb max de mentions par message
    "flood_msgs":    "5",     # nb de messages...
    "flood_sec":     "5",     # ...dans ce laps de temps (secondes) = flood
    "strike_timeout":"3",     # nb d'infractions avant timeout
    "strike_kick":   "6",     # nb d'infractions avant kick
    "timeout_min":   "10",    # duree du timeout en minutes
    "warn_delete":   "4",     # secondes avant suppression du message d'avertissement du bot
}

# Motifs d'invitations Discord.
RE_INVITE = re.compile(r"(?:discord\.gg|discord(?:app)?\.com/invite)/\S+", re.IGNORECASE)

# Motifs d'arnaques / phishing courants (volontairement simple et prudent).
SCAM_PATTERNS = [
    r"free\s*nitro", r"nitro\s*free", r"steamcommunity\.[a-z]+\s*/?\s*gift",
    r"@everyone.*https?://", r"claim\s*your\s*(free)?\s*gift",
    r"discord\s*nitro\s*giveaway", r"airdrop.*https?://",
]
RE_SCAM = re.compile("|".join(SCAM_PATTERNS), re.IGNORECASE)

# Domaines connus d'IP-grabbers / loggers (vol d'IP = atteinte a la vie privee).
GRABBER_DOMAINS = [
    "grabify", "iplogger", "2no.co", "yip.su", "ipgrabber", "ip-logger",
    "blasze", "lovebird", "trackview", "iplis", "ps3cfw", "grabifylink",
    "bmwforum.co", "leancoding.co", "stopify", "fviewer", "ipgraber",
]
RE_GRABBER = re.compile("|".join(re.escape(d) for d in GRABBER_DOMAINS), re.IGNORECASE)

# Vente/achat d'actifs Discord (interdit par la regle 16 des Guidelines).
_ACTIFS = r"(?:compte|account|token|serveur|server|invite|pseudo|username|nitro)"
_VENTE = r"(?:vends?|à\s*vendre|a\s*vendre|sell(?:ing)?|buy(?:ing)?|achat|achete[rz]?|for\s*sale|en\s*vente)"
RE_SELLING = re.compile(
    rf"(?:{_VENTE}.{{0,20}}{_ACTIFS})|(?:{_ACTIFS}.{{0,20}}{_VENTE})",
    re.IGNORECASE)

# Tout lien externe (pour le mode strict f_links).
RE_URL = re.compile(r"https?://\S+", re.IGNORECASE)

# ==============================================================================
#  BASE DE DONNEES
# ==============================================================================

def db():
    return sqlite3.connect(DB_PATH)


def init_db():
    conn = db()
    conn.execute("CREATE TABLE IF NOT EXISTS settings     (key TEXT PRIMARY KEY, value TEXT)")
    conn.execute("CREATE TABLE IF NOT EXISTS exempt_roles (role_id INTEGER PRIMARY KEY)")
    conn.execute("CREATE TABLE IF NOT EXISTS badwords     (word TEXT PRIMARY KEY)")
    conn.execute("CREATE TABLE IF NOT EXISTS strikes      (user_id INTEGER PRIMARY KEY, count INTEGER)")
    conn.execute("CREATE TABLE IF NOT EXISTS owners       (user_id INTEGER PRIMARY KEY)")
    conn.commit(); conn.close()


def get_setting(key):
    conn = db()
    row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    conn.close()
    return row[0] if row else DEFAUTS.get(key, "")


def get_int(key):
    try:
        return int(get_setting(key))
    except (TypeError, ValueError):
        return int(DEFAUTS.get(key, "0"))


def set_setting(key, value):
    conn = db()
    conn.execute("INSERT INTO settings (key,value) VALUES (?,?) "
                 "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, str(value)))
    conn.commit(); conn.close()


def charger_exempts():
    conn = db()
    rows = conn.execute("SELECT role_id FROM exempt_roles").fetchall()
    conn.close()
    return {r[0] for r in rows}


def charger_badwords():
    conn = db()
    rows = conn.execute("SELECT word FROM badwords").fetchall()
    conn.close()
    return {r[0] for r in rows}


def get_strikes(uid):
    conn = db()
    row = conn.execute("SELECT count FROM strikes WHERE user_id=?", (uid,)).fetchone()
    conn.close()
    return row[0] if row else 0


def add_strike(uid):
    conn = db()
    conn.execute("INSERT INTO strikes (user_id,count) VALUES (?,1) "
                 "ON CONFLICT(user_id) DO UPDATE SET count=count+1", (uid,))
    conn.commit()
    row = conn.execute("SELECT count FROM strikes WHERE user_id=?", (uid,)).fetchone()
    conn.close()
    return row[0]


def reset_strikes(uid):
    conn = db()
    conn.execute("DELETE FROM strikes WHERE user_id=?", (uid,))
    conn.commit(); conn.close()


def charger_owners():
    conn = db()
    rows = conn.execute("SELECT user_id FROM owners").fetchall()
    conn.close()
    return {r[0] for r in rows}


def ajouter_owner(uid):
    conn = db(); conn.execute("INSERT OR IGNORE INTO owners (user_id) VALUES (?)", (uid,))
    conn.commit(); conn.close(); OWNERS.add(uid)


def retirer_owner(uid):
    conn = db(); conn.execute("DELETE FROM owners WHERE user_id=?", (uid,))
    conn.commit(); conn.close(); OWNERS.discard(uid)


init_db()
EXEMPT_ROLES = charger_exempts()
BADWORDS = charger_badwords()
OWNERS = charger_owners()

# Suivi du flood en memoire : user_id -> deque de timestamps recents.
flood_tracker = defaultdict(lambda: deque(maxlen=20))


# --- Hierarchie buyer / owner ---
def est_buyer(uid): return uid == BUYER_ID
def est_owner(uid): return uid == BUYER_ID or uid in OWNERS


def check_buyer():
    async def predicate(ctx): return est_buyer(ctx.author.id)
    return commands.check(predicate)


def check_owner():
    async def predicate(ctx): return est_owner(ctx.author.id)
    return commands.check(predicate)

# ==============================================================================
#  BOT
# ==============================================================================

intents = discord.Intents.default()
intents.members = True
intents.message_content = True

bot = commands.Bot(command_prefix=".", intents=intents, help_command=None)


# ==============================================================================
#  ANALYSE & SANCTIONS
# ==============================================================================

def est_exempt(member: discord.Member) -> bool:
    """Les admins, le buyer/owners et les roles exemptes echappent a l'automod."""
    if est_owner(member.id):
        return True
    if member.guild_permissions.administrator or member.guild_permissions.manage_guild:
        return True
    return any(r.id in EXEMPT_ROLES for r in member.roles)


def contient_badword(texte: str) -> bool:
    bas = texte.lower()
    if any(re.search(rf"\b{re.escape(m)}\b", bas) for m in BADWORDS):
        return True
    if PROFANITY_OK and get_setting("f_badwords") == "on":
        return profanity.contains_profanity(texte)
    return False


def analyser(message: discord.Message) -> str | None:
    """Renvoie la raison de l'infraction, ou None si le message est propre."""
    contenu = message.content or ""

    if get_setting("f_invites") == "on" and RE_INVITE.search(contenu):
        return "Invitation externe"

    if get_setting("f_scam") == "on" and RE_SCAM.search(contenu):
        return "Arnaque / phishing presume"

    if get_setting("f_grabber") == "on" and RE_GRABBER.search(contenu):
        return "Lien IP-grabber / logger"

    if get_setting("f_selling") == "on" and RE_SELLING.search(contenu):
        return "Vente d'actifs Discord (interdit par les ToS)"

    if get_setting("f_links") == "on" and RE_URL.search(contenu):
        return "Lien externe (mode strict)"

    if get_setting("f_badwords") == "on" and contient_badword(contenu):
        return "Langage interdit"

    if get_setting("f_mentions") == "on":
        nb = len(message.mentions) + len(message.role_mentions)
        if nb > get_int("mentions_max"):
            return f"Spam de mentions ({nb})"

    if get_setting("f_flood") == "on":
        maintenant = time.time()
        dq = flood_tracker[message.author.id]
        dq.append(maintenant)
        fenetre = get_int("flood_sec")
        recents = [t for t in dq if maintenant - t <= fenetre]
        if len(recents) > get_int("flood_msgs"):
            return f"Flood de messages ({len(recents)} en {fenetre}s)"

    if get_setting("f_caps") == "on":
        lettres = [c for c in contenu if c.isalpha()]
        if len(lettres) >= 10 and sum(c.isupper() for c in lettres) / len(lettres) > 0.7:
            return "Majuscules abusives"

    return None


async def logger_action(guild, embed):
    salon = guild.get_channel(get_int("modlog"))
    if salon:
        try:
            await salon.send(embed=embed)
        except discord.HTTPException:
            pass


async def sanctionner(message: discord.Message, raison: str):
    member = message.author
    guild = message.guild

    # 1) Supprimer le message fautif
    try:
        await message.delete()
    except (discord.Forbidden, discord.NotFound, discord.HTTPException):
        pass

    # 2) Incrementer le compteur d'infractions
    total = add_strike(member.id)
    action = "Message supprime + avertissement"
    couleur = discord.Color.orange()
    sanction_txt = ""

    # 3) Escalade
    try:
        if total >= get_int("strike_kick"):
            await member.kick(reason=f"Automod: {raison} ({total} infractions)")
            action = "Kick"
            couleur = discord.Color.red()
            sanction_txt = " Tu as ete **expulse** du serveur."
        elif total >= get_int("strike_timeout"):
            minutes = get_int("timeout_min")
            await member.timeout(datetime.timedelta(minutes=minutes),
                                 reason=f"Automod: {raison} ({total} infractions)")
            action = f"Timeout {minutes} min"
            couleur = discord.Color.dark_orange()
            sanction_txt = f" Tu es **exclu {minutes} minutes**."
    except discord.Forbidden:
        action += " (echec : permissions du bot insuffisantes)"
    except discord.HTTPException:
        pass

    # 4) Avertir la personne par un ping, message auto-supprime apres quelques secondes
    try:
        await message.channel.send(
            f"⚠️ {member.mention} ton message a ete supprime — **{raison}**.{sanction_txt}",
            delete_after=get_int("warn_delete"),
            allowed_mentions=discord.AllowedMentions(users=True, roles=False, everyone=False),
        )
    except discord.HTTPException:
        pass

    # 5) Logger
    embed = discord.Embed(title="🛡️ Action d'auto-moderation", color=couleur,
                          timestamp=datetime.datetime.now(datetime.timezone.utc))
    embed.add_field(name="Membre", value=f"{member.mention} (`{member.id}`)", inline=True)
    embed.add_field(name="Infraction", value=raison, inline=True)
    embed.add_field(name="Sanction", value=action, inline=True)
    embed.add_field(name="Infractions totales", value=str(total), inline=True)
    embed.add_field(name="Salon", value=message.channel.mention, inline=True)
    extrait = (message.content or "")[:300]
    if extrait:
        embed.add_field(name="Contenu", value=f"```{extrait}```", inline=False)
    await logger_action(guild, embed)


# ==============================================================================
#  EVENEMENTS
# ==============================================================================

@bot.event
async def on_message(message: discord.Message):
    if message.author.bot or message.guild is None:
        await bot.process_commands(message)
        return
    if est_exempt(message.author):
        await bot.process_commands(message)
        return

    raison = analyser(message)
    if raison:
        await sanctionner(message, raison)
        return  # message supprime : on ne traite pas de commande dessus
    await bot.process_commands(message)


@bot.event
async def on_ready():
    print(f"Bot d'auto-moderation connecte : {bot.user} (id {bot.user.id})")
    if not PROFANITY_OK:
        print("/!\\ better_profanity non installe : filtre de gros mots reduit aux mots personnalises.")


@bot.event
async def on_command_error(ctx, error):
    if isinstance(error, commands.CheckFailure):
        await ctx.send("⛔ Reserve au buyer / aux owners.")
    elif isinstance(error, commands.CommandNotFound):
        return
    elif isinstance(error, (commands.BadArgument, commands.MissingRequiredArgument,
                            commands.RoleNotFound, commands.ChannelNotFound, commands.MemberNotFound)):
        await ctx.send("Argument invalide ou manquant.")
    else:
        raise error


# ==============================================================================
#  MENU D'AIDE
# ==============================================================================

class AuthorView(discord.ui.View):
    def __init__(self, author, timeout=180):
        super().__init__(timeout=timeout)
        self.author = author

    async def interaction_check(self, interaction):
        if interaction.user.id != self.author.id:
            await interaction.response.send_message("Ce menu n'est pas pour toi 🙂", ephemeral=True)
            return False
        return True


HELP_CATEGORIES = {
    "🛡️ Moderation": [
        (".automod", "Affiche l'etat des filtres et des seuils."),
        (".toggle <filtre> on/off", "Active/desactive un filtre (invites, scam, badwords, mentions, flood, caps, grabber, selling, links)."),
        (".setseuil <cle> <valeur>", "Regle un seuil (mentions_max, flood_msgs, timeout_min, warn_delete...)."),
        (".modlog #salon", "Definit le salon des logs de moderation."),
    ],
    "🚫 Exemptions & mots": [
        (".exempt @role", "Exempte un role de l'auto-moderation."),
        (".unexempt @role", "Retire l'exemption d'un role."),
        (".badword add/remove/list <mot>", "Gere la liste de mots interdits personnalisee."),
    ],
    "⚖️ Infractions": [
        (".warnings @membre", "Voir le nombre d'infractions d'un membre."),
        (".clearwarnings @membre", "Remet ses infractions a zero."),
    ],
    "👑 Gestion": [
        (".owner @membre", "Ajoute un owner (buyer uniquement)."),
        (".unowner @membre", "Retire un owner (buyer uniquement)."),
        (".owners", "Affiche le buyer et les owners."),
    ],
}


def embed_help_accueil():
    e = discord.Embed(title="📖 Aide — Bot de protection",
                      description="Auto-moderation stricte basee sur les regles de Discord.\n"
                                  "Choisis une categorie dans le menu ci-dessous.",
                      color=discord.Color.blurple())
    e.add_field(name="Categories", value="\n".join(f"• {c}" for c in HELP_CATEGORIES), inline=False)
    e.set_footer(text="Commandes reservees au buyer / aux owners.")
    return e


def embed_help_categorie(cat):
    e = discord.Embed(title=f"📖 Aide — {cat}", color=discord.Color.blurple())
    for nom, desc in HELP_CATEGORIES[cat]:
        e.add_field(name=nom, value=desc, inline=False)
    return e


class HelpSelect(discord.ui.Select):
    def __init__(self):
        opts = [discord.SelectOption(label="Accueil", value="accueil", emoji="🏠")]
        opts += [discord.SelectOption(label=c, value=c) for c in HELP_CATEGORIES]
        super().__init__(placeholder="Choisis une categorie…", options=opts)

    async def callback(self, interaction):
        v = self.values[0]
        embed = embed_help_accueil() if v == "accueil" else embed_help_categorie(v)
        await interaction.response.edit_message(embed=embed, view=self.view)


class HelpView(AuthorView):
    def __init__(self, author):
        super().__init__(author)
        self.add_item(HelpSelect())


# ==============================================================================
#  COMMANDES (administrateurs)
# ==============================================================================

@bot.command(name="help")
async def help_cmd(ctx):
    await ctx.send(embed=embed_help_accueil(), view=HelpView(ctx.author))


@bot.command(name="modlog")
@check_owner()
async def modlog(ctx, salon: discord.TextChannel = None):
    salon = salon or ctx.channel
    set_setting("modlog", salon.id)
    await ctx.send(f"✅ Salon de logs d'auto-moderation : {salon.mention}")


@bot.command(name="automod")
@check_owner()
async def automod(ctx):
    """Affiche la configuration de l'auto-moderation."""
    filtres = {
        "invites": "f_invites", "scam": "f_scam", "badwords": "f_badwords",
        "mentions": "f_mentions", "flood": "f_flood", "caps": "f_caps",
        "grabber": "f_grabber", "selling": "f_selling", "links": "f_links",
    }
    lignes = [f"`{nom}` : {'🟢 ON' if get_setting(cle)=='on' else '🔴 OFF'}"
              for nom, cle in filtres.items()]
    salon = ctx.guild.get_channel(get_int("modlog"))
    embed = discord.Embed(title="🛡️ Configuration auto-moderation", color=discord.Color.blurple())
    embed.add_field(name="Filtres", value="\n".join(lignes), inline=False)
    embed.add_field(name="Seuils",
                    value=(f"mentions max : {get_int('mentions_max')}\n"
                           f"flood : {get_int('flood_msgs')} msg / {get_int('flood_sec')}s\n"
                           f"timeout a {get_int('strike_timeout')} infractions ({get_int('timeout_min')} min)\n"
                           f"kick a {get_int('strike_kick')} infractions"),
                    inline=False)
    embed.add_field(name="Salon de logs", value=salon.mention if salon else "*non defini*", inline=False)
    embed.add_field(name="Roles exemptes",
                    value=", ".join(f"<@&{r}>" for r in EXEMPT_ROLES) or "*aucun*", inline=False)
    embed.set_footer(text=".toggle <filtre> on/off  ·  .setseuil <cle> <valeur>")
    await ctx.send(embed=embed)


@bot.command(name="toggle")
@check_owner()
async def toggle(ctx, filtre: str = None, etat: str = None):
    cles = {"invites": "f_invites", "scam": "f_scam", "badwords": "f_badwords",
            "mentions": "f_mentions", "flood": "f_flood", "caps": "f_caps",
            "grabber": "f_grabber", "selling": "f_selling", "links": "f_links"}
    if filtre not in cles or etat not in ("on", "off"):
        await ctx.send(f"Utilisation : `.toggle <{'/'.join(cles)}> <on/off>`")
        return
    set_setting(cles[filtre], etat)
    await ctx.send(f"✅ Filtre `{filtre}` mis sur **{etat.upper()}**.")


@bot.command(name="setseuil")
@check_owner()
async def setseuil(ctx, cle: str = None, valeur: int = None):
    autorises = {"mentions_max", "flood_msgs", "flood_sec",
                 "strike_timeout", "strike_kick", "timeout_min"}
    if cle not in autorises or valeur is None:
        await ctx.send(f"Utilisation : `.setseuil <cle> <nombre>`\nCles : {', '.join(autorises)}")
        return
    set_setting(cle, valeur)
    await ctx.send(f"✅ `{cle}` = **{valeur}**.")


@bot.command(name="exempt")
@check_owner()
async def exempt(ctx, role: discord.Role):
    conn = db(); conn.execute("INSERT OR IGNORE INTO exempt_roles (role_id) VALUES (?)", (role.id,))
    conn.commit(); conn.close(); EXEMPT_ROLES.add(role.id)
    await ctx.send(f"✅ {role.mention} est maintenant exempte de l'auto-moderation.")


@bot.command(name="unexempt")
@check_owner()
async def unexempt(ctx, role: discord.Role):
    conn = db(); conn.execute("DELETE FROM exempt_roles WHERE role_id=?", (role.id,))
    conn.commit(); conn.close(); EXEMPT_ROLES.discard(role.id)
    await ctx.send(f"✅ {role.mention} n'est plus exempte.")


@bot.command(name="badword")
@check_owner()
async def badword(ctx, action: str = None, *, mot: str = None):
    if action == "add" and mot:
        conn = db(); conn.execute("INSERT OR IGNORE INTO badwords (word) VALUES (?)", (mot.lower(),))
        conn.commit(); conn.close(); BADWORDS.add(mot.lower())
        await ctx.send("✅ Mot ajoute au filtre.")  # on ne re-affiche pas le mot
    elif action == "remove" and mot:
        conn = db(); conn.execute("DELETE FROM badwords WHERE word=?", (mot.lower(),))
        conn.commit(); conn.close(); BADWORDS.discard(mot.lower())
        await ctx.send("✅ Mot retire du filtre.")
    elif action == "list":
        await ctx.send(f"{len(BADWORDS)} mot(s) personnalise(s) dans le filtre.")
    else:
        await ctx.send("Utilisation : `.badword add <mot>` · `.badword remove <mot>` · `.badword list`")


@bot.command(name="warnings")
@check_owner()
async def warnings(ctx, membre: discord.Member):
    await ctx.send(f"{membre.mention} a **{get_strikes(membre.id)}** infraction(s) enregistree(s).")


@bot.command(name="clearwarnings")
@check_owner()
async def clearwarnings(ctx, membre: discord.Member):
    reset_strikes(membre.id)
    await ctx.send(f"✅ Infractions de {membre.mention} remises a zero.")


@bot.command(name="owner")
@check_buyer()
async def owner_cmd(ctx, membre: discord.User):
    """Ajoute un owner. Buyer uniquement."""
    if membre.id == BUYER_ID:
        await ctx.send("Tu es le buyer : tu as deja tous les droits."); return
    if membre.id in OWNERS:
        await ctx.send(f"{membre.mention} est deja owner."); return
    ajouter_owner(membre.id)
    await ctx.send(f"✅ {membre.mention} (`{membre.id}`) est maintenant owner.")


@bot.command(name="unowner")
@check_buyer()
async def unowner_cmd(ctx, membre: discord.User):
    """Retire un owner. Buyer uniquement."""
    if membre.id == BUYER_ID:
        await ctx.send("Le buyer ne peut pas etre retire."); return
    if membre.id not in OWNERS:
        await ctx.send(f"{membre.mention} n'est pas owner."); return
    retirer_owner(membre.id)
    await ctx.send(f"✅ {membre.mention} n'est plus owner.")


@bot.command(name="owners")
@check_owner()
async def owners_cmd(ctx):
    lignes = [f"👑 <@{BUYER_ID}> — **Buyer**"]
    lignes += [f"• <@{uid}>" for uid in OWNERS] or ["*(aucun owner)*"]
    await ctx.send(embed=discord.Embed(title="Hierarchie du bot", description="\n".join(lignes),
                                       color=discord.Color.blurple()))


if __name__ == "__main__":
    if not TOKEN or TOKEN == "COLLE_TON_TOKEN_ICI_SI_TU_VEUX":
        raise SystemExit("Aucun token. Definis DISCORD_TOKEN ou colle-le dans TOKEN.")
    bot.run(TOKEN)
