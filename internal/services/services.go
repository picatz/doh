// Package services catalogs popular apps and sites by the domains they
// use, so a profile can block "TikTok" or "Roblox" without anyone looking
// up which domains that takes.
//
// Each service lists domains it owns and serves itself from, with their
// subdomains. Apps change their domains, and some share infrastructure,
// so a list is a well-kept best effort: blocking a service stops it from
// working, but a determined app may still find a way around, and a
// profile can add domains to deny alongside it.
package services

import (
	"slices"
	"strings"
)

// Service categories, in the order they're presented.
const (
	CategorySocial    = "social"
	CategoryMessaging = "messaging"
	CategoryVideo     = "video"
	CategoryMusic     = "music"
	CategoryGaming    = "gaming"
	CategoryAI        = "ai"
	CategoryShopping  = "shopping"
	CategoryDating    = "dating"
	CategoryGambling  = "gambling"
)

// Categories lists every category, in the order they're presented.
var Categories = []string{
	CategorySocial, CategoryMessaging, CategoryVideo, CategoryMusic, CategoryGaming,
	CategoryAI, CategoryShopping, CategoryDating, CategoryGambling,
}

// Service is an app or site, by the domains it uses.
type Service struct {
	// ID identifies the service in profiles, such as "tiktok".
	ID string `json:"id"`

	// Name is its name for people, such as "TikTok".
	Name string `json:"name"`

	// Category groups services: one of [Categories].
	Category string `json:"category"`

	// Domains are the domains it uses, each with its subdomains. Where a
	// service lives on part of a shared domain, such as
	// gemini.google.com, only that part is listed.
	Domains []string `json:"domains"`
}

// Catalog is every known service, in the order they're presented.
var Catalog = []Service{
	// Social
	{ID: "tiktok", Name: "TikTok", Category: CategorySocial, Domains: []string{
		"tiktok.com", "tiktokv.com", "tiktokv.us", "tiktokcdn.com", "tiktokcdn-us.com", "tiktokcdn-eu.com",
		"tiktokw.us", "ttwstatic.com", "byteoversea.com", "ibytedtos.com", "ibyteimg.com", "musical.ly",
	}},
	{ID: "instagram", Name: "Instagram", Category: CategorySocial, Domains: []string{
		"instagram.com", "cdninstagram.com", "ig.me", "instagr.am",
	}},
	{ID: "facebook", Name: "Facebook", Category: CategorySocial, Domains: []string{
		"facebook.com", "fb.com", "fb.me", "fbcdn.net", "facebook.net", "fbsbx.com",
	}},
	{ID: "threads", Name: "Threads", Category: CategorySocial, Domains: []string{
		"threads.net", "threads.com",
	}},
	{ID: "snapchat", Name: "Snapchat", Category: CategorySocial, Domains: []string{
		"snapchat.com", "snap.com", "sc-cdn.net", "sc-static.net", "snapkit.com", "snap-dev.net", "feelinsonice-hrd.appspot.com",
	}},
	{ID: "x", Name: "X (Twitter)", Category: CategorySocial, Domains: []string{
		"x.com", "twitter.com", "twimg.com", "t.co",
	}},
	{ID: "bluesky", Name: "Bluesky", Category: CategorySocial, Domains: []string{
		"bsky.app", "bsky.social", "bsky.network",
	}},
	{ID: "reddit", Name: "Reddit", Category: CategorySocial, Domains: []string{
		"reddit.com", "redd.it", "redditmedia.com", "redditstatic.com", "reddituploads.com",
	}},
	{ID: "pinterest", Name: "Pinterest", Category: CategorySocial, Domains: []string{
		"pinterest.com", "pinimg.com", "pin.it",
	}},
	{ID: "tumblr", Name: "Tumblr", Category: CategorySocial, Domains: []string{
		"tumblr.com",
	}},
	{ID: "bereal", Name: "BeReal", Category: CategorySocial, Domains: []string{
		"bereal.com", "bere.al",
	}},
	{ID: "linkedin", Name: "LinkedIn", Category: CategorySocial, Domains: []string{
		"linkedin.com", "licdn.com", "lnkd.in",
	}},
	{ID: "quora", Name: "Quora", Category: CategorySocial, Domains: []string{
		"quora.com", "quoracdn.net",
	}},
	{ID: "9gag", Name: "9GAG", Category: CategorySocial, Domains: []string{
		"9gag.com", "9cache.com",
	}},
	{ID: "wattpad", Name: "Wattpad", Category: CategorySocial, Domains: []string{
		"wattpad.com",
	}},
	{ID: "vk", Name: "VK", Category: CategorySocial, Domains: []string{
		"vk.com", "vk.me", "userapi.com",
	}},

	// Messaging
	{ID: "whatsapp", Name: "WhatsApp", Category: CategoryMessaging, Domains: []string{
		"whatsapp.com", "whatsapp.net", "wa.me",
	}},
	{ID: "messenger", Name: "Messenger", Category: CategoryMessaging, Domains: []string{
		"messenger.com", "m.me",
	}},
	{ID: "discord", Name: "Discord", Category: CategoryMessaging, Domains: []string{
		"discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.media", "discordcdn.com",
	}},
	{ID: "telegram", Name: "Telegram", Category: CategoryMessaging, Domains: []string{
		"telegram.org", "telegram.me", "t.me", "telegra.ph", "telesco.pe",
	}},
	{ID: "signal", Name: "Signal", Category: CategoryMessaging, Domains: []string{
		"signal.org", "signal.group", "signal.me", "whispersystems.org",
	}},
	{ID: "viber", Name: "Viber", Category: CategoryMessaging, Domains: []string{
		"viber.com",
	}},
	{ID: "line", Name: "LINE", Category: CategoryMessaging, Domains: []string{
		"line.me", "line-apps.com", "line-scdn.net",
	}},
	{ID: "wechat", Name: "WeChat", Category: CategoryMessaging, Domains: []string{
		"wechat.com", "weixin.qq.com",
	}},
	{ID: "kik", Name: "Kik", Category: CategoryMessaging, Domains: []string{
		"kik.com",
	}},

	// Video
	{ID: "youtube", Name: "YouTube", Category: CategoryVideo, Domains: []string{
		"youtube.com", "youtu.be", "ytimg.com", "googlevideo.com", "youtube-nocookie.com",
		"youtubei.googleapis.com", "youtube.googleapis.com", "youtubekids.com",
	}},
	{ID: "twitch", Name: "Twitch", Category: CategoryVideo, Domains: []string{
		"twitch.tv", "ttvnw.net", "jtvnw.net", "twitchcdn.net", "twitchsvc.net",
	}},
	{ID: "kick", Name: "Kick", Category: CategoryVideo, Domains: []string{
		"kick.com",
	}},
	{ID: "netflix", Name: "Netflix", Category: CategoryVideo, Domains: []string{
		"netflix.com", "netflix.net", "nflxvideo.net", "nflximg.net", "nflximg.com", "nflxext.com", "nflxso.net",
	}},
	{ID: "disneyplus", Name: "Disney+", Category: CategoryVideo, Domains: []string{
		"disneyplus.com", "disney-plus.net", "dssott.com", "bamgrid.com",
	}},
	{ID: "hulu", Name: "Hulu", Category: CategoryVideo, Domains: []string{
		"hulu.com", "hulustream.com", "huluim.com",
	}},
	{ID: "primevideo", Name: "Prime Video", Category: CategoryVideo, Domains: []string{
		"primevideo.com", "amazonvideo.com", "aiv-cdn.net", "aiv-delivery.net",
	}},
	{ID: "hbomax", Name: "HBO Max", Category: CategoryVideo, Domains: []string{
		"hbomax.com", "max.com", "hbo.com", "hbomaxcdn.com",
	}},
	{ID: "paramountplus", Name: "Paramount+", Category: CategoryVideo, Domains: []string{
		"paramountplus.com", "pplusstatic.com",
	}},
	{ID: "peacock", Name: "Peacock", Category: CategoryVideo, Domains: []string{
		"peacocktv.com",
	}},
	{ID: "crunchyroll", Name: "Crunchyroll", Category: CategoryVideo, Domains: []string{
		"crunchyroll.com", "vrv.co",
	}},
	{ID: "plutotv", Name: "Pluto TV", Category: CategoryVideo, Domains: []string{
		"pluto.tv",
	}},
	{ID: "tubi", Name: "Tubi", Category: CategoryVideo, Domains: []string{
		"tubitv.com", "tubi.tv",
	}},
	{ID: "vimeo", Name: "Vimeo", Category: CategoryVideo, Domains: []string{
		"vimeo.com", "vimeocdn.com",
	}},
	{ID: "dailymotion", Name: "Dailymotion", Category: CategoryVideo, Domains: []string{
		"dailymotion.com", "dmcdn.net",
	}},
	{ID: "rumble", Name: "Rumble", Category: CategoryVideo, Domains: []string{
		"rumble.com",
	}},
	{ID: "bilibili", Name: "Bilibili", Category: CategoryVideo, Domains: []string{
		"bilibili.com", "bilivideo.com", "hdslb.com", "biliapi.net",
	}},

	// Music
	{ID: "spotify", Name: "Spotify", Category: CategoryMusic, Domains: []string{
		"spotify.com", "scdn.co", "spotifycdn.com", "spotify.link", "spoti.fi",
	}},
	{ID: "soundcloud", Name: "SoundCloud", Category: CategoryMusic, Domains: []string{
		"soundcloud.com", "sndcdn.com",
	}},
	{ID: "deezer", Name: "Deezer", Category: CategoryMusic, Domains: []string{
		"deezer.com", "dzcdn.net",
	}},
	{ID: "pandora", Name: "Pandora", Category: CategoryMusic, Domains: []string{
		"pandora.com",
	}},
	{ID: "tidal", Name: "TIDAL", Category: CategoryMusic, Domains: []string{
		"tidal.com",
	}},

	// Gaming
	{ID: "roblox", Name: "Roblox", Category: CategoryGaming, Domains: []string{
		"roblox.com", "rbxcdn.com", "rbx.com", "robloxlabs.com", "roblox.cn",
	}},
	{ID: "fortnite", Name: "Fortnite and Epic Games", Category: CategoryGaming, Domains: []string{
		"fortnite.com", "epicgames.com", "epicgames.dev", "epicgames.net", "unrealengine.com",
	}},
	{ID: "minecraft", Name: "Minecraft", Category: CategoryGaming, Domains: []string{
		"minecraft.net", "mojang.com", "minecraftservices.com", "minecraft-services.net",
	}},
	{ID: "steam", Name: "Steam", Category: CategoryGaming, Domains: []string{
		"steampowered.com", "steamcommunity.com", "steamstatic.com", "steamcontent.com", "steamserver.net", "steamgames.com",
	}},
	{ID: "xbox", Name: "Xbox network", Category: CategoryGaming, Domains: []string{
		"xbox.com", "xboxlive.com", "xboxservices.com",
	}},
	{ID: "playstation", Name: "PlayStation Network", Category: CategoryGaming, Domains: []string{
		"playstation.com", "playstation.net", "sonyentertainmentnetwork.com",
	}},
	{ID: "nintendo", Name: "Nintendo online", Category: CategoryGaming, Domains: []string{
		"nintendo.com", "nintendo.net",
	}},
	{ID: "riot", Name: "Riot Games (League of Legends, Valorant)", Category: CategoryGaming, Domains: []string{
		"riotgames.com", "leagueoflegends.com", "playvalorant.com", "riotcdn.net",
	}},
	{ID: "blizzard", Name: "Blizzard Battle.net", Category: CategoryGaming, Domains: []string{
		"blizzard.com", "battle.net",
	}},
	{ID: "ea", Name: "EA", Category: CategoryGaming, Domains: []string{
		"ea.com", "origin.com",
	}},
	{ID: "ubisoft", Name: "Ubisoft", Category: CategoryGaming, Domains: []string{
		"ubisoft.com", "ubi.com",
	}},
	{ID: "rockstar", Name: "Rockstar Games", Category: CategoryGaming, Domains: []string{
		"rockstargames.com",
	}},
	{ID: "hoyoverse", Name: "HoYoverse (Genshin Impact)", Category: CategoryGaming, Domains: []string{
		"hoyoverse.com", "mihoyo.com", "hoyolab.com",
	}},
	{ID: "pokemongo", Name: "Pokémon GO", Category: CategoryGaming, Domains: []string{
		"pokemongolive.com", "nianticlabs.com",
	}},
	{ID: "itchio", Name: "itch.io", Category: CategoryGaming, Domains: []string{
		"itch.io", "itch.zone",
	}},

	// AI chat
	{ID: "chatgpt", Name: "ChatGPT", Category: CategoryAI, Domains: []string{
		"chatgpt.com", "chat.openai.com", "oaistatic.com", "oaiusercontent.com",
	}},
	{ID: "claude", Name: "Claude", Category: CategoryAI, Domains: []string{
		"claude.ai",
	}},
	{ID: "gemini", Name: "Gemini", Category: CategoryAI, Domains: []string{
		"gemini.google.com", "bard.google.com",
	}},
	{ID: "copilot", Name: "Microsoft Copilot", Category: CategoryAI, Domains: []string{
		"copilot.microsoft.com",
	}},
	{ID: "metaai", Name: "Meta AI", Category: CategoryAI, Domains: []string{
		"meta.ai",
	}},
	{ID: "grok", Name: "Grok", Category: CategoryAI, Domains: []string{
		"grok.com",
	}},
	{ID: "perplexity", Name: "Perplexity", Category: CategoryAI, Domains: []string{
		"perplexity.ai", "pplx.ai",
	}},
	{ID: "deepseek", Name: "DeepSeek", Category: CategoryAI, Domains: []string{
		"deepseek.com",
	}},
	{ID: "characterai", Name: "Character.AI", Category: CategoryAI, Domains: []string{
		"character.ai",
	}},
	{ID: "replika", Name: "Replika", Category: CategoryAI, Domains: []string{
		"replika.com", "replika.ai",
	}},
	{ID: "poe", Name: "Poe", Category: CategoryAI, Domains: []string{
		"poe.com",
	}},

	// Shopping
	{ID: "temu", Name: "Temu", Category: CategoryShopping, Domains: []string{
		"temu.com", "kwcdn.com",
	}},
	{ID: "shein", Name: "SHEIN", Category: CategoryShopping, Domains: []string{
		"shein.com", "ltwebstatic.com",
	}},
	{ID: "aliexpress", Name: "AliExpress", Category: CategoryShopping, Domains: []string{
		"aliexpress.com", "aliexpress.us",
	}},
	{ID: "ebay", Name: "eBay", Category: CategoryShopping, Domains: []string{
		"ebay.com", "ebayimg.com", "ebaystatic.com",
	}},
	{ID: "etsy", Name: "Etsy", Category: CategoryShopping, Domains: []string{
		"etsy.com", "etsystatic.com",
	}},

	// Dating
	{ID: "tinder", Name: "Tinder", Category: CategoryDating, Domains: []string{
		"tinder.com", "gotinder.com",
	}},
	{ID: "bumble", Name: "Bumble", Category: CategoryDating, Domains: []string{
		"bumble.com",
	}},
	{ID: "hinge", Name: "Hinge", Category: CategoryDating, Domains: []string{
		"hinge.co",
	}},
	{ID: "grindr", Name: "Grindr", Category: CategoryDating, Domains: []string{
		"grindr.com",
	}},
	{ID: "okcupid", Name: "OkCupid", Category: CategoryDating, Domains: []string{
		"okcupid.com",
	}},
	{ID: "match", Name: "Match", Category: CategoryDating, Domains: []string{
		"match.com",
	}},
	{ID: "pof", Name: "Plenty of Fish", Category: CategoryDating, Domains: []string{
		"pof.com",
	}},

	// Gambling
	{ID: "draftkings", Name: "DraftKings", Category: CategoryGambling, Domains: []string{
		"draftkings.com",
	}},
	{ID: "fanduel", Name: "FanDuel", Category: CategoryGambling, Domains: []string{
		"fanduel.com",
	}},
	{ID: "betmgm", Name: "BetMGM", Category: CategoryGambling, Domains: []string{
		"betmgm.com",
	}},
	{ID: "bet365", Name: "bet365", Category: CategoryGambling, Domains: []string{
		"bet365.com",
	}},
	{ID: "stake", Name: "Stake", Category: CategoryGambling, Domains: []string{
		"stake.com", "stake.us",
	}},
	{ID: "pokerstars", Name: "PokerStars", Category: CategoryGambling, Domains: []string{
		"pokerstars.com",
	}},
	{ID: "polymarket", Name: "Polymarket", Category: CategoryGambling, Domains: []string{
		"polymarket.com",
	}},
	{ID: "kalshi", Name: "Kalshi", Category: CategoryGambling, Domains: []string{
		"kalshi.com",
	}},
}

// Lookup returns the service with id.
func Lookup(id string) (Service, bool) {
	i := slices.IndexFunc(Catalog, func(s Service) bool { return s.ID == id })
	if i < 0 {
		return Service{}, false
	}
	return Catalog[i], true
}

// IDs returns every service's ID, in catalog order.
func IDs() []string {
	ids := make([]string, len(Catalog))
	for i, s := range Catalog {
		ids[i] = s.ID
	}
	return ids
}

// Domains returns the domains of the services with ids, ignoring unknown
// ones.
func Domains(ids ...string) []string {
	var domains []string
	for _, id := range ids {
		if s, ok := Lookup(strings.ToLower(id)); ok {
			domains = append(domains, s.Domains...)
		}
	}
	return domains
}
