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

// Service categories.
const (
	CategorySocial    = "social"
	CategoryVideo     = "video"
	CategoryGaming    = "gaming"
	CategoryMessaging = "messaging"
)

// Service is an app or site, by the domains it uses.
type Service struct {
	// ID identifies the service in profiles, such as "tiktok".
	ID string `json:"id"`

	// Name is its name for people, such as "TikTok".
	Name string `json:"name"`

	// Category groups services: CategorySocial, CategoryVideo,
	// CategoryGaming, or CategoryMessaging.
	Category string `json:"category"`

	// Domains are the domains it uses, each with its subdomains.
	Domains []string `json:"domains"`
}

// Catalog is every known service, in the order they're presented.
var Catalog = []Service{
	{ID: "tiktok", Name: "TikTok", Category: CategorySocial, Domains: []string{
		"tiktok.com", "tiktokv.com", "tiktokv.us", "tiktokcdn.com", "tiktokcdn-us.com", "tiktokcdn-eu.com",
		"tiktokw.us", "ttwstatic.com", "byteoversea.com", "ibytedtos.com", "ibyteimg.com", "musical.ly",
	}},
	{ID: "instagram", Name: "Instagram", Category: CategorySocial, Domains: []string{
		"instagram.com", "cdninstagram.com", "ig.me", "instagr.am",
	}},
	{ID: "facebook", Name: "Facebook", Category: CategorySocial, Domains: []string{
		"facebook.com", "fb.com", "fb.me", "fbcdn.net", "facebook.net", "fbsbx.com", "messenger.com",
	}},
	{ID: "snapchat", Name: "Snapchat", Category: CategorySocial, Domains: []string{
		"snapchat.com", "snap.com", "sc-cdn.net", "sc-static.net", "snapkit.com", "snap-dev.net", "feelinsonice-hrd.appspot.com",
	}},
	{ID: "x", Name: "X (Twitter)", Category: CategorySocial, Domains: []string{
		"x.com", "twitter.com", "twimg.com", "t.co",
	}},
	{ID: "reddit", Name: "Reddit", Category: CategorySocial, Domains: []string{
		"reddit.com", "redd.it", "redditmedia.com", "redditstatic.com", "reddituploads.com",
	}},
	{ID: "pinterest", Name: "Pinterest", Category: CategorySocial, Domains: []string{
		"pinterest.com", "pinimg.com", "pin.it",
	}},
	{ID: "youtube", Name: "YouTube", Category: CategoryVideo, Domains: []string{
		"youtube.com", "youtu.be", "ytimg.com", "googlevideo.com", "youtube-nocookie.com",
		"youtubei.googleapis.com", "youtube.googleapis.com", "youtubekids.com",
	}},
	{ID: "twitch", Name: "Twitch", Category: CategoryVideo, Domains: []string{
		"twitch.tv", "ttvnw.net", "jtvnw.net", "twitchcdn.net", "twitchsvc.net",
	}},
	{ID: "netflix", Name: "Netflix", Category: CategoryVideo, Domains: []string{
		"netflix.com", "netflix.net", "nflxvideo.net", "nflximg.net", "nflximg.com", "nflxext.com", "nflxso.net",
	}},
	{ID: "roblox", Name: "Roblox", Category: CategoryGaming, Domains: []string{
		"roblox.com", "rbxcdn.com", "rbx.com", "robloxlabs.com", "roblox.cn",
	}},
	{ID: "fortnite", Name: "Fortnite", Category: CategoryGaming, Domains: []string{
		"fortnite.com", "epicgames.com", "epicgames.dev", "epicgames.net", "unrealengine.com",
	}},
	{ID: "minecraft", Name: "Minecraft", Category: CategoryGaming, Domains: []string{
		"minecraft.net", "mojang.com", "minecraftservices.com", "minecraft-services.net",
	}},
	{ID: "steam", Name: "Steam", Category: CategoryGaming, Domains: []string{
		"steampowered.com", "steamcommunity.com", "steamstatic.com", "steamcontent.com", "steamserver.net", "steamgames.com",
	}},
	{ID: "discord", Name: "Discord", Category: CategoryMessaging, Domains: []string{
		"discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.media", "discordcdn.com",
	}},
	{ID: "whatsapp", Name: "WhatsApp", Category: CategoryMessaging, Domains: []string{
		"whatsapp.com", "whatsapp.net", "wa.me",
	}},
	{ID: "telegram", Name: "Telegram", Category: CategoryMessaging, Domains: []string{
		"telegram.org", "telegram.me", "t.me", "telegra.ph", "telesco.pe",
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
