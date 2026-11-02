package filter

// brands are the names typosquatting protection guards: banks, payments,
// email, big tech, shopping, shipping, and government services that
// phishing imitates most. Each lists the registrable domains the brand
// uses, so its own names, and its own look-alike names, are never flagged.
//
// Names that are ordinary words or close to them (apple, chase, costco,
// which is a letter from cosco), or that are short, are matched exactly,
// never by edit distance (edits is zero), since too many legitimate
// domains are a letter away from a word: apply.com isn't a typo of
// apple.com. They're still matched with look-alike characters (app1e) and
// risk words (apple-login).
//
// Keep the list curated: a brand belongs here only if it's phished often
// and its legitimate domains are known. Add domains a brand uses as they
// turn up; a missing one is a false positive.
var brands = []brand{
	// Payments and money.
	{name: "paypal", edits: 1, domains: []string{"paypal.com", "paypal.me", "paypalobjects.com", "paypal-community.com", "paypal-prepaid.com", "paypalcorp.com", "paypal-mktg.com", "paypal-dynamic.com"}},
	{name: "venmo", domains: []string{"venmo.com"}},
	{name: "stripe", domains: []string{"stripe.com", "stripe.network", "stripecdn.com"}},
	{name: "squareup", domains: []string{"squareup.com", "square.com", "squarecdn.com"}},
	{name: "cashapp", domains: []string{"cash.app", "cashapp.com"}},
	{name: "zelle", domains: []string{"zellepay.com", "zelle.com"}},
	{name: "revolut", domains: []string{"revolut.com"}},
	{name: "klarna", domains: []string{"klarna.com", "klarnacdn.net", "klarnaservices.com"}},
	{name: "afterpay", edits: 1, domains: []string{"afterpay.com"}},
	{name: "coinbase", edits: 1, domains: []string{"coinbase.com", "cbhq.net"}},
	{name: "binance", domains: []string{"binance.com", "binance.us", "bnbstatic.com"}},
	{name: "metamask", edits: 1, domains: []string{"metamask.io"}},
	{name: "americanexpress", edits: 1, domains: []string{"americanexpress.com", "aexp.com", "aexp-static.com"}},
	{name: "amex", domains: []string{"americanexpress.com"}},
	{name: "mastercard", edits: 1, domains: []string{"mastercard.com", "mastercard.us"}},
	{name: "visa", domains: []string{"visa.com"}},

	// Banks.
	{name: "chase", domains: []string{"chase.com", "jpmorganchase.com", "jpmorgan.com", "chasecdn.com"}},
	{name: "jpmorgan", edits: 1, domains: []string{"jpmorgan.com", "jpmorganchase.com"}},
	{name: "bankofamerica", edits: 2, domains: []string{"bankofamerica.com", "bofa.com", "bac-assets.com", "ml.com"}},
	{name: "wellsfargo", edits: 1, domains: []string{"wellsfargo.com", "wf.com", "wellsfargoadvisors.com", "wellsfargomedia.com"}},
	{name: "citibank", edits: 1, domains: []string{"citibank.com", "citi.com", "citigroup.com", "citibankonline.com"}},
	{name: "capitalone", edits: 1, domains: []string{"capitalone.com", "capitalone360.com"}},
	{name: "usbank", domains: []string{"usbank.com"}},
	{name: "truist", domains: []string{"truist.com"}},
	{name: "schwab", domains: []string{"schwab.com", "schwabcdn.com"}},
	{name: "fidelity", domains: []string{"fidelity.com", "fidelityinvestments.com", "fmr.com"}},
	{name: "robinhood", domains: []string{"robinhood.com"}},
	{name: "hsbc", domains: []string{"hsbc.com", "hsbc.co.uk", "hsbc.com.hk", "hsbcnet.com"}},
	{name: "barclays", edits: 1, domains: []string{"barclays.co.uk", "barclays.com", "barclaycard.co.uk"}},
	{name: "santander", edits: 1, domains: []string{"santander.com", "santander.co.uk", "santanderbank.com"}},
	{name: "lloydsbank", edits: 1, domains: []string{"lloydsbank.com", "lloydsbank.co.uk", "lloydsbankinggroup.com"}},
	{name: "natwest", domains: []string{"natwest.com"}},
	{name: "monzo", domains: []string{"monzo.com"}},
	{name: "commbank", domains: []string{"commbank.com.au"}},
	{name: "westpac", domains: []string{"westpac.com.au", "westpac.co.nz"}},
	{name: "scotiabank", edits: 1, domains: []string{"scotiabank.com"}},
	{name: "interac", domains: []string{"interac.ca"}},
	{name: "sparkasse", edits: 1, domains: []string{"sparkasse.de", "sparkasse.at"}},
	{name: "deutschebank", edits: 1, domains: []string{"deutsche-bank.de", "db.com"}},

	// Email, accounts, and big tech.
	{name: "google", edits: 1, domains: []string{
		"google.com", "googleapis.com", "gstatic.com", "googlevideo.com", "googleusercontent.com", "googlesyndication.com",
		"googletagmanager.com", "google-analytics.com", "googleadservices.com", "googlemail.com", "gmail.com", "youtube.com",
		"goo.gl", "g.co", "withgoogle.com", "googleblog.com", "googledrive.com", "googlesource.com", "googlezip.net",
		"googletagservices.com", "googleoptimize.com", "googlecode.com", "google.dev", "googleplex.com", "googleworkspace.com",
	}},
	{name: "gmail", domains: []string{"gmail.com", "googlemail.com"}},
	{name: "youtube", edits: 1, domains: []string{"youtube.com", "youtu.be", "ytimg.com", "youtube-nocookie.com", "youtubekids.com"}},
	{name: "microsoft", edits: 1, domains: []string{
		"microsoft.com", "microsoftonline.com", "live.com", "outlook.com", "office.com", "office.net", "office365.com",
		"msn.com", "bing.com", "azure.com", "azure.net", "windows.com", "windows.net", "sharepoint.com", "onmicrosoft.com",
		"msftauth.net", "msauth.net", "s-microsoft.com", "cloud.microsoft", "microsoftstore.com", "microsoft365.com", "skype.com", "xbox.com", "msftconnecttest.com",
		"microsoftonline-p.com", "msecnd.net", "aka.ms", "visualstudio.com", "onedrive.com", "hotmail.com",
	}},
	{name: "outlook", edits: 1, domains: []string{"outlook.com", "office.com", "live.com"}},
	{name: "office365", edits: 1, domains: []string{"office365.com", "office.com"}},
	{name: "microsoft365", edits: 1, domains: []string{"microsoft365.com", "microsoft.com"}},
	{name: "hotmail", edits: 1, domains: []string{"hotmail.com", "live.com", "outlook.com"}},
	{name: "onedrive", edits: 1, domains: []string{"onedrive.com", "live.com"}},
	{name: "sharepoint", edits: 1, domains: []string{"sharepoint.com"}},
	{name: "apple", domains: []string{"apple.com", "icloud.com", "me.com", "mzstatic.com", "apple-dns.net", "cdn-apple.com", "apple-cloudkit.com", "applemusic.com", "apple.news", "appleid.com"}},
	{name: "icloud", domains: []string{"icloud.com", "icloud-content.com", "apple.com"}},
	{name: "itunes", domains: []string{"itunes.com", "apple.com"}},
	{name: "amazon", edits: 1, domains: []string{
		"amazon.com", "amazonaws.com", "media-amazon.com", "ssl-images-amazon.com", "amazon-adsystem.com", "amazontrust.com",
		"amazonpay.com", "amazonvideo.com", "primevideo.com", "a2z.com", "aws.amazon.com", "amazon.jobs", "amazon.dev", "awsstatic.com",
	}},
	{name: "facebook", edits: 1, domains: []string{"facebook.com", "fb.com", "fbcdn.net", "facebook.net", "fbsbx.com", "messenger.com", "meta.com", "fb.me"}},
	{name: "instagram", edits: 1, domains: []string{"instagram.com", "cdninstagram.com", "ig.me"}},
	{name: "whatsapp", edits: 1, domains: []string{"whatsapp.com", "whatsapp.net", "wa.me"}},
	{name: "linkedin", edits: 1, domains: []string{"linkedin.com", "licdn.com", "lnkd.in"}},
	{name: "twitter", domains: []string{"twitter.com", "x.com", "twimg.com", "t.co"}},
	{name: "netflix", edits: 1, domains: []string{"netflix.com", "netflix.net", "nflxvideo.net", "nflximg.net", "nflximg.com", "nflxso.net", "nflxext.com"}},
	{name: "spotify", edits: 1, domains: []string{"spotify.com", "scdn.co", "spotifycdn.com", "spotify.link"}},
	{name: "adobe", domains: []string{"adobe.com", "adobe.io", "adobelogin.com", "typekit.net", "adobedtm.com"}},
	{name: "dropbox", edits: 1, domains: []string{"dropbox.com", "dropboxusercontent.com", "dropboxstatic.com", "dropboxapi.com", "db.tt"}},
	{name: "docusign", edits: 1, domains: []string{"docusign.com", "docusign.net"}},
	{name: "github", domains: []string{"github.com", "githubusercontent.com", "githubassets.com", "github.dev", "github.blog"}},
	{name: "gitlab", domains: []string{"gitlab.com", "gitlab.io", "gitlab-static.net"}},
	{name: "yahoo", domains: []string{"yahoo.com", "yimg.com", "yahoodns.net", "yahoo.co.jp", "yahooapis.com", "aol.com"}},
	{name: "protonmail", edits: 1, domains: []string{"protonmail.com", "proton.me", "protonmail.ch"}},
	{name: "okta", domains: []string{"okta.com", "oktacdn.com", "okta-emea.com"}},
	{name: "salesforce", domains: []string{"salesforce.com", "force.com", "salesforce-sites.com", "sfdcstatic.com"}},
	{name: "cloudflare", edits: 1, domains: []string{"cloudflare.com", "cloudflare.net", "cloudflare-dns.com", "cloudflareinsights.com", "workers.dev", "pages.dev"}},
	{name: "godaddy", edits: 1, domains: []string{"godaddy.com", "secureserver.net", "godaddysites.com"}},

	// Games and social.
	{name: "steamcommunity", edits: 1, domains: []string{"steamcommunity.com", "steampowered.com", "steamstatic.com"}},
	{name: "steampowered", edits: 1, domains: []string{"steampowered.com", "steamcommunity.com", "steamstatic.com"}},
	{name: "epicgames", edits: 1, domains: []string{"epicgames.com", "epicgames.dev", "unrealengine.com"}},
	{name: "playstation", edits: 1, domains: []string{"playstation.com", "playstation.net", "sonyentertainmentnetwork.com"}},
	{name: "nintendo", edits: 1, domains: []string{"nintendo.com", "nintendo.net", "nintendo.co.jp"}},
	{name: "roblox", edits: 1, domains: []string{"roblox.com", "rbxcdn.com", "rbx.com"}},
	{name: "discord", domains: []string{"discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.media"}},
	{name: "telegram", domains: []string{"telegram.org", "t.me", "telegram.me", "telegra.ph"}},
	{name: "tiktok", edits: 1, domains: []string{"tiktok.com", "tiktokcdn.com", "tiktokv.com", "tiktokv.us", "tiktokw.us", "tiktokw.eu", "tiktokv.eu", "byteoversea.com", "ttwstatic.com"}},
	{name: "snapchat", edits: 1, domains: []string{"snapchat.com", "snap.com", "sc-cdn.net", "snapkit.com"}},

	// Shopping.
	{name: "ebay", domains: []string{"ebay.com", "ebayimg.com", "ebaystatic.com", "ebay.co.uk", "ebay.de"}},
	{name: "walmart", domains: []string{"walmart.com", "walmartimages.com", "wal.co", "wal-mart.com"}},
	{name: "costco", domains: []string{"costco.com"}},
	{name: "bestbuy", edits: 1, domains: []string{"bestbuy.com", "bbystatic.com"}},
	{name: "aliexpress", domains: []string{"aliexpress.com", "aliexpress.us", "alicdn.com"}},
	{name: "alibaba", edits: 1, domains: []string{"alibaba.com", "alicdn.com", "alibabacloud.com"}},
	{name: "shopify", domains: []string{"shopify.com", "myshopify.com", "shopifycdn.com", "shopifysvc.com", "shop.app"}},
	{name: "airbnb", edits: 1, domains: []string{"airbnb.com", "muscache.com", "airbnb.co.uk"}},

	// Shipping and post.
	{name: "dhl", domains: []string{"dhl.com", "dhl.de", "dhl.co.uk", "dhlparcel.nl", "dpdhl.com"}},
	{name: "fedex", domains: []string{"fedex.com"}},
	{name: "ups", domains: []string{"ups.com"}},
	{name: "usps", domains: []string{"usps.com", "usps.gov"}},
	{name: "royalmail", edits: 1, domains: []string{"royalmail.com", "royalmail.co.uk", "royalmailgroup.com"}},
	{name: "canadapost", edits: 1, domains: []string{"canadapost.ca", "canadapost-postescanada.ca", "postescanada.ca"}},
	{name: "auspost", edits: 1, domains: []string{"auspost.com.au"}},
	{name: "evri", domains: []string{"evri.com"}},
	{name: "inpost", domains: []string{"inpost.pl", "inpost.co.uk", "inpost.eu"}},
	{name: "laposte", domains: []string{"laposte.fr", "laposte.net"}},
	{name: "postnl", domains: []string{"postnl.nl"}},

	// Government and telecoms.
	{name: "irs", domains: []string{"irs.gov"}},
	{name: "hmrc", domains: []string{"gov.uk"}},
	{name: "medicare", domains: []string{"medicare.gov"}},
	{name: "verizon", edits: 1, domains: []string{"verizon.com", "verizonwireless.com", "vzw.com"}},
	{name: "tmobile", domains: []string{"t-mobile.com", "tmobile.com", "t-mobile.de"}},
	{name: "xfinity", domains: []string{"xfinity.com", "comcast.net", "comcast.com"}},
	{name: "comcast", edits: 1, domains: []string{"comcast.com", "comcast.net", "xfinity.com"}},
	{name: "vodafone", edits: 1, domains: []string{"vodafone.com", "vodafone.co.uk", "vodafone.de"}},
}

// trustedDomains are legitimate domains close to a brand, which the
// detector would otherwise flag: organizations of their own, found by
// running it over the Tranco list's top million domains and reviewing
// what it flagged. Their subdomains are trusted too. The list can't be
// complete; profiles' allow lists cover the rest.
var trustedDomains = []string{
	"paypay.ne.jp",            // PayPay, a Japanese payment service
	"paipai.com", "paipai.fm", // Paipai, a Chinese marketplace
	"citicbank.com", "citicbank.cn", // China CITIC Bank
	"bankofafrica.ma",           // Bank of Africa
	"ausport.gov.au",            // the Australian Sports Commission
	"amazone.de", "amazone.net", // Amazone, a maker of farm machinery
	"amaron.com",    // Amaron, a battery maker
	"imazon.org.br", // Imazon, an Amazon research institute
	"1cloud.ru",     // a Russian cloud provider
	"fairbnb.coop",  // Fairbnb, a cooperative rental site
	"netfile.com",   // NetFile, a filing service
}

// riskWords are words phishing domains combine with a brand to look like
// one of its sign-in, account, or delivery pages, as in
// paypal-login.com or secure-paypal-account.net.
var riskWords = []string{
	"login", "logon", "signin", "verify", "verification", "verified", "validate", "validation",
	"secure", "security", "account", "accounts", "auth", "authenticate", "authentication", "password",
	"recover", "recovery", "unlock", "unlocked", "locked", "confirm", "confirmation", "suspended", "suspend",
	"alert", "alerts", "billing", "invoice", "refund", "refunds", "wallet", "webscr", "update", "updates",
	"support", "helpdesk", "customer", "id", "reset", "restore", "restored", "limited", "unusual",
	"activate", "activation", "giveaway", "airdrop",
	"tracking", "track", "delivery", "parcel", "shipment", "redelivery", "customs", "payment",
}

// infraDomains are content delivery networks, DNS blocklists, and
// reputation services whose host names embed other domains' names, as in
// www.paypal.com.edgekey.net (a CNAME target) or paypal.com.dbl.spamhaus.org
// (a mail server's blocklist query). Names under them are never flagged
// as typosquats.
var infraDomains = newDomainSet([]string{
	"akamai.net", "akamaiedge.net", "akamaihd.net", "akamaized.net", "akadns.net", "akamaitechnologies.com",
	"edgekey.net", "edgesuite.net", "cloudflare.net", "fastly.net", "fastlylb.net", "trafficmanager.net",
	"azureedge.net", "azurefd.net", "edgecastcdn.net", "impervadns.net", "incapdns.net", "cdn77.org",
	"llnwd.net", "footprint.net", "b-cdn.net", "stackpathdns.com", "kxcdn.com", "cdngc.net", "sucuri.net",
	"spamhaus.org", "spamhaus.net", "uribl.com", "surbl.org", "dnswl.org", "mailspike.net", "spameatingmonkey.net",
	"barracudacentral.org", "sorbs.net", "abuseat.org", "senderscore.com", "sophosxl.net", "mcafee.com",
	"trendmicro.com", "webroot.com", "dnsbl.info", "invaluement.com", "nordspam.com",
})

// userContentDomains are platforms whose subdomains anyone can claim,
// such as GitHub Pages and Firebase, including some that brands own.
// Their own names aren't typosquats, but subdomains like
// paypal-login.web.app are checked.
var userContentDomains = newDomainSet([]string{
	"github.io", "gitlab.io", "web.app", "firebaseapp.com", "appspot.com", "blogspot.com", "sharepoint.com",
	"azurewebsites.net", "herokuapp.com", "netlify.app", "vercel.app", "pages.dev", "workers.dev",
	"000webhostapp.com", "wixsite.com", "weebly.com", "godaddysites.com", "glitch.me", "repl.co",
	"ngrok.io", "ngrok-free.app", "amazonaws.com", "cloudfront.net", "myshopify.com", "webflow.io",
	"framer.app", "googleusercontent.com", "translate.goog", "r2.dev", "onrender.com", "fly.dev",
})
