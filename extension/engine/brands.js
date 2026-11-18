// Brands that are frequently impersonated in phishing campaigns, with the
// registrable domains each brand legitimately owns. The `label` is the
// second-level name we compare look-alike domains against.
//
// Contributions welcome: keep entries lowercase and only list domains the
// brand actually controls.

export const BRANDS = [
  { label: 'paypal', domains: ['paypal.com', 'paypal.me', 'paypalobjects.com'] },
  { label: 'apple', domains: ['apple.com', 'icloud.com', 'me.com'] },
  { label: 'icloud', domains: ['icloud.com', 'apple.com'] },
  { label: 'microsoft', domains: ['microsoft.com', 'live.com', 'office.com', 'microsoftonline.com', 'outlook.com', 'azure.com', 'bing.com'] },
  { label: 'office', domains: ['office.com', 'microsoft.com', 'office365.com'] },
  { label: 'outlook', domains: ['outlook.com', 'live.com', 'microsoft.com'] },
  { label: 'google', domains: ['google.com', 'gmail.com', 'youtube.com', 'googleusercontent.com', 'gstatic.com'] },
  { label: 'gmail', domains: ['gmail.com', 'google.com'] },
  { label: 'amazon', domains: ['amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.ca', 'amazon.co.jp', 'amazonaws.com', 'aws.amazon.com'] },
  { label: 'netflix', domains: ['netflix.com'] },
  { label: 'facebook', domains: ['facebook.com', 'fb.com', 'meta.com', 'messenger.com'] },
  { label: 'instagram', domains: ['instagram.com'] },
  { label: 'whatsapp', domains: ['whatsapp.com', 'whatsapp.net'] },
  { label: 'linkedin', domains: ['linkedin.com', 'lnkd.in'] },
  { label: 'twitter', domains: ['twitter.com', 'x.com', 't.co'] },
  { label: 'github', domains: ['github.com', 'github.io', 'githubusercontent.com'] },
  { label: 'dropbox', domains: ['dropbox.com', 'dropboxusercontent.com'] },
  { label: 'docusign', domains: ['docusign.com', 'docusign.net'] },
  { label: 'adobe', domains: ['adobe.com'] },
  { label: 'chase', domains: ['chase.com', 'jpmorganchase.com'] },
  { label: 'wellsfargo', domains: ['wellsfargo.com'] },
  { label: 'bankofamerica', domains: ['bankofamerica.com', 'bofa.com'] },
  { label: 'citibank', domains: ['citibank.com', 'citi.com'] },
  { label: 'hsbc', domains: ['hsbc.com', 'hsbc.co.uk'] },
  { label: 'barclays', domains: ['barclays.co.uk', 'barclays.com'] },
  { label: 'americanexpress', domains: ['americanexpress.com'] },
  { label: 'coinbase', domains: ['coinbase.com'] },
  { label: 'binance', domains: ['binance.com'] },
  { label: 'metamask', domains: ['metamask.io'] },
  { label: 'steam', domains: ['steampowered.com', 'steamcommunity.com'] },
  { label: 'steamcommunity', domains: ['steamcommunity.com'] },
  { label: 'roblox', domains: ['roblox.com'] },
  { label: 'discord', domains: ['discord.com', 'discord.gg', 'discordapp.com'] },
  { label: 'ebay', domains: ['ebay.com', 'ebay.co.uk', 'ebay.de'] },
  { label: 'walmart', domains: ['walmart.com'] },
  { label: 'dhl', domains: ['dhl.com', 'dhl.de'] },
  { label: 'fedex', domains: ['fedex.com'] },
  { label: 'usps', domains: ['usps.com'] },
  { label: 'ups', domains: ['ups.com'] },
  { label: 'irs', domains: ['irs.gov'] },
  { label: 'yahoo', domains: ['yahoo.com'] },
  { label: 'spotify', domains: ['spotify.com'] },
  { label: 'zoom', domains: ['zoom.us', 'zoom.com'] },
  { label: 'slack', domains: ['slack.com'] },
  { label: 'okta', domains: ['okta.com'] },
];

/** Set of every registrable domain owned by a listed brand. */
export const OFFICIAL_DOMAINS = new Set(BRANDS.flatMap((b) => b.domains));

// Labels shorter than this are too ambiguous for fuzzy matching ("ups",
// "irs", "dhl" would match half the internet at edit distance 1).
export const MIN_FUZZY_LABEL_LENGTH = 5;
