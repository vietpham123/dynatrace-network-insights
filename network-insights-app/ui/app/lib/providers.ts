/* ============================================================================
   Destination classification — who is on the other end, and what KIND of thing they are.

   WHY NOT LOGOS. A Dynatrace app runs under a strict CSP, so a remote image (Clearbit, a
   favicon service, a CDN) is simply blocked — anything visual must be bundled or drawn.
   Bundling brand artwork then makes it a trademark question rather than a technical one,
   which is not a decision this file should make on a customer's behalf.

   WHY CATEGORY IS BETTER ANYWAY. "Amazon" with a logo tells an operator something they
   already knew from the name. "PacketHub S.A. — hosting / VPN" tells them something they
   did not, and it is the fact that changes what they do next: egress to a CDN is routine,
   egress to an anonymous hoster is worth a look. Classification is analysis; a logo is
   decoration.

   KEYED ON ASN FIRST. The AS number is the stable identity — organisation strings drift
   between registries and rDNS is often absent. Name matching is only a fallback for
   networks not in the table, and the category is left UNKNOWN rather than guessed when
   nothing matches: an unclassified destination must not silently read as "ordinary".
   ============================================================================ */

export type ProviderCategory = "cloud" | "cdn" | "saas" | "hosting" | "isp" | "security" | "unknown";

export const CATEGORY_LABEL: Record<ProviderCategory, string> = {
  cloud: "Cloud platform",
  cdn: "CDN / edge",
  saas: "SaaS",
  hosting: "Hosting / VPS",
  isp: "ISP / carrier",
  security: "Security service",
  unknown: "Unclassified",
};

// CATEGORY -> Strato icon NAME. Deliberately the Dynatrace icon set rather than hand-drawn
// glyphs or bundled brand artwork: it is already a dependency, it matches the icon language a
// Dynatrace operator reads everywhere else in the product, and it sidesteps the trademark
// question entirely. The mapping lives here as a string so this module stays free of React —
// the component resolves it.
export const CATEGORY_ICON: Record<ProviderCategory, string> = {
  cloud: "DataCenterIcon",
  cdn: "InternetIcon",
  saas: "ApplicationsIcon",
  hosting: "HostsIcon",
  isp: "NetworkDevicesIcon",
  security: "ApplicationSecurityIcon",
  unknown: "ConnectorIcon",
};

/** ASN -> (short name, category). Curated, not exhaustive — the fallback is honest. */
const BY_ASN: Record<number, { short: string; cat: ProviderCategory }> = {
  16509: { short: "AWS", cat: "cloud" },
  14618: { short: "AWS", cat: "cloud" },
  8075: { short: "Microsoft", cat: "cloud" },
  12076: { short: "Microsoft", cat: "cloud" },
  15169: { short: "Google", cat: "cloud" },
  396982: { short: "Google Cloud", cat: "cloud" },
  32934: { short: "Meta", cat: "saas" },
  13335: { short: "Cloudflare", cat: "cdn" },
  20940: { short: "Akamai", cat: "cdn" },
  16625: { short: "Akamai", cat: "cdn" },
  63949: { short: "Akamai Cloud", cat: "hosting" },
  54113: { short: "Fastly", cat: "cdn" },
  22822: { short: "Edgio", cat: "cdn" },
  32590: { short: "Valve", cat: "saas" },
  2906: { short: "Netflix", cat: "saas" },
  36459: { short: "GitHub", cat: "saas" },
  399358: { short: "Anthropic", cat: "saas" },   // verified from the live feed 2026-08-03
  41231:  { short: "Canonical", cat: "saas" },
  14061: { short: "DigitalOcean", cat: "hosting" },
  16276: { short: "OVH", cat: "hosting" },
  24940: { short: "Hetzner", cat: "hosting" },
  141039: { short: "PacketHub", cat: "hosting" },
  49453: { short: "Global Layer", cat: "hosting" },
  62240: { short: "Clouvider", cat: "hosting" },
  19281: { short: "Quad9", cat: "security" },
};

// Fallback keywords, applied to the organisation string when the ASN is unknown.
const BY_NAME: { m: RegExp; short: string; cat: ProviderCategory }[] = [
  { m: /amazon|aws/i, short: "AWS", cat: "cloud" },
  { m: /microsoft|azure/i, short: "Microsoft", cat: "cloud" },
  { m: /google/i, short: "Google", cat: "cloud" },
  { m: /cloudflare/i, short: "Cloudflare", cat: "cdn" },
  { m: /akamai/i, short: "Akamai", cat: "cdn" },
  { m: /fastly/i, short: "Fastly", cat: "cdn" },
  { m: /github/i, short: "GitHub", cat: "saas" },
  { m: /anthropic/i, short: "Anthropic", cat: "saas" },
  { m: /apple/i, short: "Apple", cat: "saas" },
  { m: /\bvpn\b|packethub|nord|surfshark/i, short: "", cat: "hosting" },
  { m: /hosting|server|vps|datacent|data cent|colo/i, short: "", cat: "hosting" },
  { m: /telecom|communications|broadband|cable|wireless|isp/i, short: "", cat: "isp" },
];

export type Provider = { short: string; category: ProviderCategory; label: string; icon: string; initials: string };

/** Classify a destination. `org` is the raw flow.dst_org; asn is preferred when present. */
export function classifyProvider(org: string | undefined, asn?: number): Provider {
  const clean = prettyName(org || "");
  let short = "";
  let cat: ProviderCategory = "unknown";

  if (asn != null && BY_ASN[asn]) {
    short = BY_ASN[asn].short;
    cat = BY_ASN[asn].cat;
  } else {
    for (const r of BY_NAME) {
      if (r.m.test(clean)) { short = r.short || clean; cat = r.cat; break; }
    }
  }
  const name = short || clean || "Unresolved";
  return {
    short: name,
    category: cat,
    label: CATEGORY_LABEL[cat],
    icon: CATEGORY_ICON[cat],
    initials: initialsOf(name),
  };
}

function prettyName(raw: string): string {
  let s = String(raw || "").trim();
  const dash = s.indexOf(" - ");
  if (dash > 0) s = s.slice(dash + 3).trim();
  return s.replace(/,\s*[A-Z]{2}$/, "").trim();
}

function initialsOf(name: string): string {
  const words = name.replace(/[^A-Za-z0-9 .]/g, " ").split(/\s+/).filter(Boolean);
  if (!words.length) return "?";
  if (words.length === 1) return words[0].slice(0, 2).toUpperCase();
  return (words[0][0] + words[1][0]).toUpperCase();
}

// Stable colour per name, so a provider keeps its identity between renders and between pages.
const HUES = ["#3987e5", "#008300", "#d55181", "#c98500", "#199e70", "#d95926", "#7a5cd6"];
export function providerHue(name: string): string {
  let h = 0;
  for (let i = 0; i < name.length; i++) h = (h * 31 + name.charCodeAt(i)) >>> 0;
  return HUES[h % HUES.length];
}
