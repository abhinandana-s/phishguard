/**
 * PhishGuard - Advanced rule-based phishing detection engine
 * Multi-factor risk analysis with confidence scoring and explainable output
 */

export interface DetectionRule {
  id: string;
  name: string;
  description: string;
  weight: number;
  check: (urlObj: URL) => boolean;
}

export interface DetectionResult {
  url: string;
  threatLevel: "safe" | "suspicious" | "dangerous";
  riskScore: number;
  confidence: "LOW" | "MEDIUM" | "HIGH";
  reasons: string[];
  recommendation: string;
  triggeredRules: Array<{
    id: string;
    name: string;
    description: string;
    weight: number;
  }>;
}

// Suspicious keywords that often appear in phishing URLs
// Focus on action words that indicate user interaction, not brand names
const SUSPICIOUS_KEYWORDS = [
  "login",
  "verify",
  "account",
  "confirm",
  "update",
  "authenticate",
  "validate",
  "authorize",
  "password",
  "signin",
  "reset",
  "verify-account",
];

// Common phishing TLDs
const SUSPICIOUS_TLDS = [
  ".tk",
  ".ml",
  ".ga",
  ".cf",
  ".gq",
  ".pw",
  ".xyz",
  ".download",
  ".review",
  ".trade",
  ".cricket",
  ".accountant",
];

// Blacklist of known phishing domains (mock data)
const BLACKLISTED_DOMAINS = [
  "paypa1.com",
  "amaz0n.com",
  "apple-verify.com",
  "microsoft-security.com",
  "google-account-verify.com",
];

// Detection rules with weighted scoring
const DETECTION_RULES: DetectionRule[] = [
  {
    id: "url_length",
    name: "Excessive URL Length",
    description: "URL is unusually long (>75 characters), often used to obfuscate the real destination",
    weight: 15,
    check: (urlObj) => urlObj.href.length > 75,
  },
  {
    id: "at_symbol",
    name: "@ Symbol in URL",
    description: "URL contains @ symbol, which can be used to hide the real domain",
    weight: 25,
    check: (urlObj) => urlObj.href.includes("@"),
  },
  {
    id: "excessive_hyphens",
    name: "Excessive Hyphens",
    description: "Domain contains multiple hyphens, often used in typosquatting",
    weight: 20,
    check: (urlObj) => {
      const hostname = urlObj.hostname;
      const hyphens = (hostname.match(/-/g) || []).length;
      return hyphens > 2;
    },
  },
  {
    id: "ip_address",
    name: "IP Address Instead of Domain",
    description: "URL uses IP address instead of domain name, suspicious for phishing",
    weight: 30,
    check: (urlObj) => {
      const hostname = urlObj.hostname;
      const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
      return ipPattern.test(hostname);
    },
  },
  {
    id: "no_https",
    name: "Missing HTTPS Protocol",
    description: "URL does not use HTTPS encryption, data could be intercepted",
    weight: 20,
    check: (urlObj) => urlObj.protocol !== "https:",
  },
  {
    id: "suspicious_keywords",
    name: "Suspicious Keywords",
    description: "URL contains keywords commonly used in phishing attempts",
    weight: 25,
    check: (urlObj) => {
      const urlLower = urlObj.href.toLowerCase();
      return SUSPICIOUS_KEYWORDS.some((keyword) => urlLower.includes(keyword));
    },
  },
  {
    id: "suspicious_tld",
    name: "Suspicious Top-Level Domain",
    description: "URL uses a TLD commonly associated with phishing",
    weight: 20,
    check: (urlObj) => {
      const hostname = urlObj.hostname;
      return SUSPICIOUS_TLDS.some((tld) => hostname.endsWith(tld));
    },
  },
  {
    id: "excessive_subdomains",
    name: "Excessive Subdomains",
    description: "URL has too many subdomains, often used to obfuscate the real domain",
    weight: 18,
    check: (urlObj) => {
      const hostname = urlObj.hostname;
      const subdomains = hostname.split(".").length;
      return subdomains > 3;
    },
  },
  {
    id: "port_number",
    name: "Non-Standard Port",
    description: "URL uses a non-standard port, which could bypass security filters",
    weight: 15,
    check: (urlObj) => {
      const port = urlObj.port;
      const protocol = urlObj.protocol;
      if (!port) return false;
      if (protocol === "http:" && port !== "80") return true;
      if (protocol === "https:" && port !== "443") return true;
      return false;
    },
  },
  {
    id: "blacklisted_domain",
    name: "Known Phishing Domain",
    description: "Domain is on our known phishing blacklist",
    weight: 40,
    check: (urlObj) => {
      const hostname = urlObj.hostname;
      return BLACKLISTED_DOMAINS.some((domain) => hostname.includes(domain));
    },
  },
  {
    id: "url_encoding",
    name: "URL Encoding Obfuscation",
    description: "URL contains encoded characters that could hide the real destination",
    weight: 22,
    check: (urlObj) => {
      const url = urlObj.href;
      return /%[0-9A-Fa-f]{2}/.test(url);
    },
  },
  {
    id: "homograph_attack",
    name: "Homograph Attack Indicators",
    description: "URL contains characters that look similar to legitimate domains",
    weight: 28,
    check: (urlObj) => {
      const hostname = urlObj.hostname;
      const hasNumbers = /[0-9]/.test(hostname);
      const hasLetters = /[a-z]/i.test(hostname);
      if (hasNumbers && hasLetters) {
        const suspiciousPattern = /[0o1il][0o1il]/i;
        return suspiciousPattern.test(hostname);
      }
      return false;
    },
  },
  {
    id: "domain_entropy",
    name: "High Domain Entropy",
    description: "Domain appears random or generated, typical of phishing sites",
    weight: 18,
    check: (urlObj) => {
      const hostname = urlObj.hostname;
      const domain = hostname.split(".")[0];
      // Check for high entropy: many consonants in a row, unusual patterns
      const consonantRuns = (domain.match(/[bcdfghjklmnpqrstvwxyz]{4,}/gi) || []).length;
      const randomPattern = /[aeiou]{0,1}[bcdfghjklmnpqrstvwxyz]{3,}[aeiou]{0,1}/gi;
      return consonantRuns > 0 || randomPattern.test(domain);
    },
  },
];

/**
 * Calculate domain entropy score (0-1)
 * Higher entropy = more random-looking domain
 */
function calculateDomainEntropy(domain: string): number {
  const chars = domain.toLowerCase().split("");
  const freq: Record<string, number> = {};

  for (const char of chars) {
    freq[char] = (freq[char] || 0) + 1;
  }

  let entropy = 0;
  for (const count of Object.values(freq)) {
    const p = count / chars.length;
    entropy -= p * Math.log2(p);
  }

  // Normalize to 0-1 range
  return entropy / Math.log2(26); // Max entropy for 26 letters
}

/**
 * Calculate confidence level based on number of triggered rules and their weights
 */
function calculateConfidence(
  riskScore: number,
  triggeredRulesCount: number,
  maxRuleWeight: number
): "LOW" | "MEDIUM" | "HIGH" {
  // Confidence is HIGH if:
  // - Multiple rules triggered (>3)
  // - High-weight rules triggered (>25)
  // - Risk score is extreme (>80 or <20)

  if (riskScore > 80 || riskScore < 20) {
    return "HIGH";
  }

  if (triggeredRulesCount >= 3 && maxRuleWeight > 25) {
    return "HIGH";
  }

  if (triggeredRulesCount >= 2 || riskScore > 50) {
    return "MEDIUM";
  }

  return "LOW";
}

/**
 * Generate recommendation based on threat level
 */
function getRecommendation(threatLevel: string, riskScore: number): string {
  if (threatLevel === "dangerous") {
    return "⛔ Do not proceed. Avoid entering any personal information. Report this URL if possible.";
  }
  if (threatLevel === "suspicious") {
    if (riskScore > 60) {
      return "⚠️ Exercise caution. Verify the website is legitimate before proceeding. Check the official website directly.";
    }
    return "⚠️ Use caution. Verify the source before entering sensitive information.";
  }
  return "✅ This URL appears safe, but always verify the source of sensitive requests.";
}

/**
 * Validates and parses a URL
 */
function parseUrl(urlString: string): URL | null {
  try {
    let url = urlString.trim();
    if (!url.match(/^https?:\/\//i)) {
      url = "https://" + url;
    }
    return new URL(url);
  } catch {
    return null;
  }
}

/**
 * Analyzes a URL for phishing indicators with confidence scoring
 */
export function analyzeUrl(urlString: string): DetectionResult {
  const urlObj = parseUrl(urlString);

  if (!urlObj) {
    return {
      url: urlString,
      threatLevel: "dangerous",
      riskScore: 100,
      confidence: "HIGH",
      reasons: ["Invalid URL format - cannot be analyzed"],
      recommendation: "⛔ This is not a valid URL. Please check the format and try again.",
      triggeredRules: [],
    };
  }

  let riskScore = 0;
  const triggeredRules: DetectionResult["triggeredRules"] = [];
  const reasons: string[] = [];
  let maxRuleWeight = 0;

  // Check each rule
  for (const rule of DETECTION_RULES) {
    try {
      if (rule.check(urlObj)) {
        riskScore += rule.weight;
        maxRuleWeight = Math.max(maxRuleWeight, rule.weight);
        triggeredRules.push({
          id: rule.id,
          name: rule.name,
          description: rule.description,
          weight: rule.weight,
        });
        reasons.push(rule.description);
      }
    } catch (error) {
      console.error(`Error checking rule ${rule.id}:`, error);
    }
  }

  // Domain entropy analysis disabled for stability
  // Can be re-enabled with better tuning in future versions

  // Cap risk score at 100
  riskScore = Math.min(riskScore, 100);

  // Determine threat level
  let threatLevel: "safe" | "suspicious" | "dangerous";
  if (riskScore <= 30) {
    threatLevel = "safe";
  } else if (riskScore <= 70) {
    threatLevel = "suspicious";
  } else {
    threatLevel = "dangerous";
  }

  // Calculate confidence level
  const confidence = calculateConfidence(riskScore, triggeredRules.length, maxRuleWeight);

  // Generate recommendation
  const recommendation = getRecommendation(threatLevel, riskScore);

  return {
    url: urlObj.href,
    threatLevel,
    riskScore,
    confidence,
    reasons,
    recommendation,
    triggeredRules,
  };
}

/**
 * Batch analyze multiple URLs
 */
export function analyzeUrls(urls: string[]): DetectionResult[] {
  return urls.map((url) => analyzeUrl(url));
}
