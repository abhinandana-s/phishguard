/**
 * PhishGuard v2 - Premium AI-Powered Detection Engine
 * Threat intelligence breakdown, multi-engine simulation, and hybrid ML scoring
 */

export interface ThreatBreakdown {
  urlStructureRisk: number;
  domainRisk: number;
  contentRisk: number;
}

export interface ScanEngine {
  name: string;
  status: "checking" | "checked";
  result?: string;
}

export interface DetectionRule {
  id: string;
  name: string;
  description: string;
  weight: number;
  category: "url_structure" | "domain" | "content";
  check: (urlObj: URL) => boolean;
}

export interface PremiumDetectionResult {
  url: string;
  threatLevel: "safe" | "suspicious" | "dangerous";
  riskScore: number;
  mlScore: number;
  finalScore: number;
  confidence: "LOW" | "MEDIUM" | "HIGH";
  threatBreakdown: ThreatBreakdown;
  engines: ScanEngine[];
  reasons: string[];
  recommendations: string[];
  triggeredRules: Array<{
    id: string;
    name: string;
    description: string;
    weight: number;
    category: string;
  }>;
}

// Suspicious keywords
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

// Suspicious TLDs
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
];

// Blacklisted domains
const BLACKLISTED_DOMAINS = [
  "paypa1.com",
  "amaz0n.com",
  "apple-verify.com",
  "microsoft-security.com",
];

// Enhanced detection rules with categories
const DETECTION_RULES: DetectionRule[] = [
  // URL Structure Rules
  {
    id: "url_length",
    name: "Excessive URL Length",
    description: "URL is unusually long (>75 characters)",
    weight: 15,
    category: "url_structure",
    check: (urlObj) => urlObj.href.length > 75,
  },
  {
    id: "at_symbol",
    name: "@ Symbol in URL",
    description: "URL contains @ symbol used for obfuscation",
    weight: 25,
    category: "url_structure",
    check: (urlObj) => urlObj.href.includes("@"),
  },
  {
    id: "excessive_hyphens",
    name: "Excessive Hyphens",
    description: "Domain contains multiple hyphens",
    weight: 20,
    category: "url_structure",
    check: (urlObj) => {
      const hostname = urlObj.hostname;
      const hyphens = (hostname.match(/-/g) || []).length;
      return hyphens > 2;
    },
  },
  {
    id: "url_encoding",
    name: "URL Encoding Obfuscation",
    description: "URL contains encoded characters",
    weight: 22,
    category: "url_structure",
    check: (urlObj) => /%[0-9A-Fa-f]{2}/.test(urlObj.href),
  },

  // Domain Rules
  {
    id: "ip_address",
    name: "IP Address Instead of Domain",
    description: "URL uses IP address instead of domain",
    weight: 30,
    category: "domain",
    check: (urlObj) => {
      const hostname = urlObj.hostname;
      const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
      return ipPattern.test(hostname);
    },
  },
  {
    id: "no_https",
    name: "Missing HTTPS Protocol",
    description: "URL does not use HTTPS encryption",
    weight: 20,
    category: "domain",
    check: (urlObj) => urlObj.protocol !== "https:",
  },
  {
    id: "suspicious_tld",
    name: "Suspicious Top-Level Domain",
    description: "URL uses a TLD commonly associated with phishing",
    weight: 20,
    category: "domain",
    check: (urlObj) => {
      const hostname = urlObj.hostname;
      return SUSPICIOUS_TLDS.some((tld) => hostname.endsWith(tld));
    },
  },
  {
    id: "excessive_subdomains",
    name: "Excessive Subdomains",
    description: "URL has too many subdomains",
    weight: 18,
    category: "domain",
    check: (urlObj) => {
      const hostname = urlObj.hostname;
      const subdomains = hostname.split(".").length;
      return subdomains > 3;
    },
  },
  {
    id: "port_number",
    name: "Non-Standard Port",
    description: "URL uses a non-standard port",
    weight: 15,
    category: "domain",
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
    category: "domain",
    check: (urlObj) => {
      const hostname = urlObj.hostname;
      return BLACKLISTED_DOMAINS.some((domain) => hostname.includes(domain));
    },
  },

  // Content Rules
  {
    id: "suspicious_keywords",
    name: "Suspicious Keywords",
    description: "URL contains keywords commonly used in phishing",
    weight: 25,
    category: "content",
    check: (urlObj) => {
      const urlLower = urlObj.href.toLowerCase();
      return SUSPICIOUS_KEYWORDS.some((keyword) => urlLower.includes(keyword));
    },
  },
  {
    id: "homograph_attack",
    name: "Homograph Attack Indicators",
    description: "URL contains characters that look similar to legitimate domains",
    weight: 28,
    category: "content",
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
];

/**
 * Calculate threat breakdown by category
 */
function calculateThreatBreakdown(
  triggeredRules: DetectionRule[]
): ThreatBreakdown {
  const categories = {
    url_structure: 0,
    domain: 0,
    content: 0,
  };

  const maxWeights = {
    url_structure: 0,
    domain: 0,
    content: 0,
  };

  // Calculate max possible weights for each category
  for (const rule of DETECTION_RULES) {
    maxWeights[rule.category] += rule.weight;
  }

  // Calculate actual weights for triggered rules
  for (const rule of triggeredRules) {
    categories[rule.category] += rule.weight;
  }

  // Normalize to percentage (0-100)
  return {
    urlStructureRisk: Math.min(
      100,
      (categories.url_structure / maxWeights.url_structure) * 100
    ),
    domainRisk: Math.min(100, (categories.domain / maxWeights.domain) * 100),
    contentRisk: Math.min(100, (categories.content / maxWeights.content) * 100),
  };
}

/**
 * Generate dynamic recommendations based on threat level
 */
function generateRecommendations(
  threatLevel: string,
  riskScore: number
): string[] {
  const recommendations: string[] = [];

  if (threatLevel === "dangerous") {
    recommendations.push("Do not enter any personal or financial information");
    recommendations.push("Avoid visiting this website immediately");
    recommendations.push("Report this URL to your security team");
    recommendations.push("Consider blocking this domain");
  } else if (threatLevel === "suspicious") {
    if (riskScore > 60) {
      recommendations.push("Proceed with extreme caution");
      recommendations.push("Verify the domain manually before proceeding");
      recommendations.push("Do not enter sensitive credentials");
    } else {
      recommendations.push("Proceed with caution");
      recommendations.push("Verify the source of this URL");
      recommendations.push("Check for HTTPS and valid certificate");
    }
  } else {
    recommendations.push("This URL appears safe to visit");
    recommendations.push("Always verify sender information for emails");
    recommendations.push("Keep your browser and security software updated");
  }

  return recommendations;
}

/**
 * Simulate ML model prediction (placeholder for actual ML integration)
 */
function predictWithML(urlObj: URL, riskScore: number): number {
  // Simplified ML scoring based on URL features
  let mlScore = 0;

  // Feature 1: URL length (0-20)
  mlScore += Math.min(20, (urlObj.href.length / 100) * 20);

  // Feature 2: Number of dots in hostname (0-15)
  const dotCount = (urlObj.hostname.match(/\./g) || []).length;
  mlScore += Math.min(15, (dotCount / 5) * 15);

  // Feature 3: Suspicious keywords (0-30)
  const urlLower = urlObj.href.toLowerCase();
  const keywordCount = SUSPICIOUS_KEYWORDS.filter((kw) =>
    urlLower.includes(kw)
  ).length;
  mlScore += Math.min(30, (keywordCount / 3) * 30);

  // Feature 4: HTTPS presence (0-25)
  if (urlObj.protocol === "https:") {
    mlScore += 25;
  }

  // Feature 5: Port number (0-10)
  if (!urlObj.port || urlObj.port === "80" || urlObj.port === "443") {
    mlScore += 10;
  }

  // Add some randomness to simulate ML uncertainty
  const variance = (Math.random() - 0.5) * 10;
  return Math.max(0, Math.min(100, mlScore + variance));
}

/**
 * Parse URL safely
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
 * Simulate multi-engine scanning with delay
 */
async function simulateEngineScans(): Promise<ScanEngine[]> {
  const engines: ScanEngine[] = [
    { name: "Internal Engine", status: "checking" },
    { name: "Pattern Analyzer", status: "checking" },
    { name: "Heuristic Scanner", status: "checking" },
  ];

  // Simulate scanning delay (1-2 seconds)
  await new Promise((resolve) => setTimeout(resolve, 1500));

  return engines.map((engine) => ({
    ...engine,
    status: "checked",
    result: "completed",
  }));
}

/**
 * Premium analysis with threat intelligence and ML
 */
export async function analyzeUrlPremium(
  urlString: string
): Promise<PremiumDetectionResult> {
  const urlObj = parseUrl(urlString);

  if (!urlObj) {
    return {
      url: urlString,
      threatLevel: "dangerous",
      riskScore: 100,
      mlScore: 100,
      finalScore: 100,
      confidence: "HIGH",
      threatBreakdown: { urlStructureRisk: 100, domainRisk: 100, contentRisk: 100 },
      engines: [],
      reasons: ["Invalid URL format - cannot be analyzed"],
      recommendations: [
        "This is not a valid URL. Please check the format and try again.",
      ],
      triggeredRules: [],
    };
  }

  // Run rule-based detection
  let riskScore = 0;
  const triggeredRules: DetectionRule[] = [];
  const reasons: string[] = [];

  for (const rule of DETECTION_RULES) {
    try {
      if (rule.check(urlObj)) {
        riskScore += rule.weight;
        triggeredRules.push(rule);
        reasons.push(rule.description);
      }
    } catch (error) {
      console.error(`Error checking rule ${rule.id}:`, error);
    }
  }

  riskScore = Math.min(riskScore, 100);

  // Calculate threat breakdown
  const threatBreakdown = calculateThreatBreakdown(triggeredRules);

  // Determine threat level
  let threatLevel: "safe" | "suspicious" | "dangerous";
  if (riskScore <= 30) {
    threatLevel = "safe";
  } else if (riskScore <= 70) {
    threatLevel = "suspicious";
  } else {
    threatLevel = "dangerous";
  }

  // Get ML prediction
  const mlScore = predictWithML(urlObj, riskScore);

  // Combine scores: 60% rule-based, 40% ML
  const finalScore = Math.round(riskScore * 0.6 + mlScore * 0.4);

  // Calculate confidence
  const confidence =
    triggeredRules.length >= 6
      ? "HIGH"
      : triggeredRules.length >= 3
        ? "MEDIUM"
        : "LOW";

  // Generate recommendations
  const recommendations = generateRecommendations(threatLevel, finalScore);

  // Simulate engine scans
  const engines = await simulateEngineScans();

  return {
    url: urlObj.href,
    threatLevel,
    riskScore,
    mlScore: Math.round(mlScore),
    finalScore,
    confidence,
    threatBreakdown: {
      urlStructureRisk: Math.round(threatBreakdown.urlStructureRisk),
      domainRisk: Math.round(threatBreakdown.domainRisk),
      contentRisk: Math.round(threatBreakdown.contentRisk),
    },
    engines,
    reasons,
    recommendations,
    triggeredRules: triggeredRules.map((r) => ({
      id: r.id,
      name: r.name,
      description: r.description,
      weight: r.weight,
      category: r.category,
    })),
  };
}
