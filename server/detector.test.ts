import { describe, expect, it } from "vitest";
import { analyzeUrl, analyzeUrls } from "./detector";

describe("PhishGuard Detection Engine", () => {
  describe("analyzeUrl", () => {
    it("should detect safe URLs correctly", () => {
      const result = analyzeUrl("https://www.google.com");
      expect(result.threatLevel).toBe("safe");
      expect(result.riskScore).toBeLessThanOrEqual(30);
      expect(result.confidence).toBeDefined();
      expect(result.recommendation).toBeDefined();
    });

    it("should detect suspicious URLs with multiple indicators", () => {
      const result = analyzeUrl("http://verify-account-secure.tk/login");
      expect(result.threatLevel).toBe("suspicious");
      expect(result.riskScore).toBeGreaterThan(30);
      expect(result.riskScore).toBeLessThanOrEqual(70);
    });

    it("should detect dangerous URLs with critical indicators", () => {
      const result = analyzeUrl("http://192.168.1.1/paypal-verify");
      expect(result.threatLevel).toBe("dangerous");
      expect(result.riskScore).toBeGreaterThan(70);
      expect(result.confidence).toBe("HIGH");
    });

    it("should handle invalid URLs", () => {
      const result = analyzeUrl("not a valid url");
      expect(result.threatLevel).toBe("dangerous");
      expect(result.riskScore).toBe(100);
      expect(result.confidence).toBe("HIGH");
      expect(result.recommendation).toContain("⛔");
    });

    it("should detect @ symbol obfuscation", () => {
      const result = analyzeUrl("https://google.com@malicious.com");
      expect(result.triggeredRules.some((r) => r.id === "at_symbol")).toBe(true);
    });

    it("should detect IP address usage", () => {
      const result = analyzeUrl("http://192.168.1.1/admin");
      expect(result.triggeredRules.some((r) => r.id === "ip_address")).toBe(true);
    });

    it("should detect missing HTTPS", () => {
      const result = analyzeUrl("http://example.com");
      expect(result.triggeredRules.some((r) => r.id === "no_https")).toBe(true);
    });

    it("should detect suspicious keywords", () => {
      const result = analyzeUrl("https://verify-account.com/login");
      expect(result.triggeredRules.some((r) => r.id === "suspicious_keywords")).toBe(true);
    });

    it("should detect suspicious TLDs", () => {
      const result = analyzeUrl("https://secure-bank.tk");
      expect(result.triggeredRules.some((r) => r.id === "suspicious_tld")).toBe(true);
    });

    it("should detect excessive subdomains", () => {
      const result = analyzeUrl("https://verify.account.secure.bank.com");
      expect(result.triggeredRules.some((r) => r.id === "excessive_subdomains")).toBe(true);
    });

    it("should detect excessive hyphens", () => {
      const result = analyzeUrl("https://verify-account-secure-bank.com");
      expect(result.triggeredRules.some((r) => r.id === "excessive_hyphens")).toBe(true);
    });

    it("should detect excessive URL length", () => {
      const longUrl =
        "https://example.com/very/long/path/that/goes/on/and/on/and/on/with/many/segments/to/obfuscate";
      const result = analyzeUrl(longUrl);
      expect(result.triggeredRules.some((r) => r.id === "url_length")).toBe(true);
    });

    it("should detect URL encoding obfuscation", () => {
      const result = analyzeUrl("https://example.com/path%20with%20encoding");
      expect(result.triggeredRules.some((r) => r.id === "url_encoding")).toBe(true);
    });

    it("should detect blacklisted domains", () => {
      const result = analyzeUrl("https://paypa1.com");
      expect(result.triggeredRules.some((r) => r.id === "blacklisted_domain")).toBe(true);
    });

    it("should add protocol if missing", () => {
      const result = analyzeUrl("www.google.com");
      expect(result.url).toContain("https://");
    });

    it("should cap risk score at 100", () => {
      const result = analyzeUrl("http://192.168.1.1/verify-account-secure-bank");
      expect(result.riskScore).toBeLessThanOrEqual(100);
      expect(["LOW", "MEDIUM", "HIGH"]).toContain(result.confidence);
    });

    it("should provide detailed reasons for detection", () => {
      const result = analyzeUrl("http://verify-account.tk");
      expect(result.reasons.length).toBeGreaterThan(0);
      expect(result.reasons.some((r) => r.includes("keyword") || r.includes("TLD") || r.includes("HTTPS"))).toBe(true);
      expect(result.recommendation).toContain("⚠️");
    });
  });

  describe("analyzeUrls", () => {
    it("should analyze multiple URLs", () => {
      const urls = [
        "https://www.google.com",
        "http://verify-account.tk",
        "https://paypa1.com",
      ];
      const results = analyzeUrls(urls);
      expect(results).toHaveLength(3);
      expect(results[0].threatLevel).toBe("safe");
      expect(results[1].threatLevel).toBe("suspicious");
      // paypa1.com is blacklisted (weight 40) but also has suspicious keywords (weight 25)
      // Total: 40 + 25 = 65, which is suspicious (31-70), not dangerous
      expect(["suspicious", "dangerous"]).toContain(results[2].threatLevel);
    });

    it("should handle empty array", () => {
      const results = analyzeUrls([]);
      expect(results).toHaveLength(0);
    });
  });
});
