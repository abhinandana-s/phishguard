import { useState } from "react";
import { useAuth } from "@/_core/hooks/useAuth";
import { Button } from "@/components/ui/button";
import { Loader2, Shield, Github, ExternalLink } from "lucide-react";
import { getLoginUrl } from "@/const";
import { UrlAnalysisForm } from "@/components/UrlAnalysisForm";
import { ThreatScoreDisplay } from "@/components/ThreatScoreDisplay";
import { DetectionResults } from "@/components/DetectionResults";
import { ScanHistory } from "@/components/ScanHistory";
import { trpc } from "@/lib/trpc";

interface AnalysisResult {
  url: string;
  threatLevel: "safe" | "suspicious" | "dangerous";
  riskScore: number;
  confidence: "LOW" | "MEDIUM" | "HIGH";
  recommendation: string;
  reasons: string[];
  triggeredRules: Array<{
    id: string;
    name: string;
    description: string;
    weight: number;
  }>;
}

export default function Home() {
  const { user, loading, isAuthenticated, logout } = useAuth();
  const [analysisResult, setAnalysisResult] = useState<AnalysisResult | null>(null);
  const [refreshTrigger, setRefreshTrigger] = useState(0);
  const utils = trpc.useUtils();

  const handleAnalysisComplete = async () => {
    setRefreshTrigger((prev) => prev + 1);
    await utils.urlAnalysis.history.invalidate();
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <Loader2 className="w-8 h-8 animate-spin text-neon-green" />
      </div>
    );
  }

  if (!isAuthenticated) {
    return (
      <div className="min-h-screen bg-background text-foreground">
        {/* Navigation */}
        <nav className="border-b border-neon-green/20 bg-card/50 backdrop-blur-sm">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Shield className="w-6 h-6 text-neon-green" />
              <h1 className="text-xl font-bold neon-text-green">PhishGuard</h1>
            </div>
            <p className="text-sm text-muted-foreground">Real-time URL Threat Detection</p>
          </div>
        </nav>

        {/* Hero Section */}
        <div className="min-h-[calc(100vh-80px)] flex flex-col items-center justify-center px-4 py-12">
          <div className="max-w-2xl text-center space-y-8">
            {/* Logo Animation */}
            <div className="flex justify-center">
              <div className="relative w-24 h-24">
                <div className="absolute inset-0 bg-gradient-to-r from-neon-green via-neon-blue to-neon-purple rounded-full blur-2xl opacity-50 animate-pulse" />
                <div className="relative w-full h-full bg-card border-2 border-neon-green rounded-full flex items-center justify-center neon-glow-green">
                  <Shield className="w-12 h-12 text-neon-green" />
                </div>
              </div>
            </div>

            {/* Heading */}
            <div className="space-y-4">
              <h1 className="text-5xl md:text-6xl font-bold">
                <span className="neon-text-green">PhishGuard</span>
              </h1>
              <p className="text-xl text-muted-foreground">
                Advanced URL threat detection powered by intelligent analysis
              </p>
              <p className="text-sm text-muted-foreground max-w-md mx-auto">
                Protect yourself from phishing attacks and malicious URLs with real-time threat assessment
              </p>
            </div>

            {/* CTA Button */}
            <div className="pt-4">
              <Button
                onClick={() => window.location.href = getLoginUrl()}
                className="px-8 py-6 text-lg bg-gradient-to-r from-neon-green to-neon-blue text-background font-semibold rounded-lg hover:shadow-lg neon-glow-green transition-all duration-300"
              >
                <Shield className="w-5 h-5 mr-2" />
                Start Scanning
              </Button>
            </div>

            {/* Features Grid */}
            <div className="grid md:grid-cols-3 gap-4 pt-12">
              {[
                {
                  title: "Real-time Analysis",
                  description: "Instant threat assessment using advanced detection rules",
                  icon: "⚡",
                },
                {
                  title: "Detailed Reports",
                  description: "Comprehensive breakdown of detected threats and indicators",
                  icon: "📊",
                },
                {
                  title: "Scan History",
                  description: "Track and review all your previous URL scans",
                  icon: "📜",
                },
              ].map((feature, idx) => (
                <div
                  key={idx}
                  className="bg-card border border-neon-green/20 rounded-lg p-6 hover:border-neon-green/50 transition-colors neon-border-green"
                >
                  <div className="text-3xl mb-3">{feature.icon}</div>
                  <h3 className="font-semibold text-foreground mb-2">{feature.title}</h3>
                  <p className="text-sm text-muted-foreground">{feature.description}</p>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Footer */}
        <footer className="border-t border-neon-green/20 bg-card/50 backdrop-blur-sm mt-12">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 text-center text-sm text-muted-foreground">
            <p>Built for cybersecurity awareness • Protecting against phishing threats</p>
          </div>
        </footer>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background text-foreground">
      {/* Navigation */}
      <nav className="border-b border-neon-green/20 bg-card/50 backdrop-blur-sm sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Shield className="w-6 h-6 text-neon-green" />
            <h1 className="text-xl font-bold neon-text-green">PhishGuard</h1>
          </div>
          <div className="flex items-center gap-4">
            <p className="text-sm text-muted-foreground hidden sm:block">
              Welcome, <span className="text-neon-green font-semibold">{user?.name || "User"}</span>
            </p>
            <Button
              onClick={() => logout()}
              variant="outline"
              size="sm"
              className="border-neon-red/30 hover:bg-neon-red/10 text-neon-red"
            >
              Logout
            </Button>
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="grid lg:grid-cols-3 gap-8">
          {/* Left Column - Analysis */}
          <div className="lg:col-span-2 space-y-8">
            {/* URL Input Section */}
            <div className="bg-card border border-neon-green/20 rounded-xl p-8 neon-border-green">
              <div className="mb-6">
                <h2 className="text-2xl font-bold text-foreground mb-2">Analyze URL</h2>
                <p className="text-sm text-muted-foreground">
                  Enter a URL to scan for phishing indicators and threats
                </p>
              </div>
              <UrlAnalysisForm onAnalysisComplete={handleAnalysisComplete} />
            </div>

            {/* Results Section */}
            {analysisResult && (
              <div className="space-y-6">
                {/* Threat Score */}
                <div className="bg-card border border-neon-green/20 rounded-xl p-8 neon-border-green">
                  <ThreatScoreDisplay
                    riskScore={analysisResult.riskScore}
                    threatLevel={analysisResult.threatLevel}
                    confidence={analysisResult.confidence}
                  />
                </div>

                {/* Detection Details */}
                <div className="bg-card border border-neon-green/20 rounded-xl p-8 neon-border-green">
                  <h2 className="text-xl font-bold text-foreground mb-6">Detection Details</h2>
                  <DetectionResults
                    url={analysisResult.url}
                    threatLevel={analysisResult.threatLevel}
                    riskScore={analysisResult.riskScore}
                    recommendation={analysisResult.recommendation}
                    reasons={analysisResult.reasons}
                    triggeredRules={analysisResult.triggeredRules}
                  />
                </div>
              </div>
            )}
          </div>

          {/* Right Column - History */}
          <div className="lg:col-span-1">
            <div className="bg-card border border-neon-green/20 rounded-xl p-6 neon-border-green sticky top-24">
              <h2 className="text-lg font-bold text-foreground mb-4 flex items-center gap-2">
                <Shield className="w-5 h-5 text-neon-green" />
                Recent Scans
              </h2>
              <ScanHistory refreshTrigger={refreshTrigger} />
            </div>
          </div>
        </div>
      </div>

      {/* Footer */}
      <footer className="border-t border-neon-green/20 bg-card/50 backdrop-blur-sm mt-12">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <div className="flex flex-col md:flex-row items-center justify-between gap-4 text-sm text-muted-foreground">
            <p>Built for cybersecurity awareness • Protecting against phishing threats</p>
            <div className="flex items-center gap-4">
              <a href="#" className="hover:text-neon-green transition-colors flex items-center gap-1">
                <Github className="w-4 h-4" />
                GitHub
              </a>
              <a href="#" className="hover:text-neon-green transition-colors flex items-center gap-1">
                <ExternalLink className="w-4 h-4" />
                Docs
              </a>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}
