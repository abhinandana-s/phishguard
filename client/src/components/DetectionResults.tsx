import { AlertTriangle, CheckCircle, Zap } from "lucide-react";
import { Button } from "@/components/ui/button";
import { RecommendationBox } from "./RecommendationBox";
import { toast } from "sonner";

interface TriggeredRule {
  id: string;
  name: string;
  description: string;
  weight: number;
}

interface DetectionResultsProps {
  url: string;
  threatLevel: "safe" | "suspicious" | "dangerous";
  riskScore: number;
  recommendation: string;
  reasons: string[];
  triggeredRules: TriggeredRule[];
}

export function DetectionResults({
  url,
  threatLevel,
  riskScore,
  recommendation,
  reasons,
  triggeredRules,
}: DetectionResultsProps) {
  const handleCopyUrl = () => {
    navigator.clipboard.writeText(url);
    toast.success("URL copied to clipboard");
  };

  const handleCopyResults = () => {
    const resultsText = `
URL: ${url}
Threat Level: ${threatLevel.toUpperCase()}
Risk Score: ${riskScore}%

Triggered Rules:
${triggeredRules.map((rule) => `- ${rule.name} (Weight: ${rule.weight})`).join("\n")}

Reasons:
${reasons.map((reason) => `- ${reason}`).join("\n")}
    `.trim();

    navigator.clipboard.writeText(resultsText);
    toast.success("Results copied to clipboard");
  };

  const getRuleIcon = (weight: number) => {
    if (weight >= 30) return <Zap className="w-4 h-4 text-neon-red" />;
    if (weight >= 20) return <AlertTriangle className="w-4 h-4 text-neon-yellow" />;
    return <CheckCircle className="w-4 h-4 text-neon-blue" />;
  };

  return (
    <div className="space-y-6">
      {/* Recommendation Box */}
      <RecommendationBox recommendation={recommendation} threatLevel={threatLevel} />

      {/* URL Display */}
      <div className="bg-card border border-neon-blue/20 rounded-lg p-4 neon-border-blue">
        <p className="text-xs text-muted-foreground mb-2">Analyzed URL</p>
        <div className="flex items-center justify-between gap-3">
          <p className="text-sm font-mono text-foreground break-all">{url}</p>
          <Button
            size="sm"
            variant="outline"
            onClick={handleCopyUrl}
            className="flex-shrink-0 border-neon-blue/30 hover:bg-neon-blue/10"
          >
            Copy
          </Button>
        </div>
      </div>

      {/* Triggered Rules */}
      <div className="space-y-3">
        <h3 className="text-sm font-semibold text-foreground flex items-center gap-2">
          <Zap className="w-4 h-4 text-neon-green" />
          Triggered Rules ({triggeredRules.length})
        </h3>

        {triggeredRules.length > 0 ? (
          <div className="space-y-2 max-h-64 overflow-y-auto">
            {triggeredRules.map((rule) => (
              <div
                key={rule.id}
                className="bg-card border border-neon-green/20 rounded-lg p-3 neon-border-green hover:border-neon-green/50 transition-colors"
              >
                <div className="flex items-start gap-3">
                  {getRuleIcon(rule.weight)}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between gap-2 mb-1">
                      <p className="font-semibold text-sm text-foreground">{rule.name}</p>
                      <span className="text-xs font-bold text-neon-yellow bg-neon-yellow/10 px-2 py-1 rounded">
                        +{rule.weight}
                      </span>
                    </div>
                    <p className="text-xs text-muted-foreground">{rule.description}</p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="bg-card border border-neon-green/20 rounded-lg p-4 text-center neon-border-green">
            <p className="text-sm text-muted-foreground">No suspicious rules triggered</p>
          </div>
        )}
      </div>

      {/* Detailed Reasons */}
      <div className="space-y-3">
        <h3 className="text-sm font-semibold text-foreground flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-neon-yellow" />
          Detection Summary
        </h3>

        {reasons.length > 0 ? (
          <div className="bg-card border border-neon-yellow/20 rounded-lg p-4 space-y-2 neon-border-yellow">
            {reasons.map((reason, index) => (
              <div key={index} className="flex gap-3 text-sm">
                <span className="text-neon-yellow font-bold flex-shrink-0">•</span>
                <span className="text-foreground">{reason}</span>
              </div>
            ))}
          </div>
        ) : (
          <div className="bg-card border border-neon-green/20 rounded-lg p-4 text-center neon-border-green">
            <p className="text-sm text-neon-green font-semibold">✓ No suspicious indicators detected</p>
          </div>
        )}
      </div>

      {/* Action Buttons */}
      <div className="flex gap-3">
        <Button
          onClick={handleCopyResults}
          variant="outline"
          className="flex-1 border-neon-blue/30 hover:bg-neon-blue/10 text-neon-blue"
        >
          Copy Results
        </Button>
      </div>
    </div>
  );
}
