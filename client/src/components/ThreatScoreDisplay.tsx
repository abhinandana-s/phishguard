import { useEffect, useState } from "react";
import { AlertTriangle, CheckCircle, AlertCircle } from "lucide-react";
import { ConfidenceBadge } from "./ConfidenceBadge";

interface ThreatScoreDisplayProps {
  riskScore: number;
  threatLevel: "safe" | "suspicious" | "dangerous";
  confidence: "LOW" | "MEDIUM" | "HIGH";
}

export function ThreatScoreDisplay({ riskScore, threatLevel, confidence }: ThreatScoreDisplayProps) {
  const [animatedScore, setAnimatedScore] = useState(0);

  useEffect(() => {
    let animationFrame: number;
    let currentScore = 0;
    const increment = riskScore / 30;

    const animate = () => {
      if (currentScore < riskScore) {
        currentScore = Math.min(currentScore + increment, riskScore);
        setAnimatedScore(Math.round(currentScore));
        animationFrame = requestAnimationFrame(animate);
      }
    };

    animationFrame = requestAnimationFrame(animate);
    return () => cancelAnimationFrame(animationFrame);
  }, [riskScore]);

  const getThreatColor = () => {
    switch (threatLevel) {
      case "safe":
        return "neon-green";
      case "suspicious":
        return "neon-yellow";
      case "dangerous":
        return "neon-red";
    }
  };

  const getThreatIcon = () => {
    switch (threatLevel) {
      case "safe":
        return <CheckCircle className="w-12 h-12 text-neon-green" />;
      case "suspicious":
        return <AlertTriangle className="w-12 h-12 text-neon-yellow" />;
      case "dangerous":
        return <AlertCircle className="w-12 h-12 text-neon-red" />;
    }
  };

  const getThreatLabel = () => {
    switch (threatLevel) {
      case "safe":
        return "SAFE";
      case "suspicious":
        return "SUSPICIOUS";
      case "dangerous":
        return "DANGEROUS";
    }
  };

  const getProgressColor = () => {
    switch (threatLevel) {
      case "safe":
        return "from-neon-green to-neon-blue";
      case "suspicious":
        return "from-neon-yellow to-neon-green";
      case "dangerous":
        return "from-neon-red to-neon-yellow";
    }
  };

  return (
    <div className="space-y-6">
      {/* Threat Level Indicator */}
      <div className="flex flex-col items-center justify-center space-y-4 p-8 bg-card border border-neon-green/20 rounded-xl neon-border-green">
        <div className="animate-pulse">{getThreatIcon()}</div>
        <div className="text-center">
          <h3 className={`text-3xl font-bold mb-2 neon-text-${getThreatColor()}`}>
            {getThreatLabel()}
          </h3>
          <p className="text-sm text-muted-foreground mb-3">Threat Assessment Result</p>
          <ConfidenceBadge confidence={confidence} />
        </div>
      </div>

      {/* Risk Score with Progress Bar */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <label className="text-sm font-semibold text-foreground">Risk Score</label>
          <span className={`text-2xl font-bold neon-text-${getThreatColor()}`}>
            {animatedScore}%
          </span>
        </div>

        {/* Animated Progress Bar */}
        <div className="relative h-3 bg-card border border-neon-green/20 rounded-full overflow-hidden">
          <div
            className={`h-full bg-gradient-to-r ${getProgressColor()} rounded-full transition-all duration-500 ease-out`}
            style={{ width: `${animatedScore}%` }}
          >
            <div className="h-full bg-gradient-to-r from-white/20 to-transparent animate-pulse" />
          </div>
          {/* Glow effect */}
          <div
            className={`absolute top-0 h-full bg-gradient-to-r ${getProgressColor()} blur-md opacity-50 rounded-full`}
            style={{ width: `${animatedScore}%` }}
          />
        </div>

        {/* Risk Level Breakdown */}
        <div className="grid grid-cols-3 gap-2 mt-4 text-xs">
          <div className="text-center">
            <div className="text-neon-green font-bold">0-30%</div>
            <div className="text-muted-foreground">Safe</div>
          </div>
          <div className="text-center">
            <div className="text-neon-yellow font-bold">31-70%</div>
            <div className="text-muted-foreground">Suspicious</div>
          </div>
          <div className="text-center">
            <div className="text-neon-red font-bold">71-100%</div>
            <div className="text-muted-foreground">Dangerous</div>
          </div>
        </div>
      </div>
    </div>
  );
}
