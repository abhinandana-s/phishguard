import { Shield, AlertTriangle, CheckCircle } from "lucide-react";

interface ConfidenceBadgeProps {
  confidence: "LOW" | "MEDIUM" | "HIGH";
}

export function ConfidenceBadge({ confidence }: ConfidenceBadgeProps) {
  const getConfidenceColor = () => {
    switch (confidence) {
      case "LOW":
        return "bg-neon-yellow/20 border-neon-yellow text-neon-yellow";
      case "MEDIUM":
        return "bg-neon-blue/20 border-neon-blue text-neon-blue";
      case "HIGH":
        return "bg-neon-green/20 border-neon-green text-neon-green";
    }
  };

  const getConfidenceIcon = () => {
    switch (confidence) {
      case "LOW":
        return <AlertTriangle className="w-4 h-4" />;
      case "MEDIUM":
        return <Shield className="w-4 h-4" />;
      case "HIGH":
        return <CheckCircle className="w-4 h-4" />;
    }
  };

  const getConfidenceLabel = () => {
    switch (confidence) {
      case "LOW":
        return "Low Confidence";
      case "MEDIUM":
        return "Medium Confidence";
      case "HIGH":
        return "High Confidence";
    }
  };

  return (
    <div className={`inline-flex items-center gap-2 px-3 py-1 rounded-full border ${getConfidenceColor()}`}>
      {getConfidenceIcon()}
      <span className="text-sm font-semibold">{getConfidenceLabel()}</span>
    </div>
  );
}
