import { AlertCircle, AlertTriangle, CheckCircle } from "lucide-react";

interface RecommendationBoxProps {
  recommendation: string;
  threatLevel: "safe" | "suspicious" | "dangerous";
}

export function RecommendationBox({ recommendation, threatLevel }: RecommendationBoxProps) {
  const getRecommendationColor = () => {
    switch (threatLevel) {
      case "safe":
        return "bg-neon-green/10 border-neon-green/50 text-neon-green";
      case "suspicious":
        return "bg-neon-yellow/10 border-neon-yellow/50 text-neon-yellow";
      case "dangerous":
        return "bg-neon-red/10 border-neon-red/50 text-neon-red";
    }
  };

  const getRecommendationIcon = () => {
    switch (threatLevel) {
      case "safe":
        return <CheckCircle className="w-5 h-5 flex-shrink-0" />;
      case "suspicious":
        return <AlertTriangle className="w-5 h-5 flex-shrink-0" />;
      case "dangerous":
        return <AlertCircle className="w-5 h-5 flex-shrink-0" />;
    }
  };

  return (
    <div className={`border rounded-lg p-4 flex gap-3 ${getRecommendationColor()}`}>
      {getRecommendationIcon()}
      <div className="flex-1">
        <p className="text-sm font-semibold mb-1">Recommendation</p>
        <p className="text-sm opacity-90">{recommendation}</p>
      </div>
    </div>
  );
}
