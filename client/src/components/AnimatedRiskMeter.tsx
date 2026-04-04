import { useEffect, useState } from "react";

interface AnimatedRiskMeterProps {
  score: number;
  threatLevel: "safe" | "suspicious" | "dangerous";
}

export function AnimatedRiskMeter({ score, threatLevel }: AnimatedRiskMeterProps) {
  const [animatedScore, setAnimatedScore] = useState(0);

  useEffect(() => {
    let animationFrame: number;
    let currentScore = 0;
    const increment = score / 30; // Animate over ~30 frames

    const animate = () => {
      currentScore += increment;
      if (currentScore < score) {
        setAnimatedScore(Math.round(currentScore));
        animationFrame = requestAnimationFrame(animate);
      } else {
        setAnimatedScore(score);
      }
    };

    animationFrame = requestAnimationFrame(animate);
    return () => cancelAnimationFrame(animationFrame);
  }, [score]);

  const getColor = () => {
    if (animatedScore <= 30) return "#22C55E"; // Green
    if (animatedScore <= 70) return "#F59E0B"; // Yellow
    return "#EF4444"; // Red
  };

  const circumference = 2 * Math.PI * 45;
  const strokeDashoffset = circumference - (animatedScore / 100) * circumference;

  return (
    <div className="flex flex-col items-center justify-center">
      <div className="relative w-40 h-40">
        {/* Background circle */}
        <svg className="absolute inset-0 w-full h-full" viewBox="0 0 100 100">
          <circle
            cx="50"
            cy="50"
            r="45"
            fill="none"
            stroke="rgba(255,255,255,0.1)"
            strokeWidth="4"
          />
          {/* Animated progress circle */}
          <circle
            cx="50"
            cy="50"
            r="45"
            fill="none"
            stroke={getColor()}
            strokeWidth="4"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            style={{
              transition: "stroke-dashoffset 0.3s ease-out, stroke 0.3s ease-out",
              filter: `drop-shadow(0 0 8px ${getColor()})`,
            }}
            transform="rotate(-90 50 50)"
          />
        </svg>

        {/* Center text */}
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <div className="text-4xl font-bold" style={{ color: getColor() }}>
            {animatedScore}
          </div>
          <div className="text-xs text-muted-foreground mt-1">Risk Score</div>
        </div>
      </div>

      {/* Legend */}
      <div className="mt-6 text-center">
        <p className="text-sm font-semibold text-foreground">
          {threatLevel === "safe"
            ? "Safe"
            : threatLevel === "suspicious"
              ? "Suspicious"
              : "Dangerous"}
        </p>
        <p className="text-xs text-muted-foreground mt-1">
          {threatLevel === "safe"
            ? "No major threats detected"
            : threatLevel === "suspicious"
              ? "Multiple risk factors identified"
              : "Critical threats detected"}
        </p>
      </div>
    </div>
  );
}
