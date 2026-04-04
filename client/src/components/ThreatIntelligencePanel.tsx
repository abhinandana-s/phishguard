import { useEffect, useState } from "react";

interface ThreatIntelligencePanelProps {
  urlStructureRisk: number;
  domainRisk: number;
  contentRisk: number;
}

interface RiskCategory {
  label: string;
  value: number;
  color: string;
  icon: string;
}

export function ThreatIntelligencePanel({
  urlStructureRisk,
  domainRisk,
  contentRisk,
}: ThreatIntelligencePanelProps) {
  const [animatedValues, setAnimatedValues] = useState({
    urlStructure: 0,
    domain: 0,
    content: 0,
  });

  useEffect(() => {
    let animationFrame: number;
    let currentValues = { urlStructure: 0, domain: 0, content: 0 };

    const animate = () => {
      const increment = 2;
      let isComplete = true;

      if (currentValues.urlStructure < urlStructureRisk) {
        currentValues.urlStructure = Math.min(
          currentValues.urlStructure + increment,
          urlStructureRisk
        );
        isComplete = false;
      }
      if (currentValues.domain < domainRisk) {
        currentValues.domain = Math.min(currentValues.domain + increment, domainRisk);
        isComplete = false;
      }
      if (currentValues.content < contentRisk) {
        currentValues.content = Math.min(
          currentValues.content + increment,
          contentRisk
        );
        isComplete = false;
      }

      setAnimatedValues({ ...currentValues });

      if (!isComplete) {
        animationFrame = requestAnimationFrame(animate);
      }
    };

    animationFrame = requestAnimationFrame(animate);
    return () => cancelAnimationFrame(animationFrame);
  }, [urlStructureRisk, domainRisk, contentRisk]);

  const categories: RiskCategory[] = [
    {
      label: "URL Structure Risk",
      value: animatedValues.urlStructure,
      color: "neon-blue",
      icon: "🔗",
    },
    {
      label: "Domain Risk",
      value: animatedValues.domain,
      color: "neon-yellow",
      icon: "🌐",
    },
    {
      label: "Content Risk",
      value: animatedValues.content,
      color: "neon-red",
      icon: "📄",
    },
  ];

  const getProgressColor = (value: number) => {
    if (value <= 30) return "bg-neon-green";
    if (value <= 70) return "bg-neon-yellow";
    return "bg-neon-red";
  };

  return (
    <div className="space-y-6">
      <h3 className="text-lg font-bold text-foreground flex items-center gap-2">
        <span>🧠</span> Threat Intelligence Breakdown
      </h3>

      <div className="space-y-4">
        {categories.map((category) => (
          <div key={category.label} className="space-y-2">
            <div className="flex items-center justify-between">
              <label className="text-sm font-semibold text-foreground flex items-center gap-2">
                <span>{category.icon}</span>
                {category.label}
              </label>
              <span className={`text-sm font-bold neon-text-${category.color}`}>
                {Math.round(category.value)}%
              </span>
            </div>

            {/* Progress bar */}
            <div className="w-full h-3 bg-card border border-neon-green/20 rounded-full overflow-hidden">
              <div
                className={`h-full ${getProgressColor(category.value)} transition-all duration-500`}
                style={{
                  width: `${category.value}%`,
                  boxShadow: `0 0 10px ${
                    category.value <= 30
                      ? "#22C55E"
                      : category.value <= 70
                        ? "#F59E0B"
                        : "#EF4444"
                  }`,
                }}
              />
            </div>
          </div>
        ))}
      </div>

      {/* Summary */}
      <div className="mt-6 p-4 bg-card border border-neon-green/20 rounded-lg">
        <p className="text-xs text-muted-foreground mb-2">Overall Threat Assessment</p>
        <p className="text-sm font-semibold text-foreground">
          {Math.round((animatedValues.urlStructure + animatedValues.domain + animatedValues.content) / 3)}% Average Risk
        </p>
      </div>
    </div>
  );
}
