import { useState, useMemo } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { trpc } from "@/lib/trpc";
import { Loader2, Search, Shield, AlertTriangle, AlertCircle, ChevronDown } from "lucide-react";
import { format } from "date-fns";

interface ScanHistoryProps {
  refreshTrigger?: number;
}

export function ScanHistory({ refreshTrigger }: ScanHistoryProps) {
  const [searchTerm, setSearchTerm] = useState("");
  const [sortBy, setSortBy] = useState<"date" | "risk">("date");
  const [filterLevel, setFilterLevel] = useState<"all" | "safe" | "suspicious" | "dangerous">("all");
  const [expandedId, setExpandedId] = useState<number | null>(null);

  const historyQuery = trpc.urlAnalysis.history.useQuery({ limit: 100, offset: 0 });

  const filteredAndSortedScans = useMemo(() => {
    if (!historyQuery.data) return [];

    let filtered = historyQuery.data.filter((scan) => {
      const matchesSearch = scan.url.toLowerCase().includes(searchTerm.toLowerCase());
      const matchesFilter = filterLevel === "all" || scan.threatLevel === filterLevel;
      return matchesSearch && matchesFilter;
    });

    return filtered.sort((a, b) => {
      if (sortBy === "date") {
        return new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime();
      } else {
        return b.riskScore - a.riskScore;
      }
    });
  }, [historyQuery.data, searchTerm, sortBy, filterLevel]);

  const getThreatIcon = (level: string) => {
    switch (level) {
      case "safe":
        return <Shield className="w-4 h-4 text-neon-green" />;
      case "suspicious":
        return <AlertTriangle className="w-4 h-4 text-neon-yellow" />;
      case "dangerous":
        return <AlertCircle className="w-4 h-4 text-neon-red" />;
    }
  };

  const getThreatColor = (level: string) => {
    switch (level) {
      case "safe":
        return "text-neon-green";
      case "suspicious":
        return "text-neon-yellow";
      case "dangerous":
        return "text-neon-red";
    }
  };

  const getBorderColor = (level: string) => {
    switch (level) {
      case "safe":
        return "border-neon-green/20 hover:border-neon-green/50";
      case "suspicious":
        return "border-neon-yellow/20 hover:border-neon-yellow/50";
      case "dangerous":
        return "border-neon-red/20 hover:border-neon-red/50";
    }
  };

  if (historyQuery.isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="w-6 h-6 animate-spin text-neon-green" />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Search and Filter Controls */}
      <div className="space-y-3">
        <div className="relative">
          <Search className="absolute left-3 top-3 w-4 h-4 text-muted-foreground" />
          <Input
            placeholder="Search URLs..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="pl-10 bg-card border-neon-green/20 focus:border-neon-green/50"
          />
        </div>

        <div className="flex gap-2 flex-wrap">
          <div className="flex gap-1">
            {(["all", "safe", "suspicious", "dangerous"] as const).map((level) => (
              <Button
                key={level}
                size="sm"
                variant={filterLevel === level ? "default" : "outline"}
                onClick={() => setFilterLevel(level)}
                className={
                  filterLevel === level
                    ? "bg-neon-green text-background hover:bg-neon-green/90"
                    : "border-neon-green/30 hover:bg-neon-green/10"
                }
              >
                {level.charAt(0).toUpperCase() + level.slice(1)}
              </Button>
            ))}
          </div>

          <div className="flex gap-1 ml-auto">
            <Button
              size="sm"
              variant={sortBy === "date" ? "default" : "outline"}
              onClick={() => setSortBy("date")}
              className={
                sortBy === "date"
                  ? "bg-neon-blue text-background hover:bg-neon-blue/90"
                  : "border-neon-blue/30 hover:bg-neon-blue/10"
              }
            >
              Recent
            </Button>
            <Button
              size="sm"
              variant={sortBy === "risk" ? "default" : "outline"}
              onClick={() => setSortBy("risk")}
              className={
                sortBy === "risk"
                  ? "bg-neon-blue text-background hover:bg-neon-blue/90"
                  : "border-neon-blue/30 hover:bg-neon-blue/10"
              }
            >
              Risk
            </Button>
          </div>
        </div>
      </div>

      {/* Scan History List */}
      <div className="space-y-2">
        {filteredAndSortedScans.length > 0 ? (
          filteredAndSortedScans.map((scan) => (
            <div
              key={scan.id}
              className={`bg-card border rounded-lg transition-all duration-200 ${getBorderColor(scan.threatLevel)}`}
            >
              <button
                onClick={() => setExpandedId(expandedId === scan.id ? null : scan.id)}
                className="w-full p-4 flex items-center justify-between hover:bg-card/50 transition-colors"
              >
                <div className="flex items-center gap-3 flex-1 min-w-0">
                  {getThreatIcon(scan.threatLevel)}
                  <div className="flex-1 min-w-0 text-left">
                    <p className="text-sm font-mono text-foreground truncate">{scan.url}</p>
                    <p className="text-xs text-muted-foreground">
                      {format(new Date(scan.createdAt), "MMM dd, yyyy HH:mm:ss")}
                    </p>
                  </div>
                </div>

                <div className="flex items-center gap-3 flex-shrink-0">
                  <div className="text-right">
                    <p className={`text-sm font-bold ${getThreatColor(scan.threatLevel)}`}>
                      {scan.riskScore}%
                    </p>
                    <p className={`text-xs font-semibold ${getThreatColor(scan.threatLevel)}`}>
                      {scan.threatLevel.toUpperCase()}
                    </p>
                  </div>
                  <ChevronDown
                    className={`w-4 h-4 text-muted-foreground transition-transform ${
                      expandedId === scan.id ? "rotate-180" : ""
                    }`}
                  />
                </div>
              </button>

              {/* Expanded Details */}
              {expandedId === scan.id && (
                <div className="border-t border-neon-green/20 p-4 space-y-3 bg-card/50">
                  {scan.triggeredRules.length > 0 && (
                    <div>
                      <p className="text-xs font-semibold text-muted-foreground mb-2">
                        Triggered Rules ({scan.triggeredRules.length})
                      </p>
                      <div className="space-y-1">
                        {scan.triggeredRules.slice(0, 5).map((rule: any) => (
                          <div key={rule.id} className="text-xs text-foreground flex justify-between">
                            <span>{rule.name}</span>
                            <span className="text-neon-yellow">+{rule.weight}</span>
                          </div>
                        ))}
                        {scan.triggeredRules.length > 5 && (
                          <p className="text-xs text-muted-foreground">
                            +{scan.triggeredRules.length - 5} more rules
                          </p>
                        )}
                      </div>
                    </div>
                  )}

                  {scan.reasons.length > 0 && (
                    <div>
                      <p className="text-xs font-semibold text-muted-foreground mb-2">Reasons</p>
                      <ul className="space-y-1">
                        {scan.reasons.slice(0, 3).map((reason: any, idx: number) => (
                          <li key={idx} className="text-xs text-foreground flex gap-2">
                            <span className="text-neon-green">•</span>
                            <span>{reason}</span>
                          </li>
                        ))}
                        {scan.reasons.length > 3 && (
                          <p className="text-xs text-muted-foreground">+{scan.reasons.length - 3} more</p>
                        )}
                      </ul>
                    </div>
                  )}
                </div>
              )}
            </div>
          ))
        ) : (
          <div className="text-center py-12 bg-card border border-neon-green/20 rounded-lg neon-border-green">
            <Shield className="w-8 h-8 text-muted-foreground mx-auto mb-3" />
            <p className="text-sm text-muted-foreground">
              {historyQuery.data?.length === 0 ? "No scans yet. Analyze your first URL!" : "No results match your filters."}
            </p>
          </div>
        )}
      </div>

      {/* Load More Indicator */}
      {filteredAndSortedScans.length > 0 && (
        <p className="text-xs text-muted-foreground text-center">
          Showing {filteredAndSortedScans.length} of {historyQuery.data?.length || 0} scans
        </p>
      )}
    </div>
  );
}
