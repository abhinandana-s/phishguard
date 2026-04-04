import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Loader2, Shield, AlertCircle } from "lucide-react";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";

interface UrlAnalysisFormProps {
  onAnalysisComplete?: () => void;
}

export function UrlAnalysisForm({ onAnalysisComplete }: UrlAnalysisFormProps) {
  const [url, setUrl] = useState("");
  const [isValidating, setIsValidating] = useState(false);
  const analyzeMutation = trpc.urlAnalysis.analyze.useMutation();

  const isLoading = analyzeMutation.isPending;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!url.trim()) {
      toast.error("Please enter a URL");
      return;
    }

    try {
      setIsValidating(true);
      await analyzeMutation.mutateAsync({ url: url.trim() });
      setUrl("");
      onAnalysisComplete?.();
      toast.success("URL analyzed successfully");
    } catch (error) {
      const message = error instanceof Error ? error.message : "Failed to analyze URL";
      toast.error(message);
    } finally {
      setIsValidating(false);
    }
  };

  const handleUrlChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setUrl(e.target.value);
  };

  return (
    <form onSubmit={handleSubmit} className="w-full">
      <div className="space-y-4">
        <div className="relative">
          <div className="absolute inset-0 bg-gradient-to-r from-neon-green/20 via-neon-blue/20 to-neon-purple/20 rounded-lg blur-xl opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
          <div className="relative flex items-center gap-3 p-1 bg-card border border-neon-green/30 rounded-lg neon-border-green">
            <Shield className="w-5 h-5 text-neon-green ml-3 flex-shrink-0" />
            <Input
              type="text"
              placeholder="Enter a URL to scan (e.g., https://example.com)"
              value={url}
              onChange={handleUrlChange}
              disabled={isLoading}
              className="flex-1 bg-transparent border-0 text-foreground placeholder:text-muted-foreground focus:ring-0 focus-visible:ring-0"
            />
            {url && !isLoading && (
              <button
                type="button"
                onClick={() => setUrl("")}
                className="mr-3 text-muted-foreground hover:text-foreground transition-colors"
              >
                ✕
              </button>
            )}
          </div>
        </div>

        <Button
          type="submit"
          disabled={isLoading || !url.trim()}
          className="w-full h-12 bg-gradient-to-r from-neon-green to-neon-blue text-background font-semibold rounded-lg hover:shadow-lg neon-glow-green transition-all duration-300 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {isLoading ? (
            <>
              <Loader2 className="w-4 h-4 mr-2 animate-spin" />
              Scanning URL...
            </>
          ) : (
            <>
              <Shield className="w-4 h-4 mr-2" />
              Scan URL
            </>
          )}
        </Button>

        {isValidating && (
          <div className="flex items-center justify-center gap-2 text-sm text-neon-blue">
            <Loader2 className="w-4 h-4 animate-spin" />
            <span>Validating URL...</span>
          </div>
        )}
      </div>
    </form>
  );
}
