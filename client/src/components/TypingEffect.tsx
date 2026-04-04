import { useEffect, useState } from "react";

interface TypingEffectProps {
  messages: string[];
  speed?: number;
  onComplete?: () => void;
}

export function TypingEffect({
  messages,
  speed = 100,
  onComplete,
}: TypingEffectProps) {
  const [displayText, setDisplayText] = useState("");
  const [currentMessageIndex, setCurrentMessageIndex] = useState(0);
  const [isTyping, setIsTyping] = useState(true);

  useEffect(() => {
    if (!isTyping) {
      onComplete?.();
      return;
    }

    const currentMessage = messages[currentMessageIndex];
    let currentCharIndex = 0;

    const typeInterval = setInterval(() => {
      if (currentCharIndex < currentMessage.length) {
        setDisplayText(currentMessage.substring(0, currentCharIndex + 1));
        currentCharIndex++;
      } else {
        clearInterval(typeInterval);

        // Move to next message or complete
        if (currentMessageIndex < messages.length - 1) {
          setTimeout(() => {
            setCurrentMessageIndex(currentMessageIndex + 1);
            setDisplayText("");
          }, 1000);
        } else {
          setIsTyping(false);
        }
      }
    }, speed);

    return () => clearInterval(typeInterval);
  }, [currentMessageIndex, isTyping, messages, speed, onComplete]);

  return (
    <div className="flex items-center gap-2 text-sm text-muted-foreground">
      <div className="w-2 h-2 rounded-full bg-neon-green animate-pulse" />
      <span>{displayText}</span>
      {isTyping && <span className="animate-pulse">|</span>}
    </div>
  );
}
