"use client";

import { Bot } from "lucide-react";

export function TypingIndicator() {
  return (
    <div className="px-6 py-4">
      <div className="flex items-start gap-3">
        <div className="w-9 h-9 rounded-2xl bg-gradient-to-br from-[#495A43] to-[#869B7E] flex items-center justify-center shadow-lg flex-shrink-0">
          <Bot className="w-4 h-4 text-white" />
        </div>

        <div className="bg-[#495A43] rounded-3xl rounded-tl-md px-5 py-4 shadow-[0_8px_24px_rgba(0,0,0,0.25)]">
          <div className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-[#495A43] animate-bounce" />
            <span className="w-2 h-2 rounded-full bg-[#495A43] animate-bounce [animation-delay:120ms]" />
            <span className="w-2 h-2 rounded-full bg-[#495A43] animate-bounce [animation-delay:240ms]" />
          </div>

          <p className="text-xs text-slate-500 mt-2">
            Analyzing knowledge graph...
          </p>
        </div>
      </div>
    </div>
  );
}