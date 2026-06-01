"use client";

import { useChatStore } from "@/lib/store";
import { AnalysisMode } from "@/lib/types";

import {
  ShieldAlert,
  FileSearch,
  Network,
} from "lucide-react";

import { cn } from "@/lib/utils";

const MODES: {
  mode: AnalysisMode;
  label: string;
  icon: React.ReactNode;
}[] = [
  {
    mode: "threat_intelligence",
    label: "Threat Intelligence",
    icon: <ShieldAlert className="w-4 h-4" />,
  },
  {
    mode: "log_analysis",
    label: "Log Analysis",
    icon: <FileSearch className="w-4 h-4" />,
  },
  {
    mode: "combined",
    label: "Threat Correlation",
    icon: <Network className="w-4 h-4" />,
  },
];

export function ModeSelector() {
  const {
    currentMode,
    setCurrentMode,
  } = useChatStore();

  return (
    <div className="flex flex-wrap gap-2">
      {MODES.map((item) => (
        <button
          key={item.mode}
          onClick={() =>
            setCurrentMode(item.mode)
          }
          className={cn(
            "flex items-center gap-2 px-4 py-2 rounded-2xl text-sm transition-all",

            currentMode === item.mode
              ? "bg-[#2F4128] border border-[#495A43] text-white shadow-lg"
              : "bg-[#495A43]/30 border border-[#495A43] hover:bg-[#2F4128]/80 text-[#2F4128] hover:text-white cursor-pointer"
          )}
        >
          {item.icon}

          <span>{item.label}</span>
        </button>
      ))}
    </div>
  );
}