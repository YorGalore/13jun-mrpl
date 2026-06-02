"use client";

import { useChatStore } from "@/lib/store";
import { AnalysisMode } from "@/lib/types";
import { getModeLabel } from "@/lib/utils";
import { Cpu, ShieldAlert, FileSearch, Layers3 } from "lucide-react";

const MODES: AnalysisMode[] = [
  "threat_intelligence",
  "log_analysis",
  "combined",
];

function modeIcon(mode: AnalysisMode) {
  switch (mode) {
    case "threat_intelligence":
      return <ShieldAlert className="w-4 h-4" />;
    case "log_analysis":
      return <FileSearch className="w-4 h-4" />;
    default:
      return <Layers3 className="w-4 h-4" />;
  }
}

export function ModeSelector() {
  const { currentMode, setCurrentMode } = useChatStore();

  return (
    <div className="flex items-center gap-1 bg-[#495A43]/15 border border-[#495A43]/40 rounded-2xl p-1">
      {MODES.map((mode) => {
        const active = mode === currentMode;
        return (
          <button
            key={mode}
            onClick={() => setCurrentMode(mode)}
            title={getModeLabel(mode)}
            className={`flex items-center gap-2 rounded-xl px-3 py-2 text-sm font-medium transition-all cursor-pointer ${
              active
                ? "bg-[#495A43] text-white shadow-sm"
                : "text-[#2F4128] hover:bg-[#495A43]/20"
            }`}
          >
            {modeIcon(mode)}
            <span className="hidden sm:inline">{getModeLabel(mode)}</span>
          </button>
        );
      })}
    </div>
  );
}

export function ModelSelector() {
  const { currentModel, availableModels, setCurrentModel } = useChatStore();

  const models = availableModels ?? [];
  if (!models.length) return null;

  return (
    <div className="flex items-center gap-2">
      <Cpu className="w-4 h-4 text-[#495A43]" />
      <select
        value={currentModel}
        onChange={(e) => setCurrentModel(e.target.value)}
        className="bg-[#495A43]/20 border border-[#495A43] text-[#2F4128] text-sm rounded-2xl px-3 py-2 cursor-pointer focus:outline-none max-w-[260px]"
        title="Pilih model LLM (untuk perbandingan)"
      >
        {availableModels.map((m) => (
          <option key={m} value={m}>
            {m}
          </option>
        ))}
      </select>
    </div>
  );
}
