"use client";

import { useChatStore } from "@/lib/store";

import {
  Bot,
  Network,
  Sparkles,
  Trash2,
} from "lucide-react";

import { SessionItem } from "./SessionItem";

interface Props {
  onToggleGraph: () => void;
  isGraphOpen: boolean;
}

export function Sidebar({
  onToggleGraph,
  isGraphOpen,
}: Props) {
  const {
    sessions,
    activeSessionId,
    clearAllSessions,
  } = useChatStore();

  return (
  
  <div className="flex flex-col h-full bg-[#C9CAAC] shadow-[8px_0_32px_rgba(0,0,0,0.35)]">
      {/* Header */}

      <div className="px-5 py-5">
        <div className="flex items-center gap-3">
          <div className="w-20 h-15 rounded-full bg-gradient-to-br from-[#2F4128] to-[#7A9370] flex items-center justify-center shadow-lg">
            <Bot className="w-8 h-8 text-white" />
          </div>

        <div>
          <div className="flex items-center gap-2">
            <h2 className="font-semibold text-[#2F4128] text-lg">
              ThreatGraph AI
            </h2>

            <Sparkles className="w-4 h-4 text-[#495A43]" />
          </div>

          <p className="text-xs text-[#495A43]">
            Knowledge Graph Powered Security Assistant
          </p>
        </div>
        </div>
      </div>

      {/* Graph Button */}

      <div className="px-4">
        <button
          onClick={onToggleGraph}
          className={`w-full flex items-center justify-center gap-2 rounded-xl px-4 py-3 transition-all ${
            isGraphOpen
              ? "bg-[#2F4128] border border-[#495A43] text-[#2F4128] border text-white"
              : "hover:bg-[#2F4128] bg-[#495A43]/25 border border-[#495A43] hover:text-white text-[#2F4128] cursor-pointer"
          }`}
        >
          <Network className="w-4 h-4" />

          <span className="text-sm font-medium">
            Knowledge Graph
          </span>
        </button>
      </div>

      {/* Session Label */}

      <div className="px-5 pt-6 pb-2">
        <p className="text-[11px] uppercase tracking-[0.2em] text-black">
          Session History
        </p>
      </div>

      {/* Sessions */}

      <div className="flex-1 overflow-y-auto px-3 pb-4">
        {sessions.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-center px-4">
            <div className="w-14 h-14 rounded-2xl bg-white/5 flex items-center justify-center mb-3">
              <Bot className="w-6 h-6 text-slate-500" />
            </div>

            <p className="text-sm text-slate-400">
              No investigations yet
            </p>

            <p className="text-xs text-slate-600 mt-1">
              Start a new analysis to create a session
            </p>
          </div>
        ) : (
          <div className="space-y-2">
            {sessions.map((session) => (
              <SessionItem
                key={session.id}
                session={session}
                isActive={
                  session.id === activeSessionId
                }
              />
            ))}
          </div>
        )}
      </div>

      {/* Footer */}

      {sessions.length > 0 && (
        <div className="p-4">
          <button
            onClick={clearAllSessions}
            className="w-full flex items-center justify-center gap-2 rounded-2xl bg-[#495A43] hover:bg-red-900 text-white py-3 transition-all cursor-pointer"
          >
            <Trash2 className="w-4 h-4" />

            <span className="text-sm">
              Clear History
            </span>
          </button>
        </div>
      )}
    </div>
  );
}