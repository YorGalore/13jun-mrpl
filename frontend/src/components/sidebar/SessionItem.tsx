"use client";

import { ChatSession } from "@/lib/types";

import {
  cn,
  truncateText,
  getModeLabel,
} from "@/lib/utils";

import { useChatStore } from "@/lib/store";

import {
  Trash2,
  ShieldAlert,
  FileSearch,
  Layers3,
} from "lucide-react";

import { formatDistanceToNow } from "date-fns";

interface Props {
  session: ChatSession;
  isActive: boolean;
}

export function SessionItem({
  session,
  isActive,
}: Props) {
  const {
    setActiveSession,
    deleteSession,
  } = useChatStore();

  const getModeIcon = () => {
    switch (session.mode) {
      case "threat_intelligence":
        return (
          <ShieldAlert className="w-3.5 h-3.5 text-[#495A43]" />
        );

      case "log_analysis":
        return (
          <FileSearch className="w-3.5 h-3.5 text-[#495A43]" />
        );

      default:
        return (
          <Layers3 className="w-3.5 h-3.5 text-[#495A43]" />
        );
    }
  };

  return (
    <div
      onClick={() =>
        setActiveSession(session.id)
      }
      className={cn(
        "group cursor-pointer rounded-xl p-4 transition-all",
        isActive
          ? "bg-[#F6F3EB] shadow-lg"
          : "bg-[#E4E5CA] hover:bg-[#E4E5CA]"
      )}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="flex items-center gap-2 min-w-0">
          {getModeIcon()}

          <h4 className="text-sm text-black truncate">
            {truncateText(
              session.title || "New Investigation",
              36
            )}
          </h4>
        </div>

        <button
          onClick={(e) => {
            e.stopPropagation();
            deleteSession(session.id);
          }}
          className="opacity-0 group-hover:opacity-100 transition-opacity text-slate-500 hover:text-red-900 cursor-pointer"
        >
          <Trash2 className="w-3.5 h-3.5" />
        </button>
      </div>

      <div className="mt-3 flex items-center justify-between">
        <span className="text-[11px] text-black/80 tracking-[0.1em]">
          {getModeLabel(session.mode)}
        </span>

        <span className="text-[11px] text-black/80">
          {formatDistanceToNow(
            new Date(session.createdAt),
            { addSuffix: true }
          )}
        </span>
      </div>

      {session.messages.length > 0 && (
        <p className="mt-2 text-xs text-black/60 line-clamp-2">
          {
            session.messages[
              session.messages.length - 1
            ].content
          }
        </p>
      )}
    </div>
  );
}