"use client";

import {
  useState,
  useRef,
  KeyboardEvent,
} from "react";

import {
  SendHorizontal,
  Sparkles,
  Paperclip,
} from "lucide-react";

import { cn } from "@/lib/utils";
import { useChatStore } from "@/lib/store";

interface Props {
  onSend: (message: string) => void;
}

export function ChatInput({
  onSend,
}: Props) {
  const [value, setValue] =
    useState("");

  const textareaRef =
    useRef<HTMLTextAreaElement>(null);

  const {
    currentMode,
    isLoading,
  } = useChatStore();

  const handleSend = () => {
    const trimmed =
      value.trim();

    if (!trimmed || isLoading)
      return;

    onSend(trimmed);

    setValue("");

    if (textareaRef.current) {
      textareaRef.current.style.height =
        "auto";
    }
  };

  const handleKeyDown = (
    e: KeyboardEvent<HTMLTextAreaElement>
  ) => {
    if (
      e.key === "Enter" &&
      !e.shiftKey
    ) {
      e.preventDefault();
      handleSend();
    }
  };

  const handleInput = () => {
    const el = textareaRef.current;

    if (!el) return;

    el.style.height = "auto";

    el.style.height =
      Math.min(
        el.scrollHeight,
        160
      ) + "px";
  };

  const PLACEHOLDERS = {
    threat_intelligence:
      "Ask about CVEs, malware, attack patterns, or threat actors...",

    log_analysis:
      "Paste security logs or suspicious events for analysis...",

    combined:
      "Correlate logs with threat intelligence and attack patterns...",
  };

  const MODE_LABELS = {
    threat_intelligence:
      "Threat Intelligence",

    log_analysis:
      "Security Log Analysis",

    combined:
      "Threat Correlation",
  };

  return (
    <div className="px-6 pb-6 pt-4 bg-[#F6F3EB]">
      {/* Container */}

      <div className="bg-[#FFFDF6] rounded-[28px] shadow-[0_10px_40px_rgba(0,0,0,0.35)] overflow-hidden">
        {/* Top */}

        <div className="px-5 pt-4 flex items-center justify-between">
          <div className="flex items-center gap-2 text-[#495A43]">
            <Sparkles className="w-4 h-4 text-[#495A43]" />

            <span className="text-xs font-medium">
              {
                MODE_LABELS[
                  currentMode
                ]
              }
            </span>
          </div>

          <button
            disabled
            className="w-8 h-8 rounded-xl bg-white/5 flex items-center justify-center text-slate-500 cursor-not-allowed"
          >
            <Paperclip className="w-4 h-4" />
          </button>
        </div>

        {/* Textarea */}

        <div className="px-5 py-3">
          <textarea
            ref={textareaRef}
            rows={1}
            value={value}
            disabled={isLoading}
            onInput={handleInput}
            onKeyDown={handleKeyDown}
            onChange={(e) =>
              setValue(
                e.target.value
              )
            }
            placeholder={
              PLACEHOLDERS[
                currentMode
              ]
            }
            className={cn(
              "w-full bg-transparent resize-none outline-none",
              "text-sm text-black/80",
              "placeholder:text-slate-500",
              "min-h-[24px] max-h-[160px]",
              "disabled:opacity-50"
            )}
          />
        </div>

        {/* Footer */}

        <div className="px-5 pb-4 flex items-center justify-between">
          <p className="text-[11px] text-slate-500">
            Enter to send · Shift+Enter
            for newline
          </p>

          <button
            onClick={handleSend}
            disabled={
              !value.trim() ||
              isLoading
            }
            className={cn(
              "w-11 h-11 rounded-2xl flex items-center justify-center transition-all",

              value.trim() &&
                !isLoading
                ? "bg-[#495A43] hover:bg-[#2F4128] text-white shadow-lg cursor-pointer"
                : "bg-white/5 text-slate-600 cursor-not-allowed"
            )}
          >
            <SendHorizontal className="w-4 h-4" />
          </button>
        </div>
      </div>
    </div>
  );
}