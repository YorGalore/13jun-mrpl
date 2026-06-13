"use client";
import { useState } from "react";
import { Message } from "@/lib/types";

import {
  formatTimestamp,
  getModeLabel,
  cn,
} from "@/lib/utils";

import { useChatStore } from "@/lib/store";

import {
  Bot,
  User2,
  Cpu,
  BookOpen,
  Network,
  Code2,
} from "lucide-react";

import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

interface Props {
  message: Message;
}

export function MessageBubble({
  message,
}: Props) {
  const { toggleGraphViewer } = useChatStore();

  const [showSparql, setShowSparql] = useState(false);

  const isUser = message.role === "user";

  return (
    <div
      className={cn(
        "px-6 py-4",
        isUser ? "flex justify-end" : "flex"
      )}
    >
      <div
        className={cn(
          "flex gap-3 max-w-4xl",
          isUser
            ? "flex-row-reverse"
            : "flex-row"
        )}
      >
        {/* Avatar */}

        <div
          className={cn(
            "w-9 h-9 rounded-2xl flex items-center justify-center flex-shrink-0",
            isUser
              ? "bg-[#495A43]"
              : "bg-gradient-to-br from-[#495A43] to-[#869B7E] shadow-lg"
          )}
        >
          {isUser ? (
            <User2 className="w-4 h-4 text-white" />
          ) : (
            <Bot className="w-4 h-4 text-white" />
          )}
        </div>

        {/* Content */}

        <div
          className={cn(
            "flex flex-col",
            isUser && "items-end"
          )}
        >
          {/* Bubble */}

          <div
            className={cn(
              "rounded-3xl px-4 py-2 text-sm leading-7",
              isUser
                ? "bg-gradient-to-r from-[#495A43] to-[#7A9370] text-white shadow-lg rounded-tr-md"
                : "bg-[#495A43] pb-0 text-slate-200 shadow-[0_8px_24px_rgba(0,0,0,0.25)] rounded-tl-md"
            )}
          >
            {isUser ? (
              <p>{message.content}</p>
            ) : (
              <div className="prose prose-invert max-w-none">
                <ReactMarkdown
                  remarkPlugins={[remarkGfm]}
                >
                  {message.content}
                </ReactMarkdown>
              </div>
            )}
          </div>

          {/* Meta */}

          <div className="flex flex-wrap items-center gap-3 mt-2 px-2">
            <span className="text-[11px] text-black/60">
              {formatTimestamp(
                message.timestamp
              )}
            </span>

            {message.llmUsed && (
              <span className="flex items-center gap-1 text-[11px] text-black/60">
                <Cpu className="w-3 h-3" />
                {message.llmUsed}
              </span>
            )}

            {message.mode &&
              !isUser && (
                <span className="text-[11px] text-black/60">
                  {getModeLabel(
                    message.mode
                  )}
                </span>
              )}

            {message.sources &&
              message.sources.length >
                0 && (
                <span className="flex items-center gap-1 text-[11px] text-black/60">
                  <BookOpen className="w-3 h-3" />
                  {message.sources.join(
                    ", "
                  )}
                </span>
              )}

            {message.triples &&
              message.triples.length >
                0 && (
                <button
                  onClick={() =>
                    toggleGraphViewer(
                      message
                    )
                  }
                  className="flex items-center gap-1 bg-[#495A43]/20 hover:bg-[#495A43]/40 text-[#495A43] px-2 py-1 rounded-full text-[11px] transition-all"
                >
                  <Network className="w-3 h-3" />

                  {
                    message.triples
                      .length
                  }{" "}
                  triples
                </button>
              )}

            {!isUser && message.method && (
              <span className="text-[11px] text-black/60 uppercase tracking-wide">
                {message.method}
              </span>
            )}

            {!isUser && message.sparql && (
              <button
                onClick={() => setShowSparql((v) => !v)}
                className="flex items-center gap-1 bg-[#495A43]/20 hover:bg-[#495A43]/40 text-[#495A43] px-2 py-1 rounded-full text-[11px] transition-all"
              >
                <Code2 className="w-3 h-3" />
                {showSparql ? "Hide SPARQL" : "SPARQL"}
              </button>
            )}
          </div>

          {!isUser && message.sparql && showSparql && (
            <pre className="mt-2 max-w-full overflow-x-auto rounded-2xl bg-[#2F4128] px-4 py-3 text-[11px] leading-5 text-slate-100 whitespace-pre-wrap">
              {message.sparql}
            </pre>
          )}
        </div>
      </div>
    </div>
  );
}