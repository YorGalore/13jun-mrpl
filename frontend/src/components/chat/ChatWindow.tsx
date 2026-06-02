"use client";

import { useEffect, useRef } from "react";

import { useChatStore } from "@/lib/store";
import { MessageBubble } from "./MessageBubble";
import { ChatInput } from "./ChatInput";
import { TypingIndicator } from "./TypingIndicator";
import { ModeSelector, ModelSelector } from "../analysis/ModeSelector";
import { useChat } from "@/hooks/useChat";

import {
Bot,
MessageSquarePlus,
ShieldAlert,
FileSearch,
Network,
ArrowRight,
} from "lucide-react";

import { getModeDescription } from "@/lib/utils";

export function ChatWindow() {
const {
getActiveSession,
isLoading,
currentMode,
createSession,
} = useChatStore();

const { sendMessage } = useChat();

const bottomRef = useRef<HTMLDivElement>(null);

const session = getActiveSession();

useEffect(() => {
bottomRef.current?.scrollIntoView({
behavior: "smooth",
});
}, [session?.messages, isLoading]);

const handleNewChat = () =>
createSession(currentMode);

return ( <div className="flex flex-col h-full bg-[#F6F3EB]">
{/* Header */}


  <div className="px-8 py-3 bg-[#E4E5CA] border-b border-[#C9CAAC]">
    <div className="flex items-center justify-between">
      <div className="flex items-center gap-3">
        <ModeSelector />
        <ModelSelector />
      </div>

      <button
        onClick={handleNewChat}
        className="flex items-center gap-2 rounded-2xl bg-[#495A43] hover:bg-[#2F4128] cursor-pointer px-4 py-2.5 text-white transition-all shadow-sm"
      >
        <MessageSquarePlus className="w-4 h-4" />
        New Chat
      </button>
    </div>
  </div>

  {/* Messages */}

  <div className="flex-1 overflow-y-auto">
    {!session ||
    session.messages.length === 0 ? (
      <EmptyState
        mode={currentMode}
        onExample={sendMessage}
      />
    ) : (
      session.messages.map((msg) => (
        <MessageBubble
          key={msg.id}
          message={msg}
        />
      ))
    )}

    {isLoading && <TypingIndicator />}

    <div ref={bottomRef} />
  </div>

  {/* Input */}

  <ChatInput onSend={sendMessage} />
</div>


);
}

function EmptyState({
mode,
onExample,
}: {
mode: Parameters<typeof getModeDescription>[0];
onExample: (question: string) => void;
}) {
const EXAMPLES: Record<
typeof mode,
string[]
> = {
  threat_intelligence: [
    "Analyze CVE-2021-44228",
    "Profile APT41",
    "Show ransomware attack patterns",
  ],

log_analysis: [
  "Analyze failed SSH login attempts",
  "Review suspicious PowerShell activity",
  "Investigate Windows security events",
],

combined: [
  "Correlate logs with MITRE ATT&CK",
  "Link traffic anomalies to threat actors",
  "Match indicators to known campaigns",
],

};

return (
<div className="h-full translate-y-[25%] flex flex-col items-center justify-center px-8 py-12 bg-[#F6F3EB] text-center">
{/* Logo */}

  <div className="w-15 h-15 rounded-xl bg-gradient-to-br from-[#495A43] to-[#869B7E] flex items-center justify-center shadow-lg">
    <Bot className="w-15 h-15 text-white p-2" />
  </div>

  {/* Title */}

  <h1 className="mt-3 text-4xl font-bold text-[#2F4128]">
    ThreatGraph AI
  </h1>

  <p className="mt-3 text-[#495A43] max-w-xl">
    Security Copilot powered by
    Cyber Security Knowledge Graphs
  </p>

  {/* Feature Cards */}

  <div className="grid md:grid-cols-3 gap-6 mt-10 w-full max-w-5xl">
    <FeatureCard
      icon={
        <ShieldAlert className="w-8 h-8" />
      }
      title="Threat Intelligence"
      desc="Malware investigation, CVE analysis, vulnerability relationships, and threat actor profiling."
    />

    <FeatureCard
      icon={
        <FileSearch className="w-8 h-8" />
      }
      title="Security Log Analysis"
      desc="Analyze suspicious events, authentication anomalies, and system security logs."
    />

    <FeatureCard
      icon={
        <Network className="w-8 h-8" />
      }
      title="Threat Correlation"
      desc="Connect security logs with global threat intelligence and attack patterns."
    />
  </div>

  {/* Examples */}

  <div className="mt-10 w-full max-w-3xl space-y-3">
    {EXAMPLES[mode].map(
      (example) => (
        <button
          key={example}
          onClick={() =>
            onExample(example)
          }
          className="
            w-full
            text-left
            bg-[#C9CAAC]
            hover:bg-[#E4E5CA]
            border
            border-[#C9CAAC]
            rounded-2xl
            px-5
            py-4
            text-sm
            text-[#2F4128]
            transition-all
            shadow-sm
            cursor-pointer
            flex justify-between
            font-medium
          "
        >
          {example}
          <ArrowRight className="w-5 h-5 text-[#2F4128] font-bold" />
        </button>
      )
    )}
  </div>
</div>

);
}

function FeatureCard({
icon,
title,
desc,
}: {
icon: React.ReactNode;
title: string;
desc: string;
}) {
return ( <div
   className="
     h-full
     bg-white
     rounded-3xl
     p-6
     flex
     flex-col
     items-center
     text-center
     border
     border-[#C9CAAC]
     shadow-sm
     hover:shadow-md
     transition-all
   "
 > <div className="flex items-center justify-center mb-4 text-[#495A43]">
{icon} </div>

  <h3 className="font-semibold text-[#2F4128] text-lg">
    {title}
  </h3>

  <p className="mt-2 text-sm text-[#495A43]">
    {desc}
  </p>
</div>

);
}
