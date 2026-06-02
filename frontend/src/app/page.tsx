"use client";

import { useEffect, useState } from "react";

import { Sidebar } from "@/components/sidebar/Sidebar";
import { ChatWindow } from "@/components/chat/ChatWindow";
import { GraphViewer } from "@/components/graph/GraphViewer";

import { useChatStore } from "@/lib/store";

export default function Home() {
  const {
    sessions,
    createSession,
    isGraphViewerOpen,
    toggleGraphViewer,
    setAvailableModels
  } = useChatStore();

  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    const id = requestAnimationFrame(() => {
      setMounted(true);
    });

    return () => cancelAnimationFrame(id);
  }, []);

  useEffect(() => {
    const url = process.env.NEXT_PUBLIC_API_URL
      ? process.env.NEXT_PUBLIC_API_URL.replace(/\/chat$/, "/models")
      : "/api/models";
    fetch(url)
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => {
        if (d?.models?.length) setAvailableModels(d.models);
      })
      .catch(() => {
        /* backend belum jalan; dropdown disembunyikan */
      });
  }, [setAvailableModels]);

  useEffect(() => {
    if (sessions.length === 0) {
      createSession();
    }
  }, [sessions.length, createSession]);

  if (!mounted) return null;

  return (
    <main className="flex h-screen overflow-hidden bg-[#0B1220]">
      {/* Sidebar */}

      <aside className="w-72 shrink-0">
        <Sidebar
          onToggleGraph={toggleGraphViewer}
          isGraphOpen={isGraphViewerOpen}
        />
      </aside>

      {/* Chat */}

      <section className="flex-1 min-w-0">
        <ChatWindow />
      </section>

      {/* Graph */}

      {isGraphViewerOpen && (
        <aside className="w-[380px] shrink-0">
          <GraphViewer />
        </aside>
      )}
    </main>
  );
}