"use client";

import { useChatStore } from "@/lib/store";
import { ChatRequest } from "@/lib/types";

export function useChat() {
  const store = useChatStore();

  const sendMessage = async (content: string) => {
    let sessionId = store.activeSessionId;

    if (!sessionId) {
      sessionId = store.createSession();
    }

    const session = store.getActiveSession();
    if (!session && sessionId) {
      // session just created
    }

    // Add user message
    store.addMessage(sessionId!, {
      role: "user",
      content,
      mode: store.currentMode,
    });

    store.setLoading(true);

    try {
      const currentSession = store.sessions.find((s) => s.id === sessionId);
      const history = (currentSession?.messages ?? [])
        .slice(-10)
        .map((m) => ({ role: m.role, content: m.content }));

      const request: ChatRequest = {
        message: content,
        mode: store.currentMode,
        sessionId: sessionId!,
        history,
        model: store.currentModel || undefined,
      };

      const apiUrl =
        process.env.NEXT_PUBLIC_API_URL ?? "/api/chat";

      const res = await fetch(apiUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(request),
      });

      if (!res.ok) throw new Error(`API error: ${res.status}`);

      const data = await res.json();

      store.addMessage(sessionId!, {
        role: "assistant",
        content: data.message,
        mode: store.currentMode,
        triples: data.triples,
        graphData: data.graphData,
        llmUsed: data.llmUsed,
        sources: data.sources,
        method: data.method,
        sparql: data.sparql,
      });
    } catch (err) {
      store.addMessage(sessionId!, {
        role: "assistant",
        content:
          "⚠️ Failed to connect to backend. Make sure the Python backend is running on port 8000.",
        mode: store.currentMode,
      });
    } finally {
      store.setLoading(false);
    }
  };

  return { sendMessage };
}