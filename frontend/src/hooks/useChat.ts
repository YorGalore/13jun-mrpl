"use client";

import { useChatStore } from "@/lib/store";
import { ChatRequest } from "@/lib/types";

const REQUEST_TIMEOUT_MS = 180_000;

export function useChat() {
  const store = useChatStore();

  const sendMessage = async (content: string) => {
    let sessionId = store.activeSessionId;

    if (!sessionId) {
      sessionId = store.createSession();
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

      const apiUrl = process.env.NEXT_PUBLIC_API_URL ?? "/api/chat";

      // Timeout eksplisit via AbortController supaya tidak menggantung selamanya.
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

      let res: Response;
      try {
        res = await fetch(apiUrl, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(request),
          signal: controller.signal,
        });
      } finally {
        clearTimeout(timer);
      }

      if (!res.ok) {
        let detail = "";
        try {
          detail = await res.text();
        } catch {
          /* abaikan */
        }
        throw new Error(
          `Backend error ${res.status}: ${detail?.slice(0, 400) || res.statusText}`
        );
      }

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
    } catch (err: any) {
      let msg: string;
      if (err?.name === "AbortError") {
        msg =
          "⚠️ Permintaan timeout: model terlalu lama merespons (umum pada model lokal/Ollama saat beban tinggi). Coba lagi, atau pilih model lain di dropdown.";
      } else if (
        err instanceof TypeError ||
        /failed to fetch|networkerror|load failed/i.test(err?.message ?? "")
      ) {
        msg =
          "⚠️ Tidak dapat terhubung ke backend. Pastikan backend Python jalan di port 8000 dan NEXT_PUBLIC_API_URL benar.";
      } else {
        msg = `⚠️ ${err?.message || "Terjadi kesalahan saat memproses permintaan."}`;
      }
      store.addMessage(sessionId!, {
        role: "assistant",
        content: msg,
        mode: store.currentMode,
      });
    } finally {
      store.setLoading(false);
    }
  };

  return { sendMessage };
}