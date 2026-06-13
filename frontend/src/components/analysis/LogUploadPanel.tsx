"use client";

import { useEffect, useRef, useState } from "react";
import {
  UploadCloud,
  FileText,
  Loader2,
  CheckCircle2,
  AlertTriangle,
} from "lucide-react";

import { cn, getLogTypeLabel } from "@/lib/utils";
import {
  LogType,
  LogStatsResponse,
  LogUploadResponse,
} from "@/lib/types";

const TYPE_OPTIONS: { value: "" | LogType; label: string }[] = [
  { value: "", label: "Auto-deteksi" },
  { value: "auth", label: "Auth / SSH" },
  { value: "syslog", label: "Syslog" },
  { value: "web_access", label: "Web access" },
  { value: "ids_alert", label: "IDS alert" },
  { value: "firewall", label: "Firewall" },
];

export function LogUploadPanel() {
  const [content, setContent] = useState("");
  const [logType, setLogType] = useState<"" | LogType>("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<{ ok: boolean; text: string } | null>(null);
  const [backend, setBackend] = useState("");
  const [stats, setStats] = useState<Record<string, number>>({});
  const [types, setTypes] = useState<LogType[]>([]);
  const fileRef = useRef<HTMLInputElement>(null);

  const loadStats = async () => {
    try {
      const res = await fetch("/api/logs/stats", { cache: "no-store" });
      if (!res.ok) return;
      const data: LogStatsResponse = await res.json();
      setBackend(data.backend ?? "");
      setStats(data.stats ?? {});
      setTypes(data.types ?? []);
    } catch {
      /* panel tetap berguna walau stats gagal */
    }
  };

  useEffect(() => {
    loadStats();
  }, []);

  const onFile = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const text = await file.text();
    setContent((prev) => (prev ? `${prev}\n${text}` : text));
  };

  const submit = async () => {
    setResult(null);
    const trimmed = content.trim();
    if (!trimmed) {
      setResult({ ok: false, text: "Tempel teks log atau pilih file terlebih dulu." });
      return;
    }
    setBusy(true);
    try {
      const res = await fetch("/api/logs", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          content: trimmed,
          source: "upload",
          logType: logType || null,
        }),
      });
      const data: LogUploadResponse = await res.json();
      if (data.ok) {
        setResult({
          ok: true,
          text: `Terindeks ${data.inserted} entri ke ${data.backend}.`,
        });
        setContent("");
        if (fileRef.current) fileRef.current.value = "";
        setBackend(data.backend || backend);
        if (data.stats) setStats(data.stats);
      } else {
        setResult({ ok: false, text: "Tidak ada entri terindeks. Periksa isi log." });
      }
    } catch {
      setResult({
        ok: false,
        text: "Gagal menghubungi backend. Pastikan server jalan di port 8000.",
      });
    } finally {
      setBusy(false);
    }
  };

  const total = stats.total ?? 0;

  return (
    <div className="rounded-3xl border border-[#C9CAAC] bg-white shadow-sm p-5 space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-2 text-[#2F4128]">
          <div className="w-9 h-9 rounded-2xl bg-gradient-to-br from-[#495A43] to-[#869B7E] flex items-center justify-center shadow-sm">
            <UploadCloud className="w-4 h-4 text-white" />
          </div>
          <div>
            <h3 className="text-sm font-semibold leading-tight">Unggah log keamanan</h3>
            <p className="text-[11px] text-black/60">
              {backend ? backend : "Vector DB"} · {total} entri
            </p>
          </div>
        </div>
      </div>

      {/* Textarea */}
      <textarea
        value={content}
        onChange={(e) => setContent(e.target.value)}
        rows={6}
        placeholder={`Tempel baris log (auth / syslog / web / IDS / firewall)…
Contoh: Oct 16 13:22 web01 sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2`}
        className={cn(
          "w-full resize-y rounded-2xl border border-[#C9CAAC] bg-[#F6F3EB]",
          "px-4 py-3 text-xs font-mono text-black/80 outline-none",
          "focus:border-[#495A43] placeholder:text-slate-500"
        )}
      />

      {/* Controls */}
      <div className="flex flex-wrap items-center gap-3">
        <label className="flex items-center gap-2 text-sm text-[#2F4128]">
          Tipe:
          <select
            value={logType}
            onChange={(e) => setLogType(e.target.value as "" | LogType)}
            className="bg-[#495A43]/15 border border-[#495A43]/40 text-[#2F4128] text-sm rounded-xl px-3 py-2 cursor-pointer focus:outline-none"
          >
            {TYPE_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </select>
        </label>

        <label className="flex items-center gap-2 text-sm text-[#2F4128] cursor-pointer">
          <span className="flex items-center gap-1.5 rounded-xl border border-[#495A43]/40 bg-[#495A43]/15 px-3 py-2 hover:bg-[#495A43]/25 transition-all">
            <FileText className="w-4 h-4" />
            Pilih file
          </span>
          <input
            ref={fileRef}
            type="file"
            accept=".log,.txt,text/plain"
            onChange={onFile}
            className="hidden"
          />
        </label>

        <button
          onClick={submit}
          disabled={busy || !content.trim()}
          className={cn(
            "ml-auto flex items-center gap-2 rounded-2xl px-4 py-2.5 text-sm font-medium transition-all",
            busy || !content.trim()
              ? "bg-[#495A43]/30 text-white/70 cursor-not-allowed"
              : "bg-[#495A43] hover:bg-[#2F4128] text-white shadow-sm cursor-pointer"
          )}
        >
          {busy ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin" />
              Mengindeks…
            </>
          ) : (
            <>
              <UploadCloud className="w-4 h-4" />
              Indeks log
            </>
          )}
        </button>
      </div>

      {/* Result */}
      {result && (
        <div
          className={cn(
            "flex items-center gap-2 rounded-2xl px-3 py-2 text-sm",
            result.ok
              ? "bg-[#495A43]/15 text-[#2F4128]"
              : "bg-red-900/10 text-red-800"
          )}
        >
          {result.ok ? (
            <CheckCircle2 className="w-4 h-4" />
          ) : (
            <AlertTriangle className="w-4 h-4" />
          )}
          {result.text}
        </div>
      )}

      {/* Per-type counts */}
      {types.length > 0 && (
        <div className="flex flex-wrap gap-2 pt-1">
          {types
            .filter((t) => t !== "unknown" || (stats["unknown"] ?? 0) > 0)
            .map((t) => (
              <span
                key={t}
                className={cn(
                  "rounded-full border border-[#C9CAAC] px-2.5 py-1 text-[11px] text-[#2F4128]",
                  (stats[t] ?? 0) > 0 ? "bg-[#E4E5CA]" : "bg-transparent opacity-50"
                )}
              >
                {getLogTypeLabel(t)}: {stats[t] ?? 0}
              </span>
            ))}
        </div>
      )}
    </div>
  );
}
