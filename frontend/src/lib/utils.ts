import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";
import { AnalysisMode, GraphData, RDFTriple, LogType } from "./types";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function generateId(): string {
  return Math.random().toString(36).substring(2) + Date.now().toString(36);
}

export function getModeLabel(mode: AnalysisMode): string {
  const labels: Record<AnalysisMode, string> = {
    threat_intelligence: "Threat Intelligence",
    log_analysis: "Security Log Analysis",
    combined: "Threat Correlation",
  };
  return labels[mode];
}

export function getModeDescription(mode: AnalysisMode): string {
  const descriptions: Record<AnalysisMode, string> = {
    threat_intelligence:
      "Analyze malware, CVEs, threat actors using SEPSES CSKG",
    log_analysis: "Parse and analyze security logs for suspicious activity",
    combined:
      "Combine security logs with global threat intelligence knowledge",
  };
  return descriptions[mode];
}

export function getModeColor(mode: AnalysisMode): string {
  const colors: Record<AnalysisMode, string> = {
    threat_intelligence: "text-red-400",
    log_analysis: "text-yellow-400",
    combined: "text-cyan-400",
  };
  return colors[mode];
}

// Label ramah-pengguna untuk tipe log (Issue #2).
export function getLogTypeLabel(t: LogType | string): string {
  const labels: Record<string, string> = {
    auth: "Auth / SSH",
    syslog: "Syslog",
    web_access: "Web access",
    ids_alert: "IDS alert",
    firewall: "Firewall",
    unknown: "Lainnya",
  };
  return labels[t] ?? t;
}

export function getNodeColor(type: string): string {
  const palette: Record<string, string> = {
    Malware: "#ef4444",
    CVE: "#f97316",
    ThreatActor: "#8b5cf6",
    AttackPattern: "#ec4899",
    CAPEC: "#ec4899",
    Weakness: "#a855f7",
    CWE: "#a855f7",
    Vulnerability: "#f59e0b",
    CVSS: "#22c55e",
    Tool: "#3b82f6",
    Campaign: "#10b981",
    Identity: "#6366f1",
    default: "#6b7280",
  };
  return palette[type] ?? palette.default;
}

export function triplesToGraphData(triples: RDFTriple[]): GraphData {
  const nodeMap = new Map<string, { id: string; label: string; type: string }>();
  const links: GraphData["links"] = [];

  const getLabel = (uri: string) => {
    const parts = uri.split(/[#/]/);
    return parts[parts.length - 1] || uri;
  };

  const inferType = (uri: string): string => {
    const lower = uri.toLowerCase();
    // CVE dulu sebelum 'vuln' generik agar "CVE-..." tidak salah jadi Vulnerability.
    if (/\bcve-\d/.test(lower) || lower.includes("/cve")) return "CVE";
    if (lower.includes("malware")) return "Malware";
    if (lower.includes("threat") || lower.includes("actor")) return "ThreatActor";
    if (/\bcapec-\d/.test(lower) || lower.includes("capec")) return "CAPEC";
    if (/\bcwe-\d/.test(lower) || lower.includes("cwe") || lower.includes("weakness"))
      return "Weakness";
    if (lower.includes("cvss") || lower.includes("score")) return "CVSS";
    if (lower.includes("attack")) return "AttackPattern";
    if (lower.includes("vuln")) return "Vulnerability";
    if (lower.includes("tool")) return "Tool";
    if (lower.includes("campaign")) return "Campaign";
    return "default";
  };

  triples.forEach((triple) => {
    if (!nodeMap.has(triple.subject)) {
      nodeMap.set(triple.subject, {
        id: triple.subject,
        label: getLabel(triple.subject),
        type: inferType(triple.subject),
      });
    }
    if (!nodeMap.has(triple.object)) {
      nodeMap.set(triple.object, {
        id: triple.object,
        label: getLabel(triple.object),
        type: inferType(triple.object),
      });
    }
    links.push({
      source: triple.subject,
      target: triple.object,
      label: getLabel(triple.predicate),
    });
  });

  return {
    nodes: Array.from(nodeMap.values()).map((n) => ({
      ...n,
      color: getNodeColor(n.type),
    })),
    links,
  };
}

export function formatTimestamp(date: Date): string {
  return new Intl.DateTimeFormat("id-ID", {
    hour: "2-digit",
    minute: "2-digit",
  }).format(new Date(date));
}

export function truncateText(text: string, maxLength = 40): string {
  return text.length > maxLength ? text.slice(0, maxLength) + "..." : text;
}