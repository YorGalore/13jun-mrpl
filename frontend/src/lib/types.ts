export type AnalysisMode =
  | "threat_intelligence"
  | "log_analysis"
  | "combined";

export type MessageRole = "user" | "assistant" | "system";
export type LLMModel = string;

// Selaras dengan backend generate_sparql(): regex | llm | fallback | fallback_keyword.
export type SparqlMethod = "regex" | "llm" | "fallback" | "fallback_keyword";

// Tipe log untuk Issue #2 (vector DB). Selaras dengan LOG_TYPES di backend/sources/logs.py.
export type LogType =
  | "auth"
  | "syslog"
  | "web_access"
  | "ids_alert"
  | "firewall"
  | "unknown";

export interface RDFTriple {
  subject: string;
  predicate: string;
  object: string;
  source?: string;
}

export interface GraphNode {
  id: string;
  label: string;
  type: string; // e.g., "Malware", "CVE", "ThreatActor", "Weakness", "AttackPattern"
  color?: string;
}

export interface GraphLink {
  source: string;
  target: string;
  label: string;
}

export interface GraphData {
  nodes: GraphNode[];
  links: GraphLink[];
}

export interface Message {
  id: string;
  role: MessageRole;
  content: string;
  timestamp: Date;
  mode?: AnalysisMode;
  triples?: RDFTriple[];      // Retrieved KG triples
  graphData?: GraphData;       // For graph viewer
  llmUsed?: string;            // Which LLM answered
  sources?: string[];          // Source URLs/references
  method?: SparqlMethod;
  sparql?: string;
}

export interface ChatSession {
  id: string;
  title: string;
  mode: AnalysisMode;
  messages: Message[];
  createdAt: Date;
  updatedAt: Date;
}

export interface ChatRequest {
  message: string;
  mode: AnalysisMode;
  sessionId: string;
  history: { role: MessageRole; content: string }[];
  model?: LLMModel;
}

export interface ChatResponse {
  message: string;
  triples?: RDFTriple[];
  graphData?: GraphData;
  llmUsed?: string;
  sources?: string[];
  method?: SparqlMethod;
  sparql?: string;
}

// ---- Issue #2: upload & statistik log ----
export interface LogUploadRequest {
  content: string;
  source?: string;
  logType?: LogType | null;
}

export interface LogUploadResponse {
  ok: boolean;
  inserted: number;
  backend: string;
  stats: Record<string, number>;
}

export interface LogStatsResponse {
  backend: string;
  types: LogType[];
  stats: Record<string, number>;
}
