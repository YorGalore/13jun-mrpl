export type AnalysisMode = 
  | "threat_intelligence" 
  | "log_analysis" 
  | "combined";

export type MessageRole = "user" | "assistant" | "system";
export type LLMModel = "gpt-4o-mini" | "deepseek-chat";

export interface RDFTriple {
  subject: string;
  predicate: string;
  object: string;
  source?: string;
}

export interface GraphNode {
  id: string;
  label: string;
  type: string; // e.g., "Malware", "CVE", "ThreatActor"
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
  method?: "regex" | "llm" | "fallback";
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
  method?: "regex" | "llm" | "fallback";
  sparql?: string;
}