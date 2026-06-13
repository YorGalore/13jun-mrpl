"use client";

import { useChatStore } from "@/lib/store";
import { TriplesList } from "./TriplesList";

import {
  triplesToGraphData,
  getNodeColor,
} from "@/lib/utils";

import {
  X,
  Network,
  Database,
  Link2,
} from "lucide-react";

export function GraphViewer() {
  const {
    isGraphViewerOpen,
    selectedMessage,
    toggleGraphViewer,
  } = useChatStore();

  if (
    !isGraphViewerOpen ||
    !selectedMessage
  )
    return null;

  const triples =
    selectedMessage.triples ?? [];

  const graphData =
    selectedMessage.graphData ??
    triplesToGraphData(triples);

  return (
    <div className="flex flex-col overflow-y-auto h-full bg-[#F6F3EB] border-l border-[#C9CAAC]">
      {/* Header */}

      <div className="px-5 py-3.5 border-b border-[#C9CAAC] bg-[#E4E5CA]">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-2xl bg-gradient-to-r from-[#2F4128] to-[#7A9370] flex items-center justify-center">
              <Network className="w-5 h-5 text-white" />
            </div>

            <div>
              <h3 className="text-[#1F2B1A] font-semibold">
                Analysis Dashboard
              </h3>

              <p className="text-xs text-black/60">
                Explainability View
              </p>
            </div>
          </div>

          <button
            onClick={() =>
              toggleGraphViewer()
            }
            className="w-9 h-9 rounded-xl bg-[#C9CAAC] hover:bg-red-900/50 cursor-pointer flex items-center justify-center transition-all"
          >
            <X className="w-4 h-4 text-black/60" />
          </button>
        </div>
      </div>

      {/* Stats */}

      <div className="grid grid-cols-2 gap-3 p-4">
        <div className="bg-[#495A43] rounded-2xl p-4">
          <div className="flex items-center gap-2 text-white">
            <Database className="w-4 h-4" />

            <span className="text-xs text-white">
              Nodes
            </span>
          </div>

          <p className="mt-2 text-2xl font-bold text-white">
            {
              graphData.nodes.length
            }
          </p>
        </div>

        <div className="bg-[#495A43] rounded-2xl p-4">
          <div className="flex items-center gap-2 text-white">
            <Link2 className="w-4 h-4" />

            <span className="text-xs text-white">
              Relations
            </span>
          </div>

          <p className="mt-2 text-2xl font-bold text-white">
            {
              graphData.links.length
            }
          </p>
        </div>
      </div>

      {/* Graph */}

      <div className="px-4">
        <div className="bg-[#495A43]/50 rounded-3xl p-4 h-[320px]">
          <SimpleGraphViz
            nodes={
              graphData.nodes
            }
            links={
              graphData.links
            }
          />
        </div>
      </div>

      {/* Entity Types */}

      <div className="px-4 pt-4">
        <h4 className="text-xs uppercase tracking-[0.2em] text-black/60 mb-3">
          Entity Types
        </h4>

        <div className="flex flex-wrap gap-2">
          {[
            "CVE",
            "Weakness",
            "CAPEC",
            "CVSS",
            "ThreatActor",
            "Malware",
          ].map((type) => (
            <div
              key={type}
              className="flex items-center gap-2 bg-[#495A43] px-3 py-2 rounded-xl"
            >
              <div
                className="w-2 h-2 rounded-full"
                style={{
                  backgroundColor:
                    getNodeColor(
                      type
                    ),
                }}
              />

              <span className="text-xs text-white">
                {type}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Triples */}

      <div className="flex-1 mt-4">
        <div className="px-4 pb-2">
          <h4 className="text-xs uppercase tracking-[0.2em] text-black/60">
            Retrieved Triples
          </h4>
        </div>

        <TriplesList
          triples={triples}
        />
      </div>
    </div>
  );
}

function SimpleGraphViz({
  nodes,
  links,
}: {
  nodes: {
    id: string;
    label: string;
    type: string;
    color?: string;
  }[];

  links: {
    source: string;
    target: string;
    label: string;
  }[];
}) {
  if (!nodes.length) {
    return (
      <div className="w-full h-full flex items-center justify-center text-black/60">
        No graph available
      </div>
    );
  }

  const W = 320;
  const H = 280;

  const cx = W / 2;
  const cy = H / 2;

  const radius =
    Math.min(W, H) * 0.32;

  const positioned =
    nodes.map((node, i) => {
      const angle =
        (i / nodes.length) *
        Math.PI *
        2;

      return {
        ...node,
        x:
          cx +
          radius *
            Math.cos(angle),
        y:
          cy +
          radius *
            Math.sin(angle),
      };
    });

  const map = new Map(
    positioned.map((n) => [
      n.id,
      n,
    ])
  );

  return (
    <svg
      viewBox={`0 0 ${W} ${H}`}
      className="w-full h-full"
    >
      {links.map(
        (link, index) => {
          const source =
            map.get(
              link.source
            );

          const target =
            map.get(
              link.target
            );

          if (
            !source ||
            !target
          )
            return null;

          return (
            <g key={index}>
              <line
                x1={source.x}
                y1={source.y}
                x2={target.x}
                y2={target.y}
                stroke="rgba(255,255,255,0.12)"
              />

              <text
                x={
                  (source.x +
                    target.x) /
                  2
                }
                y={
                  (source.y +
                    target.y) /
                  2
                }
                fill="rgba(255,255,255,0.35)"
                fontSize="7"
                textAnchor="middle"
              >
                {link.label.slice(
                  0,
                  12
                )}
              </text>
            </g>
          );
        }
      )}

      {positioned.map(
        (node) => (
          <g key={node.id}>
            <circle
              cx={node.x}
              cy={node.y}
              r="15"
              fill={
                node.color ??
                "#6B7280"
              }
              fillOpacity="0.3"
              stroke={
                node.color ??
                "#6B7280"
              }
            />

            <text
              x={node.x}
              y={node.y + 4}
              fill="white"
              fontSize="7"
              textAnchor="middle"
            >
              {node.label.slice(
                0,
                10
              )}
            </text>
          </g>
        )
      )}
    </svg>
  );
}