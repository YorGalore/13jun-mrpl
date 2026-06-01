"use client";

import { RDFTriple } from "@/lib/types";

interface Props {
  triples: RDFTriple[];
}

const shorten = (value: string) => {
  const parts = value.split(/[#/]/);

  return (
    parts[parts.length - 1] || value
  );
};

export function TriplesList({
  triples,
}: Props) {
  if (!triples.length) {
    return (
      <div className="p-6 text-center text-sm text-black/60">
        No triples available
      </div>
    );
  }

  return (
    <div className="overflow-auto max-h-[260px] px-4 pb-4">
      <div className="space-y-2">
        {triples.map(
          (triple, index) => (
            <div
              key={index}
              className="bg-[#495A43] rounded-2xl p-3"
            >
              <div className="text-xs text-violet-400 font-medium">
                {shorten(
                  triple.subject
                )}
              </div>

              <div className="text-[11px] text-black/60 my-1">
                {shorten(
                  triple.predicate
                )}
              </div>

              <div className="text-xs text-sky-400 font-medium">
                {shorten(
                  triple.object
                )}
              </div>
            </div>
          )
        )}
      </div>
    </div>
  );
}