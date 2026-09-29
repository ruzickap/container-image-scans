"use client";

import { useRef, useLayoutEffect, useState } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import type { Cve } from "@/lib/supabase";

interface Props {
  cve: Cve;
}

/* Height reserved for the sticky controls bar plus a small gap */
const STICKY_OFFSET = 80;
const VIEWPORT_PAD = 8;

export function CveTooltip({ cve }: Props) {
  const content = cve.help_markdown || cve.description || "No details available.";
  const ref = useRef<HTMLDivElement>(null);
  const [style, setStyle] = useState<React.CSSProperties>({});

  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    const parent = el.parentElement;
    if (!parent) return;

    const parentRect = parent.getBoundingClientRect();
    const tooltipHeight = el.scrollHeight;
    const vh = window.innerHeight;

    let top: number;
    const spaceAbove = parentRect.top - STICKY_OFFSET;
    const spaceBelow = vh - parentRect.bottom;

    if (spaceAbove >= tooltipHeight + VIEWPORT_PAD) {
      top = parentRect.top - tooltipHeight;
    } else if (spaceBelow >= tooltipHeight + VIEWPORT_PAD) {
      top = parentRect.bottom;
    } else {
      top = Math.min(
        Math.max(STICKY_OFFSET + VIEWPORT_PAD, parentRect.top - tooltipHeight / 2),
        vh - tooltipHeight - VIEWPORT_PAD,
      );
    }

    setStyle({
      position: "fixed",
      top,
      left: parentRect.left,
    });
  }, []);

  return (
    <div ref={ref} className="tooltip" role="tooltip" style={style}>
      <h3 style={{ marginTop: 0 }}>{cve.cve_id}</h3>
      {cve.description && cve.help_markdown && (
        <p style={{ color: "var(--text-muted)", marginBottom: "0.75rem" }}>
          {cve.description}
        </p>
      )}
      <ReactMarkdown remarkPlugins={[remarkGfm]}>{content}</ReactMarkdown>
      {cve.package_name && (
        <p style={{ marginTop: "0.5rem", color: "var(--text-muted)" }}>
          <strong>Package:</strong> {cve.package_name}
          {cve.installed_version && (
            <> (installed: {cve.installed_version})</>
          )}
          {cve.fixed_version && <> &rarr; fix: {cve.fixed_version}</>}
        </p>
      )}
    </div>
  );
}
