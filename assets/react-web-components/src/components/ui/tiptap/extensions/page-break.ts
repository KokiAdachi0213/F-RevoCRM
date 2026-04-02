import { Node } from "@tiptap/core";

const PAGE_BREAK_VALUES = ["always", "avoid", "auto", "left", "right"];

function normalizePageBreak(raw: string): string | null {
  if (!raw) return null;
  const normalized = raw.trim().toLowerCase();
  return PAGE_BREAK_VALUES.includes(normalized) ? normalized : null;
}

export const PageBreak = Node.create({
  name: "pageBreak",
  group: "block",
  atom: true,

  addAttributes() {
    return {
      pageBreakAfter: {
        default: null,
        parseHTML: (el: HTMLElement) =>
          normalizePageBreak(el.style.pageBreakAfter || ""),
      },
      pageBreakBefore: {
        default: null,
        parseHTML: (el: HTMLElement) =>
          normalizePageBreak(el.style.pageBreakBefore || ""),
      },
    };
  },

  parseHTML() {
    return [
      {
        tag: "div",
        priority: 60,
        getAttrs: (el) => {
          const s = (el as HTMLElement).style;
          if (!s.pageBreakAfter && !s.pageBreakBefore) return false;
          return {};
        },
      },
      {
        tag: "p",
        priority: 60,
        getAttrs: (el) => {
          const s = (el as HTMLElement).style;
          if (!s.pageBreakAfter && !s.pageBreakBefore) return false;
          return {};
        },
      },
    ];
  },

  renderHTML({ node }) {
    const parts: string[] = [];
    if (node.attrs.pageBreakAfter) {
      parts.push(`page-break-after: ${node.attrs.pageBreakAfter}`);
    }
    if (node.attrs.pageBreakBefore) {
      parts.push(`page-break-before: ${node.attrs.pageBreakBefore}`);
    }
    return ["div", { style: parts.join("; ") }];
  },
});
