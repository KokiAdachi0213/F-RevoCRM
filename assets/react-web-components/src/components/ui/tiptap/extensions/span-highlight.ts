import Highlight from "@tiptap/extension-highlight";

/**
 * Highlight拡張をカスタマイズ: <mark> → <span> に変更
 * HTMLPurifierが<mark>タグを除去するため
 */
export const SpanHighlight = Highlight.extend({
  renderHTML({ HTMLAttributes }) {
    return ["span", HTMLAttributes, 0];
  },
  parseHTML() {
    return [
      { tag: "mark" },
      {
        tag: "span",
        getAttrs: (element) => {
          const bg = (element as HTMLElement).style.backgroundColor;
          if (!bg) return false;
          return { color: bg };
        },
      },
    ];
  },
  addAttributes() {
    return {
      color: {
        default: null,
        parseHTML: (element) =>
          element.getAttribute("data-color") ||
          element.style.backgroundColor ||
          null,
        renderHTML: (attributes) => {
          if (!attributes.color) return {};
          return {
            "data-color": attributes.color,
            style: `background-color: ${attributes.color}`,
          };
        },
      },
    };
  },
});
