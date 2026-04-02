import Highlight from "@tiptap/extension-highlight";
import { normalizeColor } from "./utils/normalize";

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
        parseHTML: (element) => {
          const raw =
            element.getAttribute("data-color") ||
            element.style.backgroundColor;
          if (!raw) return null;
          return normalizeColor(raw);
        },
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
