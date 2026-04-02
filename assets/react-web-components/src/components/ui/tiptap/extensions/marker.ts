import { Mark } from "@tiptap/core";
import { normalizeColor } from "./utils/normalize";

// CKEditorのマーカークラス名 → 背景色マッピング
const MARKER_CLASS_COLORS: Record<string, string> = {
  "marker": "#ffff00",
  "marker-yellow": "#ffff00",
  "marker-green": "#00ff00",
  "marker-pink": "#ff00ff",
  "marker-blue": "#0000ff",
};

export const Marker = Mark.create({
  name: "marker",

  addAttributes() {
    return {
      backgroundColor: {
        default: null,
        parseHTML: (element) => {
          // 1. class属性からマーカー色を取得
          const classList = element.className?.split(/\s+/) || [];
          for (const cls of classList) {
            const color = MARKER_CLASS_COLORS[cls];
            if (color) return color;
          }
          // 2. style属性のbackground-colorからも取得（フォールバック）
          const bg = element.style.backgroundColor;
          if (bg) return normalizeColor(bg);
          return null;
        },
        renderHTML: (attributes) => {
          if (!attributes.backgroundColor) return {};
          return { style: `background-color: ${attributes.backgroundColor}` };
        },
      },
    };
  },

  parseHTML() {
    return [
      {
        tag: "span",
        getAttrs: (el) => {
          const element = el as HTMLElement;
          const classList = element.className?.split(/\s+/) || [];
          // markerクラスを持つspanのみマッチ
          const hasMarkerClass = classList.some((cls) => cls in MARKER_CLASS_COLORS);
          if (!hasMarkerClass) return false;
          return {};
        },
      },
    ];
  },

  renderHTML({ HTMLAttributes }) {
    // class属性は出力しない（CSSクラス悪用防止）
    const { class: _, ...rest } = HTMLAttributes;
    return ["span", rest, 0];
  },
});
