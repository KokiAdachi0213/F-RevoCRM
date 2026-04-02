import { Mark } from "@tiptap/core";

export const Anchor = Mark.create({
  name: "anchor",

  addAttributes() {
    return {
      anchor: {
        default: null,
        parseHTML: (element) => {
          // id または name 属性からアンカー名を取得
          const value = element.getAttribute("id") || element.getAttribute("name");
          if (!value) return null;
          // アンカー名を正規化: 英数字、ハイフン、アンダースコアのみ許可
          const normalized = value.trim();
          if (!/^[a-zA-Z0-9\-_]+$/.test(normalized)) return null;
          return normalized;
        },
        renderHTML: (attributes) => {
          if (!attributes.anchor) return {};
          // data-anchor属性で出力（id/nameは使わない → DOMクロバリング防止）
          return { "data-anchor": attributes.anchor };
        },
      },
    };
  },

  parseHTML() {
    return [
      {
        tag: "a",
        getAttrs: (el) => {
          const element = el as HTMLElement;
          // hrefがあるリンクはLink拡張が処理するのでスキップ
          if (element.getAttribute("href")) return false;
          // id または name を持つアンカーのみマッチ
          if (!element.getAttribute("id") && !element.getAttribute("name")) return false;
          return {};
        },
      },
    ];
  },

  renderHTML({ HTMLAttributes }) {
    return ["span", HTMLAttributes, 0];
  },
});
