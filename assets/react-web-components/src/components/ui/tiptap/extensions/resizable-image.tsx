import React, { useRef, useState, useCallback } from "react";
import Image from "@tiptap/extension-image";
import { NodeViewWrapper, ReactNodeViewRenderer } from "@tiptap/react";
import type { NodeViewProps } from "@tiptap/react";

const ResizableImageComponent = ({
  node,
  updateAttributes,
  selected,
}: NodeViewProps) => {
  const imgRef = useRef<HTMLImageElement>(null);
  const [resizing, setResizing] = useState(false);

  const handleMouseDown = useCallback(
    (e: React.MouseEvent) => {
      e.preventDefault();
      e.stopPropagation();
      const startX = e.clientX;
      const startWidth = imgRef.current?.offsetWidth || 200;
      setResizing(true);
      const onMouseMove = (ev: MouseEvent) => {
        updateAttributes({ width: Math.max(50, startWidth + ev.clientX - startX) });
      };
      const onMouseUp = () => {
        setResizing(false);
        document.removeEventListener("mousemove", onMouseMove);
        document.removeEventListener("mouseup", onMouseUp);
      };
      document.addEventListener("mousemove", onMouseMove);
      document.addEventListener("mouseup", onMouseUp);
    },
    [updateAttributes]
  );

  const width = node.attrs.width as number | null;
  return (
    <NodeViewWrapper
      as="span"
      className="tiptap-resizable-image-wrapper"
      style={{ display: "inline-block" }}
    >
      <span
        className={`tiptap-resizable-image ${selected ? "selected" : ""} ${resizing ? "resizing" : ""}`}
        style={{
          display: "inline-block",
          position: "relative",
          width: width ? `${width}px` : undefined,
        }}
      >
        <img
          ref={imgRef}
          src={node.attrs.src as string}
          alt={(node.attrs.alt as string) || ""}
          title={(node.attrs.title as string) || undefined}
          style={{ width: "100%", height: "auto", display: "block" }}
          draggable={false}
        />
        {selected && (
          <span
            className="tiptap-resize-handle tiptap-resize-handle-br"
            onMouseDown={handleMouseDown}
          />
        )}
      </span>
    </NodeViewWrapper>
  );
};

export const ResizableImage = Image.extend({
  addAttributes() {
    return {
      ...this.parent?.(),
      width: {
        default: null,
        parseHTML: (element) => {
          const w = element.getAttribute("width") || element.style.width;
          return w ? parseInt(String(w), 10) || null : null;
        },
        renderHTML: (attributes) => {
          if (!attributes.width) return {};
          return {
            width: attributes.width,
            style: `width: ${attributes.width}px`,
          };
        },
      },
    };
  },
  addNodeView() {
    return ReactNodeViewRenderer(ResizableImageComponent);
  },
});
