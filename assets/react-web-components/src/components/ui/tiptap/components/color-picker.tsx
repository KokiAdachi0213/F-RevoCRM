import React from "react";
import { ChevronDown, RemoveFormatting } from "lucide-react";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuPortal,
  DropdownMenuTrigger,
} from "../../dropdown-menu";

interface ColorPickerProps {
  icon: React.ReactNode;
  title: string;
  currentColor: string;
  palette: string[];
  columns?: number;
  onSelect: (color: string) => void;
  onClear: () => void;
  portalContainer?: HTMLElement | null;
}

export const ColorPicker = ({
  icon,
  title,
  currentColor,
  palette,
  columns = 6,
  onSelect,
  onClear,
  portalContainer,
}: ColorPickerProps) => (
  <DropdownMenu modal={false}>
    <DropdownMenuTrigger asChild>
      <button
        type="button"
        className="tiptap-color-btn"
        title={title}
        onMouseDown={(e) => e.preventDefault()}
      >
        <span style={{ position: "relative", display: "inline-flex" }}>
          {icon}
          {currentColor && (
            <span
              className="tiptap-color-indicator"
              style={{ backgroundColor: currentColor }}
            />
          )}
        </span>
        <ChevronDown size={8} />
      </button>
    </DropdownMenuTrigger>
    <DropdownMenuPortal container={portalContainer}>
    <DropdownMenuContent
      style={{ padding: "8px", width: "auto" }}
      onMouseDown={(e) => e.preventDefault()}
    >
      <div
        className="tiptap-color-grid"
        style={{ gridTemplateColumns: `repeat(${columns}, 1fr)` }}
      >
        {palette.map((color) => (
          <button
            key={color}
            type="button"
            className={`tiptap-color-swatch ${currentColor === color ? "active" : ""}`}
            style={{ backgroundColor: color }}
            title={color}
            onMouseDown={(e) => {
              e.preventDefault();
              onSelect(color);
            }}
          />
        ))}
      </div>
      <button
        type="button"
        className="tiptap-color-clear"
        onMouseDown={(e) => {
          e.preventDefault();
          onClear();
        }}
      >
        <RemoveFormatting size={12} />
        <span>クリア</span>
      </button>
    </DropdownMenuContent>
    </DropdownMenuPortal>
  </DropdownMenu>
);
