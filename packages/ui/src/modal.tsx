"use client";
import * as React from "react";
import { X } from "lucide-react";
import { cn } from "./lib/utils";
import { Button } from "./button";

interface ModalProps {
  open:       boolean;
  onClose:    () => void;
  title?:     string;
  description?: string;
  children:   React.ReactNode;
  className?: string;
  size?:      "sm" | "md" | "lg" | "xl" | "full";
}

const SIZE_MAP = {
  sm:   "max-w-sm",
  md:   "max-w-md",
  lg:   "max-w-lg",
  xl:   "max-w-2xl",
  full: "max-w-full mx-4",
};

function Modal({ open, onClose, title, description, children, className, size = "md" }: ModalProps) {
  React.useEffect(() => {
    if (!open) return;
    const handleKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    document.addEventListener("keydown", handleKey);
    return () => document.removeEventListener("keydown", handleKey);
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby={title ? "modal-title" : undefined}
      className="fixed inset-0 z-50 flex items-center justify-center"
    >
      {/* Overlay */}
      <div
        className="absolute inset-0 bg-black/60 backdrop-blur-sm"
        onClick={onClose}
        aria-hidden="true"
      />
      {/* Panel */}
      <div
        className={cn(
          "relative z-10 w-full rounded-xl border border-border bg-card text-card-foreground shadow-xl",
          SIZE_MAP[size],
          className,
        )}
      >
        {/* Header */}
        {(title || description) && (
          <div className="flex items-start justify-between gap-4 p-6 border-b border-border">
            <div>
              {title && (
                <h2 id="modal-title" className="text-lg font-semibold leading-none">
                  {title}
                </h2>
              )}
              {description && (
                <p className="mt-1 text-sm text-muted-foreground">{description}</p>
              )}
            </div>
            <Button
              variant="ghost"
              size="icon-sm"
              onClick={onClose}
              aria-label="Close"
              className="shrink-0"
            >
              <X />
            </Button>
          </div>
        )}
        {/* Body */}
        <div className="p-6">{children}</div>
      </div>
    </div>
  );
}

export { Modal };
