import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "./lib/utils";

const badgeVariants = cva(
  "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-semibold transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2",
  {
    variants: {
      variant: {
        default:  "border-transparent bg-primary text-primary-foreground",
        success:  "border-green-500/20  bg-green-500/10  text-green-400",
        warning:  "border-amber-500/20  bg-amber-500/10  text-amber-400",
        error:    "border-red-500/20    bg-red-500/10    text-red-400",
        info:     "border-blue-500/20   bg-blue-500/10   text-blue-400",
        neutral:  "border-border        bg-muted         text-muted-foreground",
        violet:   "border-violet-500/20 bg-violet-500/10 text-violet-400",
        outline:  "border-border        bg-transparent   text-foreground",
      },
    },
    defaultVariants: { variant: "default" },
  },
);

export interface BadgeProps
  extends React.HTMLAttributes<HTMLSpanElement>,
    VariantProps<typeof badgeVariants> {
  dot?: boolean;
}

const DOT_COLOR: Record<string, string> = {
  default: "bg-primary-foreground",
  success: "bg-green-400",
  warning: "bg-amber-400",
  error:   "bg-red-400",
  info:    "bg-blue-400",
  neutral: "bg-muted-foreground",
  violet:  "bg-violet-400",
  outline: "bg-foreground",
};

function Badge({ className, variant = "default", dot, children, ...props }: BadgeProps) {
  return (
    <span className={cn(badgeVariants({ variant }), className)} {...props}>
      {dot && (
        <span className={cn("h-1.5 w-1.5 rounded-full shrink-0", DOT_COLOR[variant ?? "default"])} />
      )}
      {children}
    </span>
  );
}

export { Badge, badgeVariants };
