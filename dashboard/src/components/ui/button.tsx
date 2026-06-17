import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const buttonVariants = cva(
  "inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-lg text-sm font-medium transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent-blue focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 [&_svg]:pointer-events-none [&_svg]:size-4 [&_svg]:shrink-0",
  {
    variants: {
      variant: {
        primary:     "bg-accent-blue text-white shadow hover:bg-blue-600 active:scale-[0.98]",
        secondary:   "bg-surface-3 text-gray-200 border border-border hover:bg-surface-4",
        outline:     "border border-border bg-transparent hover:bg-surface-3 text-gray-200",
        ghost:       "hover:bg-surface-3 text-gray-400 hover:text-white",
        destructive: "bg-accent-red text-white shadow-sm hover:bg-red-600",
        link:        "text-accent-blue underline-offset-4 hover:underline",
      },
      size: {
        sm:       "h-8 rounded-md px-3 text-xs",
        md:       "h-9 px-4 py-2",
        lg:       "h-11 rounded-lg px-8 text-base",
        icon:     "h-9 w-9",
        "icon-sm":"h-8 w-8",
      },
    },
    defaultVariants: { variant: "primary", size: "md" },
  },
);

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {}

const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, ...props }, ref) => (
    <button ref={ref} className={cn(buttonVariants({ variant, size, className }))} {...props} />
  ),
);
Button.displayName = "Button";

export { Button, buttonVariants };
