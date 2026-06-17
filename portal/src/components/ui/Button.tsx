import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const buttonVariants = cva(
  "inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-lg text-sm font-medium transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 [&_svg]:pointer-events-none [&_svg]:size-4 [&_svg]:shrink-0",
  {
    variants: {
      variant: {
        primary:     "bg-brand-600 text-white shadow hover:bg-brand-700 active:scale-[0.98]",
        secondary:   "bg-dark-700 text-slate-200 border border-white/10 hover:bg-dark-600",
        outline:     "border border-white/10 bg-transparent hover:bg-white/5 text-slate-200",
        ghost:       "hover:bg-white/5 text-slate-300 hover:text-white",
        destructive: "bg-red-600 text-white shadow-sm hover:bg-red-700",
        link:        "text-brand-400 underline-offset-4 hover:underline",
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
