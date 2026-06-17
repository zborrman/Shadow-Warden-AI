/**
 * portal/src/components/ui/index.ts
 * Re-exports all UI primitives for a single import point.
 *
 * Usage:
 *   import { Badge, Metric, StatusDot } from '@/components/ui'
 */
export { Badge }     from './Badge'
export { Metric }    from './Metric'
export { StatusDot } from './StatusDot'

// Design system primitives (DS-01)
export { Card, CardHeader, CardTitle, CardDescription, CardContent, CardFooter } from './Card'
export { Button, buttonVariants, type ButtonProps } from './Button'
export { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from './Table'
export { Tabs, TabsList, TabsTrigger, TabsContent } from './Tabs'
export { ThemeProvider, useTheme } from './ThemeProvider'
