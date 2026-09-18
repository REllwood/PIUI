import type { ReactNode } from 'react';

export function StatusPill({
  tone = 'neutral',
  children,
}: Readonly<{
  tone?: 'neutral' | 'success' | 'work' | 'warning' | 'danger';
  children: ReactNode;
}>) {
  return (
    <span className="status-pill" data-tone={tone}>
      {children}
    </span>
  );
}
