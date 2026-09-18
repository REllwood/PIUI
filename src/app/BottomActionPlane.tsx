import type { ReactNode } from 'react';

export function BottomActionPlane({ children }: Readonly<{ children: ReactNode }>) {
  return <div className="bottom-action-plane">{children}</div>;
}
