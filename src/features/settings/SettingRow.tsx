import type { ReactNode } from 'react';
import { StatusPill } from '../../components/primitives/StatusPill';

export function SettingRow({
  label,
  description,
  scope = 'Global',
  origin,
  children,
}: Readonly<{
  label: string;
  description: string;
  scope?: 'Global' | 'Project';
  origin?: string;
  children: ReactNode;
}>) {
  return (
    <div className="setting-row">
      <div className="setting-row__copy">
        <div>
          <strong>{label}</strong>
          <StatusPill>{scope}</StatusPill>
        </div>
        <p>{description}</p>
        {origin ? <small>Inherited from {origin}</small> : null}
      </div>
      <div className="setting-row__control">{children}</div>
    </div>
  );
}
