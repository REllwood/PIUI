import type { SVGProps } from 'react';

export type IconName =
  | 'conversation'
  | 'sessions'
  | 'activity'
  | 'settings'
  | 'search'
  | 'plus'
  | 'send'
  | 'stop'
  | 'paperclip'
  | 'chevron-right'
  | 'chevron-down'
  | 'more'
  | 'close'
  | 'menu'
  | 'check'
  | 'warning'
  | 'file'
  | 'command'
  | 'branch'
  | 'download'
  | 'copy'
  | 'refresh'
  | 'shield'
  | 'folder'
  | 'external'
  | 'moon'
  | 'sun';

export function Icon({ name, ...props }: Readonly<{ name: IconName } & SVGProps<SVGSVGElement>>) {
  const shared = {
    width: 20,
    height: 20,
    viewBox: '0 0 20 20',
    fill: 'none',
    stroke: 'currentColor',
    strokeWidth: 1.75,
    strokeLinecap: 'round' as const,
    strokeLinejoin: 'round' as const,
    'aria-hidden': true,
    focusable: false,
  };
  const path = {
    conversation: (
      <>
        <path d="M3 4.5h14v9H8l-4.5 3v-3H3z" />
        <path d="M6.5 8h7M6.5 10.5h4.5" />
      </>
    ),
    sessions: (
      <>
        <rect x="4" y="3" width="12" height="14" rx="2" />
        <path d="M7 7h6M7 10h6M7 13h4" />
      </>
    ),
    activity: (
      <>
        <path d="M3 10h3l1.5-4 3 8 1.8-4H17" />
        <circle cx="10" cy="10" r="8" />
      </>
    ),
    settings: (
      <>
        <circle cx="10" cy="10" r="2.5" />
        <path d="M10 2.5v2M10 15.5v2M17.5 10h-2M4.5 10h-2M15.3 4.7l-1.4 1.4M6.1 13.9l-1.4 1.4M15.3 15.3l-1.4-1.4M6.1 6.1 4.7 4.7" />
      </>
    ),
    search: (
      <>
        <circle cx="8.5" cy="8.5" r="5.5" />
        <path d="m12.5 12.5 4 4" />
      </>
    ),
    plus: <path d="M10 4v12M4 10h12" />,
    send: (
      <>
        <path d="m3 4 14 6-14 6 2-6z" />
        <path d="M5 10h7" />
      </>
    ),
    stop: <rect x="5" y="5" width="10" height="10" rx="1.5" />,
    paperclip: (
      <path d="m7 10 4.6-4.6a3 3 0 1 1 4.2 4.2l-6.3 6.3a4 4 0 0 1-5.7-5.7l6-6a2 2 0 0 1 2.9 2.8l-6 6" />
    ),
    'chevron-right': <path d="m7 4 6 6-6 6" />,
    'chevron-down': <path d="m4 7 6 6 6-6" />,
    more: (
      <>
        <circle cx="4" cy="10" r="1" fill="currentColor" stroke="none" />
        <circle cx="10" cy="10" r="1" fill="currentColor" stroke="none" />
        <circle cx="16" cy="10" r="1" fill="currentColor" stroke="none" />
      </>
    ),
    close: <path d="m4 4 12 12M16 4 4 16" />,
    menu: <path d="M3 5h14M3 10h14M3 15h14" />,
    check: <path d="m4 10 4 4 8-9" />,
    warning: (
      <>
        <path d="m10 2.5 8 14H2z" />
        <path d="M10 7v4M10 14h.01" />
      </>
    ),
    file: (
      <>
        <path d="M5 2.5h6l4 4v11H5z" />
        <path d="M11 2.5v4h4" />
      </>
    ),
    command: (
      <>
        <rect x="3" y="4" width="14" height="12" rx="2" />
        <path d="m6 8 2 2-2 2M10 12h4" />
      </>
    ),
    branch: (
      <>
        <circle cx="6" cy="4" r="2" />
        <circle cx="14" cy="6" r="2" />
        <circle cx="6" cy="16" r="2" />
        <path d="M6 6v8M8 10h2a4 4 0 0 0 4-4" />
      </>
    ),
    download: (
      <>
        <path d="M10 3v10M6 9l4 4 4-4" />
        <path d="M4 16h12" />
      </>
    ),
    copy: (
      <>
        <rect x="6" y="6" width="10" height="10" rx="2" />
        <path d="M13 6V4a1 1 0 0 0-1-1H4a1 1 0 0 0-1 1v8a1 1 0 0 0 1 1h2" />
      </>
    ),
    refresh: (
      <>
        <path d="M16 6V3l-2 2a7 7 0 1 0 2.2 7" />
        <path d="M16 3h-4" />
      </>
    ),
    shield: <path d="M10 2.5 16 5v4.5c0 3.8-2.4 6.6-6 8-3.6-1.4-6-4.2-6-8V5z" />,
    folder: <path d="M2.5 5h6l1.5 2h7.5v9.5h-15z" />,
    external: (
      <>
        <path d="M11 3h6v6M17 3l-8 8" />
        <path d="M15 11v5H4V5h5" />
      </>
    ),
    moon: <path d="M15.5 13.8A7 7 0 0 1 6.2 4.5 7 7 0 1 0 15.5 13.8z" />,
    sun: (
      <>
        <circle cx="10" cy="10" r="3.5" />
        <path d="M10 2v2M10 16v2M2 10h2M16 10h2M4.3 4.3l1.4 1.4M14.3 14.3l1.4 1.4M15.7 4.3l-1.4 1.4M5.7 14.3l-1.4 1.4" />
      </>
    ),
  }[name];
  return (
    <svg {...shared} {...props}>
      {path}
    </svg>
  );
}
