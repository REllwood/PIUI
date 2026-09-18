import { useEffect, useRef, useState } from 'react';

export type Announcement = Readonly<{
  id: string;
  message: string;
  urgency?: 'polite' | 'assertive';
}>;

export function AnnouncementHost({
  announcement,
}: Readonly<{ announcement: Announcement | null }>) {
  const lastId = useRef<string | null>(null);
  const [visible, setVisible] = useState<Announcement | null>(null);

  useEffect(() => {
    if (!announcement || announcement.id === lastId.current || document.hidden) return;
    lastId.current = announcement.id;
    const handle = window.setTimeout(
      () => setVisible(announcement),
      announcement.urgency === 'assertive' ? 0 : 250,
    );
    return () => window.clearTimeout(handle);
  }, [announcement]);

  return (
    <div
      className="sr-only"
      role={visible?.urgency === 'assertive' ? 'alert' : 'status'}
      aria-live={visible?.urgency ?? 'polite'}
    >
      {visible?.message ?? ''}
    </div>
  );
}
