import { useEffect, useMemo, useState, type RefObject } from 'react';
import { useVirtualizer } from '@tanstack/react-virtual';
import type { Message } from '../../domain/types';
import { MessageArticle } from './StableMessageList';

export function VirtualMessageList({
  messages,
  scrollElement,
}: Readonly<{
  messages: readonly Message[];
  scrollElement: RefObject<HTMLDivElement | null>;
}>) {
  const stable = useMemo(
    () => messages.filter((message) => message.status !== 'streaming'),
    [messages],
  );
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);
  const virtualizer = useVirtualizer({
    count: stable.length,
    getScrollElement: () => (mounted ? scrollElement.current : null),
    estimateSize: (index) => {
      const characters = stable[index]?.markdown.length ?? 0;
      const estimatedLines = Math.max(1, Math.ceil(characters / 72));
      return Math.min(2_400, 76 + estimatedLines * 24);
    },
    overscan: 1,
    getItemKey: (index) => stable[index]?.id ?? index,
  });
  const items = virtualizer.getVirtualItems();
  return (
    <div
      className="transcript-list transcript-list--virtual"
      style={{ height: virtualizer.getTotalSize() }}
    >
      {items.map((item) => {
        const message = stable[item.index];
        if (!message) return null;
        return (
          <div
            key={message.id}
            ref={virtualizer.measureElement}
            data-index={item.index}
            className="virtual-message"
            style={{ transform: `translateY(${item.start}px)` }}
          >
            <MessageArticle message={message} />
          </div>
        );
      })}
    </div>
  );
}
