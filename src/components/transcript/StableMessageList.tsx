import { memo, useMemo } from 'react';
import type { Message } from '../../domain/types';
import { SafeMarkdown } from '../markdown/SafeMarkdown';

export type TranscriptAnchor = Readonly<{ messageId: string; offsetPx: number }>;

// Messages keep their identity until they change, so memoising here stops approval
// polls and unrelated store updates from re-parsing every message's Markdown.
export const MessageArticle = memo(function MessageArticle({
  message,
}: Readonly<{ message: Message }>) {
  return (
    <article
      id={`transcript-${message.id}`}
      className="message"
      data-role={message.role}
      aria-label={`${message.author}, ${message.timestamp}`}
      tabIndex={message.status === 'failed' ? 0 : undefined}
    >
      <header className="message__meta">
        <strong>{message.author}</strong>
        <time>{message.timestamp}</time>
        {message.status === 'partial' ? <span>Partial response</span> : null}
        {message.status === 'failed' ? <span>Response failed</span> : null}
      </header>
      <SafeMarkdown markdown={message.markdown} />
    </article>
  );
});

export function StableMessageList({
  messages,
  accessible,
}: Readonly<{
  messages: readonly Message[];
  accessible: boolean;
}>) {
  const stable = useMemo(
    () => messages.filter((message) => message.status !== 'streaming'),
    [messages],
  );
  return (
    <div className="transcript-list" data-accessible={accessible}>
      {stable.map((message) => (
        <MessageArticle key={message.id} message={message} />
      ))}
    </div>
  );
}
