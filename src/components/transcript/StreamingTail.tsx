import type { Message } from '../../domain/types';
import { SafeMarkdown } from '../markdown/SafeMarkdown';

export function StreamingTail({ message }: Readonly<{ message: Message | undefined }>) {
  if (!message) return null;
  const hasContent = message.markdown.length > 0;
  return (
    <article
      className="message message--streaming"
      aria-label={`${message.author}, responding now`}
      aria-busy="true"
    >
      <header className="message__meta">
        <strong>{message.author}</strong>
        <span>{hasContent ? 'Working' : 'Preparing response'}</span>
      </header>
      {hasContent ? <SafeMarkdown markdown={message.markdown} complete={false} /> : null}
      <span className="stream-caret" aria-hidden="true" />
    </article>
  );
}
