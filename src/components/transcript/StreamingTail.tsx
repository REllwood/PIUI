import type { Message } from '../../domain/types';
import { SafeMarkdown } from '../markdown/SafeMarkdown';

export function StreamingTail({ message }: Readonly<{ message: Message | undefined }>) {
  if (!message) return null;
  return (
    <article
      className="message message--streaming"
      aria-label={`${message.author}, responding now`}
      aria-busy="true"
    >
      <header className="message__meta">
        <strong>{message.author}</strong>
        <span>Working</span>
      </header>
      <SafeMarkdown markdown={message.markdown} complete={false} />
      <span className="stream-caret" aria-hidden="true" />
    </article>
  );
}
