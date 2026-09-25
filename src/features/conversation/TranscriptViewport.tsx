import { useEffect, useRef, useState } from 'react';
import type { Message } from '../../domain/types';
import { useAppearance } from '../appearance/AppearanceProvider';
import { StableMessageList } from '../../components/transcript/StableMessageList';
import { StreamingTail } from '../../components/transcript/StreamingTail';
import { VirtualMessageList } from '../../components/transcript/VirtualMessageList';

export function TranscriptViewport({ messages }: Readonly<{ messages: readonly Message[] }>) {
  const { preferences } = useAppearance();
  const viewport = useRef<HTMLDivElement>(null);
  const [awayFromLatest, setAwayFromLatest] = useState(false);
  let streaming: Message | undefined;
  for (let index = messages.length - 1; index >= 0; index -= 1) {
    const candidate = messages[index];
    if (candidate?.status === 'streaming') {
      streaming = candidate;
      break;
    }
  }

  useEffect(() => {
    const element = viewport.current;
    if (!element || awayFromLatest) return;
    requestAnimationFrame(() => {
      element.scrollTop = element.scrollHeight;
    });
  }, [messages, awayFromLatest]);

  return (
    <div
      ref={viewport}
      className="transcript-viewport"
      role="log"
      aria-label="Conversation transcript"
      tabIndex={0}
      onScroll={(event) => {
        const element = event.currentTarget;
        setAwayFromLatest(element.scrollHeight - element.scrollTop - element.clientHeight > 80);
      }}
    >
      <div className="transcript-viewport__inner">
        {!preferences.accessibleTranscript && messages.length > 100 ? (
          <VirtualMessageList messages={messages} scrollElement={viewport} />
        ) : (
          <StableMessageList messages={messages} accessible={preferences.accessibleTranscript} />
        )}
        <StreamingTail message={streaming} />
      </div>
      {awayFromLatest ? (
        <button
          type="button"
          className="button jump-latest"
          onClick={() => {
            const element = viewport.current;
            if (element) element.scrollTop = element.scrollHeight;
            setAwayFromLatest(false);
          }}
        >
          Jump to latest
        </button>
      ) : null}
    </div>
  );
}
