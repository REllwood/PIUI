import type { AuthEvent, AuthInteraction, AuthPrompt } from '@earendil-works/pi-ai';
import type { AuthInteractionPort, AuthNotice } from '../pi/adapter.js';

function mapPrompt(prompt: AuthPrompt): Parameters<AuthInteractionPort['prompt']>[0] {
  return Object.freeze({
    type: prompt.type === 'manual_code' ? 'manual-code' : prompt.type,
    message: prompt.message,
    ...('options' in prompt
      ? { options: prompt.options.map((option) => ({ id: option.id, label: option.label })) }
      : {}),
    ...(prompt.signal ? { signal: prompt.signal } : {}),
  });
}

function mapEvent(event: AuthEvent): AuthNotice | null {
  if (event.type === 'auth_url')
    return {
      type: 'opening-browser',
      url: event.url,
      ...(event.instructions ? { instructions: event.instructions } : {}),
    };
  if (event.type === 'device_code')
    return {
      type: 'device-code',
      verificationUri: event.verificationUri,
      userCode: event.userCode,
      ...(event.expiresInSeconds ? { expiresInSeconds: event.expiresInSeconds } : {}),
    };
  if (event.type === 'progress' || event.type === 'info')
    return { type: 'progress', message: event.message };
  return null;
}

export function createOAuthInteraction(port: AuthInteractionPort): AuthInteraction {
  return Object.freeze({
    signal: port.signal,
    prompt: (prompt: AuthPrompt) => port.prompt(mapPrompt(prompt)),
    notify: (event: AuthEvent) => {
      const notice = mapEvent(event);
      if (notice) port.notify(notice);
    },
  });
}

export function validateOAuthReturn(
  expectedState: string,
  returnedState: string,
  consumed: Set<string>,
): boolean {
  if (
    !/^[A-Za-z0-9_-]{32,128}$/u.test(expectedState) ||
    expectedState !== returnedState ||
    consumed.has(returnedState)
  )
    return false;
  consumed.add(returnedState);
  return true;
}
