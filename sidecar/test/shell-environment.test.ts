import { describe, expect, it } from 'vitest';
import { userShellSpawnHook } from '../src/pi/shell-environment';

const binDir = '/sealed/.pi/agent/bin';
const piContext = Object.freeze({
  command: 'pnpm test',
  cwd: '/workspace',
  env: Object.freeze({ HOME: '/sealed', PATH: binDir, PI_SESSION_ID: 'session', OTHER: 'kept' }),
});

describe('user shell environment for the bash tool', () => {
  it('leaves Pi unchanged when the host supplies neither variable', () => {
    expect(userShellSpawnHook({}, binDir)).toBeUndefined();
    expect(userShellSpawnHook({ PIUI_USER_HOME: 'relative/home' }, binDir)).toBeUndefined();
  });

  it("runs commands with the user's HOME and PATH behind Pi's bin directory", () => {
    const hook = userShellSpawnHook(
      { PIUI_USER_HOME: '/Users/person', PIUI_USER_PATH: '/opt/homebrew/bin:/usr/bin:/bin' },
      binDir,
    );
    expect(hook?.(piContext)).toEqual({
      command: 'pnpm test',
      cwd: '/workspace',
      env: {
        HOME: '/Users/person',
        PATH: `${binDir}:/opt/homebrew/bin:/usr/bin:/bin`,
        PI_SESSION_ID: 'session',
        OTHER: 'kept',
      },
    });
  });

  it('does not duplicate the bin directory or keep a differently cased path key', () => {
    const hook = userShellSpawnHook({ PIUI_USER_PATH: `/usr/bin:${binDir}` }, binDir);
    const result = hook?.({ ...piContext, env: { ...piContext.env, Path: '/stale' } });
    expect(result?.env.PATH).toBe(`/usr/bin:${binDir}`);
    expect(result?.env.HOME).toBe('/sealed');
    expect(result?.env).not.toHaveProperty('Path');
  });
});
