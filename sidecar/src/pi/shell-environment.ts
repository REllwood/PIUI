import { delimiter, isAbsolute } from 'node:path';
import type { PublicBashSpawnHook } from './public-sdk.js';

/**
 * Rust clears the sidecar environment and seals HOME inside the signed bundle.
 * That is right for Pi's internals but wrong for commands the agent runs on the
 * user's behalf: without the user's PATH and HOME, pnpm, Homebrew tools and git
 * configuration are missing. When Rust supplies PIUI_USER_HOME and
 * PIUI_USER_PATH, Pi's bash tool runs commands with them, keeping Pi's own bin
 * directory first on PATH exactly as Pi's getShellEnv does. Without them the
 * bash tool behaves exactly as before.
 */
export function userShellSpawnHook(
  environment: NodeJS.ProcessEnv,
  piBinDir: string,
): PublicBashSpawnHook | undefined {
  const home = environment.PIUI_USER_HOME;
  const path = environment.PIUI_USER_PATH;
  const userHome = home !== undefined && isAbsolute(home) ? home : undefined;
  if (userHome === undefined && path === undefined) return undefined;
  return (context) => {
    const env = { ...context.env };
    if (userHome !== undefined) env.HOME = userHome;
    if (path !== undefined) {
      for (const key of Object.keys(env)) {
        if (key !== 'PATH' && key.toLowerCase() === 'path') delete env[key];
      }
      env.PATH = path.split(delimiter).includes(piBinDir)
        ? path
        : [piBinDir, path].filter(Boolean).join(delimiter);
    }
    return { ...context, env };
  };
}
