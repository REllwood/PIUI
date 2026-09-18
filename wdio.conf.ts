import {
  lstatSync,
  realpathSync,
} from 'node:fs';
import {
  basename,
  dirname,
  resolve,
} from 'node:path';

export const A28_TAURI_SERVICE_VERSION = '1.2.0';
export const A28_WDIO_MODE = 'a28-accessibility';
export const A28_WDIO_PORT_MIN = 49_152;
export const A28_WDIO_PORT_MAX = 65_535;

const SHA256 = /^[0-9a-f]{64}$/u;
const REQUIRED_RUN_FILES = Object.freeze({
  PIUI_A28_DOM_EVIDENCE: 'dom-evidence.json',
  PIUI_A28_AX_READY: 'ax-ready.json',
  PIUI_A28_AX_RELEASE: 'ax-release.json',
  PIUI_A28_HUMAN_READY: 'human-ready.json',
  PIUI_A28_HUMAN_VISIBLE: 'human-visible.json',
});

type A28WdioEnvironment = Readonly<{
  appBinaryPath: string;
  axReadyPath: string;
  axReleasePath: string;
  domEvidencePath: string;
  humanReadyPath: string;
  humanVisiblePath: string;
  nonce: string;
  port: number;
  runRoot: string;
}>;

function reject(): never {
  throw new Error('A.28 WDIO configuration rejected');
}

function required(environment: NodeJS.ProcessEnv, key: string): string {
  const value = environment[key];
  if (typeof value !== 'string' || value.length === 0 || value.includes('\0')) reject();
  return value;
}

function exactAbsolutePath(value: string): string {
  if (resolve(value) !== value) reject();
  return value;
}

function assertPrivateRunRoot(value: string): string {
  const requested = exactAbsolutePath(value);
  const canonical = realpathSync(requested);
  const item = lstatSync(requested);
  if (canonical !== requested
    || !item.isDirectory()
    || item.isSymbolicLink()
    || (item.mode & 0o777) !== 0o700
    || (typeof process.getuid === 'function' && item.uid !== process.getuid())) reject();
  return requested;
}

function assertAppBinary(value: string): string {
  const requested = exactAbsolutePath(value);
  const canonical = realpathSync(requested);
  const item = lstatSync(requested);
  if (canonical !== requested
    || !item.isFile()
    || item.isSymbolicLink()
    || (item.mode & 0o111) === 0
    || (typeof process.getuid === 'function' && item.uid !== process.getuid())) reject();
  return requested;
}

function assertRunFile(
  environment: NodeJS.ProcessEnv,
  key: keyof typeof REQUIRED_RUN_FILES,
  runRoot: string,
): string {
  const path = exactAbsolutePath(required(environment, key));
  if (dirname(path) !== runRoot || basename(path) !== REQUIRED_RUN_FILES[key]) reject();
  return path;
}

export function readA28WdioEnvironment(
  environment: NodeJS.ProcessEnv = process.env,
): A28WdioEnvironment {
  const mode = required(environment, 'PIUI_ARCHITECTURE_TEST_MODE');
  const nonce = required(environment, 'PIUI_ARCHITECTURE_TEST_NONCE');
  const portText = required(environment, 'PIUI_ARCHITECTURE_TEST_PORT');
  if (mode !== A28_WDIO_MODE
    || !SHA256.test(nonce)
    || !/^[0-9]{5}$/u.test(portText)) {
    reject();
  }
  const port = Number(portText);
  if (!Number.isSafeInteger(port)
    || port < A28_WDIO_PORT_MIN
    || port > A28_WDIO_PORT_MAX
    || String(port) !== portText) reject();

  const runRoot = assertPrivateRunRoot(required(environment, 'PIUI_A28_RUN_ROOT'));
  return Object.freeze({
    appBinaryPath: assertAppBinary(required(environment, 'PIUI_A28_APP_BINARY')),
    axReadyPath: assertRunFile(environment, 'PIUI_A28_AX_READY', runRoot),
    axReleasePath: assertRunFile(environment, 'PIUI_A28_AX_RELEASE', runRoot),
    domEvidencePath: assertRunFile(environment, 'PIUI_A28_DOM_EVIDENCE', runRoot),
    humanReadyPath: assertRunFile(environment, 'PIUI_A28_HUMAN_READY', runRoot),
    humanVisiblePath: assertRunFile(environment, 'PIUI_A28_HUMAN_VISIBLE', runRoot),
    nonce,
    port,
    runRoot,
  });
}

const a28 = readA28WdioEnvironment();

export const config = {
  runner: 'local',
  specs: ['./tests/packaged/accessibility-spike.spec.ts'],
  exclude: [],
  maxInstances: 1,
  maxInstancesPerCapability: 1,
  capabilities: [{
    browserName: 'tauri',
  }],
  services: [[
    '@wdio/tauri-service',
    {
      appBinaryPath: a28.appBinaryPath,
      appArgs: [],
      autoDownloadEdgeDriver: false,
      autoInstallTauriDriver: false,
      captureBackendLogs: false,
      captureFrontendLogs: false,
      commandTimeout: 30_000,
      driverProvider: 'embedded',
      embeddedPort: a28.port,
      env: {
        HOME: resolve(a28.runRoot, 'home'),
        CFFIXED_USER_HOME: resolve(a28.runRoot, 'home'),
        TMPDIR: `${resolve(a28.runRoot, 'tmp')}/`,
        XDG_CACHE_HOME: resolve(a28.runRoot, 'cache'),
        XDG_CONFIG_HOME: resolve(a28.runRoot, 'config'),
        XDG_DATA_HOME: resolve(a28.runRoot, 'data'),
        PIUI_AGENT_ROOT: resolve(a28.runRoot, 'agent'),
        PIUI_SESSION_ROOT: resolve(a28.runRoot, 'sessions'),
        PATH: '/usr/bin:/bin:/usr/sbin:/sbin',
        LANG: 'en_AU.UTF-8',
        LC_ALL: 'en_AU.UTF-8',
        OPENSSL_CONF: '/System/Library/OpenSSL/openssl.cnf',
        PIUI_ARCHITECTURE_TEST_MODE: A28_WDIO_MODE,
        PIUI_ARCHITECTURE_TEST_NONCE: a28.nonce,
        PIUI_ARCHITECTURE_TEST_PORT: String(a28.port),
        PIUI_A28_APP_BINARY: '',
        PIUI_A28_RUN_ROOT: '',
        PIUI_A28_DOM_EVIDENCE: '',
        PIUI_A28_AX_READY: '',
        PIUI_A28_AX_RELEASE: '',
        PIUI_A28_HUMAN_READY: '',
        PIUI_A28_HUMAN_VISIBLE: '',
        PIUI_A28_HUMAN_EVIDENCE_ROOT: '',
      },
      logLevel: 'error',
      startTimeout: 60_000,
      statusPollTimeout: 2_000,
    },
  ]],
  hostname: '127.0.0.1',
  port: a28.port,
  path: '/',
  logLevel: 'error',
  bail: 1,
  waitforTimeout: 10_000,
  connectionRetryTimeout: 30_000,
  connectionRetryCount: 0,
  framework: 'mocha',
  reporters: ['spec'],
  injectGlobals: false,
  specFileRetries: 0,
  mochaOpts: {
    ui: 'bdd',
    timeout: 32 * 60_000,
  },
};
