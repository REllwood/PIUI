import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  chmod,
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  writeFile,
} from 'node:fs/promises';
import { platform, tmpdir } from 'node:os';
import { resolve } from 'node:path';
import test from 'node:test';
import { a26RuntimeSandbox } from '../../scripts/run-packaged-markdown-probe.mjs';
import { a27RuntimeSandbox } from '../../scripts/run-packaged-lifecycle-probe.mjs';
import {
  a28NegativeRuntimeSandbox,
  a28WdioSandbox,
} from '../../scripts/run-packaged-accessibility-probe.mjs';
import { credentialProbeSandbox } from '../../scripts/run-packaged-credential-probe.mjs';

const active = Object.freeze({ nonce: 'a'.repeat(64), port: 53_421 });
const runtimeDirectoryNames = Object.freeze([
  'agent',
  'cache',
  'config',
  'data',
  'home',
  'sessions',
  'tmp',
]);
const credentialBrokerServices = Object.freeze([
  'com.apple.SecurityServer',
  'com.apple.cfprefsd.agent',
  'com.apple.cfprefsd.daemon',
  'com.apple.securityd.xpc',
]);

async function fixture(t) {
  const requested = await mkdtemp(resolve(tmpdir(), 'piui-runtime-sandbox-test-'));
  await chmod(requested, 0o700);
  const fixtureRoot = await realpath(requested);
  t.after(async () => {
    try {
      await chmod(resolve(fixtureRoot, 'run/control'), 0o700);
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error;
    }
    await rm(fixtureRoot, { force: false, recursive: true });
  });
  const paths = Object.freeze({
    app: resolve(fixtureRoot, 'Test.app'),
    evidence: resolve(fixtureRoot, 'external-evidence'),
    home: resolve(fixtureRoot, 'ambient-home'),
    repository: resolve(fixtureRoot, 'repository'),
    run: resolve(fixtureRoot, 'run'),
  });
  for (const path of Object.values(paths)) await mkdir(path, { mode: 0o700 });
  for (const name of runtimeDirectoryNames) {
    await mkdir(resolve(paths.run, name), { mode: 0o700 });
  }
  for (const [path, contents] of [
    [resolve(paths.app, 'canary'), 'app-secret\n'],
    [resolve(paths.evidence, 'canary'), 'evidence-secret\n'],
    [resolve(paths.home, 'canary'), 'home-secret\n'],
    [resolve(paths.repository, 'canary'), 'repository-secret\n'],
    [
      resolve(paths.repository, 'worker.cjs'),
      "process.send?.('ready', () => process.exit(0));\n",
    ],
  ]) {
    await writeFile(path, contents, { flag: 'wx', mode: 0o600 });
  }
  return Object.freeze({
    bundle: Object.freeze({
      appPath: paths.app,
      hostPath: '/bin/bash',
      nodePath: '/usr/bin/true',
    }),
    paths,
  });
}

function runBash(profile, cwd, home, script, path) {
  return spawnSync('/usr/bin/sandbox-exec', [
    '-p',
    profile,
    '/bin/bash',
    '--noprofile',
    '--norc',
    '-c',
    script,
    'runtime-sandbox-test',
    path,
  ], {
    cwd,
    encoding: 'utf8',
    env: {
      HOME: home,
      PATH: '/usr/bin:/bin',
      TMPDIR: `${resolve(cwd, 'tmp')}/`,
    },
    timeout: 5_000,
  });
}

function readWithBash(profile, cwd, home, path) {
  return runBash(
    profile,
    cwd,
    home,
    'if IFS= read -r value < "$1"; then printf "%s" "$value"; else exit 73; fi',
    path,
  );
}

function writeWithBash(profile, cwd, home, path) {
  return runBash(
    profile,
    cwd,
    home,
    'if printf "%s" changed > "$1"; then exit 0; else exit 74; fi',
    path,
  );
}

function runNode(profile, cwd, code, paths) {
  return spawnSync('/usr/bin/sandbox-exec', [
    '-p',
    profile,
    process.execPath,
    '--eval',
    code,
    ...paths,
  ], {
    cwd,
    encoding: 'utf8',
    env: {
      HOME: resolve(cwd, 'home'),
      OPENSSL_CONF: '/System/Library/OpenSSL/openssl.cnf',
      PATH: '/usr/bin:/bin',
      TMPDIR: `${resolve(cwd, 'tmp')}/`,
    },
    timeout: 5_000,
  });
}

function credentialRuntime(runRoot) {
  return Object.freeze({
    artefacts: resolve(runRoot, 'agent'),
    cache: resolve(runRoot, 'cache'),
    config: resolve(runRoot, 'config'),
    data: resolve(runRoot, 'data'),
    home: resolve(runRoot, 'home'),
    temporary: resolve(runRoot, 'tmp'),
    working: runRoot,
  });
}

test('runtime profiles are deny-default and grant only exact activation loopback', {
  skip: platform() !== 'darwin',
}, async (t) => {
  const { bundle, paths } = await fixture(t);
  const profiles = {
    a26Active: a26RuntimeSandbox({ activation: active, bundle, isolate: paths.run }),
    a26Dormant: a26RuntimeSandbox({ activation: undefined, bundle, isolate: paths.run }),
    a27: a27RuntimeSandbox({ activation: active, bundle, isolate: paths.run }),
    a28Negative: a28NegativeRuntimeSandbox({ bundle, isolate: paths.run }),
    a28Wdio: a28WdioSandbox({
      bundle,
      controlRoot: resolve(paths.run, 'control'),
      evidenceRoot: paths.evidence,
      port: active.port,
      repositoryRoot: paths.repository,
      runRoot: paths.run,
      runnerPath: process.execPath,
    }),
  };
  const credentialProfile = credentialProbeSandbox(
    credentialRuntime(paths.run),
    bundle,
  );
  for (const profile of Object.values(profiles)) {
    assert.match(profile, /\(deny default\)/u);
    assert.doesNotMatch(profile, /\(allow default\)/u);
    assert.match(profile, new RegExp(`\\(subpath "${bundle.appPath}"\\)`, 'u'));
    assert.match(profile, new RegExp(`\\(literal "${bundle.hostPath}"\\)`, 'u'));
    assert.match(profile, new RegExp(`\\(literal "${bundle.nodePath}"\\)`, 'u'));
    assert.match(profile, new RegExp(`deny file-write\\* \\(subpath "${bundle.appPath}"\\)`, 'u'));
    for (const service of credentialBrokerServices) {
      assert.doesNotMatch(profile, new RegExp(service.replaceAll('.', '\\.')));
    }
  }
  for (const service of credentialBrokerServices) {
    assert.match(credentialProfile, new RegExp(service.replaceAll('.', '\\.')));
  }
  assert.throws(() => credentialProbeSandbox(
    credentialRuntime(paths.run),
    bundle,
    { allowCredentialBrokers: 'false' },
  ));
  for (const profile of [profiles.a26Dormant, profiles.a28Negative]) {
    assert.doesNotMatch(profile, /\(allow network-(?:inbound|outbound)/u);
  }
  for (const profile of [profiles.a26Active, profiles.a27, profiles.a28Wdio]) {
    assert.match(
      profile,
      new RegExp(`\\(allow network-inbound \\(local tcp "localhost:${active.port}"\\)\\)`, 'u'),
    );
    assert.match(
      profile,
      new RegExp(`\\(allow network-outbound \\(remote tcp "localhost:${active.port}"\\)\\)`, 'u'),
    );
    assert.doesNotMatch(profile, /\(allow network-(?:inbound|outbound)[^\n]*\*/u);
  }
});

test('non-credential runtimes deny Keychain and preferences broker lookup', {
  skip: platform() !== 'darwin',
}, async (t) => {
  const { paths } = await fixture(t);
  const helperPath = resolve(paths.app, 'mach-lookup-probe');
  const compilation = spawnSync('/usr/bin/clang', [
    '-std=c17',
    '-Wall',
    '-Wextra',
    '-Werror',
    '-x',
    'c',
    '-',
    '-o',
    helperPath,
  ], {
    encoding: 'utf8',
    env: { PATH: '/usr/bin:/bin' },
    input: `
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

extern int sandbox_check(pid_t pid, const char *operation, int type, ...);

int main(int argc, char **argv) {
  if (argc != 2) return 64;
  int status = sandbox_check(getpid(), "mach-lookup", 2, argv[1]);
  printf("%d\\n", status);
  return status == 0 ? 0 : 77;
}
`,
  });
  assert.equal(compilation.status, 0, compilation.stderr);
  assert.equal(compilation.stdout, '');
  assert.equal(compilation.stderr, '');
  const bundle = Object.freeze({
    appPath: paths.app,
    hostPath: helperPath,
    nodePath: '/usr/bin/true',
  });
  const nonCredentialProfiles = [
    a26RuntimeSandbox({ activation: undefined, bundle, isolate: paths.run }),
    a27RuntimeSandbox({ activation: active, bundle, isolate: paths.run }),
    a28NegativeRuntimeSandbox({ bundle, isolate: paths.run }),
    a28WdioSandbox({
      bundle,
      controlRoot: resolve(paths.run, 'control'),
      evidenceRoot: paths.evidence,
      port: active.port,
      repositoryRoot: paths.repository,
      runRoot: paths.run,
      runnerPath: process.execPath,
    }),
  ];
  const credentialProfile = credentialProbeSandbox(
    credentialRuntime(paths.run),
    bundle,
  );
  const runProbe = (profile, service) => spawnSync('/usr/bin/sandbox-exec', [
    '-p',
    profile,
    helperPath,
    service,
  ], {
    cwd: paths.run,
    encoding: 'utf8',
    env: { HOME: resolve(paths.run, 'home'), PATH: '/usr/bin:/bin' },
    timeout: 5_000,
  });

  for (const service of credentialBrokerServices) {
    const credentialResult = runProbe(credentialProfile, service);
    assert.equal(credentialResult.status, 0, credentialResult.stderr);
    assert.equal(credentialResult.stdout, '0\n');
    for (const profile of nonCredentialProfiles) {
      const denied = runProbe(profile, service);
      assert.equal(denied.status, 77, denied.stderr);
      assert.equal(denied.stdout, '1\n');
    }
  }
  for (const profile of nonCredentialProfiles) {
    const uiControl = runProbe(profile, 'com.apple.windowserver.active');
    assert.equal(uiControl.status, 0, uiControl.stderr);
    assert.equal(uiControl.stdout, '0\n');
  }
});

test('packaged app profiles confine reads and writes to the private runtime isolate', {
  skip: platform() !== 'darwin',
}, async (t) => {
  const { bundle, paths } = await fixture(t);
  const profiles = [
    a26RuntimeSandbox({ activation: undefined, bundle, isolate: paths.run }),
    a27RuntimeSandbox({ activation: active, bundle, isolate: paths.run }),
    a28NegativeRuntimeSandbox({ bundle, isolate: paths.run }),
  ];
  const appCanary = resolve(paths.app, 'canary');
  const deniedCanaries = [
    resolve(paths.home, 'canary'),
    resolve(paths.repository, 'canary'),
    resolve(paths.evidence, 'canary'),
  ];
  for (const [index, profile] of profiles.entries()) {
    const isolateWrite = resolve(paths.run, `allowed-${index}`);
    assert.equal(writeWithBash(profile, paths.run, paths.home, isolateWrite).status, 0);
    assert.equal(await readFile(isolateWrite, 'utf8'), 'changed');
    const appRead = readWithBash(profile, paths.run, paths.home, appCanary);
    assert.equal(appRead.status, 0);
    assert.equal(appRead.stdout, 'app-secret');
    assert.notEqual(writeWithBash(profile, paths.run, paths.home, appCanary).status, 0);
    assert.equal(await readFile(appCanary, 'utf8'), 'app-secret\n');
    for (const canary of deniedCanaries) {
      assert.notEqual(readWithBash(profile, paths.run, paths.home, canary).status, 0);
      assert.notEqual(writeWithBash(profile, paths.run, paths.home, canary).status, 0);
    }
  }
  assert.equal(await readFile(resolve(paths.home, 'canary'), 'utf8'), 'home-secret\n');
  assert.equal(
    await readFile(resolve(paths.repository, 'canary'), 'utf8'),
    'repository-secret\n',
  );
  assert.equal(
    await readFile(resolve(paths.evidence, 'canary'), 'utf8'),
    'evidence-secret\n',
  );
});

test('A.27 candidate cannot read, replace or execute its private reopen control', {
  skip: platform() !== 'darwin',
}, async (t) => {
  const { paths } = await fixture(t);
  const controlRoot = resolve(paths.run, 'control');
  const controlTool = resolve(controlRoot, 'reopen-exact-application');
  await mkdir(controlRoot, { mode: 0o700 });
  await copyFile('/usr/bin/true', controlTool);
  await chmod(controlTool, 0o500);
  await chmod(controlRoot, 0o500);
  const bundle = Object.freeze({
    appPath: paths.app,
    hostPath: '/bin/bash',
    nodePath: '/usr/bin/true',
  });
  const profile = a27RuntimeSandbox({ activation: active, bundle, isolate: paths.run });
  assert.notEqual(readWithBash(profile, paths.run, paths.home, controlTool).status, 0);
  assert.notEqual(writeWithBash(profile, paths.run, paths.home, controlTool).status, 0);
  const execution = runBash(
    profile,
    paths.run,
    paths.home,
    '"$1"',
    controlTool,
  );
  assert.notEqual(execution.status, 0);
  assert.equal((await readFile(controlTool)).equals(await readFile('/usr/bin/true')), true);
});

test('A.28 gives evidence authority to the exact WDIO Node runner, never the app', {
  skip: platform() !== 'darwin',
}, async (t) => {
  const { bundle, paths } = await fixture(t);
  const controlRoot = resolve(paths.run, 'control');
  const controlTool = resolve(controlRoot, 'inspect-accessibility');
  await mkdir(controlRoot, { mode: 0o700 });
  await copyFile('/usr/bin/true', controlTool);
  await chmod(controlTool, 0o500);
  await chmod(controlRoot, 0o500);
  const profile = a28WdioSandbox({
    bundle,
    controlRoot,
    evidenceRoot: paths.evidence,
    port: active.port,
    repositoryRoot: paths.repository,
    runRoot: paths.run,
    runnerPath: process.execPath,
  });
  const repositoryCanary = resolve(paths.repository, 'canary');
  const externalEvidenceCanary = resolve(paths.evidence, 'canary');
  const runEvidence = resolve(paths.run, 'dom-evidence.json');
  const allowed = runNode(
    profile,
    paths.run,
    "const fs=require('node:fs');const value=fs.readFileSync(process.argv[1],'utf8');fs.writeFileSync(process.argv[2],value);",
    [repositoryCanary, runEvidence],
  );
  assert.equal(allowed.status, 0, allowed.stderr);
  assert.equal(await readFile(runEvidence, 'utf8'), 'repository-secret\n');

  const controlBytes = await readFile(controlTool);
  const deniedReplacement = runNode(
    profile,
    paths.run,
    "const fs=require('node:fs');try{fs.chmodSync(process.argv[1],0o700);fs.writeFileSync(process.argv[1],'forged');process.exit(3);}catch{process.stdout.write('replacement-denied\\n');}",
    [controlTool],
  );
  assert.equal(deniedReplacement.status, 0, deniedReplacement.stderr);
  assert.equal(deniedReplacement.stdout, 'replacement-denied\n');
  assert.equal((await readFile(controlTool)).equals(controlBytes), true);
  const deniedExecution = runNode(
    profile,
    paths.run,
    "const{spawnSync}=require('node:child_process');const result=spawnSync(process.argv[1]);if(!result.error&&result.status===0)process.exit(3);process.stdout.write('execution-denied\\n');",
    [controlTool],
  );
  assert.equal(deniedExecution.status, 0, deniedExecution.stderr);
  assert.equal(deniedExecution.stdout, 'execution-denied\n');

  const workerEvidence = resolve(paths.run, 'ax-ready.json');
  const worker = runNode(
    profile,
    paths.run,
    "const fs=require('node:fs');const{fork}=require('node:child_process');let ready=false;const child=fork(process.argv[1],[],{stdio:['ignore','ignore','ignore','ipc']});child.on('message',(value)=>{ready=value==='ready';});child.on('exit',(code)=>{if(code!==0||!ready)process.exit(2);fs.writeFileSync(process.argv[2],'worker-ready');});",
    [resolve(paths.repository, 'worker.cjs'), workerEvidence],
  );
  assert.equal(worker.status, 0, worker.stderr);
  assert.equal(await readFile(workerEvidence, 'utf8'), 'worker-ready');

  const survivorScript = resolve(paths.repository, 'detached-survivor.cjs');
  const survivorStatus = resolve(paths.run, 'detached-survivor-status');
  const forgedCompletion = resolve(paths.evidence, 'completion.json');
  await writeFile(survivorScript, `
    const fs = require('node:fs');
    setTimeout(() => {
      let status = 'forged';
      try { fs.writeFileSync(process.argv[2], 'forged-completion'); }
      catch { status = 'denied'; }
      fs.writeFileSync(process.argv[3], status);
    }, 100);
  `, { mode: 0o400 });
  const detached = runNode(
    profile,
    paths.run,
    "const{spawn}=require('node:child_process');const child=spawn(process.execPath,[process.argv[1],process.argv[2],process.argv[3]],{detached:true,stdio:'ignore'});child.unref();",
    [survivorScript, forgedCompletion, survivorStatus],
  );
  assert.equal(detached.status, 0, detached.stderr);
  const survivorDeadline = Date.now() + 2_000;
  let survivorOutcome;
  while (Date.now() < survivorDeadline && survivorOutcome === undefined) {
    try {
      survivorOutcome = await readFile(survivorStatus, 'utf8');
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error;
      await new Promise((resolvePause) => setTimeout(resolvePause, 25));
    }
  }
  assert.equal(survivorOutcome, 'denied');
  await assert.rejects(readFile(forgedCompletion), { code: 'ENOENT' });

  for (const deniedPath of [repositoryCanary, externalEvidenceCanary]) {
    const deniedWrite = runNode(
      profile,
      paths.run,
      "require('node:fs').writeFileSync(process.argv[1],'changed');",
      [deniedPath],
    );
    assert.notEqual(deniedWrite.status, 0);
  }
  const deniedEvidenceRead = runNode(
    profile,
    paths.run,
    "require('node:fs').readFileSync(process.argv[1]);",
    [externalEvidenceCanary],
  );
  assert.notEqual(deniedEvidenceRead.status, 0);

  assert.notEqual(readWithBash(profile, paths.run, paths.home, runEvidence).status, 0);
  assert.notEqual(writeWithBash(profile, paths.run, paths.home, runEvidence).status, 0);
  assert.notEqual(readWithBash(profile, paths.run, paths.home, repositoryCanary).status, 0);
  assert.notEqual(writeWithBash(profile, paths.run, paths.home, repositoryCanary).status, 0);
  assert.notEqual(readWithBash(profile, paths.run, paths.home, externalEvidenceCanary).status, 0);
  assert.notEqual(writeWithBash(profile, paths.run, paths.home, externalEvidenceCanary).status, 0);
  assert.equal(await readFile(runEvidence, 'utf8'), 'repository-secret\n');
  assert.equal(await readFile(repositoryCanary, 'utf8'), 'repository-secret\n');
  assert.equal(await readFile(externalEvidenceCanary, 'utf8'), 'evidence-secret\n');
});

test('all owned packaged launch sites invoke sandbox-exec and strip evidence paths from the app', async () => {
  const repositoryRoot = resolve(import.meta.dirname, '../..');
  const [packageSpike, a26, a27, a28, wdio] = await Promise.all([
    readFile(resolve(repositoryRoot, 'scripts/package-spike.mjs'), 'utf8'),
    readFile(resolve(repositoryRoot, 'scripts/run-packaged-markdown-probe.mjs'), 'utf8'),
    readFile(resolve(repositoryRoot, 'scripts/run-packaged-lifecycle-probe.mjs'), 'utf8'),
    readFile(resolve(repositoryRoot, 'scripts/run-packaged-accessibility-probe.mjs'), 'utf8'),
    readFile(resolve(repositoryRoot, 'wdio.conf.ts'), 'utf8'),
  ]);
  for (const source of [packageSpike, a26, a27, a28]) {
    assert.match(source, /['"]\/usr\/bin\/sandbox-exec['"]/u);
    assert.match(source, /allowCredentialBrokers: false/u);
  }
  assert.doesNotMatch(packageSpike, /const runtimeSandbox = .*allow default/u);
  assert.match(a28, /command: '\/usr\/bin\/sandbox-exec'/u);
  for (const name of [
    'PIUI_A28_APP_BINARY',
    'PIUI_A28_RUN_ROOT',
    'PIUI_A28_DOM_EVIDENCE',
    'PIUI_A28_AX_READY',
    'PIUI_A28_AX_RELEASE',
    'PIUI_A28_HUMAN_READY',
    'PIUI_A28_HUMAN_VISIBLE',
    'PIUI_A28_HUMAN_EVIDENCE_ROOT',
  ]) {
    assert.match(wdio, new RegExp(`${name}: ''`, 'u'));
  }
});
