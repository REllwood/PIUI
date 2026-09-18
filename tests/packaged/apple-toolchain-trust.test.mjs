import assert from 'node:assert/strict';
import { chmod, mkdir, mkdtemp, realpath, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import {
  APPLE_TOOLCHAIN_PATHS,
  appleToolchainBuildEnvironment,
  assertRootOwnedImmutableAncestorChain,
  captureAppleToolchainAuthority,
  releaseAppleToolchainAuthority,
  revalidateAppleToolchainAuthority,
} from '../../scripts/apple-toolchain-trust.mjs';

const root = '/Library/Developer/CommandLineTools';
const clang = `${root}/usr/bin/clang`;
const clangxx = `${root}/usr/bin/clang++`;
const sdk = `${root}/SDKs/MacOSX26.5.sdk`;

test('holds and revalidates the root-owned non-writable Command Line Tools authority', () => {
  const authority = captureAppleToolchainAuthority();
  try {
    assert.deepEqual(authority, {
      entries: 101_546,
      root,
      schemaVersion: 1,
    });
    assert.equal(revalidateAppleToolchainAuthority(authority), authority);
    assert.throws(
      () => revalidateAppleToolchainAuthority(Object.freeze({ ...authority })),
      /Apple Command Line Tools authority rejected/u,
    );
  } finally {
    releaseAppleToolchainAuthority(authority);
  }
  assert.throws(
    () => revalidateAppleToolchainAuthority(authority),
    /Apple Command Line Tools authority rejected/u,
  );
  assert.doesNotThrow(() => releaseAppleToolchainAuthority(authority));
});

test('exposes only the fixed CLT compiler, SDK and deployment environment', () => {
  assert.deepEqual(APPLE_TOOLCHAIN_PATHS, {
    ar: `${root}/usr/bin/ar`,
    bin: `${root}/usr/bin`,
    clang,
    clangxx,
    dsymutil: `${root}/usr/bin/dsymutil`,
    installNameTool: `${root}/usr/bin/install_name_tool`,
    ld: `${root}/usr/bin/ld`,
    libtool: `${root}/usr/bin/libtool`,
    lipo: `${root}/usr/bin/lipo`,
    llvmNm: `${root}/usr/bin/llvm-nm`,
    llvmOtool: `${root}/usr/bin/llvm-otool`,
    nm: `${root}/usr/bin/nm`,
    otool: `${root}/usr/bin/otool`,
    otoolClassic: `${root}/usr/bin/otool-classic`,
    ranlib: `${root}/usr/bin/ranlib`,
    root,
    sdk,
    sdkSettings: `${sdk}/SDKSettings.json`,
    strip: `${root}/usr/bin/strip`,
  });
  assert.deepEqual(appleToolchainBuildEnvironment(), {
    AR: `${root}/usr/bin/ar`,
    'AR_aarch64-apple-darwin': `${root}/usr/bin/ar`,
    AR_aarch64_apple_darwin: `${root}/usr/bin/ar`,
    CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER: clang,
    CC: clang,
    'CC_aarch64-apple-darwin': clang,
    CC_aarch64_apple_darwin: clang,
    CXX: clangxx,
    'CXX_aarch64-apple-darwin': clangxx,
    CXX_aarch64_apple_darwin: clangxx,
    DEVELOPER_DIR: root,
    DSYMUTIL: `${root}/usr/bin/dsymutil`,
    INSTALL_NAME_TOOL: `${root}/usr/bin/install_name_tool`,
    LD: `${root}/usr/bin/ld`,
    LIBTOOL: `${root}/usr/bin/libtool`,
    LIPO: `${root}/usr/bin/lipo`,
    MACOSX_DEPLOYMENT_TARGET: '13.0',
    NM: `${root}/usr/bin/nm`,
    OTOOL: `${root}/usr/bin/otool`,
    RANLIB: `${root}/usr/bin/ranlib`,
    SDKROOT: sdk,
    STRIP: `${root}/usr/bin/strip`,
  });
  for (const value of Object.values(appleToolchainBuildEnvironment())) {
    assert.equal(typeof value, 'string');
    assert.doesNotMatch(value, /Applications\/Xcode|^\/usr\/bin\/(?:cc|clang)$|xcrun/u);
  }
});

test('rejects a user-owned path before it can become compiler authority', async (context) => {
  const fixture = await realpath(await mkdtemp(join(tmpdir(), 'piui-clt-authority-test-')));
  context.after(async () => rm(fixture, { recursive: true, force: true }));
  const candidate = join(fixture, 'CommandLineTools');
  await mkdir(candidate, { mode: 0o700 });
  await chmod(candidate, 0o700);
  assert.throws(
    () => assertRootOwnedImmutableAncestorChain(candidate, fixture),
    /Apple Command Line Tools authority rejected/u,
  );
});
