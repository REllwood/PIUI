#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonDigest.h>
#import <Security/Security.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <libproc.h>
#include <mach-o/dyld.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

extern char **environ;

static const NSUInteger A28MaximumPinnedFileBytes = 300U * 1024U * 1024U;
static NSString *const A28SupportRoot =
  @"/Library/Application Support/PIUI/A28Witness/";
static NSString *const A28LauncherIdentifier =
  @"au.com.piui.a28-root-launcher";
static NSString *const A28CheckpointPrivateDirectory =
  @"/Library/Application Support/PIUI/A28Witness/checkpoint-private";
static NSString *const A28CheckpointCommitmentDirectory =
  @"/Library/Application Support/PIUI/A28Witness/checkpoint-commitments";
static const NSUInteger A28MaximumChallengeRequestBytes = 65536U;
static const int A28PrepareReadTimeoutMilliseconds = 30000;

static void Fail(NSString *message) {
  NSData *bytes = [[message stringByAppendingString:@"\n"]
    dataUsingEncoding:NSUTF8StringEncoding];
  (void)write(STDERR_FILENO, bytes.bytes, bytes.length);
  exit(EXIT_FAILURE);
}

static NSString *Hex(NSData *data) {
  const unsigned char *bytes = data.bytes;
  NSMutableString *value = [NSMutableString stringWithCapacity:data.length * 2U];
  for (NSUInteger index = 0; index < data.length; index += 1U) {
    [value appendFormat:@"%02x", bytes[index]];
  }
  return value;
}

static NSString *Sha256(NSData *data) {
  if (data.length > UINT32_MAX) Fail(@"A.28 pinned file is too large");
  unsigned char digest[CC_SHA256_DIGEST_LENGTH] = {0};
  if (CC_SHA256(data.bytes, (CC_LONG)data.length, digest) == NULL) {
    Fail(@"A.28 launcher SHA-256 failed");
  }
  return Hex([NSData dataWithBytes:digest length:sizeof(digest)]);
}

static BOOL IsSha256(NSString *value) {
  if (value.length != 64U) return NO;
  NSCharacterSet *invalid = [[NSCharacterSet
    characterSetWithCharactersInString:@"0123456789abcdef"] invertedSet];
  return [value rangeOfCharacterFromSet:invalid].location == NSNotFound;
}

static BOOL IsCdHash(NSString *value) {
  if (value.length != 40U) return NO;
  NSCharacterSet *invalid = [[NSCharacterSet
    characterSetWithCharactersInString:@"0123456789abcdef"] invertedSet];
  return [value rangeOfCharacterFromSet:invalid].location == NSNotFound;
}

static void AssertRootPathChain(NSString *path, mode_t leafMode) {
  if (![path hasPrefix:@"/"]
      || [path containsString:@"\0"]
      || [path containsString:@"\r"]
      || [path containsString:@"\n"]
      || [path.pathComponents containsObject:@".."]) {
    Fail(@"A.28 launcher path rejected");
  }
  NSString *current = path;
  BOOL leaf = YES;
  while (YES) {
    struct stat item = {0};
    if (lstat(current.fileSystemRepresentation, &item) != 0
        || S_ISLNK(item.st_mode)
        || item.st_uid != 0
        || (item.st_mode & 0022) != 0
        || (leaf && (!S_ISREG(item.st_mode)
          || item.st_nlink != 1
          || (item.st_mode & 0777) != leafMode))
        || (!leaf && !S_ISDIR(item.st_mode))) {
      Fail(@"A.28 launcher root-owned path rejected");
    }
    if ([current isEqualToString:@"/"]) break;
    current = current.stringByDeletingLastPathComponent;
    if (current.length == 0U) current = @"/";
    leaf = NO;
  }
}

static void AssertRootDirectory(NSString *path, mode_t leafMode) {
  if (![path hasPrefix:@"/"]
      || [path containsString:@"\0"]
      || [path containsString:@"\r"]
      || [path containsString:@"\n"]
      || [path.pathComponents containsObject:@".."]) {
    Fail(@"A.28 launcher directory path rejected");
  }
  NSString *current = path;
  BOOL leaf = YES;
  while (YES) {
    struct stat item = {0};
    if (lstat(current.fileSystemRepresentation, &item) != 0
        || S_ISLNK(item.st_mode)
        || item.st_uid != 0
        || (item.st_mode & 0022) != 0
        || !S_ISDIR(item.st_mode)
        || (leaf && (item.st_mode & 0777) != leafMode)) {
      Fail(@"A.28 launcher root-owned directory rejected");
    }
    if ([current isEqualToString:@"/"]) break;
    current = current.stringByDeletingLastPathComponent;
    if (current.length == 0U) current = @"/";
    leaf = NO;
  }
}

static NSData *ReadPinnedFile(
  NSString *path,
  mode_t mode,
  NSString *expectedSha256
) {
  if (!IsSha256(expectedSha256)) Fail(@"A.28 pinned SHA-256 rejected");
  AssertRootPathChain(path, mode);
  int descriptor = open(path.fileSystemRepresentation, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (descriptor < 0) Fail(@"A.28 pinned file open failed");
  struct stat before = {0};
  struct stat after = {0};
  if (fstat(descriptor, &before) != 0
      || !S_ISREG(before.st_mode)
      || before.st_uid != 0
      || before.st_nlink != 1
      || (before.st_mode & 0777) != mode
      || before.st_size < 1
      || (uint64_t)before.st_size > A28MaximumPinnedFileBytes) {
    (void)close(descriptor);
    Fail(@"A.28 pinned file identity rejected");
  }
  NSMutableData *bytes = [NSMutableData dataWithLength:(NSUInteger)before.st_size];
  NSUInteger offset = 0U;
  while (offset < bytes.length) {
    ssize_t count = read(
      descriptor,
      (unsigned char *)bytes.mutableBytes + offset,
      bytes.length - offset
    );
    if (count <= 0) {
      (void)close(descriptor);
      Fail(@"A.28 pinned file read failed");
    }
    offset += (NSUInteger)count;
  }
  if (fstat(descriptor, &after) != 0
      || close(descriptor) != 0
      || before.st_dev != after.st_dev
      || before.st_ino != after.st_ino
      || before.st_size != after.st_size
      || before.st_mode != after.st_mode
      || before.st_mtimespec.tv_sec != after.st_mtimespec.tv_sec
      || before.st_mtimespec.tv_nsec != after.st_mtimespec.tv_nsec
      || ![Sha256(bytes) isEqualToString:expectedSha256]) {
    Fail(@"A.28 pinned file changed during validation");
  }
  return bytes;
}

static NSString *SelfPath(void) {
  uint32_t length = PROC_PIDPATHINFO_MAXSIZE;
  char path[PROC_PIDPATHINFO_MAXSIZE] = {0};
  if (_NSGetExecutablePath(path, &length) != 0) {
    Fail(@"A.28 launcher executable path unavailable");
  }
  char canonical[PATH_MAX] = {0};
  if (realpath(path, canonical) == NULL) {
    Fail(@"A.28 launcher executable path rejected");
  }
  NSString *value = [NSString stringWithUTF8String:canonical];
  if (value == nil) Fail(@"A.28 launcher executable path invalid");
  return value;
}

static void AssertLauncherCode(
  NSString *path,
  NSString *requirementText,
  NSString *expectedCdHash,
  NSString *expectedTeamIdentifier
) {
  if (!IsCdHash(expectedCdHash)
      || expectedTeamIdentifier.length != 10U
      || ![requirementText containsString:
        [NSString stringWithFormat:@"identifier \"%@\"", A28LauncherIdentifier]]
      || ![requirementText containsString:@"anchor apple generic"]
      || (![requirementText containsString:[NSString stringWithFormat:
        @"certificate leaf[subject.OU] = %@", expectedTeamIdentifier]]
        && ![requirementText containsString:[NSString stringWithFormat:
          @"certificate leaf[subject.OU] = \"%@\"", expectedTeamIdentifier]])
      || [requirementText rangeOfString:
        @"(^|[^A-Za-z0-9_])(or|not|always|true)([^A-Za-z0-9_]|$)|!"
        options:NSRegularExpressionSearch | NSCaseInsensitiveSearch].location
        != NSNotFound) {
    Fail(@"A.28 launcher requirement rejected");
  }
  SecRequirementRef requirement = NULL;
  OSStatus status = SecRequirementCreateWithString(
    (__bridge CFStringRef)requirementText,
    kSecCSDefaultFlags,
    &requirement
  );
  if (status != errSecSuccess || requirement == NULL) {
    Fail(@"A.28 launcher requirement unavailable");
  }
  SecStaticCodeRef code = NULL;
  status = SecStaticCodeCreateWithPath(
    (__bridge CFURLRef)[NSURL fileURLWithPath:path],
    kSecCSDefaultFlags,
    &code
  );
  if (status != errSecSuccess || code == NULL) {
    CFRelease(requirement);
    Fail(@"A.28 launcher code identity unavailable");
  }
  status = SecStaticCodeCheckValidity(
    code,
    kSecCSStrictValidate | kSecCSCheckAllArchitectures,
    requirement
  );
  CFRelease(requirement);
  if (status != errSecSuccess) {
    CFRelease(code);
    Fail(@"A.28 launcher code signature rejected");
  }
  NSString *positiveRequirementText = [NSString stringWithFormat:
    @"anchor apple generic and identifier \"%@\" and certificate leaf[subject.OU] = \"%@\"",
    A28LauncherIdentifier,
    expectedTeamIdentifier];
  SecRequirementRef positiveRequirement = NULL;
  status = SecRequirementCreateWithString(
    (__bridge CFStringRef)positiveRequirementText,
    kSecCSDefaultFlags,
    &positiveRequirement
  );
  if (status != errSecSuccess || positiveRequirement == NULL) {
    CFRelease(code);
    Fail(@"A.28 launcher positive requirement unavailable");
  }
  status = SecStaticCodeCheckValidity(
    code,
    kSecCSStrictValidate | kSecCSCheckAllArchitectures,
    positiveRequirement
  );
  CFRelease(positiveRequirement);
  if (status != errSecSuccess) {
    CFRelease(code);
    Fail(@"A.28 launcher positive identity rejected");
  }
  CFDictionaryRef copied = NULL;
  status = SecCodeCopySigningInformation(
    code,
    kSecCSSigningInformation,
    &copied
  );
  CFRelease(code);
  if (status != errSecSuccess || copied == NULL) {
    Fail(@"A.28 launcher signing information unavailable");
  }
  NSDictionary *information = CFBridgingRelease(copied);
  NSString *identifier = information[(__bridge id)kSecCodeInfoIdentifier];
  NSData *cdHash = information[(__bridge id)kSecCodeInfoUnique];
  NSNumber *flags = information[(__bridge id)kSecCodeInfoFlags];
  NSString *teamIdentifier = information[(__bridge id)kSecCodeInfoTeamIdentifier];
  if (![identifier isEqualToString:A28LauncherIdentifier]
      || ![cdHash isKindOfClass:NSData.class]
      || cdHash.length != 20U
      || ![Hex(cdHash) isEqualToString:expectedCdHash]
      || ![teamIdentifier isEqualToString:expectedTeamIdentifier]
      || ![flags isKindOfClass:NSNumber.class]
      || (flags.unsignedIntValue & kSecCodeSignatureRuntime)
        != kSecCodeSignatureRuntime) {
    Fail(@"A.28 launcher hardened identity rejected");
  }
}

static NSData *ReadRootCanonicalConfig(NSString *path) {
  AssertRootPathChain(path, 0444);
  int descriptor = open(path.fileSystemRepresentation, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (descriptor < 0) Fail(@"A.28 launch config open failed");
  struct stat before = {0};
  struct stat after = {0};
  if (fstat(descriptor, &before) != 0
      || !S_ISREG(before.st_mode)
      || before.st_uid != 0
      || before.st_nlink != 1
      || (before.st_mode & 0777) != 0444
      || before.st_size < 3
      || before.st_size > 65536) {
    (void)close(descriptor);
    Fail(@"A.28 launch config identity rejected");
  }
  NSMutableData *bytes = [NSMutableData dataWithLength:(NSUInteger)before.st_size];
  NSUInteger offset = 0U;
  while (offset < bytes.length) {
    ssize_t count = read(
      descriptor,
      (unsigned char *)bytes.mutableBytes + offset,
      bytes.length - offset
    );
    if (count <= 0) {
      (void)close(descriptor);
      Fail(@"A.28 launch config read failed");
    }
    offset += (NSUInteger)count;
  }
  if (fstat(descriptor, &after) != 0
      || close(descriptor) != 0
      || before.st_dev != after.st_dev
      || before.st_ino != after.st_ino
      || before.st_size != after.st_size
      || before.st_mode != after.st_mode
      || before.st_mtimespec.tv_sec != after.st_mtimespec.tv_sec
      || before.st_mtimespec.tv_nsec != after.st_mtimespec.tv_nsec) {
    Fail(@"A.28 launch config changed during validation");
  }
  return bytes;
}

static NSDictionary *ParseLaunchConfig(NSData *line, NSString *mode) {
  if (line.length < 3U
      || ((const unsigned char *)line.bytes)[line.length - 1U] != '\n') {
    Fail(@"A.28 launch config framing rejected");
  }
  NSData *json = [line subdataWithRange:NSMakeRange(0U, line.length - 1U)];
  NSError *error = nil;
  id parsed = [NSJSONSerialization JSONObjectWithData:json options:0 error:&error];
  if (error != nil || ![parsed isKindOfClass:NSDictionary.class]) {
    Fail(@"A.28 launch config JSON rejected");
  }
  NSDictionary *config = parsed;
  NSSet *expected = [NSSet setWithArray:@[
    @"contractPath",
    @"contractSha256",
    @"entrypointPath",
    @"entrypointSha256",
    @"launcherCdHash",
    @"launcherDesignatedRequirement",
    @"launcherPath",
    @"launcherSha256",
    @"mode",
    @"nodePath",
    @"nodeSha256",
    @"schemaVersion",
    @"teamIdentifier",
  ]];
  if (![[NSSet setWithArray:config.allKeys] isEqualToSet:expected]
      || ![config[@"mode"] isEqualToString:mode]
      || ![config[@"schemaVersion"] isEqual:@1]) {
    Fail(@"A.28 launch config schema rejected");
  }
  NSData *canonical = [NSJSONSerialization
    dataWithJSONObject:config
    options:(NSJSONWritingSortedKeys | NSJSONWritingWithoutEscapingSlashes)
    error:&error];
  if (canonical == nil || error != nil) Fail(@"A.28 launch config canonicalisation failed");
  NSMutableData *canonicalLine = [canonical mutableCopy];
  const unsigned char newline = '\n';
  [canonicalLine appendBytes:&newline length:1U];
  if (![canonicalLine isEqualToData:line]) Fail(@"A.28 launch config is not canonical");
  return config;
}

static BOOL SafeAbsoluteArgument(NSString *value) {
  return [value hasPrefix:@"/"]
    && ![value containsString:@"\0"]
    && ![value containsString:@"\r"]
    && ![value containsString:@"\n"]
    && ![value.pathComponents containsObject:@".."];
}

static int RemainingPrepareMilliseconds(struct timespec started) {
  struct timespec current = {0};
  if (clock_gettime(CLOCK_MONOTONIC, &current) != 0) {
    Fail(@"A.28 launcher clock unavailable");
  }
  int64_t elapsed = (current.tv_sec - started.tv_sec) * 1000LL
    + (current.tv_nsec - started.tv_nsec) / 1000000LL;
  int64_t remaining = A28PrepareReadTimeoutMilliseconds - elapsed;
  if (remaining <= 0) return 0;
  return remaining > INT_MAX ? INT_MAX : (int)remaining;
}

static NSData *ReadBoundedPrepareRequest(void) {
  struct stat input = {0};
  if (fstat(STDIN_FILENO, &input) != 0
      || (!S_ISFIFO(input.st_mode)
        && !S_ISREG(input.st_mode)
        && !S_ISSOCK(input.st_mode))) {
    Fail(@"A.28 prepare request input rejected");
  }
  int flags = fcntl(STDIN_FILENO, F_GETFL);
  if (flags < 0 || fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK) != 0) {
    Fail(@"A.28 prepare request input flags rejected");
  }
  struct timespec started = {0};
  if (clock_gettime(CLOCK_MONOTONIC, &started) != 0) {
    Fail(@"A.28 launcher clock unavailable");
  }
  NSMutableData *bytes = [NSMutableData data];
  unsigned char chunk[4096] = {0};
  while (YES) {
    int remaining = RemainingPrepareMilliseconds(started);
    if (remaining == 0) Fail(@"A.28 prepare request timed out");
    struct pollfd observed = {
      .fd = STDIN_FILENO,
      .events = POLLIN | POLLHUP,
      .revents = 0,
    };
    int ready = poll(&observed, 1, remaining);
    if (ready < 0 && errno == EINTR) continue;
    if (ready <= 0 || (observed.revents & (POLLERR | POLLNVAL)) != 0) {
      Fail(@"A.28 prepare request input failed");
    }
    ssize_t count = read(STDIN_FILENO, chunk, sizeof(chunk));
    if (count < 0 && (errno == EAGAIN || errno == EINTR)) continue;
    if (count < 0) Fail(@"A.28 prepare request read failed");
    if (count == 0) break;
    if (bytes.length + (NSUInteger)count > A28MaximumChallengeRequestBytes) {
      Fail(@"A.28 prepare request is too large");
    }
    [bytes appendBytes:chunk length:(NSUInteger)count];
  }
  if (bytes.length < 3U
      || ((const unsigned char *)bytes.bytes)[bytes.length - 1U] != '\n') {
    Fail(@"A.28 prepare request framing rejected");
  }
  const unsigned char *raw = bytes.bytes;
  for (NSUInteger index = 0U; index + 1U < bytes.length; index += 1U) {
    if (raw[index] == '\0' || raw[index] == '\r' || raw[index] == '\n') {
      Fail(@"A.28 prepare request framing rejected");
    }
  }
  return bytes;
}

static NSString *CreateRootPrepareRequest(NSData *bytes) {
  AssertRootDirectory(A28CheckpointPrivateDirectory, 0700);
  int directory = open(
    A28CheckpointPrivateDirectory.fileSystemRepresentation,
    O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_DIRECTORY
  );
  struct stat directoryIdentity = {0};
  if (directory < 0
      || fstat(directory, &directoryIdentity) != 0
      || !S_ISDIR(directoryIdentity.st_mode)
      || directoryIdentity.st_uid != 0
      || directoryIdentity.st_gid != 0
      || (directoryIdentity.st_mode & 0777) != 0700) {
    if (directory >= 0) (void)close(directory);
    Fail(@"A.28 prepare request directory rejected");
  }
  unsigned char nonce[32] = {0};
  if (SecRandomCopyBytes(kSecRandomDefault, sizeof(nonce), nonce) != errSecSuccess) {
    (void)close(directory);
    Fail(@"A.28 prepare request nonce failed");
  }
  NSString *name = [NSString stringWithFormat:
    @"request-%@.json",
    Hex([NSData dataWithBytes:nonce length:sizeof(nonce)])];
  int descriptor = openat(
    directory,
    name.fileSystemRepresentation,
    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
    0600
  );
  struct stat initial = {0};
  if (descriptor < 0
      || fstat(descriptor, &initial) != 0
      || !S_ISREG(initial.st_mode)
      || initial.st_uid != 0
      || initial.st_gid != 0
      || initial.st_nlink != 1
      || (initial.st_mode & 0777) != 0600
      || initial.st_size != 0) {
    if (descriptor >= 0) (void)close(descriptor);
    (void)close(directory);
    Fail(@"A.28 prepare request slot rejected");
  }
  NSUInteger offset = 0U;
  while (offset < bytes.length) {
    ssize_t count = write(
      descriptor,
      (const unsigned char *)bytes.bytes + offset,
      bytes.length - offset
    );
    if (count <= 0) {
      (void)close(descriptor);
      (void)close(directory);
      Fail(@"A.28 prepare request publication failed");
    }
    offset += (NSUInteger)count;
  }
  struct stat held = {0};
  struct stat pathname = {0};
  if (fchmod(descriptor, 0400) != 0
      || fsync(descriptor) != 0
      || fstat(descriptor, &held) != 0
      || fstatat(directory, name.fileSystemRepresentation, &pathname,
        AT_SYMLINK_NOFOLLOW) != 0
      || !S_ISREG(held.st_mode)
      || S_ISLNK(pathname.st_mode)
      || held.st_dev != pathname.st_dev
      || held.st_ino != pathname.st_ino
      || held.st_nlink != 1
      || pathname.st_nlink != 1
      || held.st_uid != 0
      || held.st_gid != 0
      || (held.st_mode & 0777) != 0400
      || held.st_size != (off_t)bytes.length
      || held.st_mode != pathname.st_mode
      || held.st_size != pathname.st_size
      || held.st_mtimespec.tv_sec != pathname.st_mtimespec.tv_sec
      || held.st_mtimespec.tv_nsec != pathname.st_mtimespec.tv_nsec
      || held.st_ctimespec.tv_sec != pathname.st_ctimespec.tv_sec
      || held.st_ctimespec.tv_nsec != pathname.st_ctimespec.tv_nsec
      || fsync(directory) != 0
      || close(descriptor) != 0
      || close(directory) != 0) {
    Fail(@"A.28 prepare request identity changed");
  }
  return [A28CheckpointPrivateDirectory
    stringByAppendingPathComponent:name];
}

static void CloseInheritedDescriptors(void) {
  struct rlimit limits = {0};
  if (getrlimit(RLIMIT_NOFILE, &limits) != 0) {
    Fail(@"A.28 launcher descriptor limit unavailable");
  }
  rlim_t maximum = limits.rlim_cur;
  if (maximum == RLIM_INFINITY || maximum > 1048576U) maximum = 1048576U;
  for (int descriptor = 3; (rlim_t)descriptor < maximum; descriptor += 1) {
    (void)close(descriptor);
  }
}

static void ResetEnvironment(void) {
  static char *emptyEnvironment[] = {NULL};
  environ = emptyEnvironment;
  if (setenv("PATH", "/usr/bin:/bin", 1) != 0
      || setenv("HOME", "/var/root", 1) != 0
      || setenv("LANG", "C", 1) != 0
      || setenv("LC_ALL", "C", 1) != 0) {
    Fail(@"A.28 launcher environment scrub failed");
  }
}

static NSArray<NSString *> *ValidatedEntrypointArguments(
  NSArray<NSString *> *arguments,
  NSString *mode
) {
  if ([mode isEqualToString:@"enrol"] && arguments.count == 3U) return @[];
  if ([mode isEqualToString:@"checkpoint"]
      && arguments.count == 5U
      && [arguments[3] isEqualToString:@"--action"]
      && [arguments[4] isEqualToString:@"prepare"]) {
    return @[@"--action", @"prepare"];
  }
  if ([mode isEqualToString:@"checkpoint"]
      && arguments.count == 9U
      && [arguments[3] isEqualToString:@"--action"]
      && [arguments[4] isEqualToString:@"authorise"]
      && [arguments[5] isEqualToString:@"--input"]
      && SafeAbsoluteArgument(arguments[6])
      && [arguments[7] isEqualToString:@"--output"]
      && SafeAbsoluteArgument(arguments[8])) {
    return [arguments subarrayWithRange:NSMakeRange(3U, 6U)];
  }
  if ([mode isEqualToString:@"checkpoint"]
      && arguments.count == 11U
      && [arguments[3] isEqualToString:@"--action"]
      && [arguments[4] isEqualToString:@"reveal"]
      && [arguments[5] isEqualToString:@"--input"]
      && SafeAbsoluteArgument(arguments[6])
      && [arguments[7] isEqualToString:@"--output"]
      && SafeAbsoluteArgument(arguments[8])
      && [arguments[9] isEqualToString:@"--witness-pid"]
      && [arguments[10] integerValue] >= 2) {
    return [arguments subarrayWithRange:NSMakeRange(3U, 8U)];
  }
  if ([mode isEqualToString:@"verify"]
      && arguments.count == 9U
      && [arguments[3] isEqualToString:@"--attestation"]
      && SafeAbsoluteArgument(arguments[4])
      && [arguments[5] isEqualToString:@"--challenge"]
      && SafeAbsoluteArgument(arguments[6])
      && [arguments[7] isEqualToString:@"--expected-challenge-sha256"]
      && IsSha256(arguments[8])) {
    return [arguments subarrayWithRange:NSMakeRange(3U, 6U)];
  }
  Fail(@"A.28 launcher arguments rejected");
  return @[];
}

int main(int argc, const char *argv[]) {
  @autoreleasepool {
    if (getuid() != 0 || geteuid() != 0 || argc < 3
        || strcmp(argv[1], "--mode") != 0) {
      Fail(@"A.28 root launcher requires root and an exact mode");
    }
    NSString *mode = [NSString stringWithUTF8String:argv[2]];
    NSDictionary *configPaths = @{
      @"checkpoint": [A28SupportRoot
        stringByAppendingString:@"launcher/checkpoint-launch.json"],
      @"enrol": [A28SupportRoot
        stringByAppendingString:@"launcher/enrolment-launch.json"],
      @"verify": [A28SupportRoot
        stringByAppendingString:@"launcher/verifier-launch.json"],
    };
    NSString *configPath = configPaths[mode];
    if (configPath == nil) Fail(@"A.28 launcher mode rejected");
    NSMutableArray<NSString *> *arguments = [NSMutableArray arrayWithCapacity:(NSUInteger)argc];
    for (int index = 0; index < argc; index += 1) {
      NSString *argument = [NSString stringWithUTF8String:argv[index]];
      if (argument == nil) Fail(@"A.28 launcher argument encoding rejected");
      [arguments addObject:argument];
    }
    NSArray<NSString *> *entrypointArguments = ValidatedEntrypointArguments(
      arguments,
      mode
    );
    NSDictionary *config = ParseLaunchConfig(
      ReadRootCanonicalConfig(configPath),
      mode
    );
    NSString *selfPath = SelfPath();
    if (![selfPath isEqualToString:config[@"launcherPath"]]) {
      Fail(@"A.28 launcher path did not match its root config");
    }
    (void)ReadPinnedFile(selfPath, 0555, config[@"launcherSha256"]);
    AssertLauncherCode(
      selfPath,
      config[@"launcherDesignatedRequirement"],
      config[@"launcherCdHash"],
      config[@"teamIdentifier"]
    );
    (void)ReadPinnedFile(config[@"nodePath"], 0500, config[@"nodeSha256"]);
    (void)ReadPinnedFile(
      config[@"entrypointPath"],
      0444,
      config[@"entrypointSha256"]
    );
    (void)ReadPinnedFile(
      config[@"contractPath"],
      0444,
      config[@"contractSha256"]
    );
    if ([mode isEqualToString:@"checkpoint"]
        && entrypointArguments.count == 2U
        && [entrypointArguments[1] isEqualToString:@"prepare"]) {
      NSData *notice = [@"[working] Waiting for one complete A.28 challenge request on standard input.\n"
        dataUsingEncoding:NSUTF8StringEncoding];
      if (write(STDERR_FILENO, notice.bytes, notice.length)
          != (ssize_t)notice.length) {
        Fail(@"A.28 launcher loading indicator failed");
      }
      NSString *requestPath = CreateRootPrepareRequest(
        ReadBoundedPrepareRequest()
      );
      entrypointArguments = @[
        @"--action",
        @"prepare",
        @"--input",
        requestPath,
        @"--output",
        A28CheckpointCommitmentDirectory,
      ];
    }
    if (chdir("/private/var/empty") != 0) Fail(@"A.28 launcher cwd rejected");
    (void)umask(077);
    CloseInheritedDescriptors();
    ResetEnvironment();
    NSMutableArray<NSString *> *execArguments = [NSMutableArray arrayWithObjects:
      config[@"nodePath"],
      config[@"entrypointPath"],
      nil];
    [execArguments addObjectsFromArray:entrypointArguments];
    char *execArgv[12] = {0};
    if (execArguments.count >= 12U) Fail(@"A.28 launcher argv capacity rejected");
    for (NSUInteger index = 0; index < execArguments.count; index += 1U) {
      execArgv[index] = (char *)[execArguments[index] fileSystemRepresentation];
    }
    execve(
      [config[@"nodePath"] fileSystemRepresentation],
      execArgv,
      environ
    );
    Fail(@"A.28 launcher execve failed");
  }
}
