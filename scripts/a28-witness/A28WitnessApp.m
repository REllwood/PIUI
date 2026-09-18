#import <AppKit/AppKit.h>
#import <CommonCrypto/CommonDigest.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <Security/Security.h>
#include <bsm/audit.h>
#include <fcntl.h>
#include <libproc.h>
#include <limits.h>
#include <mach/mach.h>
#include <mach/task_info.h>
#include <sys/stat.h>
#include <unistd.h>

static NSString *const A28BundleIdentifier = @"au.com.piui.a28-witness";
static NSString *const A28WitnessDomain =
  @"au.com.piui.a28.voiceover-witness.v1";
static NSString *const A28EnrolmentDomain =
  @"au.com.piui.a28.secure-enclave-enrolment.v1";
static NSString *const A28KeyApplicationTag =
  @"au.com.piui.a28-witness.secure-enclave.v1";
static NSString *const A28VoiceOverApplicationPath =
  @"/System/Library/CoreServices/VoiceOver.app";
static NSString *const A28GateContextAuthority =
  @"external-final-consumer-required";
static NSString *const A28HumanAssertionScope =
  @"reviewer-reported-voiceover-behaviour-only;excludes-run-source-artifact-fingerprint-authentication";
static const NSUInteger A28MaximumInputBytes = 65536U;

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
  unsigned char digest[CC_SHA256_DIGEST_LENGTH] = {0};
  if (data.length > UINT32_MAX
      || CC_SHA256(data.bytes, (CC_LONG)data.length, digest) == NULL) {
    Fail(@"A.28 SHA-256 failed");
  }
  return Hex([NSData dataWithBytes:digest length:sizeof(digest)]);
}

static NSData *CanonicalJson(id value) {
  NSError *error = nil;
  NSData *bytes = [NSJSONSerialization
    dataWithJSONObject:value
    options:(NSJSONWritingSortedKeys | NSJSONWritingWithoutEscapingSlashes)
    error:&error];
  if (bytes == nil || error != nil) Fail(@"A.28 canonical JSON failed");
  return bytes;
}

static NSString *IsoInstant(void) {
  NSISO8601DateFormatter *formatter = [[NSISO8601DateFormatter alloc] init];
  formatter.formatOptions = NSISO8601DateFormatWithInternetDateTime
    | NSISO8601DateFormatWithFractionalSeconds;
  formatter.timeZone = [NSTimeZone timeZoneForSecondsFromGMT:0];
  return [formatter stringFromDate:[NSDate date]];
}

static BOOL IsSha256(id value) {
  if (![value isKindOfClass:NSString.class] || [value length] != 64U) return NO;
  NSCharacterSet *invalid = [[NSCharacterSet
    characterSetWithCharactersInString:@"0123456789abcdef"] invertedSet];
  return [value rangeOfCharacterFromSet:invalid].location == NSNotFound;
}

static NSData *ReadHeldCanonicalFile(NSString *path) {
  if (![path hasPrefix:@"/"]) Fail(@"A.28 input path rejected");
  int descriptor = open(path.fileSystemRepresentation, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (descriptor < 0) Fail(@"A.28 input open failed");
  struct stat before = {0};
  struct stat after = {0};
  if (fstat(descriptor, &before) != 0
      || !S_ISREG(before.st_mode)
      || before.st_nlink != 1
      || before.st_size < 3
      || before.st_size > (off_t)A28MaximumInputBytes) {
    (void)close(descriptor);
    Fail(@"A.28 input identity rejected");
  }
  NSMutableData *bytes = [NSMutableData dataWithLength:(NSUInteger)before.st_size];
  NSUInteger offset = 0;
  while (offset < bytes.length) {
    ssize_t count = read(
      descriptor,
      (unsigned char *)bytes.mutableBytes + offset,
      bytes.length - offset
    );
    if (count <= 0) {
      (void)close(descriptor);
      Fail(@"A.28 input read failed");
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
    Fail(@"A.28 input changed during read");
  }
  const unsigned char *raw = bytes.bytes;
  if (raw[bytes.length - 1U] != '\n'
      || memchr(raw, '\0', bytes.length) != NULL
      || memchr(raw, '\r', bytes.length) != NULL
      || memchr(raw, '\n', bytes.length - 1U) != NULL) {
    Fail(@"A.28 input framing rejected");
  }
  NSData *jsonBytes = [bytes subdataWithRange:NSMakeRange(0, bytes.length - 1U)];
  NSError *error = nil;
  id value = [NSJSONSerialization JSONObjectWithData:jsonBytes options:0 error:&error];
  if (error != nil
      || ![value isKindOfClass:NSDictionary.class]
      || ![CanonicalJson(value) isEqualToData:jsonBytes]) {
    Fail(@"A.28 input canonical form rejected");
  }
  return bytes;
}

static NSDictionary *HeldExecutableIdentity(NSString *path) {
  int descriptor = open(path.fileSystemRepresentation, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (descriptor < 0) Fail(@"A.28 witness executable open failed");
  struct stat before = {0};
  struct stat after = {0};
  if (fstat(descriptor, &before) != 0
      || !S_ISREG(before.st_mode)
      || before.st_nlink != 1
      || before.st_size < 8192
      || before.st_size > (off_t)(1024U * 1024U * 1024U)) {
    (void)close(descriptor);
    Fail(@"A.28 witness executable identity rejected");
  }
  NSMutableData *bytes = [NSMutableData dataWithLength:(NSUInteger)before.st_size];
  NSUInteger offset = 0;
  while (offset < bytes.length) {
    ssize_t count = read(
      descriptor,
      (unsigned char *)bytes.mutableBytes + offset,
      bytes.length - offset
    );
    if (count <= 0) {
      (void)close(descriptor);
      Fail(@"A.28 witness executable read failed");
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
    Fail(@"A.28 witness executable changed during inspection");
  }
  return @{
    @"dev": @((unsigned long long)before.st_dev),
    @"ino": @((unsigned long long)before.st_ino),
    @"path": path,
    @"sha256": Sha256(bytes),
    @"size": @((unsigned long long)before.st_size),
  };
}

static NSDictionary *SelfProcessIdentity(void) {
  pid_t pid = getpid();
  struct proc_bsdinfo process = {0};
  if (proc_pidinfo(
      pid,
      PROC_PIDTBSDINFO,
      0,
      &process,
      sizeof(process)
    ) != sizeof(process)
      || process.pbi_start_tvusec > 999999) {
    Fail(@"A.28 witness start identity unavailable");
  }
  char rawPath[PROC_PIDPATHINFO_MAXSIZE] = {0};
  int pathLength = proc_pidpath(pid, rawPath, sizeof(rawPath));
  if (pathLength < 2 || pathLength >= (int)sizeof(rawPath)) {
    Fail(@"A.28 witness executable path unavailable");
  }
  NSString *path = [[NSFileManager defaultManager]
    stringWithFileSystemRepresentation:rawPath
    length:(NSUInteger)pathLength];
  audit_token_t auditToken = {0};
  mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
  if (task_info(
      mach_task_self(),
      TASK_AUDIT_TOKEN,
      (task_info_t)&auditToken,
      &count
    ) != KERN_SUCCESS
      || count != TASK_AUDIT_TOKEN_COUNT) {
    Fail(@"A.28 witness audit identity unavailable");
  }
  SecCodeRef code = NULL;
  if (SecCodeCopySelf(kSecCSDefaultFlags, &code) != errSecSuccess
      || code == NULL) {
    Fail(@"A.28 witness code identity unavailable");
  }
  CFDictionaryRef copied = NULL;
  OSStatus status = SecCodeCopySigningInformation(
    code,
    kSecCSSigningInformation | kSecCSRequirementInformation,
    &copied
  );
  CFRelease(code);
  if (status != errSecSuccess || copied == NULL) {
    Fail(@"A.28 witness signing identity unavailable");
  }
  NSDictionary *signing = CFBridgingRelease(copied);
  NSString *identifier = signing[(__bridge id)kSecCodeInfoIdentifier];
  NSData *cdHash = signing[(__bridge id)kSecCodeInfoUnique];
  SecRequirementRef requirement = (__bridge SecRequirementRef)
    signing[(__bridge id)kSecCodeInfoDesignatedRequirement];
  if (![identifier isKindOfClass:NSString.class]
      || ![identifier isEqual:A28BundleIdentifier]
      || ![cdHash isKindOfClass:NSData.class]
      || cdHash.length != 20U
      || requirement == NULL) {
    Fail(@"A.28 witness live code identity rejected");
  }
  CFStringRef copiedRequirement = NULL;
  status = SecRequirementCopyString(
    requirement,
    kSecCSDefaultFlags,
    &copiedRequirement
  );
  if (status != errSecSuccess || copiedRequirement == NULL) {
    Fail(@"A.28 witness designated requirement unavailable");
  }
  NSString *designatedRequirement = CFBridgingRelease(copiedRequirement);
  return @{
    @"auditTokenSha256": Sha256(
      [NSData dataWithBytes:&auditToken length:sizeof(auditToken)]
    ),
    @"bundleIdentifier": identifier,
    @"cdHash": Hex(cdHash),
    @"designatedRequirement": designatedRequirement,
    @"executable": HeldExecutableIdentity(path),
    @"pid": @(pid),
    @"startTime": [NSString stringWithFormat:
      @"%llu.%06llu",
      process.pbi_start_tvsec,
      process.pbi_start_tvusec],
  };
}

static BOOL VoiceOverIsRunning(void) {
  for (NSRunningApplication *application
      in NSWorkspace.sharedWorkspace.runningApplications) {
    if ([application.bundleIdentifier isEqual:@"com.apple.VoiceOver"]
        && [application.bundleURL.path isEqual:A28VoiceOverApplicationPath]
        && !application.terminated) {
      return YES;
    }
  }
  return NO;
}

static NSDictionary *ParseChallenge(NSData *line) {
  NSData *jsonBytes = [line subdataWithRange:NSMakeRange(0, line.length - 1U)];
  NSDictionary *challenge = [NSJSONSerialization
    JSONObjectWithData:jsonBytes
    options:0
    error:NULL];
  NSArray *keys = @[
    @"applicationPid",
    @"architectureGateRunContextSha256",
    @"architectureGateRunId",
    @"attestationSlot",
    @"automationTwinFingerprint",
    @"challengeExpiresAt",
    @"challengeIssuedAt",
    @"challengeRequestSha256",
    @"checkpointSessionId",
    @"gateId",
    @"gateContextAuthority",
    @"hostAuditTokenSha256",
    @"hostBundleFingerprint",
    @"hostBundleIdentifier",
    @"hostBundlePath",
    @"hostCdHash",
    @"hostDesignatedRequirement",
    @"hostExecutable",
    @"hostStartTime",
    @"macosVersion",
    @"measuredTwinDeltaSha256",
    @"policyPinSha256",
    @"productionFingerprint",
    @"reviewerIdentity",
    @"reviewerKeyId",
    @"runnerAuditTokenSha256",
    @"runnerAuthority",
    @"runnerBundleIdentifier",
    @"runnerCdHash",
    @"runnerDesignatedRequirement",
    @"runnerExecutable",
    @"runnerPid",
    @"runnerStartTime",
    @"schemaVersion",
    @"sourceDigest",
    @"stateCheckpoints",
    @"voiceOverAuditTokenSha256",
    @"voiceOverBundleIdentifier",
    @"voiceOverCdHash",
    @"voiceOverDesignatedRequirement",
    @"voiceOverExecutable",
    @"voiceOverPid",
    @"voiceOverStartTime",
    @"voiceOverVersion",
    @"witnessNonce",
  ];
  NSSet *expected = [NSSet setWithArray:keys];
  if (![challenge isKindOfClass:NSDictionary.class]
      || ![[NSSet setWithArray:challenge.allKeys] isEqualToSet:expected]
      || ![challenge[@"schemaVersion"] isEqual:@1]
      || ![challenge[@"gateId"] isEqual:@"A.28"]
      || ![challenge[@"applicationPid"] isKindOfClass:NSNumber.class]
      || [challenge[@"applicationPid"] integerValue] < 2
      || ![challenge[@"runnerPid"] isKindOfClass:NSNumber.class]
      || [challenge[@"runnerPid"] integerValue] < 2
      || ![challenge[@"runnerAuthority"] isEqual:@"continuity-only"]
      || ![challenge[@"gateContextAuthority"]
        isEqual:A28GateContextAuthority]
      || ![challenge[@"voiceOverPid"] isKindOfClass:NSNumber.class]
      || [challenge[@"voiceOverPid"] integerValue] < 2
      || ![challenge[@"voiceOverBundleIdentifier"]
        isEqual:@"com.apple.VoiceOver"]
      || ![challenge[@"hostBundleIdentifier"]
        isEqual:@"au.com.piui.desktop.architecture-test"]) {
    Fail(@"A.28 challenge contract rejected");
  }
  NSArray *digests = @[
    challenge[@"architectureGateRunContextSha256"],
    challenge[@"automationTwinFingerprint"],
    challenge[@"challengeRequestSha256"],
    challenge[@"checkpointSessionId"],
    challenge[@"hostAuditTokenSha256"],
    challenge[@"hostBundleFingerprint"],
    challenge[@"measuredTwinDeltaSha256"],
    challenge[@"policyPinSha256"],
    challenge[@"productionFingerprint"],
    challenge[@"reviewerKeyId"],
    challenge[@"runnerAuditTokenSha256"],
    challenge[@"sourceDigest"],
    challenge[@"voiceOverAuditTokenSha256"],
    challenge[@"witnessNonce"],
  ];
  for (id digest in digests) {
    if (!IsSha256(digest)) Fail(@"A.28 challenge digest rejected");
  }
  NSDictionary *attestationSlot = challenge[@"attestationSlot"];
  NSSet *slotKeys = [NSSet setWithArray:
    @[@"dev", @"gid", @"ino", @"path", @"uid"]];
  if (![attestationSlot isKindOfClass:NSDictionary.class]
      || ![[NSSet setWithArray:attestationSlot.allKeys] isEqualToSet:slotKeys]
      || ![attestationSlot[@"dev"] isKindOfClass:NSNumber.class]
      || [attestationSlot[@"dev"] unsignedLongLongValue] < 1U
      || ![attestationSlot[@"ino"] isKindOfClass:NSNumber.class]
      || [attestationSlot[@"ino"] unsignedLongLongValue] < 1U
      || ![attestationSlot[@"uid"] isEqual:@(getuid())]
      || ![attestationSlot[@"gid"] isKindOfClass:NSNumber.class]
      || ![attestationSlot[@"path"] isKindOfClass:NSString.class]
      || ![attestationSlot[@"path"] hasPrefix:
        @"/Library/Application Support/PIUI/A28Witness/checkpoint-deliveries/"]
      || ![attestationSlot[@"path"] hasSuffix:@".attestation.json"]
      || [attestationSlot[@"path"] containsString:@"\0"]
      || [attestationSlot[@"path"] containsString:@"\r"]
      || [attestationSlot[@"path"] containsString:@"\n"]) {
    Fail(@"A.28 attestation output slot rejected");
  }
  if (![challenge[@"hostBundleFingerprint"]
      isEqual:challenge[@"automationTwinFingerprint"]]
      || [challenge[@"productionFingerprint"]
        isEqual:challenge[@"automationTwinFingerprint"]]) {
    Fail(@"A.28 challenge artefact identity rejected");
  }
  NSDictionary *executable = challenge[@"hostExecutable"];
  NSSet *executableKeys = [NSSet setWithArray:
    @[@"dev", @"ino", @"path", @"sha256", @"size"]];
  if (![executable isKindOfClass:NSDictionary.class]
      || ![[NSSet setWithArray:executable.allKeys] isEqualToSet:executableKeys]
      || !IsSha256(executable[@"sha256"])
      || ![executable[@"path"] isKindOfClass:NSString.class]
      || ![executable[@"path"] hasPrefix:@"/"]) {
    Fail(@"A.28 challenge executable identity rejected");
  }
  NSDictionary *runnerExecutable = challenge[@"runnerExecutable"];
  NSDictionary *voiceOverExecutable = challenge[@"voiceOverExecutable"];
  if (![runnerExecutable isKindOfClass:NSDictionary.class]
      || ![[NSSet setWithArray:runnerExecutable.allKeys]
        isEqualToSet:executableKeys]
      || !IsSha256(runnerExecutable[@"sha256"])
      || ![runnerExecutable[@"path"] isKindOfClass:NSString.class]
      || ![runnerExecutable[@"path"] hasPrefix:@"/"]
      || ![challenge[@"hostCdHash"] isKindOfClass:NSString.class]
      || [challenge[@"hostCdHash"] length] != 40U
      || ![challenge[@"runnerCdHash"] isKindOfClass:NSString.class]
      || [challenge[@"runnerCdHash"] length] != 40U
      || ![challenge[@"runnerBundleIdentifier"] isKindOfClass:NSString.class]) {
    Fail(@"A.28 challenge runner identity rejected");
  }
  if (![voiceOverExecutable isKindOfClass:NSDictionary.class]
      || ![[NSSet setWithArray:voiceOverExecutable.allKeys]
        isEqualToSet:executableKeys]
      || !IsSha256(voiceOverExecutable[@"sha256"])
      || ![voiceOverExecutable[@"path"] isEqual:
        @"/System/Library/CoreServices/VoiceOver.app/Contents/MacOS/VoiceOver"]
      || ![challenge[@"voiceOverCdHash"] isKindOfClass:NSString.class]
      || [challenge[@"voiceOverCdHash"] length] != 40U) {
    Fail(@"A.28 challenge VoiceOver identity rejected");
  }
  NSArray *checkpoints = challenge[@"stateCheckpoints"];
  NSArray *appearances = @[@"dark", @"dark", @"light", @"light"];
  NSArray *modes = @[@"accessible", @"virtualised", @"accessible", @"virtualised"];
  NSMutableSet *checkpointIds = [NSMutableSet set];
  NSMutableSet *commitments = [NSMutableSet set];
  NSSet *checkpointKeys = [NSSet setWithArray:
    @[@"appearance", @"checkpointId", @"mode", @"ordinal", @"tokenSha256"]];
  if (![checkpoints isKindOfClass:NSArray.class] || checkpoints.count != 4U) {
    Fail(@"A.28 challenge checkpoints rejected");
  }
  for (NSUInteger index = 0U; index < checkpoints.count; index += 1U) {
    NSDictionary *checkpoint = checkpoints[index];
    if (![checkpoint isKindOfClass:NSDictionary.class]
        || ![[NSSet setWithArray:checkpoint.allKeys] isEqualToSet:checkpointKeys]
        || ![checkpoint[@"appearance"] isEqual:appearances[index]]
        || ![checkpoint[@"mode"] isEqual:modes[index]]
        || ![checkpoint[@"ordinal"] isEqual:@(index + 1U)]
        || !IsSha256(checkpoint[@"checkpointId"])
        || !IsSha256(checkpoint[@"tokenSha256"])
        || [checkpointIds containsObject:checkpoint[@"checkpointId"]]
        || [commitments containsObject:checkpoint[@"tokenSha256"]]) {
      Fail(@"A.28 challenge checkpoint order rejected");
    }
    [checkpointIds addObject:checkpoint[@"checkpointId"]];
    [commitments addObject:checkpoint[@"tokenSha256"]];
  }
  NSISO8601DateFormatter *dateFormatter = [[NSISO8601DateFormatter alloc] init];
  dateFormatter.formatOptions = NSISO8601DateFormatWithInternetDateTime
    | NSISO8601DateFormatWithFractionalSeconds;
  NSDate *issued = [dateFormatter dateFromString:challenge[@"challengeIssuedAt"]];
  NSDate *expires = [dateFormatter dateFromString:challenge[@"challengeExpiresAt"]];
  NSTimeInterval window = [expires timeIntervalSinceDate:issued];
  if (issued == nil
      || expires == nil
      || window <= 0
      || window > 30.0 * 60.0
      || [expires timeIntervalSinceNow] < -300.0) {
    Fail(@"A.28 challenge freshness rejected");
  }
  return challenge;
}

static NSString *CopyKeychainAccessGroup(void) {
  SecTaskRef task = SecTaskCreateFromSelf(kCFAllocatorDefault);
  if (task == NULL) Fail(@"A.28 signing task unavailable");
  CFErrorRef copiedError = NULL;
  CFTypeRef copied = SecTaskCopyValueForEntitlement(
    task,
    CFSTR("keychain-access-groups"),
    &copiedError
  );
  CFRelease(task);
  if (copiedError != NULL) CFRelease(copiedError);
  NSArray *groups = CFBridgingRelease(copied);
  if (![groups isKindOfClass:NSArray.class]
      || groups.count != 1U
      || ![groups[0] isKindOfClass:NSString.class]
      || ![groups[0] hasSuffix:
        @".au.com.piui.a28-witness.secure-enclave"]) {
    Fail(@"A.28 dedicated keychain group unavailable");
  }
  return groups[0];
}

static SecKeyRef CopySecureEnclaveKey(NSString *prompt) {
  NSData *tag = [A28KeyApplicationTag dataUsingEncoding:NSUTF8StringEncoding];
  NSString *accessGroup = CopyKeychainAccessGroup();
  LAContext *authenticationContext = [[LAContext alloc] init];
  authenticationContext.localizedReason = prompt;
  NSDictionary *query = @{
    (__bridge id)kSecClass: (__bridge id)kSecClassKey,
    (__bridge id)kSecAttrApplicationTag: tag,
    (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeECSECPrimeRandom,
    (__bridge id)kSecAttrAccessGroup: accessGroup,
    (__bridge id)kSecAttrTokenID: (__bridge id)kSecAttrTokenIDSecureEnclave,
    (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitAll,
    (__bridge id)kSecReturnRef: @YES,
    (__bridge id)kSecUseAuthenticationContext: authenticationContext,
    (__bridge id)kSecUseDataProtectionKeychain: @YES,
  };
  CFTypeRef copied = NULL;
  OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &copied);
  NSArray *keys = CFBridgingRelease(copied);
  if (status != errSecSuccess
      || ![keys isKindOfClass:NSArray.class]
      || keys.count != 1U
      || CFGetTypeID((__bridge CFTypeRef)keys[0]) != SecKeyGetTypeID()) {
    Fail(@"A.28 Secure Enclave key unavailable");
  }
  SecKeyRef key = (__bridge SecKeyRef)keys[0];
  CFRetain(key);
  return key;
}

static void RejectExistingSecureEnclaveKey(NSString *accessGroup, NSData *tag) {
  NSDictionary *query = @{
    (__bridge id)kSecClass: (__bridge id)kSecClassKey,
    (__bridge id)kSecAttrApplicationTag: tag,
    (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeECSECPrimeRandom,
    (__bridge id)kSecAttrAccessGroup: accessGroup,
    (__bridge id)kSecAttrTokenID: (__bridge id)kSecAttrTokenIDSecureEnclave,
    (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitAll,
    (__bridge id)kSecReturnAttributes: @YES,
    (__bridge id)kSecUseDataProtectionKeychain: @YES,
  };
  CFTypeRef copied = NULL;
  OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &copied);
  if (copied != NULL) CFRelease(copied);
  if (status == errSecSuccess) {
    Fail(@"A.28 Secure Enclave key is already enrolled");
  }
  if (status != errSecItemNotFound) {
    Fail(@"A.28 Secure Enclave duplicate-key check failed");
  }
}

static NSDictionary *VerifiedSecureEnclaveKeyAttributes(
  SecKeyRef key,
  NSString *accessGroup,
  NSData *tag
) {
  CFDictionaryRef copiedKeyAttributes = SecKeyCopyAttributes(key);
  if (copiedKeyAttributes == NULL) {
    Fail(@"A.28 Secure Enclave key attributes unavailable");
  }
  NSDictionary *keyAttributes = CFBridgingRelease(copiedKeyAttributes);
  NSDictionary *query = @{
    (__bridge id)kSecClass: (__bridge id)kSecClassKey,
    (__bridge id)kSecAttrApplicationTag: tag,
    (__bridge id)kSecAttrAccessGroup: accessGroup,
    (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeECSECPrimeRandom,
    (__bridge id)kSecAttrTokenID: (__bridge id)kSecAttrTokenIDSecureEnclave,
    (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitOne,
    (__bridge id)kSecReturnAttributes: @YES,
    (__bridge id)kSecReturnRef: @YES,
    (__bridge id)kSecUseDataProtectionKeychain: @YES,
  };
  CFTypeRef copiedResult = NULL;
  OSStatus status = SecItemCopyMatching(
    (__bridge CFDictionaryRef)query,
    &copiedResult
  );
  NSDictionary *storedAttributes = CFBridgingRelease(copiedResult);
  id storedKey = storedAttributes[(__bridge id)kSecValueRef];
  id storedAccessControl = storedAttributes[(__bridge id)kSecAttrAccessControl];
  BOOL permanent = [keyAttributes[(__bridge id)kSecAttrIsPermanent] boolValue]
    || [storedAttributes[(__bridge id)kSecAttrIsPermanent] boolValue];
  if (status != errSecSuccess
      || ![storedAttributes isKindOfClass:NSDictionary.class]
      || storedKey == nil
      || CFGetTypeID((__bridge CFTypeRef)storedKey) != SecKeyGetTypeID()
      || !CFEqual((__bridge SecKeyRef)storedKey, key)
      || storedAccessControl == nil
      || ![storedAttributes[(__bridge id)kSecAttrApplicationTag] isEqual:tag]
      || ![storedAttributes[(__bridge id)kSecAttrAccessGroup]
        isEqual:accessGroup]
      || ![keyAttributes[(__bridge id)kSecAttrTokenID]
        isEqual:(__bridge id)kSecAttrTokenIDSecureEnclave]
      || ![keyAttributes[(__bridge id)kSecAttrKeyType]
        isEqual:(__bridge id)kSecAttrKeyTypeECSECPrimeRandom]
      || ![keyAttributes[(__bridge id)kSecAttrKeyClass]
        isEqual:(__bridge id)kSecAttrKeyClassPrivate]
      || ![keyAttributes[(__bridge id)kSecAttrKeySizeInBits] isEqual:@256]
      || ![keyAttributes[(__bridge id)kSecAttrCanSign] boolValue]
      || !permanent) {
    Fail(@"A.28 Secure Enclave key attribute query rejected");
  }
  return @{
    @"accessControlFlags": @[@"biometryCurrentSet", @"privateKeyUsage"],
    @"accessGroup": accessGroup,
    @"applicationTag": A28KeyApplicationTag,
    @"canSign": @YES,
    @"dataProtectionKeychain": @YES,
    @"isPermanent": @YES,
    @"keyClass": @"private",
    @"keySizeInBits": @256,
    @"keyType": @"ECSECPrimeRandom",
    @"tokenId": @"com.apple.setoken",
  };
}

static NSData *PublicKeySpki(SecKeyRef privateKey) {
  SecKeyRef publicKey = SecKeyCopyPublicKey(privateKey);
  if (publicKey == NULL) Fail(@"A.28 public key unavailable");
  CFErrorRef copiedError = NULL;
  CFDataRef copiedPoint = SecKeyCopyExternalRepresentation(publicKey, &copiedError);
  CFRelease(publicKey);
  if (copiedPoint == NULL || CFDataGetLength(copiedPoint) != 65) {
    if (copiedError != NULL) CFRelease(copiedError);
    if (copiedPoint != NULL) CFRelease(copiedPoint);
    Fail(@"A.28 P-256 public key rejected");
  }
  if (copiedError != NULL) CFRelease(copiedError);
  static const unsigned char prefix[] = {
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86,
    0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
    0x42, 0x00,
  };
  NSMutableData *spki = [NSMutableData dataWithBytes:prefix length:sizeof(prefix)];
  [spki appendData:CFBridgingRelease(copiedPoint)];
  return spki;
}

static NSData *SignPayload(SecKeyRef key, NSData *payload, BOOL enrolment) {
  const char witnessPrefix[] = "PIUI-A28-VOICEOVER-WITNESS\0v1\0";
  const char enrolmentPrefix[] = "PIUI-A28-SECURE-ENCLAVE-ENROLMENT\0v1\0";
  NSMutableData *signedBytes = [NSMutableData data];
  if (enrolment) {
    [signedBytes appendBytes:enrolmentPrefix length:sizeof(enrolmentPrefix) - 1U];
  } else {
    [signedBytes appendBytes:witnessPrefix length:sizeof(witnessPrefix) - 1U];
  }
  [signedBytes appendData:payload];
  CFErrorRef copiedError = NULL;
  CFDataRef copiedSignature = SecKeyCreateSignature(
    key,
    kSecKeyAlgorithmECDSASignatureMessageX962SHA256,
    (__bridge CFDataRef)signedBytes,
    &copiedError
  );
  if (copiedSignature == NULL) {
    if (copiedError != NULL) CFRelease(copiedError);
    Fail(@"A.28 biometric signature was not completed");
  }
  if (copiedError != NULL) CFRelease(copiedError);
  return CFBridgingRelease(copiedSignature);
}

static void WriteHeldAttestationSlot(
  NSString *path,
  NSDictionary *slot,
  NSDictionary *value
) {
  NSMutableData *line = [CanonicalJson(value) mutableCopy];
  const unsigned char newline = '\n';
  [line appendBytes:&newline length:1];
  int descriptor = open(
    path.fileSystemRepresentation,
    O_WRONLY | O_CLOEXEC | O_NOFOLLOW
  );
  struct stat before = {0};
  if (descriptor < 0
      || fstat(descriptor, &before) != 0
      || !S_ISREG(before.st_mode)
      || before.st_nlink != 1
      || before.st_dev != (dev_t)[slot[@"dev"] unsignedLongLongValue]
      || before.st_ino != (ino_t)[slot[@"ino"] unsignedLongLongValue]
      || before.st_uid != (uid_t)[slot[@"uid"] unsignedIntValue]
      || before.st_gid != (gid_t)[slot[@"gid"] unsignedIntValue]
      || before.st_uid != getuid()
      || (before.st_mode & 0777) != S_IWUSR
      || before.st_size != 0) {
    if (descriptor >= 0) (void)close(descriptor);
    Fail(@"A.28 held attestation output rejected");
  }
  NSUInteger offset = 0;
  while (offset < line.length) {
    ssize_t count = pwrite(
      descriptor,
      (const unsigned char *)line.bytes + offset,
      line.length - offset,
      (off_t)offset
    );
    if (count <= 0) {
      (void)close(descriptor);
      Fail(@"A.28 output write failed");
    }
    offset += (NSUInteger)count;
  }
  struct stat after = {0};
  struct stat pathname = {0};
  if (fchmod(descriptor, S_IRUSR) != 0
      || fsync(descriptor) != 0
      || fstat(descriptor, &after) != 0
      || lstat(path.fileSystemRepresentation, &pathname) != 0
      || S_ISLNK(pathname.st_mode)
      || after.st_dev != before.st_dev
      || after.st_ino != before.st_ino
      || after.st_dev != pathname.st_dev
      || after.st_ino != pathname.st_ino
      || after.st_uid != before.st_uid
      || after.st_gid != before.st_gid
      || after.st_nlink != 1
      || (after.st_mode & 0777) != S_IRUSR
      || after.st_size != (off_t)line.length
      || after.st_mode != pathname.st_mode
      || after.st_size != pathname.st_size
      || after.st_mtimespec.tv_sec != pathname.st_mtimespec.tv_sec
      || after.st_mtimespec.tv_nsec != pathname.st_mtimespec.tv_nsec
      || after.st_ctimespec.tv_sec != pathname.st_ctimespec.tv_sec
      || after.st_ctimespec.tv_nsec != pathname.st_ctimespec.tv_nsec
      || close(descriptor) != 0) {
    Fail(@"A.28 output durability failed");
  }
}

static void WriteHeldCanonicalDescriptor(int descriptor, NSDictionary *value) {
  struct stat before = {0};
  struct stat after = {0};
  if (descriptor < 3
      || fstat(descriptor, &before) != 0
      || !S_ISREG(before.st_mode)
      || before.st_nlink != 1
      || before.st_uid != 0
      || before.st_gid != 0
      || (before.st_mode & 0777) != S_IRUSR
      || before.st_size != 0) {
    Fail(@"A.28 held enrolment output rejected");
  }
  NSMutableData *line = [CanonicalJson(value) mutableCopy];
  const unsigned char newline = '\n';
  [line appendBytes:&newline length:1];
  NSUInteger offset = 0;
  while (offset < line.length) {
    ssize_t count = pwrite(
      descriptor,
      (const unsigned char *)line.bytes + offset,
      line.length - offset,
      (off_t)offset
    );
    if (count <= 0) Fail(@"A.28 held enrolment output write failed");
    offset += (NSUInteger)count;
  }
  if (fsync(descriptor) != 0
      || fstat(descriptor, &after) != 0
      || before.st_dev != after.st_dev
      || before.st_ino != after.st_ino
      || after.st_size != (off_t)line.length
      || (after.st_mode & 0777) != S_IRUSR) {
    Fail(@"A.28 held enrolment output durability failed");
  }
}

static void WriteProtocolLine(NSString *value) {
  NSData *line = [[value stringByAppendingString:@"\n"]
    dataUsingEncoding:NSUTF8StringEncoding];
  if (write(STDOUT_FILENO, line.bytes, line.length) != (ssize_t)line.length) {
    Fail(@"A.28 enrolment protocol write failed");
  }
}

static void ReadProtocolLine(NSString *expected) {
  NSData *required = [[expected stringByAppendingString:@"\n"]
    dataUsingEncoding:NSUTF8StringEncoding];
  unsigned char bytes[16] = {0};
  if (required.length > sizeof(bytes)) Fail(@"A.28 enrolment protocol rejected");
  NSUInteger offset = 0U;
  while (offset < required.length) {
    ssize_t count = read(STDIN_FILENO, bytes + offset, required.length - offset);
    if (count <= 0) Fail(@"A.28 enrolment protocol read failed");
    offset += (NSUInteger)count;
  }
  if (memcmp(bytes, required.bytes, required.length) != 0) {
    Fail(@"A.28 enrolment protocol command rejected");
  }
}

static void RunEnrolment(NSDictionary<NSString *, NSString *> *arguments) {
  NSString *authorityConfigSha256 =
    arguments[@"--enrolment-authority-config-sha256"];
  NSString *reviewerIdentity = arguments[@"--reviewer-identity"];
  NSString *nonce = arguments[@"--enrolment-nonce"];
  NSInteger outputDescriptor = [arguments[@"--output-fd"] integerValue];
  NSInteger witnessUid = [arguments[@"--witness-uid"] integerValue];
  if (!IsSha256(authorityConfigSha256)
      || !IsSha256(nonce)
      || reviewerIdentity.length < 3
      || witnessUid != getuid()
      || outputDescriptor < 3
      || outputDescriptor > INT_MAX) {
    Fail(@"A.28 enrolment arguments rejected");
  }
  WriteProtocolLine(@"READY");
  ReadProtocolLine(@"G");
  CFErrorRef copiedError = NULL;
  SecAccessControlRef access = SecAccessControlCreateWithFlags(
    kCFAllocatorDefault,
    kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    kSecAccessControlBiometryCurrentSet
      | kSecAccessControlPrivateKeyUsage,
    &copiedError
  );
  if (access == NULL) {
    if (copiedError != NULL) CFRelease(copiedError);
    Fail(@"A.28 biometric access control unavailable");
  }
  if (copiedError != NULL) CFRelease(copiedError);
  NSData *tag = [A28KeyApplicationTag dataUsingEncoding:NSUTF8StringEncoding];
  NSString *accessGroup = CopyKeychainAccessGroup();
  RejectExistingSecureEnclaveKey(accessGroup, tag);
  NSDictionary *privateAttributes = @{
    (__bridge id)kSecAttrIsPermanent: @YES,
    (__bridge id)kSecAttrApplicationTag: tag,
    (__bridge id)kSecAttrAccessControl: (__bridge id)access,
  };
  NSDictionary *attributes = @{
    (__bridge id)kSecAttrAccessGroup: accessGroup,
    (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeECSECPrimeRandom,
    (__bridge id)kSecAttrKeySizeInBits: @256,
    (__bridge id)kSecAttrTokenID: (__bridge id)kSecAttrTokenIDSecureEnclave,
    (__bridge id)kSecPrivateKeyAttrs: privateAttributes,
    (__bridge id)kSecUseDataProtectionKeychain: @YES,
  };
  copiedError = NULL;
  SecKeyRef key = SecKeyCreateRandomKey(
    (__bridge CFDictionaryRef)attributes,
    &copiedError
  );
  CFRelease(access);
  if (key == NULL) {
    if (copiedError != NULL) CFRelease(copiedError);
    Fail(@"A.28 Secure Enclave enrolment failed closed");
  }
  if (copiedError != NULL) CFRelease(copiedError);
  copiedError = NULL;
  CFDataRef forbiddenPrivateBytes = SecKeyCopyExternalRepresentation(
    key,
    &copiedError
  );
  if (forbiddenPrivateBytes != NULL) {
    CFRelease(forbiddenPrivateBytes);
    if (copiedError != NULL) CFRelease(copiedError);
    CFRelease(key);
    Fail(@"A.28 private key was unexpectedly exportable");
  }
  if (copiedError != NULL) CFRelease(copiedError);
  NSDictionary *keyAttributes = VerifiedSecureEnclaveKeyAttributes(
    key,
    accessGroup,
    tag
  );
  NSData *spki = PublicKeySpki(key);
  NSString *publicKeySha256 = Sha256(spki);
  NSString *enrolledAt = IsoInstant();
  NSDictionary *proofPayload = @{
    @"algorithm": @"ES256",
    @"domain": A28EnrolmentDomain,
    @"enrolledAt": enrolledAt,
    @"enrolmentAuthorityConfigSha256": authorityConfigSha256,
    @"enrolmentNonce": nonce,
    @"keyAttributes": keyAttributes,
    @"publicKeySha256": publicKeySha256,
    @"reviewerIdentity": reviewerIdentity,
    @"reviewerKeyId": publicKeySha256,
    @"schemaVersion": @1,
    @"witnessUid": @(witnessUid),
  };
  NSData *signature = SignPayload(key, CanonicalJson(proofPayload), YES);
  CFRelease(key);
  NSDictionary *candidate = @{
    @"algorithm": @"ES256",
    @"enrolledAt": enrolledAt,
    @"enrolmentAuthorityConfigSha256": authorityConfigSha256,
    @"enrolmentProof": @{
      @"algorithm": @"ES256",
      @"enrolledAt": enrolledAt,
      @"enrolmentAuthorityConfigSha256": authorityConfigSha256,
      @"enrolmentNonce": nonce,
      @"keyAttributes": keyAttributes,
      @"publicKeySha256": publicKeySha256,
      @"reviewerIdentity": reviewerIdentity,
      @"reviewerKeyId": publicKeySha256,
      @"signatureDerBase64": [signature base64EncodedStringWithOptions:0],
      @"witnessUid": @(witnessUid),
    },
    @"keyAttributes": keyAttributes,
    @"publicKeySha256": publicKeySha256,
    @"publicKeySpkiDerBase64": [spki base64EncodedStringWithOptions:0],
    @"reviewerIdentity": reviewerIdentity,
    @"reviewerKeyId": publicKeySha256,
    @"schemaVersion": @1,
    @"witnessUid": @(witnessUid),
  };
  WriteHeldCanonicalDescriptor((int)outputDescriptor, candidate);
  WriteProtocolLine(@"SIGNED");
  ReadProtocolLine(@"A");
}

static NSString *CheckpointCommitment(
  NSDictionary *challenge,
  NSDictionary *checkpoint,
  NSString *token
) {
  NSDictionary *preimage = @{
    @"appearance": checkpoint[@"appearance"],
    @"architectureGateRunId": challenge[@"architectureGateRunId"],
    @"challengeRequestSha256": challenge[@"challengeRequestSha256"],
    @"checkpointId": checkpoint[@"checkpointId"],
    @"checkpointSessionId": challenge[@"checkpointSessionId"],
    @"mode": checkpoint[@"mode"],
    @"ordinal": checkpoint[@"ordinal"],
    @"token": token,
    @"witnessNonce": challenge[@"witnessNonce"],
  };
  NSMutableData *line = [CanonicalJson(preimage) mutableCopy];
  const unsigned char newline = '\n';
  [line appendBytes:&newline length:1U];
  return Sha256(line);
}

@interface A28WitnessController : NSObject <NSApplicationDelegate>
@property(nonatomic, copy) NSDictionary *challenge;
@property(nonatomic, copy) NSData *challengeLine;
@property(nonatomic, copy) NSString *outputPath;
@property(nonatomic, strong) NSWindow *window;
@property(nonatomic, strong) NSButton *signButton;
@property(nonatomic, strong) NSProgressIndicator *spinner;
@property(nonatomic, strong) NSOperationQueue *signingQueue;
@property(nonatomic, strong) NSTextField *statusLabel;
@property(nonatomic, strong) NSMutableArray<NSSegmentedControl *> *decisionControls;
@property(nonatomic, strong) NSMutableArray<NSTextField *> *defectFields;
@property(nonatomic, strong) NSMutableArray<NSTextField *> *tokenFields;
@property(nonatomic, strong) NSMutableArray<NSString *> *observedTimes;
@property(nonatomic, copy) NSString *observationStartedAt;
@end

@implementation A28WitnessController

- (instancetype)initWithChallengeLine:(NSData *)line output:(NSString *)output {
  self = [super init];
  if (self != nil) {
    _challengeLine = [line copy];
    _challenge = [ParseChallenge(line) copy];
    _outputPath = [output copy];
    _decisionControls = [NSMutableArray array];
    _defectFields = [NSMutableArray array];
    _tokenFields = [NSMutableArray array];
    _observedTimes = [NSMutableArray arrayWithObjects:
      @"", @"", @"", @"", nil];
    _observationStartedAt = IsoInstant();
    _signingQueue = [[NSOperationQueue alloc] init];
    _signingQueue.maxConcurrentOperationCount = 1;
    _signingQueue.name = @"au.com.piui.a28-witness.signing";
  }
  return self;
}

- (NSTextField *)label:(NSString *)value font:(NSFont *)font {
  NSTextField *label = [NSTextField labelWithString:value];
  label.font = font;
  label.selectable = YES;
  label.lineBreakMode = NSLineBreakByWordWrapping;
  label.maximumNumberOfLines = 0;
  return label;
}

- (void)applicationDidFinishLaunching:(NSNotification *)notification {
  (void)notification;
  self.window = [[NSWindow alloc]
    initWithContentRect:NSMakeRect(0, 0, 1220, 760)
    styleMask:(NSWindowStyleMaskTitled
      | NSWindowStyleMaskClosable
      | NSWindowStyleMaskResizable)
    backing:NSBackingStoreBuffered
    defer:NO];
  self.window.title = @"PIUI A.28 VoiceOver Witness";
  self.window.minSize = NSMakeSize(1040, 640);
  NSStackView *root = [NSStackView stackViewWithViews:@[]];
  root.orientation = NSUserInterfaceLayoutOrientationVertical;
  root.alignment = NSLayoutAttributeLeading;
  root.spacing = 12;
  root.edgeInsets = NSEdgeInsetsMake(20, 20, 20, 20);
  root.translatesAutoresizingMaskIntoConstraints = NO;
  [self.window.contentView addSubview:root];
  [NSLayoutConstraint activateConstraints:@[
    [root.leadingAnchor constraintEqualToAnchor:self.window.contentView.leadingAnchor],
    [root.trailingAnchor constraintEqualToAnchor:self.window.contentView.trailingAnchor],
    [root.topAnchor constraintEqualToAnchor:self.window.contentView.topAnchor],
    [root.bottomAnchor constraintEqualToAnchor:self.window.contentView.bottomAnchor],
  ]];
  [root addArrangedSubview:[self label:@"Authenticated A.28 VoiceOver witness"
    font:[NSFont systemFontOfSize:22 weight:NSFontWeightSemibold]]];
  [root addArrangedSubview:[self label:
    @"Review the immutable challenge below. Exercise the retained packaged twin with VoiceOver, then record all four appearance and rendering combinations."
    font:[NSFont systemFontOfSize:13]]];
  NSTextView *identity = [[NSTextView alloc] initWithFrame:NSMakeRect(0, 0, 880, 145)];
  identity.editable = NO;
  identity.selectable = YES;
  identity.font = [NSFont monospacedSystemFontOfSize:11 weight:NSFontWeightRegular];
  identity.string = [[NSString alloc]
    initWithData:[self.challengeLine
      subdataWithRange:NSMakeRange(0, self.challengeLine.length - 1U)]
    encoding:NSUTF8StringEncoding];
  identity.accessibilityLabel = @"Immutable architecture gate challenge";
  NSScrollView *identityScroll = [[NSScrollView alloc] init];
  identityScroll.documentView = identity;
  identityScroll.borderType = NSBezelBorder;
  identityScroll.hasVerticalScroller = YES;
  [identityScroll.heightAnchor constraintEqualToConstant:145].active = YES;
  [identityScroll.widthAnchor constraintEqualToAnchor:root.widthAnchor].active = YES;
  [root addArrangedSubview:identityScroll];

  NSArray<NSArray<NSString *> *> *combinations = @[
    @[@"Dark", @"Accessible"],
    @[@"Dark", @"Virtualised"],
    @[@"Light", @"Accessible"],
    @[@"Light", @"Virtualised"],
  ];
  for (NSUInteger index = 0; index < combinations.count; index += 1U) {
    NSStackView *row = [NSStackView stackViewWithViews:@[]];
    row.orientation = NSUserInterfaceLayoutOrientationHorizontal;
    row.alignment = NSLayoutAttributeCenterY;
    row.spacing = 8;
    NSString *title = [NSString stringWithFormat:
      @"%@ / %@",
      combinations[index][0],
      combinations[index][1]];
    NSTextField *titleLabel = [self label:title
      font:[NSFont systemFontOfSize:13 weight:NSFontWeightSemibold]];
    [titleLabel.widthAnchor constraintEqualToConstant:145].active = YES;
    [row addArrangedSubview:titleLabel];
    NSArray *criteria = @[@"Announcements", @"Focus", @"Keyboard"];
    for (NSString *criterion in criteria) {
      NSSegmentedControl *control = [NSSegmentedControl
        segmentedControlWithLabels:@[@"Pass", @"Fail"]
        trackingMode:NSSegmentSwitchTrackingSelectOne
        target:self
        action:@selector(decisionChanged:)];
      control.selectedSegment = -1;
      control.enabled = index == 0U;
      control.tag = (NSInteger)(index * 3U + self.decisionControls.count % 3U);
      control.accessibilityLabel = [NSString stringWithFormat:
        @"%@, %@",
        title,
        criterion];
      [self.decisionControls addObject:control];
      [row addArrangedSubview:control];
    }
    NSTextField *token = [NSTextField textFieldWithString:@""];
    token.placeholderString = @"Root checkpoint token";
    token.target = self;
    token.action = @selector(decisionChanged:);
    token.enabled = index == 0U;
    token.accessibilityLabel = [NSString stringWithFormat:
      @"%@ root checkpoint token",
      title];
    [token.widthAnchor constraintGreaterThanOrEqualToConstant:175].active = YES;
    [self.tokenFields addObject:token];
    [row addArrangedSubview:token];
    NSTextField *defect = [NSTextField textFieldWithString:@""];
    defect.placeholderString = @"Blocking defect when any result fails";
    defect.target = self;
    defect.action = @selector(decisionChanged:);
    defect.enabled = index == 0U;
    defect.accessibilityLabel = [NSString stringWithFormat:
      @"%@ blocking defect",
      title];
    [defect.widthAnchor constraintGreaterThanOrEqualToConstant:200].active = YES;
    [self.defectFields addObject:defect];
    [row addArrangedSubview:defect];
    [root addArrangedSubview:row];
  }
  NSStackView *actions = [NSStackView stackViewWithViews:@[]];
  actions.orientation = NSUserInterfaceLayoutOrientationHorizontal;
  actions.alignment = NSLayoutAttributeCenterY;
  actions.spacing = 10;
  self.signButton = [NSButton buttonWithTitle:@"Authenticate and sign witness"
    target:self
    action:@selector(signWitness:)];
  self.signButton.enabled = NO;
  [actions addArrangedSubview:self.signButton];
  self.spinner = [[NSProgressIndicator alloc] init];
  self.spinner.style = NSProgressIndicatorStyleSpinning;
  self.spinner.displayedWhenStopped = NO;
  self.spinner.accessibilityLabel = @"Waiting for biometric authentication";
  [actions addArrangedSubview:self.spinner];
  self.statusLabel = [self label:
    @"Complete all four rows. Failed results require a blocking defect."
    font:[NSFont systemFontOfSize:12]];
  self.statusLabel.accessibilityRole = NSAccessibilityStaticTextRole;
  [actions addArrangedSubview:self.statusLabel];
  [root addArrangedSubview:actions];
  [self.window center];
  [self.window makeKeyAndOrderFront:nil];
  [NSApp activateIgnoringOtherApps:YES];
}

- (void)decisionChanged:(id)sender {
  (void)sender;
  BOOL voiceOverRunning = VoiceOverIsRunning();
  BOOL allComplete = voiceOverRunning;
  BOOL priorComplete = YES;
  for (NSUInteger row = 0; row < 4U; row += 1U) {
    for (NSUInteger criterion = 0; criterion < 3U; criterion += 1U) {
      self.decisionControls[row * 3U + criterion].enabled = priorComplete;
    }
    self.tokenFields[row].enabled = priorComplete;
    self.defectFields[row].enabled = priorComplete;
    BOOL answered = YES;
    BOOL hasFailure = NO;
    for (NSUInteger criterion = 0; criterion < 3U; criterion += 1U) {
      NSInteger selected = self.decisionControls[row * 3U + criterion].selectedSegment;
      answered = answered && selected >= 0;
      hasFailure = hasFailure || selected == 1;
    }
    NSString *defect = [self.defectFields[row].stringValue
      stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    NSString *token = [self.tokenFields[row].stringValue
      stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    NSDictionary *checkpoint = self.challenge[@"stateCheckpoints"][row];
    BOOL tokenMatches = IsSha256(token)
      && [CheckpointCommitment(self.challenge, checkpoint, token)
        isEqual:checkpoint[@"tokenSha256"]];
    BOOL consistent = priorComplete
      && tokenMatches
      && defect.length <= 240U
      && answered
      && ((hasFailure && defect.length > 0U)
        || (!hasFailure && defect.length == 0U));
    if (consistent && voiceOverRunning) {
      if (self.observedTimes[row].length == 0U) self.observedTimes[row] = IsoInstant();
    } else {
      self.observedTimes[row] = @"";
    }
    allComplete = allComplete && consistent;
    priorComplete = priorComplete && consistent;
  }
  self.signButton.enabled = allComplete;
  self.statusLabel.stringValue = !voiceOverRunning
    ? @"VoiceOver must be running while observations are recorded."
    : (allComplete
      ? @"Ready. Authentication will require the enrolled biometric set."
      : @"Enter each root checkpoint token in order. Failed results require a blocking defect.");
}

- (NSArray *)decisions {
  NSArray *appearances = @[@"dark", @"dark", @"light", @"light"];
  NSArray *modes = @[@"accessible", @"virtualised", @"accessible", @"virtualised"];
  NSMutableArray *values = [NSMutableArray arrayWithCapacity:4];
  for (NSUInteger row = 0; row < 4U; row += 1U) {
    NSString *defect = [self.defectFields[row].stringValue
      stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    NSString *token = [self.tokenFields[row].stringValue
      stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    NSDictionary *checkpoint = self.challenge[@"stateCheckpoints"][row];
    [values addObject:@{
      @"announcements": self.decisionControls[row * 3U].selectedSegment == 0
        ? @"pass" : @"fail",
      @"assertionScope": A28HumanAssertionScope,
      @"appearance": appearances[row],
      @"blockingDefects": defect.length == 0U ? @[] : @[defect],
      @"checkpointId": checkpoint[@"checkpointId"],
      @"checkpointOrdinal": checkpoint[@"ordinal"],
      @"checkpointToken": token,
      @"checkpointTokenSha256": checkpoint[@"tokenSha256"],
      @"focusRetention": self.decisionControls[row * 3U + 1U].selectedSegment == 0
        ? @"pass" : @"fail",
      @"humanAssertion": @YES,
      @"keyboardOrder": self.decisionControls[row * 3U + 2U].selectedSegment == 0
        ? @"pass" : @"fail",
      @"mode": modes[row],
      @"observedAt": self.observedTimes[row],
    }];
  }
  return values;
}

- (void)signWitness:(id)sender {
  (void)sender;
  if (!VoiceOverIsRunning()) {
    self.signButton.enabled = NO;
    self.statusLabel.stringValue =
      @"VoiceOver stopped. Restart it and reconfirm every observation.";
    [self.observedTimes setArray:@[@"", @"", @"", @""]];
    return;
  }
  self.signButton.enabled = NO;
  for (NSSegmentedControl *control in self.decisionControls) {
    control.enabled = NO;
  }
  for (NSTextField *field in self.tokenFields) field.enabled = NO;
  for (NSTextField *field in self.defectFields) field.enabled = NO;
  self.window.preventsApplicationTerminationWhenModal = YES;
  [self.spinner startAnimation:nil];
  self.statusLabel.stringValue =
    @"Waiting for Secure Enclave biometric authentication…";
  NSArray *decisions = [self decisions];
  NSString *completedAt = IsoInstant();
  NSDictionary *challenge = self.challenge;
  NSData *challengeLine = self.challengeLine;
  NSString *outputPath = self.outputPath;
  NSString *observationStartedAt = self.observationStartedAt;
  [self.signingQueue addOperationWithBlock:^{
    SecKeyRef key = CopySecureEnclaveKey(
      @"Authenticate the PIUI A.28 VoiceOver witness"
    );
    NSData *spki = PublicKeySpki(key);
    NSString *keySha256 = Sha256(spki);
    if (![keySha256 isEqual:challenge[@"reviewerKeyId"]]) {
      CFRelease(key);
      Fail(@"A.28 enrolled witness key did not match the challenge");
    }
    if (!VoiceOverIsRunning()) {
      CFRelease(key);
      Fail(@"A.28 VoiceOver stopped before biometric signing completed");
    }
    BOOL passed = YES;
    for (NSDictionary *decision in decisions) {
      passed = passed
        && [decision[@"announcements"] isEqual:@"pass"]
        && [decision[@"focusRetention"] isEqual:@"pass"]
        && [decision[@"keyboardOrder"] isEqual:@"pass"]
        && [decision[@"blockingDefects"] count] == 0U;
    }
    NSMutableDictionary *payload = [challenge mutableCopy];
    NSDictionary *selfIdentity = SelfProcessIdentity();
    payload[@"challengeSha256"] = Sha256(challengeLine);
    payload[@"checks"] = decisions;
    payload[@"completedAt"] = completedAt;
    payload[@"domain"] = A28WitnessDomain;
    payload[@"observationStartedAt"] = observationStartedAt;
    payload[@"status"] = passed ? @"pass" : @"fail";
    payload[@"witnessApplicationPid"] = selfIdentity[@"pid"];
    payload[@"witnessAuditTokenSha256"] = selfIdentity[@"auditTokenSha256"];
    payload[@"witnessBundleIdentifier"] = selfIdentity[@"bundleIdentifier"];
    payload[@"witnessCdHash"] = selfIdentity[@"cdHash"];
    payload[@"witnessDesignatedRequirement"] =
      selfIdentity[@"designatedRequirement"];
    payload[@"witnessExecutable"] = selfIdentity[@"executable"];
    payload[@"witnessKeySha256"] = keySha256;
    payload[@"witnessUid"] = @(getuid());
    payload[@"witnessStartTime"] = selfIdentity[@"startTime"];
    NSData *signature = SignPayload(key, CanonicalJson(payload), NO);
    CFRelease(key);
    NSDictionary *envelope = @{
      @"algorithm": @"ES256",
      @"payload": payload,
      @"schemaVersion": @1,
      @"signatureDerBase64": [signature base64EncodedStringWithOptions:0],
    };
    WriteHeldAttestationSlot(
      outputPath,
      challenge[@"attestationSlot"],
      envelope
    );
    [[NSOperationQueue mainQueue] addOperationWithBlock:^{
      [self.spinner stopAnimation:nil];
      self.window.preventsApplicationTerminationWhenModal = NO;
      self.statusLabel.stringValue =
        @"Signed witness saved. Return to the architecture gate runner.";
      self.signButton.title = @"Witness signed";
      self.signButton.enabled = NO;
    }];
  }];
}

@end

static NSDictionary<NSString *, NSString *> *ParseArguments(
  NSArray<NSString *> *arguments
) {
  NSMutableDictionary *values = [NSMutableDictionary dictionary];
  for (NSUInteger index = 1U; index < arguments.count; index += 2U) {
    if (index + 1U >= arguments.count) Fail(@"A.28 arguments rejected");
    NSString *key = arguments[index];
    NSString *value = arguments[index + 1U];
    if (![key hasPrefix:@"--"] || values[key] != nil) {
      Fail(@"A.28 arguments rejected");
    }
    values[key] = value;
  }
  return values;
}

int main(int argc, const char *argv[]) {
  (void)argc;
  (void)argv;
  @autoreleasepool {
    NSDictionary *arguments = ParseArguments(
      NSProcessInfo.processInfo.arguments
    );
    if ([arguments[@"--mode"] isEqual:@"enrol"]) {
      NSSet *expected = [NSSet setWithArray:@[
        @"--enrolment-nonce",
        @"--enrolment-authority-config-sha256",
        @"--mode",
        @"--output-fd",
        @"--reviewer-identity",
        @"--witness-uid",
      ]];
      if (![[NSSet setWithArray:arguments.allKeys] isEqualToSet:expected]) {
        Fail(@"A.28 enrolment arguments rejected");
      }
      RunEnrolment(arguments);
      return EXIT_SUCCESS;
    }
    NSSet *expected = [NSSet setWithArray:
      @[@"--challenge", @"--mode", @"--output"]];
    if (![arguments[@"--mode"] isEqual:@"witness"]
        || ![[NSSet setWithArray:arguments.allKeys] isEqualToSet:expected]) {
      Fail(@"A.28 witness arguments rejected");
    }
    NSString *output = arguments[@"--output"];
    NSData *challengeLine = ReadHeldCanonicalFile(arguments[@"--challenge"]);
    NSDictionary *challenge = ParseChallenge(challengeLine);
    if (![output isEqual:challenge[@"attestationSlot"][@"path"]]) {
      Fail(@"A.28 output path did not match the root-created slot");
    }
    A28WitnessController *controller = [[A28WitnessController alloc]
      initWithChallengeLine:challengeLine
      output:output];
    NSApplication *application = NSApplication.sharedApplication;
    application.activationPolicy = NSApplicationActivationPolicyRegular;
    application.delegate = controller;
    [application run];
  }
  return EXIT_SUCCESS;
}
