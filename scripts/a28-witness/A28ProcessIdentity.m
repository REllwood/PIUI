#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonDigest.h>
#import <Security/Security.h>
#include <bsm/audit.h>
#include <fcntl.h>
#include <libproc.h>
#include <mach/mach.h>
#include <mach/task_info.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const NSUInteger A28MaximumExecutableBytes = 1024U * 1024U * 1024U;

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
  if (CC_SHA256(data.bytes, (CC_LONG)data.length, digest) == NULL) {
    Fail(@"A.28 SHA-256 failed");
  }
  return Hex([NSData dataWithBytes:digest length:sizeof(digest)]);
}

static BOOL SameExecutableStat(struct stat left, struct stat right) {
  return left.st_dev == right.st_dev
    && left.st_ino == right.st_ino
    && left.st_size == right.st_size
    && left.st_mode == right.st_mode
    && left.st_nlink == right.st_nlink
    && left.st_uid == right.st_uid
    && left.st_gid == right.st_gid
    && left.st_mtimespec.tv_sec == right.st_mtimespec.tv_sec
    && left.st_mtimespec.tv_nsec == right.st_mtimespec.tv_nsec
    && left.st_ctimespec.tv_sec == right.st_ctimespec.tv_sec
    && left.st_ctimespec.tv_nsec == right.st_ctimespec.tv_nsec;
}

static NSDictionary *ReadHeldExecutableIdentity(
  int descriptor,
  NSString *path,
  struct stat before
) {
  struct stat after = {0};
  if (!S_ISREG(before.st_mode)
      || before.st_nlink != 1
      || before.st_size < 8192
      || (uint64_t)before.st_size > A28MaximumExecutableBytes) {
    Fail(@"A.28 executable identity rejected");
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
      Fail(@"A.28 executable read failed");
    }
    offset += (NSUInteger)count;
  }
  if (fstat(descriptor, &after) != 0
      || !SameExecutableStat(before, after)) {
    Fail(@"A.28 executable changed during inspection");
  }
  return @{
    @"dev": @((unsigned long long)before.st_dev),
    @"ino": @((unsigned long long)before.st_ino),
    @"path": path,
    @"sha256": Sha256(bytes),
    @"size": @((unsigned long long)before.st_size),
  };
}

static SecRequirementRef CopyPositiveRequirement(
  NSString *bundleIdentifier,
  NSString *teamIdentifier
) {
  NSCharacterSet *bundleInvalid = [[NSCharacterSet
    characterSetWithCharactersInString:
      @"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-"]
    invertedSet];
  NSCharacterSet *teamInvalid = [[NSCharacterSet
    characterSetWithCharactersInString:@"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"]
    invertedSet];
  BOOL appleSystem = [teamIdentifier isEqual:@"APPLE-SYSTEM"];
  if (bundleIdentifier.length < 3U
      || bundleIdentifier.length > 255U
      || [bundleIdentifier rangeOfCharacterFromSet:bundleInvalid].location
        != NSNotFound
      || (appleSystem && ![bundleIdentifier isEqual:@"com.apple.VoiceOver"])
      || (!appleSystem && (teamIdentifier.length != 10U
        || [teamIdentifier rangeOfCharacterFromSet:teamInvalid].location
          != NSNotFound))) {
    Fail(@"A.28 structured signing authority rejected");
  }
  NSString *value = appleSystem
    ? [NSString stringWithFormat:
      @"anchor apple and identifier \"%@\"",
      bundleIdentifier]
    : [NSString stringWithFormat:
      @"anchor apple generic and identifier \"%@\" and certificate leaf[subject.OU] = %@",
      bundleIdentifier,
      teamIdentifier];
  SecRequirementRef requirement = NULL;
  OSStatus status = SecRequirementCreateWithString(
    (__bridge CFStringRef)value,
    kSecCSDefaultFlags,
    &requirement
  );
  if (status != errSecSuccess || requirement == NULL) {
    Fail(@"A.28 policy requirement rejected");
  }
  return requirement;
}

static NSDictionary *SigningInformationForPid(
  pid_t pid,
  NSString *bundleIdentifier,
  NSString *teamIdentifier,
  SecCodeRef *retainedCode
) {
  NSDictionary *attributes = @{(__bridge id)kSecGuestAttributePid: @(pid)};
  SecCodeRef code = NULL;
  OSStatus status = SecCodeCopyGuestWithAttributes(
    NULL,
    (__bridge CFDictionaryRef)attributes,
    kSecCSDefaultFlags,
    &code
  );
  if (status != errSecSuccess || code == NULL) {
    Fail(@"A.28 process signing identity unavailable");
  }
  SecRequirementRef requirement = CopyPositiveRequirement(
    bundleIdentifier,
    teamIdentifier
  );
  status = SecCodeCheckValidity(
    code,
    kSecCSStrictValidate | kSecCSCheckAllArchitectures,
    requirement
  );
  CFRelease(requirement);
  if (status != errSecSuccess) {
    CFRelease(code);
    Fail(@"A.28 live process failed its policy-pinned requirement");
  }
  CFDictionaryRef information = NULL;
  status = SecCodeCopySigningInformation(
    code,
    kSecCSSigningInformation | kSecCSRequirementInformation,
    &information
  );
  if (status != errSecSuccess || information == NULL) {
    CFRelease(code);
    Fail(@"A.28 process signing information unavailable");
  }
  *retainedCode = code;
  return CFBridgingRelease(information);
}

static NSString *RequirementString(SecRequirementRef requirement) {
  if (requirement == NULL) Fail(@"A.28 designated requirement unavailable");
  CFStringRef copied = NULL;
  OSStatus status = SecRequirementCopyString(
    requirement,
    kSecCSDefaultFlags,
    &copied
  );
  if (status != errSecSuccess || copied == NULL) {
    Fail(@"A.28 designated requirement string unavailable");
  }
  return CFBridgingRelease(copied);
}

static void AssertStaticCodeMatchesLive(
  NSString *path,
  NSString *bundleIdentifier,
  NSString *teamIdentifier,
  NSDictionary *liveInformation,
  SecStaticCodeRef *retainedStaticCode
) {
  SecRequirementRef requirement = CopyPositiveRequirement(
    bundleIdentifier,
    teamIdentifier
  );
  SecStaticCodeRef staticCode = NULL;
  OSStatus status = SecStaticCodeCreateWithPath(
    (__bridge CFURLRef)[NSURL fileURLWithPath:path],
    kSecCSDefaultFlags,
    &staticCode
  );
  if (status != errSecSuccess || staticCode == NULL) {
    CFRelease(requirement);
    Fail(@"A.28 live executable static code unavailable");
  }
  status = SecStaticCodeCheckValidity(
    staticCode,
    kSecCSStrictValidate | kSecCSCheckAllArchitectures,
    requirement
  );
  CFRelease(requirement);
  if (status != errSecSuccess) {
    CFRelease(staticCode);
    Fail(@"A.28 live executable static signature rejected");
  }
  CFDictionaryRef copied = NULL;
  status = SecCodeCopySigningInformation(
    staticCode,
    kSecCSSigningInformation | kSecCSRequirementInformation,
    &copied
  );
  if (status != errSecSuccess || copied == NULL) {
    CFRelease(staticCode);
    Fail(@"A.28 live executable static identity unavailable");
  }
  NSDictionary *staticInformation = CFBridgingRelease(copied);
  NSString *staticIdentifier = staticInformation[(__bridge id)kSecCodeInfoIdentifier];
  NSData *staticCdHash = staticInformation[(__bridge id)kSecCodeInfoUnique];
  SecRequirementRef staticRequirement = (__bridge SecRequirementRef)
    staticInformation[(__bridge id)kSecCodeInfoDesignatedRequirement];
  NSURL *liveExecutable = liveInformation[(__bridge id)kSecCodeInfoMainExecutable];
  NSURL *staticExecutable = staticInformation[(__bridge id)kSecCodeInfoMainExecutable];
  if (![staticIdentifier isEqual:
        liveInformation[(__bridge id)kSecCodeInfoIdentifier]]
      || ![staticCdHash isEqual:liveInformation[(__bridge id)kSecCodeInfoUnique]]
      || ![RequirementString(staticRequirement) isEqual:
        RequirementString((__bridge SecRequirementRef)
          liveInformation[(__bridge id)kSecCodeInfoDesignatedRequirement])]
      || ![liveExecutable isKindOfClass:NSURL.class]
      || ![staticExecutable isKindOfClass:NSURL.class]
      || ![liveExecutable.path isEqual:path]
      || ![staticExecutable.path isEqual:path]) {
    Fail(@"A.28 live and static executable identities differed");
  }
  *retainedStaticCode = staticCode;
}

static void RevalidateRetainedCodes(
  SecCodeRef liveCode,
  SecStaticCodeRef staticCode,
  NSString *path,
  NSString *bundleIdentifier,
  NSString *teamIdentifier,
  NSString *reportedRequirement,
  NSDictionary *originalInformation
) {
  SecRequirementRef liveRequirement = CopyPositiveRequirement(
    bundleIdentifier,
    teamIdentifier
  );
  SecRequirementRef staticRequirement = CopyPositiveRequirement(
    bundleIdentifier,
    teamIdentifier
  );
  OSStatus liveStatus = SecCodeCheckValidity(
    liveCode,
    kSecCSStrictValidate | kSecCSCheckAllArchitectures,
    liveRequirement
  );
  OSStatus staticStatus = SecStaticCodeCheckValidity(
    staticCode,
    kSecCSStrictValidate | kSecCSCheckAllArchitectures,
    staticRequirement
  );
  CFRelease(liveRequirement);
  CFRelease(staticRequirement);
  if (liveStatus != errSecSuccess || staticStatus != errSecSuccess) {
    Fail(@"A.28 retained code validity changed");
  }
  CFDictionaryRef copiedLive = NULL;
  CFDictionaryRef copiedStatic = NULL;
  liveStatus = SecCodeCopySigningInformation(
    liveCode,
    kSecCSSigningInformation | kSecCSRequirementInformation,
    &copiedLive
  );
  staticStatus = SecCodeCopySigningInformation(
    staticCode,
    kSecCSSigningInformation | kSecCSRequirementInformation,
    &copiedStatic
  );
  if (liveStatus != errSecSuccess
      || staticStatus != errSecSuccess
      || copiedLive == NULL
      || copiedStatic == NULL) {
    if (copiedLive != NULL) CFRelease(copiedLive);
    if (copiedStatic != NULL) CFRelease(copiedStatic);
    Fail(@"A.28 retained code identity unavailable");
  }
  NSDictionary *finalLive = CFBridgingRelease(copiedLive);
  NSDictionary *finalStatic = CFBridgingRelease(copiedStatic);
  for (NSDictionary *information in @[finalLive, finalStatic]) {
    SecRequirementRef requirement = (__bridge SecRequirementRef)
      information[(__bridge id)kSecCodeInfoDesignatedRequirement];
    NSURL *executable = information[(__bridge id)kSecCodeInfoMainExecutable];
    if (![information[(__bridge id)kSecCodeInfoIdentifier]
          isEqual:bundleIdentifier]
        || ![information[(__bridge id)kSecCodeInfoUnique]
          isEqual:originalInformation[(__bridge id)kSecCodeInfoUnique]]
        || ![RequirementString(requirement) isEqual:reportedRequirement]
        || ![executable isKindOfClass:NSURL.class]
        || ![executable.path isEqual:path]) {
      Fail(@"A.28 retained live/static identity changed");
    }
  }
}

static NSString *AuditTokenSha256(pid_t pid) {
  mach_port_name_t task = MACH_PORT_NULL;
  kern_return_t result = task_name_for_pid(mach_task_self(), pid, &task);
  if (result != KERN_SUCCESS || task == MACH_PORT_NULL) {
    Fail(@"A.28 process audit token unavailable");
  }
  audit_token_t token = {0};
  mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
  result = task_info(
    task,
    TASK_AUDIT_TOKEN,
    (task_info_t)&token,
    &count
  );
  (void)mach_port_deallocate(mach_task_self(), task);
  if (result != KERN_SUCCESS || count != TASK_AUDIT_TOKEN_COUNT) {
    Fail(@"A.28 process audit token inspection failed");
  }
  return Sha256([NSData dataWithBytes:&token length:sizeof(token)]);
}

static NSDictionary *InspectPid(
  pid_t pid,
  NSString *bundleIdentifier,
  NSString *teamIdentifier,
  NSString *reportedRequirement
) {
  if (pid < 2 || kill(pid, 0) != 0) Fail(@"A.28 process is not live");
  struct proc_bsdinfo information = {0};
  int received = proc_pidinfo(
    pid,
    PROC_PIDTBSDINFO,
    0,
    &information,
    sizeof(information)
  );
  if (received != sizeof(information)
      || information.pbi_start_tvusec > 999999) {
    Fail(@"A.28 process start identity unavailable");
  }
  char executablePath[PROC_PIDPATHINFO_MAXSIZE] = {0};
  int pathLength = proc_pidpath(pid, executablePath, sizeof(executablePath));
  if (pathLength < 2 || pathLength >= (int)sizeof(executablePath)) {
    Fail(@"A.28 process executable path unavailable");
  }
  NSString *path = [[NSFileManager defaultManager]
    stringWithFileSystemRepresentation:executablePath
    length:(NSUInteger)pathLength];
  if (path == nil || ![path hasPrefix:@"/"]) {
    Fail(@"A.28 process executable path rejected");
  }
  int descriptor = open(
    path.fileSystemRepresentation,
    O_RDONLY | O_CLOEXEC | O_NOFOLLOW
  );
  struct stat heldBefore = {0};
  struct stat pathnameBefore = {0};
  if (descriptor < 0
      || fstat(descriptor, &heldBefore) != 0
      || lstat(path.fileSystemRepresentation, &pathnameBefore) != 0
      || !SameExecutableStat(heldBefore, pathnameBefore)
      || !S_ISREG(heldBefore.st_mode)
      || heldBefore.st_nlink != 1) {
    if (descriptor >= 0) (void)close(descriptor);
    Fail(@"A.28 held live executable rejected");
  }
  SecCodeRef liveCode = NULL;
  SecStaticCodeRef staticCode = NULL;
  NSDictionary *signing = SigningInformationForPid(
    pid,
    bundleIdentifier,
    teamIdentifier,
    &liveCode
  );
  AssertStaticCodeMatchesLive(
    path,
    bundleIdentifier,
    teamIdentifier,
    signing,
    &staticCode
  );
  NSString *identifier = signing[(__bridge id)kSecCodeInfoIdentifier];
  NSData *cdHash = signing[(__bridge id)kSecCodeInfoUnique];
  SecRequirementRef designatedRequirement = (__bridge SecRequirementRef)
    signing[(__bridge id)kSecCodeInfoDesignatedRequirement];
  if (![identifier isKindOfClass:NSString.class]
      || ![identifier isEqual:bundleIdentifier]
      || ![cdHash isKindOfClass:NSData.class]
      || cdHash.length != 20U
      || designatedRequirement == NULL) {
    Fail(@"A.28 process bundle identity unavailable");
  }
  NSString *actualRequirement = RequirementString(designatedRequirement);
  if (![actualRequirement isEqual:reportedRequirement]) {
    Fail(@"A.28 reported designated requirement changed");
  }
  NSString *auditTokenSha256 = AuditTokenSha256(pid);
  NSDictionary *executable = ReadHeldExecutableIdentity(
    descriptor,
    path,
    heldBefore
  );
  RevalidateRetainedCodes(
    liveCode,
    staticCode,
    path,
    bundleIdentifier,
    teamIdentifier,
    reportedRequirement,
    signing
  );
  struct proc_bsdinfo after = {0};
  struct stat heldAfter = {0};
  struct stat pathnameAfter = {0};
  char finalPath[PROC_PIDPATHINFO_MAXSIZE] = {0};
  int finalPathLength = proc_pidpath(pid, finalPath, sizeof(finalPath));
  if (kill(pid, 0) != 0
      || proc_pidinfo(
        pid,
        PROC_PIDTBSDINFO,
        0,
        &after,
        sizeof(after)
      ) != sizeof(after)
      || finalPathLength < 2
      || finalPathLength >= (int)sizeof(finalPath)
      || fstat(descriptor, &heldAfter) != 0
      || lstat(path.fileSystemRepresentation, &pathnameAfter) != 0
      || !SameExecutableStat(heldBefore, heldAfter)
      || !SameExecutableStat(heldBefore, pathnameAfter)
      || information.pbi_start_tvsec != after.pbi_start_tvsec
      || information.pbi_start_tvusec != after.pbi_start_tvusec
      || strncmp(executablePath, finalPath, sizeof(executablePath)) != 0
      || ![auditTokenSha256 isEqual:AuditTokenSha256(pid)]) {
    Fail(@"A.28 process changed during inspection");
  }
  CFRelease(liveCode);
  CFRelease(staticCode);
  if (close(descriptor) != 0) Fail(@"A.28 held executable close failed");
  return @{
    @"auditTokenSha256": auditTokenSha256,
    @"bundleIdentifier": identifier,
    @"cdHash": Hex(cdHash),
    @"designatedRequirement": actualRequirement,
    @"executable": executable,
    @"pid": @(pid),
    @"startTime": [NSString stringWithFormat:
      @"%llu.%06llu",
      information.pbi_start_tvsec,
      information.pbi_start_tvusec],
  };
}

static NSDictionary *InspectApplication(
  NSString *path,
  NSString *bundleIdentifier,
  NSString *teamIdentifier,
  NSString *reportedRequirement
) {
  NSURL *url = [NSURL fileURLWithPath:path isDirectory:YES];
  SecStaticCodeRef code = NULL;
  OSStatus status = SecStaticCodeCreateWithPath(
    (__bridge CFURLRef)url,
    kSecCSDefaultFlags,
    &code
  );
  if (status != errSecSuccess || code == NULL) {
    Fail(@"A.28 witness application code unavailable");
  }
  SecRequirementRef policyRequirement = CopyPositiveRequirement(
    bundleIdentifier,
    teamIdentifier
  );
  status = SecStaticCodeCheckValidity(
    code,
    kSecCSStrictValidate | kSecCSCheckAllArchitectures,
    policyRequirement
  );
  CFRelease(policyRequirement);
  if (status != errSecSuccess) {
    CFRelease(code);
    Fail(@"A.28 witness application signature rejected");
  }
  CFDictionaryRef copied = NULL;
  status = SecCodeCopySigningInformation(
    code,
    kSecCSSigningInformation | kSecCSRequirementInformation,
    &copied
  );
  CFRelease(code);
  if (status != errSecSuccess || copied == NULL) {
    Fail(@"A.28 witness application signing information unavailable");
  }
  NSDictionary *information = CFBridgingRelease(copied);
  NSString *identifier = information[(__bridge id)kSecCodeInfoIdentifier];
  NSString *team = information[(__bridge id)kSecCodeInfoTeamIdentifier];
  NSData *cdHash = information[(__bridge id)kSecCodeInfoUnique];
  NSArray *certificates = information[(__bridge id)kSecCodeInfoCertificates];
  NSDictionary *entitlements =
    information[(__bridge id)kSecCodeInfoEntitlementsDict];
  SecRequirementRef requirement = (__bridge SecRequirementRef)
    information[(__bridge id)kSecCodeInfoDesignatedRequirement];
  NSNumber *flags = information[(__bridge id)kSecCodeInfoFlags];
  if (![identifier isKindOfClass:NSString.class]
      || ![team isKindOfClass:NSString.class]
      || ![cdHash isKindOfClass:NSData.class]
      || cdHash.length != 20
      || ![certificates isKindOfClass:NSArray.class]
      || certificates.count < 3
      || ![entitlements isKindOfClass:NSDictionary.class]
      || requirement == NULL
      || ![flags isKindOfClass:NSNumber.class]) {
    Fail(@"A.28 witness application signing fields rejected");
  }
  CFStringRef copiedRequirement = NULL;
  status = SecRequirementCopyString(
    requirement,
    kSecCSDefaultFlags,
    &copiedRequirement
  );
  if (status != errSecSuccess || copiedRequirement == NULL) {
    Fail(@"A.28 designated requirement unavailable");
  }
  NSString *designatedRequirement = CFBridgingRelease(copiedRequirement);
  if (![identifier isEqual:bundleIdentifier]
      || ![designatedRequirement isEqual:reportedRequirement]) {
    Fail(@"A.28 witness reported requirement changed");
  }
  NSMutableArray *authorities = [NSMutableArray arrayWithCapacity:certificates.count];
  NSString *leafSha256 = nil;
  for (NSUInteger index = 0; index < certificates.count; index += 1U) {
    SecCertificateRef certificate = (__bridge SecCertificateRef)certificates[index];
    CFStringRef copiedName = NULL;
    status = SecCertificateCopyCommonName(certificate, &copiedName);
    if (status != errSecSuccess || copiedName == NULL) {
      Fail(@"A.28 certificate name unavailable");
    }
    [authorities addObject:CFBridgingRelease(copiedName)];
    if (index == 0) {
      CFDataRef copiedData = SecCertificateCopyData(certificate);
      if (copiedData == NULL) Fail(@"A.28 signing certificate unavailable");
      leafSha256 = Sha256(CFBridgingRelease(copiedData));
    }
  }
  NSString *signingIdentity = authorities.firstObject;
  NSData *entitlementsBytes = [NSJSONSerialization
    dataWithJSONObject:entitlements
    options:(NSJSONWritingSortedKeys | NSJSONWritingWithoutEscapingSlashes)
    error:NULL];
  if (entitlementsBytes == nil || leafSha256 == nil) {
    Fail(@"A.28 effective entitlements rejected");
  }
  NSString *applicationIdentifier =
    entitlements[@"com.apple.application-identifier"];
  if (![applicationIdentifier isKindOfClass:NSString.class]) {
    Fail(@"A.28 application identifier entitlement unavailable");
  }
  return @{
    @"applicationIdentifier": applicationIdentifier,
    @"appleCertificateChain": authorities,
    @"bundleIdentifier": identifier,
    @"cdHash": Hex(cdHash),
    @"designatedRequirement": designatedRequirement,
    @"effectiveEntitlements": entitlements,
    @"effectiveEntitlementsSha256": Sha256(entitlementsBytes),
    @"hardenedRuntime": @((flags.unsignedIntValue
      & kSecCodeSignatureRuntime) == kSecCodeSignatureRuntime),
    @"signingCertificateSha256": leafSha256,
    @"signingIdentity": signingIdentity,
    @"teamIdentifier": team,
  };
}

static void PrintCanonical(NSDictionary *value) {
  NSError *error = nil;
  NSData *bytes = [NSJSONSerialization
    dataWithJSONObject:value
    options:(NSJSONWritingSortedKeys | NSJSONWritingWithoutEscapingSlashes)
    error:&error];
  if (bytes == nil || error != nil) Fail(@"A.28 identity serialisation failed");
  NSMutableData *line = [bytes mutableCopy];
  const unsigned char newline = '\n';
  [line appendBytes:&newline length:1];
  if (write(STDOUT_FILENO, line.bytes, line.length) != (ssize_t)line.length) {
    Fail(@"A.28 identity output failed");
  }
}

int main(int argc, const char *argv[]) {
  @autoreleasepool {
    if (argc != 9
        || strcmp(argv[3], "--bundle-id") != 0
        || strcmp(argv[5], "--team-id") != 0
        || strcmp(argv[7], "--reported-requirement") != 0) {
      Fail(@"Usage: a28-process-identity --pid PID --bundle-id ID --team-id TEAM --reported-requirement REQUIREMENT | --app PATH --bundle-id ID --team-id TEAM --reported-requirement REQUIREMENT");
    }
    NSString *mode = [NSString stringWithUTF8String:argv[1]];
    NSString *value = [NSString stringWithUTF8String:argv[2]];
    NSString *bundleIdentifier = [NSString stringWithUTF8String:argv[4]];
    NSString *teamIdentifier = [NSString stringWithUTF8String:argv[6]];
    NSString *reportedRequirement = [NSString stringWithUTF8String:argv[8]];
    if (reportedRequirement.length < 20U
        || reportedRequirement.length > 4096U) {
      Fail(@"A.28 policy requirement argument rejected");
    }
    if ([mode isEqualToString:@"--pid"]) {
      NSScanner *scanner = [NSScanner scannerWithString:value];
      int pid = 0;
      if (![scanner scanInt:&pid] || !scanner.isAtEnd || pid < 2) {
        Fail(@"A.28 process PID rejected");
      }
      PrintCanonical(InspectPid(
        (pid_t)pid,
        bundleIdentifier,
        teamIdentifier,
        reportedRequirement
      ));
      return EXIT_SUCCESS;
    }
    if ([mode isEqualToString:@"--app"]
        && [value hasPrefix:@"/"]
        && [value hasSuffix:@".app"]) {
      PrintCanonical(InspectApplication(
        value,
        bundleIdentifier,
        teamIdentifier,
        reportedRequirement
      ));
      return EXIT_SUCCESS;
    }
    Fail(@"A.28 process identity arguments rejected");
  }
}
