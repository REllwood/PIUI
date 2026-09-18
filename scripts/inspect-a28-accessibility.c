#include <ApplicationServices/ApplicationServices.h>
#include <CoreFoundation/CoreFoundation.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
  kMaximumDepth = 32,
  kMaximumNodes = 4096,
  kMaximumChildren = 256,
  kMaximumStringBytes = 512,
};

typedef struct {
  pid_t expected_pid;
  size_t nodes_visited;
  size_t list_roles;
  size_t list_item_roles;
  size_t named_transcript_rows;
  size_t focused_transcript_rows;
  size_t unexpected_row_identifiers;
  long focused_row_ordinal;
  long last_row_ordinal;
  bool ordered_transcript_rows;
  bool bounded;
} Evidence;

static bool copy_string_attribute(
  AXUIElementRef element,
  CFStringRef attribute,
  char output[kMaximumStringBytes]
) {
  CFTypeRef value = NULL;
  if (AXUIElementCopyAttributeValue(element, attribute, &value) != kAXErrorSuccess || value == NULL) {
    return false;
  }
  bool copied = false;
  if (CFGetTypeID(value) == CFStringGetTypeID()) {
    copied = CFStringGetCString((CFStringRef)value, output, kMaximumStringBytes, kCFStringEncodingUTF8);
  }
  CFRelease(value);
  return copied;
}

static bool copy_boolean_attribute(AXUIElementRef element, CFStringRef attribute, bool *output) {
  CFTypeRef value = NULL;
  if (AXUIElementCopyAttributeValue(element, attribute, &value) != kAXErrorSuccess || value == NULL) {
    return false;
  }
  bool copied = false;
  if (CFGetTypeID(value) == CFBooleanGetTypeID()) {
    *output = CFBooleanGetValue((CFBooleanRef)value);
    copied = true;
  }
  CFRelease(value);
  return copied;
}

static bool parse_row_ordinal(const char *identifier, long *ordinal) {
  static const char prefix[] = "a28-transcript-row-";
  const size_t prefix_length = sizeof(prefix) - 1;
  if (strncmp(identifier, prefix, prefix_length) != 0) return false;
  const char *digits = identifier + prefix_length;
  if (*digits == '\0') return false;
  errno = 0;
  char *end = NULL;
  const long parsed = strtol(digits, &end, 10);
  if (errno != 0 || end == digits || *end != '\0' || parsed < 1 || parsed > 100) return false;
  *ordinal = parsed;
  return true;
}

static bool has_accessible_name(AXUIElementRef element) {
  const CFStringRef attributes[] = {
    kAXTitleAttribute,
    kAXDescriptionAttribute,
    kAXValueAttribute,
  };
  char value[kMaximumStringBytes] = {0};
  for (size_t index = 0; index < sizeof(attributes) / sizeof(attributes[0]); index += 1) {
    memset(value, 0, sizeof(value));
    if (copy_string_attribute(element, attributes[index], value) && value[0] != '\0') return true;
  }
  return false;
}

static void inspect_element(AXUIElementRef element, size_t depth, Evidence *evidence) {
  if (!evidence->bounded) return;
  if (depth > kMaximumDepth || evidence->nodes_visited >= kMaximumNodes) {
    evidence->bounded = false;
    return;
  }
  evidence->nodes_visited += 1;

  char role[kMaximumStringBytes] = {0};
  if (copy_string_attribute(element, kAXRoleAttribute, role) && strcmp(role, "AXList") == 0) {
    evidence->list_roles += 1;
  }

  char identifier[kMaximumStringBytes] = {0};
  long ordinal = 0;
  if (copy_string_attribute(element, CFSTR("AXDOMIdentifier"), identifier)
      && strncmp(identifier, "a28-transcript-row-", 20) == 0) {
    if (!parse_row_ordinal(identifier, &ordinal)) {
      evidence->unexpected_row_identifiers += 1;
    } else {
      if (strcmp(role, "AXGroup") == 0 || strcmp(role, "AXListItem") == 0) {
        evidence->list_item_roles += 1;
      }
      if (has_accessible_name(element)) evidence->named_transcript_rows += 1;
      if (evidence->last_row_ordinal != 0 && ordinal <= evidence->last_row_ordinal) {
        evidence->ordered_transcript_rows = false;
      }
      evidence->last_row_ordinal = ordinal;
      bool focused = false;
      if (copy_boolean_attribute(element, kAXFocusedAttribute, &focused) && focused) {
        evidence->focused_transcript_rows += 1;
        evidence->focused_row_ordinal = ordinal;
      }
    }
  }

  CFTypeRef children_value = NULL;
  if (AXUIElementCopyAttributeValue(element, kAXChildrenAttribute, &children_value) != kAXErrorSuccess
      || children_value == NULL) return;
  if (CFGetTypeID(children_value) != CFArrayGetTypeID()) {
    CFRelease(children_value);
    return;
  }
  const CFArrayRef children = (CFArrayRef)children_value;
  const CFIndex count = CFArrayGetCount(children);
  if (count < 0 || count > kMaximumChildren) {
    evidence->bounded = false;
    CFRelease(children_value);
    return;
  }
  for (CFIndex index = 0; index < count && evidence->bounded; index += 1) {
    const CFTypeRef child = CFArrayGetValueAtIndex(children, index);
    if (child != NULL && CFGetTypeID(child) == AXUIElementGetTypeID()) {
      inspect_element((AXUIElementRef)child, depth + 1, evidence);
    }
  }
  CFRelease(children_value);
}

static bool parse_pid(const char *value, pid_t *pid) {
  errno = 0;
  char *end = NULL;
  const long parsed = strtol(value, &end, 10);
  if (errno != 0 || end == value || *end != '\0' || parsed < 2 || parsed > INT_MAX) return false;
  *pid = (pid_t)parsed;
  return true;
}

int main(int argc, char *argv[]) {
  if (argc != 2) {
    fputs("A.28 accessibility inspection requires one PID.\n", stderr);
    return 64;
  }
  pid_t expected_pid = 0;
  if (!parse_pid(argv[1], &expected_pid)) {
    fputs("A.28 accessibility inspection rejected the PID.\n", stderr);
    return 64;
  }
  if (!AXIsProcessTrusted()) {
    fputs("A.28 accessibility permission is required.\n", stderr);
    return 77;
  }

  AXUIElementRef application = AXUIElementCreateApplication(expected_pid);
  if (application == NULL) {
    fputs("A.28 could not create the application accessibility element.\n", stderr);
    return 65;
  }
  pid_t observed_pid = 0;
  const bool pid_matched = AXUIElementGetPid(application, &observed_pid) == kAXErrorSuccess
    && observed_pid == expected_pid;
  Evidence evidence = {
    .expected_pid = expected_pid,
    .nodes_visited = 0,
    .list_roles = 0,
    .list_item_roles = 0,
    .named_transcript_rows = 0,
    .focused_transcript_rows = 0,
    .unexpected_row_identifiers = 0,
    .focused_row_ordinal = 0,
    .last_row_ordinal = 0,
    .ordered_transcript_rows = true,
    .bounded = true,
  };
  if (pid_matched) inspect_element(application, 0, &evidence);
  CFRelease(application);

  printf(
    "{\"applicationPidMatched\":%s,\"bounded\":%s,\"focusedRowOrdinal\":%ld,"
    "\"focusedTranscriptRows\":%zu,\"listItemRoles\":%zu,\"listRoles\":%zu,"
    "\"namedTranscriptRows\":%zu,\"nodesVisited\":%zu,\"orderedTranscriptRows\":%s,"
    "\"pid\":%d,\"schemaVersion\":1,\"trusted\":true,\"unexpectedRowIdentifiers\":%zu}\n",
    pid_matched ? "true" : "false",
    evidence.bounded ? "true" : "false",
    evidence.focused_row_ordinal,
    evidence.focused_transcript_rows,
    evidence.list_item_roles,
    evidence.list_roles,
    evidence.named_transcript_rows,
    evidence.nodes_visited,
    evidence.ordered_transcript_rows ? "true" : "false",
    expected_pid,
    evidence.unexpected_row_identifiers
  );
  return pid_matched && evidence.bounded ? 0 : 65;
}
