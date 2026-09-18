#define _DARWIN_C_SOURCE 1

#include <sys/acl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
#ifndef O_DIRECTORY
#define O_DIRECTORY 0
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

#define SCAN_VERSION 1U
#define SCAN_FLAG_HOOKS 1U
#define MAX_ROOTS 16U
#define MAX_AUTHORISED 16U
#define MAX_ENTRIES 512U
#define MAX_DEPTH 32U
#define MAX_FILE_BYTES (256U * 1024U)
#define MAX_AGGREGATE_FILE_DATA_BYTES (2U * 1024U * 1024U)
#define MAX_METADATA_BYTES (16U * 1024U)
#define MAX_RESOLUTION_COMPONENTS 2048U
#define MAX_RESOLUTION_WORK 4096U
#define MAX_OCCURRENCES 4096U
#define MIN_CANARY_BYTES 24U
#define MAX_CANARY_BYTES 1024U
#define MAX_CONFIG_BYTES (64U * 1024U)
#define MAX_XATTR_LIST_BYTES (4U * 1024U)
#define MAX_XATTR_VALUE_BYTES (4U * 1024U)
#define MAX_XATTR_SCAN_BYTES (8U * 1024U)
#define FILE_CHUNK_BYTES (64U * 1024U)
#define FRAME_HEADER_BYTES 28U
#define PARENT_LIVENESS_FD 5
#define WATCHDOG_DEADLINE_SECONDS 20

static const unsigned char FRAME_MAGIC[8] = {'P', 'I', 'U', 'I', 'S', 'C', 'A', 'N'};
static const char SAFE_REJECTION[] =
    "{\"schemaVersion\":1,\"status\":\"rejected\",\"errorCode\":\"canary-scan-rejected\"}\n";
static const char PROVENANCE_XATTR[] = "com.apple.provenance";
static atomic_int WATCHDOG_STOP = 0;

struct Identity {
  dev_t dev;
  ino_t ino;
  mode_t mode;
  nlink_t nlink;
  uid_t uid;
  gid_t gid;
  off_t size;
  struct timespec mtime;
  struct timespec ctime;
};

struct Root {
  char supplied[PATH_MAX];
  char canonical[PATH_MAX];
  struct Identity identity;
  int fd;
  int is_directory;
};

struct Authorisation {
  char supplied[PATH_MAX];
  char canonical[PATH_MAX];
  struct Identity scanned_identity;
  uint32_t expected;
  uint32_t observed_count;
  int observed;
};

struct ScanState {
  unsigned char canary[MAX_CANARY_BYTES];
  uint16_t prefix[MAX_CANARY_BYTES];
  size_t canary_len;
  struct Root roots[MAX_ROOTS];
  size_t root_count;
  struct Authorisation authorised[MAX_AUTHORISED];
  size_t authorised_count;
  char workspace[PATH_MAX];
  char canonical_workspace[PATH_MAX];
  struct Identity workspace_identity;
  fsid_t workspace_mount;
  int authority_root_fd;
  int workspace_fd;
  int workspace_mount_set;
  uint32_t flags;
  size_t entries;
  size_t files;
  size_t file_data_bytes;
  size_t metadata_bytes;
  size_t resolution_components;
  size_t resolution_work;
  size_t authorised_occurrences;
  int file_hook_sent;
};

static void secure_zero(void *pointer, size_t length) {
  volatile unsigned char *bytes = (volatile unsigned char *)pointer;
  while (length > 0) {
    *bytes++ = 0;
    length -= 1;
  }
}

static void *watch_parent_and_deadline(void *unused) {
  (void)unused;
  struct timespec started;
  if (clock_gettime(CLOCK_MONOTONIC, &started) != 0) {
    _exit(1);
  }
  for (;;) {
    if (atomic_load_explicit(&WATCHDOG_STOP, memory_order_acquire) != 0) {
      return NULL;
    }
    struct pollfd watched = {.fd = PARENT_LIVENESS_FD, .events = POLLIN | POLLHUP};
    int result;
    do {
      result = poll(&watched, 1, 100);
    } while (result < 0 && errno == EINTR);
    if (atomic_load_explicit(&WATCHDOG_STOP, memory_order_acquire) != 0) {
      return NULL;
    }
    if (result < 0 || (result > 0 && (watched.revents & (POLLHUP | POLLERR | POLLNVAL)) != 0)) {
      _exit(1);
    }
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0 ||
        now.tv_sec - started.tv_sec >= WATCHDOG_DEADLINE_SECONDS) {
      _exit(1);
    }
  }
}

static int start_watchdog(pthread_t *thread) {
  atomic_store_explicit(&WATCHDOG_STOP, 0, memory_order_release);
  if (fcntl(PARENT_LIVENESS_FD, F_GETFD) < 0 ||
      pthread_create(thread, NULL, watch_parent_and_deadline, NULL) != 0) {
    return -1;
  }
  return 0;
}

static void stop_watchdog(pthread_t thread) {
  atomic_store_explicit(&WATCHDOG_STOP, 1, memory_order_release);
  (void)close(PARENT_LIVENESS_FD);
  (void)pthread_join(thread, NULL);
}

static uint16_t read_u16_be(const unsigned char *bytes) {
  return (uint16_t)(((uint16_t)bytes[0] << 8) | (uint16_t)bytes[1]);
}

static uint32_t read_u32_be(const unsigned char *bytes) {
  return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) |
         ((uint32_t)bytes[2] << 8) | (uint32_t)bytes[3];
}

static int read_exact(int fd, void *output, size_t length) {
  unsigned char *cursor = (unsigned char *)output;
  while (length > 0) {
    ssize_t count = read(fd, cursor, length);
    if (count == 0) {
      return -1;
    }
    if (count < 0) {
      if (errno == EINTR) {
        continue;
      }
      return -1;
    }
    cursor += (size_t)count;
    length -= (size_t)count;
  }
  return 0;
}

static int read_u32(int fd, uint32_t *value, size_t *consumed) {
  unsigned char bytes[4] = {0};
  if (read_exact(fd, bytes, sizeof(bytes)) != 0) {
    secure_zero(bytes, sizeof(bytes));
    return -1;
  }
  *value = read_u32_be(bytes);
  *consumed += sizeof(bytes);
  secure_zero(bytes, sizeof(bytes));
  return 0;
}

static int read_path(int fd, char output[PATH_MAX], size_t *consumed) {
  uint32_t length = 0;
  if (read_u32(fd, &length, consumed) != 0 || length == 0 || length >= PATH_MAX) {
    return -1;
  }
  if (*consumed > MAX_CONFIG_BYTES || length > MAX_CONFIG_BYTES - *consumed) {
    return -1;
  }
  if (read_exact(fd, output, length) != 0) {
    return -1;
  }
  *consumed += length;
  output[length] = '\0';
  if (memchr(output, '\0', length) != NULL || output[0] != '/') {
    return -1;
  }
  return 0;
}

static struct Identity identity_from_stat(const struct stat *item) {
  struct Identity identity;
  identity.dev = item->st_dev;
  identity.ino = item->st_ino;
  identity.mode = item->st_mode;
  identity.nlink = item->st_nlink;
  identity.uid = item->st_uid;
  identity.gid = item->st_gid;
  identity.size = item->st_size;
#if defined(__APPLE__)
  identity.mtime = item->st_mtimespec;
  identity.ctime = item->st_ctimespec;
#else
  identity.mtime = item->st_mtim;
  identity.ctime = item->st_ctim;
#endif
  return identity;
}

static int same_identity(const struct Identity *left, const struct Identity *right) {
  return left->dev == right->dev && left->ino == right->ino &&
         left->mode == right->mode && left->nlink == right->nlink &&
         left->uid == right->uid && left->gid == right->gid &&
         left->size == right->size &&
         left->mtime.tv_sec == right->mtime.tv_sec &&
         left->mtime.tv_nsec == right->mtime.tv_nsec &&
         left->ctime.tv_sec == right->ctime.tv_sec &&
         left->ctime.tv_nsec == right->ctime.tv_nsec;
}

static int stat_identity(int fd, struct Identity *identity) {
  struct stat item;
  if (fstat(fd, &item) != 0) {
    return -1;
  }
  *identity = identity_from_stat(&item);
  secure_zero(&item, sizeof(item));
  return 0;
}

static int supported_identity(const struct Identity *identity, dev_t workspace_device) {
  if (identity->dev != workspace_device || identity->uid != getuid() ||
      (identity->mode & 0077U) != 0) {
    return -1;
  }
  if (!S_ISDIR(identity->mode) && !S_ISREG(identity->mode)) {
    return -1;
  }
  if (S_ISREG(identity->mode) && identity->nlink != 1) {
    return -1;
  }
  return 0;
}

static size_t match_bytes(const struct ScanState *state, const unsigned char *bytes,
                          size_t length, size_t *matched);

static int metadata_budget_available(const struct ScanState *state, size_t amount) {
  return state->metadata_bytes <= MAX_METADATA_BYTES &&
         amount <= MAX_METADATA_BYTES - state->metadata_bytes;
}

static int descriptor_has_allowed_xattrs(struct ScanState *state, int fd) {
#if defined(__APPLE__)
  ssize_t list_length = flistxattr(fd, NULL, 0, 0);
  if (list_length < 0 || list_length > MAX_XATTR_LIST_BYTES) {
    return -1;
  }
  if (list_length == 0) {
    return 0;
  }
  if ((size_t)list_length > MAX_XATTR_SCAN_BYTES ||
      !metadata_budget_available(state, (size_t)list_length)) {
    return -1;
  }

  unsigned char names[MAX_XATTR_LIST_BYTES + 1] = {0};
  if (flistxattr(fd, (char *)names, (size_t)list_length, 0) != list_length) {
    secure_zero(names, sizeof(names));
    return -1;
  }
  state->metadata_bytes += (size_t)list_length;

  /* Xattr names are read exactly once as the bytes returned by flistxattr. */
  size_t descriptor_bytes = (size_t)list_length;
  size_t offset = 0;
  while (offset < (size_t)list_length) {
    char *name = (char *)&names[offset];
    size_t remaining = (size_t)list_length - offset;
    char *terminator = memchr(name, '\0', remaining);
    if (terminator == NULL) {
      secure_zero(names, sizeof(names));
      return -1;
    }

    size_t name_length = (size_t)(terminator - name);
    size_t entry_length = name_length + 1;
    size_t matched = 0;
    if (match_bytes(state, (const unsigned char *)name, name_length, &matched) > 0 ||
        name_length != sizeof(PROVENANCE_XATTR) - 1 ||
        memcmp(name, PROVENANCE_XATTR, sizeof(PROVENANCE_XATTR) - 1) != 0) {
      secure_zero(names, sizeof(names));
      return -1;
    }

    ssize_t value_length = fgetxattr(fd, PROVENANCE_XATTR, NULL, 0, 0, 0);
    if (value_length < 0 || value_length > MAX_XATTR_VALUE_BYTES ||
        descriptor_bytes > MAX_XATTR_SCAN_BYTES - (size_t)value_length ||
        !metadata_budget_available(state, (size_t)value_length)) {
      secure_zero(names, sizeof(names));
      return -1;
    }

    unsigned char value[MAX_XATTR_VALUE_BYTES] = {0};
    if (value_length > 0 &&
        fgetxattr(fd, PROVENANCE_XATTR, value, (size_t)value_length, 0, 0) != value_length) {
      secure_zero(value, sizeof(value));
      secure_zero(names, sizeof(names));
      return -1;
    }
    state->metadata_bytes += (size_t)value_length;
    descriptor_bytes += (size_t)value_length;

    matched = 0;
    if (match_bytes(state, value, (size_t)value_length, &matched) > 0) {
      secure_zero(value, sizeof(value));
      secure_zero(names, sizeof(names));
      return -1;
    }

    secure_zero(value, sizeof(value));
    offset += entry_length;
  }
  secure_zero(names, sizeof(names));
  return 0;
#else
  ssize_t length = flistxattr(fd, NULL, 0);
  return length == 0 ? 0 : -1;
#endif
}

static int descriptor_has_no_acl(int fd) {
  errno = 0;
#if defined(__APPLE__)
  acl_t acl = acl_get_fd_np(fd, ACL_TYPE_EXTENDED);
#else
  acl_t acl = acl_get_fd(fd);
#endif
  if (acl == NULL) {
    return errno == ENOENT ? 0 : -1;
  }
  acl_entry_t entry;
  int result = acl_get_entry(acl, ACL_FIRST_ENTRY, &entry);
  int free_result = acl_free(acl);
  if (free_result != 0 || result < 0) {
    return -1;
  }
  return result == 0 ? 0 : -1;
}

static int descriptor_is_on_workspace_mount(const struct ScanState *state, int fd) {
  struct statfs filesystem;
  if (!state->workspace_mount_set || fstatfs(fd, &filesystem) != 0) {
    secure_zero(&filesystem, sizeof(filesystem));
    return -1;
  }
  int result = memcmp(&state->workspace_mount, &filesystem.f_fsid,
                      sizeof(state->workspace_mount)) == 0
                   ? 0
                   : -1;
  secure_zero(&filesystem, sizeof(filesystem));
  return result;
}

static int validate_descriptor(struct ScanState *state, int fd,
                               dev_t workspace_device, struct Identity *identity) {
  if (stat_identity(fd, identity) != 0 ||
      supported_identity(identity, workspace_device) != 0 ||
      descriptor_is_on_workspace_mount(state, fd) != 0 ||
      descriptor_has_allowed_xattrs(state, fd) != 0 || descriptor_has_no_acl(fd) != 0) {
    return -1;
  }
  return 0;
}

static int path_strictly_below(const char *parent, const char *child) {
  size_t parent_length = strlen(parent);
  if (parent_length == 0 || strncmp(parent, child, parent_length) != 0) {
    return 0;
  }
  if (parent[parent_length - 1] == '/') {
    return child[parent_length] != '\0';
  }
  return child[parent_length] == '/' && child[parent_length + 1] != '\0';
}

static int paths_overlap(const char *left, const char *right) {
  return strcmp(left, right) == 0 || path_strictly_below(left, right) ||
         path_strictly_below(right, left);
}

static const char *path_basename(const char *path) {
  const char *last = strrchr(path, '/');
  return last == NULL ? path : last + 1;
}

static void build_prefix(struct ScanState *state) {
  size_t matched = 0;
  state->prefix[0] = 0;
  for (size_t index = 1; index < state->canary_len; index += 1) {
    while (matched > 0 && state->canary[index] != state->canary[matched]) {
      matched = state->prefix[matched - 1];
    }
    if (state->canary[index] == state->canary[matched]) {
      matched += 1;
    }
    state->prefix[index] = (uint16_t)matched;
  }
}

static size_t match_bytes(const struct ScanState *state, const unsigned char *bytes,
                          size_t length, size_t *matched) {
  size_t occurrences = 0;
  for (size_t index = 0; index < length; index += 1) {
    while (*matched > 0 && bytes[index] != state->canary[*matched]) {
      *matched = state->prefix[*matched - 1];
    }
    if (bytes[index] == state->canary[*matched]) {
      *matched += 1;
    }
    if (*matched == state->canary_len) {
      occurrences += 1;
      *matched = state->prefix[*matched - 1];
    }
  }
  return occurrences;
}

static int name_has_canary(const struct ScanState *state, const char *name) {
  size_t matched = 0;
  return match_bytes(state, (const unsigned char *)name, strlen(name), &matched) > 0 ? -1 : 0;
}

static int signal_hook(const struct ScanState *state, unsigned char phase) {
  if ((state->flags & SCAN_FLAG_HOOKS) == 0) {
    return 0;
  }
  unsigned char acknowledgement = 0;
  ssize_t written;
  do {
    written = write(3, &phase, 1);
  } while (written < 0 && errno == EINTR);
  if (written != 1 || read_exact(4, &acknowledgement, 1) != 0 || acknowledgement != phase) {
    secure_zero(&acknowledgement, sizeof(acknowledgement));
    return -1;
  }
  secure_zero(&acknowledgement, sizeof(acknowledgement));
  return 0;
}

static int relative_path_depth(const struct ScanState *state, const char *canonical,
                               size_t *output_depth) {
  if (!path_strictly_below(state->canonical_workspace, canonical)) {
    return -1;
  }
  const char *relative = canonical + strlen(state->canonical_workspace);
  if (*relative == '/') {
    relative += 1;
  }
  size_t depth = 0;
  const char *component = relative;
  while (*component != '\0') {
    const char *separator = strchr(component, '/');
    size_t length = separator == NULL ? strlen(component) : (size_t)(separator - component);
    if (length == 0 || (length == 1 && component[0] == '.') ||
        (length == 2 && component[0] == '.' && component[1] == '.') || depth >= MAX_DEPTH) {
      return -1;
    }
    depth += 1;
    if (separator == NULL) {
      break;
    }
    component = separator + 1;
  }
  if (depth == 0) {
    return -1;
  }
  *output_depth = depth;
  return 0;
}

static int charge_resolution_component(struct ScanState *state) {
  if (state->resolution_components >= MAX_RESOLUTION_COMPONENTS ||
      state->resolution_work > MAX_RESOLUTION_WORK - 2U) {
    return -1;
  }
  state->resolution_components += 1;
  state->resolution_work += 2;
  return 0;
}

static int open_absolute_from_authority(struct ScanState *state, const char *canonical,
                                        int *output_fd, struct Identity *output_identity) {
  if (state->authority_root_fd < 0 || canonical[0] != '/' || canonical[1] == '\0') {
    return -1;
  }
  char path[PATH_MAX] = {0};
  size_t path_length = strlen(canonical + 1);
  if (path_length == 0 || path_length >= sizeof(path)) {
    return -1;
  }
  memcpy(path, canonical + 1, path_length + 1);

  int current = dup(state->authority_root_fd);
  if (current < 0) {
    secure_zero(path, sizeof(path));
    return -1;
  }
  (void)fcntl(current, F_SETFD, FD_CLOEXEC);
  char *component = path;
  for (;;) {
    char *separator = strchr(component, '/');
    int final = separator == NULL;
    if (separator != NULL) {
      *separator = '\0';
    }
    if (component[0] == '\0' || strcmp(component, ".") == 0 ||
        strcmp(component, "..") == 0 || charge_resolution_component(state) != 0) {
      close(current);
      secure_zero(path, sizeof(path));
      return -1;
    }
    int next = openat(current, component,
                      O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    close(current);
    if (next < 0) {
      secure_zero(path, sizeof(path));
      return -1;
    }
    if (final) {
      if (stat_identity(next, output_identity) != 0 || !S_ISDIR(output_identity->mode)) {
        close(next);
        secure_zero(output_identity, sizeof(*output_identity));
        secure_zero(path, sizeof(path));
        return -1;
      }
      *output_fd = next;
      secure_zero(path, sizeof(path));
      return 0;
    }
    current = next;
    component = separator + 1;
  }
}

static int open_below_workspace(struct ScanState *state, const char *canonical,
                                int *output_fd, struct Identity *output_identity) {
  size_t expected_depth = 0;
  if (relative_path_depth(state, canonical, &expected_depth) != 0) {
    return -1;
  }
  const char *relative = canonical + strlen(state->canonical_workspace);
  if (*relative == '/') {
    relative += 1;
  }
  char path[PATH_MAX] = {0};
  size_t relative_length = strlen(relative);
  if (relative_length == 0 || relative_length >= sizeof(path)) {
    return -1;
  }
  memcpy(path, relative, relative_length + 1);

  int current = dup(state->workspace_fd);
  if (current < 0) {
    secure_zero(path, sizeof(path));
    return -1;
  }
  (void)fcntl(current, F_SETFD, FD_CLOEXEC);

  size_t depth = 0;
  char *component = path;
  for (;;) {
    char *separator = strchr(component, '/');
    int final = separator == NULL;
    if (separator != NULL) {
      *separator = '\0';
    }
    if (component[0] == '\0' || strcmp(component, ".") == 0 ||
        strcmp(component, "..") == 0 || charge_resolution_component(state) != 0) {
      close(current);
      secure_zero(path, sizeof(path));
      return -1;
    }
    depth += 1;
    int flags = O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK;
    if (!final) {
      flags |= O_DIRECTORY;
    }
    int next = openat(current, component, flags);
    close(current);
    if (next < 0) {
      secure_zero(path, sizeof(path));
      return -1;
    }
    struct Identity identity;
    if (validate_descriptor(state, next, state->workspace_identity.dev, &identity) != 0 ||
        (!final && !S_ISDIR(identity.mode))) {
      close(next);
      secure_zero(&identity, sizeof(identity));
      secure_zero(path, sizeof(path));
      return -1;
    }
    if (final) {
      if (depth != expected_depth) {
        close(next);
        secure_zero(&identity, sizeof(identity));
        secure_zero(path, sizeof(path));
        return -1;
      }
      *output_fd = next;
      *output_identity = identity;
      secure_zero(&identity, sizeof(identity));
      secure_zero(path, sizeof(path));
      return 0;
    }
    secure_zero(&identity, sizeof(identity));
    current = next;
    component = separator + 1;
  }
}

static int parse_frame(struct ScanState *state) {
  unsigned char header[FRAME_HEADER_BYTES] = {0};
  size_t consumed = 0;
  if (read_exact(STDIN_FILENO, header, sizeof(header)) != 0 ||
      memcmp(header, FRAME_MAGIC, sizeof(FRAME_MAGIC)) != 0) {
    secure_zero(header, sizeof(header));
    return -1;
  }
  uint32_t version = read_u32_be(header + 8);
  state->flags = read_u32_be(header + 12);
  uint32_t config_length = read_u32_be(header + 16);
  uint32_t canary_length = read_u32_be(header + 20);
  uint16_t root_count = read_u16_be(header + 24);
  uint16_t authorised_count = read_u16_be(header + 26);
  secure_zero(header, sizeof(header));

  if (version != SCAN_VERSION || (state->flags & ~SCAN_FLAG_HOOKS) != 0 ||
      config_length == 0 || config_length > MAX_CONFIG_BYTES ||
      canary_length < MIN_CANARY_BYTES || canary_length > MAX_CANARY_BYTES ||
      root_count == 0 || root_count > MAX_ROOTS || authorised_count == 0 ||
      authorised_count > MAX_AUTHORISED) {
    return -1;
  }

  state->root_count = root_count;
  state->authorised_count = authorised_count;
  state->canary_len = canary_length;
  if (read_path(STDIN_FILENO, state->workspace, &consumed) != 0) {
    return -1;
  }
  for (size_t index = 0; index < state->root_count; index += 1) {
    if (read_path(STDIN_FILENO, state->roots[index].supplied, &consumed) != 0) {
      return -1;
    }
    state->roots[index].fd = -1;
  }
  for (size_t index = 0; index < state->authorised_count; index += 1) {
    uint32_t expected = 0;
    if (read_path(STDIN_FILENO, state->authorised[index].supplied, &consumed) != 0 ||
        read_u32(STDIN_FILENO, &expected, &consumed) != 0 || expected == 0 ||
        expected > MAX_OCCURRENCES) {
      return -1;
    }
    state->authorised[index].expected = expected;
  }
  if (consumed != config_length ||
      read_exact(STDIN_FILENO, state->canary, state->canary_len) != 0) {
    return -1;
  }
  unsigned char overflow = 0;
  ssize_t count;
  do {
    count = read(STDIN_FILENO, &overflow, 1);
  } while (count < 0 && errno == EINTR);
  secure_zero(&overflow, sizeof(overflow));
  if (count != 0) {
    return -1;
  }
  build_prefix(state);
  return 0;
}

static int prepare_workspace(struct ScanState *state) {
  struct stat before;
  if (lstat(state->workspace, &before) != 0 || !S_ISDIR(before.st_mode) ||
      S_ISLNK(before.st_mode) || realpath(state->workspace, state->canonical_workspace) == NULL ||
      strcmp(state->workspace, state->canonical_workspace) != 0) {
    secure_zero(&before, sizeof(before));
    return -1;
  }
  struct Identity observed = identity_from_stat(&before);
  secure_zero(&before, sizeof(before));
  if (observed.uid != getuid() || (observed.mode & 0077U) != 0) {
    secure_zero(&observed, sizeof(observed));
    return -1;
  }
  state->authority_root_fd =
      open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
  struct Identity authority_observed;
  state->workspace_fd = -1;
  if (state->authority_root_fd < 0 ||
      open_absolute_from_authority(state, state->canonical_workspace,
                                   &state->workspace_fd, &authority_observed) != 0 ||
      !same_identity(&observed, &authority_observed)) {
    secure_zero(&authority_observed, sizeof(authority_observed));
    secure_zero(&observed, sizeof(observed));
    return -1;
  }
  secure_zero(&authority_observed, sizeof(authority_observed));
  struct statfs filesystem;
  if (fstatfs(state->workspace_fd, &filesystem) != 0) {
    secure_zero(&filesystem, sizeof(filesystem));
    secure_zero(&observed, sizeof(observed));
    return -1;
  }
  state->workspace_mount = filesystem.f_fsid;
  state->workspace_mount_set = 1;
  secure_zero(&filesystem, sizeof(filesystem));
  if (validate_descriptor(state, state->workspace_fd, observed.dev,
                          &state->workspace_identity) != 0 ||
      !same_identity(&observed, &state->workspace_identity)) {
    secure_zero(&observed, sizeof(observed));
    return -1;
  }
  secure_zero(&observed, sizeof(observed));
  return 0;
}

static int prepare_roots(struct ScanState *state) {
  for (size_t index = 0; index < state->root_count; index += 1) {
    struct Root *root = &state->roots[index];
    struct stat before;
    if (lstat(root->supplied, &before) != 0 || S_ISLNK(before.st_mode) ||
        realpath(root->supplied, root->canonical) == NULL ||
        strcmp(root->supplied, root->canonical) != 0 ||
        !path_strictly_below(state->canonical_workspace, root->canonical) ||
        name_has_canary(state, path_basename(root->canonical)) != 0) {
      secure_zero(&before, sizeof(before));
      return -1;
    }
    struct Identity observed = identity_from_stat(&before);
    secure_zero(&before, sizeof(before));
    if (supported_identity(&observed, state->workspace_identity.dev) != 0 ||
        open_below_workspace(state, root->canonical, &root->fd, &root->identity) != 0 ||
        !same_identity(&observed, &root->identity)) {
      secure_zero(&observed, sizeof(observed));
      return -1;
    }
    root->is_directory = S_ISDIR(root->identity.mode);
    secure_zero(&observed, sizeof(observed));

    for (size_t earlier = 0; earlier < index; earlier += 1) {
      if (paths_overlap(state->roots[earlier].canonical, root->canonical) ||
          (state->roots[earlier].identity.dev == root->identity.dev &&
           state->roots[earlier].identity.ino == root->identity.ino)) {
        return -1;
      }
    }
  }
  return 0;
}

static int prepare_authorisations(struct ScanState *state) {
  for (size_t index = 0; index < state->authorised_count; index += 1) {
    struct Authorisation *authorisation = &state->authorised[index];
    struct stat item;
    if (lstat(authorisation->supplied, &item) != 0 || S_ISLNK(item.st_mode) ||
        !S_ISREG(item.st_mode) || item.st_nlink != 1 || item.st_uid != getuid() ||
        (item.st_mode & 0077U) != 0 || item.st_dev != state->workspace_identity.dev ||
        realpath(authorisation->supplied, authorisation->canonical) == NULL ||
        strcmp(authorisation->supplied, authorisation->canonical) != 0 ||
        !path_strictly_below(state->canonical_workspace, authorisation->canonical)) {
      secure_zero(&item, sizeof(item));
      return -1;
    }
    size_t relative_depth = 0;
    if (relative_path_depth(state, authorisation->canonical, &relative_depth) != 0) {
      secure_zero(&item, sizeof(item));
      return -1;
    }
    relative_depth = 0;
    secure_zero(&item, sizeof(item));
    int beneath_root = 0;
    for (size_t root_index = 0; root_index < state->root_count; root_index += 1) {
      const struct Root *root = &state->roots[root_index];
      if ((!root->is_directory && strcmp(root->canonical, authorisation->canonical) == 0) ||
          (root->is_directory && path_strictly_below(root->canonical, authorisation->canonical))) {
        beneath_root = 1;
        break;
      }
    }
    if (!beneath_root) {
      return -1;
    }
    for (size_t earlier = 0; earlier < index; earlier += 1) {
      if (strcmp(state->authorised[earlier].canonical, authorisation->canonical) == 0) {
        return -1;
      }
    }
  }
  return 0;
}

static struct Authorisation *find_authorisation(struct ScanState *state,
                                                 const char *canonical) {
  for (size_t index = 0; index < state->authorised_count; index += 1) {
    if (strcmp(state->authorised[index].canonical, canonical) == 0) {
      return &state->authorised[index];
    }
  }
  return NULL;
}

static int inspect_entry_fd(struct ScanState *state, int fd, const char *canonical,
                            const struct Identity *observed, size_t depth);

static int inspect_file(struct ScanState *state, int fd, const char *canonical,
                        const struct Identity *before) {
  if (before->size < 0 || (uint64_t)before->size > MAX_FILE_BYTES) {
    return -1;
  }
  if ((state->flags & SCAN_FLAG_HOOKS) != 0 && !state->file_hook_sent) {
    state->file_hook_sent = 1;
    if (signal_hook(state, 3) != 0) {
      return -1;
    }
  }

  unsigned char chunk[FILE_CHUNK_BYTES] = {0};
  size_t total = 0;
  size_t matched = 0;
  size_t occurrences = 0;
  int result = -1;
  if (lseek(fd, 0, SEEK_SET) < 0) {
    goto cleanup;
  }
  for (;;) {
    size_t file_remaining = total <= MAX_FILE_BYTES ? MAX_FILE_BYTES - total : 0;
    size_t aggregate_used = state->file_data_bytes;
    if (aggregate_used > MAX_AGGREGATE_FILE_DATA_BYTES ||
        total > MAX_AGGREGATE_FILE_DATA_BYTES - aggregate_used) {
      goto cleanup;
    }
    size_t aggregate_remaining =
        MAX_AGGREGATE_FILE_DATA_BYTES - aggregate_used - total;
    size_t allowed = file_remaining < aggregate_remaining ? file_remaining
                                                          : aggregate_remaining;
    if (allowed > FILE_CHUNK_BYTES) {
      allowed = FILE_CHUNK_BYTES;
    }
    /* A one-byte read is issued after reaching either exact cap. */
    size_t requested = allowed < FILE_CHUNK_BYTES ? allowed + 1 : FILE_CHUNK_BYTES;
    ssize_t count;
    do {
      count = read(fd, chunk, requested);
    } while (count < 0 && errno == EINTR);
    if (count < 0) {
      goto cleanup;
    }
    if (count == 0) {
      break;
    }
    if ((size_t)count > allowed) {
      goto cleanup;
    }
    occurrences += match_bytes(state, chunk, (size_t)count, &matched);
    total += (size_t)count;
    secure_zero(chunk, sizeof(chunk));
  }

  struct Identity after;
  if (validate_descriptor(state, fd, state->workspace_identity.dev, &after) != 0 ||
      !same_identity(before, &after) || (uint64_t)after.size != total) {
    secure_zero(&after, sizeof(after));
    goto cleanup;
  }
  secure_zero(&after, sizeof(after));

  struct Authorisation *authorisation = find_authorisation(state, canonical);
  if (authorisation == NULL) {
    if (occurrences != 0) {
      goto cleanup;
    }
  } else {
    if (occurrences != authorisation->expected) {
      goto cleanup;
    }
    authorisation->scanned_identity = *before;
    authorisation->observed = 1;
    authorisation->observed_count = (uint32_t)occurrences;
    state->authorised_occurrences += occurrences;
  }
  state->files += 1;
  state->file_data_bytes += total;
  result = 0;

cleanup:
  secure_zero(chunk, sizeof(chunk));
  matched = 0;
  occurrences = 0;
  total = 0;
  return result;
}

static int join_canonical(const char *parent, const char *name, char output[PATH_MAX]) {
  size_t parent_length = strlen(parent);
  size_t name_length = strlen(name);
  if (parent_length == 0 || name_length == 0 ||
      parent_length + 1 + name_length >= PATH_MAX) {
    return -1;
  }
  memcpy(output, parent, parent_length);
  output[parent_length] = '/';
  memcpy(output + parent_length + 1, name, name_length + 1);
  return 0;
}

static int inspect_directory(struct ScanState *state, int fd, const char *canonical,
                             const struct Identity *before, size_t depth) {
  if (find_authorisation(state, canonical) != NULL || depth >= MAX_DEPTH) {
    return -1;
  }
  int enumeration_fd = dup(fd);
  if (enumeration_fd < 0) {
    return -1;
  }
  (void)fcntl(enumeration_fd, F_SETFD, FD_CLOEXEC);
  DIR *directory = fdopendir(enumeration_fd);
  if (directory == NULL) {
    close(enumeration_fd);
    return -1;
  }

  int result = -1;
  errno = 0;
  for (;;) {
    struct dirent *entry = readdir(directory);
    if (entry == NULL) {
      if (errno != 0) {
        goto cleanup;
      }
      break;
    }
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
      continue;
    }
    size_t name_length = strlen(entry->d_name);
    if (name_length == 0 || name_length > NAME_MAX ||
        name_has_canary(state, entry->d_name) != 0) {
      goto cleanup;
    }
    state->entries += 1;
    if (state->entries > MAX_ENTRIES) {
      goto cleanup;
    }

    struct stat observed_stat;
    if (fstatat(fd, entry->d_name, &observed_stat, AT_SYMLINK_NOFOLLOW) != 0 ||
        S_ISLNK(observed_stat.st_mode)) {
      secure_zero(&observed_stat, sizeof(observed_stat));
      goto cleanup;
    }
    struct Identity observed = identity_from_stat(&observed_stat);
    secure_zero(&observed_stat, sizeof(observed_stat));
    if (supported_identity(&observed, state->workspace_identity.dev) != 0) {
      secure_zero(&observed, sizeof(observed));
      goto cleanup;
    }
    int child_flags = O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK;
    if (S_ISDIR(observed.mode)) {
      child_flags |= O_DIRECTORY;
    }
    int child_fd = openat(fd, entry->d_name, child_flags);
    if (child_fd < 0) {
      secure_zero(&observed, sizeof(observed));
      goto cleanup;
    }
    char child_canonical[PATH_MAX] = {0};
    if (join_canonical(canonical, entry->d_name, child_canonical) != 0 ||
        inspect_entry_fd(state, child_fd, child_canonical, &observed, depth + 1) != 0) {
      close(child_fd);
      secure_zero(child_canonical, sizeof(child_canonical));
      secure_zero(&observed, sizeof(observed));
      goto cleanup;
    }
    close(child_fd);
    secure_zero(child_canonical, sizeof(child_canonical));
    secure_zero(&observed, sizeof(observed));
    errno = 0;
  }

  struct Identity after;
  if (validate_descriptor(state, fd, state->workspace_identity.dev, &after) != 0 ||
      !same_identity(before, &after)) {
    secure_zero(&after, sizeof(after));
    goto cleanup;
  }
  secure_zero(&after, sizeof(after));
  result = 0;

cleanup:
  closedir(directory);
  return result;
}

static int inspect_entry_fd(struct ScanState *state, int fd, const char *canonical,
                            const struct Identity *observed, size_t depth) {
  struct Identity before;
  if (validate_descriptor(state, fd, state->workspace_identity.dev, &before) != 0 ||
      !same_identity(observed, &before)) {
    secure_zero(&before, sizeof(before));
    return -1;
  }
  int result;
  if (S_ISREG(before.mode)) {
    result = inspect_file(state, fd, canonical, &before);
  } else if (S_ISDIR(before.mode)) {
    result = inspect_directory(state, fd, canonical, &before, depth);
  } else {
    result = -1;
  }
  secure_zero(&before, sizeof(before));
  return result;
}

static int scan_roots(struct ScanState *state) {
  for (size_t index = 0; index < state->root_count; index += 1) {
    struct Root *root = &state->roots[index];
    state->entries += 1;
    if (state->entries > MAX_ENTRIES ||
        inspect_entry_fd(state, root->fd, root->canonical, &root->identity, 0) != 0) {
      return -1;
    }
  }
  for (size_t index = 0; index < state->authorised_count; index += 1) {
    if (!state->authorised[index].observed ||
        state->authorised[index].observed_count != state->authorised[index].expected) {
      return -1;
    }
  }
  return 0;
}

/*
 * This is the pass linearisation point. Every declared path is resolved again
 * from the held workspace namespace after traversal and any test hook, and its
 * complete identity must still be the object that was held or scanned.
 */
static int validate_pass_authority(struct ScanState *state) {
  int current_workspace_fd = -1;
  struct Identity workspace_after;
  if (open_absolute_from_authority(state, state->canonical_workspace,
                                   &current_workspace_fd, &workspace_after) != 0 ||
      validate_descriptor(state, current_workspace_fd, state->workspace_identity.dev,
                          &workspace_after) != 0 ||
      !same_identity(&state->workspace_identity, &workspace_after)) {
    if (current_workspace_fd >= 0) {
      close(current_workspace_fd);
    }
    secure_zero(&workspace_after, sizeof(workspace_after));
    return -1;
  }
  close(current_workspace_fd);
  secure_zero(&workspace_after, sizeof(workspace_after));

  for (size_t index = 0; index < state->root_count; index += 1) {
    int current_fd = -1;
    struct Identity current_identity;
    if (open_below_workspace(state, state->roots[index].canonical, &current_fd,
                             &current_identity) != 0 ||
        !same_identity(&state->roots[index].identity, &current_identity)) {
      if (current_fd >= 0) {
        close(current_fd);
      }
      secure_zero(&current_identity, sizeof(current_identity));
      return -1;
    }
    close(current_fd);
    secure_zero(&current_identity, sizeof(current_identity));
  }

  for (size_t index = 0; index < state->authorised_count; index += 1) {
    struct Authorisation *authorisation = &state->authorised[index];
    int current_fd = -1;
    struct Identity current_identity;
    if (!authorisation->observed ||
        open_below_workspace(state, authorisation->canonical, &current_fd,
                             &current_identity) != 0 ||
        !same_identity(&authorisation->scanned_identity, &current_identity)) {
      if (current_fd >= 0) {
        close(current_fd);
      }
      secure_zero(&current_identity, sizeof(current_identity));
      return -1;
    }
    close(current_fd);
    secure_zero(&current_identity, sizeof(current_identity));
  }
  return 0;
}

static void cleanup_state(struct ScanState *state) {
  for (size_t index = 0; index < MAX_ROOTS; index += 1) {
    if (state->roots[index].fd >= 0) {
      close(state->roots[index].fd);
      state->roots[index].fd = -1;
    }
  }
  if (state->workspace_fd >= 0) {
    close(state->workspace_fd);
    state->workspace_fd = -1;
  }
  if (state->authority_root_fd >= 0) {
    close(state->authority_root_fd);
    state->authority_root_fd = -1;
  }
  secure_zero(state, sizeof(*state));
}

int main(int argc, char **argv) {
  (void)argv;
  pthread_t watchdog;
  if (argc != 1 || start_watchdog(&watchdog) != 0) {
    (void)write(STDOUT_FILENO, SAFE_REJECTION, sizeof(SAFE_REJECTION) - 1);
    return 1;
  }
  struct ScanState state;
  memset(&state, 0, sizeof(state));
  state.authority_root_fd = -1;
  state.workspace_fd = -1;
  for (size_t index = 0; index < MAX_ROOTS; index += 1) {
    state.roots[index].fd = -1;
  }

  int passed = parse_frame(&state) == 0 && prepare_workspace(&state) == 0 &&
               prepare_roots(&state) == 0 &&
               prepare_authorisations(&state) == 0 && signal_hook(&state, 1) == 0 &&
               scan_roots(&state) == 0 && signal_hook(&state, 2) == 0 &&
               validate_pass_authority(&state) == 0;

  size_t root_count = state.root_count;
  size_t entries = state.entries;
  size_t files = state.files;
  size_t file_data_bytes = state.file_data_bytes;
  size_t metadata_bytes = state.metadata_bytes;
  size_t authorised_count = state.authorised_count;
  size_t authorised_occurrences = state.authorised_occurrences;
  cleanup_state(&state);
  stop_watchdog(watchdog);

  if (passed) {
    (void)dprintf(STDOUT_FILENO,
                  "{\"schemaVersion\":1,\"status\":\"pass\",\"rootsScanned\":%zu,"
                  "\"entriesScanned\":%zu,\"filesScanned\":%zu,"
                  "\"fileDataBytesScanned\":%zu,\"metadataBytesScanned\":%zu,"
                  "\"authorisedFiles\":%zu,\"authorisedOccurrences\":%zu,"
                  "\"unauthorisedOccurrences\":0}\n",
                  root_count, entries, files, file_data_bytes, metadata_bytes,
                  authorised_count, authorised_occurrences);
  } else {
    (void)write(STDOUT_FILENO, SAFE_REJECTION, sizeof(SAFE_REJECTION) - 1);
  }
  return passed ? 0 : 1;
}
