#if !defined(__APPLE__)

int main(void) {
  return 125;
}

#else

#define _DARWIN_C_SOURCE 1

#include <sys/acl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
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

struct expected_identity {
  uint64_t dev;
  uint64_t ino;
  uint64_t uid;
  uint64_t gid;
  uint64_t mode;
};

struct expected_file_state {
  struct expected_identity identity;
  uint64_t nlink;
  uint64_t size;
  uint64_t mtime_ns;
  uint64_t ctime_ns;
};

#define HELD_DIRECTORY_FD 3
#define HELD_FILE_FD 4
#define RENAME_SOURCE_PARENT_FD 3
#define RENAME_DESTINATION_PARENT_FD 4
#define RENAME_SOURCE_FD 5
#define HELD_HELPER_SOURCE_FD 6
#define HELD_HELPER_WORKSPACE_FD 7
#define HELD_HELPER_PARENT_FD 8
#define HELD_HELPER_FD 9
#define MAX_REWRITE_BYTES (1024U * 1024U)
#define MAX_PLACEHOLDER_XATTR_VALUE_BYTES (4U * 1024U)
#define MAX_TREE_DEPTH 128U
#define MAX_TREE_ENTRIES 100000U
#define RENAME_COMPLETED_REJECTED 76

static int parse_u64(const char *text, uint64_t *value) {
  char *end = NULL;
  unsigned long long parsed;

  if (text == NULL || text[0] == '\0' || text[0] == '-') {
    return -1;
  }
  errno = 0;
  parsed = strtoull(text, &end, 10);
  if (errno != 0 || end == text || *end != '\0') {
    return -1;
  }
  *value = (uint64_t)parsed;
  return 0;
}

static int parse_identity(char *const arguments[], struct expected_identity *identity) {
  return parse_u64(arguments[0], &identity->dev) == 0 &&
                 parse_u64(arguments[1], &identity->ino) == 0 &&
                 parse_u64(arguments[2], &identity->uid) == 0 &&
                 parse_u64(arguments[3], &identity->gid) == 0 &&
                 parse_u64(arguments[4], &identity->mode) == 0
             ? 0
             : -1;
}

static int parse_file_state(char *const arguments[], struct expected_file_state *state) {
  return parse_identity(arguments, &state->identity) == 0 &&
                 parse_u64(arguments[5], &state->nlink) == 0 &&
                 parse_u64(arguments[6], &state->size) == 0 &&
                 parse_u64(arguments[7], &state->mtime_ns) == 0 &&
                 parse_u64(arguments[8], &state->ctime_ns) == 0
             ? 0
             : -1;
}

static int safe_name(const char *name) {
  size_t length;

  if (name == NULL || name[0] == '\0' || strcmp(name, ".") == 0 ||
      strcmp(name, "..") == 0 || strchr(name, '/') != NULL) {
    return 0;
  }
  length = strlen(name);
  return length <= NAME_MAX;
}

static int matches_expected_directory(const struct stat *state,
                                      const struct expected_identity *expected) {
  return S_ISDIR(state->st_mode) && (uint64_t)state->st_dev == expected->dev &&
         (uint64_t)state->st_ino == expected->ino &&
         (uint64_t)state->st_uid == expected->uid &&
         (uint64_t)state->st_gid == expected->gid &&
         (uint64_t)state->st_mode == expected->mode &&
         state->st_uid == geteuid() && (state->st_mode & 0022U) == 0U;
}

static int matches_private_source_directory(const struct stat *state,
                                            const struct expected_identity *expected) {
  return matches_expected_directory(state, expected) &&
         (state->st_mode & 0777U) == 0700U;
}

static uint64_t stat_mtime_ns(const struct stat *state) {
  return (uint64_t)state->st_mtimespec.tv_sec * UINT64_C(1000000000) +
         (uint64_t)state->st_mtimespec.tv_nsec;
}

static uint64_t stat_ctime_ns(const struct stat *state) {
  return (uint64_t)state->st_ctimespec.tv_sec * UINT64_C(1000000000) +
         (uint64_t)state->st_ctimespec.tv_nsec;
}

static int matches_expected_file(const struct stat *state,
                                 const struct expected_file_state *expected) {
  return S_ISREG(state->st_mode) &&
         (uint64_t)state->st_dev == expected->identity.dev &&
         (uint64_t)state->st_ino == expected->identity.ino &&
         (uint64_t)state->st_uid == expected->identity.uid &&
         (uint64_t)state->st_gid == expected->identity.gid &&
         (uint64_t)state->st_mode == expected->identity.mode &&
         (uint64_t)state->st_nlink == expected->nlink &&
         (uint64_t)state->st_size == expected->size &&
         stat_mtime_ns(state) == expected->mtime_ns &&
         stat_ctime_ns(state) == expected->ctime_ns &&
         state->st_uid == geteuid() && state->st_nlink == 1 &&
         (state->st_mode & 0022U) == 0U;
}

static int matches_expected_directory_state(
    const struct stat *state, const struct expected_file_state *expected) {
  return matches_expected_directory(state, &expected->identity) &&
         (uint64_t)state->st_nlink == expected->nlink &&
         (uint64_t)state->st_size == expected->size &&
         stat_mtime_ns(state) == expected->mtime_ns &&
         stat_ctime_ns(state) == expected->ctime_ns;
}

static int same_directory_identity(const struct stat *left, const struct stat *right) {
  return S_ISDIR(left->st_mode) && S_ISDIR(right->st_mode) &&
         left->st_dev == right->st_dev && left->st_ino == right->st_ino &&
         left->st_mode == right->st_mode && left->st_uid == right->st_uid &&
         left->st_gid == right->st_gid && left->st_nlink == right->st_nlink;
}

static int same_directory_object(const struct stat *left, const struct stat *right) {
  return S_ISDIR(left->st_mode) && S_ISDIR(right->st_mode) &&
         left->st_dev == right->st_dev && left->st_ino == right->st_ino &&
         left->st_mode == right->st_mode && left->st_uid == right->st_uid &&
         left->st_gid == right->st_gid;
}

static int same_regular_file_object(const struct stat *left, const struct stat *right) {
  return S_ISREG(left->st_mode) && S_ISREG(right->st_mode) &&
         left->st_dev == right->st_dev && left->st_ino == right->st_ino &&
         left->st_uid == right->st_uid && left->st_gid == right->st_gid &&
         left->st_nlink == right->st_nlink;
}

static int descriptor_path_is(int fd, const char *expected) {
  char path[PATH_MAX];

  if (fcntl(fd, F_GETPATH, path) != 0) {
    return 0;
  }
  return strcmp(path, expected) == 0;
}

static int descriptor_path(int fd, char path[PATH_MAX]) {
  return fcntl(fd, F_GETPATH, path) == 0 && path[0] == '/';
}

static int direct_child_path(const char *parent, const char *child) {
  size_t parent_length;
  const char *name;

  if (parent == NULL || child == NULL) {
    return 0;
  }
  parent_length = strlen(parent);
  if (parent_length == 0U || strncmp(parent, child, parent_length) != 0 ||
      child[parent_length] != '/') {
    return 0;
  }
  name = child + parent_length + 1U;
  return safe_name(name);
}

static int destination_missing(int parent_fd, const char *name) {
  struct stat unused;

  errno = 0;
  return fstatat(parent_fd, name, &unused, AT_SYMLINK_NOFOLLOW) == -1 && errno == ENOENT;
}

static int synchronise_test_phase(const char *selected_phase,
                                  const char *required_phase,
                                  const char *ready_path,
                                  const char *continue_path) {
  struct stat continue_state;
  struct timespec delay = {0, 1000000L};
  unsigned int attempt;
  int ready_fd;

  if (selected_phase == NULL) {
    return 0;
  }
  if (strcmp(selected_phase, required_phase) != 0) {
    return 0;
  }
  if (ready_path == NULL || continue_path == NULL || ready_path[0] != '/' ||
      continue_path[0] != '/' || strlen(ready_path) >= PATH_MAX ||
      strlen(continue_path) >= PATH_MAX || strcmp(ready_path, continue_path) == 0) {
    return -1;
  }
  ready_fd = open(ready_path,
                  O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                  0600);
  if (ready_fd < 0) {
    return -1;
  }
  if (close(ready_fd) != 0) {
    return -1;
  }
  for (attempt = 0U; attempt < 5000U; attempt += 1U) {
    if (lstat(continue_path, &continue_state) == 0) {
      return S_ISREG(continue_state.st_mode) && continue_state.st_nlink == 1 &&
                     continue_state.st_uid == geteuid() &&
                     (continue_state.st_mode & 0022U) == 0U
                 ? 0
                 : -1;
    }
    if (errno != ENOENT || nanosleep(&delay, NULL) != 0) {
      return -1;
    }
  }
  return -1;
}

static int descriptor_has_no_extended_acl(int fd) {
  acl_t acl;

  errno = 0;
  acl = acl_get_fd_np(fd, ACL_TYPE_EXTENDED);
  if (acl != NULL) {
    (void)acl_free(acl);
    return 0;
  }
  return errno == ENOENT;
}

struct placeholder_xattrs {
  int provenance_present;
  size_t provenance_length;
  unsigned char provenance[MAX_PLACEHOLDER_XATTR_VALUE_BYTES];
};

static int capture_placeholder_xattrs(int fd, struct placeholder_xattrs *captured) {
  static const char allowed[] = "com.apple.provenance";
  char names[sizeof(allowed)];
  ssize_t list_length;
  ssize_t value_length;

  memset(captured, 0, sizeof(*captured));
  errno = 0;
  list_length = flistxattr(fd, NULL, 0U, 0);
  if (list_length == 0) {
    return 0;
  }
  if (list_length != (ssize_t)sizeof(allowed) ||
      flistxattr(fd, names, sizeof(names), 0) != list_length ||
      memcmp(names, allowed, sizeof(allowed)) != 0) {
    return -1;
  }
  value_length = fgetxattr(fd, allowed, NULL, 0U, 0U, 0);
  if (value_length < 0 ||
      (uint64_t)value_length > MAX_PLACEHOLDER_XATTR_VALUE_BYTES ||
      (value_length > 0 &&
       fgetxattr(fd, allowed, captured->provenance,
                 (size_t)value_length, 0U, 0) != value_length)) {
    memset(captured, 0, sizeof(*captured));
    return -1;
  }
  captured->provenance_present = 1;
  captured->provenance_length = (size_t)value_length;
  return 0;
}

static int same_placeholder_xattrs(const struct placeholder_xattrs *left,
                                   const struct placeholder_xattrs *right) {
  return left->provenance_present == right->provenance_present &&
         left->provenance_length == right->provenance_length &&
         memcmp(left->provenance, right->provenance,
                left->provenance_length) == 0;
}

static int descriptor_directory_is_empty(int fd) {
  DIR *directory = NULL;
  struct dirent *entry;
  int duplicate_fd;
  int status = -1;

  duplicate_fd = openat(fd, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (duplicate_fd < 0) {
    return -1;
  }
  directory = fdopendir(duplicate_fd);
  if (directory == NULL) {
    (void)close(duplicate_fd);
    return -1;
  }
  errno = 0;
  while ((entry = readdir(directory)) != NULL) {
    if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
      goto cleanup;
    }
    errno = 0;
  }
  if (errno == 0) {
    status = 0;
  }

cleanup:
  if (closedir(directory) != 0) {
    status = -1;
  }
  return status;
}

static int same_tree_state(const struct stat *left, const struct stat *right) {
  return left->st_dev == right->st_dev && left->st_ino == right->st_ino &&
         left->st_mode == right->st_mode && left->st_uid == right->st_uid &&
         left->st_gid == right->st_gid && left->st_nlink == right->st_nlink &&
         left->st_size == right->st_size &&
         stat_mtime_ns(left) == stat_mtime_ns(right) &&
         stat_ctime_ns(left) == stat_ctime_ns(right);
}

static int same_placeholder_state(const struct stat *left,
                                  const struct stat *right) {
  return same_tree_state(left, right) && left->st_flags == right->st_flags;
}

static int same_placeholder_after_rename(const struct stat *left,
                                         const struct stat *right) {
  return same_directory_identity(left, right) &&
         left->st_size == right->st_size &&
         stat_mtime_ns(left) == stat_mtime_ns(right) &&
         left->st_flags == right->st_flags;
}

static int capture_empty_placeholder_state(
    int fd, int parent_fd, const char *name, struct stat *captured_state,
    struct placeholder_xattrs *captured_xattrs) {
  struct stat before;
  struct stat path_before;
  struct stat after;
  struct stat path_after;
  struct placeholder_xattrs xattrs_before;
  struct placeholder_xattrs xattrs_after;
  int status = -1;

  memset(&xattrs_before, 0, sizeof(xattrs_before));
  memset(&xattrs_after, 0, sizeof(xattrs_after));
  if (fd < 0 || parent_fd < 0 || !safe_name(name) ||
      fstat(fd, &before) != 0 ||
      fstatat(parent_fd, name, &path_before, AT_SYMLINK_NOFOLLOW) != 0 ||
      !same_placeholder_state(&before, &path_before) ||
      (before.st_mode & 0777U) != 0700U || before.st_flags != 0U ||
      !descriptor_has_no_extended_acl(fd) ||
      descriptor_directory_is_empty(fd) != 0 ||
      capture_placeholder_xattrs(fd, &xattrs_before) != 0 ||
      fstat(fd, &after) != 0 ||
      fstatat(parent_fd, name, &path_after, AT_SYMLINK_NOFOLLOW) != 0 ||
      !same_placeholder_state(&before, &after) ||
      !same_placeholder_state(&after, &path_after) ||
      !descriptor_has_no_extended_acl(fd) ||
      descriptor_directory_is_empty(fd) != 0 ||
      capture_placeholder_xattrs(fd, &xattrs_after) != 0 ||
      !same_placeholder_xattrs(&xattrs_before, &xattrs_after)) {
    goto cleanup;
  }
  *captured_state = after;
  *captured_xattrs = xattrs_after;
  status = 0;

cleanup:
  memset(&xattrs_before, 0, sizeof(xattrs_before));
  memset(&xattrs_after, 0, sizeof(xattrs_after));
  return status;
}

static int inspect_tree_directory(int directory_fd, uint64_t expected_uid,
                                  unsigned int depth, unsigned int *entries) {
  struct stat directory_before;
  struct stat directory_after;
  DIR *directory = NULL;
  struct dirent *entry;
  int duplicate_fd = -1;
  int status = -1;

  if (depth > MAX_TREE_DEPTH || fstat(directory_fd, &directory_before) != 0 ||
      !S_ISDIR(directory_before.st_mode) ||
      (uint64_t)directory_before.st_uid != expected_uid ||
      (directory_before.st_mode & 0022U) != 0U ||
      !descriptor_has_no_extended_acl(directory_fd)) {
    return -1;
  }
  duplicate_fd = openat(directory_fd, ".",
                        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (duplicate_fd < 0 || fstat(duplicate_fd, &directory_after) != 0 ||
      !same_tree_state(&directory_before, &directory_after)) {
    if (duplicate_fd >= 0) {
      (void)close(duplicate_fd);
    }
    return -1;
  }
  directory = fdopendir(duplicate_fd);
  if (directory == NULL) {
    (void)close(duplicate_fd);
    return -1;
  }
  duplicate_fd = -1;
  for (;;) {
    struct stat path_state;
    struct stat opened_state;
    int child_fd;
    int flags;

    errno = 0;
    entry = readdir(directory);
    if (entry == NULL) {
      if (errno != 0) {
        goto cleanup;
      }
      break;
    }
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
      continue;
    }
    if (!safe_name(entry->d_name) || *entries >= MAX_TREE_ENTRIES ||
        fstatat(directory_fd, entry->d_name, &path_state, AT_SYMLINK_NOFOLLOW) != 0 ||
        S_ISLNK(path_state.st_mode) ||
        (!S_ISDIR(path_state.st_mode) && !S_ISREG(path_state.st_mode)) ||
        (uint64_t)path_state.st_uid != expected_uid ||
        (path_state.st_mode & 0022U) != 0U ||
        (S_ISREG(path_state.st_mode) && path_state.st_nlink != 1)) {
      goto cleanup;
    }
    *entries += 1U;
    flags = O_RDONLY | O_NOFOLLOW | O_CLOEXEC;
    if (S_ISDIR(path_state.st_mode)) {
      flags |= O_DIRECTORY;
    }
    child_fd = openat(directory_fd, entry->d_name, flags);
    if (child_fd < 0 || fstat(child_fd, &opened_state) != 0 ||
        !same_tree_state(&path_state, &opened_state) ||
        !descriptor_has_no_extended_acl(child_fd)) {
      if (child_fd >= 0) {
        (void)close(child_fd);
      }
      goto cleanup;
    }
    if (S_ISDIR(opened_state.st_mode) &&
        inspect_tree_directory(child_fd, expected_uid, depth + 1U, entries) != 0) {
      (void)close(child_fd);
      goto cleanup;
    }
    if (fstatat(directory_fd, entry->d_name, &path_state,
                AT_SYMLINK_NOFOLLOW) != 0 ||
        !same_tree_state(&opened_state, &path_state)) {
      (void)close(child_fd);
      goto cleanup;
    }
    if (close(child_fd) != 0) {
      goto cleanup;
    }
  }
  if (fstat(directory_fd, &directory_after) != 0 ||
      !same_tree_state(&directory_before, &directory_after)) {
    goto cleanup;
  }
  status = 0;

cleanup:
  if (directory != NULL && closedir(directory) != 0) {
    status = -1;
  }
  if (duplicate_fd >= 0 && close(duplicate_fd) != 0) {
    status = -1;
  }
  return status;
}

static int advance_shared_directory_offset(int directory_fd) {
  DIR *directory;
  struct dirent *entry;
  int duplicate_fd = dup(directory_fd);
  int status = -1;

  if (duplicate_fd < 0) {
    return -1;
  }
  directory = fdopendir(duplicate_fd);
  if (directory == NULL) {
    (void)close(duplicate_fd);
    return -1;
  }
  errno = 0;
  while ((entry = readdir(directory)) != NULL) {
    (void)entry;
    errno = 0;
  }
  if (errno == 0) {
    status = 0;
  }
  if (closedir(directory) != 0) {
    status = -1;
  }
  return status;
}

static int directory_has_exact_entries(int directory_fd, const char *first,
                                       const char *second) {
  DIR *directory;
  struct dirent *entry;
  int fresh_fd;
  int saw_first = 0;
  int saw_second = 0;
  int status = -1;

  fresh_fd = openat(directory_fd, ".",
                    O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (fresh_fd < 0) {
    return -1;
  }
  directory = fdopendir(fresh_fd);
  if (directory == NULL) {
    (void)close(fresh_fd);
    return -1;
  }
  errno = 0;
  while ((entry = readdir(directory)) != NULL) {
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
      errno = 0;
      continue;
    }
    if (strcmp(entry->d_name, first) == 0 && !saw_first) {
      saw_first = 1;
    } else if (strcmp(entry->d_name, second) == 0 && !saw_second) {
      saw_second = 1;
    } else {
      goto cleanup;
    }
    errno = 0;
  }
  if (errno == 0 && saw_first && saw_second) {
    status = 0;
  }

cleanup:
  if (closedir(directory) != 0) {
    status = -1;
  }
  return status;
}

static int authenticated_helper_fd(const char *path) {
  struct stat helper_state;
  struct stat held_helper_state;
  struct stat workspace_state;
  struct stat workspace_path_state;
  struct stat parent_state;
  struct stat parent_path_state;
  char canonical[PATH_MAX];
  char workspace_path[PATH_MAX];
  char parent_path[PATH_MAX];
  int helper_fd;

  if (path == NULL || path[0] != '/' || strlen(path) >= PATH_MAX ||
      realpath(path, canonical) == NULL || strcmp(path, canonical) != 0) {
    return -1;
  }
  helper_fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  if (helper_fd < 0 || fstat(helper_fd, &helper_state) != 0 ||
      fstat(HELD_HELPER_FD, &held_helper_state) != 0 ||
      fstat(HELD_HELPER_WORKSPACE_FD, &workspace_state) != 0 ||
      fstat(HELD_HELPER_PARENT_FD, &parent_state) != 0 ||
      !descriptor_path(HELD_HELPER_WORKSPACE_FD, workspace_path) ||
      !descriptor_path(HELD_HELPER_PARENT_FD, parent_path) ||
      lstat(workspace_path, &workspace_path_state) != 0 ||
      lstat(parent_path, &parent_path_state) != 0 ||
      !S_ISREG(helper_state.st_mode) || helper_state.st_nlink != 1 ||
      helper_state.st_uid != geteuid() || (helper_state.st_mode & 0777U) != 0700U ||
      !same_tree_state(&helper_state, &held_helper_state) ||
      !S_ISDIR(workspace_state.st_mode) || workspace_state.st_uid != geteuid() ||
      (workspace_state.st_mode & 0777U) != 0700U ||
      !same_directory_object(&workspace_state, &workspace_path_state) ||
      !S_ISDIR(parent_state.st_mode) || parent_state.st_uid != geteuid() ||
      (parent_state.st_mode & 0022U) != 0U ||
      !same_directory_object(&parent_state, &parent_path_state) ||
      !direct_child_path(parent_path, workspace_path) ||
      !direct_child_path(workspace_path, path) ||
      !descriptor_has_no_extended_acl(helper_fd) ||
      !descriptor_has_no_extended_acl(HELD_HELPER_FD) ||
      !descriptor_has_no_extended_acl(HELD_HELPER_WORKSPACE_FD) ||
      !descriptor_has_no_extended_acl(HELD_HELPER_PARENT_FD) ||
      !descriptor_path_is(helper_fd, path)) {
    if (helper_fd >= 0) {
      (void)close(helper_fd);
    }
    return -1;
  }
  return helper_fd;
}

static int inspect_held_path(int argc, char *argv[]) {
  const char *path;
  const char *kind;
  struct expected_file_state expected;
  struct stat before;
  struct stat pathname_before;
  struct stat after;
  struct stat pathname_after;
  char canonical[PATH_MAX];
  int helper_fd = -1;
  int status = 1;

  if (argc != 13 || parse_file_state(&argv[4], &expected) != 0) {
    return 2;
  }
  path = argv[2];
  kind = argv[3];
  if (path == NULL || path[0] != '/' || strlen(path) >= PATH_MAX ||
      (strcmp(kind, "directory") != 0 && strcmp(kind, "mutable-directory") != 0 &&
       strcmp(kind, "file") != 0) ||
      realpath(path, canonical) == NULL || strcmp(path, canonical) != 0) {
    return 3;
  }
  helper_fd = authenticated_helper_fd(argv[0]);
  if (helper_fd < 0 || fstat(HELD_DIRECTORY_FD, &before) != 0 ||
      lstat(path, &pathname_before) != 0 ||
      (strcmp(kind, "directory") == 0
           ? (!matches_expected_directory_state(&before, &expected) ||
              !same_tree_state(&before, &pathname_before))
           : strcmp(kind, "mutable-directory") == 0
               ? (!matches_expected_directory(&before, &expected.identity) ||
                  !same_directory_object(&before, &pathname_before))
           : (!matches_expected_file(&before, &expected) ||
              !same_tree_state(&before, &pathname_before))) ||
      !descriptor_path_is(HELD_DIRECTORY_FD, path) ||
      !descriptor_has_no_extended_acl(HELD_DIRECTORY_FD)) {
    goto cleanup;
  }
  if (fstat(HELD_DIRECTORY_FD, &after) != 0 ||
      lstat(path, &pathname_after) != 0 ||
      (strcmp(kind, "directory") == 0
           ? (!same_tree_state(&before, &after) ||
              !same_tree_state(&before, &pathname_after))
           : strcmp(kind, "mutable-directory") == 0
               ? (!same_directory_object(&before, &after) ||
                  !same_directory_object(&before, &pathname_after))
           : (!same_tree_state(&before, &after) ||
              !same_tree_state(&before, &pathname_after))) ||
      !descriptor_path_is(HELD_DIRECTORY_FD, path) ||
      realpath(path, canonical) == NULL || strcmp(path, canonical) != 0) {
    goto cleanup;
  }
  status = 0;

cleanup:
  if (helper_fd >= 0 && close(helper_fd) != 0) {
    status = 1;
  }
  return status;
}

static int inspect_held_empty_placeholder(int argc, char *argv[]) {
  const char *path;
  struct expected_file_state expected;
  struct stat before;
  struct stat pathname_before;
  struct stat stable;
  struct stat pathname_stable;
  struct stat after;
  struct stat pathname_after;
  struct placeholder_xattrs xattrs_before;
  struct placeholder_xattrs xattrs_after;
  char canonical[PATH_MAX];
  int helper_fd = -1;
  int status = 1;

  if (argc != 12 || parse_file_state(&argv[3], &expected) != 0) {
    return 2;
  }
  path = argv[2];
  if (strcmp(argv[1], "--inspect-held-empty-placeholder") != 0 ||
      path == NULL || path[0] != '/' || strlen(path) >= PATH_MAX ||
      realpath(path, canonical) == NULL || strcmp(path, canonical) != 0) {
    return 3;
  }
  helper_fd = authenticated_helper_fd(argv[0]);
  if (helper_fd < 0 || fstat(HELD_DIRECTORY_FD, &before) != 0 ||
      lstat(path, &pathname_before) != 0 ||
      !matches_expected_directory_state(&before, &expected) ||
      !same_placeholder_state(&before, &pathname_before) ||
      (before.st_mode & 0777U) != 0700U || before.st_flags != 0U ||
      !descriptor_path_is(HELD_DIRECTORY_FD, path) ||
      !descriptor_has_no_extended_acl(HELD_DIRECTORY_FD) ||
      descriptor_directory_is_empty(HELD_DIRECTORY_FD) != 0 ||
      capture_placeholder_xattrs(HELD_DIRECTORY_FD, &xattrs_before) != 0) {
    goto cleanup;
  }
  if (fstat(HELD_DIRECTORY_FD, &stable) != 0 ||
      lstat(path, &pathname_stable) != 0 ||
      !same_placeholder_state(&before, &stable) ||
      !same_placeholder_state(&stable, &pathname_stable) ||
      (stable.st_mode & 0777U) != 0700U || stable.st_flags != 0U ||
      !descriptor_path_is(HELD_DIRECTORY_FD, path) ||
      !descriptor_has_no_extended_acl(HELD_DIRECTORY_FD) ||
      descriptor_directory_is_empty(HELD_DIRECTORY_FD) != 0 ||
      capture_placeholder_xattrs(HELD_DIRECTORY_FD, &xattrs_after) != 0 ||
      !same_placeholder_xattrs(&xattrs_before, &xattrs_after) ||
      fstat(HELD_DIRECTORY_FD, &after) != 0 ||
      lstat(path, &pathname_after) != 0 ||
      !same_placeholder_state(&stable, &after) ||
      !same_placeholder_state(&after, &pathname_after) ||
      !descriptor_path_is(HELD_DIRECTORY_FD, path) ||
      realpath(path, canonical) == NULL || strcmp(path, canonical) != 0) {
    goto cleanup;
  }
  status = 0;

cleanup:
  if (helper_fd >= 0 && close(helper_fd) != 0) {
    status = 1;
  }
  memset(&xattrs_before, 0, sizeof(xattrs_before));
  memset(&xattrs_after, 0, sizeof(xattrs_after));
  return status;
}

static int inspect_held_tree(int argc, char *argv[]) {
  const char *path;
  struct expected_file_state expected;
  struct stat before;
  struct stat pathname_before;
  struct stat after;
  struct stat pathname_after;
  char canonical[PATH_MAX];
  unsigned int entries = 0U;
  int helper_fd = -1;
  int status = 1;

  if (argc != 12 || parse_file_state(&argv[3], &expected) != 0) {
    return 2;
  }
  path = argv[2];
  if (path == NULL || path[0] != '/' || strlen(path) >= PATH_MAX ||
      realpath(path, canonical) == NULL || strcmp(path, canonical) != 0) {
    return 3;
  }
  helper_fd = authenticated_helper_fd(argv[0]);
  if (helper_fd < 0 || fstat(HELD_DIRECTORY_FD, &before) != 0 ||
      lstat(path, &pathname_before) != 0 ||
      !matches_expected_directory_state(&before, &expected) ||
      !same_tree_state(&before, &pathname_before) ||
      !descriptor_path_is(HELD_DIRECTORY_FD, path) ||
      (strcmp(argv[1], "--inspect-held-tree-after-offset") == 0 &&
       advance_shared_directory_offset(HELD_DIRECTORY_FD) != 0) ||
      inspect_tree_directory(HELD_DIRECTORY_FD, expected.identity.uid, 0U, &entries) != 0 ||
      fstat(HELD_DIRECTORY_FD, &after) != 0 ||
      lstat(path, &pathname_after) != 0 ||
      !same_tree_state(&before, &after) ||
      !same_tree_state(&after, &pathname_after) ||
      !descriptor_path_is(HELD_DIRECTORY_FD, path) ||
      realpath(path, canonical) == NULL || strcmp(path, canonical) != 0) {
    goto cleanup;
  }
  status = 0;

cleanup:
  if (helper_fd >= 0 && close(helper_fd) != 0) {
    status = 1;
  }
  return status;
}

static int rewrite_held_file(int argc, char *argv[]) {
  const char *parent_path;
  const char *name;
  struct expected_file_state expected_parent;
  struct expected_file_state expected_file;
  struct stat parent_before;
  struct stat parent_path_before;
  struct stat parent_after;
  struct stat parent_path_after;
  struct stat file_before;
  struct stat file_path_before;
  struct stat held_writable_before;
  struct stat writable_before;
  struct stat writable_path_before;
  struct stat file_after;
  struct stat writable_after;
  struct stat file_path_after;
  struct stat file_verified;
  struct stat writable_verified;
  struct stat file_path_verified;
  struct stat parent_verified;
  struct stat parent_path_verified;
  char canonical_parent[PATH_MAX];
  unsigned char *bytes = NULL;
  unsigned char verification[4096];
  size_t capacity = 4096U;
  size_t length = 0U;
  ssize_t count;
  size_t offset;
  int helper_fd = -1;
  int writable_fd = -1;
  int status = 1;

  if (argc != 22 || parse_file_state(&argv[4], &expected_parent) != 0 ||
      parse_file_state(&argv[13], &expected_file) != 0) {
    return 2;
  }
  parent_path = argv[2];
  name = argv[3];
  if (parent_path == NULL || parent_path[0] != '/' ||
      strlen(parent_path) >= PATH_MAX || !safe_name(name) ||
      realpath(parent_path, canonical_parent) == NULL ||
      strcmp(parent_path, canonical_parent) != 0) {
    return 3;
  }
  bytes = malloc(capacity);
  if (bytes == NULL) {
    return 4;
  }
  while ((count = read(STDIN_FILENO, bytes + length, capacity - length)) > 0) {
    length += (size_t)count;
    if (length == capacity) {
      unsigned char *grown;
      if (capacity >= MAX_REWRITE_BYTES) {
        unsigned char extra;
        count = read(STDIN_FILENO, &extra, 1U);
        if (count != 0) {
          goto cleanup;
        }
        break;
      }
      capacity *= 2U;
      if (capacity > MAX_REWRITE_BYTES) {
        capacity = MAX_REWRITE_BYTES;
      }
      grown = realloc(bytes, capacity);
      if (grown == NULL) {
        goto cleanup;
      }
      bytes = grown;
    }
  }
  if (count < 0 || length == 0U || length > MAX_REWRITE_BYTES) {
    goto cleanup;
  }

  helper_fd = authenticated_helper_fd(argv[0]);
  if (helper_fd < 0 || fstat(HELD_DIRECTORY_FD, &parent_before) != 0 ||
      lstat(parent_path, &parent_path_before) != 0 ||
      !matches_expected_directory_state(&parent_before, &expected_parent) ||
      !same_tree_state(&parent_before, &parent_path_before) ||
      !descriptor_path_is(HELD_DIRECTORY_FD, parent_path) ||
      !descriptor_has_no_extended_acl(HELD_DIRECTORY_FD) ||
      fstat(HELD_FILE_FD, &file_before) != 0 ||
      fstatat(HELD_DIRECTORY_FD, name, &file_path_before, AT_SYMLINK_NOFOLLOW) != 0 ||
      !matches_expected_file(&file_before, &expected_file) ||
      !same_regular_file_object(&file_before, &file_path_before) ||
      file_before.st_mode != file_path_before.st_mode ||
      file_before.st_size != file_path_before.st_size ||
      stat_mtime_ns(&file_before) != stat_mtime_ns(&file_path_before) ||
      stat_ctime_ns(&file_before) != stat_ctime_ns(&file_path_before) ||
      !descriptor_has_no_extended_acl(HELD_FILE_FD)) {
    goto cleanup;
  }
  if (fchmod(HELD_FILE_FD, 0600) != 0) {
    goto cleanup;
  }
  writable_fd = openat(HELD_DIRECTORY_FD, name,
                       O_RDWR | O_NOFOLLOW | O_CLOEXEC);
  if (writable_fd < 0 || fstat(HELD_FILE_FD, &held_writable_before) != 0 ||
      fstat(writable_fd, &writable_before) != 0 ||
      fstatat(HELD_DIRECTORY_FD, name, &writable_path_before,
              AT_SYMLINK_NOFOLLOW) != 0 ||
      !same_tree_state(&held_writable_before, &writable_before) ||
      !same_tree_state(&writable_before, &writable_path_before) ||
      !same_regular_file_object(&file_before, &writable_before) ||
      (writable_before.st_mode & 0777U) != 0600U ||
      !descriptor_has_no_extended_acl(writable_fd) ||
      ftruncate(writable_fd, 0) != 0) {
    goto cleanup;
  }
  offset = 0U;
  while (offset < length) {
    count = pwrite(writable_fd, bytes + offset, length - offset, (off_t)offset);
    if (count <= 0) {
      goto cleanup;
    }
    offset += (size_t)count;
  }
  if (fsync(writable_fd) != 0 || fstat(HELD_FILE_FD, &file_after) != 0 ||
      fstat(writable_fd, &writable_after) != 0 ||
      fstatat(HELD_DIRECTORY_FD, name, &file_path_after, AT_SYMLINK_NOFOLLOW) != 0 ||
      fstat(HELD_DIRECTORY_FD, &parent_after) != 0 ||
      lstat(parent_path, &parent_path_after) != 0 ||
      !same_regular_file_object(&file_before, &file_after) ||
      !same_tree_state(&file_after, &writable_after) ||
      !same_tree_state(&writable_after, &file_path_after) ||
      !same_tree_state(&parent_before, &parent_after) ||
      !same_tree_state(&parent_after, &parent_path_after) ||
      (file_after.st_mode & 0777U) != 0600U ||
      file_after.st_size != (off_t)length || writable_after.st_size != (off_t)length ||
      file_path_after.st_size != (off_t)length ||
      !descriptor_has_no_extended_acl(HELD_FILE_FD) ||
      !descriptor_has_no_extended_acl(writable_fd) ||
      !descriptor_path_is(HELD_DIRECTORY_FD, parent_path) ||
      realpath(parent_path, canonical_parent) == NULL ||
      strcmp(parent_path, canonical_parent) != 0) {
    goto cleanup;
  }
  offset = 0U;
  while (offset < length) {
    size_t wanted = length - offset;
    if (wanted > sizeof(verification)) {
      wanted = sizeof(verification);
    }
    count = pread(writable_fd, verification, wanted, (off_t)offset);
    if (count != (ssize_t)wanted ||
        memcmp(verification, bytes + offset, wanted) != 0) {
      goto cleanup;
    }
    offset += wanted;
  }
  if (fstat(HELD_FILE_FD, &file_verified) != 0 ||
      fstat(writable_fd, &writable_verified) != 0 ||
      fstatat(HELD_DIRECTORY_FD, name, &file_path_verified,
              AT_SYMLINK_NOFOLLOW) != 0 ||
      fstat(HELD_DIRECTORY_FD, &parent_verified) != 0 ||
      lstat(parent_path, &parent_path_verified) != 0 ||
      !same_tree_state(&file_after, &file_verified) ||
      !same_tree_state(&file_verified, &writable_verified) ||
      !same_tree_state(&writable_verified, &file_path_verified) ||
      !same_tree_state(&parent_after, &parent_verified) ||
      !same_tree_state(&parent_verified, &parent_path_verified) ||
      !descriptor_has_no_extended_acl(HELD_FILE_FD) ||
      !descriptor_has_no_extended_acl(writable_fd) ||
      !descriptor_has_no_extended_acl(HELD_DIRECTORY_FD) ||
      !descriptor_path_is(HELD_DIRECTORY_FD, parent_path)) {
    goto cleanup;
  }
  status = 0;

cleanup:
  memset(verification, 0, sizeof(verification));
  if (bytes != NULL) {
    memset(bytes, 0, capacity);
    free(bytes);
  }
  if (writable_fd >= 0 && close(writable_fd) != 0) {
    status = 1;
  }
  if (helper_fd >= 0 && close(helper_fd) != 0) {
    status = 1;
  }
  return status;
}

static int cleanup_held_helper_workspace(int argc, char *argv[]) {
  const char *workspace_path;
  const char *source_name;
  const char *helper_name;
  const char *test_ready_path = NULL;
  const char *test_continue_path = NULL;
  struct expected_file_state expected_source;
  struct expected_file_state expected_helper;
  struct stat workspace_before;
  struct stat workspace_path_before;
  struct stat workspace_after;
  struct stat parent_before;
  struct stat parent_path_before;
  struct stat parent_after;
  struct stat source_path_state;
  struct stat source_held_state;
  struct stat source_opened_state;
  struct stat helper_path_state;
  struct stat helper_held_state;
  struct stat helper_opened_state;
  char held_workspace_path[PATH_MAX];
  char held_parent_path[PATH_MAX];
  const char *workspace_name;
  int authenticated_fd = -1;
  int source_fd = -1;
  int helper_entry_fd = -1;
  int status = 1;

  if ((argc != 23 && argc != 25) ||
      parse_file_state(&argv[5], &expected_source) != 0 ||
      parse_file_state(&argv[14], &expected_helper) != 0) {
    return 2;
  }
  workspace_path = argv[2];
  source_name = argv[3];
  helper_name = argv[4];
  if (argc == 25) {
    test_ready_path = argv[23];
    test_continue_path = argv[24];
  }
  if (workspace_path == NULL || workspace_path[0] != '/' ||
      strlen(workspace_path) >= PATH_MAX || !safe_name(source_name) ||
      !safe_name(helper_name) || strcmp(source_name, helper_name) == 0) {
    return 3;
  }

  authenticated_fd = authenticated_helper_fd(argv[0]);
  if (authenticated_fd < 0 ||
      fstat(HELD_HELPER_WORKSPACE_FD, &workspace_before) != 0 ||
      fstat(HELD_HELPER_PARENT_FD, &parent_before) != 0 ||
      fstat(HELD_HELPER_SOURCE_FD, &source_held_state) != 0 ||
      fstat(HELD_HELPER_FD, &helper_held_state) != 0 ||
      !descriptor_path(HELD_HELPER_WORKSPACE_FD, held_workspace_path) ||
      !descriptor_path(HELD_HELPER_PARENT_FD, held_parent_path) ||
      strcmp(workspace_path, held_workspace_path) != 0 ||
      !direct_child_path(held_parent_path, held_workspace_path) ||
      lstat(held_workspace_path, &workspace_path_before) != 0 ||
      lstat(held_parent_path, &parent_path_before) != 0 ||
      !same_directory_object(&workspace_before, &workspace_path_before) ||
      !same_directory_object(&parent_before, &parent_path_before) ||
      !matches_expected_file(&source_held_state, &expected_source) ||
      !matches_expected_file(&helper_held_state, &expected_helper) ||
      !descriptor_has_no_extended_acl(HELD_HELPER_WORKSPACE_FD) ||
      !descriptor_has_no_extended_acl(HELD_HELPER_PARENT_FD) ||
      !descriptor_has_no_extended_acl(HELD_HELPER_SOURCE_FD) ||
      !descriptor_has_no_extended_acl(HELD_HELPER_FD) ||
      directory_has_exact_entries(HELD_HELPER_WORKSPACE_FD, source_name,
                                  helper_name) != 0) {
    goto cleanup;
  }

  if (synchronise_test_phase(test_ready_path == NULL ? NULL : "cleanup",
                             "cleanup", test_ready_path,
                             test_continue_path) != 0) {
    goto cleanup;
  }

  workspace_name = strrchr(held_workspace_path, '/');
  if (workspace_name == NULL || !safe_name(workspace_name + 1) ||
      !descriptor_path_is(HELD_HELPER_WORKSPACE_FD, held_workspace_path) ||
      fstatat(HELD_HELPER_PARENT_FD, workspace_name + 1,
              &workspace_path_before, AT_SYMLINK_NOFOLLOW) != 0 ||
      !same_directory_object(&workspace_before, &workspace_path_before) ||
      !descriptor_has_no_extended_acl(HELD_HELPER_WORKSPACE_FD) ||
      !descriptor_has_no_extended_acl(HELD_HELPER_PARENT_FD)) {
    goto cleanup;
  }

  source_fd = openat(HELD_HELPER_WORKSPACE_FD, source_name,
                     O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  helper_entry_fd = openat(HELD_HELPER_WORKSPACE_FD, helper_name,
                           O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  if (source_fd < 0 || helper_entry_fd < 0 ||
      fstat(source_fd, &source_opened_state) != 0 ||
      fstat(helper_entry_fd, &helper_opened_state) != 0 ||
      fstatat(HELD_HELPER_WORKSPACE_FD, source_name, &source_path_state,
              AT_SYMLINK_NOFOLLOW) != 0 ||
      fstatat(HELD_HELPER_WORKSPACE_FD, helper_name, &helper_path_state,
              AT_SYMLINK_NOFOLLOW) != 0 ||
      !same_tree_state(&source_held_state, &source_opened_state) ||
      !same_tree_state(&source_opened_state, &source_path_state) ||
      !same_tree_state(&helper_held_state, &helper_opened_state) ||
      !same_tree_state(&helper_opened_state, &helper_path_state) ||
      !descriptor_has_no_extended_acl(source_fd) ||
      !descriptor_has_no_extended_acl(helper_entry_fd) ||
      directory_has_exact_entries(HELD_HELPER_WORKSPACE_FD, source_name,
                                  helper_name) != 0 ||
      unlinkat(HELD_HELPER_WORKSPACE_FD, source_name, 0) != 0) {
    goto cleanup;
  }
  errno = 0;
  if (!(fstatat(HELD_HELPER_WORKSPACE_FD, source_name, &source_path_state,
                AT_SYMLINK_NOFOLLOW) == -1 &&
        errno == ENOENT) ||
      fstatat(HELD_HELPER_WORKSPACE_FD, helper_name, &helper_path_state,
              AT_SYMLINK_NOFOLLOW) != 0 ||
      !same_tree_state(&helper_held_state, &helper_path_state) ||
      unlinkat(HELD_HELPER_WORKSPACE_FD, helper_name, 0) != 0) {
    goto cleanup;
  }
  errno = 0;
  if (!(fstatat(HELD_HELPER_WORKSPACE_FD, helper_name, &helper_path_state,
                AT_SYMLINK_NOFOLLOW) == -1 &&
        errno == ENOENT)) {
    goto cleanup;
  }

  if (fstat(HELD_HELPER_WORKSPACE_FD, &workspace_after) != 0 ||
      fstat(HELD_HELPER_PARENT_FD, &parent_after) != 0 ||
      fstatat(HELD_HELPER_PARENT_FD, workspace_name + 1,
              &workspace_path_before, AT_SYMLINK_NOFOLLOW) != 0 ||
      !same_directory_object(&workspace_before, &workspace_after) ||
      !same_directory_object(&workspace_before, &workspace_path_before) ||
      !same_directory_object(&parent_before, &parent_after) ||
      !descriptor_path_is(HELD_HELPER_WORKSPACE_FD, held_workspace_path) ||
      !descriptor_has_no_extended_acl(HELD_HELPER_WORKSPACE_FD) ||
      !descriptor_has_no_extended_acl(HELD_HELPER_PARENT_FD) ||
      unlinkat(HELD_HELPER_PARENT_FD, workspace_name + 1, AT_REMOVEDIR) != 0) {
    goto cleanup;
  }
  errno = 0;
  if (!(fstatat(HELD_HELPER_PARENT_FD, workspace_name + 1,
                &workspace_path_before, AT_SYMLINK_NOFOLLOW) == -1 &&
        errno == ENOENT)) {
    goto cleanup;
  }
  status = 0;

cleanup:
  if (helper_entry_fd >= 0 && close(helper_entry_fd) != 0) {
    status = 1;
  }
  if (source_fd >= 0 && close(source_fd) != 0) {
    status = 1;
  }
  if (authenticated_fd >= 0 && close(authenticated_fd) != 0) {
    status = 1;
  }
  return status;
}

static int rename_exclusive(int argc, char *argv[]) {
  const char *source_parent_path;
  const char *source_name;
  const char *destination_parent_path;
  const char *destination_name;
  const char *source_policy;
  struct expected_identity expected_source_parent;
  struct expected_identity expected_destination_parent;
  struct expected_identity expected_source;
  struct stat source_parent_before;
  struct stat source_parent_path_before;
  struct stat source_parent_after;
  struct stat source_parent_path_after;
  struct stat destination_parent_before;
  struct stat destination_parent_path_before;
  struct stat destination_parent_after;
  struct stat destination_parent_path_after;
  struct stat source_before;
  struct stat source_name_before;
  struct stat source_after;
  struct stat destination_after;
  struct stat destination_verified;
  struct stat placeholder_before;
  struct stat placeholder_current;
  struct placeholder_xattrs placeholder_xattrs_before;
  struct placeholder_xattrs placeholder_xattrs_current;
  char canonical_source_parent[PATH_MAX];
  char canonical_source_parent_after[PATH_MAX];
  char canonical_destination_parent[PATH_MAX];
  char canonical_destination_parent_after[PATH_MAX];
  int source_parent_fd = RENAME_SOURCE_PARENT_FD;
  int destination_parent_fd = RENAME_DESTINATION_PARENT_FD;
  int source_fd = RENAME_SOURCE_FD;
  int helper_fd = -1;
  int operation_completed = 0;
  int require_empty_placeholder = 0;
  int status = 1;
  const char *test_phase = NULL;
  const char *test_ready_path = NULL;
  const char *test_continue_path = NULL;

  memset(&placeholder_xattrs_before, 0, sizeof(placeholder_xattrs_before));
  memset(&placeholder_xattrs_current, 0, sizeof(placeholder_xattrs_current));
  if (argc != 21 && argc != 24) {
    return 2;
  }
  source_parent_path = argv[1];
  source_name = argv[2];
  destination_parent_path = argv[3];
  destination_name = argv[4];
  source_policy = argv[5];
  if (source_parent_path == NULL || source_parent_path[0] != '/' ||
      strlen(source_parent_path) >= PATH_MAX || destination_parent_path == NULL ||
      destination_parent_path[0] != '/' || strlen(destination_parent_path) >= PATH_MAX ||
      !safe_name(source_name) || !safe_name(destination_name) ||
      (strcmp(source_policy, "private-directory") != 0 &&
       strcmp(source_policy, "empty-placeholder") != 0) ||
      (strcmp(source_parent_path, destination_parent_path) == 0 &&
       strcmp(source_name, destination_name) == 0) ||
      parse_identity(&argv[6], &expected_source_parent) != 0 ||
      parse_identity(&argv[11], &expected_destination_parent) != 0 ||
      parse_identity(&argv[16], &expected_source) != 0 ||
      expected_source_parent.uid != (uint64_t)geteuid() ||
      expected_destination_parent.uid != (uint64_t)geteuid() ||
      expected_source.uid != (uint64_t)geteuid()) {
    return 3;
  }
  require_empty_placeholder = strcmp(source_policy, "empty-placeholder") == 0;
  if (argc == 24) {
    test_phase = argv[21];
    test_ready_path = argv[22];
    test_continue_path = argv[23];
    if (strcmp(test_phase, "before-final-check") != 0 &&
        strcmp(test_phase, "after-final-check") != 0 &&
        strcmp(test_phase, "after-rename") != 0) {
      return 3;
    }
  }
  if (realpath(source_parent_path, canonical_source_parent) == NULL ||
      strcmp(source_parent_path, canonical_source_parent) != 0 ||
      realpath(destination_parent_path, canonical_destination_parent) == NULL ||
      strcmp(destination_parent_path, canonical_destination_parent) != 0) {
    return 4;
  }

  helper_fd = authenticated_helper_fd(argv[0]);
  if (helper_fd < 0) {
    goto cleanup;
  }

  if (source_parent_fd < 0 || destination_parent_fd < 0 ||
      fstat(source_parent_fd, &source_parent_before) != 0 ||
      lstat(source_parent_path, &source_parent_path_before) != 0 ||
      fstat(destination_parent_fd, &destination_parent_before) != 0 ||
      lstat(destination_parent_path, &destination_parent_path_before) != 0 ||
      !matches_expected_directory(&source_parent_before, &expected_source_parent) ||
      !matches_expected_directory(&destination_parent_before,
                                  &expected_destination_parent) ||
      !same_directory_identity(&source_parent_before, &source_parent_path_before) ||
      !same_directory_identity(&destination_parent_before,
                               &destination_parent_path_before) ||
      !descriptor_has_no_extended_acl(source_parent_fd) ||
      !descriptor_has_no_extended_acl(destination_parent_fd)) {
    goto cleanup;
  }

  if (source_fd < 0 || fstat(source_fd, &source_before) != 0 ||
      fstatat(source_parent_fd, source_name, &source_name_before,
              AT_SYMLINK_NOFOLLOW) != 0 ||
      !matches_private_source_directory(&source_before, &expected_source) ||
      !same_directory_identity(&source_before, &source_name_before) ||
      source_before.st_dev != source_parent_before.st_dev ||
      source_before.st_dev != destination_parent_before.st_dev ||
      !descriptor_has_no_extended_acl(source_fd) ||
      !destination_missing(destination_parent_fd, destination_name)) {
    goto cleanup;
  }
  if (require_empty_placeholder &&
      (capture_empty_placeholder_state(
           source_fd, source_parent_fd, source_name, &placeholder_before,
           &placeholder_xattrs_before) != 0 ||
       !same_placeholder_state(&source_before, &placeholder_before))) {
    goto cleanup;
  }

  if (synchronise_test_phase(test_phase, "before-final-check", test_ready_path,
                             test_continue_path) != 0 ||
      fstat(source_parent_fd, &source_parent_after) != 0 ||
      lstat(source_parent_path, &source_parent_path_after) != 0 ||
      fstat(destination_parent_fd, &destination_parent_after) != 0 ||
      lstat(destination_parent_path, &destination_parent_path_after) != 0 ||
      fstat(source_fd, &source_after) != 0 ||
      fstatat(source_parent_fd, source_name, &source_name_before,
              AT_SYMLINK_NOFOLLOW) != 0 ||
      !same_directory_identity(&source_parent_before, &source_parent_after) ||
      !same_directory_identity(&source_parent_before, &source_parent_path_after) ||
      !same_directory_identity(&destination_parent_before, &destination_parent_after) ||
      !same_directory_identity(&destination_parent_before,
                               &destination_parent_path_after) ||
      !same_directory_identity(&source_before, &source_after) ||
      !same_directory_identity(&source_before, &source_name_before) ||
      !descriptor_path_is(source_parent_fd, source_parent_path) ||
      !descriptor_path_is(destination_parent_fd, destination_parent_path) ||
      !descriptor_has_no_extended_acl(source_parent_fd) ||
      !descriptor_has_no_extended_acl(destination_parent_fd) ||
      !descriptor_has_no_extended_acl(source_fd) ||
      !destination_missing(destination_parent_fd, destination_name) ||
      realpath(source_parent_path, canonical_source_parent_after) == NULL ||
      strcmp(canonical_source_parent, canonical_source_parent_after) != 0 ||
      realpath(destination_parent_path, canonical_destination_parent_after) == NULL ||
      strcmp(canonical_destination_parent, canonical_destination_parent_after) != 0) {
    goto cleanup;
  }
  if (require_empty_placeholder &&
      (capture_empty_placeholder_state(
           source_fd, source_parent_fd, source_name, &placeholder_current,
           &placeholder_xattrs_current) != 0 ||
       !same_placeholder_state(&placeholder_before, &placeholder_current) ||
       !same_placeholder_xattrs(&placeholder_xattrs_before,
                                &placeholder_xattrs_current))) {
    goto cleanup;
  }

  {
    char source_path[PATH_MAX];
    int written = snprintf(source_path, sizeof(source_path), "%s/%s",
                           source_parent_path, source_name);
    if (written < 0 || (size_t)written >= sizeof(source_path) ||
        !descriptor_path_is(source_fd, source_path)) {
      goto cleanup;
    }
  }

  if (synchronise_test_phase(test_phase, "after-final-check", test_ready_path,
                             test_continue_path) != 0) {
    goto cleanup;
  }
  if (require_empty_placeholder &&
      (capture_empty_placeholder_state(
           source_fd, source_parent_fd, source_name, &placeholder_current,
           &placeholder_xattrs_current) != 0 ||
       !same_placeholder_state(&placeholder_before, &placeholder_current) ||
       !same_placeholder_xattrs(&placeholder_xattrs_before,
                                &placeholder_xattrs_current))) {
    goto cleanup;
  }

  if (renameatx_np(source_parent_fd, source_name, destination_parent_fd,
                   destination_name,
                   RENAME_EXCL | RENAME_NOFOLLOW_ANY |
                       RENAME_RESOLVE_BENEATH) != 0) {
    goto cleanup;
  }
  operation_completed = 1;

  if (synchronise_test_phase(test_phase, "after-rename", test_ready_path,
                             test_continue_path) != 0) {
    goto cleanup;
  }

  errno = 0;
  if (!(fstatat(source_parent_fd, source_name, &source_name_before,
                AT_SYMLINK_NOFOLLOW) == -1 &&
        errno == ENOENT) ||
      fstatat(destination_parent_fd, destination_name, &destination_after,
              AT_SYMLINK_NOFOLLOW) != 0 ||
      fstat(source_fd, &source_after) != 0 ||
      !same_directory_identity(&source_before, &source_after) ||
      !same_directory_identity(&source_before, &destination_after) ||
      fstat(source_parent_fd, &source_parent_after) != 0 ||
      lstat(source_parent_path, &source_parent_path_after) != 0 ||
      fstat(destination_parent_fd, &destination_parent_after) != 0 ||
      lstat(destination_parent_path, &destination_parent_path_after) != 0 ||
      !same_directory_object(&source_parent_before, &source_parent_after) ||
      !same_directory_object(&source_parent_before, &source_parent_path_after) ||
      !same_directory_object(&destination_parent_before, &destination_parent_after) ||
      !same_directory_object(&destination_parent_before,
                             &destination_parent_path_after) ||
      !descriptor_has_no_extended_acl(source_parent_fd) ||
      !descriptor_has_no_extended_acl(destination_parent_fd) ||
      !descriptor_has_no_extended_acl(source_fd) ||
      !descriptor_path_is(source_parent_fd, source_parent_path) ||
      !descriptor_path_is(destination_parent_fd, destination_parent_path) ||
      realpath(source_parent_path, canonical_source_parent_after) == NULL ||
      strcmp(canonical_source_parent, canonical_source_parent_after) != 0 ||
      realpath(destination_parent_path, canonical_destination_parent_after) == NULL ||
      strcmp(canonical_destination_parent, canonical_destination_parent_after) != 0) {
    goto cleanup;
  }
  if (require_empty_placeholder &&
      (capture_empty_placeholder_state(
           source_fd, destination_parent_fd, destination_name,
           &placeholder_current, &placeholder_xattrs_current) != 0 ||
       !same_placeholder_after_rename(&placeholder_before,
                                      &placeholder_current) ||
       !same_placeholder_xattrs(&placeholder_xattrs_before,
                                &placeholder_xattrs_current))) {
    goto cleanup;
  }

  {
    char destination_path[PATH_MAX];
    int written = snprintf(destination_path, sizeof(destination_path), "%s/%s",
                           destination_parent_path, destination_name);
    if (written < 0 || (size_t)written >= sizeof(destination_path) ||
        !descriptor_path_is(source_fd, destination_path) ||
        fstatat(destination_parent_fd, destination_name, &destination_verified,
                AT_SYMLINK_NOFOLLOW) != 0 ||
        !same_directory_identity(&source_before, &destination_verified)) {
      goto cleanup;
    }
  }

  status = 0;

cleanup:
  if (helper_fd >= 0 && close(helper_fd) != 0) {
    status = 1;
  }
  if (source_fd >= 0 && close(source_fd) != 0) {
    status = 1;
  }
  if (destination_parent_fd >= 0 && close(destination_parent_fd) != 0) {
    status = 1;
  }
  if (source_parent_fd >= 0 && close(source_parent_fd) != 0) {
    status = 1;
  }
  memset(&placeholder_xattrs_before, 0, sizeof(placeholder_xattrs_before));
  memset(&placeholder_xattrs_current, 0, sizeof(placeholder_xattrs_current));
  return operation_completed && status != 0 ? RENAME_COMPLETED_REJECTED : status;
}

int main(int argc, char *argv[]) {
  if (argc > 1 && strcmp(argv[1], "--inspect-held") == 0) {
    return inspect_held_path(argc, argv);
  }
  if (argc > 1 && strcmp(argv[1], "--inspect-held-tree") == 0) {
    return inspect_held_tree(argc, argv);
  }
  if (argc > 1 && strcmp(argv[1], "--inspect-held-tree-after-offset") == 0) {
    return inspect_held_tree(argc, argv);
  }
  if (argc > 1 && strcmp(argv[1], "--inspect-held-empty-placeholder") == 0) {
    return inspect_held_empty_placeholder(argc, argv);
  }
  if (argc > 1 && strcmp(argv[1], "--rewrite-held-file") == 0) {
    return rewrite_held_file(argc, argv);
  }
  if (argc > 1 && strcmp(argv[1], "--cleanup-held-helper-workspace") == 0) {
    return cleanup_held_helper_workspace(argc, argv);
  }
  return rename_exclusive(argc, argv);
}

#endif
