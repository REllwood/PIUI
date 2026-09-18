#define _DARWIN_C_SOURCE 1

#include <sys/acl.h>
#include <sys/stat.h>

#include <errno.h>
#include <unistd.h>

enum {
  TARGET_FD = 3,
};

int main(int argc, char **argv) {
  (void)argv;
  if (argc != 1) {
    return 1;
  }

  struct stat before;
  struct stat after;
  if (fstat(TARGET_FD, &before) != 0) {
    return 1;
  }

  errno = 0;
  acl_t acl = acl_get_fd_np(TARGET_FD, ACL_TYPE_EXTENDED);
  if (acl != NULL) {
    (void)acl_free(acl);
    return 1;
  }
  if (errno != ENOENT) {
    return 1;
  }

  if (fstat(TARGET_FD, &after) != 0 || before.st_dev != after.st_dev ||
      before.st_ino != after.st_ino || before.st_mode != after.st_mode ||
      before.st_uid != after.st_uid || before.st_gid != after.st_gid) {
    return 1;
  }
  return 0;
}
