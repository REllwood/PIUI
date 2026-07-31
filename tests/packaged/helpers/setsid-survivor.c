#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

static void sleep_milliseconds(long milliseconds) {
  while (milliseconds > 0) {
    long slice = milliseconds > 1000 ? 1000 : milliseconds;
    if (usleep((useconds_t)(slice * 1000)) != 0 && errno != EINTR) _exit(20);
    milliseconds -= slice;
  }
}

int main(int argc, char **argv) {
  if (argc != 3) return 2;
  char *end = NULL;
  long parent_milliseconds = strtol(argv[2], &end, 10);
  if (!end || *end != '\0' || parent_milliseconds < 1) return 3;

  pid_t child = fork();
  if (child < 0) return 4;
  if (child > 0) {
    sleep_milliseconds(parent_milliseconds);
    return 0;
  }

  pid_t direct_parent = getppid();
  if (setsid() < 0) _exit(5);
  close(STDIN_FILENO);
  close(STDOUT_FILENO);
  close(STDERR_FILENO);
  int null_fd = open("/dev/null", O_RDWR);
  if (null_fd < 0) _exit(6);
  if (dup2(null_fd, STDIN_FILENO) < 0 || dup2(null_fd, STDOUT_FILENO) < 0 || dup2(null_fd, STDERR_FILENO) < 0) _exit(7);
  if (null_fd > STDERR_FILENO) close(null_fd);

  int marker = open(argv[1], O_CREAT | O_EXCL | O_WRONLY, 0600);
  if (marker < 0) _exit(8);
  char evidence[160];
  int length = snprintf(evidence, sizeof(evidence), "%d %d %d %d\n", getpid(), direct_parent, getsid(0), getpgrp());
  if (length < 1 || length >= (int)sizeof(evidence) || write(marker, evidence, (size_t)length) != length) _exit(9);
  if (fsync(marker) != 0 || close(marker) != 0) _exit(10);

  for (;;) pause();
}
