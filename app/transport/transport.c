/* Copyright 2022-2024 TII (SSRC) and the Ghaf contributors
   SPDX-License-Identifier: Apache-2.0
*/
#include <arpa/inet.h>
#include <errno.h>
#include <execinfo.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "../../drivers/char/ivshmem/kvm_ivshmem.h"

#ifndef VM_COUNT
#define VM_COUNT (5)
#endif

#define SHM_DEVICE_FN "/dev/ivshmem"

#define MAX_EVENTS (1024)
#define MAX_CLIENTS (10)
#define SHMEM_POLL_TIMEOUT (3000)
#define SHMEM_BUFFER_SIZE (512 * 1024)
#define UNKNOWN_PEER (-1)
#define CLOSE_FD (1)
#define IGNORE_ERROR (1)
#define PAGE_SIZE (32)

#define DBG(fmt, ...)                                                          \
  {                                                                            \
    char tmp1[512], tmp2[256];                                                 \
    sprintf(tmp2, fmt, __VA_ARGS__);                                           \
    sprintf(tmp1, "[%d] %s:%d: %s\n", instance_no, __FUNCTION__, __LINE__,     \
            tmp2);                                                             \
    errno = 0;                                                                 \
    report(tmp1, 0);                                                           \
  }

#ifdef DEBUG_ON
#define DEBUG(fmt, ...)                                                        \
  {}
#else
#define DEBUG DBG
#endif

#if 0 
//ndef DEBUG_ON
#define INFO(fmt, ...)                                                         \
  {}
#else
#define INFO(fmt, ...)                                                         \
  {                                                                            \
    char tmp1[512], tmp2[256];                                                 \
    sprintf(tmp2, fmt, __VA_ARGS__);                                           \
    sprintf(tmp1, "[%d] [%s:%d] %s\n", instance_no, __FUNCTION__, __LINE__,    \
            tmp2);                                                             \
    errno = 0;                                                                 \
    report(tmp1, 0);                                                           \
  }
#endif

#define ERROR0(msg)                                                            \
  {                                                                            \
    char tmp[512];                                                             \
    sprintf(tmp, "[%d] [%s:%d] %s\n", instance_no, __FUNCTION__, __LINE__,     \
            msg);                                                              \
    report(tmp, 0);                                                            \
  }

#define ERROR(fmt, ...)                                                        \
  {                                                                            \
    char tmp1[512], tmp2[256];                                                 \
    sprintf(tmp2, fmt, __VA_ARGS__);                                           \
    sprintf(tmp1, "[%d] [%s:%d] %s\n", instance_no, __FUNCTION__, __LINE__,    \
            tmp2);                                                             \
    report(tmp1, 0);                                                           \
  }

#define FATAL(msg)                                                             \
  {                                                                            \
    char tmp1[512], tmp2[256];                                                 \
    sprintf(tmp2, msg);                                                        \
    sprintf(tmp1, "[%d] [%s:%d]: %s\n", instance_no, __FUNCTION__, __LINE__,   \
            tmp2);                                                             \
    report(tmp1, 1);                                                           \
  }

enum { CMD_LOGIN, CMD_CONNECT, CMD_DATA, CMD_CLOSE, CMD_DATA_CLOSE };
#define FD_MAP_COUNT (sizeof(fd_map) / sizeof(fd_map[0]))
int shmem_fd[VM_COUNT];
static const char usage_string[] = "Usage: memsocket [-c|-s] socket_path "
                                   "{instance number (server mode only)}\n";

void report(const char *msg, int terminate) {

  if (errno)
    perror(msg);
  else
    fprintf(stderr, "%s", msg);

  if (terminate)
    exit(-1);
}

int get_shmem_size(int instance_no) {

  int res;

  res = lseek(shmem_fd[instance_no], 0, SEEK_END);
  if (res < 0) {
    FATAL("seek");
  }
  lseek(shmem_fd[instance_no], 0, SEEK_SET);
  return res;
}

void run(int instance_no, int server) {

  int res = -1, vm_id, c = 2;
  long int shmem_size;
  struct ioctl_transport_data data;

  if (server) {
    vm_id = 4;
  }

  /* Open shared memory */
  shmem_fd[instance_no] = open(SHM_DEVICE_FN, O_RDWR);
  if (shmem_fd[instance_no] < 0) {
    FATAL("Open " SHM_DEVICE_FN);
  }
  INFO("shared memory fd: %d", shmem_fd[instance_no]);
  /* Store instance number inside driver */
  ioctl(shmem_fd[instance_no], SHMEM_IOCSETINSTANCENO, instance_no);

  /* get my VM Id */
  res = ioctl(shmem_fd[instance_no], SHMEM_IOCIVPOSN, &vm_id);
  if (res < 0) {
    FATAL("ioctl SHMEM_IOCIVPOSN failed");
  }
  vm_id = vm_id << 16;
  INFO("My VM id = 0x%x. Running as a ", vm_id);

  ioctl(shmem_fd[instance_no], SHMEM_IOCTINI, 0);
  INFO("Initialized", "");

  if (!server) {
    while (1) {
      unsigned char str1[256];
      sprintf(str1, "Hello word! %d\n", c++);
      INFO("Sending...", "]1");
      data.peer_vm_id = 0x4;
      data.type = 0x2;
      data.data = str1;
      data.length = sizeof(str1);
      ioctl(shmem_fd[instance_no], SHMEM_IOCTSEND, &data);
    }
  } else
    while (1) {
      unsigned char str2[256];
      INFO("Waiting for the data...", "");
      data.peer_vm_id = 2;
      data.type = 0x2;
      data.data = str2;
      data.length = sizeof(str2);
      ioctl(shmem_fd[instance_no], SHMEM_IOCTRCV, &data);
      INFO("Received", "");
      printf(str2);
    };
}

void print_usage_and_exit() {
  fprintf(stderr, usage_string);
  exit(1);
}

int main(int argc, char **argv) { run(0, argc > 1); }
