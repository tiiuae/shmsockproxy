/* Copyright 2022-2024 TII (SSRC) and the Ghaf contributors
 * SPDX-License-Identifier: Apache-2.0
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

#include "../drivers/char/ivshmem/kvm_ivshmem.h"

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
#define PAGE_SIZE (4096)
#define DEBUG_ON /* TODO: debug only */
#define DBG(fmt, ...)                                                          \
  {                                                                            \
    char tmp1[512], tmp2[256];                                                 \
    snprintf(tmp2, sizeof(tmp2), fmt, __VA_ARGS__);                            \
    snprintf(tmp1, sizeof(tmp1), "[%d] %s:%d: %s\n", instance_no,              \
             __FUNCTION__, __LINE__, tmp2);                                    \
    errno = 0;                                                                 \
    report(tmp1, 0);                                                           \
  }

#ifndef DEBUG_ON
#define DEBUG(fmt, ...)                                                        \
  {}
#else
#define DEBUG DBG
#endif

#ifndef DEBUG_ON
#define INFO(fmt, ...)                                                         \
  {}
#else
#define INFO(fmt, ...)                                                         \
  {                                                                            \
    char tmp1[512], tmp2[256];                                                 \
    snprintf(tmp2, sizeof(tmp2), fmt, __VA_ARGS__);                            \
    snprintf(tmp1, sizeof(tmp1), "[%d] [%s:%d] %s\n", instance_no,             \
             __FUNCTION__, __LINE__, tmp2);                                    \
    errno = 0;                                                                 \
    report(tmp1, 0);                                                           \
  }
#endif

#define ERROR0(msg)                                                            \
  {                                                                            \
    char tmp[512];                                                             \
    snprintf(tmp, sizeof(tmp), "[%d] [%s:%d] %s\n", instance_no, __FUNCTION__, \
             __LINE__, msg);                                                   \
    report(tmp, 0);                                                            \
  }

#define ERROR(fmt, ...)                                                        \
  {                                                                            \
    char tmp1[512], tmp2[256];                                                 \
    snprintf(tmp2, sizeof(tmp2), fmt, __VA_ARGS__);                            \
    snprintf(tmp1, sizeof(tmp1), "[%d] [%s:%d] %s\n", instance_no,             \
             __FUNCTION__, __LINE__, tmp2);                                    \
    report(tmp1, 0);                                                           \
  }

#define FATAL(msg, ...)                                                        \
  {                                                                            \
    char tmp1[512], tmp2[256];                                                 \
    snprintf(tmp2, sizeof(tmp2), msg);                                         \
    snprintf(tmp1, sizeof(tmp1), "[%d] [%s:%d]: %s\n", instance_no,            \
             __FUNCTION__, __LINE__, tmp2);                                    \
    report(tmp1, 1);                                                           \
  }

enum { CMD_LOGIN, CMD_CONNECT, CMD_DATA, CMD_CLOSE, CMD_DATA_CLOSE };
#define FD_MAP_COUNT (sizeof(fd_map) / sizeof(fd_map[0]))
struct {
  int my_fd;
  int remote_fd;
} fd_map[VM_COUNT][MAX_CLIENTS];

typedef struct {
  volatile __attribute__((aligned(64))) unsigned char data[SHMEM_BUFFER_SIZE];
  volatile int server_vmid;
  volatile int cmd;
  volatile int fd;
  volatile int len;
} vm_data;

int epollfd_full[VM_COUNT], epollfd_limited[VM_COUNT];
char *socket_path = NULL;
int server_socket = -1, shmem_fd[VM_COUNT];

/* Variables related with running on host
   and talking to the ivshmem server */
int run_on_host = 0;
char *ivshmem_socket_path = NULL;
int host_socket_fd = -1; /* socket to ivshm server */
pthread_mutex_t host_fd_mutex;
pthread_cond_t host_cond;
struct peer {
  int vm_id;
  int interrupt_fd[VM_COUNT * 2];
  int fd_count;
} peers_on_host[VM_COUNT];
const long long int kick = 1; /* defined by qemu ivshm */

volatile int *my_vmid = NULL;
int vm_id = -1;
vm_data *my_shm_data[VM_COUNT], *peer_shm_data[VM_COUNT];
int run_as_server = -1;
int local_rr_int_no[VM_COUNT], remote_rc_int_no[VM_COUNT];
pthread_t server_threads[VM_COUNT];
struct {
  volatile int client_vmid;
  vm_data __attribute__((aligned(64))) client_data[VM_COUNT];
  vm_data __attribute__((aligned(64))) server_data[VM_COUNT];
} *vm_control;

static const char usage_string[] = "Usage: memsocket { -c socket_path [-h "
                                   "socket_path] | -s socket_path vmid }\n";

static void report(const char *msg, int terminate) {

  if (errno)
    perror(msg);
  else
    fprintf(stderr, "%s", msg);

  if (terminate)
    exit(-1);
}

static int get_shmem_size(int instance_no) {

  int res;

  res = lseek(shmem_fd[instance_no], 0, SEEK_END);
  if (res < 0) {
    FATAL("seek");
  }
  lseek(shmem_fd[instance_no], 0, SEEK_SET);
  return res;
}

static void fd_map_clear(int instance_no) {

  int i;

  for (i = 0; i < MAX_CLIENTS; i++) {
    fd_map[instance_no][i].my_fd = -1;
    fd_map[instance_no][i].remote_fd = -1;
  }
}

static void read_msg(int ivshmem_fd, long int *buf, int *fd, int instance_no) {
  int rv;
  struct msghdr msg;
  struct iovec iov[1];
  union {
    struct cmsghdr cmsg;
    char control[CMSG_SPACE(sizeof(int))];
  } msg_ctl;
  struct cmsghdr *cmsg;

  iov[0].iov_base = buf;
  iov[0].iov_len = sizeof(buf);

  memset(&msg, 0, sizeof(msg));
  msg.msg_iov = iov;
  msg.msg_iovlen = 1;
  msg.msg_control = &msg_ctl;
  msg.msg_controllen = sizeof(msg_ctl);

  rv = recvmsg(ivshmem_fd, &msg, 0);
  if (!rv)
    FATAL("ivshmem server socket: connection closed")
  if (rv < sizeof(buf))
    FATAL("ivshmem server socket: can't read");

  *buf = le64toh(*buf);
  *fd = -1;

  for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {

    if (cmsg->cmsg_len != CMSG_LEN(sizeof(int)) ||
        cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS) {
      continue;
    }

    memcpy(fd, CMSG_DATA(cmsg), sizeof(*fd));
  }
}

int peer_index_op(int op, int vmid, int instance_no) {
  int i, n, free = VM_COUNT;
  struct peer *peer;

  if (vmid == vm_id >> 16)
    return 0; /* Our data is always on the index 0*/

  for (i = 0; i < VM_COUNT; i++) {
    peer = &peers_on_host[i];
    if (peer->vm_id == -1) {
      free = i;
      continue;
    }

    if (peer->vm_id == vmid) {
      switch (op) {
      case 0: /* get index */
      case 3:
        return i;
        break;
      case 1: /* clear */
        peer->vm_id = -1;
        for (n = 0; n < VM_COUNT * 2; n++) {
          /* TODO: how about closing and active i/o operations ??? */
          if (peer->interrupt_fd[n] >= 0)
            close(peer->interrupt_fd[n]);
          peer->interrupt_fd[n] = -1;
        }
        peer->fd_count = 0;
        return 0;
      }
    }
  }
  switch (op) { /* Not found */
  case 0:
    peers_on_host[free].vm_id = vmid;
    return free;
  case 1:
    return -1;
  case 3:
    ERROR("vmid %d not found", vmid);
    FATAL("Exiting.")
  }
}

int doorbell_fd(int instance_no, unsigned int_addr) {
  int vm_id, fd_no, index, res;

  vm_id = int_addr >> 16;
  index = peer_index_op(3, vm_id, instance_no);
  res = write(peers_on_host[index].interrupt_fd[int_addr & 0xffff], &kick,
              sizeof(kick));
  INFO("Writing to interrupt fd: Addr=0x%x fd=%d", int_addr,
       peers_on_host[index].interrupt_fd[int_addr & 0xffff]);
  if (res < 0) {
    ERROR("Writing to interrupt fd failed. Addr=0x%x fd=%d", int_addr,
          peers_on_host[index].interrupt_fd[int_addr & 0xffff]);
    FATAL("Exiting"); // TODO: maybe we shouldn't exit?
  }
  return res;
}

static void *host_run(void *arg) {
  int instance_no = (long int)arg;
  int ivshmemsrv_fd;
  long int tmp;
  int shm_fd;
  struct peer *peer;
  int peer_idx;
  struct sockaddr_un socket_name;

  /* Set up socket connection */
  ivshmemsrv_fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (ivshmemsrv_fd < 0) {
    FATAL("ivshmem server socket");
  }
  DEBUG("ivshmem server socket: %d", ivshmemsrv_fd);
  memset(&socket_name, 0, sizeof(socket_name));
  socket_name.sun_family = AF_UNIX;
  strncpy(socket_name.sun_path, ivshmem_socket_path,
          sizeof(socket_name.sun_path) - 1);
  if (connect(ivshmemsrv_fd, (struct sockaddr *)&socket_name,
              sizeof(socket_name)) < 0) {
    FATAL("connect to ivshmem server socket");
  }

  /* Read protocol version */
  read_msg(ivshmemsrv_fd, &tmp, &shm_fd, instance_no);
  INFO("ivshmem protocol version %ld", tmp);

  /* Get my vm id */
  read_msg(ivshmemsrv_fd, &tmp, &shm_fd, instance_no);
  if (tmp >= 0 || shm_fd == -1) {
    vm_id = tmp << 16;
    INFO("my physical vm id=%ld", tmp);
  } else {
    DEBUG("tmp=%ld fd=%d", tmp, shm_fd);
    FATAL("invalid ivshmem server response");
  }

  /* Get shared memory fd */
  read_msg(ivshmemsrv_fd, &tmp, &shm_fd, instance_no);
  INFO("shared memory fd=%d", shm_fd);
  if (shm_fd >= 0 || tmp == -1) {
    host_socket_fd = shm_fd;
  } else {
    DEBUG("tmp=%ld fd=%d", tmp, shm_fd);
    if (shm_fd > 0)
      close(shm_fd);
    FATAL("invalid ivshmem server response");
  }
  /* Process messages */
  do {
    read_msg(ivshmemsrv_fd, &tmp, &shm_fd, instance_no);
    INFO("tmp=%ld shm_fd=%d", tmp, shm_fd);

    if (tmp >= 0) {      /* peer or self  connection or disconnection */
      if (shm_fd >= 0) { /* peer or self connection */

        peer_idx = peer_index_op(0, tmp, instance_no);
        INFO("peer_idx=%d", peer_idx);
        if (peer_idx >= VM_COUNT) {
          ERROR("vm id %ld not found", tmp);
          continue;
        }
        peer = &peers_on_host[peer_idx];

        if (peer->fd_count >= VM_COUNT * 2) {
          ERROR("Ignored received excessive interrupt fd: %d", shm_fd);
          continue;
        }
        if (peer->interrupt_fd[peer->fd_count] == -1) {
          peer->interrupt_fd[peer->fd_count] = shm_fd;
          INFO("Received peer idx=%d interrupt[%d] fd %d", peer_idx,
               peer->fd_count, shm_fd);
          peer->fd_count++;
          if (peer->fd_count == VM_COUNT * 2 && !peer_idx) {
            INFO("%s", "Host configuration ready");
            pthread_cond_signal(&host_cond);
            pthread_mutex_unlock(&host_fd_mutex);
            INFO("my physical vm id=0x%x", vm_id); // TODO: remove
          }
        } else
          ERROR("Ignored re-using peer's %d interrupt[%d] fd: %d", peer_idx,
                peer->fd_count, shm_fd);
        continue;
      }

      else { /* peer disconnection */
        if (!peer_index_op(1, tmp, 0xff)) {
          INFO("Peer %ld disconnected", tmp);
        } else
          ERROR("Peer %ld not found", tmp);
      }
    }

    if (tmp == -1) {
      ERROR("Ignored msg. Params: -1, %d", shm_fd);
    }

  } while (1);
}

static void server_init(int instance_no) {

  struct sockaddr_un socket_name;
  struct epoll_event ev;

  /* Remove socket file if exists */
  if (access(socket_path, F_OK) == 0) {
    remove(socket_path);
  }

  server_socket = socket(AF_UNIX, SOCK_STREAM, 0);
  if (server_socket < 0) {
    FATAL("server socket");
  }

  DEBUG("server socket: %d", server_socket);

  memset(&socket_name, 0, sizeof(socket_name));
  socket_name.sun_family = AF_UNIX;
  strncpy(socket_name.sun_path, socket_path, sizeof(socket_name.sun_path) - 1);
  if (bind(server_socket, (struct sockaddr *)&socket_name,
           sizeof(socket_name)) < 0) {
    FATAL("bind");
  }

  if (listen(server_socket, MAX_EVENTS) < 0)
    FATAL("listen");

  ev.events = EPOLLIN;
  ev.data.fd = server_socket;
  if (epoll_ctl(epollfd_full[instance_no], EPOLL_CTL_ADD, server_socket, &ev) ==
      -1) {
    FATAL("server_init: epoll_ctl: server_socket");
  }

  INFO("%s", "server initialized");
}

static int wayland_connect(int instance_no) {

  struct sockaddr_un socket_name;
  struct epoll_event ev;
  int wayland_fd;

  wayland_fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (wayland_fd < 0) {
    FATAL("wayland socket");
  }

  DEBUG("wayland socket: %d", wayland_fd);

  memset(&socket_name, 0, sizeof(socket_name));
  socket_name.sun_family = AF_UNIX;
  strncpy(socket_name.sun_path, socket_path, sizeof(socket_name.sun_path) - 1);
  if (connect(wayland_fd, (struct sockaddr *)&socket_name,
              sizeof(socket_name)) < 0) {
    FATAL("connect");
  }

  ev.events = EPOLLIN;
  ev.data.fd = wayland_fd;
  if (epoll_ctl(epollfd_full[instance_no], EPOLL_CTL_ADD, wayland_fd, &ev) ==
      -1) {
    FATAL("epoll_ctl: wayland_fd");
  }

  INFO("%s", "client initialized");
  return wayland_fd;
}

static void make_wayland_connection(int instance_no, int peer_fd) {

  int i;

  for (i = 0; i < MAX_CLIENTS; i++) {
    if (fd_map[instance_no][i].my_fd == -1) {
      fd_map[instance_no][i].my_fd = wayland_connect(instance_no);
      fd_map[instance_no][i].remote_fd = peer_fd;
      return;
    }
  }
  ERROR("FAILED fd#%d", peer_fd);
  FATAL("fd_map table full");
}

static int map_peer_fd(int instance_no, int peer_fd, int close_fd) {

  int i, rv;

  for (i = 0; i < MAX_CLIENTS; i++) {
    if (fd_map[instance_no][i].remote_fd == peer_fd) {
      rv = fd_map[instance_no][i].my_fd;
      if (close_fd)
        fd_map[instance_no][i].my_fd = -1;
      return rv;
    }
  }
  ERROR("FAILED on mapping remote fd#%d", peer_fd);
  return -1;
}

static int get_remote_socket(int instance_no, int my_fd, int close_fd,
                             int ignore_error) {

  int i;

  for (i = 0; i < MAX_CLIENTS; i++) {
    if (fd_map[instance_no][i].my_fd == my_fd) {
      if (close_fd)
        fd_map[instance_no][i].my_fd = -1;
      return fd_map[instance_no][i].remote_fd;
    }
  }
  if (ignore_error)
    return -1;

  FATAL("my fd not found");
  return -1;
}

static void shmem_init(int instance_no) {

  int res = -1;
  struct epoll_event ev;
  long int shmem_size;
  int tmp;

  /* Open shared memory */
  if (run_on_host) {
    /* wait until shared memory file descriptor is received */
    INFO("%s", "Waiting for shared memory fd");
    pthread_mutex_lock(&host_fd_mutex);
    while (host_socket_fd == -1) {
      pthread_cond_wait(&host_cond, &host_fd_mutex);
    }
    pthread_mutex_unlock(&host_fd_mutex);
    shmem_fd[instance_no] = host_socket_fd;
    INFO("ivshmem shared memory fd: %d", shmem_fd[instance_no]);
  } else {
    shmem_fd[instance_no] = open(SHM_DEVICE_FN, O_RDWR);
    if (shmem_fd[instance_no] < 0) {
      FATAL("Open " SHM_DEVICE_FN);
    }
    INFO("shared memory fd: %d", shmem_fd[instance_no]);
    /* Store instance number inside driver */
    ioctl(shmem_fd[instance_no], SHMEM_IOCSETINSTANCENO, instance_no);
  }

  /* Get shared memory */
  shmem_size = get_shmem_size(instance_no);
  if (shmem_size <= 0) {
    FATAL("No shared memory detected");
  }
  if (shmem_size < sizeof(*vm_control)) {
    ERROR("Shared memory too small: %ld bytes allocated whereas %ld needed",
          shmem_size, sizeof(*vm_control));
    FATAL("Exiting");
  }
  vm_control = mmap(NULL, shmem_size, PROT_READ | PROT_WRITE,
                    MAP_SHARED | MAP_NORESERVE, shmem_fd[instance_no], 0);
  if (!vm_control) {
    FATAL("Got NULL pointer from mmap");
  }
  DEBUG("Shared memory at address %p 0x%lx bytes", vm_control, shmem_size);

  if (run_as_server) {
    my_shm_data[instance_no] = &vm_control->server_data[instance_no];
    peer_shm_data[instance_no] = &vm_control->client_data[instance_no];
  } else {
    my_shm_data[instance_no] = &vm_control->client_data[instance_no];
    peer_shm_data[instance_no] = &vm_control->server_data[instance_no];
  }
  DEBUG("[%d] vm_control=%p my_shm_data=%p peer_shm_data=%p", instance_no,
        vm_control, my_shm_data[instance_no], peer_shm_data[instance_no]);
  DEBUG("[%d] my_shm_data offset=0x%lx peer_shm_data offset=0x%lx", instance_no,
        (void *)my_shm_data[instance_no] - (void *)vm_control,
        (void *)peer_shm_data[instance_no] - (void *)vm_control);
  if (!run_on_host) {
    /* get my VM Id */
    res = ioctl(shmem_fd[instance_no], SHMEM_IOCIVPOSN, &tmp);
    if (res < 0) {
      FATAL("ioctl SHMEM_IOCIVPOSN failed");
    }
    vm_id = tmp << 16;
  }
  if (run_as_server) {
    my_vmid = &vm_control->server_data[instance_no].server_vmid;
  } else {
    my_vmid = &vm_control->client_vmid;
    vm_control->server_data[instance_no].server_vmid = UNKNOWN_PEER;
  }
  *my_vmid = vm_id;
  INFO("My VM id = 0x%x. Running as a ", *my_vmid);
  if (run_as_server) {
    INFO("%s", "server");
  } else {
    INFO("%s", "client");
  }

  if (!run_on_host) {
    ev.events = EPOLLIN | EPOLLOUT;
    ev.data.fd = shmem_fd[instance_no];
    if (epoll_ctl(epollfd_full[instance_no], EPOLL_CTL_ADD, ev.data.fd, &ev) ==
        -1) {
      FATAL("epoll_ctl: -1");
    }
    ev.events = EPOLLIN | EPOLLOUT;
    ev.data.fd = shmem_fd[instance_no];
    if (epoll_ctl(epollfd_limited[instance_no], EPOLL_CTL_ADD, ev.data.fd,
                  &ev) == -1) {
      FATAL("epoll_ctl: -1");
    }
    /* Set output buffer it's available */
    ioctl(shmem_fd[instance_no], SHMEM_IOCSET,
          (LOCAL_RESOURCE_READY_INT_VEC << 8) + 1);
  } else { /* on host use file descriptors provided by ivshmem server */
    ev.events = EPOLLIN;
    ev.data.fd =
        peers_on_host[0]
            .interrupt_fd[instance_no << 1 | PEER_RESOURCE_CONSUMED_INT_VEC];
    if (epoll_ctl(epollfd_limited[instance_no], EPOLL_CTL_ADD, ev.data.fd,
                  &ev) == -1) {
      FATAL("epoll_ctl: -1");
    }
    ev.events = EPOLLIN;
    ev.data.fd =
        peers_on_host[0]
            .interrupt_fd[instance_no << 1 | LOCAL_RESOURCE_READY_INT_VEC];
    if (epoll_ctl(epollfd_full[instance_no], EPOLL_CTL_ADD, ev.data.fd, &ev) ==
        -1) {
      FATAL("epoll_ctl: -1");
    }
  }
  INFO("%s", "shared memory initialized");
}

static void thread_init(int instance_no) {

  int res;
  struct ioctl_data ioctl_data;

  fd_map_clear(instance_no);

  epollfd_full[instance_no] = epoll_create1(0);
  if (epollfd_full[instance_no] == -1) {
    FATAL("server_init: epoll_create1");
  }
  epollfd_limited[instance_no] = epoll_create1(0);
  if (epollfd_limited[instance_no] == -1) {
    FATAL("server_init: epoll_create1");
  }

  shmem_init(instance_no);

  if (run_as_server) {
    /* Create socket that waypipe can write to
     * Add the socket fd to the epollfd_full
     */
    server_init(instance_no);
    /* interrupt signaling the peer there is data ready to process  */
    local_rr_int_no[instance_no] = vm_control->client_vmid |
                                   (instance_no << 1) |
                                   LOCAL_RESOURCE_READY_INT_VEC;
    /* interrupt received when the peer has consumed our data */
    remote_rc_int_no[instance_no] = vm_control->client_vmid |
                                    (instance_no << 1) |
                                    PEER_RESOURCE_CONSUMED_INT_VEC;
    /*
     * Send LOGIN cmd to the client. Supply my_vmid
     */
    my_shm_data[instance_no]->cmd = CMD_LOGIN;
    my_shm_data[instance_no]->fd = *my_vmid;
    my_shm_data[instance_no]->len = 0;

    ioctl_data.int_no = local_rr_int_no[instance_no];
#ifdef DEBUG_IOCTL
    ioctl_data.cmd = my_shm_data[instance_no]->cmd;
    ioctl_data.fd = my_shm_data[instance_no]->fd;
    ioctl_data.len = my_shm_data[instance_no]->len;
#endif
    if (!run_on_host) { // TODO
      res = ioctl(shmem_fd[instance_no], SHMEM_IOCDORBELL, &ioctl_data);
    } else { /* run on host */
      INFO("ioctl_data.int_no=0x%x (vmid.int_no)", ioctl_data.int_no); // TODO
      res = doorbell_fd(instance_no, ioctl_data.int_no);
    }
    DEBUG("Sent login vmid: 0x%x ioctl result=%d --> vm_id=0x%x", *my_vmid, res,
          vm_control->client_vmid);
  }
}

static void close_peer_vm(int instance_no) {
  int i;

  for (i = 0; i < MAX_CLIENTS; i++) {
    if (fd_map[instance_no][i].my_fd != -1)
      close(fd_map[instance_no][i].my_fd);
  }
  fd_map_clear(instance_no);
}

static int cksum(unsigned char *buf, int len) {
  int i, res = 0;
  for (i = 0; i < len; i++)
    res += buf[i];
  return res;
}

static void *run(void *arg) {

  int instance_no = (intptr_t)arg;
  int new_connection_fd, rv, nfds, n, read_count, event_handled;
  struct sockaddr_un caddr;      /* client address */
  socklen_t len = sizeof(caddr); /* address length could change */
  struct pollfd shm_buffer_fd = {.events = POLLOUT};
  struct epoll_event ev, *current_event;
  struct epoll_event events[MAX_EVENTS];
  struct ioctl_data ioctl_data;
  unsigned int tmp;
  int epollfd;
  vm_data *peer_shm_desc, *my_shm_desc;
  int data_ack, data_in;
  int fd_int_data_ack /* peer has consumed our data */;
  int fd_int_data_ready; /* signal the peer that there is data ready */
  long long int kick;

  if (instance_no >= VM_COUNT || instance_no < 0)
    FATAL("Invalid instance no");

  thread_init(instance_no);
  peer_shm_desc = peer_shm_data[instance_no];
  my_shm_desc = my_shm_data[instance_no];
  shm_buffer_fd.fd = shmem_fd[instance_no];
  epollfd = epollfd_full[instance_no];

  if (run_on_host) {
    if (!run_as_server) {
      fd_int_data_ack =
          peers_on_host[0]
              .interrupt_fd[instance_no << 1 | PEER_RESOURCE_CONSUMED_INT_VEC];
      fd_int_data_ready =
          peers_on_host[0]
              .interrupt_fd[instance_no << 1 | LOCAL_RESOURCE_READY_INT_VEC];
    } else {
      fd_int_data_ack =
          peers_on_host[0].interrupt_fd[PEER_RESOURCE_CONSUMED_INT_VEC];
      fd_int_data_ready =
          peers_on_host[0].interrupt_fd[LOCAL_RESOURCE_READY_INT_VEC];
    }
    INFO("fd_int_data_ack=%d fd_int_data_ready=%d", fd_int_data_ack,
         fd_int_data_ready)
  }

  while (1) {
#ifdef DEBUG_ON
    if (epollfd == epollfd_full[instance_no]) {
      DEBUG("%s", "Waiting for all events");
    } else {
      DEBUG("%s", "Waiting for ACK");
    }
#endif
    nfds = epoll_wait(epollfd, events, MAX_EVENTS, -1);
    if (nfds == -1) {
      FATAL("epoll_wait");
    }

    for (n = 0; n < nfds; n++) {
      current_event = &events[n];
#ifdef DEBUG_ON
      if (!run_on_host)
        ioctl(shm_buffer_fd.fd, SHMEM_IOCNOP, &tmp);

      DBG("Event index=%d 0x%x on fd %d inout=%d-%d", n, current_event->events,
          current_event->data.fd, tmp & 0xffff, tmp >> 16);
#endif
      /* Check for ACK from the peer via shared memory */
      if (!run_on_host)
        data_ack = current_event->events & EPOLLOUT &&
                   current_event->data.fd == shm_buffer_fd.fd;
      else
        data_ack = current_event->events & EPOLLIN &&
                   current_event->data.fd == fd_int_data_ack;
      if (data_ack) {
        DEBUG("%s", "Received remote ACK");
        /* Notify the driver that we reserve the local buffer */
        if (!run_on_host) {
          INFO("%s", "????????? ....");
          ioctl(shm_buffer_fd.fd, SHMEM_IOCSET,
                (LOCAL_RESOURCE_READY_INT_VEC << 8) + 0);
        } else {
          INFO("%s", "Reading ....");
          rv = read(fd_int_data_ack, &kick, sizeof(kick));
          if (rv < 0) {
            FATAL("Exiting");
          } else if (rv != sizeof(kick))
            ERROR("Invalid read data lenght %d", rv);
        }
        /* as the local is free, start to handle all events */
        epollfd = epollfd_full[instance_no];
      }
      event_handled = 0;
      /* Handle the new connection on the socket */
      if (current_event->events & EPOLLIN && run_as_server &&
          current_event->data.fd == server_socket) {
        new_connection_fd =
            accept(server_socket, (struct sockaddr *)&caddr, &len);
        if (new_connection_fd == -1) {
          FATAL("accept");
        }
        ev.events = EPOLLIN | EPOLLET | EPOLLHUP;
        ev.data.fd = new_connection_fd;
        if (epoll_ctl(epollfd_full[instance_no], EPOLL_CTL_ADD,
                      new_connection_fd, &ev) == -1) {
          FATAL("epoll_ctl: new_connection_fd");
        }
        /* Send the connect request to the wayland peer */
        my_shm_desc->cmd = CMD_CONNECT;
        my_shm_desc->fd = new_connection_fd;
        my_shm_desc->len = 0;
        ioctl_data.int_no = local_rr_int_no[instance_no];
#ifdef DEBUG_IOCTL
        ioctl_data.cmd = my_shm_desc->cmd;
        ioctl_data.fd = my_shm_desc->fd;
        ioctl_data.len = my_shm_desc->len;
#endif
        epollfd = epollfd_limited[instance_no];
        if (!run_on_host) {
          ioctl(shm_buffer_fd.fd, SHMEM_IOCDORBELL, &ioctl_data);
        } else {
          doorbell_fd(instance_no, ioctl_data.int_no);
        }
        DEBUG("Doorbell to add the client on fd %d", new_connection_fd);
        event_handled = 1;
      }

      /*
       * Client and server: Received INT from peer VM - there is incoming data
       * in the shared memory - EPOLLIN
       */
      INFO("current_event->events=0x%x current_event->data.fd=%d "
           "fd_int_data_ready=%d",
           current_event->events, current_event->data.fd, fd_int_data_ready)
      if (!run_on_host)
        data_in = current_event->events & EPOLLIN &&
                  current_event->data.fd == shm_buffer_fd.fd;
      else /* run on host */
        data_in = data_in = current_event->events & EPOLLIN &&
                            current_event->data.fd == fd_int_data_ready;

      if (data_in) {
        DEBUG("shmem_fd/host_fd=%d event: 0x%x cmd: 0x%x remote fd: %d remote "
              "len: %d",
              run_on_host ? fd_int_data_ready : shm_buffer_fd.fd,
              current_event->events, peer_shm_desc->cmd, peer_shm_desc->fd,
              peer_shm_desc->len);

        switch (peer_shm_desc->cmd) {
        case CMD_LOGIN:
          DEBUG("Received login request from 0x%x", peer_shm_desc->fd);
          /* If the peer VM starts again, close all opened file handles */
          close_peer_vm(instance_no);

          local_rr_int_no[instance_no] = peer_shm_desc->fd |
                                         (instance_no << 1) |
                                         LOCAL_RESOURCE_READY_INT_VEC;
          remote_rc_int_no[instance_no] = peer_shm_desc->fd |
                                          (instance_no << 1) |
                                          PEER_RESOURCE_CONSUMED_INT_VEC;

          peer_shm_desc->fd = -1;
          break;
        case CMD_DATA:
        case CMD_DATA_CLOSE:
          new_connection_fd =
              run_as_server ? peer_shm_desc->fd
                            : map_peer_fd(instance_no, peer_shm_desc->fd, 0);
          DEBUG(
              "shmem: received %d bytes for %d cksum=0x%x", peer_shm_desc->len,
              new_connection_fd,
              cksum((unsigned char *)peer_shm_desc->data, peer_shm_desc->len));
          rv = send(new_connection_fd, (const void *)peer_shm_desc->data,
                    peer_shm_desc->len, 0);
          if (rv != peer_shm_desc->len) {
            ERROR("Sent %d out of %d bytes on fd#%d", rv, peer_shm_desc->len,
                  new_connection_fd);
          }
          DEBUG("%s", "Received data has been sent");

          if (peer_shm_desc->cmd == CMD_DATA) {
            break;
          }
          /* no break if we need to the the fd */
        case CMD_CLOSE:
          if (run_as_server) {
            new_connection_fd = peer_shm_desc->fd;
            DEBUG("Closing %d", new_connection_fd);
          } else {
            new_connection_fd = map_peer_fd(instance_no, peer_shm_desc->fd, 1);
            DEBUG("Closing %d peer fd=%d", new_connection_fd,
                  peer_shm_desc->fd);
          }
          if (new_connection_fd > 0) {
            if (epoll_ctl(epollfd_full[instance_no], EPOLL_CTL_DEL,
                          new_connection_fd, NULL) == -1) {
              ERROR0("epoll_ctl: EPOLL_CTL_DEL");
            }
            close(new_connection_fd);
          }
          break;
        case CMD_CONNECT:
          make_wayland_connection(instance_no, peer_shm_desc->fd);
          break;
        default:
          ERROR("Invalid CMD 0x%x from peer!", peer_shm_desc->cmd);
          break;
        } /* switch peer_shm_desc->cmd */

        /* Signal the other side that its buffer has been processed */
        DEBUG("%s", "Exec ioctl REMOTE_RESOURCE_CONSUMED_INT_VEC");
        peer_shm_desc->cmd = -1;
        ioctl_data.int_no = remote_rc_int_no[instance_no];
        if (!run_on_host) {
#ifdef DEBUG_IOCTL
          ioctl_data.cmd = -1;
          ioctl_data.fd = 0;
          ioctl_data.len = 0;
#endif
          ioctl(shm_buffer_fd.fd, SHMEM_IOCDORBELL, &ioctl_data);
        } else {
          doorbell_fd(instance_no, ioctl_data.int_no);
        }
        event_handled = 1;
      } /* End of "data arrived from the peer via shared memory" */

      /* Received data from Wayland or from waypipe. It needs to
        be sent to the peer */
      if (current_event->events & EPOLLIN && !event_handled) {
        if (!run_as_server) {
          new_connection_fd = get_remote_socket(
              instance_no, current_event->data.fd, 0, IGNORE_ERROR);
          DEBUG("get_remote_socket: %d", new_connection_fd);
        } else {
          new_connection_fd = current_event->data.fd;
        }
        DEBUG("%s", "Reading from wayland/waypipe socket");
        read_count = read(current_event->data.fd, (void *)my_shm_desc->data,
                          sizeof(my_shm_desc->data));

        if (read_count <= 0) {
          if (read_count < 0)
            ERROR("read from wayland/waypipe socket failed fd=%d",
                  current_event->data.fd);
          if (!run_on_host)
            /* Release output buffer */
            ioctl(shm_buffer_fd.fd, SHMEM_IOCSET,
                  (LOCAL_RESOURCE_READY_INT_VEC << 8) + 1);

        } else { /* read_count > 0 */
          DEBUG("Read & sent %d bytes on fd#%d sent to %d checksum=0x%x",
                read_count, current_event->data.fd, new_connection_fd,
                cksum((unsigned char *)my_shm_desc->data, read_count));

          if (current_event->events & EPOLLHUP) {
            my_shm_desc->cmd = CMD_DATA_CLOSE;
            current_event->events &= ~EPOLLHUP;

            /* unmap local fd */
            if (!run_as_server)
              get_remote_socket(instance_no, current_event->data.fd, CLOSE_FD,
                                IGNORE_ERROR);
            /* close local fd*/
            close(current_event->data.fd);
          } else
            my_shm_desc->cmd = CMD_DATA;

          my_shm_desc->fd = new_connection_fd;
          my_shm_desc->len = read_count;

          ioctl_data.int_no = local_rr_int_no[instance_no];
#ifdef DEBUG_IOCTL
          ioctl_data.cmd = my_shm_desc->cmd;
          ioctl_data.fd = my_shm_desc->fd;
          ioctl_data.len = my_shm_desc->len;
#endif
          DEBUG("Exec ioctl DATA/DATA_CLOSE cmd=%d fd=%d len=%d",
                my_shm_desc->cmd, my_shm_desc->fd, my_shm_desc->len);
          epollfd = epollfd_limited[instance_no];
          if (!run_on_host)
            ioctl(shm_buffer_fd.fd, SHMEM_IOCDORBELL, &ioctl_data);
          else
            doorbell_fd(instance_no, ioctl_data.int_no);
          break;
        }
      } /* end of incoming data processing EPOLLIN*/

      /* Handling connection close */
      if (current_event->events & (EPOLLHUP | EPOLLERR)) {
        DEBUG("Closing fd#%d", current_event->data.fd);
        my_shm_desc->cmd = CMD_CLOSE;
        if (run_as_server)
          my_shm_desc->fd = current_event->data.fd;
        else {
          DEBUG("get_remote_socket: %d",
                get_remote_socket(instance_no, current_event->data.fd, 0,
                                  IGNORE_ERROR));
          my_shm_desc->fd = get_remote_socket(
              instance_no, current_event->data.fd, CLOSE_FD, IGNORE_ERROR);
        }
        if (my_shm_desc->fd > 0) {
          DEBUG("ioctl ending close request for %d", my_shm_desc->fd);

          ioctl_data.int_no = local_rr_int_no[instance_no];
#ifdef DEBUG_IOCTL
          ioctl_data.cmd = my_shm_desc->cmd;
          ioctl_data.fd = my_shm_desc->fd;
          ioctl_data.len = my_shm_desc->len;
#endif
          /* Output buffer is busy. Accept only the events
             that don't use it */
          epollfd = epollfd_limited[instance_no];
          if (!run_on_host)
            ioctl(shm_buffer_fd.fd, SHMEM_IOCDORBELL, &ioctl_data);
          else
            doorbell_fd(instance_no, ioctl_data.int_no);

        } else { /* unlock output buffer */
          ERROR("Attempt to close invalid fd %d", current_event->data.fd);
          if (!run_on_host)
            ioctl(shm_buffer_fd.fd, SHMEM_IOCSET,
                  (LOCAL_RESOURCE_READY_INT_VEC << 8) + 1);
        }
        if (epoll_ctl(epollfd_full[instance_no], EPOLL_CTL_DEL,
                      current_event->data.fd, NULL) == -1) {
          ERROR("epoll_ctl: EPOLL_CTL_DEL on fd %d", current_event->data.fd);
        }
        close(current_event->data.fd);
        /* If the buffer is busy, don't proceed any further events */
        if (epollfd == epollfd_limited[instance_no])
          break;
      } /* Handling connection close */
    } /* for */
  } /* while(1) */
  return 0;
}

static void print_usage_and_exit() {
  fprintf(stderr, usage_string);
  exit(1);
}

int main(int argc, char **argv) {

  int i, n, res = -1;
  int instance_no = -1;
  int opt;
  int run_mode = 0;
  pthread_t threads[VM_COUNT], host_thread;

  while ((opt = getopt(argc, argv, "c:s:h:")) != -1) {
    switch (opt) {
    case 'c':
      run_as_server = 0;
      socket_path = optarg;
      run_mode++;
      break;

    case 's':
      run_as_server = 1;
      socket_path = optarg;
      run_mode++;
      if (optind >= argc)
        goto wrong_args;
      instance_no = atoi(argv[optind]);
      break;

    case 'h':
      run_on_host = 1;
      ivshmem_socket_path = optarg;
      break;

    default: /* '?' */
      goto wrong_args;
    }
  }

  if (run_mode > 1 || run_as_server < 0 ||
      (instance_no < 0 && run_as_server > 0))
    goto wrong_args;

  for (i = 0; i < VM_COUNT; i++) {
    my_shm_data[i] = NULL;
    peer_shm_data[i] = NULL;
    shmem_fd[i] = -1;
    peers_on_host[i].vm_id = -1;
    peers_on_host[i].fd_count = 0;
    for (n = 0; n < VM_COUNT * 2; n++)
      peers_on_host[i].interrupt_fd[n] = -1;
  }

  if (run_on_host) {
    res = pthread_mutex_init(&host_fd_mutex, NULL);
    if (res) {
      FATAL("Cannot initialize the mutex");
    }
    pthread_mutex_lock(&host_fd_mutex);
    res = pthread_create(&host_thread, NULL, host_run, (void *)(intptr_t)i);
    if (res) {
      FATAL("Cannot create the host thread");
    }
  }

  /* On client site start thread for each display VM */
  if (run_as_server == 0) {
    for (i = 1; i <= 1 /* VM_COUNT*/; i++) { // TODO: revert
      res = pthread_create(&threads[i], NULL, run, (void *)(intptr_t)i);
      if (res) {
        ERROR("Thread id=%d", i);
        FATAL("Cannot create a thread");
      }
    }
    for (i = 1; i <= 1 /*VM_COUNT*/; i++) { // TODO:
      res = pthread_join(threads[i], NULL);
      if (res) {
        ERROR("error %d waiting for the thread #%d", res, i);
      }
    }
  } else { /* server mode - run only one instance */
    run((void *)(intptr_t)instance_no);
  }

  if (run_on_host) {
    res = pthread_join(host_thread, NULL);
    if (res) {
      ERROR("error %d waiting for the host thread", res);
    }
    res = pthread_mutex_destroy(&host_fd_mutex);
    if (res) {
      ERROR("error %d destroying mutex ", res);
    }
    res = pthread_cond_destroy(&host_cond);
    if (res) {
      ERROR("error %d destroying mutex ", res);
    }
  }

  return 0;
wrong_args:
  print_usage_and_exit();
  return 1;
}
