/* Copyright 2022-2024 TII (SSRC) and the Ghaf contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include <arpa/inet.h>
#include <errno.h>
#include <execinfo.h>
#include <fcntl.h>
#include <getopt.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <sys/select.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "../drivers/char/ivshmem/kvm_ivshmem.h"
#include "./memsocket.h"

#ifndef SHM_SLOTS
#define SHM_SLOTS (4)
#endif

#define TEST_PEER_INDEX (0)
#define CLEAR_PEER_INDEX (1)
#define GET_PEER_INDEX (3)

#define FD_MAP_COUNT (sizeof(fd_map) / sizeof(fd_map[0]))
struct {
  int my_fd;
  int remote_fd;
} fd_map[SHM_SLOTS][MAX_FDS];

int epollfd_full[SHM_SLOTS], epollfd_limited[SHM_SLOTS];
char *socket_path = NULL;
int endpoint_socket = -1, shmem_fd[SHM_SLOTS], signal_fd = -1;

/* Variables related to running on the host and communicating
  with the ivshmem server */
int run_on_host = 0;
char *ivshmem_socket_path = NULL;
int host_socket_fd = -1; /* on-host ivshm server socket path*/
pthread_mutex_t host_fd_mutex;
pthread_cond_t host_cond;
struct peer {
  int vm_id;
  int interrupt_fd[SHM_SLOTS * 2];
  int fd_count;
} peers_on_host[SHM_SLOTS];
const long long int kick =
    1; /* the value of '1' is defined by qemu ivshm app */

volatile int *my_vmid = NULL;
int vm_id = -1;
vm_data *my_shm_data[SHM_SLOTS], *peer_shm_data[SHM_SLOTS];
int run_as_client = -1;
int force_vmid = 0;
int local_rr_int_no[SHM_SLOTS], remote_rc_int_no[SHM_SLOTS];
pthread_t server_threads[SHM_SLOTS];
long long int client_listen_mask = 0;
/* End of host related variables */

struct slot *shm;

static int map_peer_fd(int slot, int peer_fd, int close_fd);

static const char warning_other_instance[] = "Exiting if the '-f' flag was "
                                             "not used";
static const char usage_string[] =
    "Usage: memsocket [-h | --host <host_ivshmem_socket_path>] [-f | "
    "--force]\n       { (-s | --server "
    "<sink_socket_path> "
    "-l | --listen <slot_list>) | (-c | --client <source_socket_path> <slot>) "
    "}\n\n"
    "Options:\n"
    "  -s, --server <sink_socket_path>\n"
    "      Connect to an existing socket (e.g., created by Waypipe) and "
    "transfer\n"
    "      data from slots specified with the `-l` option.\n\n"
    "  -l, --listen <slot_list>\n"
    "      Comma-separated list of slots (e.g., 1,2,3) to listen for data, or "
    "`-1`\n"
    "      to listen on all available slots. Used with `-s`.\n\n"
    "  -c, --client <source_socket_path> <slot>\n"
    "      Create a socket to forward all data to the connected peer’s sink "
    "socket.\n\n"
    "  -h, --host <host_ivshmem_socket_path>\n"
    "      Specify the ivshmem socket path (shared memory interface) to be "
    "used\n"
    "      when running on the host system.\n\n"
    "  -f, --force\n"
    "      Force run when other instance exited unclearly\n\n"
    "Examples:\n"
    "  1. Start socket receiving for slots 2 and 3:\n"
    "       memsocket -s /run/user/1000/pipewire-0 -l 2,3\n\n"
    "  2. Start socket forwarding for slots 2 and 3:\n"
    "       On Host:\n"
    "         memsocket -h /tmp/ivshmem_socket -c "
    "/home/ghaf/pipewire-forward.socket 2\n"
    "       On VM:\n"
    "         memsocket -c /run/user/1000/pipewire-forward.socket 3\n";

static void report(const char *msg, int terminate) {

  if (errno)
    perror(msg);
  else
    fprintf(stderr, "%s", msg);

  if (terminate)
    exit(-1);
}

static int get_shmem_size(int slot) {

  int res;

  res = lseek(shmem_fd[slot], 0, SEEK_END);
  if (res < 0) {
    FATAL("seek");
  }
  lseek(shmem_fd[slot], 0, SEEK_SET);
  return res;
}

static void fd_map_clear(int slot) {

  int i;

  for (i = 0; i < MAX_FDS; i++) {
    fd_map[slot][i].my_fd = -1;
    fd_map[slot][i].remote_fd = -1;
  }
}

static int close_connection(int slot, vm_data *shm_desc) {
  int connected_app_fd, res;

  if (run_as_client) {
    connected_app_fd = shm_desc->fd;
    DEBUG("Closing %d", connected_app_fd);
  } else {
    connected_app_fd = map_peer_fd(slot, shm_desc->fd, 1);
    DEBUG("Closing %d peer fd=%d", connected_app_fd, shm_desc->fd);
  }

  if (connected_app_fd > 0) {
    if (epoll_ctl(epollfd_full[slot], EPOLL_CTL_DEL, connected_app_fd, NULL) ==
        -1) {
      ERROR0("epoll_ctl: EPOLL_CTL_DEL");
    }
    close(connected_app_fd);
    return 0;
  } else {
    return -1;
  }
}

static void read_msg(int ivshmem_fd, long int *buf, int *fd, int slot) {
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

  rv = recvmsg(ivshmem_fd, &msg, MSG_NOSIGNAL);
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

int peer_index_op(int op, int vmid, int slot) {
  int i, n, free = SHM_SLOTS;
  struct peer *peer;

  if (vmid == vm_id >> 16)
    return 0; /* Our data is always on the index 0*/

  for (i = 0; i < SHM_SLOTS; i++) {
    peer = &peers_on_host[i];
    if (peer->vm_id == -1) {
      free = i;
      continue;
    }

    if (peer->vm_id == vmid) {
      switch (op) {
        case TEST_PEER_INDEX:
        case GET_PEER_INDEX:
          return i;
          break;
      case CLEAR_PEER_INDEX:
        peer->vm_id = -1;
        for (n = 0; n < SHM_SLOTS * 2; n++) {
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
  case TEST_PEER_INDEX:
    peers_on_host[free].vm_id = vmid;
    return free;
  case CLEAR_PEER_INDEX:
    return -1;
  case GET_PEER_INDEX:
    ERROR("vmid 0x%x not found", vmid);
    FATAL("Exiting.")
  }
  return -1;
}

int doorbell(int slot, struct ioctl_data *ioctl_data) {
  int vm_id, index, res;

  // Sync cache
  if (msync(&my_shm_data[slot]->data[0], sizeof(**my_shm_data), MS_SYNC) < 0) {
    ERROR("%s sizeof(*my_shm_data)=%d", "msync failed", sizeof(**my_shm_data));
    return -1;
  }
  if (!run_on_host) {
    return ioctl(shmem_fd[slot], SHMEM_IOCDORBELL, ioctl_data);
  }
  vm_id = ioctl_data->int_no >> 16;
  index = peer_index_op(GET_PEER_INDEX, vm_id, slot);
  res = write(peers_on_host[index].interrupt_fd[ioctl_data->int_no & 0xffff],
              &kick, sizeof(kick));
  INFO("Writing to interrupt fd: Addr=0x%x fd=%d", ioctl_data->int_no,
       peers_on_host[index].interrupt_fd[ioctl_data->int_no & 0xffff]);
  if (res < 0) {
    ERROR("Writing to interrupt fd failed. Addr=0x%x fd=%d", ioctl_data->int_no,
          peers_on_host[index].interrupt_fd[ioctl_data->int_no & 0xffff]);
    FATAL("Exiting");
  }
  return res;
}

/* Executed when the app is executed on host, not iniside VM */
static void *host_run(void *arg) {
  int slot = (long int)arg;
  int ivshmemsrv_fd;
  long int tmp;
  int shm_fd;
  struct peer *peer;
  int peer_idx;
  struct sockaddr_un socket_name;

  pthread_mutex_lock(&host_fd_mutex);

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
  read_msg(ivshmemsrv_fd, &tmp, &shm_fd, slot);
  INFO("ivshmem protocol version %ld", tmp);

  /* Get my vm id */
  read_msg(ivshmemsrv_fd, &tmp, &shm_fd, slot);
  if (tmp >= 0 || shm_fd == -1) {
    vm_id = tmp << 16;
    INFO("my physical vm id=%ld", tmp);
  } else {
    DEBUG("tmp=%ld fd=%d", tmp, shm_fd);
    FATAL("invalid ivshmem server response");
  }

  /* Get shared memory fd */
  read_msg(ivshmemsrv_fd, &tmp, &shm_fd, slot);
  INFO("shared memory fd=%d", shm_fd);
  if (shm_fd >= 0 || tmp == -1) {
    host_socket_fd = shm_fd;
  } else {
    DEBUG("tmp=%ld fd=%d", tmp, shm_fd);
    FATAL("invalid ivshmem server response");
  }
  /* Process messages */
  do {
    read_msg(ivshmemsrv_fd, &tmp, &shm_fd, slot);
    INFO("peer addr=0x%lx shm_fd=%d", tmp, shm_fd);

    if (tmp >= 0) {      /* peer or self  connection or disconnection */
      if (shm_fd >= 0) { /* peer or self connection */

        peer_idx = peer_index_op(TEST_PEER_INDEX, tmp, slot);
        if (peer_idx >= SHM_SLOTS) {
          ERROR("vm id %ld not found", tmp);
          continue;
        }
        peer = &peers_on_host[peer_idx];

        if (peer->fd_count >= SHM_SLOTS * 2) {
          ERROR("Ignored received excessive interrupt fd# %d fd_count=%d",
                shm_fd, peer->fd_count);
          continue;
        }
        if (peer->interrupt_fd[peer->fd_count] == -1) {
          peer->interrupt_fd[peer->fd_count] = shm_fd;
          INFO("Received peer idx=%d interrupt[%d] fd %d", peer_idx,
               peer->fd_count, shm_fd);
          peer->fd_count++;
          if (peer->fd_count == SHM_SLOTS * 2 && !peer_idx) {
            INFO("%s", "Host configuration ready");
            pthread_cond_signal(&host_cond);
            pthread_mutex_unlock(&host_fd_mutex);
            INFO("my physical vm id=0x%x", vm_id);
          }
        } else
          ERROR("Ignored re-using peer's %d interrupt[%d] fd: %d", peer_idx,
                peer->fd_count, shm_fd);
        continue;
      }

      else { /* peer disconnection */
        if (!peer_index_op(CLEAR_PEER_INDEX, tmp, 0xff)) {
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

static void wait_server_ready(int slot) {
  do {
    /* check if server has started */
    if (shm[slot].server.vmid &&
        shm[slot].server.vmid != UNKNOWN_PEER) {
      break;
    }
    DEBUG("%s", "Waiting for server to be ready");
    sleep(1);
  } while (1);
  DEBUG("server vmid=0x%x", (unsigned)shm[slot].server.vmid);
}

static void client_init(int slot) {

  struct sockaddr_un socket_name;
  struct epoll_event ev;
  struct stat socket_stat;

  /* Remove socket file if exists */
  if (stat(socket_path, &socket_stat) == 0) {
    if (S_ISSOCK(socket_stat.st_mode)) {
      if (unlink(socket_path)) {
        ERROR("Socket %s already exists and cannot be deleted", socket_path);
        FATAL("Exiting");
      }
    } else {
      ERROR("Socket %s cannot be created as it already exists", socket_path);
      FATAL("Exiting");
    }
  }

  endpoint_socket = socket(AF_UNIX, SOCK_STREAM, 0);
  if (endpoint_socket < 0) {
    FATAL("endpoint socket");
  }

  DEBUG("endpoint socket: %d", endpoint_socket);

  memset(&socket_name, 0, sizeof(socket_name));
  socket_name.sun_family = AF_UNIX;
  strncpy(socket_name.sun_path, socket_path, sizeof(socket_name.sun_path) - 1);
  if (bind(endpoint_socket, (struct sockaddr *)&socket_name,
           sizeof(socket_name)) < 0) {
    FATAL("bind");
  }

  if (listen(endpoint_socket, MAX_EVENTS) < 0)
    FATAL("listen");

  ev.events = EPOLLIN;
  ev.data.fd = endpoint_socket;
  if (epoll_ctl(epollfd_full[slot], EPOLL_CTL_ADD, endpoint_socket, &ev) ==
      -1) {
    FATAL("client_init: epoll_ctl: endpoint_socket");
  }

  wait_server_ready(slot);
  INFO("%s", "client instance initialized");
}

static int sink_socket_connect(int slot) {

  struct sockaddr_un socket_name;
  struct epoll_event ev;
  int sink_fd, res;

  sink_fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (sink_fd < 0) {
    FATAL("sink socket");
  }

  DEBUG("sink socket: %d", sink_fd);

  memset(&socket_name, 0, sizeof(socket_name));
  socket_name.sun_family = AF_UNIX;
  strncpy(socket_name.sun_path, socket_path, sizeof(socket_name.sun_path) - 1);
  if (connect(sink_fd, (struct sockaddr *)&socket_name, sizeof(socket_name)) <
      0) {
    res = -errno;
    ERROR("%s", "cannot connect to the sink socket");
    return res;
  }

  ev.events = EPOLLIN;
  ev.data.fd = sink_fd;
  if (epoll_ctl(epollfd_full[slot], EPOLL_CTL_ADD, sink_fd, &ev) == -1) {
    FATAL("epoll_ctl: sink_fd");
  }

  INFO("%s", "server initialized");
  return sink_fd;
}

static int make_sink_socket_connection(int slot, int peer_fd) {

  int i, tmp;

  for (i = 0; i < MAX_FDS; i++) {
    if (fd_map[slot][i].my_fd == -1) {
      tmp = sink_socket_connect(slot);
      if (tmp > 0) {
        fd_map[slot][i].my_fd = tmp;
        fd_map[slot][i].remote_fd = peer_fd;
      }
      return tmp;
    }
  }
  ERROR("fd_map table full. Failed fd#%d", peer_fd);
  return -1;
}

static int map_peer_fd(int slot, int peer_fd, int close_fd) {

  int i, rv;

  for (i = 0; i < MAX_FDS; i++) {
    if (fd_map[slot][i].remote_fd == peer_fd) {
      rv = fd_map[slot][i].my_fd;
      if (close_fd)
        fd_map[slot][i].my_fd = -1;
      return rv;
    }
  }
  ERROR("FAILED on mapping remote fd#%d", peer_fd);
  return -1;
}

static int get_remote_socket(int slot, int my_fd, int close_fd,
                             int ignore_error) {

  int i;

  for (i = 0; i < MAX_FDS; i++) {
    if (fd_map[slot][i].my_fd == my_fd) {
      if (close_fd)
        fd_map[slot][i].my_fd = -1;
      return fd_map[slot][i].remote_fd;
    }
  }
  if (ignore_error)
    return -1;

  FATAL("my fd not found");
  return -1;
}

static void shmem_init(int slot) {

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
    shmem_fd[slot] = host_socket_fd;
    INFO("ivshmem shared memory fd: %d", shmem_fd[slot]);
  } else {
    /* open shared memory device */
    shmem_fd[slot] = open(SHM_DEVICE_FN, O_RDWR);
    if (shmem_fd[slot] < 0) {
      FATAL("Open " SHM_DEVICE_FN);
    }
    INFO("shared memory fd: %d", shmem_fd[slot]);
    res = ioctl(shmem_fd[slot], SHMEM_IOCSETINSTANCENO, slot);
    if (res) {
      FATAL("Setting instance id failed");
    }
  }

  /* Get shared memory: check size and mmap it */
  shmem_size = get_shmem_size(slot);
  if (shmem_size <= 0) {
    FATAL("No shared memory detected");
  }
  if (shmem_size < sizeof(*shm)) {
    ERROR("Shared memory too small: %ld bytes allocated whereas %ld needed",
          shmem_size, sizeof(*shm));
    FATAL("Exiting");
  }
  shm = mmap(NULL, shmem_size, PROT_READ | PROT_WRITE,
                    MAP_SHARED | MAP_NORESERVE, shmem_fd[slot], 0);
  if (!shm) {
    FATAL("Got NULL pointer from mmap");
  }
  DEBUG("Shared memory at address %p 0x%lx bytes", shm, shmem_size);

  if (run_as_client) {
    my_shm_data[slot] = &shm[slot].client;
    peer_shm_data[slot] = &shm[slot].server;
  } else {
    my_shm_data[slot] = &shm[slot].server;
    peer_shm_data[slot] = &shm[slot].client;
  }
  DEBUG("shm=%p my_shm_data=%p peer_shm_data=%p", shm,
        my_shm_data[slot], peer_shm_data[slot]);
  DEBUG("my_shm_data offset=0x%lx peer_shm_data offset=0x%lx",
        (void *)my_shm_data[slot] - (void *)shm,
        (void *)peer_shm_data[slot] - (void *)shm);
  if (!run_on_host) {
    /* get my VM Id */
    res = ioctl(shmem_fd[slot], SHMEM_IOCIVPOSN, &tmp);
    if (res < 0) {
      FATAL("ioctl SHMEM_IOCIVPOSN failed");
    }
    vm_id = tmp << 16;
  }
  if (run_as_client) {
    my_vmid = &shm[slot].client.vmid;
  } else {
    my_vmid = &shm[slot].server.vmid;
  }
  if (*my_vmid) {
    ERROR("Another client/server from VM 0x%x may be running ", *my_vmid);
    if (force_vmid) {
      ERROR("%s", warning_other_instance);
    } else {
      FATAL(warning_other_instance);
    }
  }
  *my_vmid = vm_id;
  if (!run_as_client) { /* Clear the vm_id and wait longer then client's timeout
                     in order to let it know the server has restarted */
    shm[slot].server.vmid = 0;
    sleep(3 * SHMEM_POLL_TIMEOUT / 2 / 1000);
    shm[slot].server.vmid = vm_id;
  }
  INFO("My VM id = 0x%x. Running as a ", *my_vmid);
  if (run_as_client) {
    INFO("%s", "client");
  } else {
    INFO("%s", "server");
  }

  if (!run_on_host) {
    ev.events = EPOLLIN | EPOLLOUT;
    ev.data.fd = shmem_fd[slot];
    if (epoll_ctl(epollfd_full[slot], EPOLL_CTL_ADD, ev.data.fd, &ev) == -1) {
      FATAL("epoll_ctl: -1");
    }
    ev.events = EPOLLIN | EPOLLOUT;
    ev.data.fd = shmem_fd[slot];
    if (epoll_ctl(epollfd_limited[slot], EPOLL_CTL_ADD, ev.data.fd, &ev) ==
        -1) {
      FATAL("epoll_ctl: -1");
    }
    /* Set output buffer it's available */
    ioctl(shmem_fd[slot], SHMEM_IOCSET,
          (LOCAL_RESOURCE_READY_INT_VEC << 8) + 1);
  } else { /* on host use file descriptors provided by ivshmem server */
    ev.events = EPOLLIN;
    ev.data.fd =
        peers_on_host[0]
            .interrupt_fd[(slot << 1) | PEER_RESOURCE_CONSUMED_INT_VEC];
    if (epoll_ctl(epollfd_full[slot], EPOLL_CTL_ADD, ev.data.fd, &ev) == -1) {
      FATAL("epoll_ctl: -1");
    }
    if (epoll_ctl(epollfd_limited[slot], EPOLL_CTL_ADD, ev.data.fd, &ev) ==
        -1) {
      FATAL("epoll_ctl: -1");
    }
    ev.events = EPOLLIN;
    ev.data.fd = peers_on_host[0]
                     .interrupt_fd[(slot << 1) | LOCAL_RESOURCE_READY_INT_VEC];
    if (epoll_ctl(epollfd_full[slot], EPOLL_CTL_ADD, ev.data.fd, &ev) == -1) {
      FATAL("epoll_ctl: -1");
    }
    if (epoll_ctl(epollfd_limited[slot], EPOLL_CTL_ADD, ev.data.fd, &ev) ==
        -1) {
      FATAL("epoll_ctl: -1");
    }
  }
  INFO("%s", "shared memory initialized");
}

static void thread_init(int slot) {

  int res;
  struct ioctl_data ioctl_data;
  struct stat server_socket_stat;

  fd_map_clear(slot);

  epollfd_full[slot] = epoll_create1(0);
  if (epollfd_full[slot] == -1) {
    FATAL("client_init: epoll_create1");
  }
  epollfd_limited[slot] = epoll_create1(0);
  if (epollfd_limited[slot] == -1) {
    FATAL("client_init: epoll_create1");
  }

  struct epoll_event ev;
  ev.events = EPOLLIN;
  ev.data.fd = signal_fd;
  if (epoll_ctl(epollfd_limited[slot], EPOLL_CTL_ADD, ev.data.fd, &ev) == -1) {
    ERROR("%s", "epoll_ctl: -1");
  }
  if (epoll_ctl(epollfd_full[slot], EPOLL_CTL_ADD, ev.data.fd, &ev) == -1) {
    ERROR("%s", "epoll_ctl: -1");
  }

  shmem_init(slot);

  if (run_as_client) {
    /* Create the sink socket that client can write to
     * Add the socket fd to the epollfd_full
     */
    client_init(slot);
    /* Specifies the interrupt (doorbell) number used to notify the peer that
       data is ready to be processed in the buffer
    */
    local_rr_int_no[slot] = shm[slot].server.vmid | (slot << 1) |
                            LOCAL_RESOURCE_READY_INT_VEC;
    /* Specifies the interrupt (doorbell) number used to notify the peer that
       the received remote data has been consumed, allowing it to reuse its
       buffer
    */
    remote_rc_int_no[slot] = shm[slot].server.vmid | (slot << 1) |
                             PEER_RESOURCE_CONSUMED_INT_VEC;
    /*
     * Send LOGIN cmd to the server. Supply my_vmid
     */
    my_shm_data[slot]->cmd = CMD_LOGIN;
    my_shm_data[slot]->fd = *my_vmid;
    my_shm_data[slot]->len = 0;
    my_shm_data[slot]->status = 0;

    ioctl_data.int_no = local_rr_int_no[slot];
#ifdef DEBUG_IOCTL
    ioctl_data.cmd = my_shm_data[slot]->cmd;
    ioctl_data.fd = my_shm_data[slot]->fd;
    ioctl_data.len = my_shm_data[slot]->len;
    ioctl_data.status = my_shm_data[slot]->status;
#endif
    INFO("ioctl_data.int_no=0x%x (vmid.int_no)", ioctl_data.int_no);
    res = doorbell(slot, &ioctl_data);

    DBG("Sent login vmid: 0x%x ioctl result=%d to server_vm_id=0x%x", *my_vmid,
        res, peer_shm_data[slot]->vmid);
  } else { /* run as server */
    if (stat(socket_path, &server_socket_stat)) {
      ERROR("Sink socket %s doesn't exist", socket_path);
    }
  }
}

static void close_fds(int slot) {
  int i;

  for (i = 0; i < MAX_FDS; i++) {
    if (fd_map[slot][i].my_fd != -1)
      close(fd_map[slot][i].my_fd);
  }
  fd_map_clear(slot);
}

static int cksum(unsigned char *buf, int len) {
  int i, res = 0;
  for (i = 0; i < len; i++)
    res += buf[i];
  return res;
}

static void send_logout(int slot, vm_data *my_shm_desc) {
  struct ioctl_data ioctl_data;

  my_shm_desc->cmd = CMD_LOGOUT;
  my_shm_desc->fd = *my_vmid;
  my_shm_desc->len = 0;
  my_shm_desc->status = 0;
  ioctl_data.int_no = local_rr_int_no[slot];

  doorbell(slot, &ioctl_data);
  return;
}

static void *run(void *arg) {

  int slot = (intptr_t)arg;
  int connected_app_fd, rv, nfds, n, read_count, event_handled;
  struct sockaddr_un caddr;      /* server address */
  socklen_t len = sizeof(caddr); /* address length could change */
  struct pollfd shm_buffer_fd = {.events = POLLOUT};
  struct epoll_event ev, *current_event;
  struct epoll_event events[MAX_EVENTS];
  struct ioctl_data ioctl_data;
  unsigned int tmp;
  int epollfd;
  vm_data *peer_shm_desc, *my_shm_desc;
  int data_ack, data_in;

  /* Variables used when run on host*/
  int fd_int_data_ack = -1;   /* peer has consumed our data */
  int fd_int_data_ready = -1; /* signal the peer that there is data ready */
  long long int kick;

  if (slot >= SHM_SLOTS || slot < 0) {
    ERROR("Invalid slot no: %d", slot);
    FATAL("Exiting");
  }

  thread_init(slot);
  peer_shm_desc = peer_shm_data[slot];
  my_shm_desc = my_shm_data[slot];
  shm_buffer_fd.fd = shmem_fd[slot];
  epollfd = epollfd_full[slot];
  errno = 0;
  DEBUG("shm=0x%p my_shm_desc=0x%p peer_shm_desc=0x%p", (void*)my_shm_desc,
        (void*)peer_shm_desc, (void*)shm);
  DEBUG("Offsets: my_shm_desc=0x%llx peer_shm_desc=0x%llx", 
    (long long)((void*)my_shm_desc - (void*)shm),
        (long long)((void*)peer_shm_desc - (void*)shm));
  

  /* On host sockets are used for handling interrupt */
  if (run_on_host) {
    fd_int_data_ack =
        peers_on_host[0]
            .interrupt_fd[slot << 1 | PEER_RESOURCE_CONSUMED_INT_VEC];
    fd_int_data_ready =
        peers_on_host[0].interrupt_fd[slot << 1 | LOCAL_RESOURCE_READY_INT_VEC];
    INFO("fd_int_data_ack=%d fd_int_data_ready=%d", fd_int_data_ack,
         fd_int_data_ready)
  }

  while (1) {
#ifdef DEBUG_ON
    if (epollfd == epollfd_full[slot]) {
      DEBUG("%s", "Waiting for all events");
    } else {
      DEBUG("%s", "Waiting for ACK");
    }
#endif
    nfds = epoll_wait(epollfd, events, MAX_EVENTS, SHMEM_POLL_TIMEOUT);
    if (nfds < 0) {
      FATAL("epoll_wait");
    }
    if (shm[slot].server.vmid == 0) {
      FATAL("memsocket server died/restarted or another instance is running");
    }
    if (nfds == 0) { /* timeout */
      continue;
    }

    for (n = 0; n < nfds; n++) {
      event_handled = 0;
      current_event = &events[n];
#ifdef DEBUG_ON
      if (!run_on_host)
        ioctl(shm_buffer_fd.fd, SHMEM_IOCNOP, &tmp);

      DBG("Event index=%d 0x%x on fd %d inout=%d-%d", n, current_event->events,
          current_event->data.fd, tmp & 0xffff, tmp >> 16);
#endif
      /* Check for Ctrl-C */
      if (current_event->data.fd == signal_fd) {
        DBG("%s", "A signal received.");
        struct signalfd_siginfo siginfo;
        read(signal_fd, &siginfo, sizeof(siginfo)); // Read the signal info
        if (siginfo.ssi_signo == SIGINT || siginfo.ssi_signo == SIGTERM) {
          send_logout(slot, my_shm_desc);
          FATAL("SIGINT/SIGTERM: exiting.");
        }
      }

      /* Check for ACK from the peer received via shared memory */
      if (!run_on_host)
        data_ack = current_event->events & EPOLLOUT &&
                   current_event->data.fd == shm_buffer_fd.fd;
      else
        data_ack = current_event->events & EPOLLIN &&
                   current_event->data.fd == fd_int_data_ack;
      if (data_ack) {
        DEBUG("%s", "Received remote ACK");
        if (my_shm_desc->cmd == CMD_LOGIN && run_as_client) {
          DBG("%s", "Connected to the server");
        }
        if (my_shm_desc->status < 0) {
          errno = -my_shm_desc->status;
          ERROR("Peer error 0x%x fd=%d for the command #%d sent data count %d",
                my_shm_desc->status, my_shm_desc->fd, my_shm_desc->cmd,
                my_shm_desc->len);
          errno = 0;
          if (!run_as_client) {
            ERROR("Local fd=%d", map_peer_fd(slot, my_shm_desc->fd, 0));
          };
          if (my_shm_desc->len < 0) {
            ERROR("%s", "Closing connection due to error");
            close_connection(slot, my_shm_desc);
          }
          if (my_shm_desc->cmd == CMD_CONNECT) {
            ERROR("Closing fd #%d due to error on server site",
                  connected_app_fd);
            close(connected_app_fd);
          }
        }
        /* Notify the driver that we reserve the local buffer */
        if (!run_on_host) {
          ioctl(shm_buffer_fd.fd, SHMEM_IOCSET,
                (LOCAL_RESOURCE_READY_INT_VEC << 8) + 0);
        } else {
          rv = read(fd_int_data_ack, &kick, sizeof(kick));
          if (rv < 0) {
            FATAL("Exiting");
          } else if (rv != sizeof(kick))
            ERROR("Invalid read data length %d", rv);
        }
        /* as the local buffer is available, start to handle all events */
        epollfd = epollfd_full[slot];
        event_handled = 1;
      }

      /* Handle the new connection event on the listening socket */
      if (current_event->events & EPOLLIN && run_as_client &&
          current_event->data.fd == endpoint_socket) {
        connected_app_fd =
            accept(endpoint_socket, (struct sockaddr *)&caddr, &len);
        if (connected_app_fd == -1) {
          FATAL("accept");
        }
        ev.events = EPOLLIN | EPOLLET | EPOLLHUP;
        ev.data.fd = connected_app_fd;
        if (epoll_ctl(epollfd_full[slot], EPOLL_CTL_ADD, connected_app_fd,
                      &ev) == -1) {
          FATAL("epoll_ctl: connected_app_fd");
        }
        /* Send the connect request to the sink peer */
        my_shm_desc->cmd = CMD_CONNECT;
        my_shm_desc->fd = connected_app_fd;
        my_shm_desc->len = 0;
        my_shm_desc->status = 0;
        ioctl_data.int_no = local_rr_int_no[slot];
#ifdef DEBUG_IOCTL
        ioctl_data.cmd = my_shm_desc->cmd;
        ioctl_data.fd = my_shm_desc->fd;
        ioctl_data.len = my_shm_desc->len;
        ioctl_data.len = my_shm_desc->status;
#endif
        /* Buffer is busy since now. Switch to waiting for the doorbell ACK
           from the peer */
        epollfd = epollfd_limited[slot];
        /* Signal the peer that the data is ready */
        doorbell(slot, &ioctl_data);
        DEBUG("Doorbell to add the new client on fd %d", connected_app_fd);
        event_handled = 1;
      }

      /*
       * Server and client: Received interrupt from peer VM - there is
       * incoming data in the shared memory - EPOLLIN
       */
      INFO("Possible incoming data: current_event->events=0x%x "
           "current_event->data.fd=%d "
           "fd_int_data_ready=%d",
           current_event->events, current_event->data.fd, fd_int_data_ready)
      if (!run_on_host)
        data_in = current_event->events & EPOLLIN &&
                  current_event->data.fd == shm_buffer_fd.fd;
      else /* run on host */
        data_in = current_event->events & EPOLLIN &&
                  current_event->data.fd == fd_int_data_ready;

      if (data_in) {
        DEBUG("shmem_fd/host_fd=%d event: 0x%x cmd: 0x%x remote fd: %d remote "
              "len: %d status: %d",
              run_on_host ? fd_int_data_ready : shm_buffer_fd.fd,
              current_event->events, peer_shm_desc->cmd, peer_shm_desc->fd,
              peer_shm_desc->len, peer_shm_desc->status);

        switch (peer_shm_desc->cmd) {
        case CMD_LOGIN:
          DBG("Received login request from 0x%x", peer_shm_desc->fd);
          /* If the peer VM starts again, close all opened file handles */
          close_fds(slot);
          local_rr_int_no[slot] =
              peer_shm_desc->fd | (slot << 1) | LOCAL_RESOURCE_READY_INT_VEC;
          remote_rc_int_no[slot] =
              peer_shm_desc->fd | (slot << 1) | PEER_RESOURCE_CONSUMED_INT_VEC;

          peer_shm_desc->fd = 0;
          peer_shm_desc->status = 0; /* result */
          break;
        case CMD_LOGOUT:
          DBG("Received logout request from 0x%x", peer_shm_desc->fd);
          /* Close all opened file handles */
          close_fds(slot);
          if (run_as_client) {
            DBG("%s", "Server has terminated. Exiting.");
            peer_shm_desc->fd = -1;
            peer_shm_desc->status = -1;
            return NULL;
          }
          peer_shm_desc->fd = 0;
          peer_shm_desc->status = 0; /* result */
          break;
        case CMD_DATA:
        case CMD_DATA_CLOSE:
          connected_app_fd = run_as_client
                                 ? peer_shm_desc->fd
                                 : map_peer_fd(slot, peer_shm_desc->fd, 0);
          peer_shm_desc->status = 0;
          DEBUG(
              "shmem: received %d bytes for %d cksum=0x%x", peer_shm_desc->len,
              connected_app_fd,
              cksum((unsigned char *)peer_shm_desc->data, peer_shm_desc->len));
          if (connected_app_fd > 0) {
            rv = send(connected_app_fd, (const void *)peer_shm_desc->data,
                      peer_shm_desc->len, MSG_NOSIGNAL);
            if (rv != peer_shm_desc->len) {
              peer_shm_desc->status = -errno;
              ERROR("Sent %d out of %d bytes on fd#%d peer fd#%d", rv,
                    peer_shm_desc->len, connected_app_fd, peer_shm_desc->fd);
            }
            DEBUG("%s", "Received data has been sent");
            peer_shm_desc->len = rv;
            if (rv < 0) {
              close_connection(slot, peer_shm_desc);
              break;
            }
          } else {
            peer_shm_desc->status = -1;
          }
          if (peer_shm_desc->cmd == CMD_DATA) {
            break;
          }
          /* no break if we also need to close the file descriptor */
        case CMD_CLOSE:
          peer_shm_desc->status = close_connection(slot, peer_shm_desc);
          break;
        case CMD_CONNECT:
          peer_shm_desc->fd = make_sink_socket_connection(slot, peer_shm_desc->fd);
          peer_shm_desc->status = peer_shm_desc->fd > 0 ? 0 : -1;
          break;
        default:
          ERROR("Invalid CMD 0x%x from peer!", peer_shm_desc->cmd);
          peer_shm_desc->fd = -1;
          peer_shm_desc->status = -1;
          break;
        } /* switch peer_shm_desc->cmd */

        /* Signal the other side that the data buffer has been processed */
        DEBUG("%s", "Exec ioctl REMOTE_RESOURCE_CONSUMED_INT_VEC");
        ioctl_data.int_no = remote_rc_int_no[slot];
        if (!run_on_host) {
#ifdef DEBUG_IOCTL
          ioctl_data.len = 0;
#endif
        } else {
          rv = read(fd_int_data_ready, &kick, sizeof(kick));
          if (rv < 0) {
            FATAL("Invalid response");
          } else if (rv != sizeof(kick))
            ERROR("Invalid read data length %d", rv);
        }
        doorbell(slot, &ioctl_data);
        event_handled = 1;
      } /* End of "data arrived from the peer via shared memory" */

      /* Received an app data via connected socket. It needs to
         be sent to the shared memory peer */
      if ((current_event->events & EPOLLIN) && !event_handled) {
        if (!run_as_client) {
          connected_app_fd =
              get_remote_socket(slot, current_event->data.fd, 0, IGNORE_ERROR);
          DEBUG("get_remote_socket: %d", connected_app_fd);
        } else {
          connected_app_fd = current_event->data.fd;
        }
        DEBUG("%s", "Reading from sink socket");
        read_count = recv(current_event->data.fd, (void *)my_shm_desc->data,
                          sizeof(my_shm_desc->data), MSG_NOSIGNAL);

        if (read_count <= 0) {
          if (read_count < 0)
            ERROR("recv from sink socket failed fd=%d", current_event->data.fd);
          if (!run_on_host)
            /* Release output buffer */
            ioctl(shm_buffer_fd.fd, SHMEM_IOCSET,
                  (LOCAL_RESOURCE_READY_INT_VEC << 8) + 1);

        } else { /* read_count > 0 */
          DEBUG("Read %d bytes on fd#%d to be sent to #%d checksum=0x%x",
                read_count, current_event->data.fd, connected_app_fd,
                cksum((unsigned char *)my_shm_desc->data, read_count));

          if (current_event->events & EPOLLHUP) {
            my_shm_desc->cmd = CMD_DATA_CLOSE;
            current_event->events &= ~EPOLLHUP;

            /* unmap local fd */
            if (!run_as_client)
              get_remote_socket(slot, current_event->data.fd, CLOSE_FD,
                                IGNORE_ERROR);
            /* close local fd*/
            DEBUG("Close fd %d", current_event->data.fd);
            close(current_event->data.fd);
          } else
            my_shm_desc->cmd = CMD_DATA;

          my_shm_desc->fd = connected_app_fd;
          my_shm_desc->len = read_count;
          my_shm_desc->status = 0;

          ioctl_data.int_no = local_rr_int_no[slot];
#ifdef DEBUG_IOCTL
          ioctl_data.cmd = my_shm_desc->cmd;
          ioctl_data.fd = my_shm_desc->fd;
          ioctl_data.len = my_shm_desc->len;
          ioctl_data.status = my_shm_desc->status;
#endif
          DEBUG("Exec ioctl DATA/DATA_CLOSE cmd=%d fd=%d len=%d",
                my_shm_desc->cmd, my_shm_desc->fd, my_shm_desc->len);
          epollfd = epollfd_limited[slot];
          doorbell(slot, &ioctl_data);
          break;
        }
      } /* end of incoming data processing EPOLLIN*/

      /* Handling connection close */
      if (current_event->events & (EPOLLHUP | EPOLLERR)) {
        DEBUG("Closing fd#%d", current_event->data.fd);
        my_shm_desc->cmd = CMD_CLOSE;
        if (run_as_client)
          my_shm_desc->fd = current_event->data.fd;
        else {
          DEBUG(
              "get_remote_socket: %d",
              get_remote_socket(slot, current_event->data.fd, 0, IGNORE_ERROR));
          my_shm_desc->fd = get_remote_socket(slot, current_event->data.fd,
                                              CLOSE_FD, IGNORE_ERROR);
        }
        if (my_shm_desc->fd > 0) {
          DEBUG("ioctl ending close request for %d", my_shm_desc->fd);

          ioctl_data.int_no = local_rr_int_no[slot];
          my_shm_desc->status = 0;
#ifdef DEBUG_IOCTL
          ioctl_data.cmd = my_shm_desc->cmd;
          ioctl_data.fd = my_shm_desc->fd;
          ioctl_data.len = my_shm_desc->len;
          ioctl_data.status = my_shm_desc->status;
#endif
          /* Output buffer is busy. Accept only the events
             that don't use it */
          epollfd = epollfd_limited[slot];
          doorbell(slot, &ioctl_data);
        } else { /* unlock output buffer */
          ERROR("Attempt to close invalid fd %d", current_event->data.fd);
          if (!run_on_host)
            ioctl(shm_buffer_fd.fd, SHMEM_IOCSET,
                  (LOCAL_RESOURCE_READY_INT_VEC << 8) + 1);
        }
        if (epoll_ctl(epollfd_full[slot], EPOLL_CTL_DEL, current_event->data.fd,
                      NULL) == -1) {
          ERROR("epoll_ctl: EPOLL_CTL_DEL on fd %d", current_event->data.fd);
        }
        close(current_event->data.fd);
        /* If the shared memory buffer is busy, don't proceed any further
         * events
         */
        if (epollfd == epollfd_limited[slot])
          break;
      } /* Handling connection close */
    } /* for n = 0..nfds */
  } /* while(1) */
  return 0;
}

static void print_usage_and_exit() {
  fprintf(stderr, usage_string);
  exit(1);
}

int main(int argc, char **argv) {

  int i, n, res = -1;
  int slot = -1;
  int opt;
  int run_mode = 0;
  pthread_t threads[SHM_SLOTS], host_thread;
  static struct option long_opts[] = {{"server", required_argument, 0, 's'},
                                      {"client", required_argument, 0, 'c'},
                                      {"host", required_argument, 0, 'h'},
                                      {"listen", required_argument, 0, 'l'},
                                      {"force", no_argument, 0, 'f'},
                                      {0, 0, 0, 0}};

  while ((opt = getopt_long(argc, argv, "c:s:h:l:f", long_opts, NULL)) != -1) {
    switch (opt) {
    case 's':
      run_as_client = 0;
      socket_path = optarg;
      run_mode++;
      break;

    case 'c':
      run_as_client = 1;
      socket_path = optarg;
      run_mode++;
      break;

    case 'h':
      run_on_host = 1;
      ivshmem_socket_path = optarg;
      break;

    case 'l':
      /* input is a list of integers */
      char *token = strtok(optarg, ",");
      while (token != NULL) {
        if (strspn(token, "-0123456789") != strlen(token)) {
          goto invalid_value;
        }
        int value = atoi(token);
        if (value >= SHM_SLOTS || value < -1) {
          goto invalid_value;
        }
          if (value == -1) {
            client_listen_mask = -1;
          }
          client_listen_mask |= 1 << value;
        token = strtok(NULL, ",");
        continue;
      invalid_value:
        fprintf(stderr, "-l: invalid value %s\n", token);
        goto exit;
      }
      break;

    case 'f':
      force_vmid = 1;
      break;

    default: /* '?' */
      goto wrong_args;
    }
  }

  if (argc > optind) {
    if (run_as_client) { /* extract positional parameter - client id*/
      if (strspn(argv[optind], "0123456789") != strlen(argv[optind])) {
        fprintf(stderr, "-c: invalid vm_id value %s\n", argv[optind]);
        goto exit;
      }
      slot = atoi(argv[optind]);
    } else {
      fprintf(stderr, "Ignored extra parameter(s): %s\n", argv[optind]);
      goto exit;
    }
  }

  if (run_mode > 1 || run_as_client < 0 || (slot < 0 && run_as_client > 0) ||
      (!client_listen_mask && !run_as_client))
    goto wrong_args;

  for (i = 0; i < SHM_SLOTS; i++) {
    my_shm_data[i] = NULL;
    peer_shm_data[i] = NULL;
    shmem_fd[i] = -1;
    peers_on_host[i].vm_id = -1;
    peers_on_host[i].fd_count = 0;
    for (n = 0; n < SHM_SLOTS * 2; n++)
      peers_on_host[i].interrupt_fd[n] = -1;
  }

  if (run_on_host) {
    /* Create a thread which collects data about peer VMs*/
    res = pthread_mutex_init(&host_fd_mutex, NULL);
    if (res) {
      FATAL("Cannot initialize the mutex");
    }
    res = pthread_create(&host_thread, NULL, host_run, (void *)(intptr_t)i);
    if (res) {
      FATAL("Cannot create the host thread");
    }
  }

  /* Turn signal into file descriptor */
  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, SIGINT | SIGTERM);
  if (pthread_sigmask(SIG_BLOCK, &mask, NULL) != 0) {
    FATAL("pthread_sigmask");
  }
  signal_fd = signalfd(-1, &mask, 0); // Create fd for the SIGINT signal

  /* On server site start a thread for each supported client */
  if (run_as_client == 0) {
    for (i = 0; i < SHM_SLOTS; i++) {
      if (!(client_listen_mask & 1 << i)) {
        continue;
      }

      slot = i;
      DBG("Starting thread for client #%d", i);
      res = pthread_create(&threads[i], NULL, run, (void *)(intptr_t)i);
      if (res) {
        ERROR("Thread id=%d", i);
        FATAL("Cannot create a thread");
      }
    }

    for (i = 0; i < SHM_SLOTS; i++) {
      if (!(client_listen_mask & 1 << i)) {
        continue;
      }

      res = pthread_join(threads[i], NULL);
      if (res) {
        ERROR("error %d waiting for the thread #%d", res, i);
      }
    }
  } else { /* client mode - run only one instance */
    run((void *)(intptr_t)slot);
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
exit:
  return 1;
}
