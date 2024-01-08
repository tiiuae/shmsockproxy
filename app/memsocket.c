/* Copyright 2022-2024 TII (SSRC) and the Ghaf contributors
   SPDX-License-Identifier: Apache-2.0
*/
#include <arpa/inet.h>
#include <errno.h>
#include <execinfo.h>
#include <fcntl.h>
#include <netinet/tcp.h>
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

#include "../module/kvm_ivshmem.h"

#define SHM_DEVICE_FN "/dev/ivshmem"

#define REMOTE_RESOURCE_CONSUMED_INT_VEC (0)
#define LOCAL_RESOURCE_READY_INT_VEC (1)

#define MAX_EVENTS (1024)
#define MAX_CLIENTS (10)
#define MAX_VMS (3)
#define BUFFER_SIZE (1024000)
#define SHMEM_POLL_TIMEOUT (300)
#define SHMEM_BUFFER_SIZE (1024000)
#define TEST_SLEEP_TIME (3333333)
#define SYNC_SLEEP_TIME (333333)
#define UNKNOWN_PEER (-1)
#if 0
#define DEBUG(fmt, ...)                                                        \
  {}
#else
#define DEBUG(fmt, ...)                                                        \
  {                                                                            \
    char tmp1[256], tmp2[256];                                                 \
    sprintf(tmp2, fmt, __VA_ARGS__);                                           \
    sprintf(tmp1, "%s:%d: %s\n", __FUNCTION__, __LINE__, tmp2);                \
    errno = 0;                                                                 \
    report(tmp1, 0);                                                           \
  }
#endif

#if 0
#define INFO(fmt, ...)                                                         \
  {}
#else
#define INFO(fmt, ...)                                                         \
  {                                                                            \
    char tmp1[256], tmp2[256];                                                 \
    sprintf(tmp2, fmt, __VA_ARGS__);                                           \
    sprintf(tmp1, "[%s:%d] %s\n", __FUNCTION__, __LINE__, tmp2);               \
    errno = 0;                                                                 \
    report(tmp1, 0);                                                           \
  }
#endif

#define ERROR(fmt, ...)                                                        \
  {                                                                            \
    char tmp1[256], tmp2[256];                                                 \
    sprintf(tmp2, fmt, __VA_ARGS__);                                           \
    sprintf(tmp1, "[%s:%d] %s\n", __FUNCTION__, __LINE__, tmp2);               \
    report(tmp1, 0);                                                           \
  }

#define FATAL(msg)                                                             \
  {                                                                            \
    char tmp1[256], tmp2[256];                                                 \
    sprintf(tmp2, msg);                                                        \
    sprintf(tmp1, "[%s:%d]: %s\n", __FUNCTION__, __LINE__, tmp2);              \
    report(tmp1, 1);                                                           \
  }

enum { CMD_LOGIN, CMD_CONNECT, CMD_DATA, CMD_CLOSE, CMD_START };
#define FD_MAP_COUNT (sizeof(fd_map) / sizeof(fd_map[0][0]))
struct {
  int my_fd;
  int remote_fd;
} fd_map[MAX_VMS][MAX_CLIENTS];

typedef struct {
  volatile int server_vmid;
  volatile int cmd;
  volatile int fd;
  volatile int len;
  volatile unsigned char data[SHMEM_BUFFER_SIZE];
} vm_data;

int epollfd[MAX_VMS];
char *socket_path;
int server_socket = -1, shmem_fd[MAX_VMS];
int my_vmid = -1, peer_vm_id[MAX_VMS];
vm_data *my_shm_data[MAX_VMS], *peer_shm_data[MAX_VMS];
int run_as_server = 0;
int local_rr_int_no[MAX_VMS], remote_rc_int_no[MAX_VMS];

struct {
  volatile int client_vmid;
  vm_data client_data[MAX_VMS];
  vm_data server_data[MAX_VMS];
} *vm_control;

static const char usage_string[] =
    "Usage: memsocket [-c|-s] socket_path {instance number (server only)}\n";

void report(const char *msg, int terminate) {
  char tmp[256];
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

void fd_map_clear(int instance_no) {
  int i;
  for (i = 0; i < FD_MAP_COUNT; i++) {
    fd_map[instance_no][i].my_fd = -1;
    fd_map[instance_no][i].remote_fd = -1;
  }
}

int server_init(int instance_no) {
  struct sockaddr_un socket_name;
  struct epoll_event ev;

  // Remove socket file if exists
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
  if (epoll_ctl(epollfd[instance_no], EPOLL_CTL_ADD, server_socket, &ev) == -1) {
    FATAL("server_init: epoll_ctl: server_socket");
  }

  INFO("server initialized", "");
}

int wayland_connect(int instance_no) {

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
  if (epoll_ctl(epollfd[instance_no], EPOLL_CTL_ADD, wayland_fd, &ev) == -1) {
    FATAL("epoll_ctl: wayland_fd");
  }

  INFO("client initialized", "");
  return wayland_fd;
}

void make_wayland_connection(int instance_no, int peer_fd) {

  int i;

  for (i = 0; i < FD_MAP_COUNT; i++) {
    if (fd_map[instance_no][i].my_fd == -1) {
      fd_map[instance_no][i].my_fd = wayland_connect(instance_no);
      fd_map[instance_no][i].remote_fd = peer_fd;
      return;
    }
  }

  ERROR("FAILED fd#%d", peer_fd);
  FATAL("fd_map table full");
}

int map_peer_fd(int instance_no, int peer_fd, int close_fd) {

  int i, rv;

  for (i = 0; i < FD_MAP_COUNT; i++) {
    if (fd_map[instance_no][i].remote_fd == peer_fd) {
      rv = fd_map[instance_no][i].my_fd;
      if (close_fd)
        fd_map[instance_no][i].my_fd = -1;
      return rv;
    }
  }
  ERROR("FAILED fd#%d", peer_fd);
  FATAL("peer fd  not found");
  return -1;
}

int get_remote_socket(int instance_no, int my_fd, int close_fd, int ignore_error) {

  int i;
  struct epoll_event ev;

  for (i = 0; i < FD_MAP_COUNT; i++) {
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

int shmem_init(int instance_no) {
  int res = -1;
  struct epoll_event ev;
  long int shmem_size;

  memset(shmem_fd, -1, MAX_VMS);

  /* Open shared memory */
  shmem_fd[instance_no] = open(SHM_DEVICE_FN, O_RDWR);
  if (shmem_fd[instance_no] < 0) {
    FATAL("Open " SHM_DEVICE_FN);
  }
  INFO("shared memory fd: %d instance id %d", shmem_fd[instance_no], instance_no);
  /* Store instance number inside driver */
  ioctl(shmem_fd[instance_no], SHMEM_IOCSETINSTANCENO, instance_no);

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

  /* get my VM Id */
  res = ioctl(shmem_fd[instance_no], SHMEM_IOCIVPOSN, &my_vmid);
  if (res < 0) {
    FATAL("ioctl SHMEM_IOCIVPOSN failed");
  }
  my_vmid = my_vmid << 16;
  if (run_as_server) {
    vm_control->server_data[instance_no].server_vmid = my_vmid;
  } else {
    vm_control->client_vmid = my_vmid;
    vm_control->server_data[instance_no].server_vmid = UNKNOWN_PEER;
  }
  INFO("My VM id = 0x%x instance = %d. Running as a ", my_vmid, instance_no);
  if (run_as_server) {
    INFO("server", "");
  } else {
    INFO("client", "");
  }

  ev.events = EPOLLIN;
  ev.data.fd = shmem_fd[instance_no];
  if (epoll_ctl(epollfd[instance_no], EPOLL_CTL_ADD, shmem_fd[instance_no], &ev) == -1) {
    FATAL("epoll_ctl: -1");
  }
  ioctl(shmem_fd[instance_no], SHMEM_IOCRESTART, 0);

  INFO("shared memory initialized", "");

  return 0;
}

int run(int instance_no) {
  fd_set rfds;
  struct timeval tv;
  int conn_fd, rv, nfds, i, n;
  struct sockaddr_un caddr; /* client address */
  int len = sizeof(caddr);  /* address length could change */
  char buffer[BUFFER_SIZE + 1];
  struct pollfd my_buffer_fds = {
      .fd = shmem_fd[instance_no], .events = POLLOUT, .revents = 0};
  struct epoll_event ev;
  struct epoll_event events[MAX_EVENTS];

  DEBUG("Listening for events", "");
  while (1) {

    nfds = epoll_wait(epollfd[instance_no], events, MAX_EVENTS, -1);
    if (nfds == -1) {
      FATAL("epoll_wait");
    }

    for (n = 0; n < nfds; n++) {

      DEBUG("Event 0x%x on fd %d", events[n].events, events[n].data.fd)

      /* Handle the new connection on the socket */
      if (events[n].events & EPOLLIN) {
        if (run_as_server && events[n].data.fd == server_socket) {
          conn_fd = accept(server_socket, (struct sockaddr *)&caddr, &len);
          if (conn_fd == -1) {
            FATAL("accept");
          }
          fcntl(conn_fd, F_SETFL, O_NONBLOCK);
          ev.events = EPOLLIN | EPOLLET | EPOLLHUP;
          ev.data.fd = conn_fd;
          if (epoll_ctl(epollfd[instance_no], EPOLL_CTL_ADD, conn_fd, &ev) == -1) {
            FATAL("epoll_ctl: conn_fd");
          }

          rv = poll(&my_buffer_fds, 1, SHMEM_POLL_TIMEOUT);
          if (rv < 0) {
            ERROR("shmem poll timeout", "");
          }

          if (my_buffer_fds.revents & ~POLLOUT) {
            ERROR("unexpected event on shmem_fd[instance_no] %d: 0x%x", shmem_fd[instance_no],
                  my_buffer_fds.revents);
          }
          /* Send the connect request to the wayland peer */
          my_shm_data[instance_no]->cmd = CMD_CONNECT;
          my_shm_data[instance_no]->fd = conn_fd;
          ioctl(shmem_fd[instance_no], SHMEM_IOCDORBELL, local_rr_int_no[instance_no]);
          DEBUG("Added client on fd %d", conn_fd);
        }

        /* Display/client side: received data from Wayland server. It needs to
          be sent to the peer (server) */
        else if (!run_as_server &&
                 get_remote_socket(instance_no, events[n].data.fd, 0, 1) > 0) {

          int conn_fd = get_remote_socket(instance_no, events[n].data.fd, 0, 1);
          DEBUG("get_remote_socket[%d]: %d", instance_no, conn_fd);

          /* Wait for the memory buffer to be ready */
          DEBUG("Data from wayland. Waiting for shmem buffer", "");
          rv = poll(&my_buffer_fds, 1, SHMEM_POLL_TIMEOUT);
          if ((rv <= 0) || (my_buffer_fds.revents & ~POLLOUT)) {
            ERROR("unexpected event on shmem_fd[%d] %d: 0x%x poll=%d", instance_no, shmem_fd[instance_no],
                  my_buffer_fds.revents, rv);
          }

          DEBUG("Reading from wayland socket", "");
          len = read(events[n].data.fd, (void *)my_shm_data[instance_no]->data,
                     sizeof(my_shm_data[instance_no]->data));
          if (len <= 0) {
            ERROR("read from wayland socket failed fd=%d", events[n].data.fd);
          } else {
            DEBUG("Read & sent %d bytes on fd#%d sent to %d", len,
                  events[n].data.fd, conn_fd);

            /* Send the data to the peer Wayland app server */
            my_shm_data[instance_no]->cmd = CMD_DATA;
            my_shm_data[instance_no]->fd = conn_fd;
            my_shm_data[instance_no]->len = len;
            ioctl(shmem_fd[instance_no], SHMEM_IOCDORBELL, local_rr_int_no[instance_no]);
          }
        } /* received data from Wayland server */

        /* Both sides: Received data from the peer via shared memory*/
        else if (events[n].data.fd == shmem_fd[instance_no]) {
          DEBUG("shmem_fd[%d]=%d event: 0x%x cmd: %d remote fd: %d remote len: %d", instance_no, shmem_fd[instance_no],
                events[n].events, peer_shm_data[instance_no]->cmd, peer_shm_data[instance_no]->fd,
                peer_shm_data[instance_no]->len);

          switch (peer_shm_data[instance_no]->cmd) {
          case CMD_LOGIN:
            DEBUG("Received login request from 0x%x", peer_shm_data[instance_no]->fd);
            // TODO: if peer VM starts again, close all opened files
            // for (i = 0; i < FD_MAP_COUNT; i++) {
            //   if (fd_map[instance_no][i].my_fd != -1)
            //     close(fd_map[instance_no][i].my_fd);
            // }
            // fd_map_clear(instance_no);

            peer_vm_id[instance_no] = peer_shm_data[instance_no]->fd;
            local_rr_int_no[instance_no] = peer_vm_id[instance_no] | (instance_no << 1) |
                              LOCAL_RESOURCE_READY_INT_VEC;
            remote_rc_int_no[instance_no] = peer_vm_id[instance_no] | (instance_no << 1) |
                               REMOTE_RESOURCE_CONSUMED_INT_VEC;

            peer_shm_data[instance_no]->fd = -1;
            break;
          case CMD_DATA:
            conn_fd = run_as_server ? peer_shm_data[instance_no]->fd
                                    : map_peer_fd(instance_no, peer_shm_data[instance_no]->fd, 0);
            DEBUG("shmem: received %d bytes for %d", peer_shm_data[instance_no]->len,
                  conn_fd);
            rv =
                write(conn_fd, (void *)peer_shm_data[instance_no]->data, peer_shm_data[instance_no]->len);
            if (rv != peer_shm_data[instance_no]->len) {
              ERROR("Wrote %d out of %d bytes on fd#%d", rv, peer_shm_data[instance_no]->len,
                    conn_fd);
            }
            DEBUG("Received data has been sent", "");
            break;
          case CMD_CONNECT:
            make_wayland_connection(instance_no, peer_shm_data[instance_no]->fd);
            break;
          case CMD_CLOSE:
            if (run_as_server) {
              conn_fd = peer_shm_data[instance_no]->fd;
              DEBUG("Closing %d", conn_fd);
            } else {
              conn_fd = map_peer_fd(instance_no, peer_shm_data[instance_no]->fd, 1);
              DEBUG("Closing %d peer fd=%d", conn_fd, peer_shm_data[instance_no]->fd);
            }
            if (conn_fd > 0) {
              if (epoll_ctl(epollfd[instance_no], EPOLL_CTL_DEL, conn_fd, NULL) == -1) {
                ERROR("epoll_ctl: EPOLL_CTL_DEL", "");
              }
              close(conn_fd);
            }
            break;
          default:
            ERROR("Invalid CMD 0x%x from peer!", peer_shm_data[instance_no]->cmd);
            break;
          } /* case peer_shm_data[instance_no]->cmd */

          /* Signal the other side that its buffer has been processed */
          DEBUG("Exec ioctl REMOTE_RESOURCE_CONSUMED_INT_VEC", "");
          peer_shm_data[instance_no]->cmd = -1;
          ioctl(shmem_fd[instance_no], SHMEM_IOCDORBELL, remote_rc_int_no[instance_no]);
        } /* End of "data arrived from the peer via shared memory" */

        else if (events[n].data.fd == server_socket) {
          ERROR("Ignored data from server socket", "");
        }

        /* Server side: Data arrived from connected waypipe server */
        else {
          /* Wait for the memory buffer to be ready */
          DEBUG("Data from client. Waiting for shmem buffer", "");
          rv = poll(&my_buffer_fds, 1, SHMEM_POLL_TIMEOUT);
          if (rv < 0) {
            ERROR("shmem poll for client fd=%d", events[n].data.fd);
          } else if (rv == 0) {
            ERROR("shmem poll timeout for client fd=%d", events[n].data.fd);
          }
          if (my_buffer_fds.revents & ~POLLOUT) {
            ERROR("unexpected event on shmem_fd[%d] %d: 0x%x poll=%d for client ", instance_no,
                  "fd=%d",
                  shmem_fd[instance_no], my_buffer_fds.revents, rv, events[n].data.fd);
          }
          DEBUG("Reading from connected client #%d", events[n].data.fd);
          len = read(events[n].data.fd, (void *)my_shm_data[instance_no]->data,
                     sizeof(my_shm_data[instance_no]->data));
          if (len <= 0) {
            ERROR("read from connected client failed fd=%d", events[n].data.fd);
          } else {
            DEBUG("Read & sent %d bytes on fd#%d", len, events[n].data.fd);
            /* Send the data to the wayland display side */
            my_shm_data[instance_no]->cmd = CMD_DATA;
            my_shm_data[instance_no]->fd = events[n].data.fd;
            my_shm_data[instance_no]->len = len;
            ioctl(shmem_fd[instance_no], SHMEM_IOCDORBELL, local_rr_int_no[instance_no]);
          }
        } // End of "Data arrived from connected waypipe server"
      }

      /* Handling connection close */
      if (events[n].events & (EPOLLHUP | EPOLLERR)) {
        DEBUG("Closing fd#%d", events[n].data.fd);

        // Inform the peer that the closed is being closed
        rv = poll(&my_buffer_fds, 1, SHMEM_POLL_TIMEOUT);
        if (rv < 0) {
          ERROR("shmem poll timeout", "");
        }

        my_shm_data[instance_no]->cmd = CMD_CLOSE;
        if (run_as_server)
          my_shm_data[instance_no]->fd = events[n].data.fd;
        else {
          DEBUG("get_remote_socket[%d]: %d", instance_no,
                get_remote_socket(instance_no, events[n].data.fd, 0, 1));
          my_shm_data[instance_no]->fd = get_remote_socket(instance_no, events[n].data.fd, 1, 1);
        }
        if (my_shm_data[instance_no]->fd > 0) {
          DEBUG("Sending close request for %d", my_shm_data[instance_no]->fd);
          ioctl(shmem_fd[instance_no], SHMEM_IOCDORBELL, local_rr_int_no[instance_no]);
        }
        if (epoll_ctl(epollfd[instance_no], EPOLL_CTL_DEL, events[n].data.fd, NULL) == -1) {
          ERROR("epoll_ctl: EPOLL_CTL_DEL", "");
        }
        close(events[n].data.fd);
      } /* Handling connection close */
    }
  } /* while(1) */
  return 0;
}

void print_usage_and_exit() {
  fprintf(stderr, usage_string);
  exit(1);
}
int main(int argc, char **argv) {

  int i, res = -1;
  int instance_no;

  if (argc != 4)
    goto wrong_args;

  if (!strcmp(argv[1], "-c")) {
    run_as_server = 0;
  } else if (!strcmp(argv[1], "-s")) {
    run_as_server = 1;
  } else
    goto wrong_args;
  
  socket_path = argv[2];
  if (!strlen(socket_path))
    goto wrong_args;

  if (strlen(argv[3])) {
    instance_no = atoi(argv[3]);
    print_usage_and_exit();
  }
  else
    goto wrong_args;

  for(i = 0; i < MAX_VMS; i++) {
    my_shm_data[i] = NULL;
    peer_shm_data[i] = NULL;
  }
  fd_map_clear(instance_no);
  memset(peer_vm_id, -1, sizeof(peer_vm_id));

  epollfd[instance_no] = epoll_create1(0);
  if (epollfd[instance_no] == -1) {
    FATAL("server_init: epoll_create1");
  }

  shmem_init(instance_no);

  if (run_as_server) {
    /* Create socket that waypipe can write to
     * Add the socket fd to the epollfd
     */
    server_init(instance_no);
    peer_vm_id[instance_no] = vm_control->client_vmid;
    local_rr_int_no[instance_no] = peer_vm_id[instance_no] | (instance_no << 1) |
                      LOCAL_RESOURCE_READY_INT_VEC;
    remote_rc_int_no[instance_no] = peer_vm_id[instance_no] | (instance_no << 1) |
                       REMOTE_RESOURCE_CONSUMED_INT_VEC;
    /* Send LOGIN cmd to the client. Supply my_vmid
     *  TODO: Wait for reply?
     */
    my_shm_data[instance_no]->cmd = CMD_LOGIN;
    my_shm_data[instance_no]->fd = my_vmid;
    res = ioctl(shmem_fd[instance_no], SHMEM_IOCDORBELL,
                vm_control->client_vmid |
                    (instance_no << 1 | LOCAL_RESOURCE_READY_INT_VEC));
    DEBUG("Client #%d: sent login vmid: 0x%x res=%d peer_vm_id=0x%x", 0,
          my_vmid, res, peer_vm_id);
  }

  run(instance_no);
  return 0;

  wrong_args:
    print_usage_and_exit();
    return -1;
}
