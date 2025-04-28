#ifndef MEMSOCKET_H
#define MEMSOCKET_H

#define SHM_DEVICE_FN "/dev/ivshmem"

#define MAX_EVENTS (1024)
#define MAX_FDS (100)
#define SHMEM_POLL_TIMEOUT (3000)
#define SHMEM_BUFFER_SIZE (508 * 1024)
#define UNKNOWN_PEER (-1)
#define CLOSE_FD (1)
#define IGNORE_ERROR (1)

enum {
  CMD_LOGIN,
  CMD_LOGOUT,
  CMD_CONNECT,
  CMD_DATA,
  CMD_CLOSE,
  CMD_DATA_CLOSE
};

typedef struct {
  volatile __attribute__((aligned(64))) unsigned char data[SHMEM_BUFFER_SIZE];
  volatile int vmid;
  volatile int cmd;
  volatile int fd;
  volatile int len;
  volatile int status;
} vm_data;

struct slot {
  vm_data __attribute__((aligned(64))) server;
  vm_data __attribute__((aligned(64))) client;
} __attribute__((aligned(4096)));

#define SHM_SLOT_SIZE (sizeof(struct slot))
#define DBG(fmt, ...)                                                          \
  {                                                                            \
    char tmp1[512], tmp2[256];                                                 \
    snprintf(tmp2, sizeof(tmp2), fmt, __VA_ARGS__);                            \
    snprintf(tmp1, sizeof(tmp1), "[%d] %s:%d: %s\n", slot, __FUNCTION__,       \
             __LINE__, tmp2);                                                  \
    errno = 0;                                                                 \
    report(tmp1, 0);                                                           \
  }

#ifndef DEBUG_OFF
#define DEBUG(fmt, ...)                                                        \
  {                                                                            \
  }
#else
#define DEBUG DBG
#endif

#ifndef DEBUG_ON
#define INFO(fmt, ...)                                                         \
  {                                                                            \
  }
#else
#define INFO(fmt, ...)                                                         \
  {                                                                            \
    char tmp1[512], tmp2[256];                                                 \
    snprintf(tmp2, sizeof(tmp2), fmt, __VA_ARGS__);                            \
    snprintf(tmp1, sizeof(tmp1), "[%d] [%s:%d] %s\n", slot, __FUNCTION__,      \
             __LINE__, tmp2);                                                  \
    errno = 0;                                                                 \
    report(tmp1, 0);                                                           \
  }
#endif

#define ERROR0(msg)                                                            \
  {                                                                            \
    char tmp[512];                                                             \
    snprintf(tmp, sizeof(tmp), "[%d] [%s:%d] %s\n", slot, __FUNCTION__,        \
             __LINE__, msg);                                                   \
    report(tmp, 0);                                                            \
  }

#define ERROR(fmt, ...)                                                        \
  {                                                                            \
    char tmp1[512], tmp2[256];                                                 \
    snprintf(tmp2, sizeof(tmp2), fmt, __VA_ARGS__);                            \
    snprintf(tmp1, sizeof(tmp1), "[%d] [%s:%d] %s\n", slot, __FUNCTION__,      \
             __LINE__, tmp2);                                                  \
    report(tmp1, 0);                                                           \
  }

#define FATAL(msg, ...)                                                        \
  {                                                                            \
    char tmp1[512], tmp2[256];                                                 \
                                                                               \
    if (shm) {                                                          \
      if (!run_as_client) {                                                    \
        int i;                                                                 \
        for (i = 0; i < SHM_SLOTS; i++) {                                      \
          if (client_listen_mask & 1 << i) {                                   \
            shm[i].server.vmid = 0;                               \
          }                                                                    \
        }                                                                      \
      } else {                                                                 \
        shm[slot].client.vmid = 0;                                \
      }                                                                        \
    }                                                                          \
    snprintf(tmp2, sizeof(tmp2), msg);                                         \
    snprintf(tmp1, sizeof(tmp1), "[%d] [%s:%d]: %s\n", slot, __FUNCTION__,     \
             __LINE__, tmp2);                                                  \
    report(tmp1, 1);                                                           \
  }

#endif