#ifndef SECSHM_CONFIG_H
#define SECSHM_CONFIG_H

#define SHM_SLOTS 7
#define SHM_SIZE 32
#define SHM_HUGE_PAGE_SZ 2097152

struct client_entry {
  const char* name;
  int bitmask;
};

static const struct client_entry CLIENT_TABLE[] = {
    {"chrome-vm", 0x9},
  {"comms-vm", 0x12},
  {"gala-vm", 0x24},
  {"zathura-vm", 0x40},
    {"audio-vm", 0x7},
  {"gui-vm", 0x78}
};

#define CLIENT_TABLE_SIZE 6

#endif // SECSHM_CONFIG_H
