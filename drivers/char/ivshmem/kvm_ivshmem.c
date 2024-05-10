/* drivers/char/kvm_ivshmem.c - driver for KVM Inter-VM shared memory PCI device

* Copyright 2022-2024 TII (SSRC) and the Ghaf contributors
* SPDX-License-Identifier: Apache-2.0
*
*  Copyright 2009 Cam Macdonell <cam@cs.ualberta.ca>
*
* Based on cirrusfb.c and 8139cp.c:
*         Copyright 1999-2001 Jeff Garzik
*         Copyright 2001-2004 Jeff Garzik
*
*/

#include "kvm_ivshmem.h"
#include <linux/completion.h>
#include <linux/fcntl.h>
#include <linux/file.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/pci.h>
#include <linux/poll.h>
#include <linux/proc_fs.h>
#include <linux/uio.h>
#include <linux/version.h>

#ifndef CONFIG_KVM_IVSHMEM_VM_COUNT
#warning CONFIG_KVM_IVSHMEM_VM_COUNT not defined. Assuming 5.
#define CONFIG_KVM_IVSHMEM_VM_COUNT (5)
#endif

DEFINE_SPINLOCK(rawhide_irq_lock);
#define VM_COUNT (CONFIG_KVM_IVSHMEM_VM_COUNT)
#define VECTORS_COUNT (2 * VM_COUNT)
#define SHMEM_BUFFER_SIZE (512 * 1024)

#define DEBUG
#ifdef DEBUG
#define KVM_IVSHMEM_DPRINTK(fmt, ...)                                          \
  do {                                                                         \
    printk(KERN_INFO "KVM_IVSHMEM: " fmt "\n", ##__VA_ARGS__);                 \
  } while (0)
#else
#define KVM_IVSHMEM_DPRINTK(fmt, ...)                                          \
  {}
#endif

enum {
  /* KVM Inter-VM shared memory device register offsets */
  IntrMask = 0x00,   /* Interrupt Mask */
  IntrStatus = 0x04, /* Interrupt Status */
  IVPosition = 0x08, /* VM ID */
  Doorbell = 0x0c,   /* Doorbell */
};

static struct {
  /* Table of physical vm addresses indexed by logical vm_id */
  int vm_ids[VM_COUNT];
  struct {
    volatile __attribute__((aligned(64))) unsigned char data[SHMEM_BUFFER_SIZE];
    int data_len;
    transport_type prot_type;
  } buffer[VM_COUNT];
} *kvm_ivshmem_shared_mem;

typedef struct kvm_ivshmem_device {
  void __iomem *regs;

  void *base_addr;

  uint64_t ioaddr;
  unsigned int ioaddr_size;
  unsigned int irq;

  struct pci_dev *dev;
  char (*msix_names)[256];
  struct msix_entry *msix_entries;
  int nvectors;
  int my_vmid;
} kvm_ivshmem_device;

static int irq_incoming_data[VM_COUNT];
static int irq_ack[VM_COUNT];
static int local_resource_count[VM_COUNT];
static int peer_resource_count[VM_COUNT];
static wait_queue_head_t local_data_ready_wait_queue[VM_COUNT];
static wait_queue_head_t peer_data_ready_wait_queue[VM_COUNT];
struct completion local_transport_data_ready[VM_COUNT][PROTOCOLS_COUNT];
struct completion remote_transport_data_ready[VM_COUNT][PROTOCOLS_COUNT];

static kvm_ivshmem_device kvm_ivshmem_dev;

static long kvm_ivshmem_ioctl(struct file *, unsigned int, unsigned long);
static int kvm_ivshmem_mmap(struct file *, struct vm_area_struct *);
static int kvm_ivshmem_open(struct inode *, struct file *);
static int kvm_ivshmem_release(struct inode *, struct file *);
static ssize_t kvm_ivshmem_read(struct file *, char *, size_t, loff_t *);
static ssize_t kvm_ivshmem_write(struct file *, const char *, size_t, loff_t *);
static loff_t kvm_ivshmem_lseek(struct file *filp, loff_t offset, int origin);
static unsigned kvm_ivshmem_poll(struct file *filp,
                                 struct poll_table_struct *wait);
static int kvm_transport_init(struct file *filp, unsigned long arg);
static int kvm_transport_send(struct file *filp, unsigned long arg);
static int kvm_transport_receive(struct file *filp, unsigned long arg);
static void kvm_ivshmem_remove_device(struct pci_dev *pdev);
static int kvm_ivshmem_probe_device(struct pci_dev *pdev,
                                    const struct pci_device_id *ent);
static int copy_ioctl_data(struct ioctl_transport_data *ioctl_data,
                           unsigned long arg);

static const struct file_operations kvm_ivshmem_ops = {
    .owner = THIS_MODULE,
    .open = kvm_ivshmem_open,
    .mmap = kvm_ivshmem_mmap,
    .read = kvm_ivshmem_read,
    .unlocked_ioctl = kvm_ivshmem_ioctl,
    .write = kvm_ivshmem_write,
    .llseek = kvm_ivshmem_lseek,
    .release = kvm_ivshmem_release,
    .poll = kvm_ivshmem_poll,
};

static struct pci_device_id kvm_ivshmem_id_table[] = {
    {0x1af4, 0x1110, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0},
    {0},
};

static struct miscdevice kvm_ivshmem_misc_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "ivshmem",
    .fops = &kvm_ivshmem_ops,
};

static uint64_t flataddr = 0x0;
unsigned int vm_id = 3;
module_param_named(flataddr, flataddr, ullong, S_IRUGO);
#ifdef MODULE
module_param(vm_id, int, S_IRUGO);
#else
module_param_named(vm_id, vm_id, int, S_IRUGO);
#endif
// TODO: debug
static int in_counter = 0, out_counter = 0;

MODULE_DEVICE_TABLE(pci, kvm_ivshmem_id_table);

static struct pci_driver kvm_ivshmem_pci_driver = {
    .name = "kvm-shmem",
    .id_table = kvm_ivshmem_id_table,
    .probe = kvm_ivshmem_probe_device,
    .remove = kvm_ivshmem_remove_device,
};

static int copy_ioctl_data(struct ioctl_transport_data *ioctl_data,
                           unsigned long arg) {
  if (copy_from_user(ioctl_data, (void __user *)arg, sizeof(*ioctl_data)))
    return -EINVAL;

  if (ioctl_data->peer_vm_id >= VM_COUNT ||
      ioctl_data->type >= PROTOCOLS_COUNT) {
    printk(KERN_ERR "KVM_IVSHMEM: invalid data: vm_id=%d protocol type=%d",
           ioctl_data->peer_vm_id, ioctl_data->type);
    return -EINVAL;
  }

  return 0;
}

static int kvm_transport_init(struct file *filp, unsigned long arg) {
  int i, n;

  KVM_IVSHMEM_DPRINTK(KERN_ERR "KVM_IVSHMEM: My vm_id=%d", vm_id);
  if (vm_id >= VM_COUNT) {
    printk(KERN_ERR "KVM_IVSHMEM: vm_id (%d) exceeds VM_COUNT (%d)", vm_id,
           VM_COUNT);
    return -EINVAL;
  }

  if (sizeof(*kvm_ivshmem_shared_mem) > kvm_ivshmem_dev.ioaddr_size) {
    printk(
        KERN_ERR
        "KVM_IVSHMEM: To small shared memory area: %d bytes. Need %ld bytes.",
        kvm_ivshmem_dev.ioaddr_size, sizeof(*kvm_ivshmem_shared_mem));
    return -ENOMEM;
  }
  kvm_ivshmem_shared_mem = kvm_ivshmem_dev.base_addr;
  kvm_ivshmem_shared_mem->vm_ids[vm_id] = kvm_ivshmem_dev.my_vmid;

  KVM_IVSHMEM_DPRINTK(KERN_ERR
                      "KVM_IVSHMEM: logical vm_id=%d physical vm_id=%d",
                      vm_id, kvm_ivshmem_shared_mem->vm_ids[vm_id]);
  KVM_IVSHMEM_DPRINTK(KERN_ERR "Used %ld MB out of %d MB",
                      sizeof(*kvm_ivshmem_shared_mem) / (1024 * 1024),
                      kvm_ivshmem_dev.ioaddr_size / (1024 * 1024));
  for (i = 0; i < VM_COUNT; i++)
    for (n = 0; n < PROTOCOLS_COUNT; n++) {
      init_completion(&local_transport_data_ready[i][n]);
      init_completion(&remote_transport_data_ready[i][n]);
      complete(&local_transport_data_ready[i][n]);
    }
  return 0;
}

static int kvm_transport_send(struct file *filp, unsigned long arg) {

  struct ioctl_transport_data ioctl_data;
  unsigned int interrupt;
  int ret;

  if (copy_ioctl_data(&ioctl_data, arg)) {
    printk(KERN_ERR "KVM_IVSHMEM: SHMEM_IOCSEND: invalid argument 0x%lx", arg);
    return -EINVAL;
  }
  if (ioctl_data.length > SHMEM_BUFFER_SIZE) {
    printk(KERN_ERR
           "KVM_IVSHMEM: SHMEM_IOCSEND: invalid data length %d (max %d)",
           ioctl_data.length, SHMEM_BUFFER_SIZE);
    return -EINVAL;
  }
  if (ioctl_data.peer_vm_id == vm_id) {
    printk(KERN_ERR "KVM_IVSHMEM: SHMEM_IOCSEND: self vm id");
    return -EINVAL;
  }
  KVM_IVSHMEM_DPRINTK("Waiting for local_transport_data_ready");
  ret = wait_for_completion_interruptible(
      &local_transport_data_ready[ioctl_data.peer_vm_id][ioctl_data.type]);
  if (ret)
    return -EINTR;

  /* Wait for the common buffer to be free and lock it */
  ret = wait_event_interruptible(
      local_data_ready_wait_queue[ioctl_data.peer_vm_id],
      local_resource_count[ioctl_data.peer_vm_id]);
  if (ret)
    return -EINTR;

  spin_lock(&rawhide_irq_lock);
  local_resource_count[ioctl_data.peer_vm_id] = 0;
  spin_unlock(&rawhide_irq_lock);

  kvm_ivshmem_shared_mem->buffer[vm_id].prot_type = ioctl_data.type;
  kvm_ivshmem_shared_mem->buffer[vm_id].data_len = ioctl_data.length;
  if (copy_from_user((void *)&kvm_ivshmem_shared_mem->buffer[vm_id].data[0],
                     (void __user *)ioctl_data.data, ioctl_data.length)) {
    printk(KERN_ERR "KVM_IVSHMEM: SHMEM_IOCSEND: invalid ioctl data pointer %p",
           ioctl_data.data);

    return -EINVAL;
  }

  interrupt = kvm_ivshmem_shared_mem->vm_ids[ioctl_data.peer_vm_id] << 16 |
              (vm_id << 1 | LOCAL_RESOURCE_READY_INT_VEC);
  KVM_IVSHMEM_DPRINTK(KERN_ERR "KVM_IVSHMEM: raising interrupt 0x%x",
                      interrupt);
  writel(interrupt, kvm_ivshmem_dev.regs + Doorbell);

  return 0;
}

static int kvm_transport_receive(struct file *filp, unsigned long arg) {

  struct ioctl_transport_data ioctl_data;
  int ret = 0, data_length;
  int interrupt;

  if (copy_ioctl_data(&ioctl_data, arg)) {
    printk(KERN_ERR "KVM_IVSHMEM: SHMEM_IOCTRCV: invalid argument 0x%lx", arg);
    return -EINVAL;
  }
  if (ioctl_data.peer_vm_id == vm_id) {
    printk(KERN_ERR "KVM_IVSHMEM: SHMEM_IOCRCV: self vm id");
    return -EINVAL;
  }

  /* Wait for the common buffer to be received */
  ret = wait_event_interruptible(
      peer_data_ready_wait_queue[ioctl_data.peer_vm_id],
      peer_resource_count[ioctl_data.peer_vm_id]);
  if (ret)
    return -EINTR;

  spin_lock(&rawhide_irq_lock);
  peer_resource_count[ioctl_data.peer_vm_id] = 0;
  spin_unlock(&rawhide_irq_lock);

  KVM_IVSHMEM_DPRINTK("Waiting for remote_transport_data_ready. peer_vm_id=%d",
                      ioctl_data.peer_vm_id);
  ret = wait_for_completion_interruptible(
      &remote_transport_data_ready[ioctl_data.peer_vm_id][ioctl_data.type]);
  if (ret)
    return -EINTR;

  /* Copy the received data */
  data_length =
      min(kvm_ivshmem_shared_mem->buffer[ioctl_data.peer_vm_id].data_len,
          ioctl_data.length);
  if (copy_to_user(
          (void __user *)ioctl_data.data,
          (void *)&kvm_ivshmem_shared_mem->buffer[ioctl_data.peer_vm_id]
              .data[0],
          data_length)) {
    printk(KERN_ERR "KVM_IVSHMEM: SHMEM_IOCSEND: invalid ioctl data pointer %p",
           ioctl_data.data);

    ret = -EINVAL;
  } else {
    ret = data_length;
  }

  /* Send interrupt to the peer vm that the common buffer can be released */
  interrupt = kvm_ivshmem_shared_mem->vm_ids[ioctl_data.peer_vm_id] << 16 |
              (vm_id << 1 | PEER_RESOURCE_CONSUMED_INT_VEC);
  KVM_IVSHMEM_DPRINTK(KERN_ERR "KVM_IVSHMEM: raising interrupt 0x%x",
                      interrupt);
  writel(interrupt, kvm_ivshmem_dev.regs + Doorbell);

  return ret;
}

static long kvm_ivshmem_ioctl(struct file *filp, unsigned int cmd,
                              unsigned long arg) {

  int rv = 0;
  unsigned long flags;
  uint32_t msg;
  struct ioctl_data ioctl_data;

  KVM_IVSHMEM_DPRINTK("%ld ioctl: cmd=0x%x args is 0x%lx",
                      (unsigned long int)filp->private_data, cmd, arg);
  if ((unsigned long int)filp->private_data >= VM_COUNT &&
      cmd != SHMEM_IOCSETINSTANCENO) {
    printk(KERN_ERR "KVM_IVSHMEM: ioctl: invalid instance id %ld > VM_COUNT=%d",
           (unsigned long int)filp->private_data, VM_COUNT);
    return -EINVAL;
  }
  switch (cmd) {
  case SHMEM_IOCIVPOSN:
    msg = kvm_ivshmem_dev.my_vmid;
    KVM_IVSHMEM_DPRINTK("%ld my vmid is 0x%08x",
                        (unsigned long int)filp->private_data, msg);
    rv = copy_to_user((void __user *)arg, &msg, sizeof(msg));
    break;

  case SHMEM_IOCDORBELL:
    unsigned int vec;

    if (copy_from_user(&ioctl_data, (void __user *)arg, sizeof(ioctl_data))) {
      printk(KERN_ERR
             "KVM_IVSHMEM: SHMEM_IOCDORBELL: %ld invalid argument 0x%lx",
             (unsigned long int)filp->private_data, arg);
      rv = -EINVAL;
      break;
    }

    vec = ioctl_data.int_no & 0xffff;
#ifdef DEBUG_IOCTL
    KVM_IVSHMEM_DPRINTK("%ld ioctl cmd=%d fd=%d len=%d int_no=0x%x",
                        (unsigned long int)filp->private_data, ioctl_data.cmd,
                        ioctl_data.fd, ioctl_data.len, ioctl_data.int_no);
#endif
    KVM_IVSHMEM_DPRINTK("%ld ringing doorbell id=0x%x on vector 0x%x",
                        (unsigned long int)filp->private_data,
                        (ioctl_data.int_no >> 16), vec);
    spin_lock_irqsave(&rawhide_irq_lock, flags);
    if (vec & LOCAL_RESOURCE_READY_INT_VEC) {
      local_resource_count[(unsigned long int)filp->private_data] = 0;
    } else {
      peer_resource_count[(unsigned long int)filp->private_data] = 0;
    }
    spin_unlock_irqrestore(&rawhide_irq_lock, flags);
    writel(ioctl_data.int_no, kvm_ivshmem_dev.regs + Doorbell);
    break;

  case SHMEM_IOCSET:
    spin_lock_irqsave(&rawhide_irq_lock, flags);
    if ((arg >> 8) == LOCAL_RESOURCE_READY_INT_VEC)
      local_resource_count[(unsigned long int)filp->private_data] = arg & 0xff;
    else if ((arg >> 8) == PEER_RESOURCE_CONSUMED_INT_VEC)
      peer_resource_count[(unsigned long int)filp->private_data] = arg & 0xff;
    else {
      rv = -EINVAL;
      printk(KERN_ERR "KVM_IVSHMEM: SHMEM_IOCSET: invalid arg %ld", arg);
    }
    spin_unlock_irqrestore(&rawhide_irq_lock, flags);
    break;

  case SHMEM_IOCSETINSTANCENO:
    spin_lock_irqsave(&rawhide_irq_lock, flags);
    if (arg >= VM_COUNT) {
      printk(KERN_ERR "KVM_IVSHMEM: ioctl: invalid instance id %ld", arg);
      rv = -EINVAL;
      goto unlock;
    }
    filp->private_data = (void *)arg;
    KVM_IVSHMEM_DPRINTK(
        KERN_INFO "KVM_IVSHMEM: SHMEM_IOCSETINSTANCENO: set instance id 0x%lx",
        arg);

    init_waitqueue_head(&local_data_ready_wait_queue[arg]);
    init_waitqueue_head(&peer_data_ready_wait_queue[arg]);
    local_resource_count[arg] = 1;
    peer_resource_count[arg] = 0;
  unlock:
    spin_unlock_irqrestore(&rawhide_irq_lock, flags);
    break;

  case SHMEM_IOCTINI:
    rv = kvm_transport_init(filp, arg);
    break;

  case SHMEM_IOCTSEND:
    rv = kvm_transport_send(filp, arg);
    break;

  case SHMEM_IOCTRCV:
    rv = kvm_transport_receive(filp, arg);
    break;

  case SHMEM_IOCNOP:
    unsigned int tmp;

    if (copy_from_user(&tmp, (void __user *)arg, sizeof(tmp))) {
      printk(KERN_ERR "KVM_IVSHMEM: SHMEM_IOCWLOCAL: %ld invalid argument",
             (unsigned long int)filp->private_data);
    }
    KVM_IVSHMEM_DPRINTK(
        "%ld %x local %d counter=%d: peer:%d counter=%d",
        (unsigned long int)filp->private_data, tmp,
        local_resource_count[(unsigned long int)filp->private_data], in_counter,
        peer_resource_count[(unsigned long int)filp->private_data],
        out_counter);

    tmp = ((unsigned)out_counter) << 16 | (unsigned)(in_counter & 0xffff);
    rv = copy_to_user((void __user *)arg, &tmp, sizeof(tmp));
    break;

  default:
    KVM_IVSHMEM_DPRINTK("%ld bad ioctl (0x%08x)",
                        (unsigned long int)filp->private_data, cmd);
    return -EINVAL;
  }

  return rv;
}

static unsigned kvm_ivshmem_poll(struct file *filp,
                                 struct poll_table_struct *wait) {
  __poll_t mask = 0;
  __poll_t req_events = poll_requested_events(wait);

  if (req_events & EPOLLIN) {
    poll_wait(
        filp,
        &peer_data_ready_wait_queue[(unsigned long int)filp->private_data],
        wait);

    if (peer_resource_count[(unsigned long int)filp->private_data]) {
      KVM_IVSHMEM_DPRINTK(
          "%ld poll: in: peer_resource_count=%d",
          (unsigned long int)filp->private_data,
          peer_resource_count[(unsigned long int)filp->private_data]);
      mask |= (POLLIN | POLLRDNORM);
    }
  }

  if (req_events & EPOLLOUT) {
    poll_wait(
        filp,
        &local_data_ready_wait_queue[(unsigned long int)filp->private_data],
        wait);

    if (local_resource_count[(unsigned long int)filp->private_data]) {
      KVM_IVSHMEM_DPRINTK(
          "%ld poll: out: local_resource_count=%d",
          (unsigned long int)filp->private_data,
          local_resource_count[(unsigned long int)filp->private_data]);

      mask |= (POLLOUT | POLLWRNORM);
    }
  }

#ifdef DEBUG
  if (!mask) {
    printk(KERN_ERR "KVM_IVSHMEM: poll: timeout: query for events 0x%x",
           req_events);
  }
#endif
  return mask;
}

static ssize_t kvm_ivshmem_read(struct file *filp, char *buffer, size_t len,
                                loff_t *poffset) {

  int bytes_read = 0;
  unsigned long offset;

  offset = *poffset;

  if (!kvm_ivshmem_dev.base_addr) {
    printk(KERN_ERR "KVM_IVSHMEM: cannot read from ioaddr (NULL)");
    return 0;
  }

  if (len > kvm_ivshmem_dev.ioaddr_size - offset) {
    len = kvm_ivshmem_dev.ioaddr_size - offset;
  }

  if (len == 0)
    return 0;

  bytes_read =
      copy_to_user(buffer, (void *)kvm_ivshmem_dev.base_addr + offset, len);
  if (bytes_read > 0) {
    return -EFAULT;
  }

  *poffset += len;
  return len;
}

static loff_t kvm_ivshmem_lseek(struct file *filp, loff_t offset, int origin) {

  loff_t retval = -1;

  switch (origin) {
  case SEEK_CUR:
    offset += filp->f_pos;
    __attribute__((__fallthrough__));
  case SEEK_SET:
    retval = offset;
    if (offset > kvm_ivshmem_dev.ioaddr_size) {
      offset = kvm_ivshmem_dev.ioaddr_size;
    }
    filp->f_pos = offset;
    break;
  case SEEK_END:
    retval = kvm_ivshmem_dev.ioaddr_size;
    filp->f_pos = kvm_ivshmem_dev.ioaddr_size;
  }

  return retval;
}

static ssize_t kvm_ivshmem_write(struct file *filp, const char *buffer,
                                 size_t len, loff_t *poffset) {

  int bytes_written = 0;
  unsigned long offset;

  offset = *poffset;

  KVM_IVSHMEM_DPRINTK("%ld KVM_IVSHMEM: trying to write",
                      (unsigned long int)filp->private_data);
  if (!kvm_ivshmem_dev.base_addr) {
    printk(KERN_ERR "KVM_IVSHMEM: %ld cannot write to ioaddr (NULL)",
           (unsigned long int)filp->private_data);
    return 0;
  }

  if (len > kvm_ivshmem_dev.ioaddr_size - offset) {
    len = kvm_ivshmem_dev.ioaddr_size - offset;
  }

  KVM_IVSHMEM_DPRINTK("%ld KVM_IVSHMEM: len is %u",
                      (unsigned long int)filp->private_data, (unsigned)len);
  if (len == 0)
    return 0;

  bytes_written =
      copy_from_user((void *)kvm_ivshmem_dev.base_addr + offset, buffer, len);
  if (bytes_written > 0) {
    return -EFAULT;
  }

  KVM_IVSHMEM_DPRINTK("%ld KVM_IVSHMEM: wrote %u bytes at offset %lu",
                      (unsigned long int)filp->private_data, (unsigned)len,
                      offset);
  *poffset += len;
  return len;
}
// TODO: temporary debug
// #define DEBUG
#undef DEBUG
#define DEBUG
#undef KVM_IVSHMEM_DPRINTK
#ifdef DEBUG
#define KVM_IVSHMEM_DPRINTK(fmt, ...)                                          \
  do {                                                                         \
    printk(KERN_INFO "KVM_IVSHMEM: " fmt "\n", ##__VA_ARGS__);                 \
  } while (0)
#else
#define KVM_IVSHMEM_DPRINTK(fmt, ...)                                          \
  {}
#endif

static irqreturn_t kvm_ivshmem_interrupt(int irq, void *dev_instance) {
  struct kvm_ivshmem_device *dev = dev_instance;
  transport_type type;
  int i;

  if (unlikely(dev == NULL)) {
    KVM_IVSHMEM_DPRINTK("return IRQ_NONE");
    return IRQ_NONE;
  }

  KVM_IVSHMEM_DPRINTK("irq %d", irq);
  for (i = 0; i < VM_COUNT; i++) {
    if (irq == irq_incoming_data[i]) {
      out_counter++;
      type = kvm_ivshmem_shared_mem->buffer[i].prot_type;
      KVM_IVSHMEM_DPRINTK(
          "%d wake up peer_data_ready_wait_queue count=%d type=%d 0x%lx", i,
          out_counter, type,
          (unsigned long)&kvm_ivshmem_shared_mem->buffer[vm_id].prot_type -
              (unsigned long)kvm_ivshmem_shared_mem);
      if (peer_resource_count[i]) {
        KVM_IVSHMEM_DPRINTK("%d WARNING: peer_resource_count>0!: %d", i,
                            peer_resource_count[i]);
      }
      spin_lock(&rawhide_irq_lock);
      peer_resource_count[i] = 1;
      spin_unlock(&rawhide_irq_lock);
      wake_up_interruptible(&peer_data_ready_wait_queue[i]);
      if (type < PROTOCOLS_COUNT)
        complete(&remote_transport_data_ready[i][type]);
      else
        printk(KERN_ERR "KVM_IVSHMEM: irq %d invalid protocol type %d", irq,
               type);
      return IRQ_HANDLED;
    }
    if (irq == irq_ack[i]) {
      in_counter++;
      type = kvm_ivshmem_shared_mem->buffer[vm_id].prot_type;
      KVM_IVSHMEM_DPRINTK(
          "%d wake up local_data_ready_wait_queue count=%d type=%d vm_id=%d", i,
          in_counter, type, vm_id);
      if (local_resource_count[i]) {
        KVM_IVSHMEM_DPRINTK("%d WARNING: local_resource_count>0!: %d", i,
                            local_resource_count[i]);
      }
      spin_lock(&rawhide_irq_lock);
      local_resource_count[i] = 1;
      spin_unlock(&rawhide_irq_lock);
      wake_up_interruptible(&local_data_ready_wait_queue[i]);
      if (type < PROTOCOLS_COUNT)
        complete(&local_transport_data_ready[i][type]);
      else
        printk(KERN_ERR "KVM_IVSHMEM: irq %d invalid protocol type %d", irq,
               type);

      return IRQ_HANDLED;
    }
  }

  printk(KERN_ERR "KVM_IVSHMEM: irq %d not handled", irq);
  return IRQ_NONE;
}

#undef DEBUG
#undef KVM_IVSHMEM_DPRINTK
#ifdef DEBUG
#define KVM_IVSHMEM_DPRINTK(fmt, ...)                                          \
  do {                                                                         \
    printk(KERN_INFO "KVM_IVSHMEM: " fmt "\n", ##__VA_ARGS__);                 \
  } while (0)
#else
#define KVM_IVSHMEM_DPRINTK(fmt, ...)                                          \
  {}
#endif

static int request_msix_vectors(struct kvm_ivshmem_device *ivs_info,
                                int nvectors) {
  int i, n, err;
  const char *name = "ivshmem";

  KVM_IVSHMEM_DPRINTK("KVM_IVSHMEM: devname is %s", name);
  ivs_info->nvectors = nvectors;

  ivs_info->msix_entries =
      kmalloc(nvectors * sizeof *ivs_info->msix_entries, GFP_KERNEL);
  ivs_info->msix_names =
      kmalloc(nvectors * sizeof *ivs_info->msix_names, GFP_KERNEL);

  for (i = 0; i < nvectors; i++)
    ivs_info->msix_entries[i].entry = i;

  n = pci_alloc_irq_vectors(ivs_info->dev, nvectors, nvectors, PCI_IRQ_MSIX);
  if (n < 0) {
    printk(KERN_ERR "KVM_IVSHMEM: pci_alloc_irq_vectors i=%d: error %d", i, n);
    return n;
  }

  for (i = 0; i < nvectors; i++) {

    snprintf(ivs_info->msix_names[i], sizeof *ivs_info->msix_names, "%s-config",
             name);

    n = pci_irq_vector(ivs_info->dev, i);
    err = request_irq(n, kvm_ivshmem_interrupt, IRQF_SHARED,
                      ivs_info->msix_names[i], ivs_info);

    if (err) {
      printk(KERN_ERR "KVM_IVSHMEM: couldn't allocate irq for msi-x entry %d "
                      "with vector %d",
             i, n);
      return -ENOSPC;
    } else {
      printk(KERN_INFO "KVM_IVSHMEM: allocated irq #%d", n);
    }
    // vector 1 is used for data sending
    if (i & LOCAL_RESOURCE_READY_INT_VEC) {
      irq_incoming_data[i >> 1] = n;
      KVM_IVSHMEM_DPRINTK("Using interrupt #%d for incoming data for vm %d", n,
                          i >> 1);
      // vector 0 is used for for sending acknowledgments
    } else {
      irq_ack[i >> 1] = n;
      KVM_IVSHMEM_DPRINTK("Using interrupt #%d for ACKs for vm %d", n, i >> 1);
    }
  }

  pci_set_master(ivs_info->dev);
  return 0;
}

static int kvm_ivshmem_probe_device(struct pci_dev *pdev,
                                    const struct pci_device_id *ent) {

  int result;

  KVM_IVSHMEM_DPRINTK("Probing for KVM_IVSHMEM Device");

  result = pci_enable_device(pdev);
  if (result) {
    printk(KERN_ERR "KVM_IVSHMEM: Cannot probe KVM_IVSHMEM device %s: error %d",
           pci_name(pdev), result);
    return result;
  }

  result = pci_request_regions(pdev, "kvm_ivshmem");
  if (result < 0) {
    printk(KERN_ERR "KVM_IVSHMEM: cannot request regions");
    goto pci_disable;
  } else
    printk(KERN_ERR "KVM_IVSHMEM: pci_request_regions(): result is %d", result);

  kvm_ivshmem_dev.ioaddr = pci_resource_start(pdev, 2);
  kvm_ivshmem_dev.ioaddr_size = pci_resource_len(pdev, 2);

  if (flataddr) {
    kvm_ivshmem_dev.base_addr =
        memremap(flataddr, kvm_ivshmem_dev.ioaddr_size, MEMREMAP_WB);
    printk(KERN_ERR "KVM_IVSHMEM: using flat memory 0x%llx mapped to %p",
           flataddr, kvm_ivshmem_dev.base_addr);
  } else {
    kvm_ivshmem_dev.base_addr = pci_iomap(pdev, 2, 0);
    printk(KERN_INFO "KVM_IVSHMEM: using PCI iomap base = 0x%p",
           kvm_ivshmem_dev.base_addr);
  }

  if (!kvm_ivshmem_dev.base_addr) {
    printk(KERN_ERR "KVM_IVSHMEM: cannot map region size %d",
           kvm_ivshmem_dev.ioaddr_size);
    goto pci_release;
  }

  printk(KERN_INFO "KVM_IVSHMEM: ioaddr = 0x%llx ioaddr_size = 0x%x base_addr "
                   "= %p flataddr = 0x%llx",
         kvm_ivshmem_dev.ioaddr, kvm_ivshmem_dev.ioaddr_size,
         kvm_ivshmem_dev.base_addr, flataddr);

  /* Clear the the shared memory is it really needed? */
  // memset_io(kvm_ivshmem_dev.base_addr, kvm_ivshmem_dev.ioaddr_size, 0);

  kvm_ivshmem_dev.regs = pci_iomap(pdev, 0, 0x100);
  kvm_ivshmem_dev.dev = pdev;

  if (!kvm_ivshmem_dev.regs) {
    goto reg_release;
  }

  if (request_msix_vectors(&kvm_ivshmem_dev, VECTORS_COUNT) != 0) {
    printk(KERN_ERR
           "KVM_IVSHMEM: Check ivshmem and qemu configured interrupts number");
    goto reg_release;
  } else {
    printk(KERN_INFO "KVM_IVSHMEM: MSI-X enabled");
  }

  /* set all masks to on */
  writel(0xffffffff, kvm_ivshmem_dev.regs + IntrMask);
  kvm_ivshmem_dev.my_vmid = readl(kvm_ivshmem_dev.regs + IVPosition);

  return 0;

reg_release:
  if (!flataddr)
    pci_iounmap(pdev, kvm_ivshmem_dev.base_addr);
pci_release:
  pci_release_regions(pdev);
  if (flataddr)
    memunmap(kvm_ivshmem_dev.base_addr);
pci_disable:
  pci_disable_device(pdev);
  return -EBUSY;
}

static void kvm_ivshmem_remove_device(struct pci_dev *pdev) {
  int i, n;

  printk(KERN_INFO "KVM_IVSHMEM: Unregister kvm_ivshmem device.");
  for (i = 0; i < VECTORS_COUNT; i++) {
    n = pci_irq_vector(pdev, i);
    KVM_IVSHMEM_DPRINTK("Freeing irq# %d", n);
    disable_irq(n);
    free_irq(n, &kvm_ivshmem_dev);
  }
  pci_free_irq_vectors(pdev);
  pci_iounmap(pdev, kvm_ivshmem_dev.regs);
  pci_iounmap(pdev, kvm_ivshmem_dev.base_addr);
  pci_release_regions(pdev);
  pci_disable_device(pdev);
}

static void __exit kvm_ivshmem_cleanup_module(void) {
  pci_unregister_driver(&kvm_ivshmem_pci_driver);
  misc_deregister(&kvm_ivshmem_misc_dev);
}

static int __init kvm_ivshmem_init_module(void) {

  int err = -ENOMEM, i;

  /* Register device node ops. */
  err = misc_register(&kvm_ivshmem_misc_dev);
  if (err < 0) {
    printk(KERN_ERR "KVM_IVSHMEM: Unable to register kvm_ivshmem_misc device");
    return err;
  }
  KVM_IVSHMEM_DPRINTK("Registered the /dev/%s device ",
                      kvm_ivshmem_misc_dev.name);

  err = pci_register_driver(&kvm_ivshmem_pci_driver);
  if (err < 0) {
    goto error;
  }

  for (i = 0; i < VM_COUNT; i++) {
    init_waitqueue_head(&local_data_ready_wait_queue[i]);
    init_waitqueue_head(&peer_data_ready_wait_queue[i]);
    local_resource_count[i] = 1;
    peer_resource_count[i] = 0;
  }
  return 0;

error:
  misc_deregister(&kvm_ivshmem_misc_dev);
  return err;
}

static int kvm_ivshmem_open(struct inode *inode, struct file *filp) {
  printk(KERN_INFO "KVM_IVSHMEM: Opening kvm_ivshmem device. Using memory @ %p",
         kvm_ivshmem_dev.base_addr);
  filp->private_data = (void *)(unsigned long)-1;
  return 0;
}

static int kvm_ivshmem_release(struct inode *inode, struct file *filp) {
  return 0;
}

static int kvm_ivshmem_mmap(struct file *filp, struct vm_area_struct *vma) {

  unsigned long len;
  unsigned long off;
  uint64_t start;

  off = vma->vm_pgoff << PAGE_SHIFT;
  start = flataddr ? flataddr : (uint64_t)kvm_ivshmem_dev.ioaddr;

  len = PAGE_ALIGN((start & ~PAGE_MASK) + kvm_ivshmem_dev.ioaddr_size);
  start &= PAGE_MASK;

  printk(KERN_INFO
         "KVM_IVSHMEM: mmap: vma->vm_start=0x%lx vma->vm_end=0x%lx off=0x%lx",
         vma->vm_start, vma->vm_end, off);
  printk(
      KERN_INFO
      "KVM_IVSHMEM: mmap: vma->vm_end - vma->vm_start + off=0x%lx > len=0x%lx",
      (vma->vm_end - vma->vm_start + off), len);

  if ((vma->vm_end - vma->vm_start + off) > len)
    return -EINVAL;

  off += start;
  vma->vm_pgoff = off >> PAGE_SHIFT;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
  vm_flags_mod(vma, VM_SHARED, 0);
#else
  vma->vm_flags |= VM_SHARED;
#endif

  if (io_remap_pfn_range(vma, vma->vm_start, off >> PAGE_SHIFT,
                         vma->vm_end - vma->vm_start, vma->vm_page_prot)) {
    KVM_IVSHMEM_DPRINTK("%ld mmap failed",
                        (unsigned long int)filp->private_data);
    return -ENXIO;
  }

  return 0;
}

module_init(kvm_ivshmem_init_module);
module_exit(kvm_ivshmem_cleanup_module);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Cam Macdonell <cam@cs.ualberta.ca>");
MODULE_DESCRIPTION("KVM inter-VM shared memory module");
MODULE_VERSION("1.0");
