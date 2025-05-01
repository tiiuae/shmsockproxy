#include "./secshm_config.h"
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#define DEVICE_NAME "ivshmem"

static void *kernel_buffer; // Allocated memory
static loff_t secshm_lseek(struct file *filp, loff_t offset, int origin);
static const struct inode_operations secshm_inode_ops;

// Open function
static int secshm_open(struct inode *inode, struct file *filp) {
    inode->i_op = &secshm_inode_ops;  // Override default i_op
    printk(KERN_INFO "secshm: Opened\n");
    return 0;
}
// static int secshm_getattr(struct inode *inode, struct file *file)
// {
//     struct kstat *stat = file->f_path.dentry->d_inode->i_mapping->host;
//     printk(KERN_INFO "secshm: getattr called\n");
//     stat->size = SHM_SIZE;
//     return 0;
// }
// Getter for file attributes, including size
static int secshm_getattr(struct mnt_idmap *, const struct path *path, 
    struct kstat *stat, u32 request_mask,  unsigned int query_flags)

{
  printk(KERN_INFO "secshm: getattr called\n");
  int ret = vfs_getattr(path, stat, request_mask, query_flags);
  if (ret)
    return ret;

  // Set the size of the shared memory region
  stat->size = SHM_SIZE;

  printk(KERN_INFO "secshm: getattr called, size set to %lld\n", SHM_SIZE);
  return 0;
}
// Lseek function
static loff_t secshm_lseek(struct file *filp, loff_t offset, int origin) {
  loff_t newpos;

  switch (origin) {
  case 0: // SEEK_SET
    newpos = offset;
    break;
  case 1: // SEEK_CUR
    newpos = filp->f_pos + offset;
    break;
  case 2: // SEEK_END
    newpos = SHM_SIZE - offset;
    break;
  default:
    return -EINVAL;
  }

  if (newpos < 0 || newpos > SHM_SIZE) {
    return -EINVAL;
  }

  filp->f_pos = newpos;
  return newpos;
}

// mmap implementation
static int secshm_mmap(struct file *filp, struct vm_area_struct *vma) {
  struct page *page;
  unsigned long pfn;

  page = virt_to_page(kernel_buffer);
  pfn = page_to_pfn(page);

  if (remap_pfn_range(vma, vma->vm_start, pfn, vma->vm_end - vma->vm_start,
                      vma->vm_page_prot)) {
    return -EIO;
  }

  printk(KERN_INFO "secshm: Memory mapped successfully\n");
  return 0;
}

// File operations structure
static struct file_operations secshm_fops = {
    .owner = THIS_MODULE,
    .open = secshm_open,
    .llseek = secshm_lseek,
    .mmap = secshm_mmap,
};

// Misc device structure
static struct miscdevice secshm_device = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = DEVICE_NAME,
    .fops = &secshm_fops,
};

static const struct inode_operations secshm_inode_ops = {
    .getattr = secshm_getattr,
};

// Module initialization
static int __init secshm_init(void) {
  // Allocate kernel memory for shared memory region
  kernel_buffer = kmalloc(SHM_SIZE, GFP_KERNEL);
  if (!kernel_buffer) {
    printk(KERN_ERR "secshm: Failed to allocate memory\n");
    return -ENOMEM;
  }

  // Register the misc device
  int ret = misc_register(&secshm_device);
  if (ret) {
    printk(KERN_ERR "secshm: Failed to register misc device\n");
    kfree(kernel_buffer);
    return ret;
  }

  printk(KERN_INFO "secshm: Module loaded and misc device registered\n");
  return 0;
}

// Module cleanup
static void __exit secshm_exit(void) {
  misc_deregister(&secshm_device);
  kfree(kernel_buffer);
  printk(KERN_INFO "secshm: Module unloaded\n");
}

module_init(secshm_init);
module_exit(secshm_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jaroslaw Kurowski");
MODULE_DESCRIPTION("Shared memory device driver");
