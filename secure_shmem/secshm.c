#include "./secshm_config.h"
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/hugetlb.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#define DEVICE_NAME "ivshmem"

static loff_t secshm_lseek(struct file *filp, loff_t offset, int origin);
static const struct inode_operations secshm_inode_ops;
static struct page **huge_pages; // Array to hold allocated hugepages
static unsigned int num_pages;   // Number of pages to allocate

// Allocate hugepages
static int allocate_hugepages(void) {
  num_pages = SHM_SIZE / (PAGE_SIZE * 512); // 2MB per hugepage
  huge_pages = kmalloc(num_pages * sizeof(struct page *), GFP_KERNEL);
  if (!huge_pages) {
    printk(KERN_ERR "Failed to allocate hugepage array\n");
    return -ENOMEM;
  }
  printk(KERN_INFO
         "Allocating %d pages HUGETLB_PAGE_ORDER=%d get_order(SHM_SIZE)=%d\n",
         num_pages, HUGETLB_PAGE_ORDER,
         get_order(SHM_SIZE)); // jarekk: TODO delete
  // Allocate each hugepage
  for (unsigned int i = 0; i < num_pages; i++) {
    huge_pages[i] =
        alloc_pages(GFP_KERNEL | __GFP_ZERO | __GFP_COMP, HPAGE_PMD_ORDER);
    printk(KERN_INFO "Allocated page %u at %p HPAGE_PMD_ORDER=%d\n", i,
           huge_pages[i], HPAGE_PMD_ORDER); // jarekk: TODO delete
    if (!huge_pages[i]) {
      printk(KERN_ERR "Failed to allocate hugepage %u\n", i);
      // Free previously allocated pages
      for (unsigned int j = 0; j < i; j++) {
        __free_pages(huge_pages[j], HUGETLB_PAGE_ORDER);
      }
      kfree(huge_pages);
      return -ENOMEM;
    }
  }

  return 0;
}

// Free allocated hugepages
static void free_hugepages(void) {
  for (unsigned int i = 0; i < num_pages; i++) {
    if (huge_pages[i]) {
      __free_pages(huge_pages[i], HPAGE_PMD_ORDER);
    }
  }
  kfree(huge_pages);
}

// Open function
static int secshm_open(struct inode *inode, struct file *filp) {
  printk(KERN_INFO "secshm: open: inode=%p, filp=%p\n", inode, filp); // jarekk: TODO delete
  if (inode) // jarekk: TODO: remove
    inode->i_op = &secshm_inode_ops; // Override default i_op
  printk(KERN_INFO "secshm: Opened.\n");
  return 0;
}

static int secshm_getattr(struct mnt_idmap *idmap, const struct path *path,
                          struct kstat *stat, u32 request_mask,
                          unsigned int query_flags)

{
  struct inode *inode = path->dentry->d_inode;
  printk(KERN_INFO "secshm: getattr called\n");
  // Get basic attributes from the generic implementation
  generic_fillattr(idmap, request_mask, inode, stat);
  // Override the size with our shared memory size
  stat->size = SHM_SIZE;
  stat->result_mask |= STATX_SIZE; // Set the size result mask
  printk(KERN_INFO "secshm: getattr called, size set to %d\n", SHM_SIZE);
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
  unsigned long size = vma->vm_end - vma->vm_start;
  unsigned long pfn;
  unsigned long page_offset;
  unsigned long page_count = size / PAGE_SIZE;

  printk(KERN_ERR "secshm: mmap called, size: %lu\n", size);
  // Check if the requested size is valid
  if (size != SHM_SIZE) {
    pr_err("Invalid size for mmap: %lu\n", size);
    return -EINVAL;
  }

  // Map each hugepage to the user-space address
  for (unsigned int i = 0; i < page_count; i++) {
    page_offset = i * PAGE_SIZE;
    pfn = page_to_pfn(huge_pages[i]); // Convert page to physical frame number

    if (remap_pfn_range(vma, vma->vm_start + page_offset, pfn, PAGE_SIZE,
                        vma->vm_page_prot)) {
      pr_err("Failed to remap hugepage at offset %lu\n", page_offset);
      return -EAGAIN;
    }
  }

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

  // Allocate hugepages
  if (allocate_hugepages()) {
    printk(KERN_ERR "secshm: Failed to allocate hugepages\n");
    return -ENOMEM;
  }
  // Register the misc device
  int ret = misc_register(&secshm_device);
  if (ret) {
    printk(KERN_ERR "secshm: Failed to register misc device\n");
    return ret;
  }

  printk(KERN_INFO "secshm: Module loaded and misc device registered\n");
  return 0;
}

// Module cleanup
static void __exit secshm_exit(void) {
  misc_deregister(&secshm_device);
  // Free the hugepage memory
  free_hugepages();
  printk(KERN_INFO "secshm: Module unloaded\n");
}

module_init(secshm_init);
module_exit(secshm_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jaroslaw Kurowski");
MODULE_DESCRIPTION("Shared memory device driver");
