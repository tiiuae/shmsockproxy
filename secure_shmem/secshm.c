#include "./secshm_config.h"
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/hugetlb.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/pagemap.h>
#include <linux/shmem_fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>



#define DEVICE_NAME "ivshmem"

static loff_t secshm_lseek(struct file *filp, loff_t offset, int origin);
static const struct inode_operations secshm_inode_ops;
static struct page **huge_pages; // Array to hold allocated hugepages
static unsigned int num_pages;   // Number of pages to allocate
static unsigned int hugepage_size; // Size of each hugepage
static struct file *huge_file;

/**
 * Create a hugetlb file in the hugetlbfs
 */
static struct file *create_hugetlb_file(void)
{
    struct file *file;
    char *file_name = "/dev/hugepages/ivshmem"; // Path to the hugetlb file
    
    // dd if=/dev/zero of=/dev/hugepages/ivshmem bs=2M count=16
    // if (vfs_truncate(file_name, SHM_SIZE)) { // Truncate the file to the specified size
    //   printk(KERN_ERR "secshm: Failed to truncate hugetlb file: %ld\n", PTR_ERR(file));
    //   return NULL;
    // }

    file = filp_open(file_name, O_RDWR /*| O_CREAT*/, 0600);
    if (IS_ERR(file)) {
        printk(KERN_ERR "secshm: Failed to open ??? hugetlb file: %ld file=%p\n", PTR_ERR(file), file);
        return NULL;
    }
    
    // /* Truncate the file to the specified size */
    // sys_ftruncate(file_inode(file)->i_rdev, size);
    
    return file;
}

#if 0
// Allocate hugepages
static int allocate_hugepages(void) {

  hugepage_size = PAGE_SIZE * 512; // 2MB per hugepage
  num_pages = SHM_SIZE / hugepage_size; // 2MB per hugepage
  huge_pages = kmalloc(num_pages * sizeof(struct page *), GFP_KERNEL);

  if (!huge_pages) {
    printk(KERN_ERR "Failed to allocate hugepage array\n");
    return -ENOMEM;
  }
  printk(KERN_INFO
         "Allocating %d pages HUGETLB_PAGE_ORDER=%d HPAGE_PMD_ORDER=%d get_order(SHM_SIZE)=%d\n",
         num_pages, HUGETLB_PAGE_ORDER, HPAGE_PMD_ORDER,
         get_order(SHM_SIZE)); // jarekk: TODO delete

  // Allocate each hugepage
  for (unsigned int i = 0; i < num_pages; i++) {
    huge_pages[i] =
        alloc_pages(GFP_KERNEL /*| GFP_TRANSHUGE*/ | __GFP_ZERO | __GFP_COMP, get_order(hugepage_size));
    printk(KERN_INFO "Allocated page %u pfn=0x%lx virt=%p\n", i, page_to_pfn(huge_pages[i]),
      page_address(huge_pages[i])); // jarekk: TODO delete

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
#endif

// Open function
static int secshm_open(struct inode *inode, struct file *filp) {
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

  #if 1
  loff_t offset = 0;
  int ret;

  printk(KERN_ERR "secshm: mmap() called\n");

  if (!huge_file) {
      printk(KERN_ERR "secshm: huge_file not available\n");
      return -EINVAL;
  }

  ret = vma->vm_ops ? 0 : -ENODEV;
  if (ret)
      return ret;

  // Don't allow partial mapping (just for safety)
  if ((vma->vm_end - vma->vm_start) != SHM_SIZE) {
      printk(KERN_ERR "secshm: User requested wrong size: %lx should be %x\n", vma->vm_end - vma->vm_start, SHM_SIZE);
      return -EINVAL;
  }

  // mmap backing file into this VMA
#if 1 
//LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
  vm_flags_mod(vma, VM_SHARED | VM_HUGETLB | VM_LOCKED, 0);
#else
  vma->vm_flags |= VM_SHARED | VM_HUGETLB;
#endif

  printk(KERN_ERR "secshm: call_mmap()\n");
  ret = call_mmap(huge_file, vma);
  if (ret)
      printk(KERN_ERR "secshm: call_mmap failed: %d\n", ret);
  else 
      printk(KERN_ERR "secshm: call_mmap succeeded\n");
  
  return ret;

  #else
  unsigned long size = vma->vm_end - vma->vm_start;
  unsigned long pfn;
  unsigned long page_offset;

  printk(KERN_ERR "secshm: mmap called, size: %lu\n", size);
  // Check if the requested size is valid
  if (size != SHM_SIZE) {
    pr_err("Invalid size for mmap: %lu\n", size);
    return -EINVAL;
  }

  // Map each hugepage to the user-space address
  for (unsigned int i = 0; i < num_pages; i++) {
    page_offset = i * hugepage_size;  // 2MB per hugepage
    if (page_offset >= SHM_SIZE) {
      pr_err("Page offset exceeds SHM_SIZE: %lu\n", page_offset);
      return -EINVAL;
    } // Check if the page offset is valid
    // jarekk TODO delete
    pfn = page_to_pfn(huge_pages[i]); // Convert page to physical frame number
    printk(KERN_ERR "secshm: mmap page %u, pfn: 0x%lx offset: %lu\n", i, pfn, page_offset);

    if (remap_pfn_range(vma, vma->vm_start + page_offset, pfn, hugepage_size,
                        vma->vm_page_prot)) {
      pr_err("Failed to remap hugepage at offset %lu\n", page_offset);
      return -EAGAIN;
    }
  }

  return 0;
  #endif
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
  // if (allocate_hugepages()) {
  //   printk(KERN_ERR "secshm: Failed to allocate hugepages\n");
  //   return -ENOMEM;
  // }

  // Allocate hugepages file
  huge_file = create_hugetlb_file();
  if (!huge_file) {
    printk(KERN_ERR "secshm: Failed to allocate hugepages file\n");
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
  // free_hugepages();

  // Close the hugepages file
  if (huge_file && !IS_ERR(huge_file)) {
    filp_close(huge_file, NULL);
  }
  printk(KERN_INFO "secshm: Module unloaded\n");
}

module_init(secshm_init);
module_exit(secshm_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jaroslaw Kurowski");
MODULE_DESCRIPTION("Shared memory device driver");
