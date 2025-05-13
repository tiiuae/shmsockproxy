#include "./secshm_config.h"
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/sched.h>

#define DEVICE_NAME "ivshmem"
#define NUM_PAGES (SHM_SIZE / PAGE_SIZE)
#define QEMU_VM_NAME_OPT "-name"

static loff_t secshm_lseek(struct file *filp, loff_t offset, int origin);
static const struct inode_operations secshm_inode_ops;
static struct page **pages; // Array to hold allocated pages

static void get_vm_name(char *vm_name, size_t vm_name_len) {
  char *arg_start, *arg_end, *args_buf;
  int arg_len;
  struct mm_struct *mm;
  size_t i = 0;

  pr_err("secshm: get_vm_name called\n");
  vm_name[0] = '\0';

  mm = get_task_mm(current);
  if (!mm) {
    goto out_mm;
  }
  if (!mm->arg_end) {
    goto out;
  }

  spin_lock(&mm->arg_lock);
  arg_start = (char *)mm->arg_start;
  arg_end = (char *)mm->arg_end;
  arg_len = arg_end - arg_start;
  spin_unlock(&mm->arg_lock);

  args_buf = kmalloc(arg_len + 1, GFP_KERNEL);
  if (!args_buf) {
    pr_err("secshm: Failed to allocate buffer\n");
    goto out;
  }

  // Copy arguments from userspace
  if (copy_from_user(args_buf, (const void __user *)arg_start, arg_len)) {
    pr_err("secshm: Failed to copy args\n");
    kfree(args_buf);
    goto out;
  }
  args_buf[arg_len] = '\0';

  while (i < arg_len) {
    const char *token = &args_buf[i];
    size_t len = strlen(token);

    if (len == 0) {
      i++;
      continue;
    }
    if (strcmp(token, QEMU_VM_NAME_OPT) == 0) {
      i += len + 1;
      if (i < arg_len && args_buf[i] != '\0') {
        strncpy(vm_name, &args_buf[i], vm_name_len); // Next token after "-name"
        pr_info("secshm: VM name: %s\n", vm_name);
        goto out;
      } else {
        goto out; // "-name" was the last token
      }
    }
    i += len + 1;
  }
  arg_start = args_buf + strlen(args_buf) + 1;

  if (arg_len <= strlen(args_buf) || !strlen(arg_start)) {
    pr_err("secshm: Missing process command line parameter\n");
    kfree(args_buf);
    goto out;
  }

  pr_info("Process args: %s args_len: %d\n", arg_start, arg_len);
  kfree(args_buf);

out:
  mmput(mm);
out_mm:
  return;
}

static int allocate_module_pages(void) {

  pages = kmalloc((NUM_PAGES + 1) * sizeof(struct page *), GFP_KERNEL);
  if (!pages) {
    pr_err("Failed to allocate page array\n");
    return -ENOMEM;
  }

  pr_info("Allocating %ld pages\n", (NUM_PAGES + 1)); // jarekk: TODO delete
  // Allocate pages
  for (unsigned int i = 0; i < (NUM_PAGES + 1); i++) {
    pages[i] = alloc_page(GFP_KERNEL | __GFP_ZERO);
    // pr_info("Allocated page %u at %p\n", i,
    //         pages[i]); // jarekk: TODO delete

    if (IS_ERR_OR_NULL(pages[i])) {
      pr_err("Failed to allocate page %u\n", i);
      // Free previously allocated pages
      for (unsigned int j = 0; j < i; j++) {
        __free_pages(pages[j], 0);
      }
      kfree(pages);
      return -ENOMEM;
    }
  }
  return 0;
}

static void free_module_pages(void) {
  for (unsigned int i = 0; i < (NUM_PAGES + 1); i++) {
    if (pages[i]) {
      __free_pages(pages[i], 0);
    }
  }
  kfree(pages);
}

static int secshm_open(struct inode *inode, struct file *filp) {
  // Override default i_op to take over getattr
  // This is needed to set the size of the shared memory region
  inode->i_op = &secshm_inode_ops;
  pr_info("secshm: Opened.\n");
  return 0;
}

static int secshm_getattr(struct mnt_idmap *idmap, const struct path *path,
                          struct kstat *stat, u32 request_mask,
                          unsigned int query_flags)

{
  struct inode *inode = path->dentry->d_inode;
  pr_info("secshm: getattr called\n");
  // Get basic attributes from the generic implementation
  generic_fillattr(idmap, request_mask, inode, stat);

  // Override the size with our shared memory size
  stat->size = SHM_SIZE;
  stat->result_mask |= STATX_SIZE; // Set the size result mask
  pr_info("secshm: getattr called, size set to %d\n", SHM_SIZE);
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

static int secshm_mmap(struct file *filp, struct vm_area_struct *vma) {
  unsigned long size = vma->vm_end - vma->vm_start;
  unsigned long page_offset;
  struct page *page; // Dummy page for the forbidden area
  char buf[TASK_COMM_LEN];
  pid_t parent_pid = current->parent->pid;
  ;

  get_task_comm(buf, current);
  pr_info("secshm: mmap called by %s (ppid: %d)\n", buf, parent_pid);
  get_vm_name(buf, sizeof(buf));

  pr_err("secshm: mmap called, size: %lu\n", size);
  // Check if the requested size is valid
  if (size != SHM_SIZE) {
    pr_err("Invalid size for mmap: %lu\n", size);
    return -EINVAL;
  }
  if (vma->vm_pgoff != 0) {
    pr_err("secshm: mmap with non-zero offset not supported\n");
    return -EINVAL;
  }

  // Map each page to the user-space address
  for (unsigned int i = 0; i < NUM_PAGES; i++) {
    // test of assigning the same page to different offsets
    if (i < (NUM_PAGES * 3) / 4) {
      page = pages[i];
      // pr_info("secshm: mmap using normal page %u\n", i);
    } else {
      page = pages[NUM_PAGES];
      // pr_info("secshm: **** mmap using dummy page %u\n", i);
    }
    page_offset = i * PAGE_SIZE;
    if (page_offset >= SHM_SIZE) {
      pr_err("Page offset exceeds SHM_SIZE: %lu\n", page_offset);
      return -EINVAL;
    } // Check if the page offset is valid

    // jarekk TODO delete
    // pfn = page_to_pfn(page); // Convert page to physical frame number
    // pr_err("secshm: mmap page %u, pfn: 0x%lx offset: %lu\n", i, pfn,
    //        page_offset);

    if (vm_insert_page(vma, vma->vm_start + page_offset, page)) {
      pr_err("Failed to vm_insert_page [%d] page at offset %lu\n", i,
             page_offset);
      return -EAGAIN;
    }
    vm_flags_mod(vma, VM_SHARED | VM_DONTEXPAND | VM_DONTEXPAND, 0);
    vma->vm_page_prot = pgprot_writecombine(vma->vm_page_prot);
  }
  return 0;
}

static struct file_operations secshm_fops = {
    .owner = THIS_MODULE,
    .open = secshm_open,
    .llseek = secshm_lseek,
    .mmap = secshm_mmap,
};

static struct miscdevice secshm_device = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = DEVICE_NAME,
    .fops = &secshm_fops,
};

static const struct inode_operations secshm_inode_ops = {
    .getattr = secshm_getattr,
};

static int __init secshm_init(void) {

  if (allocate_module_pages()) {
    pr_err("secshm: Failed to allocate pages\n");
    return -ENOMEM;
  }

  int ret = misc_register(&secshm_device);
  if (ret) {
    pr_err("secshm: Failed to register misc device\n");
    free_module_pages();
    return ret;
  }

  pr_info("secshm: Module loaded and misc device registered\n");
  return 0;
}

static void __exit secshm_exit(void) {
  misc_deregister(&secshm_device);
  free_module_pages();
  pr_info("secshm: Module unloaded\n");
}

module_init(secshm_init);
module_exit(secshm_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jaroslaw Kurowski");
MODULE_DESCRIPTION("Shared memory device driver");
