#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/cdev.h>
#include "./secshm_config.h"
#define DEVICE_NAME "ivshmem"

static dev_t dev_num;
static struct cdev mmap_cdev;
static struct class *mmap_class;
static void *kernel_buffer;  // Allocated memory
static int client_table_size = CLIENT_TABLE_SIZE;
static loff_t secshm_lseek(struct file *filp, loff_t offset, int origin);

// Open function
static int secshm_open(struct inode *inode, struct file *filp) {
    printk(KERN_INFO "secshm: Opened\n");
    return 0;
}

// Release function
static int secshm_release(struct inode *inode, struct file *filp) {
    printk(KERN_INFO "secshm: Closed\n");
    return 0;
}

// Lseek function
static loff_t secshm_lseek(struct file *filp, loff_t offset, int origin)
{
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

    if (remap_pfn_range(vma, vma->vm_start, pfn, vma->vm_end - vma->vm_start, vma->vm_page_prot)) {
        return -EIO;
    }

    printk(KERN_INFO "secshm: Memory mapped successfully\n");
    return 0;
}

// File operations structure
static struct file_operations fops = {
    .owner = THIS_MODULE,
    .open = secshm_open,
    .release = secshm_release,
    .llseek = secshm_lseek,
    .mmap = secshm_mmap,
};

// Module initialization
static int __init secshm_init(void) {
    // Allocate device number
    if (alloc_chrdev_region(&dev_num, 0, 1, DEVICE_NAME) < 0) {
        printk(KERN_ERR "secshm: Failed to allocate device number\n");
        return -1;
    }

    // Initialize character device
    cdev_init(&mmap_cdev, &fops);
    if (cdev_add(&mmap_cdev, dev_num, 1) < 0) {
        printk(KERN_ERR "secshm: Failed to add cdev\n");
        unregister_chrdev_region(dev_num, 1);
        return -1;
    }

    // Create device class (without THIS_MODULE)
    mmap_class = class_create(DEVICE_NAME);
    if (IS_ERR(mmap_class)) {
        printk(KERN_ERR "secshm: Failed to create class\n");
        cdev_del(&mmap_cdev);
        unregister_chrdev_region(dev_num, 1);
        return -1;
    }

    // Create device node
    if (!device_create(mmap_class, NULL, dev_num, NULL, DEVICE_NAME)) {
        printk(KERN_ERR "secshm: Failed to create device\n");
        class_destroy(mmap_class);
        cdev_del(&mmap_cdev);
        unregister_chrdev_region(dev_num, 1);
        return -1;
    }

    // Allocate kernel memory
    kernel_buffer = kmalloc(SHM_SIZE, GFP_KERNEL);
    if (!kernel_buffer) {
        printk(KERN_ERR "secshm: Failed to allocate memory\n");
        device_destroy(mmap_class, dev_num);
        class_destroy(mmap_class);
        cdev_del(&mmap_cdev);
        unregister_chrdev_region(dev_num, 1);
        return -1;
    }

    printk(KERN_INFO "secshm: Module loaded successfully\n");
    return 0;
}

// Module cleanup
static void __exit secshm_exit(void) {
    kfree(kernel_buffer);
    device_destroy(mmap_class, dev_num);
    class_destroy(mmap_class);
    cdev_del(&mmap_cdev);
    unregister_chrdev_region(dev_num, 1);
    printk(KERN_INFO "secshm: Module unloaded\n");
}

module_init(secshm_init);
module_exit(secshm_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jaroslaw Kurowski");
MODULE_DESCRIPTION("Shared memory device driver");
