/*
 *  This module creates /dev/fmem device,
 *  that can be used for dumping physical memory,
 *  without limits of /dev/mem (1MB/1GB, depending on distribution)
 *
 *  Tested only on i386, feel free to test it on
 *  different arch.
 *  cloned from
 *  linux/drivers/char/mem.c (so GPL license apply)
 *
 *  2009-2011, niekt0@hysteria.sk
 */

/*
 * BUGS: if you do something like # dd if=/dev/fmem of=dump
 *       dd will not stop, even if there is no more physical RAM
 *       on the system.
 */

#include <linux/device.h>
#include <linux/highmem.h>
#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/memblock.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/pfn.h>
#include <linux/ptrace.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/tty.h>
#include <linux/version.h>
#include <linux/vmalloc.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
#define KPROBE_LOOKUP 1
#include <linux/kprobes.h>
static struct kprobe kp = {.symbol_name = "kallsyms_lookup_name"};
#endif

#include "debug.h"

#ifdef CONFIG_IA64
#include <linux/efi.h>
#endif

// this is major number used for our new dumping device.
// 341 should be in free range
// In future maybe I should request number dynamically
#define FMEM_MAJOR 341
#define FMEM_MINOR 1

// dirty global variables;

// function page_is_ram is not exported
// for modules, but is available in kallsyms.
// So we need determine this address using dirty tricks
int (*guess_page_is_ram)(phys_addr_t pagenr);

// when parsing addresses trough parameters
unsigned long page_is_ram_addr = 0;
module_param(page_is_ram_addr, ulong, 0); // address of page_is_ram function

// Char we show before each debug print
const char program_name[] = "fmem";

static inline unsigned long size_inside_page(unsigned long start,
                                             unsigned long size) {
  unsigned long sz;

  sz = PAGE_SIZE - (start & (PAGE_SIZE - 1));

  return min(sz, size);
}

int valid_phys_addr_range(phys_addr_t addr, size_t count) {
  return addr + count <= __pa(high_memory);
}

int valid_mmap_phys_addr_range(unsigned long pfn, size_t size) { return 1; }

/* Own implementation of xlate_dev_mem_ptr
 * (so we can read highmem and other)
 *
 * Input:  physical address
 * Output: pointer to virtual address where requested
 *         physical address is mapped
 */

void *my_xlate_dev_mem_ptr(phys_addr_t phys) {
  void *addr = NULL;
  phys_addr_t start = phys & PAGE_MASK;
  phys_addr_t pfn = PFN_DOWN(phys);

  /* If page is RAM, we can use __va. Otherwise ioremap and unmap. */
  if ((*guess_page_is_ram)(start >> PAGE_SHIFT)) {
    if (PageHighMem(pfn_to_page(pfn))) {
      /* The buffer does not have a mapping.  Map it! */
      addr = kmap(pfn_to_page(pfn));
      return addr;
    }
    return __va(phys);
  }

  // Not RAM, so it is some device (can be bios for example)
  addr = (void __force *)ioremap_cache(start, PAGE_SIZE);
  if (addr)
    addr = (void *)((phys_addr_t)addr | (phys & ~PAGE_MASK));
  return addr;
}

// Our own implementation of unxlate_dev_mem_ptr
// (so we can read highmem and other)
void my_unxlate_dev_mem_ptr(phys_addr_t phys, void *addr) {
  phys_addr_t pfn = PFN_DOWN(phys); // get page number

  /* If page is RAM, check for highmem, and eventualy do nothing.
     Otherwise need to iounmap. */
  if ((*guess_page_is_ram)(phys >> PAGE_SHIFT)) {

    if (PageHighMem(pfn_to_page(pfn))) {
      /* Need to kunmap kmaped memory*/
      kunmap(pfn_to_page(pfn));
      // dbgprint ("unxlate: Highmem detected");
    }
    return;
  }

  // Not RAM, so it is some device (can be bios for example)
  iounmap((void __iomem *)((unsigned long)addr & PAGE_MASK));
}

static inline bool should_stop_iteration(void) {
  if (need_resched())
    cond_resched();
  return fatal_signal_pending(current);
}

/*-- original (stripped) linux/drivers/char/mem.c starts here ---
   only one mem device (fmem) was left
   only read operation is supported
   some not necessary pieces may survived, feel free to clean them
  --------------------------------------------------------------*/

/*
 * This funcion reads the *physical* memory. The f_pos points directly to the
 * memory location.
 */
static ssize_t read_mem(struct file *file, char __user *buf, size_t count,
                        loff_t *ppos) {
  phys_addr_t p = *ppos;
  ssize_t read, sz;
  void *ptr;
  char *bounce;
  int err;

  if (p != *ppos)
    return 0;

  if (!valid_phys_addr_range(p, count))
    return -EFAULT;
  read = 0;
#ifdef __ARCH_HAS_NO_PAGE_ZERO_MAPPED
  /* we don't have page 0 mapped on sparc and m68k.. */
  if (p < PAGE_SIZE) {
    sz = size_inside_page(p, count);
    if (sz > 0) {
      if (clear_user(buf, sz))
        return -EFAULT;
      buf += sz;
      p += sz;
      count -= sz;
      read += sz;
    }
  }
#endif

  bounce = kmalloc(PAGE_SIZE, GFP_KERNEL);
  if (!bounce)
    return -ENOMEM;

  while (count > 0) {
    unsigned long remaining;
    int probe;

    sz = size_inside_page(p, count);

    err = -EFAULT;
    /*
     * On ia64 if a page has been mapped somewhere as
     * uncached, then it must also be accessed uncached
     * by the kernel or data corruption may occur.
     */
    ptr = my_xlate_dev_mem_ptr(p);
    if (!ptr)
      goto failed;

    probe = copy_from_kernel_nofault(bounce, ptr, sz);
    my_unxlate_dev_mem_ptr(p, ptr);
    if (probe)
      goto failed;

    remaining = copy_to_user(buf, bounce, sz);

    if (remaining)
      goto failed;

    buf += sz;
    p += sz;
    count -= sz;
    read += sz;
    if (should_stop_iteration())
      break;
  }
  kfree(bounce);

  *ppos += read;
  return read;

failed:
  kfree(bounce);
  return err;
}

static ssize_t write_mem(struct file *file, const char __user *buf,
                         size_t count, loff_t *ppos) {
  phys_addr_t p = *ppos;
  ssize_t written, sz;
  unsigned long copied;
  void *ptr;

  if (p != *ppos)
    return -EFBIG;

  if (!valid_phys_addr_range(p, count))
    return -EFAULT;

  written = 0;

#ifdef __ARCH_HAS_NO_PAGE_ZERO_MAPPED
  /* we don't have page 0 mapped on sparc and m68k.. */
  if (p < PAGE_SIZE) {
    sz = size_inside_page(p, count);
    /* Hmm. Do something? */
    buf += sz;
    p += sz;
    count -= sz;
    written += sz;
  }
#endif

  while (count > 0) {
    sz = size_inside_page(p, count);

    /* Skip actual writing when a page is marked as restricted. */
    /*
     * On ia64 if a page has been mapped somewhere as
     * uncached, then it must also be accessed uncached
     * by the kernel or data corruption may occur.
     */
    ptr = my_xlate_dev_mem_ptr(p);
    if (!ptr) {
      if (written)
        break;
      return -EFAULT;
    }

    copied = copy_from_user(ptr, buf, sz);
    my_unxlate_dev_mem_ptr(p, ptr);
    if (copied) {
      written += sz - copied;
      if (written)
        break;
      return -EFAULT;
    }

    buf += sz;
    p += sz;
    count -= sz;
    written += sz;
    if (should_stop_iteration())
      break;
  }

  *ppos += written;
  return written;
}

int __weak phys_mem_access_prot_allowed(struct file *file, unsigned long pfn,
                                        unsigned long size,
                                        pgprot_t *vma_prot) {
  return 1;
}

/*
 * Architectures vary in how they handle caching for addresses
 * outside of main memory.
 *
 */
static int uncached_access(struct file *file, phys_addr_t addr) {
#if defined(CONFIG_IA64)
  /*
   * On ia64, we ignore O_DSYNC because we cannot tolerate memory
   * attribute aliases.
   */
  return !(efi_mem_attributes(addr) & EFI_MEMORY_WB);
#elif defined(CONFIG_MIPS)
  {
    extern int __uncached_access(struct file * file, unsigned long addr);

    return __uncached_access(file, addr);
  }
#else
  /*
   * Accessing memory above the top the kernel knows about or through a
   * file pointer
   * that was marked O_DSYNC will be done non-cached.
   */
  if (file->f_flags & O_DSYNC)
    return 1;
  return addr >= __pa(high_memory);
#endif
}

pgprot_t phys_mem_access_prot(struct file *file, unsigned long pfn,
                              unsigned long size, pgprot_t vma_prot) {
#ifdef pgprot_noncached
  phys_addr_t offset = pfn << PAGE_SHIFT;

  if (uncached_access(file, offset))
    return pgprot_noncached(vma_prot);
#endif
  return vma_prot;
}

#ifndef CONFIG_MMU
static unsigned long
get_unmapped_area_mem(struct file *file, unsigned long addr, unsigned long len,
                      unsigned long pgoff, unsigned long flags) {
  if (!valid_mmap_phys_addr_range(pgoff, len))
    return (unsigned long)-EINVAL;
  return pgoff << PAGE_SHIFT;
}

/* can't do an in-place private mapping if there's no MMU */
static inline int private_mapping_ok(struct vm_area_struct *vma) {
  return vma->vm_flags & VM_MAYSHARE;
}
#else
#define get_unmapped_area_mem NULL

static inline int private_mapping_ok(struct vm_area_struct *vma) { return 1; }
#endif

static const struct vm_operations_struct mmap_mem_ops = {
#ifdef CONFIG_HAVE_IOREMAP_PROT
    .access = generic_access_phys
#endif
};

static int mmap_mem(struct file *file, struct vm_area_struct *vma) {
  size_t size = vma->vm_end - vma->vm_start;
  phys_addr_t offset = (phys_addr_t)vma->vm_pgoff << PAGE_SHIFT;

  /* Does it even fit in phys_addr_t? */
  if (offset >> PAGE_SHIFT != vma->vm_pgoff)
    return -EINVAL;

  /* It's illegal to wrap around the end of the physical address space. */
  if (offset + (phys_addr_t)size - 1 < offset)
    return -EINVAL;

  if (!valid_mmap_phys_addr_range(vma->vm_pgoff, size))
    return -EINVAL;

  if (!private_mapping_ok(vma))
    return -ENOSYS;

  if (!phys_mem_access_prot_allowed(file, vma->vm_pgoff, size,
                                    &vma->vm_page_prot))
    return -EINVAL;

  vma->vm_page_prot =
      phys_mem_access_prot(file, vma->vm_pgoff, size, vma->vm_page_prot);

  vma->vm_ops = &mmap_mem_ops;

  /* Remap-pfn-range will mark the range VM_IO */
  if (remap_pfn_range(vma, vma->vm_start, vma->vm_pgoff, size,
                      vma->vm_page_prot)) {
    return -EAGAIN;
  }
  return 0;
}

/*
 * The memory devices use the full 32/64 bits of the offset, and so we cannot
 * check against negative addresses: they are ok. The return value is weird,
 * though, in that case (0).
 *
 * also note that seeking relative to the "end of file" isn't supported:
 * it has no meaning, so it returns -EINVAL.
 */
static loff_t memory_lseek(struct file *file, loff_t offset, int orig) {
  loff_t ret;

  inode_lock(file->f_path.dentry->d_inode);

  switch (orig) {
  case 0:
    file->f_pos = offset;
    ret = file->f_pos;
    force_successful_syscall_return();
    break;
  case 1:
    file->f_pos += offset;
    ret = file->f_pos;
    force_successful_syscall_return();
    break;
  default:
    ret = -EINVAL;
  }
  inode_unlock(file->f_path.dentry->d_inode);
  return ret;
}

static int open_port(struct inode *inode, struct file *filp) {
  return capable(CAP_SYS_RAWIO) ? 0 : -EPERM;
}

#define full_lseek null_lseek
#define read_full read_zero
#define open_mem open_port
#define open_fmem open_port

static const struct file_operations mem_fops = {
    .llseek = memory_lseek,
    .read = read_mem,
    .write = write_mem,
    .mmap = mmap_mem,
    .open = open_mem,
    .get_unmapped_area = get_unmapped_area_mem,
};

static int memory_open(struct inode *inode, struct file *filp) {
  // no more kernel locking,
  // let's hope it is safe;)
  int ret = 0;

  switch (iminor(inode)) {
  case 1:
    filp->f_op = &mem_fops;
    break;
  default:
    return -ENXIO;
  }
  if (filp->f_op && filp->f_op->open)
    ret = filp->f_op->open(inode, filp);
  return ret;
}

static const struct file_operations memory_fops = {
    .open = memory_open, /* just a selector for the real open */
};

static const struct {
  unsigned int minor;
  char *name;
  umode_t mode;
  const struct file_operations *fops;
} devlist[] = {
    /* list of minor devices */
    {1, "fmem", S_IRUSR | S_IWUSR | S_IRGRP, &mem_fops},
};

static struct class *mem_class;

// This function actually creates device itself.
static int __init chr_dev_init(void) {
  int i;
  if (register_chrdev(FMEM_MAJOR, "fmem", &memory_fops))
    printk("unable to get major %d for memory devs\n", FMEM_MAJOR);

  mem_class = class_create(THIS_MODULE, "fmem");
  for (i = 0; i < ARRAY_SIZE(devlist); i++) {
    device_create(mem_class, NULL, MKDEV(FMEM_MAJOR, devlist[i].minor), NULL,
                  devlist[i].name);
  }
  return 0;
}

int find_symbols(void) {
  unsigned long addr;

#ifdef KPROBE_LOOKUP
  typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
  kallsyms_lookup_name_t kallsyms_lookup_name;
  register_kprobe(&kp);
  kallsyms_lookup_name = (kallsyms_lookup_name_t)kp.addr;
  unregister_kprobe(&kp);
#endif

  addr = kallsyms_lookup_name("page_is_ram");
  dbgprint("set guess_page_is_ram: %#lx", addr);
  guess_page_is_ram = (void *)addr;

  if (!guess_page_is_ram) {
    guess_page_is_ram = (void *)page_is_ram_addr;
    dbgprint("set guess_page_is_ram: %p", guess_page_is_ram);
  }

  return 0;
}

/// Function executed upon loading module
int __init fmem_init(void) {
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0))
  dbgprint("init");
  find_symbols();

  // Create device itself (/dev/fmem)
  chr_dev_init();
  return 0;
#else
  dbgprint("fmem is supported starting with Linux Kernel v5.8.0 or higher.");
  return 1;
#endif
}

/// Function executed when unloading module
void __exit fmem_cleanup(void) {
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0))
  dbgprint("destroying fmem device");

  // Clean up
  unregister_chrdev(FMEM_MAJOR, "fmem");
  device_destroy(mem_class, MKDEV(FMEM_MAJOR, FMEM_MINOR));
  class_destroy(mem_class);

  dbgprint("exit");
#else
  dbgprint("fmem is supported starting with Linux Kernel v5.8.0 or higher.");
#endif
}

module_init(fmem_init);
module_exit(fmem_cleanup);

MODULE_DESCRIPTION("Linux Kernel Module designed to help analyze volatile "
                   "memory in the linux kernel");
MODULE_LICENSE("GPL");