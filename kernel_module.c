#include <linux/namei.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/syscalls.h>

MODULE_LICENSE("GPL");

char *filter_list[] = {
    "/home"
};

typedef asmlinkage int (*syscall_wrapper)(const struct pt_regs *);
syscall_wrapper original_openat;
syscall_wrapper original_close;

unsigned long sys_call_table_addr;

static unsigned long kaddr_lookup_name(const char *fname_raw)
{
    int i;
    unsigned long kaddr;
    char *fname_lookup, *fname;

    fname_lookup = kvzalloc(NAME_MAX, GFP_KERNEL);
    if (!fname_lookup)
        return 0;

    fname = kvzalloc(strlen(fname_raw) + 4, GFP_KERNEL);
    if (!fname)
        return 0;

    strcpy(fname, fname_raw);
    strcat(fname, "+0x0");

    kaddr = (unsigned long) &sprint_symbol;
    kaddr &= 0xffffffffff000000;

    for ( i = 0x0 ; i < 0x200000 ; i++ )
    {
        sprint_symbol(fname_lookup, kaddr);
        if (strncmp(fname_lookup, fname, strlen(fname)) == 0)
        {
            kvfree(fname_lookup);
            return kaddr;
        }
        
        kaddr += 0x10;
    }

    kvfree(fname_lookup);
    return 0;
}

static void enable_page_rw(void *ptr) {
    unsigned int level;
    pte_t *pte = lookup_address((unsigned long) ptr, &level);
    if(pte->pte & ~_PAGE_RW) {
        pte->pte |= _PAGE_RW;
    }
}

static void disable_page_rw(void *ptr) {
    unsigned int level;
    pte_t *pte = lookup_address((unsigned long) ptr, &level);
    pte->pte = pte->pte & ~_PAGE_RW;
}

static char * get_absolute_path_by_fd(const int fd) {
    char *path = NULL;
    char *page = (char *) __get_free_page(GFP_KERNEL);

    struct file *file = fget(fd);

    if (!file)
        goto exit;

    path = d_path(&file->f_path, page, PAGE_SIZE);

    if (IS_ERR(path))
        goto exit;

exit:
    free_page((unsigned long) page);
    return path;
}

static char * get_absolute_path_by_dfd(const int dfd, const char *filename) {
    int flag = 0;
    int ret = -EINVAL;
    unsigned int lookup_flags = 0;
    char *path = NULL;
    char *page = (char *) __get_free_page(GFP_KERNEL);
    struct path spath;

    if ((flag & ~(AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT)) != 0)
        goto exit;

    if (!(flag & AT_SYMLINK_NOFOLLOW))
        lookup_flags |= LOOKUP_FOLLOW;

    ret = user_path_at(dfd, filename, lookup_flags, &spath);
    if (ret)
        goto exit;

    path = d_path(&spath, page, PAGE_SIZE);
    
exit:
    free_page((unsigned long) page);
    return path;
}

static bool startswith(const char *pre, const char *str)
{
    return strncmp(pre, str, strlen(pre)) == 0;
}

static bool filter_path(const char *path) {
    int i;
    int len = sizeof(filter_list)/sizeof(char*);

    for (i = 0; i < len; i++) {
        if (startswith(filter_list[i], path))
            return true;
    }

    return false;
}

static asmlinkage int hooked_openat(const struct pt_regs *regs) {
    char *path = (char *) regs->si;

    if (path[0] != '/') {
        int dfd = regs->di;

        path = get_absolute_path_by_dfd(dfd, path);
        if (!path)
            goto exit;        
    }

    if (!filter_path(path))
        goto exit;

    printk("OPENAT: %s.\n", path);

exit:
    return (*original_openat)(regs);
}

static asmlinkage int hooked_close(const struct pt_regs *regs) {
    int fd = regs->di;

    char *path = get_absolute_path_by_fd(fd);
    if (!path)
        goto exit;

    if (!filter_path(path))
        goto exit;

    printk("CLOSE: %s.\n", path);

exit:
    return (*original_close)(regs);
}

static int swap_syscall(unsigned short nr, syscall_wrapper *old, syscall_wrapper new) {
    *old = ((syscall_wrapper *)sys_call_table_addr)[nr];
    if (!*old)
        return 1;

    ((syscall_wrapper *)sys_call_table_addr)[nr] = new;

    return 0;
}

static int __init start(void) {
    printk(KERN_INFO "Anti-Ransomware Module has been started.\n");

    sys_call_table_addr = kaddr_lookup_name("sys_call_table");
    if (!sys_call_table_addr)
        goto error;

    enable_page_rw((void *)sys_call_table_addr);

    if (swap_syscall(__NR_openat, &original_openat, hooked_openat))
        goto error;
    printk(KERN_INFO "Openat got hooked.\n");

    if (swap_syscall(__NR_close, &original_close, hooked_close))
        goto error;
    printk(KERN_INFO "Close got hooked.\n");

    disable_page_rw((void *)sys_call_table_addr);

    return 0;

error:
    disable_page_rw((void *)sys_call_table_addr);
    printk(KERN_ERR "An error occurred during module initialization.\n");
    return 1;
}

static void __exit stop(void) {
    enable_page_rw((void *)sys_call_table_addr);
    ((syscall_wrapper *)sys_call_table_addr)[__NR_openat] = original_openat;
    ((syscall_wrapper *)sys_call_table_addr)[__NR_close] = original_close;
    disable_page_rw((void *)sys_call_table_addr);

    printk(KERN_INFO "Anti-Ransomware Module has been deactivated.\n");
}

module_init(start);
module_exit(stop);
