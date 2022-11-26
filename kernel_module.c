#include <crypto/hash.h>
#include <linux/namei.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/syscalls.h>

MODULE_LICENSE("GPL");

char *filter_list[] = {
    "/home/mateus/Documentos"
};

typedef asmlinkage int (*syscall_wrapper)(const struct pt_regs *);
syscall_wrapper original_openat;
syscall_wrapper original_write;

unsigned long sys_call_table_addr;

static bool md5(const char *data, const size_t len, char **result) {
    struct crypto_shash *shash;
    struct shash_desc *desc;
    size_t size, ret;
    int i;
    char c[3];
    unsigned char digest[32];

    shash = crypto_alloc_shash("md5", 0, 0);

    if (shash == NULL)
        return false;

    size = sizeof(struct shash_desc) + crypto_shash_descsize(shash);
    desc = kmalloc(size, GFP_KERNEL);
    desc->tfm = shash;

    ret = crypto_shash_digest(desc, data, len, digest);

    for (i = 0; i < 16; i++) {
        sprintf(c, "%02x", digest[i] & 0xFFu);
        memcpy(*result + i * 2, c, 2);
    }

    (*result)[32] = '\0';

    kfree(desc);
    crypto_free_shash(shash);

    return true;
}

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

    for (i = 0x0 ; i < 0x300000 ; i++) {
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
    struct path *spath;
    struct file *file = fget(fd);

    if (!file)
        goto exit;

    spath = &file->f_path;
    path_get(spath);
    path = d_path(spath, page, PAGE_SIZE);
    path_put(spath);
    fput(file);

    if (IS_ERR(path))
        path = NULL;

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

static bool is_ignore(const char *path) {
    size_t len = strlen(path);

    if (strcmp(&path[len-7], ".sqlite") == 0)
        return true;

    if (strcmp(&path[len-7], ".vlpset") == 0)
        return true;

    if (strcmp(&path[len-7], ".little") == 0)
        return true;

    if (strcmp(&path[len-7], ".db-wal") == 0)
        return true;

    return false;
}

static bool is_deleted(const char *path) {
    char d[10];
    unsigned short index = strlen(path) - 9;

    strncpy(d, &path[index], 9);
    d[9] = '\0';

    if (strcmp(d, "(deleted)\0") == 0)
        return true;
    
    return false;
}

static bool is_directory(const char *path) {
    int error;
    struct path spath;
    struct inode *inode;

    error = kern_path(path, LOOKUP_FOLLOW, &spath);
    if (error)
        goto error;

    inode = spath.dentry->d_inode;

    return S_ISDIR(inode->i_mode);

error:
    return true;
}

static unsigned short generateShingles(char *buffer, const size_t bufferSize, const char *pivot, char ***shingles, unsigned short **shinglesSizes) {
    size_t i;
    unsigned short shingleIndex, counter;

    shingleIndex = 1;
    counter = 0;
    *shingles = kmalloc(sizeof(char *), GFP_KERNEL);
    *shinglesSizes = kmalloc(sizeof(unsigned short), GFP_KERNEL);
    (*shingles)[0] = buffer;

    for (i = 2; i < bufferSize - 1; i++) {
        if (shingleIndex > 49)
            break;

        if (buffer[i] == pivot[0] && buffer[i + 1] == pivot[1]) {
            *shinglesSizes = krealloc(*shinglesSizes, shingleIndex * sizeof(unsigned short), GFP_KERNEL);
            (*shinglesSizes)[shingleIndex - 1] = i - counter;
            *shingles = krealloc(*shingles, (shingleIndex + 1) * sizeof(char *), GFP_KERNEL);
            (*shingles)[shingleIndex++] = &buffer[i];

            counter = i++;
        }
    }

    *shinglesSizes = krealloc(*shinglesSizes, shingleIndex * sizeof(unsigned short), GFP_KERNEL);
    (*shinglesSizes)[shingleIndex - 1] = bufferSize - i + 1;

    return shingleIndex;
}

static void saveFile(const char *path, const char * write, size_t writeSize) {
    struct file *writeFile;
    size_t size;
    char hashPath[38];
    char *result;

    result = kmalloc(33, GFP_KERNEL);
    result[32] = '\0';

    if (!md5(path, strlen(path), &result))
        goto free;

    hashPath[37] = '\0';
    sprintf(hashPath, "/tmp/%s", result);

    writeFile = filp_open(hashPath, O_CREAT | O_WRONLY, 0777);
    writeFile->f_pos = 0;
    size = kernel_write(writeFile, write, 32 * writeSize + 4, &writeFile->f_pos);

    filp_close(writeFile, NULL);

free:
    kfree(result);
}

static bool createHashes(const char *path, const char *pivot, char ***shingles, unsigned short **shinglesSizes, unsigned short totalShingles, char **write, size_t *writeSize) {
    size_t i, size;
    char *input;
    char *result;
    
    result = kmalloc(33, GFP_KERNEL);

    size = (*shinglesSizes)[0] + 1;
    input = kmalloc(size, GFP_KERNEL);
    input[size - 1] = '\0';
    strncpy(input, (*shingles)[0], size);
    
    if (!md5(input, size, &result))
        goto free;

    *write = kmalloc(36, GFP_KERNEL);
    (*write)[0] = pivot[0];
    (*write)[1] = pivot[1];
    (*write)[2] = ' ';
    (*write)[35] = '\0';
    sprintf(&(*write)[3], "%s", result);

    for (i = 1; i < totalShingles; i++) {
        size = (*shinglesSizes)[i] + 1;
        input = krealloc(input, size, GFP_KERNEL);
        input[size - 1] = '\0';
        strncpy(input, (*shingles)[i], size);

        if (!md5(input, size, &result))
            goto free;

        *write = krealloc(*write, 32 * (i + 1) + 4, GFP_KERNEL);
        (*write)[32 * (i + 1)] = '\0';
        sprintf(*write, "%s %s", *write, result);
    }

    *writeSize = i + 1;

    kfree(input);
    kfree(result);

    return true;

free:
    kfree(input);
    kfree(result);

    return false;
}

static asmlinkage int hooked_openat(const struct pt_regs *regs) {
    struct file *file;
    size_t size, ret, pivotIndex, writeSize;
    char pivot[3];
    char *buffer;
    char *write;
    char **shingles;
    unsigned short *shinglesSizes;
    unsigned short totalShingles;
    char *path = (char *) regs->si;

    if ((regs->dx&O_ACCMODE) == O_RDONLY)
        goto exit;

    // Criar backup dos arquivos que estão em /home/mateus/Documentos e bloquear delete através da syscall unlinkat

    if (path[0] != '/') {
        int dfd = regs->di;

        path = get_absolute_path_by_dfd(dfd, path);
        if (!path)
            goto exit;        
    }

    if (is_directory(path))
        goto exit;

    if (!filter_path(path))
        goto exit;

    if (is_ignore(path))
        goto exit;

    file = filp_open(path, O_RDONLY | O_LARGEFILE, 0777);
    size = vfs_llseek(file, 0, SEEK_END);
    vfs_llseek(file, 0, SEEK_SET);
    file->f_pos = 0;

    if (size < 3 || size > 524288000)
        goto close;

    printk("OPENAT: %s.\n", path);

    buffer = kmalloc(size + 1, GFP_KERNEL);
    ret = kernel_read(file, buffer, size, &file->f_pos);
    buffer[ret] = '\0';

    pivotIndex = ret / 2;

    pivot[0] = buffer[pivotIndex];
    pivot[1] = buffer[pivotIndex + 1];
    pivot[2] = '\0';

    printk("PIVOT: %s\n", pivot);

    totalShingles = generateShingles(buffer, ret, pivot, &shingles, &shinglesSizes);

    if (!createHashes(path, pivot, &shingles, &shinglesSizes, totalShingles, &write, &writeSize))
        goto free;

    saveFile(path, write, writeSize);

free:
    kfree(shingles);
    kfree(buffer);
    kfree(write);
    kfree(shinglesSizes);
    
close:    
    filp_close(file, NULL);

exit:
    return (*original_openat)(regs);
}

static bool compareHashes(char *oldHashTxt, const char *newHashTxt) {
    char *token1;
    char *token2;
    char *copy;

    copy = kmalloc(strlen(newHashTxt), GFP_KERNEL);

    token1 = strsep(&oldHashTxt, " ");

    while(token1 != NULL) {
        token1 = strsep(&oldHashTxt, " ");

        if (token1 == NULL)
            break;
        
        strcpy(copy, newHashTxt);

        token2 = strsep(&copy, " ");

        while(token2 != NULL) {
            token2 = strsep(&copy, " ");

            if (token2 == NULL)
                break;

            if (strcmp(token1, token2) == 0) {
                kfree(copy);
                return true;
            }
        }
    }

    kfree(copy);
    return false;
}

static asmlinkage int hooked_write(const struct pt_regs *regs) {
    struct file *file;
    int fd = regs->di;
    size_t ret, size, writeSize;
    char pivot[3];
    char hashPath[38];
    char *result;
    char *hashTxt;
    char *write;
    char **shingles;
    unsigned short *shinglesSizes;
    unsigned short totalShingles;

    char *path = get_absolute_path_by_fd(fd);

    if (!path)
        goto exit;

    if (is_deleted(path))
        goto exit;

    if (is_directory(path))
        goto exit;

    if (!filter_path(path))
        goto exit;

    if (is_ignore(path))
        goto exit;

    printk("WRITE: %s.\n", path);
    
    result = kmalloc(33, GFP_KERNEL);

    if (!md5(path, strlen(path), &result))
        goto free2;

    hashPath[37] = '\0';
    sprintf(hashPath, "/tmp/%s", result);

    file = filp_open(hashPath, O_RDONLY, 0777);

    if (IS_ERR(file))
        goto free2;

    size = vfs_llseek(file, 0, SEEK_END);
    vfs_llseek(file, 0, SEEK_SET);
    file->f_pos = 0;

    hashTxt = kmalloc(size + 1, GFP_KERNEL);
    ret = kernel_read(file, hashTxt, size, &file->f_pos);
    hashTxt[ret] = '\0';

    pivot[0] = hashTxt[0];
    pivot[1] = hashTxt[1];
    pivot[2] = '\0';

    totalShingles = generateShingles((char *)regs->si, regs->dx, pivot, &shingles, &shinglesSizes);

    if (!createHashes(path, pivot, &shingles, &shinglesSizes, totalShingles, &write, &writeSize))
        goto free1;

    printk("PIVOT: %s\n", pivot);
    printk("ORIGINAL: %s\n", hashTxt);
    printk("MUDANCA: %s\n", write);

    if (!compareHashes(hashTxt, write))
        goto block;

free1:
    filp_close(file, NULL);
    kfree(shingles);
    kfree(hashTxt);
    kfree(write);
    kfree(shinglesSizes);

free2:
    kfree(result);

exit:
    return (*original_write)(regs);

block:
    printk("BLOQUEADO BLOQUEADO BLOQUEADO BLOQUEADO BLOQUEADO BLOQUEADO BLOQUEADO BLOQUEADO");

    filp_close(file, NULL);
    kfree(shingles);
    kfree(hashTxt);
    kfree(write);
    kfree(shinglesSizes);
    kfree(result);

    return 0;
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
    printk("SYS_CALL_TABLE_ADDR: %lu.\n", sys_call_table_addr);
    if (!sys_call_table_addr)
        goto error;

    enable_page_rw((void *)sys_call_table_addr);

    if (swap_syscall(__NR_openat, &original_openat, hooked_openat))
        goto error;
    printk(KERN_INFO "Openat got hooked.\n");

    if (swap_syscall(__NR_write, &original_write, hooked_write))
        goto error;
    printk(KERN_INFO "Write got hooked.\n");

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
    ((syscall_wrapper *)sys_call_table_addr)[__NR_write] = original_write;
    disable_page_rw((void *)sys_call_table_addr);

    printk(KERN_INFO "Anti-Ransomware Module has been deactivated.\n");
}

module_init(start);
module_exit(stop);
