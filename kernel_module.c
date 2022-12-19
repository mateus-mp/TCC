#include <crypto/hash.h>
#include <linux/namei.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/syscalls.h>

MODULE_LICENSE("GPL");

char *filter_list[] = {
    "/home/mateus/Documentos"
};

char *extensions[] = {
    "rar", "zip", "iso", "vcd",
    "csv", "dat", "db", "log",
    "sav", "sql", "tar", "xml",
    "bmp", "gif", "ico", "jpeg",
    "jpg", "png", "svg", "asp",
    "aspx", "css", "htm", "html",
    "js", "php", "py", "c",
    "java", "avi", "mkv", "mp4",
    "mpg", "mpeg", "wmv", "doc",
    "odt", "pdf", "tex", "txt",
    "pem", "crt"
};

typedef asmlinkage int (*syscall_wrapper)(const struct pt_regs *);
syscall_wrapper original_openat;
syscall_wrapper original_write;
syscall_wrapper original_unlinkat;

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
            kvfree(fname);
            kvfree(fname_lookup);
            return kaddr;
        }
        
        kaddr += 0x10;
    }

    kvfree(fname);
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

    if (IS_ERR(file))
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

static bool filter_extension(char *path) {
    int i;
    char *ext = path + strlen(path);
    size_t len = sizeof(extensions) / sizeof(extensions[0]);
    
    for (; ext > path; ext--) {
        if (*ext == '.') {
            ext++;
            break;
        }
    }

    for (i = 0; i < len; i++) {
        if (strcmp(ext, extensions[i]) == 0) {
            return true;
        }
    }

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
    (*shinglesSizes)[shingleIndex - 1] = bufferSize - counter - 1;

    return shingleIndex;
}

static char * createHash(char *path) {
    char *result;

    result = kmalloc(33, GFP_KERNEL);
    result[32] = '\0';

    if (!md5(path, strlen(path), &result)) {
        kfree(result);
        return NULL;
    }

    return result;
}

static void saveFile(const char *hash, const char * write, const size_t writeSize) {
    char hashPath[38];
    struct file *writeFile;
    size_t size;
    
    hashPath[37] = '\0';

    sprintf(hashPath, "/tmp/%s", hash);

    writeFile = filp_open(hashPath, O_CREAT | O_WRONLY, 0777);
    writeFile->f_pos = 0;
    size = kernel_write(writeFile, write, 32 * writeSize + 4, &writeFile->f_pos);

    filp_close(writeFile, NULL);
}

static bool createHashes(const char *pivot, char ***shingles, unsigned short **shinglesSizes, const unsigned short totalShingles, char **write, size_t *writeSize) {
    size_t i, size;
    char *input;
    char *result;
    
    result = kmalloc(33, GFP_KERNEL);

    size = (*shinglesSizes)[0];
    input = kmalloc(size, GFP_KERNEL);
    input[size - 1] = '\0';
    strncpy(input, (*shingles)[0], size);
    printk("size of size: %lu\n", size);
    printk("oq foi: %s\n", input);
    
    if (!md5(input, size, &result))
        goto free;

    *write = kmalloc(36, GFP_KERNEL);
    (*write)[0] = pivot[0];
    (*write)[1] = pivot[1];
    (*write)[2] = ' ';
    (*write)[35] = '\0';
    sprintf(&(*write)[3], "%s", result);

    for (i = 1; i < totalShingles; i++) {
        size = (*shinglesSizes)[i];
        input = krealloc(input, size, GFP_KERNEL);
        input[size - 1] = '\0';
        strncpy(input, (*shingles)[i], size);
        printk("sizedentro: %lu\n", size);
        printk("dentro: %s\n", input);

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

static char * strdup(const char *src) {
    size_t len = strlen(src);
    char *s = kmalloc(len, GFP_KERNEL);

    if (s == NULL)
        return NULL;

    return (char *)memcpy(s, src, len);
}

static long get_file_size(const char *path) {
    struct file *file;
    long size;

    file = filp_open(path, O_RDONLY | O_LARGEFILE, 0777);

    if (IS_ERR(file))
        return -1;

    vfs_llseek(file, 0, SEEK_SET);
    size = vfs_llseek(file, 0, SEEK_END);
    vfs_llseek(file, 0, SEEK_CUR);

    filp_close(file, NULL);

    return size;
}

static size_t read_file(const char *path, const size_t size, char **buffer) {
    struct file *file;
    size_t ret;

    file = filp_open(path, O_RDONLY | O_LARGEFILE, 0777);

    if (IS_ERR(file)) {
        *buffer = NULL;
        return 0;
    }

    file->f_pos = 0;

    *buffer = kmalloc(size + 1, GFP_KERNEL);
    ret = kernel_read(file, *buffer, size, &file->f_pos);
    (*buffer)[ret] = '\0';

    filp_close(file, NULL);

    return ret;
}

static void write_file(const char *path, const char *buffer, const size_t size, const int flags) {
    struct file *file;

    file = filp_open(path, flags, 0777);

    file->f_pos = 0;
    kernel_write(file, buffer, size, &file->f_pos);

    filp_close(file, NULL);
}

static asmlinkage int hooked_openat(const struct pt_regs *regs) {
    struct file *file;
    size_t ret, pivotIndex, writeSize, len;
    long size;
    char hashPath[41];
    char pivot[3];
    char *buffer;
    char *write;
    char *tpath;
    char **shingles;
    unsigned short *shinglesSizes;
    unsigned short totalShingles;
    char *hash;
    struct inode *parent_inode;
    char *path = (char *) regs->si;

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

    if (!filter_extension(path))
        goto exit;

    len = strlen(path);
    tpath = kmalloc(len + 5, GFP_KERNEL);
    tpath[len+4] = '\0';
    sprintf(tpath, "%s.tcc", path);
    printk("tpath: %s\n", tpath);

    size = get_file_size(tpath);

    if (size < 0)
        goto notcc;
    printk("size maior q 0\n");
    ret = read_file(tpath, size, &buffer);

    if (!buffer)
        goto notcc;

    printk("vai escrever\n");
    write_file(path, buffer, ret, O_RDWR | O_CREAT | O_TRUNC | O_LARGEFILE);
    printk("escreveu\n");

    file = filp_open(tpath, O_RDONLY | O_LARGEFILE, 0777);

    parent_inode = file->f_path.dentry->d_parent->d_inode;
    inode_lock(parent_inode);
    vfs_unlink(&init_user_ns, parent_inode, file->f_path.dentry, NULL);
    inode_unlock(parent_inode);

    filp_close(file, NULL);

    kfree(buffer);

notcc:
    kfree(tpath);

    hash = createHash(path);

    if (hash == NULL)
        goto exit;

    hashPath[40] = '\0';
    sprintf(hashPath, "/backup/%s", hash);

    size = get_file_size(path);

    if (size < 3 || size > 524288000)
        goto free2;

    printk("OPENAT: %s.\n", path);
    printk("HASH: %s\n", hash);
    printk("HHPATH: %s\n", hashPath);

    ret = read_file(path, size, &buffer);

    if (!buffer)
        goto free2;

    printk("sera\n");
    write_file(hashPath, buffer, ret, O_RDWR | O_CREAT | O_TRUNC | O_LARGEFILE);
    printk("fechei\n");
    printk("OQSERAQTAACONTESENO: %lu\n", regs->dx);

    if ((regs->dx&O_ACCMODE) == O_RDONLY) {
        printk("entrou accmode\n");
        goto free3;
    }

    printk("dknsaidaisbd\n");
    pivotIndex = ret / 2;

    do {
        if (pivotIndex >= ret - 2) {
            pivot[0] = 'a';
            pivot[1] = 'a';
            break;
        }
        pivot[0] = buffer[pivotIndex];
        pivot[1] = buffer[pivotIndex + 1];
        pivotIndex += 2;
    } while (pivot[0] == ' ' || pivot[1] == ' ');
    pivot[2] = '\0';

    printk("QUANTO OPEN: %lu\n", ret);
    totalShingles = generateShingles(buffer, ret, pivot, &shingles, &shinglesSizes);
    //printShingles(&shingles, &shinglesSizes, totalShingles);
    if (!createHashes(pivot, &shingles, &shinglesSizes, totalShingles, &write, &writeSize))
        goto free;
            
    printk("HH: %s\n", hashPath);
    saveFile(hash, write, writeSize);

free:
    kfree(shingles);
    kfree(write);
    kfree(shinglesSizes);

free3: 
    printk("free3\n");
    kfree(buffer);

free2:
    printk("free2\n");
    kfree(hash);

exit:
    return (*original_openat)(regs);
}

static bool compareHashes(const char *oldHashTxt, const char *newHashTxt) {
    char *token1;
    char *token2;
    char *copy1, *r1;
    char *copy2, *r2;

    copy1 = r1 = strdup(oldHashTxt);
    printk("OOOOOOOOOO: %s\n", copy1);

    token1 = strsep(&copy1, " ");
    printk("tokout: %s\n", token1);
    printk("tokout2: %s\n", oldHashTxt);
    while(token1 != NULL) {
        token1 = strsep(&copy1, " ");
        printk("token1 in\n");

        if (token1 == NULL)
            break;
        
        copy2 = r2 = strdup(newHashTxt);
        printk("uUUUUuuuuUU: %s\n", copy2);
        token2 = strsep(&copy2, " ");
        printk("token2 out\n");
        
        while(token2 != NULL) {
            token2 = strsep(&copy2, " ");
            printk("token2 in\n");

            if (token2 == NULL)
                break;

            if (strcmp(token1, token2) == 0) {
                printk("achei innn\n");

                kfree(r1);
                kfree(r2);
                return true;
            }
        }
        printk("tenta free\n");
        
        kfree(r2);
        printk("foi ufa\n");

    }

    kfree(r1);
    return false;
}

static asmlinkage int hooked_unlinkat(const struct pt_regs *regs) {
    char *path = (char *) regs->si;

    if (path[0] != '/') {
        int dfd = regs->di;

        path = get_absolute_path_by_dfd(dfd, path);
        if (!path)
            goto exit;        
    }

    if (startswith("/backup", path))
        goto block;

exit:
    return (*original_unlinkat)(regs);

block:
    return (-EACCES);
}

static asmlinkage int hooked_write(const struct pt_regs *regs) {
    struct file *file;
    int fd = regs->di;
    size_t ret, writeSize, len;
    long size, bsize;
    char pivot[3];
    char hashPath[38];
    char backPath[41];
    char *result;
    char *hashTxt;
    char *write;
    char *tpath;
    char *buffer;
    char **shingles;
    unsigned short *shinglesSizes;
    unsigned short totalShingles;
    char *path = get_absolute_path_by_fd(fd);
    char *bpath = strdup(path);

    if (!path)
        goto exit;

    if (is_deleted(path))
        goto exit;

    if (is_directory(path))
        goto exit;

    if (!filter_path(path))
        goto exit;

    if (!filter_extension(path))
        goto exit;

    printk("OUTROSYSCALL: %s\n", (char *)regs->si);

    file = fget(fd);

    if (IS_ERR(file))
        goto exit;

    vfs_llseek(file, 0, SEEK_SET);
    size = vfs_llseek(file, 0, SEEK_END);
    vfs_llseek(file, 0, SEEK_CUR);

    result = kmalloc(33, GFP_KERNEL);

    if (!md5(path, strlen(path), &result)) {
        fput(file);
        goto free2;
    }
  
    fput(file);

    backPath[40] = '\0';
    sprintf(backPath, "/backup/%s", result);

    bsize = get_file_size(backPath);

    if (bsize < 0)
        goto free2;
    printk("pfv: %lu\n", regs->dx + size);
    printk("bbbb: %lu\n", bsize);
    if (size > 0 && regs->dx + size <= bsize)
        goto free2;

    printk("WRITE: %s.\n", path);

    if (regs->dx <= bsize)
        goto free2;

    hashPath[37] = '\0';
    sprintf(hashPath, "/tmp/%s", result);

    size = get_file_size(hashPath);

    if (size < 0)
        goto free2;

    ret = read_file(hashPath, size, &hashTxt);

    if (!hashTxt)
        goto free2;

    pivot[0] = hashTxt[0];
    pivot[1] = hashTxt[1];
    pivot[2] = '\0';

    printk("QUANTO WRITE: %lu\n", regs->dx);
    totalShingles = generateShingles((char *)regs->si, regs->dx + 1, pivot, &shingles, &shinglesSizes);
    //printShingles(&shingles, &shinglesSizes, totalShingles);

    if (!createHashes(pivot, &shingles, &shinglesSizes, totalShingles, &write, &writeSize))
        goto free1;

    if (!compareHashes(hashTxt, write)) {
        kfree(shingles);
        kfree(hashTxt);
        kfree(write);
        kfree(shinglesSizes);
        goto block;
    }
    printk("ACHOOO\n");
free1:
    printk("filp\n");
    kfree(shingles);
    printk("shingles\n");
    kfree(hashTxt);
    printk("hashTxt\n");
    kfree(write);
    printk("write\n");
    kfree(shinglesSizes);
    printk("ssizes\n");

free2:
    kfree(result);
    printk("result\n");
    printk("olha: %s\n", (char *)regs->si);
    printk("%lu\n", regs->dx);

exit:
    kfree(bpath);
    return (*original_write)(regs);

block:
    printk("BLOQUEADO BLOQUEADO BLOQUEADO BLOQUEADO BLOQUEADO BLOQUEADO BLOQUEADO BLOQUEADO\n");

    // backPath[40] = '\0';
    // sprintf(backPath, "/backup/%s", result);

    // size = get_file_size(backPath);

    // if (size < 0)
    //     goto exit2;

    ret = read_file(backPath, bsize, &buffer);

    if (!buffer)
        goto exit2;

    printk("sera: %s\n", bpath);

    len = strlen(bpath);
    tpath = kmalloc(len + 5, GFP_KERNEL);
    tpath[len+4] = '\0';
    sprintf(tpath, "%s.tcc", bpath);
    printk("TPATH: %s\n", tpath);

    write_file(tpath, buffer, ret, O_RDWR | O_CREAT | O_TRUNC | O_LARGEFILE);
    printk("fechei\n");

    kfree(buffer);
    kfree(tpath);

exit2:
    kfree(bpath);
    kfree(result);

    return (-EACCES);
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

    if (swap_syscall(__NR_unlinkat, &original_unlinkat, hooked_unlinkat))
        goto error;
    printk(KERN_INFO "Unlinkat got hooked.\n");

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
    ((syscall_wrapper *)sys_call_table_addr)[__NR_unlinkat] = original_unlinkat;
    disable_page_rw((void *)sys_call_table_addr);

    printk(KERN_INFO "Anti-Ransomware Module has been deactivated.\n");
}

module_init(start);
module_exit(stop);
