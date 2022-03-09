#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/fanotify.h>
#include <sys/sendfile.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string.h>
#include <math.h>

#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#define MIN(x, y) (((x) < (y)) ? (x) : (y))

float compareByteSimilarity(const char *a, unsigned long asize, const char *b, unsigned  long bsize) {
    unsigned long min = MIN(asize, bsize);
    unsigned long max = MAX(asize, bsize);
    unsigned long unequalCount = max - min;
    for (int i = 0; i < min; i++) {
        if (a[i] != b[i]) {
            unequalCount++;
        }
    }
    return (100.0f * (float) max - (float) unequalCount * 100.0f) / (float) max;
}

static int copyFile(int input, const char *destination) {
    int output;
    if ((output = creat(destination, 0660)) == -1) {
        return -1;
    }
    off_t bytesCopied = 0;
    struct stat fileInfo = {0};
    fstat(input, &fileInfo);
    int result = sendfile(output, input, &bytesCopied, fileInfo.st_size);
    close(output);
    return result;
}

static void handle_events(int fd) {
    const struct fanotify_event_metadata *metadata;
    struct fanotify_event_metadata buf[200];
    ssize_t len;
    char path[PATH_MAX];
    char *bkpath = (char*) malloc(50 * sizeof(char));
    char *filename;
    char *filebytes;
    char *bkfilebytes;
    ssize_t path_len;
    char procfd_path[PATH_MAX];
    struct fanotify_response response;
    FILE *file;
    unsigned long filelen;

    for (;;) {
        printf("Evento ocorreu!\n");
        fflush(stdout);
        len = read(fd, buf, sizeof(buf));

        if (len == -1 && errno != EAGAIN) {
            perror("read");
            exit(EXIT_FAILURE);
        }

        if (len <= 0)
            break;

        metadata = buf;

        while (FAN_EVENT_OK(metadata, len)) {
            if (metadata->vers != FANOTIFY_METADATA_VERSION) {
                fprintf(stderr,
                        "Mismatch of fanotify metadata version.\n");
                exit(EXIT_FAILURE);
            }

            if (metadata->fd >= 0) {
                if (metadata->pid != getpid()) {
                    if (metadata->mask & FAN_OPEN_PERM) {
                        snprintf(procfd_path, sizeof(procfd_path), "/proc/self/fd/%d", metadata->fd);
                        path_len = readlink(procfd_path, path, sizeof(path) - 1);

                        if (path_len == -1) {
                            perror("readlink");
                            exit(EXIT_FAILURE);
                        }
                        path[path_len] = '\0';

                        filename = strrchr(path, '/');
                        sprintf(bkpath, "/home/beringela/%s.swp", ++filename);
                        printf("%s\n", bkpath);
                        fflush(stdout);
                        copyFile(metadata->fd, bkpath);

                        response.fd = metadata->fd;
                        response.response = FAN_ALLOW;
                        write(fd, &response, sizeof(response));
                    } else {
                        if (metadata->mask & FAN_CLOSE_WRITE) {
                            snprintf(procfd_path, sizeof(procfd_path), "/proc/self/fd/%d", metadata->fd);
                            path_len = readlink(procfd_path, path, sizeof(path) - 1);

                            if (path_len == -1) {
                                perror("readlink");
                                exit(EXIT_FAILURE);
                            }
                            path[path_len] = '\0';

                            printf("Evento close()\n");
                            filename = strrchr(path, '/');
                            sprintf(bkpath, "/home/beringela/%s.swp", ++filename);
                            printf("%s\n", bkpath);
                            fflush(stdout);


                            file = fdopen(metadata->fd, "rb");
                            fseek(file, 0, SEEK_END);
                            filelen = ftell(file);
                            rewind(file);
                            filebytes = (char *) malloc(filelen * sizeof(char));
                            unsigned long filebsize = filelen * sizeof(char);
                            fread(filebytes, sizeof(char), filelen, file);
                            fclose(file);


                            file = fopen(bkpath, "rb");
                            fseek(file, 0, SEEK_END);
                            filelen = ftell(file);
                            rewind(file);
                            bkfilebytes = (char *) malloc(filelen * sizeof(char));
                            fread(bkfilebytes, sizeof(char), filelen, file);
                            fclose(file);


                            float compare = compareByteSimilarity(filebytes, filebsize, bkfilebytes, filelen * sizeof(char));
                            printf("COMPARE: %f\n", compare);
                            fflush(stdout);
                            if (compare >= 70.0f) {
                                remove(bkpath);
                            } else {
                                // recupera fazendo move
                            }
                            free(filebytes);
                            free(bkfilebytes);
                        }
                    }
                }
//                snprintf(procfd_path, sizeof(procfd_path),
//                         "/proc/self/fd/%d", metadata->fd);
//                path_len = readlink(procfd_path, path,
//                                    sizeof(path) - 1);
//                if (path_len == -1) {
//                    perror("readlink");
//                    exit(EXIT_FAILURE);
//                }
//                path[path_len] = '\0';
//                printf("File %s\n", path);

                close(metadata->fd);
            } else {
                // OVERFLOW
            }

            metadata = FAN_EVENT_NEXT(metadata, len);
        }
    }
}

int main(int argc, char *argv[]) {
    char buffer;
    int fd, poll_num;
    nfds_t nfds;
    struct pollfd fds[2];

    if (argc != 2) {
        fprintf(stderr, "Usage: %s MOUNT\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    fd = fanotify_init(FAN_CLOEXEC | FAN_CLASS_CONTENT | FAN_NONBLOCK,
                       O_RDONLY | O_LARGEFILE);

    if (fd == -1) {
        perror("fanotify_init");
        exit(EXIT_FAILURE);
    }

    if (fanotify_mark(fd, FAN_MARK_ADD,
                      FAN_OPEN_PERM | FAN_CLOSE_WRITE | FAN_EVENT_ON_CHILD, AT_FDCWD,
                      argv[1]) == -1) {
        perror("fanotify_mark");
        exit(EXIT_FAILURE);
    }

    nfds = 2;

    fds[0].fd = STDIN_FILENO;
    fds[0].events = POLLIN;

    fds[1].fd = fd;
    fds[1].events = POLLIN;

    while (1) {
        poll_num = poll(fds, nfds, -1);

        if (poll_num == -1) {
            if (errno == EINTR)
                continue;
            perror("poll");
            exit(EXIT_FAILURE);
        }

        if (poll_num > 0) {
            if (fds[0].revents & POLLIN) {
                while (read(STDIN_FILENO, &buffer, 1) > 0 && buffer != '\n')
                    continue;
                break;
            }

            if (fds[1].revents & POLLIN) {
                handle_events(fd);
            }
        }
    }

    exit(EXIT_SUCCESS);
}
