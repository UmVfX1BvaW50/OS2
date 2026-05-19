/*
 * detect_hidden_process.c
 * 隐藏进程检测工具
 * 
 * 原理：Linux系统中进程信息可通过多种途径获取：
 *   1. /proc 文件系统：遍历 /proc/<pid>/ 目录获取进程信息
 *   2. 系统调用：通过 getpid、getppid 等获取进程关系
 *   3. /proc/<pid>/task/：获取线程信息
 * 
 * 当Rootkit从 task_struct 链表中摘除进程后，/proc 中
 * 不再出现该进程的目录。但进程仍在内核调度器中运行，
 * 其PID仍然有效。通过暴力扫描所有可能的PID值，并
 * 检查 /proc/<pid>/ 是否可访问，可以发现被隐藏的进程。
 * 
 * 具体方法：
 *   1. 遍历 /proc 获取所有可见进程PID集合A
 *   2. 暴力扫描 /proc/<1~MAX_PID>，获取所有可访问PID集合B
 *   3. 集合B - 集合A = 隐藏进程PID集合
 * 
 * 编译：gcc -o detect_hidden_process detect_hidden_process.c
 * 运行：sudo ./detect_hidden_process
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#include <time.h>

#define MAX_PID 32768  /* 默认最大PID值 */
#define MAX_PROCS 65536

/* 进程信息结构 */
typedef struct {
    int pid;
    char comm[256];
} proc_info;

/* 位图标记PID是否可见 */
static char visible_pids[MAX_PID];
static char accessible_pids[MAX_PID];
static char sched_pids[MAX_PID];
static char allocated_pids[MAX_PID];
static char reported_pids[MAX_PID];

/* 仅统计当前用户可见的进程，避免 /proc 目录隐藏策略造成误报 */
static int is_pid_owned_by_euid(int pid)
{
    char path[64];
    char line[256];
    FILE *fp;
    uid_t euid = geteuid();

    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    fp = fopen(path, "r");
    if (!fp)
        return 0;

    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "Uid:", 4) == 0) {
            unsigned int uid = 0;
            if (sscanf(line, "Uid:\t%u", &uid) == 1) {
                fclose(fp);
                return uid == (unsigned int)euid;
            }
            break;
        }
    }

    fclose(fp);
    return 0;
}

/* 从 /proc 目录获取所有可见进程PID */
int get_visible_pids(void)
{
    DIR *dir;
    struct dirent *entry;
    int count = 0;

    dir = opendir("/proc");
    if (!dir) {
        perror("opendir /proc");
        return -1;
    }

    while ((entry = readdir(dir)) != NULL) {
        /* 检查是否为数字目录（进程目录） */
        int is_pid = 1;
        for (int i = 0; entry->d_name[i]; i++) {
            if (!isdigit(entry->d_name[i])) {
                is_pid = 0;
                break;
            }
        }

        if (is_pid) {
            int pid = atoi(entry->d_name);
            if (pid > 0 && pid < MAX_PID) {
                if (is_pid_owned_by_euid(pid)) {
                    visible_pids[pid] = 1;
                    count++;
                }
            }
        }
    }

    closedir(dir);
    return count;
}

/* 暴力扫描所有可能的PID，检查 /proc/<pid>/ 是否可访问 */
int scan_accessible_pids(void)
{
    char path[64];
    int count = 0;

    for (int pid = 1; pid < MAX_PID; pid++) {
        snprintf(path, sizeof(path), "/proc/%d", pid);

        /* 尝试打开 /proc/<pid> 目录，避免 hidepid 造成误报 */
        DIR *proc_dir = opendir(path);
        if (proc_dir) {
            closedir(proc_dir);
            if (is_pid_owned_by_euid(pid)) {
                accessible_pids[pid] = 1;
                count++;
            }
        }
    }

    return count;
}

/* 获取进程的命令名 */
void get_process_name(int pid, char *name, int name_len)
{
    char path[64];
    int fd;
    ssize_t len;

    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    fd = open(path, O_RDONLY);
    if (fd < 0) {
        strncpy(name, "<unknown>", name_len);
        return;
    }

    len = read(fd, name, name_len - 1);
    close(fd);

    if (len > 0) {
        name[len] = '\0';
        /* 去除末尾换行 */
        if (name[len - 1] == '\n')
            name[len - 1] = '\0';
    } else {
        strncpy(name, "<unknown>", name_len);
    }
}

/* 获取进程的状态信息 */
void get_process_status(int pid, char *status, int status_len)
{
    char path[64];
    char buf[1024];
    int fd;
    ssize_t len;

    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    fd = open(path, O_RDONLY);
    if (fd < 0) {
        strncpy(status, "<unknown>", status_len);
        return;
    }

    len = read(fd, buf, sizeof(buf) - 1);
    close(fd);

    if (len > 0) {
        buf[len] = '\0';
        /* 提取State行 */
        char *state_line = strstr(buf, "State:");
        if (state_line) {
            char *end = strchr(state_line, '\n');
            if (end) *end = '\0';
            strncpy(status, state_line, status_len - 1);
            status[status_len - 1] = '\0';
        } else {
            strncpy(status, "<unknown>", status_len);
        }
    } else {
        strncpy(status, "<unknown>", status_len);
    }
}

static int write_string(const char *path, const char *value)
{
    int fd = open(path, O_WRONLY);
    if (fd < 0)
        return -1;
    fcntl(fd, F_SETFD, FD_CLOEXEC);
    if (write(fd, value, strlen(value)) < 0) {
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

static const char *find_tracefs_path(void)
{
    static const char *paths[] = {
        "/sys/kernel/tracing",
        "/sys/kernel/debug/tracing",
    };

    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        if (access(paths[i], R_OK | W_OK) == 0)
            return paths[i];
    }

    return NULL;
}

static int sample_sched_switch_pids(int seconds)
{
    char path[256];
    const char *tracefs = find_tracefs_path();
    int fd;
    time_t end_time;

    if (!tracefs) {
        fprintf(stderr, "[!] tracefs not accessible (need root)\n");
        return -1;
    }

    snprintf(path, sizeof(path), "%s/current_tracer", tracefs);
    write_string(path, "nop");

    snprintf(path, sizeof(path), "%s/events/sched/sched_switch/enable", tracefs);
    if (write_string(path, "1") < 0) {
        perror("enable sched_switch");
        return -1;
    }

    snprintf(path, sizeof(path), "%s/tracing_on", tracefs);
    write_string(path, "1");

    snprintf(path, sizeof(path), "%s/trace_pipe", tracefs);
    fd = open(path, O_RDONLY | O_NONBLOCK);
    if (fd < 0) {
        perror("open trace_pipe");
        snprintf(path, sizeof(path), "%s/events/sched/sched_switch/enable", tracefs);
        write_string(path, "0");
        return -1;
    }
    fcntl(fd, F_SETFD, FD_CLOEXEC);

    end_time = time(NULL) + seconds;
    while (time(NULL) < end_time) {
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        int ret = poll(&pfd, 1, 200);
        if (ret <= 0)
            continue;
        if (pfd.revents & POLLIN) {
            char buf[4096];
            ssize_t len = read(fd, buf, sizeof(buf) - 1);
            if (len <= 0)
                continue;
            buf[len] = '\0';

            char *line = buf;
            while (line && *line) {
                char *next_line = strchr(line, '\n');
                if (next_line)
                    *next_line = '\0';

                if (strstr(line, "sched_switch")) {
                    int prev_pid = -1;
                    int next_pid = -1;
                    char *prev = strstr(line, "prev_pid=");
                    char *next = strstr(line, "next_pid=");
                    if (prev)
                        sscanf(prev, "prev_pid=%d", &prev_pid);
                    if (next)
                        sscanf(next, "next_pid=%d", &next_pid);

                    if (prev_pid > 0 && prev_pid < MAX_PID)
                        sched_pids[prev_pid] = 1;
                    if (next_pid > 0 && next_pid < MAX_PID)
                        sched_pids[next_pid] = 1;
                }

                if (!next_line)
                    break;
                line = next_line + 1;
            }
        }
    }

    close(fd);
    snprintf(path, sizeof(path), "%s/events/sched/sched_switch/enable", tracefs);
    write_string(path, "0");
    return 0;
}

static int read_allocated_pids(void)
{
    FILE *fp;
    int pid;
    int count = 0;

    fp = fopen("/proc/allocated_pids", "r");
    if (!fp)
        return -1;

    while (fscanf(fp, "%d", &pid) == 1) {
        if (pid > 0 && pid < MAX_PID) {
            allocated_pids[pid] = 1;
            count++;
        }
    }

    fclose(fp);
    return count;
}

static void report_hidden_pid(int pid, const char *tag)
{
    char name[256];
    char status[256];

    if (reported_pids[pid])
        return;

    get_process_name(pid, name, sizeof(name));
    get_process_status(pid, status, sizeof(status));

    if (tag)
        printf("[!] HIDDEN PROCESS DETECTED (%s):\n", tag);
    else
        printf("[!] HIDDEN PROCESS DETECTED:\n");
    printf("    PID:  %d\n", pid);
    printf("    Name: %s\n", name);
    printf("    %s\n\n", status);

    reported_pids[pid] = 1;
}

int main(void)
{
    int visible_count, accessible_count;
    int hidden_count = 0;

    printf("=== Rootkit Hidden Process Detection Tool ===\n\n");

    /* 步骤1：获取可见进程PID集合 */
    printf("[*] Step 1: Reading visible processes from /proc...\n");
    visible_count = get_visible_pids();
    if (visible_count < 0) {
        fprintf(stderr, "Error: cannot read /proc\n");
        return 1;
    }
    printf("    Visible processes: %d\n\n", visible_count);

    /* 步骤2：暴力扫描所有可访问的PID */
    printf("[*] Step 2: Brute-force scanning /proc/<pid>/...\n");
    accessible_count = scan_accessible_pids();
    printf("    Accessible PIDs: %d\n\n", accessible_count);

    /* 步骤3：读取内核导出的PID分配表（需加载检测内核模块） */
    printf("[*] Step 3: Reading allocated PID list from kernel...\n");
    int allocated_count = read_allocated_pids();
    if (allocated_count < 0) {
        printf("    /proc/allocated_pids not available\n\n");
    } else {
        printf("    Allocated PIDs: %d\n\n", allocated_count);
    }

    /* 步骤4：通过 tracefs 采样调度事件，获取内核运行过的PID */
    printf("[*] Step 4: Sampling sched_switch via tracefs (2s)...\n");
    if (sample_sched_switch_pids(2) < 0) {
        printf("    tracefs sampling failed (need root + tracefs)\n\n");
    } else {
        printf("    Sampling done.\n\n");
    }

    if (geteuid() != 0 && accessible_count > visible_count) {
        printf("[!] Warning: /proc listing may be filtered. Run as root for accurate results.\n\n");
    }

    /* 步骤5：交叉对比，发现隐藏进程 */
    printf("[*] Step 5: Cross-view comparison...\n\n");

    for (int pid = 1; pid < MAX_PID; pid++) {
        if (accessible_pids[pid] && !visible_pids[pid]) {
            report_hidden_pid(pid, NULL);
            hidden_count++;
        }
    }

    for (int pid = 1; pid < MAX_PID; pid++) {
        if (allocated_pids[pid] && !visible_pids[pid]) {
            report_hidden_pid(pid, "pidmap");
            hidden_count++;
        }
    }

    for (int pid = 1; pid < MAX_PID; pid++) {
        if (sched_pids[pid] && !visible_pids[pid] && !accessible_pids[pid]) {
            report_hidden_pid(pid, "sched_trace");
            hidden_count++;
        }
    }

    if (hidden_count == 0) {
        printf("[+] No hidden processes detected.\n");
    } else {
        printf("[!] Total hidden processes found: %d\n", hidden_count);
    }

    printf("\n=== Detection Complete ===\n");
    return 0;
}
