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
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

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
                visible_pids[pid] = 1;
                count++;
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
        
        /* 尝试访问 /proc/<pid> 目录 */
        if (access(path, F_OK) == 0) {
            accessible_pids[pid] = 1;
            count++;
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

    /* 步骤3：交叉对比，发现隐藏进程 */
    printf("[*] Step 3: Cross-view comparison...\n\n");

    for (int pid = 1; pid < MAX_PID; pid++) {
        if (accessible_pids[pid] && !visible_pids[pid]) {
            char name[256];
            char status[256];

            get_process_name(pid, name, sizeof(name));
            get_process_status(pid, status, sizeof(status));

            printf("[!] HIDDEN PROCESS DETECTED:\n");
            printf("    PID:  %d\n", pid);
            printf("    Name: %s\n", name);
            printf("    %s\n\n", status);
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
