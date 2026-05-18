/*
 * detect_hidden_module.c
 * 隐藏内核模块检测工具
 * 
 * 原理：Linux内核通过两种不同的机制记录已加载模块：
 *   1. 内核模块链表（modules list）：/proc/modules 读取此链表
 *   2. /sys/module/ 目录：内核为每个模块创建对应的kobject，
 *      在sysfs中表现为目录
 * 
 * 当Rootkit通过 list_del() 从模块链表中摘除模块后，
 * /proc/modules 不再显示该模块，但 /sys/module/ 中的
 * kobject目录仍然存在。通过交叉对比两个信息源，即可
 * 发现被隐藏的内核模块。
 * 
 * 编译：gcc -o detect_hidden_module detect_hidden_module.c
 * 运行：sudo ./detect_hidden_module
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <ctype.h>

#define MAX_MODULES 512
#define MAX_NAME_LEN 256

/* 从 /proc/modules 读取可见模块列表 */
int read_proc_modules(char modules[][MAX_NAME_LEN], int max_count)
{
    FILE *fp;
    char line[512];
    int count = 0;

    fp = fopen("/proc/modules", "r");
    if (!fp) {
        perror("fopen /proc/modules");
        return -1;
    }

    while (fgets(line, sizeof(line), fp) && count < max_count) {
        /* /proc/modules 每行格式：模块名 大小 依赖数 依赖列表 ... */
        char *space = strchr(line, ' ');
        if (space) {
            int len = space - line;
            if (len >= MAX_NAME_LEN) len = MAX_NAME_LEN - 1;
            strncpy(modules[count], line, len);
            modules[count][len] = '\0';
            count++;
        }
    }

    fclose(fp);
    return count;
}

/* 从 /sys/module/ 读取所有模块目录 */
int read_sys_modules(char modules[][MAX_NAME_LEN], int max_count)
{
    DIR *dir;
    struct dirent *entry;
    int count = 0;

    dir = opendir("/sys/module/");
    if (!dir) {
        perror("opendir /sys/module/");
        return -1;
    }

    while ((entry = readdir(dir)) != NULL && count < max_count) {
        /* 跳过 . 和 .. 目录 */
        if (strcmp(entry->d_name, ".") == 0 || 
            strcmp(entry->d_name, "..") == 0)
            continue;

        /* 只关注目录项 */
        if (entry->d_type == DT_DIR || entry->d_type == DT_LNK) {
            strncpy(modules[count], entry->d_name, MAX_NAME_LEN - 1);
            modules[count][MAX_NAME_LEN - 1] = '\0';
            count++;
        }
    }

    closedir(dir);
    return count;
}

/* 在模块列表中查找指定模块名 */
int find_in_list(char name[], char list[][MAX_NAME_LEN], int count)
{
    for (int i = 0; i < count; i++) {
        if (strcmp(name, list[i]) == 0)
            return 1;
    }
    return 0;
}

int main(void)
{
    char proc_modules[MAX_MODULES][MAX_NAME_LEN];
    char sys_modules[MAX_MODULES][MAX_NAME_LEN];
    int proc_count, sys_count;
    int hidden_count = 0;

    printf("=== Rootkit Hidden Kernel Module Detection Tool ===\n\n");

    /* 读取两个信息源 */
    proc_count = read_proc_modules(proc_modules, MAX_MODULES);
    if (proc_count < 0) {
        fprintf(stderr, "Error: cannot read /proc/modules\n");
        return 1;
    }

    sys_count = read_sys_modules(sys_modules, MAX_MODULES);
    if (sys_count < 0) {
        fprintf(stderr, "Error: cannot read /sys/module/\n");
        return 1;
    }

    printf("[*] Modules in /proc/modules: %d\n", proc_count);
    printf("[*] Modules in /sys/module/:  %d\n", sys_count);
    printf("\n");

    /* 交叉对比：在 /sys/module/ 中存在但 /proc/modules 中不存在的模块 */
    printf("[*] Checking for hidden modules...\n\n");

    for (int i = 0; i < sys_count; i++) {
        if (!find_in_list(sys_modules[i], proc_modules, proc_count)) {
            printf("[!] HIDDEN MODULE DETECTED: %s\n", sys_modules[i]);
            printf("    Present in /sys/module/ but NOT in /proc/modules\n\n");
            hidden_count++;
        }
    }

    if (hidden_count == 0) {
        printf("[+] No hidden kernel modules detected.\n");
    } else {
        printf("[!] Total hidden modules found: %d\n", hidden_count);
    }

    printf("\n=== Detection Complete ===\n");
    return 0;
}
