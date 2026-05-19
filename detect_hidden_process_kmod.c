/*
 * detect_hidden_process_kmod.c
 * Kernel helper to expose allocated PIDs via /proc/allocated_pids
 *
 * This allows user-space detection to compare allocated PID map
 * with /proc visibility when rootkits remove tasks from task lists
 * and PID hash tables.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/pid_namespace.h>
#include <linux/idr.h>
#include <linux/rcupdate.h>

#define PROC_NAME "allocated_pids"

static int allocated_pids_show(struct seq_file *m, void *v)
{
    struct pid *pid;
    int id = 0;

    rcu_read_lock();
    idr_for_each_entry(&init_pid_ns.idr, pid, id) {
        seq_printf(m, "%d\n", id);
    }
    rcu_read_unlock();

    return 0;
}

static int allocated_pids_open(struct inode *inode, struct file *file)
{
    return single_open(file, allocated_pids_show, NULL);
}

static const struct proc_ops allocated_pids_ops = {
    .proc_open = allocated_pids_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

static int __init allocated_pids_init(void)
{
    if (!proc_create(PROC_NAME, 0444, NULL, &allocated_pids_ops)) {
        pr_err("allocated_pids: failed to create /proc/%s\n", PROC_NAME);
        return -ENOMEM;
    }

    pr_info("allocated_pids: loaded\n");
    return 0;
}

static void __exit allocated_pids_exit(void)
{
    remove_proc_entry(PROC_NAME, NULL);
    pr_info("allocated_pids: unloaded\n");
}

module_init(allocated_pids_init);
module_exit(allocated_pids_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Experiment");
MODULE_DESCRIPTION("Expose allocated PIDs for hidden-process detection");
