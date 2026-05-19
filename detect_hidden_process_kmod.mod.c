#include <linux/module.h>
#define INCLUDE_VERMAGIC
#include <linux/build-salt.h>
#include <linux/elfnote-lto.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

BUILD_SALT;
BUILD_LTO_INFO;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif

static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0x2b4dfa79, "module_layout" },
	{ 0x53363e9, "single_release" },
	{ 0x11b64b24, "seq_lseek" },
	{ 0x223983ec, "seq_read" },
	{ 0x5c5f6242, "remove_proc_entry" },
	{ 0x92997ed8, "_printk" },
	{ 0x367b5b62, "proc_create" },
	{ 0xd0da656b, "__stack_chk_fail" },
	{ 0x2d5f69b3, "rcu_read_unlock_strict" },
	{ 0xc57c48a3, "idr_get_next" },
	{ 0x7709af1b, "init_pid_ns" },
	{ 0xc876a99f, "seq_printf" },
	{ 0x5b8239ca, "__x86_return_thunk" },
	{ 0x10ea38cd, "single_open" },
	{ 0xbdfb6dbb, "__fentry__" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "D20E9951015C18BE7009A5B");
