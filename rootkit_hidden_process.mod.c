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
	{ 0xae2ae519, "param_ops_int" },
	{ 0xa74d7881, "__put_task_struct" },
	{ 0x5b8239ca, "__x86_return_thunk" },
	{ 0x6091797f, "synchronize_rcu" },
	{ 0x1f13a2b5, "get_task_pid" },
	{ 0x296695f, "refcount_warn_saturate" },
	{ 0xe69331a8, "put_pid" },
	{ 0x2d5f69b3, "rcu_read_unlock_strict" },
	{ 0xb19b8760, "pid_task" },
	{ 0x9af830a1, "find_get_pid" },
	{ 0x92997ed8, "_printk" },
	{ 0xbdfb6dbb, "__fentry__" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "640AEFFED0507FB37836E4E");
