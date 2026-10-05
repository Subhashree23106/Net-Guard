#include <linux/module.h>
#include <linux/export-internal.h>
#include <linux/compiler.h>

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



static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0xfbe7861b, "memcpy" },
	{ 0xcb8b6ec6, "kfree" },
	{ 0x3d23d043, "seq_lseek" },
	{ 0x10a56acb, "__netlink_kernel_create" },
	{ 0xf94f657a, "remove_proc_subtree" },
	{ 0x11f4259a, "_raw_spin_lock_irqsave" },
	{ 0x0bfe5af7, "netlink_broadcast_filtered" },
	{ 0xd272d446, "__fentry__" },
	{ 0xd272d446, "dump_stack" },
	{ 0xe8213e80, "_printk" },
	{ 0xbd03ed67, "__ref_stack_chk_guard" },
	{ 0x0e675b65, "___ratelimit" },
	{ 0xd272d446, "__stack_chk_fail" },
	{ 0xd710adbf, "__kmalloc_large_noprof" },
	{ 0xd8c449b9, "nf_register_net_hooks" },
	{ 0x51683328, "__alloc_skb" },
	{ 0x7128dad5, "init_net" },
	{ 0xd272d446, "synchronize_rcu" },
	{ 0xd272d446, "__rcu_read_unlock" },
	{ 0x66f7b997, "sk_skb_reason_drop" },
	{ 0x0e9568fd, "netlink_unicast" },
	{ 0xbd03ed67, "random_kmalloc_seed" },
	{ 0x9aa6980d, "mutex_lock" },
	{ 0xc609ff70, "strncpy" },
	{ 0xd127cf6a, "netlink_kernel_release" },
	{ 0x4f1e5fd0, "__list_del_entry_valid_or_report" },
	{ 0x680628e7, "ktime_get_real_ts64" },
	{ 0x034f413b, "nf_unregister_net_hooks" },
	{ 0x444885a7, "_raw_spin_unlock_irqrestore" },
	{ 0x4c608d55, "proc_mkdir" },
	{ 0x0e9cab28, "memset" },
	{ 0xd272d446, "__x86_return_thunk" },
	{ 0x1d8ab39e, "seq_read" },
	{ 0x9aa6980d, "mutex_unlock" },
	{ 0x30eb81ed, "__dynamic_pr_debug" },
	{ 0x7a5d3ece, "__kmalloc_cache_noprof" },
	{ 0xf0f05721, "seq_printf" },
	{ 0x1b007d83, "single_release" },
	{ 0xe35a10d5, "param_ops_int" },
	{ 0x3cfb8110, "single_open" },
	{ 0x5f878bdd, "kmalloc_caches" },
	{ 0xdc352a3b, "__list_add_valid_or_report" },
	{ 0x54aae3b9, "__nlmsg_put" },
	{ 0xd337569d, "skb_copy_bits" },
	{ 0xd272d446, "__rcu_read_lock" },
	{ 0x366d11a2, "proc_create" },
	{ 0x40a621c5, "snprintf" },
	{ 0xb0c84d61, "module_layout" },
};

static const u32 ____version_ext_crcs[]
__used __section("__version_ext_crcs") = {
	0xfbe7861b,
	0xcb8b6ec6,
	0x3d23d043,
	0x10a56acb,
	0xf94f657a,
	0x11f4259a,
	0x0bfe5af7,
	0xd272d446,
	0xd272d446,
	0xe8213e80,
	0xbd03ed67,
	0x0e675b65,
	0xd272d446,
	0xd710adbf,
	0xd8c449b9,
	0x51683328,
	0x7128dad5,
	0xd272d446,
	0xd272d446,
	0x66f7b997,
	0x0e9568fd,
	0xbd03ed67,
	0x9aa6980d,
	0xc609ff70,
	0xd127cf6a,
	0x4f1e5fd0,
	0x680628e7,
	0x034f413b,
	0x444885a7,
	0x4c608d55,
	0x0e9cab28,
	0xd272d446,
	0x1d8ab39e,
	0x9aa6980d,
	0x30eb81ed,
	0x7a5d3ece,
	0xf0f05721,
	0x1b007d83,
	0xe35a10d5,
	0x3cfb8110,
	0x5f878bdd,
	0xdc352a3b,
	0x54aae3b9,
	0xd337569d,
	0xd272d446,
	0x366d11a2,
	0x40a621c5,
	0xb0c84d61,
};
static const char ____version_ext_names[]
__used __section("__version_ext_names") =
	"memcpy\0"
	"kfree\0"
	"seq_lseek\0"
	"__netlink_kernel_create\0"
	"remove_proc_subtree\0"
	"_raw_spin_lock_irqsave\0"
	"netlink_broadcast_filtered\0"
	"__fentry__\0"
	"dump_stack\0"
	"_printk\0"
	"__ref_stack_chk_guard\0"
	"___ratelimit\0"
	"__stack_chk_fail\0"
	"__kmalloc_large_noprof\0"
	"nf_register_net_hooks\0"
	"__alloc_skb\0"
	"init_net\0"
	"synchronize_rcu\0"
	"__rcu_read_unlock\0"
	"sk_skb_reason_drop\0"
	"netlink_unicast\0"
	"random_kmalloc_seed\0"
	"mutex_lock\0"
	"strncpy\0"
	"netlink_kernel_release\0"
	"__list_del_entry_valid_or_report\0"
	"ktime_get_real_ts64\0"
	"nf_unregister_net_hooks\0"
	"_raw_spin_unlock_irqrestore\0"
	"proc_mkdir\0"
	"memset\0"
	"__x86_return_thunk\0"
	"seq_read\0"
	"mutex_unlock\0"
	"__dynamic_pr_debug\0"
	"__kmalloc_cache_noprof\0"
	"seq_printf\0"
	"single_release\0"
	"param_ops_int\0"
	"single_open\0"
	"kmalloc_caches\0"
	"__list_add_valid_or_report\0"
	"__nlmsg_put\0"
	"skb_copy_bits\0"
	"__rcu_read_lock\0"
	"proc_create\0"
	"snprintf\0"
	"module_layout\0"
;

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "70FE89E9E3C6FDBFF593901");
