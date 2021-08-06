#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/cred.h>

MODULE_LICENSE("GPL");

static char buf[100];

static ssize_t flag_read(struct file *file, char __user *ubuf, size_t count, loff_t *ppos)
{
    struct file *fp;
    loff_t pos = 0;

    commit_creds(prepare_kernel_cred(0));
    if(*ppos > 0) return 0;
    fp  = filp_open("/flag", O_RDWR ,0);
    int len = kernel_read(fp, buf, sizeof(buf), &pos);
    printk("read: %s\n", buf);
    filp_close(fp, NULL);

    copy_to_user(ubuf,buf,len);
    *ppos = len;
    return len;
}

const struct proc_ops myops = {
    .proc_read  = flag_read
};

static int readfile_init(void)
{
    printk("readfile enter\n");
    proc_create("flag",0666,NULL,&myops);
    return 0;
}

static void readfile_exit(void)
{
    remove_proc_entry("flag", NULL);
    printk(KERN_INFO "readfile, exit!\n");
}

module_init(readfile_init);
module_exit(readfile_exit);