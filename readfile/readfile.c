#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
 
MODULE_LICENSE("GPL");
static char buf[100];
 
mm_segment_t old_fs;
static int readfile_init(void)
{
    struct file *fp;
    loff_t pos = 0;

    printk("readfile enter\n");
    fp  = filp_open("/flag", O_RDWR ,0);
    kernel_read(fp, buf, sizeof(buf), &pos);
    printk("read: %s\n", buf);
    filp_close(fp, NULL);
    return 0;
}
 
static void readfile_exit(void)
{
    printk(KERN_INFO "readfile, exit!\n");
}
 
module_init(readfile_init);
module_exit(readfile_exit);