#include <linux/init.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/io.h>

MODULE_LICENSE("GPL");

char * addr;
int length;

static ssize_t pmem_write(struct file *file, const char __user *ubuf, size_t count, loff_t *ppos) 
{
    char buf[0x1000];
    copy_from_user(buf, ubuf, count);
    sscanf(buf,"%llx %x",&addr,&length);
    printk("addr: %llx, length: %x\n",addr,length);
    return count;
}

static ssize_t pmem_read(struct file *file, char __user *ubuf, size_t count, loff_t *ppos) 
{
    printk(KERN_INFO "pmem, read!\n");
    if(*ppos > 0) return 0;
    char buf[0x1000];
    
    int len = sprintf(buf,"addr: 0x%llx length: 0x%x\n",addr,length);
    char * vaddr = ioremap(addr,length);

    int i=0;
    for(i;i<length;i++){
        if((i%8==0)  && (i!=0)) len += sprintf(buf+len,"  ");
        if((i%16==0) && (i!=0)) len += sprintf(buf+len,"\n");
        len += sprintf(buf+len,"%02X ",vaddr[i] & 0xff);
    }
    len += sprintf(buf+len,"\n");

    iounmap(vaddr);
    copy_to_user(ubuf,buf,len);
    *ppos = len;
    return len;
}

const struct proc_ops myops = {
    .proc_write = pmem_write,
    .proc_read  = pmem_read
};

static int pmem_init(void)
{
    printk(KERN_INFO "pmem, init!\n");
    addr = 0;
    length = 0x20;
    proc_create("pmem",0666,NULL,&myops);
    return 0;
}
 
static void pmem_exit(void)
{
    remove_proc_entry("pmem", NULL);
    printk(KERN_INFO "pmem, exit!\n");
}
 
module_init(pmem_init);
module_exit(pmem_exit);