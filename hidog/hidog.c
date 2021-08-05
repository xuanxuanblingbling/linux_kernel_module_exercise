#include <linux/init.h>
#include <linux/module.h>
#include <linux/reboot.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/proc_fs.h>

MODULE_LICENSE("GPL");

struct task_struct * result;
int clock;

int dog(void * argc)
{   
    while(!kthread_should_stop()){
        ssleep(1);
        printk(KERN_INFO "hidog clock: %d\n",++clock);
        if(clock>30) emergency_restart();
    }
    return 0;
}

int hidog_open(struct inode *inode, struct file *file){
    clock = 0;
    return 0;
}

const struct proc_ops myops = {
    .proc_open = hidog_open
};

static int hidog_init(void)
{
    printk(KERN_INFO "hidog, init!\n");
    result = kthread_create_on_node(dog, NULL, -1, "hidog");
    wake_up_process(result);
    proc_create("hidog",0666,NULL,&myops);
    return 0;
}
 
static void hidog_exit(void)
{
    kthread_stop(result);
    remove_proc_entry("hidog", NULL);
    printk(KERN_INFO "hidog, exit!\n");
}
 
module_init(hidog_init);
module_exit(hidog_exit);