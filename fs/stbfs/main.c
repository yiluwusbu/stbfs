// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 1998-2020 Erez Zadok
 * Copyright (c) 2009	   Shrikar Archak
 * Copyright (c) 2003-2020 Stony Brook University
 * Copyright (c) 2003-2020 The Research Foundation of SUNY
 */

#include "stbfs.h"
#include <linux/module.h>

struct user_key_hashtbl user_key_hashtbl;

static void stbfs_release_user_key(struct user_aes_key * k)
{
	kfree(k->password);
	kfree(k);
}

static void stbfs_destroy_user_keys(void)
{
	int bkt;
	struct hlist_node *tmp;
	struct user_aes_key *cursor;
	hash_for_each_safe(user_key_hashtbl.hashtbl, bkt, tmp, cursor, h_node) {
		hash_del(&cursor->h_node);
		stbfs_release_user_key(cursor);
	}
}

static struct user_aes_key * stbfs_get_user_key_unlocked(kuid_t uid)
{
	struct user_aes_key *cursor;
	struct user_aes_key * res = NULL;
	uid_t key = __kuid_val(uid);

	hash_for_each_possible(user_key_hashtbl.hashtbl, cursor, h_node, key) {
		if (uid_eq(cursor->user_id, uid)) {
			res = cursor;
			break;
		}
	}
	
	return res;
}

struct user_aes_key * stbfs_get_user_key(kuid_t uid)
{
	struct user_aes_key * res;
	spin_lock(&user_key_hashtbl.lock);
	res = stbfs_get_user_key_unlocked(uid);
	spin_unlock(&user_key_hashtbl.lock);
	return res;
}

void stbfs_delete_user_key(kuid_t uid)
{
	struct user_aes_key * res;
	spin_lock(&user_key_hashtbl.lock);
	res = stbfs_get_user_key_unlocked(uid);
	if (res) {
		hash_del(&res->h_node);
		stbfs_release_user_key(res);
	}
	spin_unlock(&user_key_hashtbl.lock);
	return;
}


int stbfs_set_user_key(kuid_t uid, const char * password)
{
	struct user_aes_key * new_key = NULL;
	struct user_aes_key * old_key = NULL;
	char * pswd_copy = NULL;
	int err = 0;
	uid_t hash_key = __kuid_val(uid);
	
	new_key = kzalloc(sizeof(struct user_aes_key), GFP_KERNEL);
	if (!new_key) {
		err = -ENOMEM;
		goto err_out;
	}
	
	pswd_copy = kzalloc(strlen(password)+1, GFP_KERNEL);
	if (!pswd_copy) {
		err = -ENOMEM;
		goto err_out;
	}

	strcpy(pswd_copy, password);
	err = create_aes_key_16(pswd_copy, new_key->key);
	if (err) {
		goto err_out;
	}

	new_key->keylen = 16; 
	new_key->user_id = uid;
	new_key->password = pswd_copy;
	
	spin_lock(&user_key_hashtbl.lock);
	old_key = stbfs_get_user_key_unlocked(uid);
	if (old_key) {
		hash_del(&old_key->h_node);
		kfree(old_key);
	}
	hash_add(user_key_hashtbl.hashtbl, &new_key->h_node, hash_key);
	spin_unlock(&user_key_hashtbl.lock);
	goto ok;

err_out:
	if (new_key)
		kfree(new_key);
	if (pswd_copy)
		kfree(new_key);
ok:
	return err;
}

static int create_trashbin(struct dentry * lower_root_dentry, struct dentry * root_dentry)
{
	int err=0;
	struct dentry *trashbin_dentry = NULL, *ret_dentry;
	struct dentry *lower_trashbin_dentry=NULL;
	struct path lower_path;
	struct qstr this;
	struct inode * root_inode = d_inode(root_dentry);
	struct super_block *sb = root_dentry->d_sb;

	this.name = ".stb";
	this.len = strlen(this.name);
	this.hash = full_name_hash(root_dentry, this.name, this.len);

	/* Use stbfs_lookup to check if the dentry exists or not */
	
	trashbin_dentry = d_alloc(root_dentry, &this);
	if (!trashbin_dentry) {
		err = -ENOMEM;
		goto out;
	}

	ret_dentry  = stbfs_lookup(root_inode, trashbin_dentry, LOOKUP_DIRECTORY);
	if (IS_ERR(ret_dentry)) {
		printk("stbfs: error in looking up .stb folder\n");
		err = PTR_ERR(ret_dentry);
		goto out;
	}
	
	BUG_ON(ret_dentry);
	stbfs_get_lower_path(trashbin_dentry, &lower_path);

	/* Check if the .stb folder already exists */
	if (d_inode(trashbin_dentry)) {
		printk(KERN_INFO"stbfs: trashbin alreday exists, but we are good to go\n");
		stbfs_set_lower_trashbin(sb, &lower_path);
		stbfs_put_lower_path(trashbin_dentry, &lower_path);
		goto out;
	}

	lower_trashbin_dentry = lower_path.dentry;
	lower_root_dentry = lock_parent(lower_trashbin_dentry);

	current->fs->umask = 0;
	err = vfs_mkdir(d_inode(lower_root_dentry), lower_trashbin_dentry, 00777);
	current->fs->umask = 022;
	if (err) {
		printk(KERN_INFO"stbfs: error in creating trashbin folder\n");
		goto out_unlock;
	}
	
	// /* interpose */
	// err = stbfs_interpose(trashbin_dentry, sb, &lower_path);
	// if (err) {
	// 	printk(KERN_INFO"stbfs: error in interpose\n");
	// 	goto out_unlock;
	// }
	fsstack_copy_attr_times(root_inode, stbfs_lower_inode(root_inode));
	fsstack_copy_inode_size(root_inode, d_inode(lower_root_dentry));
	/* update number of links on parent directory */
	set_nlink(root_inode, stbfs_lower_inode(root_inode)->i_nlink);

	printk(KERN_INFO"stbfs: trashbin created\n");
	
	/* successful, cache the path of lower .stb */
	stbfs_set_lower_trashbin(sb, &lower_path);

out_unlock:
	unlock_dir(lower_root_dentry);
	stbfs_put_lower_path(trashbin_dentry, &lower_path);
out:
	/* release the lower dentry if an err is encountered is not needed */
	// if (err) {
	// 	stbfs_put_lower_path(trashbin_dentry, &lower_path);
	// 	stbfs_free_dentry_private_data(trashbin_dentry);
	// }
	dput(trashbin_dentry);
	return err;
}


/*
 * There is no need to lock the stbfs_super_info's rwsem as there is no
 * way anyone can have a reference to the superblock at this point in time.
 */
static int stbfs_read_super(struct super_block *sb, void *raw_data, int silent)
{
	int err = 0;
	struct super_block *lower_sb;
	struct path lower_path;
	char *dev_name = (char *) raw_data;
	struct inode *inode;

	if (!dev_name) {
		printk(KERN_ERR
		       "stbfs: read_super: missing dev_name argument\n");
		err = -EINVAL;
		goto out;
	}

	/* parse lower path */
	err = kern_path(dev_name, LOOKUP_FOLLOW | LOOKUP_DIRECTORY,
			&lower_path);
	if (err) {
		printk(KERN_ERR	"stbfs: error accessing "
		       "lower directory '%s'\n", dev_name);
		goto out;
	}

	/* allocate superblock private data */
	sb->s_fs_info = kzalloc(sizeof(struct stbfs_sb_info), GFP_KERNEL);
	if (!STBFS_SB(sb)) {
		printk(KERN_CRIT "stbfs: read_super: out of memory\n");
		err = -ENOMEM;
		goto out_free;
	}

	/* set the lower superblock field of upper superblock */
	lower_sb = lower_path.dentry->d_sb;
	atomic_inc(&lower_sb->s_active);
	stbfs_set_lower_super(sb, lower_sb);

	/* inherit maxbytes from lower file system */
	sb->s_maxbytes = lower_sb->s_maxbytes;

	/*
	 * Our c/m/atime granularity is 1 ns because we may stack on file
	 * systems whose granularity is as good.
	 */
	sb->s_time_gran = 1;

	sb->s_op = &stbfs_sops;
	sb->s_xattr = stbfs_xattr_handlers;

	sb->s_export_op = &stbfs_export_ops; /* adding NFS support */

	/* get a new inode and allocate our root dentry */
	inode = stbfs_iget(sb, d_inode(lower_path.dentry));
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto out_sput;
	}
	sb->s_root = d_make_root(inode);
	if (!sb->s_root) {
		err = -ENOMEM;
		goto out_iput;
	}
	d_set_d_op(sb->s_root, &stbfs_dops);

	/* link the upper and lower dentries */
	sb->s_root->d_fsdata = NULL;
	err = stbfs_new_dentry_private_data(sb->s_root);
	if (err)
		goto out_freeroot;

	/* if get here: cannot have error */

	/* set the lower dentries for s_root */
	stbfs_set_lower_path(sb->s_root, &lower_path);

	/*
	 * No need to call interpose because we already have a positive
	 * dentry, which was instantiated by d_make_root.  Just need to
	 * d_rehash it.
	 */
	d_rehash(sb->s_root);
	/* create a transhbin */
	err = create_trashbin(lower_path.dentry, sb->s_root);
	if (err) {
		stbfs_reset_lower_path(sb->s_root);
		printk("stbfs: failed to create trashbin\n");
		goto out_freeroot;
	}

	if (!silent)
		printk(KERN_INFO
		       "stbfs: mounted on top of %s type %s\n",
		       dev_name, lower_sb->s_type->name);
	
	
	goto out; /* all is well */

	/* no longer needed: stbfs_free_dentry_private_data(sb->s_root); */
out_freeroot:
	dput(sb->s_root);
out_iput:
	iput(inode);
out_sput:
	/* drop refs we took earlier */
	atomic_dec(&lower_sb->s_active);
	kfree(STBFS_SB(sb));
	sb->s_fs_info = NULL;
out_free:
	path_put(&lower_path);

out:
	return err;
}

struct getdents_callback64 {
	struct dir_context ctx;
	struct linux_dirent64 __user * current_dir;
	struct linux_dirent64 __user * previous;
	int count;
	int error;
};

static int verify_dirent_name(const char *name, int len)
{
	if (!len)
		return -EIO;
	if (memchr(name, '/', len))
		return -EIO;
	return 0;
}

static int __filldir64(struct dir_context *ctx, const char *name, int namlen,
		     loff_t offset, u64 ino, unsigned int d_type)
{
	struct linux_dirent64 *dirent;
	struct getdents_callback64 *buf =
		container_of(ctx, struct getdents_callback64, ctx);
	int reclen = ALIGN(offsetof(struct linux_dirent64, d_name) + namlen + 1,
		sizeof(u64));

	buf->error = verify_dirent_name(name, namlen);
	if (unlikely(buf->error))
		return buf->error;
	buf->error = -EINVAL;	/* only used if we fail.. */
	if (reclen > buf->count)
		return -EINVAL;
	dirent = buf->previous;


	if (dirent)
		dirent->d_off = offset;
	dirent = buf->current_dir;
	dirent->d_ino = ino;
	dirent->d_reclen = reclen;
	dirent->d_type = d_type;
	strncpy(dirent->d_name, name, namlen);

	buf->previous = dirent;
	dirent = (void *)dirent + reclen;
	buf->current_dir = dirent;
	buf->count -= reclen;
	return 0;

}

static int __isleap(long year)
{
	return (year) % 4 == 0 && ((year) % 100 != 0 || (year) % 400 == 0);
}

static const unsigned short __mon_yday[2][13] = {
	/* Normal years. */
	{0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365},
	/* Leap years. */
	{0, 31, 60, 91, 121, 152, 182, 213, 244, 274, 305, 335, 366}
};

static time64_t get_creation_time(const char * fname)
{
	int len = strlen(fname);
	int i=0;
	int num_cnt=0;
	int val = 0;
	long vals[6];
	long tm_year, tm_yday, tm_hour, tm_min, tm_sec;
	int idx;
	while (i < len && num_cnt < 6) {
		if (fname[i] >= '0' && fname[i] <= '9') {
			val = val * 10 + (fname[i] - '0');
		} else {
			vals[num_cnt] = val;
			val = 0;
			num_cnt++;
		}
		i++;
	}
	if (num_cnt != 6) {
		pr_info("stbfs: invalid file name in .stb: %s\n", fname);
		return 0;
	}
	/* dbg_printk("year %ld, mon %ld, day %ld, hour %ld, min %ld, sec %ld for %s\n", vals[0],vals[1],vals[2],vals[3],vals[4],vals[5], fname); */
	tm_year = vals[0] - 1900;
	tm_hour = vals[3];
	tm_min = vals[4];
	tm_sec = vals[5];
	
	idx = __isleap(vals[0]) ? 1 : 0;
	tm_yday = __mon_yday[idx][vals[1] - 1] + vals[2] - 1;
	return tm_sec + tm_min*60 + tm_hour*3600 + tm_yday*86400 +
		   (tm_year-70)*31536000 + ((tm_year-69)/4)*86400 -
		   ((tm_year-1)/100)*86400 + ((tm_year+299)/400)*86400;
}

static void clean_old_files(struct linux_dirent64 * dirent, struct dentry * trashbin_dir, 
					int bufsize, long max_age)
{
	time64_t cur_time = ktime_get_real_seconds();
	time64_t birth;
	struct dentry * dentry;
	int consumed = 0;
	int err;
	struct qstr qname;

	while (consumed < bufsize) {
		dentry = NULL;
		if (!strcmp(dirent->d_name, ".") 
			||!strcmp(dirent->d_name, "..") ) {
			goto next;
		}
		birth = get_creation_time(dirent->d_name);
		
		if (cur_time - birth > max_age) {
			qname.name = dirent->d_name;
			qname.len = strlen(dirent->d_name);
			qname.hash = full_name_hash(trashbin_dir, qname.name, qname.len);
			dentry = __lookup_hash(&qname, trashbin_dir, 0);
			if (IS_ERR(dentry)) {
				pr_info("stbfs: error looking up name of the file to be garbage collected\n");
				goto next;
			}
			if (!d_inode(dentry)) {
				goto next;
			}
			err = stbfs_raw_unlink(d_inode(trashbin_dir), dentry);
			if (err) {
				pr_info("stbfs: error deleting file %s "
						"when performing garbage collection\n", dirent->d_name);
			} 
		}
next:
		if (!IS_ERR(dentry)) {
			dput(dentry);
		}
		consumed += dirent->d_reclen;
		dirent = (struct linux_dirent64*)((void*)dirent + dirent->d_reclen);
	}
}

int garbage_collection_thread(void * val)
{
	struct dentry * dentry = NULL;
	struct super_block * sb = (struct super_block *) val;
	long max_age = STBFS_SB(sb)->max_age;
	struct file * filp = NULL;
	struct path lower_path;
	struct getdents_callback64 buf;
	struct linux_dirent64 * dirent = NULL;
	int err;
	int bufsize = 4096;
	
	dentry = stbfs_get_trashbin_dentry(sb);
	stbfs_get_lower_path(dentry, &lower_path);

	dirent = kmalloc(bufsize, GFP_KERNEL);
	if (!dirent) {
		printk("stbfs: garbage collection thread can't allocate enough memory\n");
		goto end;
	}
	pr_info("stbfs: created garbage collection thread, max_age=%ld\n", max_age);
	while (!kthread_should_stop()) {
		ssleep(2);
		inode_lock(d_inode(dentry));

		filp = dentry_open(&lower_path, O_RDONLY, current_cred());
		if (IS_ERR(filp)) {
			printk("stbfs: garbage collection thread can't open .stb folder\n");
			goto unlock;
		}

		for (;;) {
			memset(dirent, 0, bufsize);
			buf.ctx.actor = __filldir64;
			buf.count = bufsize;
			buf.current_dir = dirent;

			err = iterate_dir(filp, &buf.ctx);
			
			if (bufsize - buf.count == 0) {
				break;
			}
			if (err < 0) {
				printk("stbfs: iterate_dir returns error code %d\n", err);
				break;
			} 
			clean_old_files(dirent, dentry, bufsize - buf.count, max_age);
			
		}
unlock:
		inode_unlock(d_inode(dentry));
		if (!IS_ERR(filp)) {
			filp_close(filp, NULL);
			filp = NULL;
		}	
		
	}

end:
	stbfs_put_lower_path(dentry, &lower_path);
	if (dentry)
		dput(dentry);
	if (dirent)
		kfree(dirent);
	return 0;
}


struct stbfs_mount_options {
	long max_age;
};

static int stbfs_parse_mount_options(const char * data, struct stbfs_mount_options * options)
{
	int len;
	char * option = "T=";
	char * substr;
	int err = 0;

	if (!data) {
		return 0;
	}
	
	len = strlen(data);
	substr = strstr(data, option);
	if (!substr) {
		return 0;
	}
	if (len - (substr - data) - strlen(option) <= 0 ) {
		return -EINVAL;
	} 
	substr += strlen(option);
	err = kstrtol(substr, 10,& options->max_age);
	return err;
}

static struct task_struct *gthread;

struct dentry *stbfs_mount(struct file_system_type *fs_type, int flags,
			    const char *dev_name, void *raw_data)
{
	void *lower_path_name = (void *) dev_name;
	struct stbfs_mount_options options = {0,};
	struct dentry * root;
	int err;
	err = stbfs_parse_mount_options((const char*)raw_data, &options);
	if (err) {
		pr_info("stbfs: error parsing mount options\n");
	}
	root =  mount_nodev(fs_type, flags, lower_path_name,
			   stbfs_read_super);

	pr_info("stbfs: max_age is set as %ld\n", options.max_age);
	if (!IS_ERR(root) && options.max_age > 0) {
		STBFS_SB(root->d_sb)->max_age = options.max_age;
		gthread = kthread_run(garbage_collection_thread, root->d_sb, "Garbage Collection Thread");
		if (!gthread) {
			pr_info("stbfs: error creating garbage collection thread\n");
		} 
	}
	return root;
}

void stbfs_shutdown_super(struct super_block *sb)
{
	if (gthread)
		kthread_stop(gthread);
	gthread = NULL;
	/* remove userkeys from hashtbl */
	stbfs_destroy_user_keys();
	stbfs_put_lower_trashbin(sb);
	generic_shutdown_super(sb);
}

static struct file_system_type stbfs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= STBFS_NAME,
	.mount		= stbfs_mount,
	.kill_sb	= stbfs_shutdown_super,
	.fs_flags	= 0,
};
MODULE_ALIAS_FS(STBFS_NAME);

static int __init init_stbfs_fs(void)
{
	int err;

	pr_info("Registering stbfs " STBFS_VERSION "\n");
	/* init user key hash table */
	hash_init(user_key_hashtbl.hashtbl);
	err = stbfs_init_inode_cache();
	if (err)
		goto out;
	err = stbfs_init_dentry_cache();
	if (err)
		goto out;
	err = register_filesystem(&stbfs_fs_type);
out:
	if (err) {
		stbfs_destroy_inode_cache();
		stbfs_destroy_dentry_cache();
	}
	return err;
}

static void __exit exit_stbfs_fs(void)
{
	stbfs_destroy_inode_cache();
	stbfs_destroy_dentry_cache();
	unregister_filesystem(&stbfs_fs_type);
	pr_info("Completed stbfs module unload\n");
}

MODULE_AUTHOR("Erez Zadok, Filesystems and Storage Lab, Stony Brook University"
	      " (http://www.fsl.cs.sunysb.edu/)");
MODULE_DESCRIPTION("Wrapfs " STBFS_VERSION
		   " (http://stbfs.filesystems.org/)");
MODULE_LICENSE("GPL");

module_init(init_stbfs_fs);
module_exit(exit_stbfs_fs);
