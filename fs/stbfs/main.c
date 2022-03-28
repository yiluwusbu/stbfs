// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 1998-2020 Erez Zadok
 * Copyright (c) 2009	   Shrikar Archak
 * Copyright (c) 2003-2020 Stony Brook University
 * Copyright (c) 2003-2020 The Research Foundation of SUNY
 */

#include "stbfs.h"
#include <linux/module.h>

static int create_trashbin(struct path * lower_root_path, struct dentry * root_dentry)
{
	int err=0;
	struct vfsmount *lower_root_mnt;
	struct dentry *lower_root_dentry = NULL;
	struct dentry *trashbin_dentry = NULL;
	struct dentry *lower_trashbin_dentry=NULL;
	struct path lower_path;
	struct qstr this;
	struct inode * root_inode = d_inode(root_dentry);

	lower_root_dentry = lower_root_path->dentry;
	lower_root_mnt = lower_root_path->mnt;

	/* Use vfs_path_lookup to check if the dentry exists or not */
	err = vfs_path_lookup(lower_root_dentry, lower_root_mnt, ".stb", 0,
			      &lower_path);

	if (!err) {
		printk(KERN_INFO"stbfs: trashbin alreday exists\n");
		return 0;
	}
		
	if (err != -ENOENT) {
		printk(KERN_INFO"stbfs: error when looking up path .stb\n");
		return err;
	}

	/* error == -ENOENT, we need to create the trashbin folder */
	this.name = ".stb";
	this.len = strlen(this.name);
	this.hash = full_name_hash(lower_root_dentry, this.name, this.len);

	lower_trashbin_dentry = d_alloc(lower_root_dentry, &this);
	if (!lower_trashbin_dentry) {
		err = -ENOMEM;
		goto out;
	}
	d_set_d_op(lower_trashbin_dentry, &stbfs_dops);
	d_add(lower_trashbin_dentry, NULL); /* instantiate and hash */

	this.hash = full_name_hash(root_dentry, this.name, this.len);
	trashbin_dentry = d_alloc(root_dentry, &this);
	if (!trashbin_dentry) {
		err = -ENOMEM;
		goto out_free_lower_dentry;
	}

	err = stbfs_new_dentry_private_data(trashbin_dentry);
	if (err) {
		printk(KERN_INFO"stbfs: error in allocating dentry_private_data\n");
		goto out_free_dentry;
	}
	d_set_d_op(trashbin_dentry , &stbfs_dops);
	d_add(trashbin_dentry, NULL); /* instantiate and hash */


	lower_root_dentry = lock_parent(lower_trashbin_dentry);
	err = vfs_mkdir(d_inode(lower_root_dentry), lower_trashbin_dentry, 0755);
	if (err) {
		printk(KERN_INFO"stbfs: error in creating trashbin folder\n");
		goto unlock_free;
	}
	
	lower_path.dentry = lower_trashbin_dentry;
	lower_path.mnt = mntget(lower_root_mnt);
	stbfs_set_lower_path(trashbin_dentry, &lower_path);
	
	/* interpose */
	err = stbfs_interpose(trashbin_dentry, root_dentry->d_sb, &lower_path);
	if (err) {
		printk(KERN_INFO"stbfs: error in interpose\n");
		goto unlock_free;
	}
	fsstack_copy_attr_times(root_inode, stbfs_lower_inode(root_inode));
	fsstack_copy_inode_size(root_inode, d_inode(lower_root_dentry));
	/* update number of links on parent directory */
	set_nlink(root_inode, stbfs_lower_inode(root_inode)->i_nlink);

	printk(KERN_INFO"stbfs: trashbin created\n");
	
	/* successful */
	unlock_dir(lower_root_dentry);
	goto out;


unlock_free:
	unlock_dir(lower_root_dentry);
out_free_dentry:
	stbfs_free_dentry_private_data(trashbin_dentry);
	dput(trashbin_dentry);
out_free_lower_dentry:
	dput(lower_trashbin_dentry);
out:
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
	if (!silent)
		printk(KERN_INFO
		       "stbfs: mounted on top of %s type %s\n",
		       dev_name, lower_sb->s_type->name);
	
	/* create a transhbin */
	if (create_trashbin(&lower_path, sb->s_root)) {
		printk("stbfs: failed to create trashbin\n");
	}
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

struct dentry *stbfs_mount(struct file_system_type *fs_type, int flags,
			    const char *dev_name, void *raw_data)
{
	void *lower_path_name = (void *) dev_name;

	return mount_nodev(fs_type, flags, lower_path_name,
			   stbfs_read_super);
}

static struct file_system_type stbfs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= STBFS_NAME,
	.mount		= stbfs_mount,
	.kill_sb	= generic_shutdown_super,
	.fs_flags	= 0,
};
MODULE_ALIAS_FS(STBFS_NAME);

static int __init init_stbfs_fs(void)
{
	int err;

	pr_info("Registering stbfs " STBFS_VERSION "\n");

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
