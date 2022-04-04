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

static void stbfs_destroy_user_keys(void)
{
	int bkt;
	struct hlist_node *tmp;
	struct user_aes_key *cursor;
	hash_for_each_safe(user_key_hashtbl.hashtbl, bkt, tmp, cursor, h_node) {
		hash_del(&cursor->h_node);
		kfree(cursor);
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

int stbfs_set_user_key(kuid_t uid, const char * key, int keylen)
{
	struct user_aes_key * new_key = NULL;
	struct user_aes_key * old_key = NULL;
	uid_t hash_key = __kuid_val(uid);
	if (keylen != 16 && keylen != 24 && keylen != 32) {
		return -EINVAL;
	}
	new_key = kzalloc(sizeof(struct user_aes_key), GFP_KERNEL);
	if (!new_key) {
		return -ENOMEM;
	}
	memcpy(new_key->key, key, keylen);
	new_key->keylen = keylen;
	new_key->user_id = uid;
	
	spin_lock(&user_key_hashtbl.lock);
	old_key = stbfs_get_user_key_unlocked(uid);
	if (old_key) {
		hash_del(&old_key->h_node);
	}
	hash_add(user_key_hashtbl.hashtbl, &new_key->h_node, hash_key);
	spin_unlock(&user_key_hashtbl.lock);

	if (old_key) {
		kfree(old_key);
	}
	return 0;
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

static char * stbfs_parse_mount_options(const char * data)
{
	int len = strlen(data);
	char * option = "enc=";
	char * substr;
	dbg_printk("data is %s, dlen=%d\n", data, len);
	substr = strstr(data, option);
	if (!substr) {
		return NULL;
	}
	if (len - (substr - data) - strlen(option) <= 0 ) {
		return NULL;
	} 
	return substr + strlen(option);
}

struct dentry *stbfs_mount(struct file_system_type *fs_type, int flags,
			    const char *dev_name, void *raw_data)
{
	char key[16];
	void *lower_path_name = (void *) dev_name;
	char * p = stbfs_parse_mount_options((char*)raw_data);
	int err;
	
	if (p) {
		dbg_printk("Password is %s\n", p);
		err = create_aes_key(p, key);
		if (!err) {
			stbfs_set_user_key(current_cred()->uid, key, 16);
		}
	} else{
		dbg_printk("No password passed\n");
	}

	return mount_nodev(fs_type, flags, lower_path_name,
			   stbfs_read_super);
}

void stbfs_shutdown_super(struct super_block *sb)
{
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
