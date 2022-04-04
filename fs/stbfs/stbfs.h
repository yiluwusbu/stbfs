// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 1998-2020 Erez Zadok
 * Copyright (c) 2009	   Shrikar Archak
 * Copyright (c) 2003-2020 Stony Brook University
 * Copyright (c) 2003-2020 The Research Foundation of SUNY
 */

#ifndef _STBFS_H_
#define _STBFS_H_

#include <linux/dcache.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/seq_file.h>
#include <linux/statfs.h>
#include <linux/fs_stack.h>
#include <linux/magic.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/xattr.h>
#include <linux/exportfs.h>
#include <linux/kernel.h>
#include <linux/time.h>
#include <linux/cred.h>
#include <linux/dirent.h>
#include <linux/fs_struct.h>
#include <linux/uuid.h>
#include <linux/hashtable.h>
/* the file system name */
#define STBFS_NAME "stbfs"

/* stbfs root inode number */
#define STBFS_ROOT_INO     1

/* useful for tracking code reachability */
#define DEBUG
#ifdef DEBUG
#define dbg_printk(fmt, ...) printk(KERN_DEFAULT "[DEBUG] stbfs: "fmt, ##__VA_ARGS__);
#define UDBG printk(KERN_DEFAULT "DBG:%s:%s:%d\n", __FILE__, __func__, __LINE__)
#else
#define dbg_printk(fmt, ...)
#define UDBG
#endif

#define ENCRYPT_FLAG 0x01
#define DECRYPT_FLAG 0x02
#define COPY_FLAG 0x04

/* undelete cmd for ioctl */
#define IOCTL_CMD_UNDELETE 0x7C
#define MAX_DENTRY_NAME_LEN 256

/* operations vectors defined in specific files */
extern const struct file_operations stbfs_main_fops;
extern const struct file_operations stbfs_dir_fops;
extern const struct inode_operations stbfs_main_iops;
extern const struct inode_operations stbfs_dir_iops;
extern const struct inode_operations stbfs_symlink_iops;
extern const struct super_operations stbfs_sops;
extern const struct dentry_operations stbfs_dops;
extern const struct address_space_operations stbfs_aops, stbfs_dummy_aops;
extern const struct vm_operations_struct stbfs_vm_ops;
extern const struct export_operations stbfs_export_ops;
extern const struct xattr_handler *stbfs_xattr_handlers[];

struct cryptocopy_params;

extern struct dentry * stbfs_get_trashbin_dentry(struct super_block * sb);
extern int stbfs_init_inode_cache(void);
extern void stbfs_destroy_inode_cache(void);
extern int stbfs_init_dentry_cache(void);
extern void stbfs_destroy_dentry_cache(void);
extern int stbfs_new_dentry_private_data(struct dentry *dentry);
extern void stbfs_free_dentry_private_data(struct dentry *dentry);
extern struct dentry *stbfs_lookup(struct inode *dir, struct dentry *dentry,
				    unsigned int flags);
extern struct inode *stbfs_iget(struct super_block *sb,
				 struct inode *lower_inode);
extern int stbfs_interpose(struct dentry *dentry, struct super_block *sb,
			    struct path *lower_path);
extern struct dentry * stbfs_alloc_dentry(const char * name, 
				struct dentry * parent, struct dentry * lower_parent);
extern struct dentry *__lookup_hash(const struct qstr *name,
		struct dentry *base, unsigned int flags);
extern int stbfs_raw_unlink(struct inode *dir, struct dentry *dentry);
extern long stbfs_cryptocopy(struct cryptocopy_params * params);
extern void prepare_cryptocpy_arg(struct cryptocopy_params * p, struct file * src, struct file * dst, int flag);
extern struct user_aes_key * stbfs_get_user_key(kuid_t uid);
extern int stbfs_set_user_key(kuid_t uid, const char * key, int keylen);
extern int create_aes_key(const char *password, char *key);

/* file private data */
struct stbfs_file_info {
	struct file *lower_file;
	const struct vm_operations_struct *lower_vm_ops;
};

/* stbfs inode data in memory */
struct stbfs_inode_info {
	struct inode *lower_inode;
	struct inode vfs_inode;
};

/* stbfs dentry data in memory */
struct stbfs_dentry_info {
	spinlock_t lock;	/* protects lower_path */
	struct path lower_path;
};

/* stbfs super-block data in memory */
struct stbfs_sb_info {
	struct super_block *lower_sb;
	struct path lower_trashbin;
};

/* argument type for stbfs cryptocopy */
struct cryptocopy_params {
	struct file * in_filp;
	struct file * out_filp;
	char *  keybuf;
	int key_len;
	char * alg_name;
	int flags;
};

/* per-user AES encryption key */
struct user_aes_key {
	char key[32];
	int keylen;
	struct hlist_node h_node;
	kuid_t user_id;
};

struct user_key_hashtbl {
	spinlock_t lock;
	DECLARE_HASHTABLE(hashtbl, 12);
};

extern struct user_key_hashtbl user_key_hashtbl;
/*
 * inode to private data
 *
 * Since we use containers and the struct inode is _inside_ the
 * stbfs_inode_info structure, STBFS_I will always (given a non-NULL
 * inode pointer), return a valid non-NULL pointer.
 */
static inline struct stbfs_inode_info *STBFS_I(const struct inode *inode)
{
	return container_of(inode, struct stbfs_inode_info, vfs_inode);
}

/* dentry to private data */
#define STBFS_D(dent) ((struct stbfs_dentry_info *)(dent)->d_fsdata)

/* superblock to private data */
#define STBFS_SB(super) ((struct stbfs_sb_info *)(super)->s_fs_info)

/* file to private Data */
#define STBFS_F(file) ((struct stbfs_file_info *)((file)->private_data))

/* file to lower file */
static inline struct file *stbfs_lower_file(const struct file *f)
{
	return STBFS_F(f)->lower_file;
}

static inline void stbfs_set_lower_file(struct file *f, struct file *val)
{
	STBFS_F(f)->lower_file = val;
}

/* inode to lower inode. */
static inline struct inode *stbfs_lower_inode(const struct inode *i)
{
	return STBFS_I(i)->lower_inode;
}

static inline void stbfs_set_lower_inode(struct inode *i, struct inode *val)
{
	STBFS_I(i)->lower_inode = val;
}

/* superblock to lower superblock */
static inline struct super_block *stbfs_lower_super(
	const struct super_block *sb)
{
	return STBFS_SB(sb)->lower_sb;
}

static inline void stbfs_set_lower_super(struct super_block *sb,
					  struct super_block *val)
{
	STBFS_SB(sb)->lower_sb = val;
}


/* path based (dentry/mnt) macros */
static inline void pathcpy(struct path *dst, const struct path *src)
{
	dst->dentry = src->dentry;
	dst->mnt = src->mnt;
}
/* Returns struct path.  Caller must path_put it. */
static inline void stbfs_get_lower_path(const struct dentry *dent,
					 struct path *lower_path)
{
	spin_lock(&STBFS_D(dent)->lock);
	pathcpy(lower_path, &STBFS_D(dent)->lower_path);
	path_get(lower_path);
	spin_unlock(&STBFS_D(dent)->lock);
	return;
}
static inline void stbfs_put_lower_path(const struct dentry *dent,
					 struct path *lower_path)
{
	path_put(lower_path);
	return;
}
static inline void stbfs_set_lower_path(const struct dentry *dent,
					 struct path *lower_path)
{
	spin_lock(&STBFS_D(dent)->lock);
	pathcpy(&STBFS_D(dent)->lower_path, lower_path);
	spin_unlock(&STBFS_D(dent)->lock);
	return;
}
static inline void stbfs_reset_lower_path(const struct dentry *dent)
{
	spin_lock(&STBFS_D(dent)->lock);
	STBFS_D(dent)->lower_path.dentry = NULL;
	STBFS_D(dent)->lower_path.mnt = NULL;
	spin_unlock(&STBFS_D(dent)->lock);
	return;
}
static inline void stbfs_put_reset_lower_path(const struct dentry *dent)
{
	struct path lower_path;
	spin_lock(&STBFS_D(dent)->lock);
	pathcpy(&lower_path, &STBFS_D(dent)->lower_path);
	STBFS_D(dent)->lower_path.dentry = NULL;
	STBFS_D(dent)->lower_path.mnt = NULL;
	spin_unlock(&STBFS_D(dent)->lock);
	path_put(&lower_path);
	return;
}

/* locking helpers */
static inline struct dentry *lock_parent(struct dentry *dentry)
{
	struct dentry *dir = dget_parent(dentry);
	inode_lock_nested(d_inode(dir), I_MUTEX_PARENT);
	return dir;
}

static inline void unlock_dir(struct dentry *dir)
{
	inode_unlock(d_inode(dir));
	dput(dir);
}

/* time to string helper */
static inline void get_datetime(char * str)
{
	time64_t sec = ktime_get_real_seconds();
	struct tm tm;
	time64_to_tm(sec, 0, &tm);
	sprintf(str, "%ld-%d-%d-%d:%d:%d-", 1900+tm.tm_year, tm.tm_mon+1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
}

static inline bool stbfs_is_trashbin(struct dentry * dentry)
{
	return STBFS_SB(dentry->d_sb)->lower_trashbin.dentry
		   == STBFS_D(dentry)->lower_path.dentry;
}

static inline bool stbfs_in_trashbin(struct dentry * dentry)
{
	struct dentry * lower_trashbin = 
		STBFS_SB(dentry->d_sb)->lower_trashbin.dentry;
	struct dentry *lower_dentry = 
		STBFS_D(dentry)->lower_path.dentry;
	return lower_dentry->d_parent == lower_trashbin;
}

static inline void stbfs_set_lower_trashbin(struct super_block *sb,
					  struct path *val)
{
	pathcpy(&(STBFS_SB(sb)->lower_trashbin), val);
	path_get(val);
}

static inline void stbfs_put_lower_trashbin(struct super_block *sb)
{
	path_put(&(STBFS_SB(sb)->lower_trashbin));
	STBFS_SB(sb)->lower_trashbin.dentry = NULL;
	STBFS_SB(sb)->lower_trashbin.mnt = NULL;
}

#endif	/* not _STBFS_H_ */
