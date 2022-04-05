// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 1998-2020 Erez Zadok
 * Copyright (c) 2009	   Shrikar Archak
 * Copyright (c) 2003-2020 Stony Brook University
 * Copyright (c) 2003-2020 The Research Foundation of SUNY
 */

#include "stbfs.h"


static int stbfs_create(struct inode *dir, struct dentry *dentry,
			 umode_t mode, bool want_excl)
{
	int err;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path lower_path;

	if (stbfs_in_trashbin(dentry)) {
		return -EPERM;
	}

	stbfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_parent_dentry = lock_parent(lower_dentry);

	err = vfs_create(d_inode(lower_parent_dentry), lower_dentry, mode,
			 want_excl);
	if (err)
		goto out;
	err = stbfs_interpose(dentry, dir->i_sb, &lower_path);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, stbfs_lower_inode(dir));
	fsstack_copy_inode_size(dir, d_inode(lower_parent_dentry));

out:
	unlock_dir(lower_parent_dentry);
	stbfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int stbfs_link(struct dentry *old_dentry, struct inode *dir,
		       struct dentry *new_dentry)
{
	struct dentry *lower_old_dentry;
	struct dentry *lower_new_dentry;
	struct dentry *lower_dir_dentry;
	u64 file_size_save;
	int err;
	struct path lower_old_path, lower_new_path;

	if (stbfs_in_trashbin(old_dentry)) {
		return -EPERM;
	}

	file_size_save = i_size_read(d_inode(old_dentry));
	stbfs_get_lower_path(old_dentry, &lower_old_path);
	stbfs_get_lower_path(new_dentry, &lower_new_path);
	lower_old_dentry = lower_old_path.dentry;
	lower_new_dentry = lower_new_path.dentry;
	lower_dir_dentry = lock_parent(lower_new_dentry);

	err = vfs_link(lower_old_dentry, d_inode(lower_dir_dentry),
		       lower_new_dentry, NULL);
	if (err || d_really_is_negative(lower_new_dentry))
		goto out;

	err = stbfs_interpose(new_dentry, dir->i_sb, &lower_new_path);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, d_inode(lower_new_dentry));
	fsstack_copy_inode_size(dir, d_inode(lower_new_dentry));
	set_nlink(d_inode(old_dentry),
		  stbfs_lower_inode(d_inode(old_dentry))->i_nlink);
	i_size_write(d_inode(new_dentry), file_size_save);
out:
	unlock_dir(lower_dir_dentry);
	stbfs_put_lower_path(old_dentry, &lower_old_path);
	stbfs_put_lower_path(new_dentry, &lower_new_path);
	return err;
}

struct dentry *__lookup_hash(const struct qstr *name,
		struct dentry *base, unsigned int flags)
{
	struct dentry *dentry = d_lookup(base, name);
	struct dentry *old;
	struct inode *dir = base->d_inode;

	if (dentry)
		return dentry;

	/* Don't create child dentry for a dead directory. */
	if (unlikely(IS_DEADDIR(dir)))
		return ERR_PTR(-ENOENT);

	dentry = d_alloc(base, name);
	if (unlikely(!dentry))
		return ERR_PTR(-ENOMEM);

	old = dir->i_op->lookup(dir, dentry, flags);
	if (unlikely(old)) {
		dput(dentry);
		dentry = old;
	}
	return dentry;
}

static void generate_stbfile_name(char * str, const char * file_name, kuid_t kuid, bool is_enc)
{
	char userid[32];
	get_datetime(str);
	printk("date: %s\n", str);
	if (is_enc) {
		sprintf(userid, "_user_%d.enc", __kuid_val(kuid));
	} else {
		sprintf(userid, "_user_%d", __kuid_val(kuid));
	}
	// sprintf(tb_file_name, "%lld-", ktime_get_seconds());
	strcat(str, file_name);
	strcat(str, userid);
}



int prepare_cryptocpy_arg(struct cryptocopy_params * p, struct file * src, struct file * dst, int flag)
{
	struct user_aes_key * key;
	dbg_printk("user id = %d\n", __kuid_val(current_cred()->uid));
	key = stbfs_get_user_key(current_cred()->uid);
	if (!key) {
		return -ENOKEY;
	}
	p->in_filp = src;
	p->out_filp = dst;
	p->alg_name = "ctr-aes-aesni";
	p->keybuf = key->key;
	p->key_len = key->keylen;
	p->flags = flag;
	return 0;
}

/* returns the lower dentry of created file in trashbin if successful */ 
static struct dentry * __stbfs_move_to_trashbin(struct inode *dir, struct dentry *dentry)
{
	int err = 0, err2;
	struct dentry *lower_stbfile_dentry;
	struct dentry *lower_trashbin_dentry;
	struct dentry *trashbin_dentry;
	struct inode *trashbin_inode, *lower_trashbin_inode;
	struct path lower_path, lower_trashbin_path;
	struct path lower_stbfile_path = {.mnt=NULL, .dentry=NULL};
	struct qstr qname;
	struct cryptocopy_params cparams;
	struct file * in_filp=NULL, *out_filp=NULL;
	char tb_file_name[MAX_DENTRY_NAME_LEN];

	trashbin_dentry = stbfs_get_trashbin_dentry(dentry->d_sb);
	if (IS_ERR(trashbin_dentry)) {
		return trashbin_dentry;
	}

	stbfs_get_lower_path(dentry, &lower_path);
	stbfs_get_lower_path(trashbin_dentry, &lower_trashbin_path);
	trashbin_inode = d_inode(trashbin_dentry);
	lower_trashbin_dentry = lower_trashbin_path.dentry;
	lower_trashbin_inode = d_inode(lower_trashbin_dentry);
	
	generate_stbfile_name(tb_file_name, dentry->d_name.name, d_inode(dentry)->i_uid, true);
	qname.name = tb_file_name;
	qname.len = strlen(tb_file_name);
	qname.hash = full_name_hash(lower_trashbin_dentry, qname.name, qname.len);

	/* lock the trashbin directory before lookup & create */
	inode_lock(lower_trashbin_inode);
	/* Normally, this should return a negative dentry */
	lower_stbfile_dentry = __lookup_hash(&qname, lower_trashbin_dentry, 0);
	if (IS_ERR(lower_stbfile_dentry)) {
		err = PTR_ERR(lower_stbfile_dentry);
		lower_stbfile_dentry = NULL;
		goto exit1;
	}
	lower_stbfile_path.mnt = mntget(lower_trashbin_path.mnt);
	lower_stbfile_path.dentry = dget(lower_stbfile_dentry);

	/* open the file to be moved to trashbin */
	in_filp = dentry_open(&lower_path, O_RDONLY, current_cred());
	if (IS_ERR(in_filp)) {
		printk("stbfs: failed to open the file to be deleted\n");
		err = PTR_ERR(in_filp);
		goto exit1;
	}
	/* create/open a new file in the trashbin, err out if exists */
	if (d_inode(lower_stbfile_dentry)) {
		err = -EEXIST;
		goto exit1;
	}
	err = vfs_create(lower_trashbin_inode, lower_stbfile_dentry, in_filp->f_inode->i_mode, false);
	if (err) {
		printk("stbfs: failed to create a new file in the trashbin\n");
		goto exit1;
	}

	out_filp = dentry_open(&lower_stbfile_path, O_RDWR, current_cred());
	if (IS_ERR(out_filp)) {
		printk("stbfs: failed to open a new file in .stb folder\n");
		err = PTR_ERR(out_filp);
		goto may_unlink;
	}
	
	err = prepare_cryptocpy_arg(&cparams, in_filp, out_filp, ENCRYPT_FLAG);
	if (err) {
		printk("stbfs: error getting user's encryption key, errcode = %d\n", err);
		goto may_unlink;
	}
	
	err = stbfs_cryptocopy(&cparams);
	if (err)
		printk("stbfs: cryptocopy failed with error code %d\n", err);

may_unlink:
	if (err) {
		/* delete partial output on failure */
		err2 = vfs_unlink(lower_trashbin_inode, lower_stbfile_dentry, NULL);
		if (err2) {
			err = err2;
			printk(KERN_CRIT"stbfs: unable to unlink partial output in .stb folder on failure\n");
		}
	}

	/* we are good here, need to update trashbin inode attrs */
	fsstack_copy_attr_all(trashbin_inode, d_inode(lower_trashbin_dentry));
	fsstack_copy_inode_size(trashbin_inode, d_inode(lower_trashbin_dentry));

	
exit1:
	inode_unlock(lower_trashbin_inode);
	stbfs_put_lower_path(dentry, &lower_path);
	stbfs_put_lower_path(trashbin_dentry, &lower_trashbin_path);
	path_put(&lower_stbfile_path);

	if (in_filp && !IS_ERR(in_filp)) 
		filp_close(in_filp, NULL);
	if (out_filp && !IS_ERR(out_filp)) 
		filp_close(out_filp, NULL);

	dput(trashbin_dentry);
	if (err) {
		dput(lower_stbfile_dentry);
		return ERR_PTR(err);
	}
	return lower_stbfile_dentry;
}

static int stbfs_unlink(struct inode *dir, struct dentry *dentry)
{
	int err, err2;
	struct dentry *lower_dentry, *lower_stbfile_dentry = NULL;
	struct inode *lower_dir_inode = stbfs_lower_inode(dir);
	struct inode *lower_trashbin_inode;
	struct dentry *lower_dir_dentry;
	struct path lower_path;
	struct dentry * trashbin = stbfs_get_trashbin_dentry(dentry->d_sb);

	if (IS_ERR(trashbin)) {
		err = PTR_ERR(trashbin);
		return err;
	}
	/* unlinking the trashbin is forbiddened */
	if (stbfs_is_trashbin(dentry)) {
		err = -EPERM;
		goto out_trashbin;
	}
	
	/* if user is unlinking a normal file outside the trashbin,
	 * We need to move it to the trashbin, else we can delete 
	 * the file in the trashbin permanently
	 */
	if (!stbfs_in_trashbin(dentry)) {
		printk("stbfs: moving file to trashbin\n");
		lower_stbfile_dentry = __stbfs_move_to_trashbin(dir, dentry);
		/* If an error occured, we don't need proceed to unlink the
		 * file because we failed to move the file to the trashbin
		 */
		if (IS_ERR(lower_stbfile_dentry)) {
			err = PTR_ERR(lower_stbfile_dentry);
			goto out_trashbin;
		}
		
	}

	stbfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	dget(lower_dentry);
	lower_dir_dentry = lock_parent(lower_dentry);
	if (lower_dentry->d_parent != lower_dir_dentry ||
	    d_unhashed(lower_dentry)) {
		err = -EINVAL;
		goto out;
	}

	err = vfs_unlink(lower_dir_inode, lower_dentry, NULL);

	/*
	 * Note: unlinking on top of NFS can cause silly-renamed files.
	 * Trying to delete such files results in EBUSY from NFS
	 * below.  Silly-renamed files will get deleted by NFS later on, so
	 * we just need to detect them here and treat such EBUSY errors as
	 * if the upper file was successfully deleted.
	 */
	if (err == -EBUSY && lower_dentry->d_flags & DCACHE_NFSFS_RENAMED)
		err = 0;
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, lower_dir_inode);
	fsstack_copy_inode_size(dir, lower_dir_inode);
	set_nlink(d_inode(dentry),
		  stbfs_lower_inode(d_inode(dentry))->i_nlink);
	d_inode(dentry)->i_ctime = dir->i_ctime;
	d_drop(dentry); /* this is needed, else LTP fails (VFS won't do it) */
out:
	unlock_dir(lower_dir_dentry);
	if (err && lower_stbfile_dentry) {
		/* unlink the file we already put into the trashbin */
		lower_trashbin_inode = d_inode(lower_stbfile_dentry->d_parent);
		inode_lock_nested(lower_trashbin_inode, I_MUTEX_PARENT);
		err2 = vfs_unlink(d_inode(lower_stbfile_dentry->d_parent), lower_stbfile_dentry, NULL);
		if (err2) {
			printk(KERN_CRIT"stbfs: unable to unlink output in .stb folder on failure\n");
		} else {
			fsstack_copy_attr_all(d_inode(trashbin), lower_trashbin_inode);
			fsstack_copy_inode_size(d_inode(trashbin), lower_trashbin_inode);
		}
		inode_unlock(lower_trashbin_inode);
	}
	dput(lower_dentry);
	stbfs_put_lower_path(dentry, &lower_path);
out_trashbin:
	dput(trashbin);
	if (!IS_ERR(lower_stbfile_dentry))
		dput(lower_stbfile_dentry);
	return err;
}

int stbfs_raw_unlink(struct inode *dir, struct dentry *dentry)
{
	int err;
	struct dentry *lower_dentry;
	struct inode *lower_dir_inode = stbfs_lower_inode(dir);
	struct dentry *lower_dir_dentry;
	struct path lower_path;

	stbfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	dget(lower_dentry);
	lower_dir_dentry = lock_parent(lower_dentry);
	if (lower_dentry->d_parent != lower_dir_dentry ||
	    d_unhashed(lower_dentry)) {
		err = -EINVAL;
		goto out;
	}

	err = vfs_unlink(lower_dir_inode, lower_dentry, NULL);

	/*
	 * Note: unlinking on top of NFS can cause silly-renamed files.
	 * Trying to delete such files results in EBUSY from NFS
	 * below.  Silly-renamed files will get deleted by NFS later on, so
	 * we just need to detect them here and treat such EBUSY errors as
	 * if the upper file was successfully deleted.
	 */
	if (err == -EBUSY && lower_dentry->d_flags & DCACHE_NFSFS_RENAMED)
		err = 0;
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, lower_dir_inode);
	fsstack_copy_inode_size(dir, lower_dir_inode);
	set_nlink(d_inode(dentry),
		  stbfs_lower_inode(d_inode(dentry))->i_nlink);
	d_inode(dentry)->i_ctime = dir->i_ctime;
	d_drop(dentry); /* this is needed, else LTP fails (VFS won't do it) */
out:
	unlock_dir(lower_dir_dentry);
	dput(lower_dentry);
	stbfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int stbfs_symlink(struct inode *dir, struct dentry *dentry,
			  const char *symname)
{
	int err;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path lower_path;

	stbfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_parent_dentry = lock_parent(lower_dentry);

	err = vfs_symlink(d_inode(lower_parent_dentry), lower_dentry, symname);
	if (err)
		goto out;
	err = stbfs_interpose(dentry, dir->i_sb, &lower_path);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, stbfs_lower_inode(dir));
	fsstack_copy_inode_size(dir, d_inode(lower_parent_dentry));

out:
	unlock_dir(lower_parent_dentry);
	stbfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int stbfs_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	int err;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path lower_path;

	stbfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_parent_dentry = lock_parent(lower_dentry);

	err = vfs_mkdir(d_inode(lower_parent_dentry), lower_dentry, mode);
	if (err)
		goto out;

	err = stbfs_interpose(dentry, dir->i_sb, &lower_path);
	if (err)
		goto out;

	fsstack_copy_attr_times(dir, stbfs_lower_inode(dir));
	fsstack_copy_inode_size(dir, d_inode(lower_parent_dentry));
	/* update number of links on parent directory */
	set_nlink(dir, stbfs_lower_inode(dir)->i_nlink);

out:
	unlock_dir(lower_parent_dentry);
	stbfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int stbfs_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct dentry *lower_dentry;
	struct dentry *lower_dir_dentry;
	int err;
	struct path lower_path;

	stbfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_dir_dentry = lock_parent(lower_dentry);
	if (lower_dentry->d_parent != lower_dir_dentry ||
	    d_unhashed(lower_dentry)) {
		err = -EINVAL;
		goto out;
	}

	err = vfs_rmdir(d_inode(lower_dir_dentry), lower_dentry);
	if (err)
		goto out;

	d_drop(dentry);	/* drop our dentry on success (why not VFS's job?) */
	if (d_inode(dentry))
		clear_nlink(d_inode(dentry));
	fsstack_copy_attr_times(dir, d_inode(lower_dir_dentry));
	fsstack_copy_inode_size(dir, d_inode(lower_dir_dentry));
	set_nlink(dir, d_inode(lower_dir_dentry)->i_nlink);

out:
	unlock_dir(lower_dir_dentry);
	stbfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int stbfs_mknod(struct inode *dir, struct dentry *dentry, umode_t mode,
			dev_t dev)
{
	int err;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path lower_path;

	stbfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_parent_dentry = lock_parent(lower_dentry);

	err = vfs_mknod(d_inode(lower_parent_dentry), lower_dentry, mode, dev);
	if (err)
		goto out;

	err = stbfs_interpose(dentry, dir->i_sb, &lower_path);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, stbfs_lower_inode(dir));
	fsstack_copy_inode_size(dir, d_inode(lower_parent_dentry));

out:
	unlock_dir(lower_parent_dentry);
	stbfs_put_lower_path(dentry, &lower_path);
	return err;
}

/*
 * The locking rules in stbfs_rename are complex.  We could use a simpler
 * superblock-level name-space lock for renames and copy-ups.
 */
static int stbfs_raw_rename(struct inode *old_dir, struct dentry *old_dentry,
			 struct inode *new_dir, struct dentry *new_dentry,
			 unsigned int flags)
{
	int err = 0;
	struct dentry *lower_old_dentry = NULL;
	struct dentry *lower_new_dentry = NULL;
	struct dentry *lower_old_dir_dentry = NULL;
	struct dentry *lower_new_dir_dentry = NULL;
	struct dentry *trap = NULL;
	struct path lower_old_path, lower_new_path;

	if (flags)
		return -EINVAL;

	stbfs_get_lower_path(old_dentry, &lower_old_path);
	stbfs_get_lower_path(new_dentry, &lower_new_path);
	lower_old_dentry = lower_old_path.dentry;
	lower_new_dentry = lower_new_path.dentry;
	lower_old_dir_dentry = dget_parent(lower_old_dentry);
	lower_new_dir_dentry = dget_parent(lower_new_dentry);

	trap = lock_rename(lower_old_dir_dentry, lower_new_dir_dentry);
	err = -EINVAL;
	/* check for unexpected namespace changes */
	if (lower_old_dentry->d_parent != lower_old_dir_dentry)
		goto out;
	if (lower_new_dentry->d_parent != lower_new_dir_dentry)
		goto out;
	/* check if either dentry got unlinked */
	if (d_unhashed(lower_old_dentry) || d_unhashed(lower_new_dentry))
		goto out;
	/* source should not be ancestor of target */
	if (trap == lower_old_dentry)
		goto out;
	/* target should not be ancestor of source */
	if (trap == lower_new_dentry) {
		err = -ENOTEMPTY;
		goto out;
	}

	err = vfs_rename(d_inode(lower_old_dir_dentry), lower_old_dentry,
			 d_inode(lower_new_dir_dentry), lower_new_dentry,
			 NULL, 0);
	if (err)
		goto out;

	fsstack_copy_attr_all(new_dir, d_inode(lower_new_dir_dentry));
	fsstack_copy_inode_size(new_dir, d_inode(lower_new_dir_dentry));
	if (new_dir != old_dir) {
		fsstack_copy_attr_all(old_dir,
				      d_inode(lower_old_dir_dentry));
		fsstack_copy_inode_size(old_dir,
					d_inode(lower_old_dir_dentry));
	}

out:
	unlock_rename(lower_old_dir_dentry, lower_new_dir_dentry);
	dput(lower_old_dir_dentry);
	dput(lower_new_dir_dentry);
	stbfs_put_lower_path(old_dentry, &lower_old_path);
	stbfs_put_lower_path(new_dentry, &lower_new_path);
	return err;
}

static int stbfs_rename(struct inode *old_dir, struct dentry *old_dentry,
			 struct inode *new_dir, struct dentry *new_dentry,
			 unsigned int flags)
{
	if (stbfs_is_trashbin(old_dentry)) {
		return -EPERM;
	}
	return stbfs_raw_rename(old_dir, old_dentry, new_dir, new_dentry, flags);
}

static const char *stbfs_get_link(struct dentry *dentry, struct inode *inode,
				   struct delayed_call *done)
{
	DEFINE_DELAYED_CALL(lower_done);
	struct dentry *lower_dentry;
	struct path lower_path;
	char *buf;
	const char *lower_link;

	if (!dentry)
		return ERR_PTR(-ECHILD);

	stbfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;

	/*
	 * get link from lower file system, but use a separate
	 * delayed_call callback.
	 */
	lower_link = vfs_get_link(lower_dentry, &lower_done);
	if (IS_ERR(lower_link)) {
		buf = ERR_CAST(lower_link);
		goto out;
	}

	/*
	 * we can't pass lower link up: have to make private copy and
	 * pass that.
	 */
	buf = kstrdup(lower_link, GFP_KERNEL);
	do_delayed_call(&lower_done);
	if (!buf) {
		buf = ERR_PTR(-ENOMEM);
		goto out;
	}

	fsstack_copy_attr_atime(d_inode(dentry), d_inode(lower_dentry));

	set_delayed_call(done, kfree_link, buf);
out:
	stbfs_put_lower_path(dentry, &lower_path);
	return buf;
}

static int stbfs_permission(struct inode *inode, int mask)
{
	struct inode *lower_inode;
	int err;

	lower_inode = stbfs_lower_inode(inode);
	err = inode_permission(lower_inode, mask);

	return err;
}

static int stbfs_setattr(struct dentry *dentry, struct iattr *ia)
{
	int err;
	struct dentry *lower_dentry;
	struct inode *inode;
	struct inode *lower_inode;
	struct path lower_path;
	struct iattr lower_ia;

	/* No user should be allowed to change attribute of a file in .stb */
	if (stbfs_in_trashbin(dentry)) {
		printk("stbfs: user try to change attributes of a file in .stb. Access denied\n");
		return -EPERM;
	}

	inode = d_inode(dentry);

	/*
	 * Check if user has permission to change inode.  We don't check if
	 * this user can change the lower inode: that should happen when
	 * calling notify_change on the lower inode.
	 */
	err = setattr_prepare(dentry, ia);
	if (err)
		goto out_err;

	stbfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_inode = stbfs_lower_inode(inode);

	/* prepare our own lower struct iattr (with the lower file) */
	memcpy(&lower_ia, ia, sizeof(lower_ia));
	if (ia->ia_valid & ATTR_FILE)
		lower_ia.ia_file = stbfs_lower_file(ia->ia_file);

	/*
	 * If shrinking, first truncate upper level to cancel writing dirty
	 * pages beyond the new eof; and also if its' maxbytes is more
	 * limiting (fail with -EFBIG before making any change to the lower
	 * level).  There is no need to vmtruncate the upper level
	 * afterwards in the other cases: we fsstack_copy_inode_size from
	 * the lower level.
	 */
	if (ia->ia_valid & ATTR_SIZE) {
		err = inode_newsize_ok(inode, ia->ia_size);
		if (err)
			goto out;
		truncate_setsize(inode, ia->ia_size);
	}

	/*
	 * mode change is for clearing setuid/setgid bits. Allow lower fs
	 * to interpret this in its own way.
	 */
	if (lower_ia.ia_valid & (ATTR_KILL_SUID | ATTR_KILL_SGID))
		lower_ia.ia_valid &= ~ATTR_MODE;

	/* notify the (possibly copied-up) lower inode */
	/*
	 * Note: we use d_inode(lower_dentry), because lower_inode may be
	 * unlinked (no inode->i_sb and i_ino==0.  This happens if someone
	 * tries to open(), unlink(), then ftruncate() a file.
	 */
	inode_lock(d_inode(lower_dentry));
	err = notify_change(lower_dentry, &lower_ia, /* note: lower_ia */
			    NULL);
	inode_unlock(d_inode(lower_dentry));
	if (err)
		goto out;

	/* get attributes from the lower inode */
	fsstack_copy_attr_all(inode, lower_inode);
	/*
	 * Not running fsstack_copy_inode_size(inode, lower_inode), because
	 * VFS should update our inode size, and notify_change on
	 * lower_inode should update its size.
	 */

out:
	stbfs_put_lower_path(dentry, &lower_path);
out_err:
	return err;
}

static int stbfs_getattr(const struct path *path, struct kstat *stat, 
                          u32 request_mask, unsigned int flags)
{
	int err;
        struct dentry *dentry = path->dentry;
	struct kstat lower_stat;
	struct path lower_path;

	stbfs_get_lower_path(dentry, &lower_path);
	err = vfs_getattr(&lower_path, &lower_stat, request_mask, flags);
	if (err)
		goto out;
	fsstack_copy_attr_all(d_inode(dentry),
			      d_inode(lower_path.dentry));
	generic_fillattr(d_inode(dentry), stat);
	stat->blocks = lower_stat.blocks;
out:
	stbfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int
stbfs_setxattr(struct dentry *dentry, struct inode *inode, const char *name,
		const void *value, size_t size, int flags)
{
	int err; struct dentry *lower_dentry;
	struct path lower_path;

	stbfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	if (!(d_inode(lower_dentry)->i_opflags & IOP_XATTR)) {
		err = -EOPNOTSUPP;
		goto out;
	}
	err = vfs_setxattr(lower_dentry, name, value, size, flags);
	if (err)
		goto out;
	fsstack_copy_attr_all(d_inode(dentry),
			      d_inode(lower_path.dentry));
out:
	stbfs_put_lower_path(dentry, &lower_path);
	return err;
}

static ssize_t
stbfs_getxattr(struct dentry *dentry, struct inode *inode,
		const char *name, void *buffer, size_t size)
{
	int err;
	struct dentry *lower_dentry;
	struct inode *lower_inode;
	struct path lower_path;

	stbfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_inode = stbfs_lower_inode(inode);
	if (!(d_inode(lower_dentry)->i_opflags & IOP_XATTR)) {
		err = -EOPNOTSUPP;
		goto out;
	}
	err = vfs_getxattr(lower_dentry, name, buffer, size);
	if (err)
		goto out;
	fsstack_copy_attr_atime(d_inode(dentry),
				d_inode(lower_path.dentry));
out:
	stbfs_put_lower_path(dentry, &lower_path);
	return err;
}

static ssize_t
stbfs_listxattr(struct dentry *dentry, char *buffer, size_t buffer_size)
{
	int err;
	struct dentry *lower_dentry;
	struct path lower_path;

	stbfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	if (!(d_inode(lower_dentry)->i_opflags & IOP_XATTR)) {
		err = -EOPNOTSUPP;
		goto out;
	}
	err = vfs_listxattr(lower_dentry, buffer, buffer_size);
	if (err)
		goto out;
	fsstack_copy_attr_atime(d_inode(dentry),
				d_inode(lower_path.dentry));
out:
	stbfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int
stbfs_removexattr(struct dentry *dentry, struct inode *inode, const char *name)
{
	int err;
	struct dentry *lower_dentry;
	struct inode *lower_inode;
	struct path lower_path;

	stbfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_inode = stbfs_lower_inode(inode);
	if (!(lower_inode->i_opflags & IOP_XATTR)) {
		err = -EOPNOTSUPP;
		goto out;
	}
	err = vfs_removexattr(lower_dentry, name);
	if (err)
		goto out;
	fsstack_copy_attr_all(d_inode(dentry), lower_inode);
out:
	stbfs_put_lower_path(dentry, &lower_path);
	return err;
}

const struct inode_operations stbfs_symlink_iops = {
	.permission	= stbfs_permission,
	.setattr	= stbfs_setattr,
	.getattr	= stbfs_getattr,
	.get_link	= stbfs_get_link,
	.listxattr	= stbfs_listxattr,
};

const struct inode_operations stbfs_dir_iops = {
	.create		= stbfs_create,
	.lookup		= stbfs_lookup,
	.link		= stbfs_link,
	.unlink		= stbfs_unlink,
	.symlink	= stbfs_symlink,
	.mkdir		= stbfs_mkdir,
	.rmdir		= stbfs_rmdir,
	.mknod		= stbfs_mknod,
	.rename		= stbfs_rename,
	.permission	= stbfs_permission,
	.setattr	= stbfs_setattr,
	.getattr	= stbfs_getattr,
	.listxattr	= stbfs_listxattr,
};

const struct inode_operations stbfs_main_iops = {
	.permission	= stbfs_permission,
	.setattr	= stbfs_setattr,
	.getattr	= stbfs_getattr,
	.listxattr	= stbfs_listxattr,
};

static int stbfs_xattr_get(const struct xattr_handler *handler,
			    struct dentry *dentry, struct inode *inode,
			    const char *name, void *buffer, size_t size)
{
	return stbfs_getxattr(dentry, inode, name, buffer, size);
}

static int stbfs_xattr_set(const struct xattr_handler *handler,
			    struct dentry *dentry, struct inode *inode,
			    const char *name, const void *value, size_t size,
			    int flags)
{
	if (value)
		return stbfs_setxattr(dentry, inode, name, value, size, flags);

	BUG_ON(flags != XATTR_REPLACE);
	return stbfs_removexattr(dentry, inode, name);
}

const struct xattr_handler stbfs_xattr_handler = {
	.prefix = "",		/* match anything */
	.get = stbfs_xattr_get,
	.set = stbfs_xattr_set,
};

const struct xattr_handler *stbfs_xattr_handlers[] = {
	&stbfs_xattr_handler,
	NULL
};
