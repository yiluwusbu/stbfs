// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 1998-2020 Erez Zadok
 * Copyright (c) 2009	   Shrikar Archak
 * Copyright (c) 2003-2020 Stony Brook University
 * Copyright (c) 2003-2020 The Research Foundation of SUNY
 */

#include "stbfs.h"

static ssize_t stbfs_read(struct file *file, char __user *buf,
			   size_t count, loff_t *ppos)
{
	int err;
	struct file *lower_file;
	struct dentry *dentry = file->f_path.dentry;

	lower_file = stbfs_lower_file(file);
	err = vfs_read(lower_file, buf, count, ppos);
	/* update our inode atime upon a successful lower read */
	if (err >= 0)
		fsstack_copy_attr_atime(d_inode(dentry),
					file_inode(lower_file));

	return err;
}

static ssize_t stbfs_write(struct file *file, const char __user *buf,
			    size_t count, loff_t *ppos)
{
	int err;

	struct file *lower_file;
	struct dentry *dentry = file->f_path.dentry;

	lower_file = stbfs_lower_file(file);
	err = vfs_write(lower_file, buf, count, ppos);
	/* update our inode times+sizes upon a successful lower write */
	if (err >= 0) {
		fsstack_copy_inode_size(d_inode(dentry),
					file_inode(lower_file));
		fsstack_copy_attr_times(d_inode(dentry),
					file_inode(lower_file));
	}

	return err;
}


struct getdents_callback64 {
	struct dir_context ctx;
	struct linux_dirent64 __user * current_dir;
	struct linux_dirent64 __user * previous;
	int count;
	int error;
};


static kuid_t get_stbfile_userid(const char * filename)
{
	int len = strlen(filename);
	const char * loc = &filename[len-1];
	int uid = 0, cnt=0;
	int factor = 1;
	int digit;
	char c;
	
	while (cnt < len && (*loc < '0' || *loc > '9')) {
		cnt++;
		loc--;
	}

	while (cnt < len && (c = *loc) != '_') {
		if (c < '0' || c > '9') {
			return KUIDT_INIT(0);
		}
		digit = c - '0';
		uid += digit * factor;
		factor *= 10;
		cnt++;
		loc--;
	}

	return KUIDT_INIT(uid);
}

static int stbfs_read_trashbin_dir(struct file *file, struct dir_context *ctx)
{
	int err;
	struct file *lower_file = NULL;
	struct dentry *dentry = file->f_path.dentry;
	struct linux_dirent64 * k_dirent;
	struct linux_dirent64 __user * dirent;
	int buflen;
	const struct cred * cred;
	kuid_t euid, owner_uid;
	kuid_t root_uid = KUIDT_INIT(0);
	// int n = 0;
	int consumed = 0;
	mm_segment_t old_fs;

	struct getdents_callback64 *buf =
		container_of(ctx, struct getdents_callback64, ctx);

	dirent = buf->current_dir;
	buflen = buf->count;

	k_dirent = kzalloc(buflen, GFP_KERNEL);
	if (!k_dirent) {
		return -ENOMEM;
	}

	buf->current_dir = k_dirent;

	lower_file = stbfs_lower_file(file);
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	err = iterate_dir(lower_file, ctx);
	set_fs(old_fs);
	file->f_pos = lower_file->f_pos;
	// copy_to_user(dirent, k_dirent, buflen);
	// buf->previous = buf->previous ? ((void*)dirent + ((void*)(buf->previous) - (void*)k_dirent)) : NULL;

	if (err >= 0) {		/* copy the atime */
		fsstack_copy_attr_atime(d_inode(dentry),
					file_inode(lower_file));
	} else {
		buf->previous = buf->previous ? ((void*)dirent + ((void*)(buf->previous) - (void*)k_dirent)) : NULL;
		if (copy_to_user(dirent, k_dirent, buflen)) {
			err = -EFAULT;
		}
		return err;
	}

	cred = get_current_cred();
	euid = cred->euid;
	buflen = buflen - buf->count;
	buf->previous = NULL;

	while (consumed < buflen) {
		if (strcmp(k_dirent->d_name, "..") == 0  
			|| strcmp(k_dirent->d_name, ".") == 0 ) {
			goto do_copy;
		} 

		owner_uid = get_stbfile_userid(k_dirent->d_name);
		if (uid_eq(root_uid, euid) || uid_eq(owner_uid, euid)) {
			goto do_copy;
		} else {
			buf->count += k_dirent->d_reclen;
			goto advance;
		}
		
do_copy:
		if (copy_to_user(dirent, k_dirent, k_dirent->d_reclen)) {
			err = -EFAULT;
			printk("stbfs: copy_to_user error\n");
			goto out;
		}
		dirent = (struct linux_dirent64 __user *)((void*)dirent + k_dirent->d_reclen);
		buf->previous = dirent;
advance:
		consumed += k_dirent->d_reclen;
		k_dirent = (struct linux_dirent64*)((void*)k_dirent + k_dirent->d_reclen);
	}

	err = buf->count;

out:
	put_cred(cred);
	return err;
}


static int stbfs_readdir(struct file *file, struct dir_context *ctx)
{
	int err;
	struct file *lower_file = NULL;
	struct dentry *dentry = file->f_path.dentry;

	if (stbfs_is_trashbin(dentry)) {
		return stbfs_read_trashbin_dir(file, ctx);
	}

	lower_file = stbfs_lower_file(file);
	err = iterate_dir(lower_file, ctx);
	file->f_pos = lower_file->f_pos;
	if (err >= 0)		/* copy the atime */
		fsstack_copy_attr_atime(d_inode(dentry),
					file_inode(lower_file));
	return err;
}

/* filename format YY-MM-DD-HH-MM-SS-<filename>_user_<userid> */
static void stbfs_extract_old_filename(const char * fname, char * oldname)
{
	const char * loc = fname;
	int namelen = strlen(fname);
	int dcnt = 0, cnt = 0; 
	char * name_on_fail = "invalid_old_name";
	int old_name_len = 0;
	int len_before;
	while (cnt < namelen && dcnt < 6) {
		if (*loc == '-' || *loc == ':') {
			dcnt++;
		}
		loc++; 
		cnt++;
	}
	if (cnt == namelen) {
		goto fail;
	}
	len_before = cnt;
	loc = &fname[namelen-1];
	cnt = 0;
	while (cnt < namelen && *loc != '_') {
		cnt++;
		loc--;
	}
	if (cnt == namelen) {
		goto fail;
	}

	old_name_len = namelen - len_before - strlen("_user_") - cnt;
	if (old_name_len <= 0) {
		goto fail;
	}

	loc = (char*)fname + len_before;
	memcpy(oldname, loc, old_name_len); 
	oldname[old_name_len] = 0;
	return;
fail:
	printk("stbfs: illegal file name in .stb detected\n");
	strcpy(oldname, name_on_fail);
	return;

}

static long stbfs_undelete_file(struct file *file)
{
	struct dentry * dentry = file->f_path.dentry;
	struct dentry * new_dentry;
	struct dentry * old_dir_dentry, * new_dir_dentry;
	struct inode * inode = d_inode(dentry);
	struct path pwd, new_path;
	struct inode *old_dir, *new_dir;
	const struct cred * cred;
	struct file *in_filp=file, *out_filp=NULL;
	struct cryptocopy_params cparams;
	long err = 0, err2=0;
	kuid_t root = KUIDT_INIT(0);
	char oldname[MAX_DENTRY_NAME_LEN];
	struct qstr qname;
	
	/* permission check */
	cred = get_current_cred();
	if (!(uid_eq(cred->euid, root) || uid_eq(cred->euid, inode->i_uid))) {
		err = -EPERM;
		goto out1;
	}
	/* should only undeletes file in trashbin */
	if (!stbfs_in_trashbin(file->f_path.dentry)) {
		err = -EPERM;
		goto out1;
	}

	get_fs_pwd(current->fs, &pwd);
	new_dir = d_inode(pwd.dentry);
	new_dir_dentry = pwd.dentry;
	old_dir_dentry = dget_parent(dentry);
	old_dir = d_inode(old_dir_dentry);
	stbfs_extract_old_filename(dentry->d_name.name, oldname);
	printk("stbfs: oldname is %s\n", oldname);
	
	lock_rename(new_dir_dentry, old_dir_dentry);
	/* check PWD */
	if (pwd.mnt != file->f_path.mnt || stbfs_is_trashbin(new_dir_dentry)) {
		err = -EPERM;
		goto out2;
	}
	/* setup qname */
	qname.name = oldname;
	qname.len = strlen(oldname);
	qname.hash = full_name_hash(new_dir_dentry, qname.name, qname.len);
	new_dentry = __lookup_hash(&qname, new_dir_dentry, 0);
	
	if (IS_ERR(new_dentry)) {
		printk("stbfs: error in looking up the new dentry in CWD\n");
		err = PTR_ERR(new_dentry);
		goto out2;
	}

	if (d_inode(new_dentry)) {
		printk("stbfs: file to be recovered already exist in CWD\n");
		err = -EEXIST;
		goto out3;
	}

	err = vfs_create(new_dir, new_dentry, file_inode(file)->i_mode, false);
	if (err) {
		printk("stbfs: vfs_create returned errcode %ld\n", err);
		goto out3;
	}

	new_path.mnt = file->f_path.mnt;
	new_path.dentry = new_dentry;
	out_filp = dentry_open(&new_path, O_RDWR, cred);

	if (IS_ERR(out_filp)) {
		err = PTR_ERR(out_filp);
		printk("stbfs: error opening new file in CWD, errcode = %ld\n", err);
		goto unlink_new;
	}

	err = prepare_cryptocpy_arg(&cparams, in_filp, out_filp, DECRYPT_FLAG);
	if (err) {
		printk("stbfs: error getting users key\n");
		goto unlink_new;
	}

	err = stbfs_cryptocopy(&cparams);
	if (err) {
		printk("stbfs: cryptocopy failed with errcode %ld\n", err);
		goto unlink_new;
	}

	/* If we have reached this point, the file in the trashbin is already undeleted */
	err = stbfs_raw_unlink(old_dir, dentry);
	if (err) {
		/* if failed, nothing can be done here */
		printk("stbfs: failed to unlink the file in the trashbin, errcode %ld\n", err);
	}
	goto out3;

unlink_new:
	err2 = stbfs_raw_unlink(new_dir, new_dentry);
	if (err2) {
		printk("stbfs: failed to unlink the (partial) undeleted file in CWD, errcode %ld\n", err2);
	}
	
out3:
	dput(new_dentry);
out2:
	unlock_rename(new_dir_dentry, old_dir_dentry);
	if (out_filp && !IS_ERR(out_filp)) {
		filp_close(out_filp, NULL);
	}
	path_put(&pwd);
	dput(old_dir_dentry);
out1:
	put_cred(cred);

	return err;

}

struct password_record {
	int plen;
	uid_t uid;
	char password[32];
};

struct stbfs_ioctl_arg {
	int nrecs;
	struct password_record recs[0]; 
};

static int stbfs_handle_set_key(struct stbfs_ioctl_arg * uarg)
{
	int ubuf_size;
	int err = 0;
	struct stbfs_ioctl_arg * karg = NULL;
	struct password_record * rec = NULL;;
	

	if (!uarg) {
		return -EINVAL;
	}
	
	ubuf_size = sizeof(*karg) + sizeof(*rec);
	karg = kmalloc(ubuf_size, GFP_KERNEL);
	if (!karg) {
		return -ENOMEM;
	}
	err = copy_from_user(karg, uarg, ubuf_size);
	if (err) {
		err = -EFAULT;
		goto out;
	}
	if (karg->nrecs != 1) {
		err = -EINVAL;
		goto out;
	}
	rec = karg->recs;
	if (rec->plen >= 32 || rec->plen < 6) {
		err = -EINVAL;
		goto out;
	}
	/* null-terminate the password */
	rec->password[rec->plen] = 0;
	err = stbfs_set_user_key(current_cred()->uid, rec->password);
	
out:
	if (karg)
		kfree(karg);
	return err;
}

static int stbfs_handle_list_key(struct stbfs_ioctl_arg * uarg)
{
	int recs_size;
	int err = 0;
	int cnt=0, bkt;
	struct stbfs_ioctl_arg * karg = NULL;
	struct password_record * recs = NULL;
	struct user_aes_key * ukey;

	if (!uarg) {
		return -EINVAL;
	}
	
	karg = kmalloc(sizeof(*karg), GFP_KERNEL);
	if (!karg) {
		return -ENOMEM;
	}
	err = copy_from_user(karg, uarg, sizeof(*karg));
	if (err) {
		err = -EFAULT;
		goto out;
	}
	if (karg->nrecs < 1 || karg->nrecs > 4096) {
		err = -EINVAL;
		goto out;
	}
	recs_size = karg->nrecs * sizeof(struct password_record);

	recs = kmalloc(recs_size, GFP_KERNEL);
	if (!recs) {
		err = -ENOMEM;
		goto out;
	}

	if (uid_eq(current_cred()->euid, KUIDT_INIT(0))) {
		spin_lock(&user_key_hashtbl.lock);
		hash_for_each(user_key_hashtbl.hashtbl, bkt, ukey, h_node) {
			if (cnt >= karg->nrecs) {
				break;
			}
			strcpy(recs[cnt].password, ukey->password);
			recs[cnt].plen = strlen(ukey->password);
			recs[cnt].uid = __kuid_val(ukey->user_id);
			cnt++;
		}
		spin_unlock(&user_key_hashtbl.lock);
		karg->nrecs = cnt;
	} else {
		ukey = stbfs_get_user_key(current_cred()->euid);
		if (ukey) {
			strcpy(recs[0].password, ukey->password);
			recs[0].plen = strlen(ukey->password);
			recs[0].uid = __kuid_val(ukey->user_id);
			cnt = 1;
		} 
		karg->nrecs = cnt;
	}

	err = copy_to_user(uarg, karg, sizeof(*karg));
	err = copy_to_user(uarg->recs, recs, cnt * sizeof(struct password_record));
	
out:
	if (karg)
		kfree(karg);
	if (recs)
		kfree(recs);
	return err;
}

static long stbfs_unlocked_ioctl(struct file *file, unsigned int cmd,
				  unsigned long arg)
{
	long err = -ENOTTY;
	struct file *lower_file;
	struct stbfs_ioctl_arg * uarg = (struct stbfs_ioctl_arg *)arg;

	if (cmd == IOCTL_CMD_UNDELETE) {
		return stbfs_undelete_file(file);
	} else if (cmd == IOCTL_CMD_SET_KEY) {
		return stbfs_handle_set_key(uarg);
	} else if (cmd == IOCTL_CMD_LIST_KEY) {
		return stbfs_handle_list_key(uarg);
	} else if (cmd == IOCTL_CMD_DEL_KEY) {
		stbfs_delete_user_key(current_cred()->uid);
		return 0;
	}

	printk("stbfs: cmd = %d, dentry = %s\n", cmd, file->f_path.dentry->d_name.name);

	lower_file = stbfs_lower_file(file);

	/* XXX: use vfs_ioctl if/when VFS exports it */
	if (!lower_file || !lower_file->f_op)
		goto out;
	if (lower_file->f_op->unlocked_ioctl)
		err = lower_file->f_op->unlocked_ioctl(lower_file, cmd, arg);

	/* some ioctls can change inode attributes (EXT2_IOC_SETFLAGS) */
	if (!err)
		fsstack_copy_attr_all(file_inode(file),
				      file_inode(lower_file));
out:
	return err;
}

#ifdef CONFIG_COMPAT
static long stbfs_compat_ioctl(struct file *file, unsigned int cmd,
				unsigned long arg)
{
	long err = -ENOTTY;
	struct file *lower_file;

	lower_file = stbfs_lower_file(file);

	/* XXX: use vfs_ioctl if/when VFS exports it */
	if (!lower_file || !lower_file->f_op)
		goto out;
	if (lower_file->f_op->compat_ioctl)
		err = lower_file->f_op->compat_ioctl(lower_file, cmd, arg);

out:
	return err;
}
#endif

static int stbfs_mmap(struct file *file, struct vm_area_struct *vma)
{
	int err = 0;
	bool willwrite;
	struct file *lower_file;
	const struct vm_operations_struct *saved_vm_ops = NULL;

	/* this might be deferred to mmap's writepage */
	willwrite = ((vma->vm_flags | VM_SHARED | VM_WRITE) == vma->vm_flags);

	/*
	 * File systems which do not implement ->writepage may use
	 * generic_file_readonly_mmap as their ->mmap op.  If you call
	 * generic_file_readonly_mmap with VM_WRITE, you'd get an -EINVAL.
	 * But we cannot call the lower ->mmap op, so we can't tell that
	 * writeable mappings won't work.  Therefore, our only choice is to
	 * check if the lower file system supports the ->writepage, and if
	 * not, return EINVAL (the same error that
	 * generic_file_readonly_mmap returns in that case).
	 */
	lower_file = stbfs_lower_file(file);
	if (willwrite && !lower_file->f_mapping->a_ops->writepage) {
		err = -EINVAL;
		printk(KERN_ERR "stbfs: lower file system does not "
		       "support writeable mmap\n");
		goto out;
	}

	/*
	 * find and save lower vm_ops.
	 *
	 * XXX: the VFS should have a cleaner way of finding the lower vm_ops
	 */
	if (!STBFS_F(file)->lower_vm_ops) {
		err = lower_file->f_op->mmap(lower_file, vma);
		if (err) {
			printk(KERN_ERR "stbfs: lower mmap failed %d\n", err);
			goto out;
		}
		saved_vm_ops = vma->vm_ops; /* save: came from lower ->mmap */
	}

	/*
	 * Next 3 lines are all I need from generic_file_mmap.  I definitely
	 * don't want its test for ->readpage which returns -ENOEXEC.
	 */
	file_accessed(file);
	vma->vm_ops = &stbfs_vm_ops;

	file->f_mapping->a_ops = &stbfs_aops; /* set our aops */
	if (!STBFS_F(file)->lower_vm_ops) /* save for our ->fault */
		STBFS_F(file)->lower_vm_ops = saved_vm_ops;

out:
	return err;
}

static int stbfs_open(struct inode *inode, struct file *file)
{
	int err = 0;
	struct file *lower_file = NULL;
	struct path lower_path;

	/* don't open unhashed/deleted files */
	if (d_unhashed(file->f_path.dentry)) {
		err = -ENOENT;
		goto out_err;
	}

	file->private_data =
		kzalloc(sizeof(struct stbfs_file_info), GFP_KERNEL);
	if (!STBFS_F(file)) {
		err = -ENOMEM;
		goto out_err;
	}

	/* open lower object and link stbfs's file struct to lower's */
	stbfs_get_lower_path(file->f_path.dentry, &lower_path);
	lower_file = dentry_open(&lower_path, file->f_flags, current_cred());
	path_put(&lower_path);
	if (IS_ERR(lower_file)) {
		err = PTR_ERR(lower_file);
		lower_file = stbfs_lower_file(file);
		if (lower_file) {
			stbfs_set_lower_file(file, NULL);
			fput(lower_file); /* fput calls dput for lower_dentry */
		}
	} else {
		stbfs_set_lower_file(file, lower_file);
	}

	if (err)
		kfree(STBFS_F(file));
	else
		fsstack_copy_attr_all(inode, stbfs_lower_inode(inode));
out_err:
	return err;
}

static int stbfs_flush(struct file *file, fl_owner_t id)
{
	int err = 0;
	struct file *lower_file = NULL;

	lower_file = stbfs_lower_file(file);
	if (lower_file && lower_file->f_op && lower_file->f_op->flush) {
		filemap_write_and_wait(file->f_mapping);
		err = lower_file->f_op->flush(lower_file, id);
	}

	return err;
}

/* release all lower object references & free the file info structure */
static int stbfs_file_release(struct inode *inode, struct file *file)
{
	struct file *lower_file;

	lower_file = stbfs_lower_file(file);
	if (lower_file) {
		stbfs_set_lower_file(file, NULL);
		fput(lower_file);
	}

	kfree(STBFS_F(file));
	return 0;
}

static int stbfs_fsync(struct file *file, loff_t start, loff_t end,
			int datasync)
{
	int err;
	struct file *lower_file;
	struct path lower_path;
	struct dentry *dentry = file->f_path.dentry;

	err = __generic_file_fsync(file, start, end, datasync);
	if (err)
		goto out;
	lower_file = stbfs_lower_file(file);
	stbfs_get_lower_path(dentry, &lower_path);
	err = vfs_fsync_range(lower_file, start, end, datasync);
	stbfs_put_lower_path(dentry, &lower_path);
out:
	return err;
}

static int stbfs_fasync(int fd, struct file *file, int flag)
{
	int err = 0;
	struct file *lower_file = NULL;

	lower_file = stbfs_lower_file(file);
	if (lower_file->f_op && lower_file->f_op->fasync)
		err = lower_file->f_op->fasync(fd, lower_file, flag);

	return err;
}

/*
 * Wrapfs cannot use generic_file_llseek as ->llseek, because it would
 * only set the offset of the upper file.  So we have to implement our
 * own method to set both the upper and lower file offsets
 * consistently.
 */
static loff_t stbfs_file_llseek(struct file *file, loff_t offset, int whence)
{
	int err;
	struct file *lower_file;

	err = generic_file_llseek(file, offset, whence);
	if (err < 0)
		goto out;

	lower_file = stbfs_lower_file(file);
	err = generic_file_llseek(lower_file, offset, whence);

out:
	return err;
}

/*
 * Wrapfs read_iter, redirect modified iocb to lower read_iter
 */
ssize_t
stbfs_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	int err;
	struct file *file = iocb->ki_filp, *lower_file;

	lower_file = stbfs_lower_file(file);
	if (!lower_file->f_op->read_iter) {
		err = -EINVAL;
		goto out;
	}

	get_file(lower_file); /* prevent lower_file from being released */
	iocb->ki_filp = lower_file;
	err = lower_file->f_op->read_iter(iocb, iter);
	iocb->ki_filp = file;
	fput(lower_file);
	/* update upper inode atime as needed */
	if (err >= 0 || err == -EIOCBQUEUED)
		fsstack_copy_attr_atime(d_inode(file->f_path.dentry),
					file_inode(lower_file));
out:
	return err;
}

/*
 * Wrapfs write_iter, redirect modified iocb to lower write_iter
 */
ssize_t
stbfs_write_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	int err;
	struct file *file = iocb->ki_filp, *lower_file;

	lower_file = stbfs_lower_file(file);
	if (!lower_file->f_op->write_iter) {
		err = -EINVAL;
		goto out;
	}

	get_file(lower_file); /* prevent lower_file from being released */
	iocb->ki_filp = lower_file;
	err = lower_file->f_op->write_iter(iocb, iter);
	iocb->ki_filp = file;
	fput(lower_file);
	/* update upper inode times/sizes as needed */
	if (err >= 0 || err == -EIOCBQUEUED) {
		fsstack_copy_inode_size(d_inode(file->f_path.dentry),
					file_inode(lower_file));
		fsstack_copy_attr_times(d_inode(file->f_path.dentry),
					file_inode(lower_file));
	}
out:
	return err;
}

const struct file_operations stbfs_main_fops = {
	.llseek		= generic_file_llseek,
	.read		= stbfs_read,
	.write		= stbfs_write,
	.unlocked_ioctl	= stbfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= stbfs_compat_ioctl,
#endif
	.mmap		= stbfs_mmap,
	.open		= stbfs_open,
	.flush		= stbfs_flush,
	.release	= stbfs_file_release,
	.fsync		= stbfs_fsync,
	.fasync		= stbfs_fasync,
	.read_iter	= stbfs_read_iter,
	.write_iter	= stbfs_write_iter,
};

/* trimmed directory options */
const struct file_operations stbfs_dir_fops = {
	.llseek		= stbfs_file_llseek,
	.read		= generic_read_dir,
	.iterate	= stbfs_readdir,
	.unlocked_ioctl	= stbfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= stbfs_compat_ioctl,
#endif
	.open		= stbfs_open,
	.release	= stbfs_file_release,
	.flush		= stbfs_flush,
	.fsync		= stbfs_fsync,
	.fasync		= stbfs_fasync,
};
