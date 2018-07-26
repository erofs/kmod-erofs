// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2017-2018 HUAWEI, Inc.
 *             https://www.huawei.com/
 * Copyright (C) 2021, Alibaba Cloud
 */
#include "internal.h"

static void *erofs_read_inode(struct erofs_buf *buf,
			      struct inode *inode, unsigned int *ofs)
{
	struct super_block *sb = inode->i_sb;
	struct erofs_sb_info *sbi = EROFS_SB(sb);
	struct erofs_inode *vi = EROFS_I(inode);
	const erofs_off_t inode_loc = erofs_iloc(inode);
	erofs_blk_t blkaddr = erofs_blknr(sb, inode_loc);
	void *kaddr;
	struct erofs_inode_compact *dic;
	struct erofs_inode_extended *die, *copied = NULL;
	union erofs_inode_i_u iu;
	unsigned int ifmt;
	int err;

	*ofs = erofs_blkoff(sb, inode_loc);
	kaddr = erofs_read_metabuf(buf, sb, blkaddr, EROFS_KMAP_ATOMIC);
	if (IS_ERR(kaddr)) {
		erofs_err(sb, "failed to get inode (nid: %llu) page, err %ld",
			  vi->nid, PTR_ERR(kaddr));
		return kaddr;
	}

	dic = kaddr + *ofs;
	ifmt = le16_to_cpu(dic->i_format);

	if (ifmt & ~EROFS_I_ALL) {
		erofs_err(sb, "unsupported i_format %u of nid %llu",
			  ifmt, vi->nid);
		err = -EOPNOTSUPP;
		goto err_out;
	}

	vi->datalayout = erofs_inode_datalayout(ifmt);
	if (vi->datalayout >= EROFS_INODE_DATALAYOUT_MAX) {
		erofs_err(sb, "unsupported datalayout %u of nid %llu",
			  vi->datalayout, vi->nid);
		err = -EOPNOTSUPP;
		goto err_out;
	}

	switch (erofs_inode_version(ifmt)) {
	case EROFS_INODE_LAYOUT_EXTENDED:
		vi->inode_isize = sizeof(struct erofs_inode_extended);
		/* check if the extended inode acrosses block boundary */
		if (*ofs + vi->inode_isize <= sb->s_blocksize) {
			*ofs += vi->inode_isize;
			die = (struct erofs_inode_extended *)dic;
		} else {
			const unsigned int gotten = sb->s_blocksize - *ofs;

			copied = kmalloc(vi->inode_isize, GFP_ATOMIC);
			if (!copied) {
				err = -ENOMEM;
				goto err_out;
			}
			memcpy(copied, dic, gotten);
			kaddr = erofs_read_metabuf(buf, sb, blkaddr + 1,
						   EROFS_KMAP_ATOMIC);
			if (IS_ERR(kaddr)) {
				erofs_err(sb, "failed to get inode payload block (nid: %llu), err %ld",
					  vi->nid, PTR_ERR(kaddr));
				kfree(copied);
				return kaddr;
			}
			*ofs = vi->inode_isize - gotten;
			memcpy((u8 *)copied + gotten, kaddr, *ofs);
			die = copied;
		}
		vi->xattr_isize = erofs_xattr_ibody_size(die->i_xattr_icount);

		inode->i_mode = le16_to_cpu(die->i_mode);
		iu = die->i_u;
		i_uid_write(inode, le32_to_cpu(die->i_uid));
		i_gid_write(inode, le32_to_cpu(die->i_gid));
		set_nlink(inode, le32_to_cpu(die->i_nlink));

		/* each extended inode has its own timestamp */
		inode->i_ctime.tv_sec = le64_to_cpu(die->i_mtime);
		inode->i_ctime.tv_nsec = le32_to_cpu(die->i_mtime_nsec);

		inode->i_size = le64_to_cpu(die->i_size);
		kfree(copied);
		copied = NULL;
		break;
	case EROFS_INODE_LAYOUT_COMPACT:
		vi->inode_isize = sizeof(struct erofs_inode_compact);
		*ofs += vi->inode_isize;
		vi->xattr_isize = erofs_xattr_ibody_size(dic->i_xattr_icount);

		inode->i_mode = le16_to_cpu(dic->i_mode);
		iu = dic->i_u;
		i_uid_write(inode, le16_to_cpu(dic->i_uid));
		i_gid_write(inode, le16_to_cpu(dic->i_gid));
		set_nlink(inode, le16_to_cpu(dic->i_nlink));

		/* use build time for compact inodes */
		inode->i_ctime.tv_sec = sbi->build_time;
		inode->i_ctime.tv_nsec = sbi->build_time_nsec;

		inode->i_size = le32_to_cpu(dic->i_size);
		break;
	default:
		erofs_err(sb, "unsupported on-disk inode version %u of nid %llu",
			  erofs_inode_version(ifmt), vi->nid);
		err = -EOPNOTSUPP;
		goto err_out;
	}

	switch (inode->i_mode & S_IFMT) {
	case S_IFREG:
	case S_IFDIR:
	case S_IFLNK:
		vi->raw_blkaddr = le32_to_cpu(iu.raw_blkaddr);
		break;
	default:
		erofs_err(sb, "bogus i_mode (%o) @ nid %llu", inode->i_mode,
			  vi->nid);
		err = -EFSCORRUPTED;
		goto err_out;
	}
	inode->i_mtime.tv_sec = inode->i_ctime.tv_sec;
	inode->i_atime.tv_sec = inode->i_ctime.tv_sec;
	inode->i_mtime.tv_nsec = inode->i_ctime.tv_nsec;
	inode->i_atime.tv_nsec = inode->i_ctime.tv_nsec;
	inode->i_blocks = round_up(inode->i_size, sb->s_blocksize) >> 9;
	return kaddr;

err_out:
	DBG_BUGON(1);
	kfree(copied);
	erofs_put_metabuf(buf);
	return ERR_PTR(err);
}

static int erofs_fill_inode(struct inode *inode)
{
	struct erofs_buf buf = __EROFS_BUF_INITIALIZER;
	void *kaddr;
	unsigned int ofs;
	int err = 0;

	/* read inode base data from disk */
	kaddr = erofs_read_inode(&buf, inode, &ofs);
	if (IS_ERR(kaddr))
		return PTR_ERR(kaddr);

	/* setup the new inode */
	switch (inode->i_mode & S_IFMT) {
	case S_IFREG:
		inode->i_fop = &generic_ro_fops;
		break;
	case S_IFDIR:
		inode->i_op = &erofs_dir_iops;
		inode->i_fop = &erofs_dir_fops;
		mapping_set_gfp_mask(inode->i_mapping, GFP_USER);
		break;
	case S_IFLNK:
		inode->i_op = &page_symlink_inode_operations;
		break;
	default:
		err = -EFSCORRUPTED;
		goto out_unlock;
	}
	inode->i_mapping->a_ops = &erofs_raw_access_aops;
out_unlock:
	erofs_put_metabuf(&buf);
	return err;
}

/*
 * ino_t is 32-bits on 32-bit arch. We have to squash the 64-bit value down
 * so that it will fit.
 */
static ino_t erofs_squash_ino(erofs_nid_t nid)
{
	ino_t ino = (ino_t)nid;

	if (sizeof(ino_t) < sizeof(erofs_nid_t))
		ino ^= nid >> (sizeof(erofs_nid_t) - sizeof(ino_t)) * 8;
	return ino;
}

static int erofs_iget5_eq(struct inode *inode, void *opaque)
{
	return EROFS_I(inode)->nid == *(erofs_nid_t *)opaque;
}

static int erofs_iget5_set(struct inode *inode, void *opaque)
{
	const erofs_nid_t nid = *(erofs_nid_t *)opaque;

	inode->i_ino = erofs_squash_ino(nid);
	EROFS_I(inode)->nid = nid;
	return 0;
}

struct inode *erofs_iget(struct super_block *sb, erofs_nid_t nid)
{
	struct inode *inode;

	inode = iget5_locked(sb, erofs_squash_ino(nid), erofs_iget5_eq,
			     erofs_iget5_set, &nid);
	if (!inode)
		return ERR_PTR(-ENOMEM);

	if (inode->i_state & I_NEW) {
		int err = erofs_fill_inode(inode);

		if (err) {
			iget_failed(inode);
			return ERR_PTR(err);
		}
		unlock_new_inode(inode);
	}
	return inode;
}
