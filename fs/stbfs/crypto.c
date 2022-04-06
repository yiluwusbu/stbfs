#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <asm/uaccess.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <crypto/skcipher.h>
#include <crypto/hash.h>
#include <linux/scatterlist.h>
#include "stbfs.h"

#define ALG_NAME_MAX_LEN 64
#define ROUND_UP_DIV(x, n) (((x) - 1) / (n) + 1)

static char * default_crypto = "ctr-aes-aesni";
static char * default_hash_alg = "md5-generic";

static int calc_hash(struct crypto_shash *alg,const unsigned char *data, unsigned int datalen,unsigned char *digest);

/* struct of preamble of the encrypted file in .stb */
struct file_preamble {
	uint8_t name_len;
	uint8_t key_hash[16];
	uint64_t orig_file_sz;
	char name_iv[];      // name followed by first iv value 
};

static char * decode_preamble(struct file * filp, struct crypto_shash *alg, struct cryptocopy_params * p, uint64_t * file_sz) 
{
	struct file_preamble preamble;
	char * name = NULL;
	char * digest = NULL;
	int digest_sz = 0;
	ssize_t n;
	int name_len = strlen(p->alg_name) + 1;

	n = kernel_read(filp, &preamble, sizeof(struct file_preamble), &filp->f_pos);
	if (n != sizeof(struct file_preamble)) {
		dbg_printk("error reading preamble head, returns %ld\n", n);
		return n < 0 ? ERR_PTR(n) : ERR_PTR(-EFAULT);	
	}
	// verify encryption methods name length
	if (preamble.name_len != name_len) {
		dbg_printk("encryption method doesn't match with the one in the preamble\n");
		return ERR_PTR(-EINVAL);
	}

	// verify hash
	digest_sz = crypto_shash_digestsize(alg);
	digest = kmalloc(digest_sz, GFP_KERNEL);
	if (!digest) {
		return ERR_PTR(-ENOMEM);
	}
	if ((n=calc_hash(alg, p->keybuf, p->key_len, digest))) {
		dbg_printk("error calculating hash, err=%ld\n", n);
		name = ERR_PTR(n);
		goto out;
	}
	// compare the hash values
	if (memcmp(digest, preamble.key_hash, 16)) {
		dbg_printk("hash doesn't match with the one in the preamble\n");
		name = ERR_PTR(-ENOKEY);
		goto out;
	}

	name = kmalloc(preamble.name_len, GFP_KERNEL);
	if (!name) {
		name = ERR_PTR(-ENOMEM);
		goto out;
	}

	n = kernel_read(filp, name, preamble.name_len, &filp->f_pos);
	if (n != preamble.name_len) {
		dbg_printk("error reading preamble alg name, returns %ld\n", n);
		kfree(name);
		name = n < 0 ? ERR_PTR(n) : ERR_PTR(-EFAULT);
		goto out;
	}

	// compare the names
	if (memcmp(name, p->alg_name, name_len)) {
		dbg_printk("encryption method doesn't match with the one in the preamble\n");
		kfree(name);
		name = ERR_PTR(-EINVAL);
		goto out;
	}
	// normal path
	*file_sz = preamble.orig_file_sz;
out:
	if (digest)
		kfree(digest);
	return name;
}


static int encode_preamble(struct file * filp, struct crypto_shash *hash_alg, struct cryptocopy_params *p, char *iv, int iv_len, uint64_t file_sz) 
{
	struct file_preamble *preamble = NULL;
	int ret = 0;
	char * digest = NULL;
	int digest_sz = 0;
	int alg_name_len = strlen(p->alg_name) + 1;
	int preamble_sz = sizeof(struct file_preamble) + alg_name_len + iv_len;
	
	ssize_t n;

	// calculate hash
	digest_sz = crypto_shash_digestsize(hash_alg);
	digest = kmalloc(digest_sz, GFP_KERNEL);

	if (!digest) {
		return -ENOMEM;
	}
	preamble = kmalloc(preamble_sz, GFP_KERNEL);
	if (!preamble) {
		ret = -ENOMEM;
		goto out;
	}
	if ((ret=calc_hash(hash_alg, p->keybuf, p->key_len, digest))) {
		dbg_printk("error calculating hash\n");
		goto out;
	}
	memcpy(preamble->key_hash, digest, 16);
	memcpy(&preamble->name_iv[0], p->alg_name, alg_name_len );
	if (iv) {
		memcpy(&preamble->name_iv[alg_name_len], iv, iv_len);
	}
	preamble->orig_file_sz = file_sz;
	preamble->name_len = alg_name_len;
	// write name
	n = kernel_write(filp, preamble, preamble_sz, &filp->f_pos);
	if (n != preamble_sz) {
		dbg_printk("error writing preamble, returns %ld\n", n);
		ret = n < 0 ? n : -EFAULT;	
		goto out;
	}

out:
	if (digest)
		kfree(digest);
	if (preamble)
		kfree(preamble);
	return ret;
}

static int check_flags(int flags) 
{
	if (flags != 0x1 && flags != 0x2 && flags != 0x4) {
		return -EINVAL;
	}
	return 0;
}

static int check_keylen(int keylen) 
{
	if (keylen != 16 && keylen != 24 && keylen != 32) {
		return -EINVAL;
	}
	return 0;
}


struct sdesc {
    struct shash_desc shash;
    char ctx[];
};

static struct sdesc *init_sdesc(struct crypto_shash *alg)
{
    struct sdesc *sdesc;
    int size;

    size = sizeof(struct shash_desc) + crypto_shash_descsize(alg);
    sdesc = kmalloc(size, GFP_KERNEL);
    if (!sdesc)
        return ERR_PTR(-ENOMEM);
    sdesc->shash.tfm = alg;
    return sdesc;
}

static int calc_hash(struct crypto_shash *alg,
             const unsigned char *data, unsigned int datalen,
             unsigned char *digest)
{
    struct sdesc *sdesc;
    int ret;

    sdesc = init_sdesc(alg);
    if (IS_ERR(sdesc)) {
        dbg_printk("can't alloc sdesc\n");
        return PTR_ERR(sdesc);
    }

    ret = crypto_shash_digest(&sdesc->shash, data, datalen, digest);
    kfree(sdesc);
    return ret;
}

int create_aes_key_16(const char *password, char *key)
{
	struct crypto_shash *hash_alg;
	int len = strlen(password);
	int ret =0;
	if (len < 6) {
		return -EINVAL;
	}
	hash_alg = crypto_alloc_shash(default_hash_alg, CRYPTO_ALG_TYPE_SHASH, 0);
	if (IS_ERR(hash_alg)) {
		dbg_printk("can't alloc hash alg %s\n", default_hash_alg);
		return PTR_ERR(hash_alg);
		
	}
	ret = calc_hash(hash_alg, password, len, key);
	crypto_free_shash(hash_alg);
	return ret;
}


static struct crypto_skcipher * create_crypto_skcipher(char * cipher_name, struct cryptocopy_params * params)
{
    struct crypto_skcipher *skcipher = NULL;
	int err;

    skcipher = crypto_alloc_skcipher(cipher_name, 0, 0);
    if (IS_ERR(skcipher)) {
        dbg_printk("could not allocate skcipher handle\n");
        goto out;
    }

    if ((err = crypto_skcipher_setkey(skcipher, params->keybuf, params->key_len))) {
        dbg_printk("key could not be set\n");
		crypto_free_skcipher(skcipher);
		skcipher = ERR_PTR(err);
    }

out:
    return skcipher;
}

static int do_decrypt_file(struct file * infilp, struct file * outfilp, struct crypto_shash *hash_alg, struct cryptocopy_params * p) 
{
	int ret = 0;
	struct skcipher_request *req = NULL;
	void * buf = NULL;
	struct scatterlist sg;
	ssize_t nread, nwrite, to_write;
	ssize_t total_read=0;
	int iv_size;
	char * iv = NULL;
	uint64_t orig_file_sz = 0;
	struct crypto_skcipher * skcipher = NULL;
	uint64_t pageno=0;
	char * alg_name = NULL;
	int blksz, bufsz; 

	infilp->f_pos = 0;
	outfilp->f_pos = 0;

	
	alg_name = decode_preamble(infilp, hash_alg, p, &orig_file_sz);
	if (IS_ERR(alg_name)) {
		ret = PTR_ERR(alg_name);
		alg_name = NULL;
		goto out;
	}
	skcipher = create_crypto_skcipher(alg_name, p);
	if (IS_ERR(skcipher)) {
		ret = PTR_ERR(skcipher);
		skcipher = NULL;
		goto out;
	}
	blksz = crypto_skcipher_blocksize(skcipher);
	dbg_printk("blksz = %d\n", blksz);
	bufsz = ROUND_UP_DIV(PAGE_SIZE, blksz) * blksz;
	buf = kzalloc(bufsz, GFP_KERNEL);
	if (!buf) {
		ret =  -ENOMEM;
		goto out;
	}

	req = skcipher_request_alloc(skcipher, GFP_KERNEL);
    if (!req) {
        dbg_printk("Could not allocate skcipher request\n");
        ret = -ENOMEM;
        goto out;
    }
	iv_size = crypto_skcipher_ivsize(skcipher);

	if (iv_size) {
		iv = kmalloc(iv_size, GFP_KERNEL);
		if (!iv) {
			ret = -ENOMEM;
			goto out;
		}
		nread = kernel_read(infilp, iv, iv_size, &infilp->f_pos);
		if (nread != iv_size) {
			dbg_printk("error in reading preamble, errcode = %ld\n", nread);
			ret =  -EFAULT;
			goto out;
		}
		memcpy(&pageno, iv, 8);
	}
	
	while ((nread = kernel_read(infilp, buf, bufsz, &infilp->f_pos)) > 0) {
		total_read += nread;

		sg_init_one(&sg, buf, nread);
		skcipher_request_set_crypt(req, &sg, &sg, nread, iv);
		ret = crypto_skcipher_decrypt(req);
		if (ret) {
			dbg_printk("decryption function returned %d\n", ret);
			goto out;
		}
		// update iv
		if (iv) {
			pageno++;
			memcpy(iv, &pageno, 8);
		}
		
		to_write = (total_read > orig_file_sz) ? (nread - (total_read - orig_file_sz)) : nread;
		if (to_write < 0) {
			pr_warn("Writing negative number of bytes\n");
			ret =  -EFAULT;
			goto out;
		}
		nwrite = kernel_write(outfilp, buf, to_write, &outfilp->f_pos);
		if (nwrite != to_write) {
			dbg_printk("error in writing file, errcode = %ld\n", nwrite);
			ret = nwrite < 0 ? nwrite : -EFAULT;
			goto out;
		}
	}

	if (nread < 0) {
		dbg_printk("error in reading file, errcode = %ld\n", nread);
		ret = nread;
	}
out:
	if (iv) 
		kfree(iv);
	if (skcipher)
		crypto_free_skcipher(skcipher);
	if (alg_name) 
		kfree(alg_name);
	if (buf)
		kfree(buf);
	if (req)
        skcipher_request_free(req);
	return ret;
}

static int do_encrypt_file(struct file * infilp, struct file * outfilp, struct crypto_shash *hash_alg, struct cryptocopy_params * p, uint64_t orig_file_sz) 
{
	int ret = 0;
	struct skcipher_request *req = NULL;
	void * buf = NULL;
	struct scatterlist sg;
	int blksz;
	ssize_t nread, nwrite, to_write;
	int iv_size;
	char * iv = NULL;
	struct crypto_skcipher * skcipher = NULL;
	uint64_t pageno=0;
	int bufsz;

	infilp->f_pos = 0;
	outfilp->f_pos = 0;

	skcipher = create_crypto_skcipher(p->alg_name, p);
	if (IS_ERR(skcipher)) {
		ret = PTR_ERR(skcipher);
		skcipher = NULL;
		goto out;
	}

	blksz = crypto_skcipher_blocksize(skcipher);
	bufsz = ROUND_UP_DIV(PAGE_SIZE, blksz) * blksz;
	dbg_printk("blksz = %d, bufsz = %d\n", blksz, bufsz);

	buf = kzalloc(bufsz, GFP_KERNEL);
	if (!buf) {
		ret =  -ENOMEM;
		goto out;
	}

	req = skcipher_request_alloc(skcipher, GFP_KERNEL);
    if (!req) {
        dbg_printk("Could not allocate skcipher request\n");
        ret = -ENOMEM;
        goto out;
    }
	iv_size = crypto_skcipher_ivsize(skcipher);

	if (iv_size) {
		iv = kmalloc(iv_size, GFP_KERNEL);
		if (!iv) {
			ret = -ENOMEM;
			goto out;
		}
		pageno = (uint64_t)buf;
		memcpy(iv, &pageno, 8);
		if (iv_size >= 16) {
			memcpy(&iv[8], &infilp->f_inode->i_ino, 8);
		}
	}

	ret = encode_preamble(outfilp, hash_alg, p, iv, iv_size, orig_file_sz);
	if (ret) {
		goto out;
	}
	
	while ((nread = kernel_read(infilp, buf, bufsz, &infilp->f_pos)) > 0) {
		to_write = ROUND_UP_DIV(nread, blksz) * blksz;
		
		sg_init_one(&sg, buf, to_write);
		skcipher_request_set_crypt(req, &sg, &sg, to_write, iv);
		ret = crypto_skcipher_encrypt(req);
		if (ret) {
			dbg_printk("encryption function returned %d\n", ret);
			goto out;
		}
		// update iv
		if (iv) {
			pageno++;
			memcpy(iv, &pageno, 8);
		}
		
		nwrite = kernel_write(outfilp, buf, to_write, &outfilp->f_pos);
		if (nwrite != to_write) {
			dbg_printk("error in writing file, errcode = %ld\n", nwrite);
			ret = nwrite < 0 ? nwrite : -EFAULT;
			goto out;
		}
		memset(buf, 0, bufsz);
	}

	if (nread < 0) {
		dbg_printk("error in reading file, errcode = %ld\n", nread);
		ret = nread;
	}
out:
	if (iv) 
		kfree(iv);
	if (skcipher)
		crypto_free_skcipher(skcipher);
	if (buf)
		kfree(buf);
	if (req)
        skcipher_request_free(req);
	return ret;
}


static int do_copy_file(struct file * src, struct file *dst) 
{
	ssize_t nread, nwrite;
	char * buf;
	int ret = 0;
	src->f_pos = 0;
	dst->f_pos = 0;
	buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!buf) {
		return -ENOMEM;
	}
	
	while ((nread = kernel_read(src, buf, PAGE_SIZE, &src->f_pos)) > 0) {
		nwrite = kernel_write(dst, buf, nread, &dst->f_pos);
		if (nwrite != nread) {
			dbg_printk("error in writing file, errcode = %ld\n", nwrite);
			ret = nwrite < 0 ? nwrite : -EACCES;
			goto out;
		}
	}
	if (nread < 0) {
		dbg_printk("error in reading file, errcode = %ld\n", nread);
		ret = nread;
	}

out:
	kfree(buf);
	return ret;
}


long stbfs_cryptocopy(struct cryptocopy_params * params)
{
	/* dummy syscall: returns 0 for non null, -EINVAL for NULL */
	int ret = 0;
	struct file * in_filp, *out_filp;
	struct crypto_shash *hash_alg=NULL;

	ret = check_flags(params->flags);
	if (ret < 0) {
		dbg_printk("invalid flags\n");
		ret = -EINVAL;
		goto out;
	}

    if (params->flags != COPY_FLAG) {
        ret = check_keylen(params->key_len);
        if (ret < 0) {
            dbg_printk("invalid key length\n");
            ret = -EINVAL;
            goto out;
        }
    }

    if (params->flags != COPY_FLAG && !params->alg_name) {
        params->alg_name = default_crypto;
    }

	in_filp =  params->in_filp;
	out_filp = params->out_filp;

	if (params->flags == 0x4) {
		// copy file
		ret = do_copy_file(in_filp, out_filp);
		if (ret < 0) {
			goto out;
		}
	} else if (params->flags == 0x1 || params->flags == 0x2 ) {
		hash_alg = crypto_alloc_shash(default_hash_alg, CRYPTO_ALG_TYPE_SHASH, 0);
		if (IS_ERR(hash_alg)) {
			dbg_printk("can't alloc hash alg %s\n", default_hash_alg);
			ret = PTR_ERR(hash_alg);
			goto out;
		}
		if (params->flags == 0x1) {
			ret = do_encrypt_file(in_filp, out_filp, hash_alg, params, i_size_read(in_filp->f_inode));
		} else {
			ret = do_decrypt_file(in_filp, out_filp, hash_alg, params);
		}
		/* free hash */
		crypto_free_shash(hash_alg);
		if (ret) {
			dbg_printk("error in encrypting/decrypting files\n");
			goto out;
		}
	} else {
		ret = -EOPNOTSUPP;
		goto out;
	}

	goto out;
	

out:
	return ret;
}


