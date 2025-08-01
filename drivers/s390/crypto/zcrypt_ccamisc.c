// SPDX-License-Identifier: GPL-2.0+
/*
 *  Copyright IBM Corp. 2019
 *  Author(s): Harald Freudenberger <freude@linux.ibm.com>
 *	       Ingo Franzki <ifranzki@linux.ibm.com>
 *
 *  Collection of CCA misc functions used by zcrypt and pkey
 */

#define KMSG_COMPONENT "zcrypt"
#define pr_fmt(fmt) KMSG_COMPONENT ": " fmt

#include <linux/export.h>
#include <linux/init.h>
#include <linux/mempool.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <asm/zcrypt.h>
#include <asm/pkey.h>

#include "ap_bus.h"
#include "zcrypt_api.h"
#include "zcrypt_debug.h"
#include "zcrypt_msgtype6.h"
#include "zcrypt_ccamisc.h"

/* Size of parameter block used for all cca requests/replies */
#define PARMBSIZE 512

/* Size of vardata block used for some of the cca requests/replies */
#define VARDATASIZE 4096

/*
 * Cprb memory pool held for urgent cases where no memory
 * can be allocated via kmalloc. This pool is only used
 * when alloc_and_prep_cprbmem() is called with the xflag
 * ZCRYPT_XFLAG_NOMEMALLOC. The cprb memory needs to hold
 * space for request AND reply!
 */
#define CPRB_MEMPOOL_ITEM_SIZE (16 * 1024)
static mempool_t *cprb_mempool;

/*
 * This is a pre-allocated memory for the device status array
 * used within the findcard() functions. It is currently
 * 128 * 128 * 4 bytes = 64 KB big. Usage of this memory is
 * controlled via dev_status_mem_mutex. Needs adaption if more
 * than 128 cards or domains to be are supported.
 */
#define ZCRYPT_DEV_STATUS_CARD_MAX 128
#define ZCRYPT_DEV_STATUS_QUEUE_MAX 128
#define ZCRYPT_DEV_STATUS_ENTRIES (ZCRYPT_DEV_STATUS_CARD_MAX * \
				   ZCRYPT_DEV_STATUS_QUEUE_MAX)
#define ZCRYPT_DEV_STATUS_EXT_SIZE (ZCRYPT_DEV_STATUS_ENTRIES * \
		sizeof(struct zcrypt_device_status_ext))
static void *dev_status_mem;
static DEFINE_MUTEX(dev_status_mem_mutex);

/*
 * Simple check if the token is a valid CCA secure AES data key
 * token. If keybitsize is given, the bitsize of the key is
 * also checked. Returns 0 on success or errno value on failure.
 */
int cca_check_secaeskeytoken(debug_info_t *dbg, int dbflvl,
			     const u8 *token, int keybitsize)
{
	struct secaeskeytoken *t = (struct secaeskeytoken *)token;

#define DBF(...) debug_sprintf_event(dbg, dbflvl, ##__VA_ARGS__)

	if (t->type != TOKTYPE_CCA_INTERNAL) {
		if (dbg)
			DBF("%s token check failed, type 0x%02x != 0x%02x\n",
			    __func__, (int)t->type, TOKTYPE_CCA_INTERNAL);
		return -EINVAL;
	}
	if (t->version != TOKVER_CCA_AES) {
		if (dbg)
			DBF("%s token check failed, version 0x%02x != 0x%02x\n",
			    __func__, (int)t->version, TOKVER_CCA_AES);
		return -EINVAL;
	}
	if (keybitsize > 0 && t->bitsize != keybitsize) {
		if (dbg)
			DBF("%s token check failed, bitsize %d != %d\n",
			    __func__, (int)t->bitsize, keybitsize);
		return -EINVAL;
	}

#undef DBF

	return 0;
}
EXPORT_SYMBOL(cca_check_secaeskeytoken);

/*
 * Simple check if the token is a valid CCA secure AES cipher key
 * token. If keybitsize is given, the bitsize of the key is
 * also checked. If checkcpacfexport is enabled, the key is also
 * checked for the export flag to allow CPACF export.
 * Returns 0 on success or errno value on failure.
 */
int cca_check_secaescipherkey(debug_info_t *dbg, int dbflvl,
			      const u8 *token, int keybitsize,
			      int checkcpacfexport)
{
	struct cipherkeytoken *t = (struct cipherkeytoken *)token;
	bool keybitsizeok = true;

#define DBF(...) debug_sprintf_event(dbg, dbflvl, ##__VA_ARGS__)

	if (t->type != TOKTYPE_CCA_INTERNAL) {
		if (dbg)
			DBF("%s token check failed, type 0x%02x != 0x%02x\n",
			    __func__, (int)t->type, TOKTYPE_CCA_INTERNAL);
		return -EINVAL;
	}
	if (t->version != TOKVER_CCA_VLSC) {
		if (dbg)
			DBF("%s token check failed, version 0x%02x != 0x%02x\n",
			    __func__, (int)t->version, TOKVER_CCA_VLSC);
		return -EINVAL;
	}
	if (t->algtype != 0x02) {
		if (dbg)
			DBF("%s token check failed, algtype 0x%02x != 0x02\n",
			    __func__, (int)t->algtype);
		return -EINVAL;
	}
	if (t->keytype != 0x0001) {
		if (dbg)
			DBF("%s token check failed, keytype 0x%04x != 0x0001\n",
			    __func__, (int)t->keytype);
		return -EINVAL;
	}
	if (t->plfver != 0x00 && t->plfver != 0x01) {
		if (dbg)
			DBF("%s token check failed, unknown plfver 0x%02x\n",
			    __func__, (int)t->plfver);
		return -EINVAL;
	}
	if (t->wpllen != 512 && t->wpllen != 576 && t->wpllen != 640) {
		if (dbg)
			DBF("%s token check failed, unknown wpllen %d\n",
			    __func__, (int)t->wpllen);
		return -EINVAL;
	}
	if (keybitsize > 0) {
		switch (keybitsize) {
		case 128:
			if (t->wpllen != (t->plfver ? 640 : 512))
				keybitsizeok = false;
			break;
		case 192:
			if (t->wpllen != (t->plfver ? 640 : 576))
				keybitsizeok = false;
			break;
		case 256:
			if (t->wpllen != 640)
				keybitsizeok = false;
			break;
		default:
			keybitsizeok = false;
			break;
		}
		if (!keybitsizeok) {
			if (dbg)
				DBF("%s token check failed, bitsize %d\n",
				    __func__, keybitsize);
			return -EINVAL;
		}
	}
	if (checkcpacfexport && !(t->kmf1 & KMF1_XPRT_CPAC)) {
		if (dbg)
			DBF("%s token check failed, XPRT_CPAC bit is 0\n",
			    __func__);
		return -EINVAL;
	}

#undef DBF

	return 0;
}
EXPORT_SYMBOL(cca_check_secaescipherkey);

/*
 * Simple check if the token is a valid CCA secure ECC private
 * key token. Returns 0 on success or errno value on failure.
 */
int cca_check_sececckeytoken(debug_info_t *dbg, int dbflvl,
			     const u8 *token, u32 keysize,
			     int checkcpacfexport)
{
	struct eccprivkeytoken *t = (struct eccprivkeytoken *)token;

#define DBF(...) debug_sprintf_event(dbg, dbflvl, ##__VA_ARGS__)

	if (t->type != TOKTYPE_CCA_INTERNAL_PKA) {
		if (dbg)
			DBF("%s token check failed, type 0x%02x != 0x%02x\n",
			    __func__, (int)t->type, TOKTYPE_CCA_INTERNAL_PKA);
		return -EINVAL;
	}
	if (t->len > keysize) {
		if (dbg)
			DBF("%s token check failed, len %d > keysize %u\n",
			    __func__, (int)t->len, keysize);
		return -EINVAL;
	}
	if (t->secid != 0x20) {
		if (dbg)
			DBF("%s token check failed, secid 0x%02x != 0x20\n",
			    __func__, (int)t->secid);
		return -EINVAL;
	}
	if (checkcpacfexport && !(t->kutc & 0x01)) {
		if (dbg)
			DBF("%s token check failed, XPRTCPAC bit is 0\n",
			    __func__);
		return -EINVAL;
	}

#undef DBF

	return 0;
}
EXPORT_SYMBOL(cca_check_sececckeytoken);

/*
 * Allocate consecutive memory for request CPRB, request param
 * block, reply CPRB and reply param block and fill in values
 * for the common fields. Returns 0 on success or errno value
 * on failure.
 */
static int alloc_and_prep_cprbmem(size_t paramblen,
				  u8 **p_cprb_mem,
				  struct CPRBX **p_req_cprb,
				  struct CPRBX **p_rep_cprb,
				  u32 xflags)
{
	u8 *cprbmem = NULL;
	size_t cprbplusparamblen = sizeof(struct CPRBX) + paramblen;
	size_t len = 2 * cprbplusparamblen;
	struct CPRBX *preqcblk, *prepcblk;

	/*
	 * allocate consecutive memory for request CPRB, request param
	 * block, reply CPRB and reply param block
	 */
	if (xflags & ZCRYPT_XFLAG_NOMEMALLOC) {
		if (len <= CPRB_MEMPOOL_ITEM_SIZE)
			cprbmem = mempool_alloc_preallocated(cprb_mempool);
	} else {
		cprbmem = kmalloc(len, GFP_KERNEL);
	}
	if (!cprbmem)
		return -ENOMEM;
	memset(cprbmem, 0, len);

	preqcblk = (struct CPRBX *)cprbmem;
	prepcblk = (struct CPRBX *)(cprbmem + cprbplusparamblen);

	/* fill request cprb struct */
	preqcblk->cprb_len = sizeof(struct CPRBX);
	preqcblk->cprb_ver_id = 0x02;
	memcpy(preqcblk->func_id, "T2", 2);
	preqcblk->rpl_msgbl = cprbplusparamblen;
	if (paramblen) {
		preqcblk->req_parmb =
			((u8 __user *)preqcblk) + sizeof(struct CPRBX);
		preqcblk->rpl_parmb =
			((u8 __user *)prepcblk) + sizeof(struct CPRBX);
	}

	*p_cprb_mem = cprbmem;
	*p_req_cprb = preqcblk;
	*p_rep_cprb = prepcblk;

	return 0;
}

/*
 * Free the cprb memory allocated with the function above.
 * If the scrub value is not zero, the memory is filled
 * with zeros before freeing (useful if there was some
 * clear key material in there).
 */
static void free_cprbmem(void *mem, size_t paramblen, bool scrub, u32 xflags)
{
	if (mem && scrub)
		memzero_explicit(mem, 2 * (sizeof(struct CPRBX) + paramblen));

	if (xflags & ZCRYPT_XFLAG_NOMEMALLOC)
		mempool_free(mem, cprb_mempool);
	else
		kfree(mem);
}

/*
 * Helper function to prepare the xcrb struct
 */
static inline void prep_xcrb(struct ica_xcRB *pxcrb,
			     u16 cardnr,
			     struct CPRBX *preqcblk,
			     struct CPRBX *prepcblk)
{
	memset(pxcrb, 0, sizeof(*pxcrb));
	pxcrb->agent_ID = 0x4341; /* 'CA' */
	pxcrb->user_defined = (cardnr == 0xFFFF ? AUTOSELECT : cardnr);
	pxcrb->request_control_blk_length =
		preqcblk->cprb_len + preqcblk->req_parml;
	pxcrb->request_control_blk_addr = (void __user *)preqcblk;
	pxcrb->reply_control_blk_length = preqcblk->rpl_msgbl;
	pxcrb->reply_control_blk_addr = (void __user *)prepcblk;
}

/*
 * Generate (random) CCA AES DATA secure key.
 */
int cca_genseckey(u16 cardnr, u16 domain,
		  u32 keybitsize, u8 *seckey, u32 xflags)
{
	int i, rc, keysize;
	int seckeysize;
	u8 *mem, *ptr;
	struct CPRBX *preqcblk, *prepcblk;
	struct ica_xcRB xcrb;
	struct kgreqparm {
		u8  subfunc_code[2];
		u16 rule_array_len;
		struct lv1 {
			u16 len;
			char  key_form[8];
			char  key_length[8];
			char  key_type1[8];
			char  key_type2[8];
		} lv1;
		struct lv2 {
			u16 len;
			struct keyid {
				u16 len;
				u16 attr;
				u8  data[SECKEYBLOBSIZE];
			} keyid[6];
		} lv2;
	} __packed * preqparm;
	struct kgrepparm {
		u8  subfunc_code[2];
		u16 rule_array_len;
		struct lv3 {
			u16 len;
			u16 keyblocklen;
			struct {
				u16 toklen;
				u16 tokattr;
				u8  tok[];
				/* ... some more data ... */
			} keyblock;
		} lv3;
	} __packed * prepparm;

	/* get already prepared memory for 2 cprbs with param block each */
	rc = alloc_and_prep_cprbmem(PARMBSIZE, &mem,
				    &preqcblk, &prepcblk, xflags);
	if (rc)
		return rc;

	/* fill request cprb struct */
	preqcblk->domain = domain;

	/* fill request cprb param block with KG request */
	preqparm = (struct kgreqparm __force *)preqcblk->req_parmb;
	memcpy(preqparm->subfunc_code, "KG", 2);
	preqparm->rule_array_len = sizeof(preqparm->rule_array_len);
	preqparm->lv1.len = sizeof(struct lv1);
	memcpy(preqparm->lv1.key_form,	 "OP      ", 8);
	switch (keybitsize) {
	case PKEY_SIZE_AES_128:
	case PKEY_KEYTYPE_AES_128: /* older ioctls used this */
		keysize = 16;
		memcpy(preqparm->lv1.key_length, "KEYLN16 ", 8);
		break;
	case PKEY_SIZE_AES_192:
	case PKEY_KEYTYPE_AES_192: /* older ioctls used this */
		keysize = 24;
		memcpy(preqparm->lv1.key_length, "KEYLN24 ", 8);
		break;
	case PKEY_SIZE_AES_256:
	case PKEY_KEYTYPE_AES_256: /* older ioctls used this */
		keysize = 32;
		memcpy(preqparm->lv1.key_length, "KEYLN32 ", 8);
		break;
	default:
		ZCRYPT_DBF_ERR("%s unknown/unsupported keybitsize %d\n",
			       __func__, keybitsize);
		rc = -EINVAL;
		goto out;
	}
	memcpy(preqparm->lv1.key_type1,  "AESDATA ", 8);
	preqparm->lv2.len = sizeof(struct lv2);
	for (i = 0; i < 6; i++) {
		preqparm->lv2.keyid[i].len = sizeof(struct keyid);
		preqparm->lv2.keyid[i].attr = (i == 2 ? 0x30 : 0x10);
	}
	preqcblk->req_parml = sizeof(struct kgreqparm);

	/* fill xcrb struct */
	prep_xcrb(&xcrb, cardnr, preqcblk, prepcblk);

	/* forward xcrb with request CPRB and reply CPRB to zcrypt dd */
	rc = zcrypt_send_cprb(&xcrb, xflags);
	if (rc) {
		ZCRYPT_DBF_ERR("%s zcrypt_send_cprb (cardnr=%d domain=%d) failed, errno %d\n",
			       __func__, (int)cardnr, (int)domain, rc);
		goto out;
	}

	/* check response returncode and reasoncode */
	if (prepcblk->ccp_rtcode != 0) {
		ZCRYPT_DBF_ERR("%s secure key generate failure, card response %d/%d\n",
			       __func__,
			  (int)prepcblk->ccp_rtcode,
			  (int)prepcblk->ccp_rscode);
		rc = -EIO;
		goto out;
	}

	/* process response cprb param block */
	ptr =  ((u8 *)prepcblk) + sizeof(struct CPRBX);
	prepcblk->rpl_parmb = (u8 __user *)ptr;
	prepparm = (struct kgrepparm *)ptr;

	/* check length of the returned secure key token */
	seckeysize = prepparm->lv3.keyblock.toklen
		- sizeof(prepparm->lv3.keyblock.toklen)
		- sizeof(prepparm->lv3.keyblock.tokattr);
	if (seckeysize != SECKEYBLOBSIZE) {
		ZCRYPT_DBF_ERR("%s secure token size mismatch %d != %d bytes\n",
			       __func__, seckeysize, SECKEYBLOBSIZE);
		rc = -EIO;
		goto out;
	}

	/* check secure key token */
	rc = cca_check_secaeskeytoken(zcrypt_dbf_info, DBF_ERR,
				      prepparm->lv3.keyblock.tok, 8 * keysize);
	if (rc) {
		rc = -EIO;
		goto out;
	}

	/* copy the generated secure key token */
	memcpy(seckey, prepparm->lv3.keyblock.tok, SECKEYBLOBSIZE);

out:
	free_cprbmem(mem, PARMBSIZE, false, xflags);
	return rc;
}
EXPORT_SYMBOL(cca_genseckey);

/*
 * Generate an CCA AES DATA secure key with given key value.
 */
int cca_clr2seckey(u16 cardnr, u16 domain, u32 keybitsize,
		   const u8 *clrkey, u8 *seckey, u32 xflags)
{
	int rc, keysize, seckeysize;
	u8 *mem, *ptr;
	struct CPRBX *preqcblk, *prepcblk;
	struct ica_xcRB xcrb;
	struct cmreqparm {
		u8  subfunc_code[2];
		u16 rule_array_len;
		char  rule_array[8];
		struct lv1 {
			u16 len;
			u8  clrkey[];
		} lv1;
		/* followed by struct lv2 */
	} __packed * preqparm;
	struct lv2 {
		u16 len;
		struct keyid {
			u16 len;
			u16 attr;
			u8  data[SECKEYBLOBSIZE];
		} keyid;
	} __packed * plv2;
	struct cmrepparm {
		u8  subfunc_code[2];
		u16 rule_array_len;
		struct lv3 {
			u16 len;
			u16 keyblocklen;
			struct {
				u16 toklen;
				u16 tokattr;
				u8  tok[];
				/* ... some more data ... */
			} keyblock;
		} lv3;
	} __packed * prepparm;

	/* get already prepared memory for 2 cprbs with param block each */
	rc = alloc_and_prep_cprbmem(PARMBSIZE, &mem,
				    &preqcblk, &prepcblk, xflags);
	if (rc)
		return rc;

	/* fill request cprb struct */
	preqcblk->domain = domain;

	/* fill request cprb param block with CM request */
	preqparm = (struct cmreqparm __force *)preqcblk->req_parmb;
	memcpy(preqparm->subfunc_code, "CM", 2);
	memcpy(preqparm->rule_array, "AES     ", 8);
	preqparm->rule_array_len =
		sizeof(preqparm->rule_array_len) + sizeof(preqparm->rule_array);
	switch (keybitsize) {
	case PKEY_SIZE_AES_128:
	case PKEY_KEYTYPE_AES_128: /* older ioctls used this */
		keysize = 16;
		break;
	case PKEY_SIZE_AES_192:
	case PKEY_KEYTYPE_AES_192: /* older ioctls used this */
		keysize = 24;
		break;
	case PKEY_SIZE_AES_256:
	case PKEY_KEYTYPE_AES_256: /* older ioctls used this */
		keysize = 32;
		break;
	default:
		ZCRYPT_DBF_ERR("%s unknown/unsupported keybitsize %d\n",
			       __func__, keybitsize);
		rc = -EINVAL;
		goto out;
	}
	preqparm->lv1.len = sizeof(struct lv1) + keysize;
	memcpy(preqparm->lv1.clrkey, clrkey, keysize);
	plv2 = (struct lv2 *)(((u8 *)preqparm) + sizeof(*preqparm) + keysize);
	plv2->len = sizeof(struct lv2);
	plv2->keyid.len = sizeof(struct keyid);
	plv2->keyid.attr = 0x30;
	preqcblk->req_parml = sizeof(*preqparm) + keysize + sizeof(*plv2);

	/* fill xcrb struct */
	prep_xcrb(&xcrb, cardnr, preqcblk, prepcblk);

	/* forward xcrb with request CPRB and reply CPRB to zcrypt dd */
	rc = zcrypt_send_cprb(&xcrb, xflags);
	if (rc) {
		ZCRYPT_DBF_ERR("%s zcrypt_send_cprb (cardnr=%d domain=%d) failed, rc=%d\n",
			       __func__, (int)cardnr, (int)domain, rc);
		goto out;
	}

	/* check response returncode and reasoncode */
	if (prepcblk->ccp_rtcode != 0) {
		ZCRYPT_DBF_ERR("%s clear key import failure, card response %d/%d\n",
			       __func__,
			       (int)prepcblk->ccp_rtcode,
			       (int)prepcblk->ccp_rscode);
		rc = -EIO;
		goto out;
	}

	/* process response cprb param block */
	ptr = ((u8 *)prepcblk) + sizeof(struct CPRBX);
	prepcblk->rpl_parmb = (u8 __user *)ptr;
	prepparm = (struct cmrepparm *)ptr;

	/* check length of the returned secure key token */
	seckeysize = prepparm->lv3.keyblock.toklen
		- sizeof(prepparm->lv3.keyblock.toklen)
		- sizeof(prepparm->lv3.keyblock.tokattr);
	if (seckeysize != SECKEYBLOBSIZE) {
		ZCRYPT_DBF_ERR("%s secure token size mismatch %d != %d bytes\n",
			       __func__, seckeysize, SECKEYBLOBSIZE);
		rc = -EIO;
		goto out;
	}

	/* check secure key token */
	rc = cca_check_secaeskeytoken(zcrypt_dbf_info, DBF_ERR,
				      prepparm->lv3.keyblock.tok, 8 * keysize);
	if (rc) {
		rc = -EIO;
		goto out;
	}

	/* copy the generated secure key token */
	if (seckey)
		memcpy(seckey, prepparm->lv3.keyblock.tok, SECKEYBLOBSIZE);

out:
	free_cprbmem(mem, PARMBSIZE, true, xflags);
	return rc;
}
EXPORT_SYMBOL(cca_clr2seckey);

/*
 * Derive proteced key from an CCA AES DATA secure key.
 */
int cca_sec2protkey(u16 cardnr, u16 domain,
		    const u8 *seckey, u8 *protkey, u32 *protkeylen,
		    u32 *protkeytype, u32 xflags)
{
	int rc;
	u8 *mem, *ptr;
	struct CPRBX *preqcblk, *prepcblk;
	struct ica_xcRB xcrb;
	struct uskreqparm {
		u8  subfunc_code[2];
		u16 rule_array_len;
		struct lv1 {
			u16 len;
			u16 attr_len;
			u16 attr_flags;
		} lv1;
		struct lv2 {
			u16 len;
			u16 attr_len;
			u16 attr_flags;
			u8  token[];	      /* cca secure key token */
		} lv2;
	} __packed * preqparm;
	struct uskrepparm {
		u8  subfunc_code[2];
		u16 rule_array_len;
		struct lv3 {
			u16 len;
			u16 attr_len;
			u16 attr_flags;
			struct cpacfkeyblock {
				u8  version;  /* version of this struct */
				u8  flags[2];
				u8  algo;
				u8  form;
				u8  pad1[3];
				u16 len;
				u8  key[64];  /* the key (len bytes) */
				u16 keyattrlen;
				u8  keyattr[32];
				u8  pad2[1];
				u8  vptype;
				u8  vp[32];  /* verification pattern */
			} ckb;
		} lv3;
	} __packed * prepparm;

	/* get already prepared memory for 2 cprbs with param block each */
	rc = alloc_and_prep_cprbmem(PARMBSIZE, &mem,
				    &preqcblk, &prepcblk, xflags);
	if (rc)
		return rc;

	/* fill request cprb struct */
	preqcblk->domain = domain;

	/* fill request cprb param block with USK request */
	preqparm = (struct uskreqparm __force *)preqcblk->req_parmb;
	memcpy(preqparm->subfunc_code, "US", 2);
	preqparm->rule_array_len = sizeof(preqparm->rule_array_len);
	preqparm->lv1.len = sizeof(struct lv1);
	preqparm->lv1.attr_len = sizeof(struct lv1) - sizeof(preqparm->lv1.len);
	preqparm->lv1.attr_flags = 0x0001;
	preqparm->lv2.len = sizeof(struct lv2) + SECKEYBLOBSIZE;
	preqparm->lv2.attr_len = sizeof(struct lv2)
		- sizeof(preqparm->lv2.len) + SECKEYBLOBSIZE;
	preqparm->lv2.attr_flags = 0x0000;
	memcpy(preqparm->lv2.token, seckey, SECKEYBLOBSIZE);
	preqcblk->req_parml = sizeof(struct uskreqparm) + SECKEYBLOBSIZE;

	/* fill xcrb struct */
	prep_xcrb(&xcrb, cardnr, preqcblk, prepcblk);

	/* forward xcrb with request CPRB and reply CPRB to zcrypt dd */
	rc = zcrypt_send_cprb(&xcrb, xflags);
	if (rc) {
		ZCRYPT_DBF_ERR("%s zcrypt_send_cprb (cardnr=%d domain=%d) failed, rc=%d\n",
			       __func__, (int)cardnr, (int)domain, rc);
		goto out;
	}

	/* check response returncode and reasoncode */
	if (prepcblk->ccp_rtcode != 0) {
		ZCRYPT_DBF_ERR("%s unwrap secure key failure, card response %d/%d\n",
			       __func__,
			       (int)prepcblk->ccp_rtcode,
			       (int)prepcblk->ccp_rscode);
		if (prepcblk->ccp_rtcode == 8 && prepcblk->ccp_rscode == 2290)
			rc = -EBUSY;
		else
			rc = -EIO;
		goto out;
	}
	if (prepcblk->ccp_rscode != 0) {
		ZCRYPT_DBF_WARN("%s unwrap secure key warning, card response %d/%d\n",
				__func__,
				(int)prepcblk->ccp_rtcode,
				(int)prepcblk->ccp_rscode);
	}

	/* process response cprb param block */
	ptr = ((u8 *)prepcblk) + sizeof(struct CPRBX);
	prepcblk->rpl_parmb = (u8 __user *)ptr;
	prepparm = (struct uskrepparm *)ptr;

	/* check the returned keyblock */
	if (prepparm->lv3.ckb.version != 0x01 &&
	    prepparm->lv3.ckb.version != 0x02) {
		ZCRYPT_DBF_ERR("%s reply param keyblock version mismatch 0x%02x\n",
			       __func__, (int)prepparm->lv3.ckb.version);
		rc = -EIO;
		goto out;
	}

	/* copy the translated protected key */
	switch (prepparm->lv3.ckb.len) {
	case 16 + 32:
		/* AES 128 protected key */
		if (protkeytype)
			*protkeytype = PKEY_KEYTYPE_AES_128;
		break;
	case 24 + 32:
		/* AES 192 protected key */
		if (protkeytype)
			*protkeytype = PKEY_KEYTYPE_AES_192;
		break;
	case 32 + 32:
		/* AES 256 protected key */
		if (protkeytype)
			*protkeytype = PKEY_KEYTYPE_AES_256;
		break;
	default:
		ZCRYPT_DBF_ERR("%s unknown/unsupported keylen %d\n",
			       __func__, prepparm->lv3.ckb.len);
		rc = -EIO;
		goto out;
	}
	memcpy(protkey, prepparm->lv3.ckb.key, prepparm->lv3.ckb.len);
	if (protkeylen)
		*protkeylen = prepparm->lv3.ckb.len;

out:
	free_cprbmem(mem, PARMBSIZE, true, xflags);
	return rc;
}
EXPORT_SYMBOL(cca_sec2protkey);

/*
 * AES cipher key skeleton created with CSNBKTB2 with these flags:
 * INTERNAL, NO-KEY, AES, CIPHER, ANY-MODE, NOEX-SYM, NOEXAASY,
 * NOEXUASY, XPRTCPAC, NOEX-RAW, NOEX-DES, NOEX-AES, NOEX-RSA
 * used by cca_gencipherkey() and cca_clr2cipherkey().
 */
static const u8 aes_cipher_key_skeleton[] = {
	0x01, 0x00, 0x00, 0x38, 0x05, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
	0x00, 0x1a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x02, 0x00, 0x01, 0x02, 0xc0, 0x00, 0xff,
	0x00, 0x03, 0x08, 0xc8, 0x00, 0x00, 0x00, 0x00 };
#define SIZEOF_SKELETON (sizeof(aes_cipher_key_skeleton))

/*
 * Generate (random) CCA AES CIPHER secure key.
 */
int cca_gencipherkey(u16 cardnr, u16 domain, u32 keybitsize, u32 keygenflags,
		     u8 *keybuf, u32 *keybufsize, u32 xflags)
{
	int rc;
	u8 *mem, *ptr;
	struct CPRBX *preqcblk, *prepcblk;
	struct ica_xcRB xcrb;
	struct gkreqparm {
		u8  subfunc_code[2];
		u16 rule_array_len;
		char rule_array[2 * 8];
		struct {
			u16 len;
			u8  key_type_1[8];
			u8  key_type_2[8];
			u16 clear_key_bit_len;
			u16 key_name_1_len;
			u16 key_name_2_len;
			u16 user_data_1_len;
			u16 user_data_2_len;
			/* u8  key_name_1[]; */
			/* u8  key_name_2[]; */
			/* u8  user_data_1[]; */
			/* u8  user_data_2[]; */
		} vud;
		struct {
			u16 len;
			struct {
				u16 len;
				u16 flag;
				/* u8  kek_id_1[]; */
			} tlv1;
			struct {
				u16 len;
				u16 flag;
				/* u8  kek_id_2[]; */
			} tlv2;
			struct {
				u16 len;
				u16 flag;
				u8  gen_key_id_1[SIZEOF_SKELETON];
			} tlv3;
			struct {
				u16 len;
				u16 flag;
				/* u8  gen_key_id_1_label[]; */
			} tlv4;
			struct {
				u16 len;
				u16 flag;
				/* u8  gen_key_id_2[]; */
			} tlv5;
			struct {
				u16 len;
				u16 flag;
				/* u8  gen_key_id_2_label[]; */
			} tlv6;
		} kb;
	} __packed * preqparm;
	struct gkrepparm {
		u8  subfunc_code[2];
		u16 rule_array_len;
		struct {
			u16 len;
		} vud;
		struct {
			u16 len;
			struct {
				u16 len;
				u16 flag;
				u8  gen_key[]; /* 120-136 bytes */
			} tlv1;
		} kb;
	} __packed * prepparm;
	struct cipherkeytoken *t;

	/* get already prepared memory for 2 cprbs with param block each */
	rc = alloc_and_prep_cprbmem(PARMBSIZE, &mem,
				    &preqcblk, &prepcblk, xflags);
	if (rc)
		return rc;

	/* fill request cprb struct */
	preqcblk->domain = domain;
	preqcblk->req_parml = sizeof(struct gkreqparm);

	/* prepare request param block with GK request */
	preqparm = (struct gkreqparm __force *)preqcblk->req_parmb;
	memcpy(preqparm->subfunc_code, "GK", 2);
	preqparm->rule_array_len =  sizeof(uint16_t) + 2 * 8;
	memcpy(preqparm->rule_array, "AES     OP      ", 2 * 8);

	/* prepare vud block */
	preqparm->vud.len = sizeof(preqparm->vud);
	switch (keybitsize) {
	case 128:
	case 192:
	case 256:
		break;
	default:
		ZCRYPT_DBF_ERR("%s unknown/unsupported keybitsize %d\n",
			       __func__, keybitsize);
		rc = -EINVAL;
		goto out;
	}
	preqparm->vud.clear_key_bit_len = keybitsize;
	memcpy(preqparm->vud.key_type_1, "TOKEN   ", 8);
	memset(preqparm->vud.key_type_2, ' ', sizeof(preqparm->vud.key_type_2));

	/* prepare kb block */
	preqparm->kb.len = sizeof(preqparm->kb);
	preqparm->kb.tlv1.len = sizeof(preqparm->kb.tlv1);
	preqparm->kb.tlv1.flag = 0x0030;
	preqparm->kb.tlv2.len = sizeof(preqparm->kb.tlv2);
	preqparm->kb.tlv2.flag = 0x0030;
	preqparm->kb.tlv3.len = sizeof(preqparm->kb.tlv3);
	preqparm->kb.tlv3.flag = 0x0030;
	memcpy(preqparm->kb.tlv3.gen_key_id_1,
	       aes_cipher_key_skeleton, SIZEOF_SKELETON);
	preqparm->kb.tlv4.len = sizeof(preqparm->kb.tlv4);
	preqparm->kb.tlv4.flag = 0x0030;
	preqparm->kb.tlv5.len = sizeof(preqparm->kb.tlv5);
	preqparm->kb.tlv5.flag = 0x0030;
	preqparm->kb.tlv6.len = sizeof(preqparm->kb.tlv6);
	preqparm->kb.tlv6.flag = 0x0030;

	/* patch the skeleton key token export flags inside the kb block */
	if (keygenflags) {
		t = (struct cipherkeytoken *)preqparm->kb.tlv3.gen_key_id_1;
		t->kmf1 |= (u16)(keygenflags & 0x0000FF00);
		t->kmf1 &= (u16)~(keygenflags & 0x000000FF);
	}

	/* prepare xcrb struct */
	prep_xcrb(&xcrb, cardnr, preqcblk, prepcblk);

	/* forward xcrb with request CPRB and reply CPRB to zcrypt dd */
	rc = zcrypt_send_cprb(&xcrb, xflags);
	if (rc) {
		ZCRYPT_DBF_ERR("%s zcrypt_send_cprb (cardnr=%d domain=%d) failed, rc=%d\n",
			       __func__, (int)cardnr, (int)domain, rc);
		goto out;
	}

	/* check response returncode and reasoncode */
	if (prepcblk->ccp_rtcode != 0) {
		ZCRYPT_DBF_ERR("%s cipher key generate failure, card response %d/%d\n",
			       __func__,
			       (int)prepcblk->ccp_rtcode,
			       (int)prepcblk->ccp_rscode);
		rc = -EIO;
		goto out;
	}

	/* process response cprb param block */
	ptr = ((u8 *)prepcblk) + sizeof(struct CPRBX);
	prepcblk->rpl_parmb = (u8 __user *)ptr;
	prepparm = (struct gkrepparm *)ptr;

	/* do some plausibility checks on the key block */
	if (prepparm->kb.len < 120 + 5 * sizeof(uint16_t) ||
	    prepparm->kb.len > 136 + 5 * sizeof(uint16_t)) {
		ZCRYPT_DBF_ERR("%s reply with invalid or unknown key block\n",
			       __func__);
		rc = -EIO;
		goto out;
	}

	/* and some checks on the generated key */
	rc = cca_check_secaescipherkey(zcrypt_dbf_info, DBF_ERR,
				       prepparm->kb.tlv1.gen_key,
				       keybitsize, 1);
	if (rc) {
		rc = -EIO;
		goto out;
	}

	/* copy the generated vlsc key token */
	t = (struct cipherkeytoken *)prepparm->kb.tlv1.gen_key;
	if (keybuf) {
		if (*keybufsize >= t->len)
			memcpy(keybuf, t, t->len);
		else
			rc = -EINVAL;
	}
	*keybufsize = t->len;

out:
	free_cprbmem(mem, PARMBSIZE, false, xflags);
	return rc;
}
EXPORT_SYMBOL(cca_gencipherkey);

/*
 * Helper function, does a the CSNBKPI2 CPRB.
 */
static int _ip_cprb_helper(u16 cardnr, u16 domain,
			   const char *rule_array_1,
			   const char *rule_array_2,
			   const char *rule_array_3,
			   const u8 *clr_key_value,
			   int clr_key_bit_size,
			   u8 *key_token,
			   int *key_token_size,
			   u32 xflags)
{
	int rc, n;
	u8 *mem, *ptr;
	struct CPRBX *preqcblk, *prepcblk;
	struct ica_xcRB xcrb;
	struct rule_array_block {
		u8  subfunc_code[2];
		u16 rule_array_len;
		char rule_array[];
	} __packed * preq_ra_block;
	struct vud_block {
		u16 len;
		struct {
			u16 len;
			u16 flag;	     /* 0x0064 */
			u16 clr_key_bit_len;
		} tlv1;
		struct {
			u16 len;
			u16 flag;	/* 0x0063 */
			u8  clr_key[];	/* clear key value bytes */
		} tlv2;
	} __packed * preq_vud_block;
	struct key_block {
		u16 len;
		struct {
			u16 len;
			u16 flag;	  /* 0x0030 */
			u8  key_token[];  /* key skeleton */
		} tlv1;
	} __packed * preq_key_block;
	struct iprepparm {
		u8  subfunc_code[2];
		u16 rule_array_len;
		struct {
			u16 len;
		} vud;
		struct {
			u16 len;
			struct {
				u16 len;
				u16 flag;	  /* 0x0030 */
				u8  key_token[];  /* key token */
			} tlv1;
		} kb;
	} __packed * prepparm;
	struct cipherkeytoken *t;
	int complete = strncmp(rule_array_2, "COMPLETE", 8) ? 0 : 1;

	/* get already prepared memory for 2 cprbs with param block each */
	rc = alloc_and_prep_cprbmem(PARMBSIZE, &mem,
				    &preqcblk, &prepcblk, xflags);
	if (rc)
		return rc;

	/* fill request cprb struct */
	preqcblk->domain = domain;
	preqcblk->req_parml = 0;

	/* prepare request param block with IP request */
	preq_ra_block = (struct rule_array_block __force *)preqcblk->req_parmb;
	memcpy(preq_ra_block->subfunc_code, "IP", 2);
	preq_ra_block->rule_array_len =  sizeof(uint16_t) + 2 * 8;
	memcpy(preq_ra_block->rule_array, rule_array_1, 8);
	memcpy(preq_ra_block->rule_array + 8, rule_array_2, 8);
	preqcblk->req_parml = sizeof(struct rule_array_block) + 2 * 8;
	if (rule_array_3) {
		preq_ra_block->rule_array_len += 8;
		memcpy(preq_ra_block->rule_array + 16, rule_array_3, 8);
		preqcblk->req_parml += 8;
	}

	/* prepare vud block */
	preq_vud_block = (struct vud_block __force *)
		(preqcblk->req_parmb + preqcblk->req_parml);
	n = complete ? 0 : (clr_key_bit_size + 7) / 8;
	preq_vud_block->len = sizeof(struct vud_block) + n;
	preq_vud_block->tlv1.len = sizeof(preq_vud_block->tlv1);
	preq_vud_block->tlv1.flag = 0x0064;
	preq_vud_block->tlv1.clr_key_bit_len = complete ? 0 : clr_key_bit_size;
	preq_vud_block->tlv2.len = sizeof(preq_vud_block->tlv2) + n;
	preq_vud_block->tlv2.flag = 0x0063;
	if (!complete)
		memcpy(preq_vud_block->tlv2.clr_key, clr_key_value, n);
	preqcblk->req_parml += preq_vud_block->len;

	/* prepare key block */
	preq_key_block = (struct key_block __force *)
		(preqcblk->req_parmb + preqcblk->req_parml);
	n = *key_token_size;
	preq_key_block->len = sizeof(struct key_block) + n;
	preq_key_block->tlv1.len = sizeof(preq_key_block->tlv1) + n;
	preq_key_block->tlv1.flag = 0x0030;
	memcpy(preq_key_block->tlv1.key_token, key_token, *key_token_size);
	preqcblk->req_parml += preq_key_block->len;

	/* prepare xcrb struct */
	prep_xcrb(&xcrb, cardnr, preqcblk, prepcblk);

	/* forward xcrb with request CPRB and reply CPRB to zcrypt dd */
	rc = zcrypt_send_cprb(&xcrb, xflags);
	if (rc) {
		ZCRYPT_DBF_ERR("%s zcrypt_send_cprb (cardnr=%d domain=%d) failed, rc=%d\n",
			       __func__, (int)cardnr, (int)domain, rc);
		goto out;
	}

	/* check response returncode and reasoncode */
	if (prepcblk->ccp_rtcode != 0) {
		ZCRYPT_DBF_ERR("%s CSNBKPI2 failure, card response %d/%d\n",
			       __func__,
			       (int)prepcblk->ccp_rtcode,
			       (int)prepcblk->ccp_rscode);
		rc = -EIO;
		goto out;
	}

	/* process response cprb param block */
	ptr = ((u8 *)prepcblk) + sizeof(struct CPRBX);
	prepcblk->rpl_parmb = (u8 __user *)ptr;
	prepparm = (struct iprepparm *)ptr;

	/* do some plausibility checks on the key block */
	if (prepparm->kb.len < 120 + 3 * sizeof(uint16_t) ||
	    prepparm->kb.len > 136 + 3 * sizeof(uint16_t)) {
		ZCRYPT_DBF_ERR("%s reply with invalid or unknown key block\n",
			       __func__);
		rc = -EIO;
		goto out;
	}

	/* do not check the key here, it may be incomplete */

	/* copy the vlsc key token back */
	t = (struct cipherkeytoken *)prepparm->kb.tlv1.key_token;
	memcpy(key_token, t, t->len);
	*key_token_size = t->len;

out:
	free_cprbmem(mem, PARMBSIZE, false, xflags);
	return rc;
}

/*
 * Build CCA AES CIPHER secure key with a given clear key value.
 */
int cca_clr2cipherkey(u16 card, u16 dom, u32 keybitsize, u32 keygenflags,
		      const u8 *clrkey, u8 *keybuf, u32 *keybufsize, u32 xflags)
{
	int rc;
	void *mem;
	int tokensize;
	u8 *token, exorbuf[32];
	struct cipherkeytoken *t;

	/* fill exorbuf with random data */
	get_random_bytes(exorbuf, sizeof(exorbuf));

	/*
	 * Allocate space for the key token to build.
	 * Also we only need up to MAXCCAVLSCTOKENSIZE bytes for this
	 * we use the already existing cprb mempool to solve this
	 * short term memory requirement.
	 */
	mem = (xflags & ZCRYPT_XFLAG_NOMEMALLOC) ?
		mempool_alloc_preallocated(cprb_mempool) :
		mempool_alloc(cprb_mempool, GFP_KERNEL);
	if (!mem)
		return -ENOMEM;

	/* prepare the token with the key skeleton */
	token = (u8 *)mem;
	tokensize = SIZEOF_SKELETON;
	memcpy(token, aes_cipher_key_skeleton, tokensize);

	/* patch the skeleton key token export flags */
	if (keygenflags) {
		t = (struct cipherkeytoken *)token;
		t->kmf1 |= (u16)(keygenflags & 0x0000FF00);
		t->kmf1 &= (u16)~(keygenflags & 0x000000FF);
	}

	/*
	 * Do the key import with the clear key value in 4 steps:
	 * 1/4 FIRST import with only random data
	 * 2/4 EXOR the clear key
	 * 3/4 EXOR the very same random data again
	 * 4/4 COMPLETE the secure cipher key import
	 */
	rc = _ip_cprb_helper(card, dom, "AES     ", "FIRST   ", "MIN3PART",
			     exorbuf, keybitsize, token, &tokensize, xflags);
	if (rc) {
		ZCRYPT_DBF_ERR("%s clear key import 1/4 with CSNBKPI2 failed, rc=%d\n",
			       __func__, rc);
		goto out;
	}
	rc = _ip_cprb_helper(card, dom, "AES     ", "ADD-PART", NULL,
			     clrkey, keybitsize, token, &tokensize, xflags);
	if (rc) {
		ZCRYPT_DBF_ERR("%s clear key import 2/4 with CSNBKPI2 failed, rc=%d\n",
			       __func__, rc);
		goto out;
	}
	rc = _ip_cprb_helper(card, dom, "AES     ", "ADD-PART", NULL,
			     exorbuf, keybitsize, token, &tokensize, xflags);
	if (rc) {
		ZCRYPT_DBF_ERR("%s clear key import 3/4 with CSNBKPI2 failed, rc=%d\n",
			       __func__, rc);
		goto out;
	}
	rc = _ip_cprb_helper(card, dom, "AES     ", "COMPLETE", NULL,
			     NULL, keybitsize, token, &tokensize, xflags);
	if (rc) {
		ZCRYPT_DBF_ERR("%s clear key import 4/4 with CSNBKPI2 failed, rc=%d\n",
			       __func__, rc);
		goto out;
	}

	/* copy the generated key token */
	if (keybuf) {
		if (tokensize > *keybufsize)
			rc = -EINVAL;
		else
			memcpy(keybuf, token, tokensize);
	}
	*keybufsize = tokensize;

out:
	mempool_free(mem, cprb_mempool);
	return rc;
}
EXPORT_SYMBOL(cca_clr2cipherkey);

/*
 * Derive proteced key from CCA AES cipher secure key.
 */
int cca_cipher2protkey(u16 cardnr, u16 domain, const u8 *ckey,
		       u8 *protkey, u32 *protkeylen, u32 *protkeytype,
		       u32 xflags)
{
	int rc;
	u8 *mem, *ptr;
	struct CPRBX *preqcblk, *prepcblk;
	struct ica_xcRB xcrb;
	struct aureqparm {
		u8  subfunc_code[2];
		u16 rule_array_len;
		u8  rule_array[8];
		struct {
			u16 len;
			u16 tk_blob_len;
			u16 tk_blob_tag;
			u8  tk_blob[66];
		} vud;
		struct {
			u16 len;
			u16 cca_key_token_len;
			u16 cca_key_token_flags;
			u8  cca_key_token[]; /* 64 or more */
		} kb;
	} __packed * preqparm;
	struct aurepparm {
		u8  subfunc_code[2];
		u16 rule_array_len;
		struct {
			u16 len;
			u16 sublen;
			u16 tag;
			struct cpacfkeyblock {
				u8  version;  /* version of this struct */
				u8  flags[2];
				u8  algo;
				u8  form;
				u8  pad1[3];
				u16 keylen;
				u8  key[64];  /* the key (keylen bytes) */
				u16 keyattrlen;
				u8  keyattr[32];
				u8  pad2[1];
				u8  vptype;
				u8  vp[32];  /* verification pattern */
			} ckb;
		} vud;
		struct {
			u16 len;
		} kb;
	} __packed * prepparm;
	int keytoklen = ((struct cipherkeytoken *)ckey)->len;

	/* get already prepared memory for 2 cprbs with param block each */
	rc = alloc_and_prep_cprbmem(PARMBSIZE, &mem,
				    &preqcblk, &prepcblk, xflags);
	if (rc)
		return rc;

	/* fill request cprb struct */
	preqcblk->domain = domain;

	/* fill request cprb param block with AU request */
	preqparm = (struct aureqparm __force *)preqcblk->req_parmb;
	memcpy(preqparm->subfunc_code, "AU", 2);
	preqparm->rule_array_len =
		sizeof(preqparm->rule_array_len)
		+ sizeof(preqparm->rule_array);
	memcpy(preqparm->rule_array, "EXPT-SK ", 8);
	/* vud, tk blob */
	preqparm->vud.len = sizeof(preqparm->vud);
	preqparm->vud.tk_blob_len = sizeof(preqparm->vud.tk_blob)
		+ 2 * sizeof(uint16_t);
	preqparm->vud.tk_blob_tag = 0x00C2;
	/* kb, cca token */
	preqparm->kb.len = keytoklen + 3 * sizeof(uint16_t);
	preqparm->kb.cca_key_token_len = keytoklen + 2 * sizeof(uint16_t);
	memcpy(preqparm->kb.cca_key_token, ckey, keytoklen);
	/* now fill length of param block into cprb */
	preqcblk->req_parml = sizeof(struct aureqparm) + keytoklen;

	/* fill xcrb struct */
	prep_xcrb(&xcrb, cardnr, preqcblk, prepcblk);

	/* forward xcrb with request CPRB and reply CPRB to zcrypt dd */
	rc = zcrypt_send_cprb(&xcrb, xflags);
	if (rc) {
		ZCRYPT_DBF_ERR("%s zcrypt_send_cprb (cardnr=%d domain=%d) failed, rc=%d\n",
			       __func__, (int)cardnr, (int)domain, rc);
		goto out;
	}

	/* check response returncode and reasoncode */
	if (prepcblk->ccp_rtcode != 0) {
		ZCRYPT_DBF_ERR("%s unwrap secure key failure, card response %d/%d\n",
			       __func__,
			       (int)prepcblk->ccp_rtcode,
			       (int)prepcblk->ccp_rscode);
		if (prepcblk->ccp_rtcode == 8 && prepcblk->ccp_rscode == 2290)
			rc = -EBUSY;
		else
			rc = -EIO;
		goto out;
	}
	if (prepcblk->ccp_rscode != 0) {
		ZCRYPT_DBF_WARN("%s unwrap secure key warning, card response %d/%d\n",
				__func__,
				(int)prepcblk->ccp_rtcode,
				(int)prepcblk->ccp_rscode);
	}

	/* process response cprb param block */
	ptr = ((u8 *)prepcblk) + sizeof(struct CPRBX);
	prepcblk->rpl_parmb = (u8 __user *)ptr;
	prepparm = (struct aurepparm *)ptr;

	/* check the returned keyblock */
	if (prepparm->vud.ckb.version != 0x01 &&
	    prepparm->vud.ckb.version != 0x02) {
		ZCRYPT_DBF_ERR("%s reply param keyblock version mismatch 0x%02x\n",
			       __func__, (int)prepparm->vud.ckb.version);
		rc = -EIO;
		goto out;
	}
	if (prepparm->vud.ckb.algo != 0x02) {
		ZCRYPT_DBF_ERR("%s reply param keyblock algo mismatch 0x%02x != 0x02\n",
			       __func__, (int)prepparm->vud.ckb.algo);
		rc = -EIO;
		goto out;
	}

	/* copy the translated protected key */
	switch (prepparm->vud.ckb.keylen) {
	case 16 + 32:
		/* AES 128 protected key */
		if (protkeytype)
			*protkeytype = PKEY_KEYTYPE_AES_128;
		break;
	case 24 + 32:
		/* AES 192 protected key */
		if (protkeytype)
			*protkeytype = PKEY_KEYTYPE_AES_192;
		break;
	case 32 + 32:
		/* AES 256 protected key */
		if (protkeytype)
			*protkeytype = PKEY_KEYTYPE_AES_256;
		break;
	default:
		ZCRYPT_DBF_ERR("%s unknown/unsupported keylen %d\n",
			       __func__, prepparm->vud.ckb.keylen);
		rc = -EIO;
		goto out;
	}
	memcpy(protkey, prepparm->vud.ckb.key, prepparm->vud.ckb.keylen);
	if (protkeylen)
		*protkeylen = prepparm->vud.ckb.keylen;

out:
	free_cprbmem(mem, PARMBSIZE, true, xflags);
	return rc;
}
EXPORT_SYMBOL(cca_cipher2protkey);

/*
 * Derive protected key from CCA ECC secure private key.
 */
int cca_ecc2protkey(u16 cardnr, u16 domain, const u8 *key,
		    u8 *protkey, u32 *protkeylen, u32 *protkeytype, u32 xflags)
{
	int rc;
	u8 *mem, *ptr;
	struct CPRBX *preqcblk, *prepcblk;
	struct ica_xcRB xcrb;
	struct aureqparm {
		u8  subfunc_code[2];
		u16 rule_array_len;
		u8  rule_array[8];
		struct {
			u16 len;
			u16 tk_blob_len;
			u16 tk_blob_tag;
			u8  tk_blob[66];
		} vud;
		struct {
			u16 len;
			u16 cca_key_token_len;
			u16 cca_key_token_flags;
			u8  cca_key_token[];
		} kb;
	} __packed * preqparm;
	struct aurepparm {
		u8  subfunc_code[2];
		u16 rule_array_len;
		struct {
			u16 len;
			u16 sublen;
			u16 tag;
			struct cpacfkeyblock {
				u8  version;  /* version of this struct */
				u8  flags[2];
				u8  algo;
				u8  form;
				u8  pad1[3];
				u16 keylen;
				u8  key[];  /* the key (keylen bytes) */
				/* u16 keyattrlen; */
				/* u8  keyattr[32]; */
				/* u8  pad2[1]; */
				/* u8  vptype; */
				/* u8  vp[32];	verification pattern */
			} ckb;
		} vud;
		/* followed by a key block */
	} __packed * prepparm;
	int keylen = ((struct eccprivkeytoken *)key)->len;

	/* get already prepared memory for 2 cprbs with param block each */
	rc = alloc_and_prep_cprbmem(PARMBSIZE, &mem,
				    &preqcblk, &prepcblk, xflags);
	if (rc)
		return rc;

	/* fill request cprb struct */
	preqcblk->domain = domain;

	/* fill request cprb param block with AU request */
	preqparm = (struct aureqparm __force *)preqcblk->req_parmb;
	memcpy(preqparm->subfunc_code, "AU", 2);
	preqparm->rule_array_len =
		sizeof(preqparm->rule_array_len)
		+ sizeof(preqparm->rule_array);
	memcpy(preqparm->rule_array, "EXPT-SK ", 8);
	/* vud, tk blob */
	preqparm->vud.len = sizeof(preqparm->vud);
	preqparm->vud.tk_blob_len = sizeof(preqparm->vud.tk_blob)
		+ 2 * sizeof(uint16_t);
	preqparm->vud.tk_blob_tag = 0x00C2;
	/* kb, cca token */
	preqparm->kb.len = keylen + 3 * sizeof(uint16_t);
	preqparm->kb.cca_key_token_len = keylen + 2 * sizeof(uint16_t);
	memcpy(preqparm->kb.cca_key_token, key, keylen);
	/* now fill length of param block into cprb */
	preqcblk->req_parml = sizeof(struct aureqparm) + keylen;

	/* fill xcrb struct */
	prep_xcrb(&xcrb, cardnr, preqcblk, prepcblk);

	/* forward xcrb with request CPRB and reply CPRB to zcrypt dd */
	rc = zcrypt_send_cprb(&xcrb, xflags);
	if (rc) {
		ZCRYPT_DBF_ERR("%s zcrypt_send_cprb (cardnr=%d domain=%d) failed, rc=%d\n",
			       __func__, (int)cardnr, (int)domain, rc);
		goto out;
	}

	/* check response returncode and reasoncode */
	if (prepcblk->ccp_rtcode != 0) {
		ZCRYPT_DBF_ERR("%s unwrap secure key failure, card response %d/%d\n",
			       __func__,
			       (int)prepcblk->ccp_rtcode,
			       (int)prepcblk->ccp_rscode);
		if (prepcblk->ccp_rtcode == 8 && prepcblk->ccp_rscode == 2290)
			rc = -EBUSY;
		else
			rc = -EIO;
		goto out;
	}
	if (prepcblk->ccp_rscode != 0) {
		ZCRYPT_DBF_WARN("%s unwrap secure key warning, card response %d/%d\n",
				__func__,
				(int)prepcblk->ccp_rtcode,
				(int)prepcblk->ccp_rscode);
	}

	/* process response cprb param block */
	ptr = ((u8 *)prepcblk) + sizeof(struct CPRBX);
	prepcblk->rpl_parmb = (u8 __user *)ptr;
	prepparm = (struct aurepparm *)ptr;

	/* check the returned keyblock */
	if (prepparm->vud.ckb.version != 0x02) {
		ZCRYPT_DBF_ERR("%s reply param keyblock version mismatch 0x%02x != 0x02\n",
			       __func__, (int)prepparm->vud.ckb.version);
		rc = -EIO;
		goto out;
	}
	if (prepparm->vud.ckb.algo != 0x81) {
		ZCRYPT_DBF_ERR("%s reply param keyblock algo mismatch 0x%02x != 0x81\n",
			       __func__, (int)prepparm->vud.ckb.algo);
		rc = -EIO;
		goto out;
	}

	/* copy the translated protected key */
	if (prepparm->vud.ckb.keylen > *protkeylen) {
		ZCRYPT_DBF_ERR("%s prot keylen mismatch %d > buffersize %u\n",
			       __func__, prepparm->vud.ckb.keylen, *protkeylen);
		rc = -EIO;
		goto out;
	}
	memcpy(protkey, prepparm->vud.ckb.key, prepparm->vud.ckb.keylen);
	*protkeylen = prepparm->vud.ckb.keylen;
	if (protkeytype)
		*protkeytype = PKEY_KEYTYPE_ECC;

out:
	free_cprbmem(mem, PARMBSIZE, true, xflags);
	return rc;
}
EXPORT_SYMBOL(cca_ecc2protkey);

/*
 * query cryptographic facility from CCA adapter
 */
int cca_query_crypto_facility(u16 cardnr, u16 domain,
			      const char *keyword,
			      u8 *rarray, size_t *rarraylen,
			      u8 *varray, size_t *varraylen,
			      u32 xflags)
{
	int rc;
	u16 len;
	u8 *mem, *ptr;
	struct CPRBX *preqcblk, *prepcblk;
	struct ica_xcRB xcrb;
	struct fqreqparm {
		u8  subfunc_code[2];
		u16 rule_array_len;
		char  rule_array[8];
		struct lv1 {
			u16 len;
			u8  data[VARDATASIZE];
		} lv1;
		u16 dummylen;
	} __packed * preqparm;
	size_t parmbsize = sizeof(struct fqreqparm);
	struct fqrepparm {
		u8  subfunc_code[2];
		u8  lvdata[];
	} __packed * prepparm;

	/* get already prepared memory for 2 cprbs with param block each */
	rc = alloc_and_prep_cprbmem(parmbsize, &mem,
				    &preqcblk, &prepcblk, xflags);
	if (rc)
		return rc;

	/* fill request cprb struct */
	preqcblk->domain = domain;

	/* fill request cprb param block with FQ request */
	preqparm = (struct fqreqparm __force *)preqcblk->req_parmb;
	memcpy(preqparm->subfunc_code, "FQ", 2);
	memcpy(preqparm->rule_array, keyword, sizeof(preqparm->rule_array));
	preqparm->rule_array_len =
		sizeof(preqparm->rule_array_len) + sizeof(preqparm->rule_array);
	preqparm->lv1.len = sizeof(preqparm->lv1);
	preqparm->dummylen = sizeof(preqparm->dummylen);
	preqcblk->req_parml = parmbsize;

	/* fill xcrb struct */
	prep_xcrb(&xcrb, cardnr, preqcblk, prepcblk);

	/* forward xcrb with request CPRB and reply CPRB to zcrypt dd */
	rc = zcrypt_send_cprb(&xcrb, xflags);
	if (rc) {
		ZCRYPT_DBF_ERR("%s zcrypt_send_cprb (cardnr=%d domain=%d) failed, rc=%d\n",
			       __func__, (int)cardnr, (int)domain, rc);
		goto out;
	}

	/* check response returncode and reasoncode */
	if (prepcblk->ccp_rtcode != 0) {
		ZCRYPT_DBF_ERR("%s unwrap secure key failure, card response %d/%d\n",
			       __func__,
			       (int)prepcblk->ccp_rtcode,
			       (int)prepcblk->ccp_rscode);
		rc = -EIO;
		goto out;
	}

	/* process response cprb param block */
	ptr = ((u8 *)prepcblk) + sizeof(struct CPRBX);
	prepcblk->rpl_parmb = (u8 __user *)ptr;
	prepparm = (struct fqrepparm *)ptr;
	ptr = prepparm->lvdata;

	/* check and possibly copy reply rule array */
	len = *((u16 *)ptr);
	if (len > sizeof(u16)) {
		ptr += sizeof(u16);
		len -= sizeof(u16);
		if (rarray && rarraylen && *rarraylen > 0) {
			*rarraylen = (len > *rarraylen ? *rarraylen : len);
			memcpy(rarray, ptr, *rarraylen);
		}
		ptr += len;
	}
	/* check and possible copy reply var array */
	len = *((u16 *)ptr);
	if (len > sizeof(u16)) {
		ptr += sizeof(u16);
		len -= sizeof(u16);
		if (varray && varraylen && *varraylen > 0) {
			*varraylen = (len > *varraylen ? *varraylen : len);
			memcpy(varray, ptr, *varraylen);
		}
		ptr += len;
	}

out:
	free_cprbmem(mem, parmbsize, false, xflags);
	return rc;
}
EXPORT_SYMBOL(cca_query_crypto_facility);

/*
 * Fetch cca_info values about a CCA queue via
 * query_crypto_facility from adapter.
 */
int cca_get_info(u16 cardnr, u16 domain, struct cca_info *ci, u32 xflags)
{
	void *mem;
	int rc, found = 0;
	size_t rlen, vlen;
	u8 *rarray, *varray;
	struct zcrypt_device_status_ext devstat;

	memset(ci, 0, sizeof(*ci));

	/* get first info from zcrypt device driver about this apqn */
	rc = zcrypt_device_status_ext(cardnr, domain, &devstat);
	if (rc)
		return rc;
	ci->hwtype = devstat.hwtype;

	/*
	 * Prep memory for rule array and var array use.
	 * Use the cprb mempool for this.
	 */
	mem = (xflags & ZCRYPT_XFLAG_NOMEMALLOC) ?
		mempool_alloc_preallocated(cprb_mempool) :
		mempool_alloc(cprb_mempool, GFP_KERNEL);
	if (!mem)
		return -ENOMEM;
	rarray = (u8 *)mem;
	varray = (u8 *)mem + PAGE_SIZE / 2;
	rlen = vlen = PAGE_SIZE / 2;

	/* QF for this card/domain */
	rc = cca_query_crypto_facility(cardnr, domain, "STATICSA",
				       rarray, &rlen, varray, &vlen, xflags);
	if (rc == 0 && rlen >= 10 * 8 && vlen >= 204) {
		memcpy(ci->serial, rarray, 8);
		ci->new_asym_mk_state = (char)rarray[4 * 8];
		ci->cur_asym_mk_state = (char)rarray[5 * 8];
		ci->old_asym_mk_state = (char)rarray[6 * 8];
		if (ci->old_asym_mk_state == '2')
			memcpy(ci->old_asym_mkvp, varray + 64, 16);
		if (ci->cur_asym_mk_state == '2')
			memcpy(ci->cur_asym_mkvp, varray + 84, 16);
		if (ci->new_asym_mk_state == '3')
			memcpy(ci->new_asym_mkvp, varray + 104, 16);
		ci->new_aes_mk_state = (char)rarray[7 * 8];
		ci->cur_aes_mk_state = (char)rarray[8 * 8];
		ci->old_aes_mk_state = (char)rarray[9 * 8];
		if (ci->old_aes_mk_state == '2')
			memcpy(&ci->old_aes_mkvp, varray + 172, 8);
		if (ci->cur_aes_mk_state == '2')
			memcpy(&ci->cur_aes_mkvp, varray + 184, 8);
		if (ci->new_aes_mk_state == '3')
			memcpy(&ci->new_aes_mkvp, varray + 196, 8);
		found++;
	}
	if (!found)
		goto out;
	rlen = vlen = PAGE_SIZE / 2;
	rc = cca_query_crypto_facility(cardnr, domain, "STATICSB",
				       rarray, &rlen, varray, &vlen, xflags);
	if (rc == 0 && rlen >= 13 * 8 && vlen >= 240) {
		ci->new_apka_mk_state = (char)rarray[10 * 8];
		ci->cur_apka_mk_state = (char)rarray[11 * 8];
		ci->old_apka_mk_state = (char)rarray[12 * 8];
		if (ci->old_apka_mk_state == '2')
			memcpy(&ci->old_apka_mkvp, varray + 208, 8);
		if (ci->cur_apka_mk_state == '2')
			memcpy(&ci->cur_apka_mkvp, varray + 220, 8);
		if (ci->new_apka_mk_state == '3')
			memcpy(&ci->new_apka_mkvp, varray + 232, 8);
		found++;
	}

out:
	mempool_free(mem, cprb_mempool);
	return found == 2 ? 0 : -ENOENT;
}
EXPORT_SYMBOL(cca_get_info);

int cca_findcard2(u32 *apqns, u32 *nr_apqns, u16 cardnr, u16 domain,
		  int minhwtype, int mktype, u64 cur_mkvp, u64 old_mkvp,
		  u32 xflags)
{
	struct zcrypt_device_status_ext *device_status;
	int i, card, dom, curmatch, oldmatch;
	struct cca_info ci;
	u32 _nr_apqns = 0;

	/* occupy the device status memory */
	mutex_lock(&dev_status_mem_mutex);
	memset(dev_status_mem, 0, ZCRYPT_DEV_STATUS_EXT_SIZE);
	device_status = (struct zcrypt_device_status_ext *)dev_status_mem;

	/* fetch crypto device status into this struct */
	zcrypt_device_status_mask_ext(device_status,
				      ZCRYPT_DEV_STATUS_CARD_MAX,
				      ZCRYPT_DEV_STATUS_QUEUE_MAX);

	/* walk through all the crypto apqnss */
	for (i = 0; i < ZCRYPT_DEV_STATUS_ENTRIES; i++) {
		card = AP_QID_CARD(device_status[i].qid);
		dom = AP_QID_QUEUE(device_status[i].qid);
		/* check online state */
		if (!device_status[i].online)
			continue;
		/* check for cca functions */
		if (!(device_status[i].functions & 0x04))
			continue;
		/* check cardnr */
		if (cardnr != 0xFFFF && card != cardnr)
			continue;
		/* check domain */
		if (domain != 0xFFFF && dom != domain)
			continue;
		/* get cca info on this apqn */
		if (cca_get_info(card, dom, &ci, xflags))
			continue;
		/* current master key needs to be valid */
		if (mktype == AES_MK_SET && ci.cur_aes_mk_state != '2')
			continue;
		if (mktype == APKA_MK_SET && ci.cur_apka_mk_state != '2')
			continue;
		/* check min hardware type */
		if (minhwtype > 0 && minhwtype > ci.hwtype)
			continue;
		if (cur_mkvp || old_mkvp) {
			/* check mkvps */
			curmatch = oldmatch = 0;
			if (mktype == AES_MK_SET) {
				if (cur_mkvp && cur_mkvp == ci.cur_aes_mkvp)
					curmatch = 1;
				if (old_mkvp && ci.old_aes_mk_state == '2' &&
				    old_mkvp == ci.old_aes_mkvp)
					oldmatch = 1;
			} else {
				if (cur_mkvp && cur_mkvp == ci.cur_apka_mkvp)
					curmatch = 1;
				if (old_mkvp && ci.old_apka_mk_state == '2' &&
				    old_mkvp == ci.old_apka_mkvp)
					oldmatch = 1;
			}
			if (curmatch + oldmatch < 1)
				continue;
		}
		/* apqn passed all filtering criterons, add to the array */
		if (_nr_apqns < *nr_apqns)
			apqns[_nr_apqns++] = (((u16)card) << 16) | ((u16)dom);
	}

	*nr_apqns = _nr_apqns;

	/* release the device status memory */
	mutex_unlock(&dev_status_mem_mutex);

	return _nr_apqns ? 0 : -ENODEV;
}
EXPORT_SYMBOL(cca_findcard2);

int __init zcrypt_ccamisc_init(void)
{
	/* Pre-allocate a small memory pool for cca cprbs. */
	cprb_mempool = mempool_create_kmalloc_pool(zcrypt_mempool_threshold,
						   CPRB_MEMPOOL_ITEM_SIZE);
	if (!cprb_mempool)
		return -ENOMEM;

	/* Pre-allocate one crypto status card struct used in findcard() */
	dev_status_mem = kvmalloc(ZCRYPT_DEV_STATUS_EXT_SIZE, GFP_KERNEL);
	if (!dev_status_mem) {
		mempool_destroy(cprb_mempool);
		return -ENOMEM;
	}

	return 0;
}

void zcrypt_ccamisc_exit(void)
{
	mutex_lock(&dev_status_mem_mutex);
	kvfree(dev_status_mem);
	mutex_unlock(&dev_status_mem_mutex);
	mempool_destroy(cprb_mempool);
}
