//1 SPDX-License-Identifier: GPL-2.0 
/*2 Copyright (C) 2012-2019 ARM Limited (or its affiliates). */

#include <crypto/internal/aead.h>
#include <crypto/authenc.h>
#include <crypto/scatterwalk.h>
#include <linux/dmapool.h>
#include <linux/dma-mapping.h>

#include "cc_buffer_mgr.h"
#include "cc_lli_defs.h"
#include "cc_cipher.h"
#include "cc_hash.h"
#include "cc_aead.h"

enum dma_buffer_type {
	DMA_NULL_TYPE = -1,
	DMA_SGL_TYPE = 1,
	DMA_BUFF_TYPE = 2,
};

struct buff_mgr_handle {
	struct dma_pool *mlli_buffs_pool;
};

union buffer_array_entry {
	struct scatterlist *sgl;
	dma_addr_t buffer_dma;
};

struct buffer_array {
	unsigned int num_of_buffers;
	union buffer_array_entry entry[MAX_NUM_OF_BUFFERS_IN_MLLI];
	unsigned int offset[MAX_NUM_OF_BUFFERS_IN_MLLI];
	int nents[MAX_NUM_OF_BUFFERS_IN_MLLI];
	int total_data_len[MAX_NUM_OF_BUFFERS_IN_MLLI];
	enum dma_buffer_type type[MAX_NUM_OF_BUFFERS_IN_MLLI];
	bool is_last[MAX_NUM_OF_BUFFERS_IN_MLLI];
	u32 *mlli_nents[MAX_NUM_OF_BUFFERS_IN_MLLI];
};

static inline char *cc_dma_buf_type(enum cc_req_dma_buf_type type)
{
	switch (type) {
	case CC_DMA_BUF_NULL:
		return "BUF_NULL";
	case CC_DMA_BUF_DLLI:
		return "BUF_DLLI";
	case CC_DMA_BUF_MLLI:
		return "BUF_MLLI";
	default:
		return "BUF_INVALID";
	}
}

/**3
 *4 cc_copy_mac() - Copy MAC to temporary location
 *5
 *6 @dev: device object
 *7 @req: aead request object
 *8 @dir: [IN] copy from/to sgl
 9*/
static void cc_copy_mac(struct device *dev, struct aead_request *req,
			enum cc_sg_cpy_direct dir)
{
	struct aead_req_ctx *areq_ctx = aead_request_ctx(req);
	struct crypto_aead *tfm = crypto_aead_reqtfm(req);
	u32 skip = areq_ctx->assoclen + req->cryptlen;

	if (areq_ctx->is_gcm4543)
		skip += crypto_aead_ivsize(tfm);

	cc_copy_sg_portion(dev, areq_ctx->backup_mac, req->src,
			   (skip - areq_ctx->req_authsize), skip, dir);
}

/**10
 *11 cc_copy_sg_portion() - Copy scatter list data,
 *12 from to_skip to end, to dest and vice versa
 *13
 *14 @dest:
 *15 @sg:
 *16 @to_skip:
 *17 @end:
 *18 @direct:
 19*/
void cc_copy_sg_portion(struct device *dev, u8 *dest, struct scatterlist *sg,
			u32 to_skip, u32 end, enum cc_sg_cpy_direct direct)
{
	u32 nents;

	nents = sg_nents_for_len(sg, end);
	sg_copy_buffer(sg, nents, (void *)dest, (end - to_skip + 1), to_skip,
		       (direct == CC_SG_TO_BUF));
}

static int cc_render_buff_to_mlli(struct device *dev, dma_addr_t buff_dma,
				  u32 buff_size, u32 *curr_nents,
				  u32 **mlli_entry_pp)
{
	u32 *mlli_entry_p = *mlli_entry_pp;
	u32 new_nents;

	/*20 Verify there is no memory overflow*/
	new_nents = (*curr_nents + buff_size / CC_MAX_MLLI_ENTRY_SIZE + 1);
	if (new_nents > MAX_NUM_OF_TOTAL_MLLI_ENTRIES) {
		dev_err(dev, "Too many mlli entries. current %d max %d\n",
			new_nents, MAX_NUM_OF_TOTAL_MLLI_ENTRIES);
		return -ENOMEM;
	}

	/*21 handle buffer longer than 64 kbytes */
	while (buff_size > CC_MAX_MLLI_ENTRY_SIZE) {
		cc_lli_set_addr(mlli_entry_p, buff_dma);
		cc_lli_set_size(mlli_entry_p, CC_MAX_MLLI_ENTRY_SIZE);
		dev_dbg(dev, "entry[%d]: single_buff=0x%08X size=%08X\n",
			*curr_nents, mlli_entry_p[LLI_WORD0_OFFSET],
			mlli_entry_p[LLI_WORD1_OFFSET]);
		buff_dma += CC_MAX_MLLI_ENTRY_SIZE;
		buff_size -= CC_MAX_MLLI_ENTRY_SIZE;
		mlli_entry_p = mlli_entry_p + 2;
		(*curr_nents)++;
	}
	/*22 Last entry */
	cc_lli_set_addr(mlli_entry_p, buff_dma);
	cc_lli_set_size(mlli_entry_p, buff_size);
	dev_dbg(dev, "entry[%d]: single_buff=0x%08X size=%08X\n",
		*curr_nents, mlli_entry_p[LLI_WORD0_OFFSET],
		mlli_entry_p[LLI_WORD1_OFFSET]);
	mlli_entry_p = mlli_entry_p + 2;
	*mlli_entry_pp = mlli_entry_p;
	(*curr_nents)++;
	return 0;
}
