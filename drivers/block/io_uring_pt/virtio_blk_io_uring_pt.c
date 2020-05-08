#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/blkdev.h>
#include <linux/hdreg.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/interrupt.h>
#include <linux/virtio.h>
#include <linux/virtio_blk.h>
#include <linux/scatterlist.h>
#include <linux/string_helpers.h>
#include <linux/idr.h>
#include <linux/blk-mq.h>
#include <linux/blk-mq-virtio.h>
#include <linux/numa.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/circ_buf.h>
#include <linux/io.h>
#include <linux/falloc.h>

#include "../virtio_blk_common.h"
#include "../../virtio/virtio_pci_common.h"

#include "virtio_blk_io_uring_pt.h"
#include <uapi/linux/io_uring.h>
#include "liburing.h"

#define IO_URING_MR_BASE        0x100000000
#define IO_URING_MR_SIZE        (1<<20)
#define IO_URING_DB_SIZE        1024

#define VIRTIO_BLK_PCI_SHMCAP_ID_IOUPT 0

#define REQ_MAX_ENTRIES		128

//#define IOUPT_CQ_KTHREAD
//#define IOUPT_CQ_KTHREAD_SLEEP
//#define IOUPT_FIXED
#define IOUPT_MEMREMAP
#define IOUPT_PCI_SHM
//#define IOUPT_HACK_IOVEC // only for latency, it works only with iodepth=1


/*
 * Shared with the host
 */
struct virtio_blk_iouring_enter {
	unsigned int to_submit;
	unsigned int min_complete;
	unsigned int flags;
};

#define VBI_F_BLKDEV		0x0001llu
#define VBI_F_USERSPACE		0x0002llu

struct virtio_blk_iouring {
	uint64_t flags;
	uint64_t mr_base;
	uint64_t mr_size;
	uint64_t phy_offset;
	uint64_t sqcq_offset;
	uint64_t sqes_offset;
	uint64_t kick_offset;
	uint32_t vector;
	struct io_uring_params params;
	struct virtio_blk_iouring_enter enter;
	char serial_id[VIRTIO_BLK_ID_BYTES];
};

struct virtblk_iouring_req {
	struct virtblk_req *vbr;
	uint64_t offset;
	uint32_t type;
	int direction;
	unsigned int sg_num;
};

struct io_uring_pt {
	struct io_uring ring;
	uint64_t phy_offset;
	struct virtio_blk_iouring *vbi;
	void *kick_addr;
	struct task_struct *kthread;
	struct gendisk *disk;
	spinlock_t sq_lock; /* TODO: maybe we can optimize splitting get_sqe, from submit */
	spinlock_t cq_lock;
#ifdef IOUPT_HACK_IOVEC
	struct iovec *iov;
	phys_addr_t iov_phy;
#endif
};

static bool iouring_cq_notify_enabled(struct io_uring *ring)
{
	if (unlikely(!ring->cq.kflags))
		return true;

	return IO_URING_READ_ONCE(*ring->cq.kflags) & IORING_CQ_NEED_WAKEUP;
}

static void iouring_cq_notify_disable(struct io_uring *ring)
{
	if (unlikely(!ring->cq.kflags))
		return;

	*ring->cq.kflags &= ~IORING_CQ_NEED_WAKEUP;
}

static bool iouring_cq_notify_enable(struct io_uring *ring)
{
	if (unlikely(!ring->cq.kflags))
		return true;

	*ring->cq.kflags |= IORING_CQ_NEED_WAKEUP;
	/* make sure to read CQ tail after writing flags */
	io_uring_barrier();

	return !io_uring_cq_ready(ring);
}

static void virtblk_iouring_submit(struct io_uring *ring, struct request *req)
{
	/* TODO how to handle multiple hipri and non-hipri requests at the same time? */
	if (req->cmd_flags & REQ_HIPRI)
		iouring_cq_notify_disable(ring);
	else
		iouring_cq_notify_enable(ring);

	io_uring_submit(ring);
}

bool virtblk_iouring_cq_poll(struct io_uring_pt *iou_pt)
{
	struct io_uring_cqe *cqe;
	bool req_done = false, disable_notify;
	unsigned long flags;

	if (unlikely(!io_uring_cq_ready(&iou_pt->ring)))
		return false;

	if (unlikely(iou_pt->vbi->flags & VBI_F_USERSPACE))
		return false;

	spin_lock_irqsave(&iou_pt->cq_lock, flags);

	disable_notify = iouring_cq_notify_enabled(&iou_pt->ring);

	do {
		if (disable_notify)
			iouring_cq_notify_disable(&iou_pt->ring);

		while (likely(io_uring_cq_ready(&iou_pt->ring))) {
			struct virtblk_req *vbr;
			struct request *req;

			io_uring_peek_cqe(&iou_pt->ring, &cqe);
			if (unlikely(!cqe))
				break;

			vbr = io_uring_cqe_get_data(cqe);
			io_uring_cqe_seen(&iou_pt->ring, cqe);

			vbr->status = VIRTIO_BLK_S_OK;
			if (unlikely(cqe->res < 0)) {
				printk("cq_poll ERROR- vbr: %p res: %d\n",
				       vbr, cqe->res);
				vbr->status = VIRTIO_BLK_S_IOERR;
			}

			if (--vbr->sub_requests > 0)
				continue;

			req = blk_mq_rq_from_pdu(vbr);
			blk_mq_complete_request(req);
			req_done = true;
		}

	} while (disable_notify & !iouring_cq_notify_enable(&iou_pt->ring));

	/* In case queue is stopped waiting for more buffers. */
	if (likely(req_done))
		blk_mq_start_stopped_hw_queues(iou_pt->disk->queue, true);

	spin_unlock_irqrestore(&iou_pt->cq_lock, flags);

	return req_done;
}
EXPORT_SYMBOL_GPL(virtblk_iouring_cq_poll);

static int virtblk_iouring_kick(struct io_uring *ring, unsigned submitted,
				       unsigned wait_nr, unsigned flags)
{
	struct io_uring_pt *iou_pt =
		container_of(ring, struct io_uring_pt, ring);

	printk("kick - submitted %u wait_nr %u flags %u\n", submitted, wait_nr, flags);

	iou_pt->vbi->enter.to_submit = submitted;
	iou_pt->vbi->enter.min_complete = wait_nr;
	iou_pt->vbi->enter.flags = flags;

	iowrite32(1, iou_pt->kick_addr);

	//return ioread32(iou_pt->kick_addr + 4);
	return submitted;
}

#if defined(IOUPT_CQ_KTHREAD)
static int virtblk_iouring_kthread(void *data)
{
	struct io_uring_pt *iou_pt = (struct io_uring_pt *)data;

	while (!kthread_should_stop()) {
		if (kthread_should_park())
			kthread_parkme();

		virtblk_iouring_cq_poll(iou_pt);

#ifdef IOUPT_CQ_KTHREAD_SLEEP
		msleep(10);
#else
		//cpu_relax();
		cond_resched();
#endif
	}

	return 0;
}
#endif

static int io_uring_mmap(void *sqcq, void* sqes,
			 struct io_uring_params *p,
			 struct io_uring_sq *sq, struct io_uring_cq *cq)
{
	size_t size;

	sq->ring_sz = p->sq_off.array + p->sq_entries * sizeof(unsigned);
	cq->ring_sz = p->cq_off.cqes + p->cq_entries * sizeof(struct io_uring_cqe);

	if (p->features & IORING_FEAT_SINGLE_MMAP) {
		if (cq->ring_sz > sq->ring_sz)
			sq->ring_sz = cq->ring_sz;
		cq->ring_sz = sq->ring_sz;
	}
	sq->ring_ptr = sqcq;

	if (p->features & IORING_FEAT_SINGLE_MMAP) {
		cq->ring_ptr = sq->ring_ptr;
	} else {
		printk("IORING_FEAT_SINGLE_MMAP needed!\n");
		return -EINVAL;
	}

	sq->khead = sq->ring_ptr + p->sq_off.head;
	sq->ktail = sq->ring_ptr + p->sq_off.tail;
	sq->kring_mask = sq->ring_ptr + p->sq_off.ring_mask;
	sq->kring_entries = sq->ring_ptr + p->sq_off.ring_entries;
	sq->kflags = sq->ring_ptr + p->sq_off.flags;
	sq->kdropped = sq->ring_ptr + p->sq_off.dropped;
	sq->array = sq->ring_ptr + p->sq_off.array;

	size = p->sq_entries * sizeof(struct io_uring_sqe);
	sq->sqes = sqes;

	cq->khead = cq->ring_ptr + p->cq_off.head;
	cq->ktail = cq->ring_ptr + p->cq_off.tail;
	cq->kring_mask = cq->ring_ptr + p->cq_off.ring_mask;
	cq->kring_entries = cq->ring_ptr + p->cq_off.ring_entries;
	cq->koverflow = cq->ring_ptr + p->cq_off.overflow;
	cq->cqes = cq->ring_ptr + p->cq_off.cqes;
	if (p->features & IORING_FEAT_CQ_FLAGS) {
		cq->kflags = cq->ring_ptr + p->cq_off.flags;
	} else {
		cq->kflags = NULL;
		printk("IORING_FEAT_CQ_FLAGS needed!\n");
	}


	return 0;
}

static int io_uring_queue_mmap(struct io_uring_pt *iou_pt,
			       void *mr_base)
{
	struct virtio_blk_iouring *vbi = mr_base;
	struct io_uring_params *p = &vbi->params;
	struct io_uring *ring = &iou_pt->ring;

	printk("sqes val(uint64_t): %lld\n", *((uint64_t *)(mr_base + vbi->sqes_offset)));
	printk("sqcq val(uint64_t): %lld\n", *((uint64_t *)(mr_base + vbi->sqcq_offset)));

	iou_pt->vbi = vbi;
	iou_pt->phy_offset = vbi->phy_offset;
	iou_pt->kick_addr = mr_base + vbi->kick_offset;

	printk("mr_base %px kick_offset %llu kick_addr %px\n",
	        mr_base, vbi->kick_offset, iou_pt->kick_addr);

	memset(ring, 0, sizeof(*ring));
	ring->flags = p->flags;
	return io_uring_mmap(mr_base + vbi->sqcq_offset,
			     mr_base + vbi->sqes_offset,
			     p, &ring->sq, &ring->cq);
}

static irqreturn_t virtblk_iouring_interrupt(int irq, void *opaque)
{
	struct virtio_blk *vblk = opaque;

	//printk("interrupt - irq %d\n", irq);

	virtblk_iouring_cq_poll(vblk->iou_pt);

	return IRQ_HANDLED;
}

int virtblk_iouring_init(struct virtio_blk *vblk)
{
	struct virtio_pci_device *vp_dev = to_vp_device(vblk->vdev);
#ifdef IOUPT_PCI_SHM
	struct virtio_shm_region shm;
	bool have_shm;
#endif
	resource_size_t mr_phy_base;
	size_t mr_size;
	void *mr_base;
	int ret;

	vblk->iou_pt = kmalloc(sizeof(*vblk->iou_pt), GFP_KERNEL);
	if (!vblk) {
		return -ENOMEM;
	}

	spin_lock_init(&vblk->iou_pt->cq_lock);
	spin_lock_init(&vblk->iou_pt->sq_lock);

	vblk->iou_pt->disk = vblk->disk;

#ifdef IOUPT_PCI_SHM
	have_shm = virtio_get_shm_region(vblk->vdev, &shm,
					 (u8)VIRTIO_BLK_PCI_SHMCAP_ID_IOUPT);
	if (!have_shm) {
		dev_notice(&vblk->vdev->dev, "%s: No MEMBAR capability\n",
			   __func__);
		ret = -ENOMEM;
		goto out;
	}

	mr_phy_base = shm.addr;
	mr_size = shm.len;
#else
	mr_phy_base = IO_URING_MR_BASE;
	mr_size = IO_URING_MR_SIZE;
#endif

#ifdef IOUPT_MEMREMAP
	mr_base = memremap(mr_phy_base, mr_size, MEMREMAP_WB);
#else
	//if (request_mem_region(mr_phy_base, mr_size, "io_uring mr") == NULL)
	//	return -EBUSY;

	mr_base = (__force void *)ioremap_cache(mr_phy_base, mr_size);
#endif
	if (mr_base == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	printk("mr_phy_base 0x%llx mr_base %px\n", mr_phy_base, mr_base);

	ret = io_uring_queue_mmap(vblk->iou_pt, mr_base);
	if (ret)
		goto out;

	printk("request_irq - vector: %d\n", vblk->iou_pt->vbi->vector);
	ret = request_irq(pci_irq_vector(vp_dev->pci_dev,
					 vblk->iou_pt->vbi->vector),
			  virtblk_iouring_interrupt, 0, "virtblk-iou-irq",
			  vblk);
	if (ret) {
		printk("request_irq failed: %d\n", ret);
		goto out;
	}

#if defined(IOUPT_CQ_KTHREAD)
	vblk->iou_pt->kthread = kthread_run(virtblk_iouring_kthread, vblk->iou_pt,
				      "virtblk io_uring kthread");
	if (IS_ERR(vblk->iou_pt->kthread)) {
		ret = PTR_ERR(vblk->iou_pt->kthread);
		goto out;
	}
#endif


#ifdef IOUPT_HACK_IOVEC
	vblk->iou_pt->iov = kmalloc_array(vblk->sg_elems, sizeof(struct iovec), GFP_KERNEL);
	vblk->iou_pt->iov_phy = vblk->iou_pt->phy_offset + virt_to_phys(vblk->iou_pt->iov);
#endif
	return 0;
out:
	if (vblk->iou_pt->kthread)
		kthread_stop(vblk->iou_pt->kthread);
	kfree(vblk->iou_pt);
	vblk->iou_pt = NULL;
	return ret;
}
EXPORT_SYMBOL_GPL(virtblk_iouring_init);

void virtblk_iouring_fini(struct virtio_blk *vblk)
{
	if (vblk->iou_pt->kthread)
		kthread_stop(vblk->iou_pt->kthread);

	kfree(vblk->iou_pt);
	vblk->iou_pt = NULL;
}
EXPORT_SYMBOL_GPL(virtblk_iouring_fini);

void virtblk_iouring_commit_rqs(struct io_uring_pt *iou_pt)
{
	unsigned long flags;

	spin_lock_irqsave(&iou_pt->sq_lock, flags);

	io_uring_submit(&iou_pt->ring);

	spin_unlock_irqrestore(&iou_pt->sq_lock, flags);
}
EXPORT_SYMBOL_GPL(virtblk_iouring_commit_rqs);

static int virtblk_iouring_queue_rq_io(struct virtio_blk *vblk,
				       struct virtblk_req *vbr,
				       struct request *req,
				       struct blk_mq_hw_ctx *hctx)
{
	uint64_t offset = (u64)blk_rq_pos(req) << SECTOR_SHIFT;
	struct io_uring_pt *iou_pt = vblk->iou_pt;
	int direction = rq_data_dir(req);
	struct io_uring_sqe *sqe;
	struct scatterlist *sg;
	unsigned long flags;
	unsigned int sg_num;
	phys_addr_t vec_phys;
	int ret = 0, i;

	sg_num = blk_rq_map_sg(hctx->queue, req, vbr->sg);
	if (!sg_num)
		return 0;

	sg = vbr->sg;

#ifndef IOUPT_FIXED
#ifndef IOUPT_HACK_IOVEC
	vbr->vec = (void *)vbr + sizeof(struct scatterlist) * vblk->sg_elems;
	vec_phys = iou_pt->phy_offset + virt_to_phys(vbr->vec);
	for (i = 0; i < sg_num; i++) {
		phys_addr_t base = iou_pt->phy_offset + sg_phys(sg);
		vbr->vec[i].iov_base = (void *)base;
		vbr->vec[i].iov_len = sg->length;
		sg = sg_next(sg);
	}
#else
	vec_phys = iou_pt->iov_phy;
	for (i = 0; i < sg_num; i++) {
		phys_addr_t base = iou_pt->phy_offset + sg_phys(sg);
		iou_pt->iov[i].iov_base = (void *)base;
		iou_pt->iov[i].iov_len = sg->length;
		sg = sg_next(sg);
	}
#endif
	spin_lock_irqsave(&iou_pt->sq_lock, flags);

	sqe = io_uring_get_sqe(&iou_pt->ring);
	if (unlikely(!sqe)) {
		ret = -EAGAIN;
		goto out;
	}

	if (direction == WRITE)
		io_uring_prep_rw(IORING_OP_WRITEV, sqe, 0,
				 (void *)vec_phys, sg_num,
				 offset);
	else
		io_uring_prep_rw(IORING_OP_READV,sqe, 0,
				 (void *)vec_phys, sg_num,
				 offset);

	sqe->flags |= IOSQE_FIXED_FILE;
	io_uring_sqe_set_data(sqe, vbr);
	vbr->sub_requests = 1;
#else
	spin_lock_irqsave(&iou_pt->sq_lock, flags);

	/* we need to queue all the requests */
	if (sg_num > io_uring_sq_space_left(&iou_pt->ring)) {
		ret = -EAGAIN;
		goto out;
	}

	vbr->sub_requests = 0;

	for (i = 0; i < sg_num; i++) {
		phys_addr_t base = iou_pt->phy_offset + sg_phys(sg);

		sqe = io_uring_get_sqe(&iou_pt->ring);
		if (unlikely(!sqe)) {
			/* shouldn't happen */
			ret = -EIO;
			goto out;
		}

		if (direction == WRITE)
			io_uring_prep_rw(IORING_OP_WRITE_FIXED, sqe, 0,
				 (void *)base, sg->length,
				 offset);
		else
			io_uring_prep_rw(IORING_OP_READ_FIXED,sqe, 0,
				 (void *)base, sg->length,
				 offset);

		sqe->buf_index = 0;
		sqe->flags |= IOSQE_FIXED_FILE;

		io_uring_sqe_set_data(sqe, vbr);
		vbr->sub_requests++;

		sg = sg_next(sg);
	}
#endif

	virtblk_iouring_submit(&iou_pt->ring, req);

out:
	spin_unlock_irqrestore(&iou_pt->sq_lock, flags);
	return ret;
}

static int virtblk_iouring_queue_rq_flush(struct virtio_blk *vblk,
					  struct virtblk_req *vbr,
					  struct request *req)
{
	struct io_uring_pt *iou_pt = vblk->iou_pt;
	struct io_uring_sqe *sqe;
	unsigned long flags;
	int ret = 0;

	spin_lock_irqsave(&iou_pt->sq_lock, flags);

	sqe = io_uring_get_sqe(&iou_pt->ring);
	if (unlikely(!sqe)) {
		ret = -EAGAIN;
		goto out;
	}

	io_uring_prep_fsync(sqe, 0, IORING_FSYNC_DATASYNC);
	sqe->flags |= IOSQE_FIXED_FILE;

	io_uring_sqe_set_data(sqe, vbr);
	vbr->sub_requests = 1;

	virtblk_iouring_submit(&iou_pt->ring, req);

out:
	spin_unlock_irqrestore(&iou_pt->sq_lock, flags);
	return ret;
}

static int virtblk_iouring_queue_rq_discard_write_zeroes(
	struct virtio_blk *vblk, struct virtblk_req *vbr,
	struct request *req, bool discard, bool write_zeroes)
{
	unsigned short segments = blk_rq_nr_discard_segments(req);
	struct io_uring_pt *iou_pt = vblk->iou_pt;
	struct io_uring_sqe *sqe;
	unsigned long flags;
	struct bio *bio;
	int mode, ret = 0;

	if (write_zeroes)
		mode = FALLOC_FL_ZERO_RANGE | FALLOC_FL_KEEP_SIZE;
	else if (discard) {
		mode = FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE;

		if (!write_zeroes && iou_pt->vbi->flags & VBI_F_BLKDEV)
			mode |= FALLOC_FL_NO_HIDE_STALE;
	} else
		return 0;

	spin_lock_irqsave(&iou_pt->sq_lock, flags);

	/* we need to queue all the requests */
	if (segments > io_uring_sq_space_left(&iou_pt->ring)) {
		ret = -EAGAIN;
		goto out;
	}

	vbr->sub_requests = 0;

	__rq_for_each_bio(bio, req) {
		off_t offset = bio->bi_iter.bi_sector << SECTOR_SHIFT;
		off_t len = bio->bi_iter.bi_size;

		sqe = io_uring_get_sqe(&iou_pt->ring);
		if (unlikely(!sqe)) {
			/* shouldn't happen */
			ret = -EIO;
			goto out;
		}

		io_uring_prep_fallocate(sqe, 0, mode, offset, len);
		sqe->flags |= IOSQE_FIXED_FILE;

		io_uring_sqe_set_data(sqe, vbr);
		vbr->sub_requests++;
	}

	virtblk_iouring_submit(&iou_pt->ring, req);

out:
	spin_unlock_irqrestore(&iou_pt->sq_lock, flags);
	return ret;
}

static int virtblk_iouring_get_id(struct virtio_blk *vblk,
				  struct virtblk_req *vbr,
				  struct request *req,
				  struct blk_mq_hw_ctx *hctx)
{
	struct io_uring_pt *iou_pt = vblk->iou_pt;
	unsigned int sg_num;

	sg_num = blk_rq_map_sg(hctx->queue, req, vbr->sg);
	if (!sg_num)
		return 0;

	sg_copy_from_buffer(vbr->sg, sg_num, iou_pt->vbi->serial_id,
			    VIRTIO_BLK_ID_BYTES);

	blk_mq_complete_request(req);

	return 0;
}

blk_status_t virtblk_iouring_queue_rq(struct virtio_blk *vblk,
				      struct virtblk_req *vbr,
				      struct request *req,
				      struct blk_mq_hw_ctx *hctx)
{
	struct io_uring_pt *iou_pt = vblk->iou_pt;
	bool unmap;
	int err;

	if (unlikely(iou_pt->vbi->flags & VBI_F_USERSPACE))
		return BLK_STS_DEV_RESOURCE;

	blk_mq_start_request(req);

	switch (req_op(req)) {
	case REQ_OP_READ:
	case REQ_OP_WRITE:
		err = virtblk_iouring_queue_rq_io(vblk, vbr, req, hctx);
		break;
	case REQ_OP_FLUSH:
		err = virtblk_iouring_queue_rq_flush(vblk, vbr, req);
		break;
	case REQ_OP_DISCARD:
		err = virtblk_iouring_queue_rq_discard_write_zeroes(vblk, vbr,
			req, true, false);
		break;
	case REQ_OP_WRITE_ZEROES:
		unmap = !(req->cmd_flags & REQ_NOUNMAP);
		err = virtblk_iouring_queue_rq_discard_write_zeroes(vblk, vbr,
			req, unmap, true);
		break;
	case REQ_OP_DRV_IN:
		err = virtblk_iouring_get_id(vblk, vbr, req, hctx);
		break;
	default:
		WARN_ON_ONCE(1);
		return BLK_STS_IOERR;
	}

	if (unlikely(err)) {
		blk_mq_stop_hw_queue(hctx);

		printk("virtblk_iouring_queue_req - err %d\n", err);
		if (err == -ENOMEM || err == -EAGAIN)
			return BLK_STS_DEV_RESOURCE;

		return BLK_STS_IOERR;
	}

	return BLK_STS_OK;
}
EXPORT_SYMBOL_GPL(virtblk_iouring_queue_rq);

MODULE_LICENSE("GPL");
