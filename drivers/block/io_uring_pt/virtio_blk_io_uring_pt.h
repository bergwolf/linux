#ifndef _VIRTIO_BLK_IO_URING_PT_H
#define _VIRTIO_BLK_IO_URING_PT_H

#include <uapi/linux/io_uring.h>
#include "liburing.h"
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/circ_buf.h>
#include <linux/io.h>

#define VIRTIO_BLK_F_IO_URING   15
#define VIRTIO_BLK_F_KTHREAD    16

#define IO_URING_MR_BASE        0x100000000
#define IO_URING_MR_SIZE        (1<<20)
#define IO_URING_DB_SIZE        1024

#define VIRTIO_BLK_PCI_SHMCAP_ID_IOUPT 0

#define REQ_MAX_ENTRIES		128

/*
 * Shared with the host
 */
struct virtio_blk_iouring_enter {
	unsigned int to_submit;
	unsigned int min_complete;
	unsigned int flags;
};

struct virtio_blk_iouring {
	uint64_t mr_base;
	uint64_t mr_size;
	uint64_t phy_offset;
	uint64_t sqcq_offset;
	uint64_t sqes_offset;
	uint64_t kick_offset;
	uint64_t userspace;
	struct io_uring_params params;
	struct virtio_blk_iouring_enter enter;
};

struct virtblk_iouring_req {
	struct virtblk_req *vbr;
	uint64_t offset;
	uint32_t type;
	int direction;
	unsigned int sg_num;
};


#define IOUPT_CQ_KTHREAD
#define IOUPT_CQ_KTHREAD_SLEEP
//#define IOUPT_FIXED
#define IOUPT_MEMREMAP
#define IOUPT_PCI_SHM
//#define IOUPT_HACK_IOVEC // only for latency, it works only with iodepth=1

struct io_uring_pt {
	struct io_uring ring;
	uint64_t phy_offset;
	struct virtio_blk_iouring *vbi;
	void *kick_addr;
	bool enabled;
	struct task_struct *kthread;
	struct gendisk *disk;
	spinlock_t cq_lock;
#ifdef IOUPT_HACK_IOVEC
	struct iovec *iov;
	phys_addr_t iov_phy;
#endif
};

static int virtblk_iouring_submit_rq(struct io_uring_pt *iou_pt,
		struct virtblk_req *vbr, int direction, uint32_t type,
		unsigned int sg_num, uint64_t offset)
{
	struct io_uring_sqe *sqe;

	if (unlikely(iou_pt->vbi->userspace != 0))
		return -EAGAIN;

	if (likely(sg_num)) {
		struct scatterlist *sg = vbr->sg;
		phys_addr_t vec_phys;
		int i;

		if (unlikely(type & VIRTIO_BLK_T_FLUSH))
			printk("VIRTIO_BLK_T_FLUSH define with data!!!!\n");

#ifndef IOUPT_FIXED
		sqe = io_uring_get_sqe(&iou_pt->ring);
		if (unlikely(!sqe)) {
			return -EAGAIN;
		}
#ifndef IOUPT_HACK_IOVEC
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
#else
		/* TODO: add new field to count requests */
		vbr->vec[0].iov_len = sg_num;
		for (i = 0; i < sg_num; i++) {
			phys_addr_t base = iou_pt->phy_offset + sg_phys(sg);

			sqe = io_uring_get_sqe(&iou_pt->ring);
			if (unlikely(!sqe)) {
				printk("AAAAAAAAAAAAAA\n");
				return -EAGAIN;
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
			sg = sg_next(sg);
		}
#endif
	}

	if (unlikely(type & VIRTIO_BLK_T_FLUSH)) {
		sqe = io_uring_get_sqe(&iou_pt->ring);
		if (unlikely(!sqe))
			return -EAGAIN;

		io_uring_prep_fsync(sqe, 0, IORING_FSYNC_DATASYNC);
		sqe->flags |= IOSQE_FIXED_FILE;
#ifdef IOUPT_FIXED
		vbr->vec[0].iov_len = 1;
#endif
		io_uring_sqe_set_data(sqe, vbr);
	}

	io_uring_submit(&iou_pt->ring);

	return 0;
}

static bool virtblk_iouring_cq_poll(struct io_uring_pt *iou_pt)
{
	struct io_uring_cqe *cqe;
	bool req_done = false;
	unsigned long flags;

	if (unlikely(!io_uring_cq_ready(&iou_pt->ring)))
		return false;

	if (unlikely(iou_pt->vbi->userspace != 0))
		return false;

	spin_lock_irqsave(&iou_pt->cq_lock, flags);

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
			printk("cq_poll ERROR- vbr: %p res: %d\n", vbr, cqe->res);
			vbr->status = VIRTIO_BLK_S_IOERR;
		}
#ifdef IOUPT_FIXED
		vbr->vec[0].iov_len--;

		if (vbr->vec[0].iov_len > 0)
			continue;
#endif

		req = blk_mq_rq_from_pdu(vbr);
		blk_mq_complete_request(req);
		req_done = true;
	}

	/* In case queue is stopped waiting for more buffers. */
	if (likely(req_done))
		blk_mq_start_stopped_hw_queues(iou_pt->disk->queue, true);

	spin_unlock_irqrestore(&iou_pt->cq_lock, flags);

	return req_done;
}

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

	return ioread32(iou_pt->kick_addr + 4);
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
		printk("IORING_FEAT_SINGLE_MMAP needed!");
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

	vbi->userspace = 0;

	printk("mr_base %px kick_offset %llu kick_addr %px\n",
	        mr_base, vbi->kick_offset, iou_pt->kick_addr);

	memset(ring, 0, sizeof(*ring));
	ring->flags = p->flags;
	return io_uring_mmap(mr_base + vbi->sqcq_offset,
			     mr_base + vbi->sqes_offset,
			     p, &ring->sq, &ring->cq);
}

static int virtblk_iouring_init(struct virtio_device *vdev,
				struct io_uring_pt *iou_pt)
{
	resource_size_t mr_phy_base;
	size_t mr_size;
	void *mr_base;
	int ret;

#ifdef IOUPT_PCI_SHM
	struct virtio_shm_region shm;
	bool have_shm;

	have_shm = virtio_get_shm_region(vdev, &shm,
					 (u8)VIRTIO_BLK_PCI_SHMCAP_ID_IOUPT);

	if (!have_shm) {
		dev_notice(&vdev->dev, "%s: No MEMBAR capability\n", __func__);
		return -ENOMEM;
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

	ret = io_uring_queue_mmap(iou_pt, mr_base);
	if (ret)
		goto out;

#if defined(IOUPT_CQ_KTHREAD)
	iou_pt->kthread = kthread_run(virtblk_iouring_kthread, iou_pt,
				      "virtblk io_uring kthread");
	if (IS_ERR(iou_pt->kthread)) {
		ret = PTR_ERR(iou_pt->kthread);
		goto out;
	}
#endif

	return 0;
out:
	if (iou_pt->kthread)
		kthread_stop(iou_pt->kthread);
	return ret;
}

static void virtblk_iouring_fini(struct io_uring_pt *iou_pt)
{
	if (iou_pt->kthread)
		kthread_stop(iou_pt->kthread);
}

static int virtblk_iouring_add_req(struct io_uring_pt *iou_pt,
		struct virtblk_req *vbr, int direction, uint32_t type,
		unsigned int sg_num, uint64_t offset)
{
	//printk("virtblk_iouring_add_req - vbr: %p dir: %d type: %u sg_num: %u offset: %llu\n",
	//       vbr, direction, type, sg_num, offset);
	//
	return virtblk_iouring_submit_rq(iou_pt, vbr, direction, type,
					 sg_num, offset);
}

#endif /* _VIRTIO_BLK_IO_URING_PT_H */
