#ifndef _VIRTIO_BLK_IO_URING_PT_H
#define _VIRTIO_BLK_IO_URING_PT_H

#include <uapi/linux/io_uring.h>
#include "liburing.h"
#include <linux/kthread.h>
#include <linux/delay.h>

#define VIRTIO_BLK_F_IO_URING   15
#define VIRTIO_BLK_F_KTHREAD    16

#define IO_URING_MR_BASE        0xd0000000
#define IO_URING_MR_SIZE        (1<<20)
#define IO_URING_DB_SIZE        1024

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
	struct io_uring_params params;
	struct virtio_blk_iouring_enter enter;
};


struct io_uring_pt {
	struct io_uring ring;
	uint64_t phy_offset;
	struct virtio_blk_iouring *vbi;
	void *kick_addr;
	bool enabled;
	struct task_struct *kthread;
	struct gendisk *disk;
};

static int virtio_blk_iourint_pt_kick(struct io_uring *ring, unsigned submitted,
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


static int iou_pt_kthread(void *data)
{
	struct io_uring_pt *iou_pt = (struct io_uring_pt *)data;

	while (!kthread_should_stop()) {
		struct io_uring_cqe *cqe;
		bool req_done = false;

#if 0
		if (!(*iou_pt->ring.cq.ktail - *iou_pt->ring.cq.khead)) {
			cond_resched();
			continue;
		}
#endif
		while (io_uring_peek_cqe(&iou_pt->ring, &cqe) == 0) {
			struct virtblk_req *vbr;
			struct request *req;

			if (!cqe)
				break;

			vbr = io_uring_cqe_get_data(cqe);
			io_uring_cqe_seen(&iou_pt->ring, cqe);

			//printk("iou_pt_kthread - vbr: %p res: %d\n", vbr,
			//       cqe->res);
			if (cqe->res < 0) {
				printk("iou_pt_kthread ERROR- vbr: %p res: %d\n", vbr, cqe->res);
			}

			req = blk_mq_rq_from_pdu(vbr);
			blk_mq_complete_request(req);
			req_done = true;
		}

		/* In case queue is stopped waiting for more buffers. */
		if (req_done)
			blk_mq_start_stopped_hw_queues(iou_pt->disk->queue,
						       true);

		//cpu_relax();
		cond_resched();
	}

	return 0;
}

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

	printk("mr_base %px kick_offset %llu kick_addr %px\n",
	        mr_base, vbi->kick_offset, iou_pt->kick_addr);

	memset(ring, 0, sizeof(*ring));
	ring->flags = p->flags;
	return io_uring_mmap(mr_base + vbi->sqcq_offset,
			     mr_base + vbi->sqes_offset,
			     p, &ring->sq, &ring->cq);
}


static int virtblk_iouring_init(struct io_uring_pt *iou_pt)
{
	void *mr_base;
	int ret;

	if (request_mem_region(IO_URING_MR_BASE, IO_URING_MR_SIZE,
	                       "io_uring mr") == NULL)
		return -EBUSY;

	mr_base = (__force void *)ioremap_cache(IO_URING_MR_BASE, IO_URING_MR_SIZE);
	if (mr_base == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	ret = io_uring_queue_mmap(iou_pt, mr_base);
	if (ret)
		goto out;

	iou_pt->kthread = kthread_run(iou_pt_kthread, iou_pt,
				      "io_uring kthread");
	if (IS_ERR(iou_pt->kthread)) {
		ret = PTR_ERR(iou_pt->kthread);
		goto out;
	}

	return 0;
out:
	release_mem_region(IO_URING_MR_BASE, IO_URING_MR_SIZE);
	return ret;
}

static void virtblk_iouring_fini(struct io_uring_pt *iou_pt)
{
	if (iou_pt->kthread) {
		kthread_stop(iou_pt->kthread);
	}
}

static int virtblk_iouring_add_req(struct io_uring_pt *iou_pt,
		struct virtblk_req *vbr, int direction, uint32_t type,
		unsigned int sg_num, uint64_t offset)
{
	struct io_uring_sqe *sqe;

	//printk("virtblk_iouring_add_req - vbr: %p dir: %d type: %u sg_num: %u offset: %llu\n",
	//       vbr, direction, type, sg_num, offset);

	if (sg_num) {
		struct scatterlist *sg = vbr->sg;
		phys_addr_t vec_phys;
		int i;

		vec_phys = iou_pt->phy_offset + virt_to_phys(vbr->vec);

		sqe = io_uring_get_sqe(&iou_pt->ring);
		if (!sqe) {
			kfree(vbr->vec);
			return -EAGAIN;
		}

		for (i = 0; i < sg_num; i++) {
			phys_addr_t base = iou_pt->phy_offset + sg_phys(sg);
			vbr->vec[i].iov_base = (void *)base;
			vbr->vec[i].iov_len = sg->length;
			sg = sg_next(sg);
		}

		if (direction == WRITE)
			io_uring_prep_rw(IORING_OP_WRITEV, sqe, 0,
					 (void *)vec_phys, sg_num, offset);
		else
			io_uring_prep_rw(IORING_OP_READV,sqe, 0,
					 (void *)vec_phys, sg_num, offset);

		sqe->flags |= IOSQE_FIXED_FILE;
		io_uring_sqe_set_data(sqe, vbr);

		if (type & VIRTIO_BLK_T_FLUSH)
			printk("VIRTIO_BLK_T_FLUSH define with data!!!!\n");
	}

	if (type & VIRTIO_BLK_T_FLUSH) {
		sqe = io_uring_get_sqe(&iou_pt->ring);
		if (!sqe)
			return -EAGAIN;
		io_uring_prep_fsync(sqe, 0, IORING_FSYNC_DATASYNC);
		sqe->flags |= IOSQE_FIXED_FILE;
		io_uring_sqe_set_data(sqe, vbr);
	}

	return 0;
}

#endif /* _VIRTIO_BLK_IO_URING_PT_H */
