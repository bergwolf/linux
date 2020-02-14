#ifndef _VIRTIO_BLK_IO_URING_PT_H
#define _VIRTIO_BLK_IO_URING_PT_H

#include <uapi/linux/io_uring.h>

#define VIRTIO_BLK_F_IO_URING   15
#define IO_URING_MR_BASE        0xd0000000
#define IO_URING_MR_SIZE        (1<<20)

/*
 * Shared with the host
 */
struct virtio_blk_iouring {
	uint64_t mr_base;
	uint64_t mr_size;
	uint64_t phy_offset;
	uint64_t sqcq_offset;
	uint64_t sqes_offset;
	struct io_uring_params params;
};

/*
 * Library interface to io_uring
 */
struct io_uring_sq {
	unsigned *khead;
	unsigned *ktail;
	unsigned *kring_mask;
	unsigned *kring_entries;
	unsigned *kflags;
	unsigned *kdropped;
	unsigned *array;
	struct io_uring_sqe *sqes;

	unsigned sqe_head;
	unsigned sqe_tail;

	size_t ring_sz;
	void *ring_ptr;
};

struct io_uring_cq {
	unsigned *khead;
	unsigned *ktail;
	unsigned *kring_mask;
	unsigned *kring_entries;
	unsigned *koverflow;
	struct io_uring_cqe *cqes;

	size_t ring_sz;
	void *ring_ptr;
};

struct io_uring {
	struct io_uring_sq sq;
	struct io_uring_cq cq;
	unsigned flags;
	int ring_fd;
};


struct io_uring_pt {
	struct io_uring ring;
	uint64_t phy_offset;
	bool enabled;
};

struct virtio_blk;

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
			       void __iomem *mr_base)
{
    	struct virtio_blk_iouring __iomem *vbi = mr_base;
	struct io_uring_params *p = &vbi->params;
	struct io_uring *ring = &iou_pt->ring;

	printk("sqes val(uint64_t): %lld\n", *((uint64_t *)(mr_base + vbi->sqes_offset)));
	printk("sqcq val(uint64_t): %lld\n", *((uint64_t *)(mr_base + vbi->sqcq_offset)));

	iou_pt->phy_offset = vbi->phy_offset;

	memset(ring, 0, sizeof(*ring));
	return io_uring_mmap(mr_base + vbi->sqcq_offset,
			     mr_base + vbi->sqes_offset,
			     p, &ring->sq, &ring->cq);
}


static int virtblk_iouring_init(struct io_uring_pt *iou_pt)
{
	void __iomem *mr_base;

	if (request_mem_region(IO_URING_MR_BASE, IO_URING_MR_SIZE,
	                       "io_uring mr") == NULL)
		return -EBUSY;

	mr_base = ioremap(IO_URING_MR_BASE, IO_URING_MR_SIZE);
	if (mr_base == NULL) {
		release_mem_region(IO_URING_MR_BASE, IO_URING_MR_SIZE);
		return -ENOMEM;
	}

	return io_uring_queue_mmap(iou_pt, mr_base);
}

#endif /* _VIRTIO_BLK_IO_URING_PT_H */
