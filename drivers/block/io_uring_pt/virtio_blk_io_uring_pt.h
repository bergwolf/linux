#ifndef _VIRTIO_BLK_IO_URING_PT_H
#define _VIRTIO_BLK_IO_URING_PT_H

#include <uapi/linux/io_uring.h>
#include "liburing.h"
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/circ_buf.h>

#define VIRTIO_BLK_F_IO_URING   15
#define VIRTIO_BLK_F_KTHREAD    16

#define IO_URING_MR_BASE        0xd0000000
#define IO_URING_MR_SIZE        (1<<20)
#define IO_URING_DB_SIZE        1024

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

struct io_uring_pt {
	struct io_uring ring;
	uint64_t phy_offset;
	struct virtio_blk_iouring *vbi;
	void *kick_addr;
	bool enabled;
	struct task_struct *kthread;
	struct task_struct *kthread_sq;
	struct gendisk *disk;
	struct work_struct sq_work;
	struct virtblk_iouring_req sq_reqs[REQ_MAX_ENTRIES];
	int sq_reqs_size;
	int sq_head;
	int sq_tail;
};

//#define IOUPT_SQ_WORKER
#define IOUPT_SQ_KTHREAD
//#define IOUPT_FIXED
//#define IOUPT_SQ_KTHREAD_DEDICATED

#if defined(IOUPT_SQ_KTHREAD) && defined(IOUPT_SQ_WORKER)
#error "IOUPT_SQ_KTHREAD & IOUPT_SQ_WORKER can't be both defined!"
#endif

#ifdef IOUPT_SQ_WORKER
static struct workqueue_struct *virtblk_iouring_workqueue;
#endif

static int virtblk_iouring_queue_req(struct io_uring_pt *iou_pt,
		struct virtblk_req *vbr, int direction, uint32_t type,
		unsigned int sg_num, uint64_t offset)
{
	struct io_uring_sqe *sqe;

	if (sg_num) {
		struct scatterlist *sg = vbr->sg;
		phys_addr_t vec_phys;
		int i;

		if (type & VIRTIO_BLK_T_FLUSH)
			printk("VIRTIO_BLK_T_FLUSH define with data!!!!\n");

		vec_phys = iou_pt->phy_offset + virt_to_phys(vbr->vec);
#ifndef IOUPT_FIXED
		sqe = io_uring_get_sqe(&iou_pt->ring);
		if (!sqe) {
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
			if (!sqe) {
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

	if (type & VIRTIO_BLK_T_FLUSH) {
		sqe = io_uring_get_sqe(&iou_pt->ring);
		if (!sqe)
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

#if defined(IOUPT_SQ_WORKER) || defined(IOUPT_SQ_KTHREAD)
static void virtblk_iouring_sq_poll(struct io_uring_pt *iou_pt)
{
	int sq_tail = iou_pt->sq_tail;
	bool submit = false;

	while(true) {
		int sq_head = smp_load_acquire(&iou_pt->sq_head);
		struct virtblk_iouring_req *sq_req;
		int ret;

		if (CIRC_CNT(sq_head, sq_tail, iou_pt->sq_reqs_size) == 0)
			break;

		sq_req = &iou_pt->sq_reqs[sq_tail];

		ret = virtblk_iouring_queue_req(iou_pt, sq_req->vbr,
						sq_req->direction, sq_req->type,
						sq_req->sg_num, sq_req->offset);
		if (ret != 0) {
			io_uring_submit(&iou_pt->ring);
			continue;
		}

		sq_tail = (sq_tail + 1) & (iou_pt->sq_reqs_size - 1);
		smp_store_release(&iou_pt->sq_tail, sq_tail);
		//submit = true;
	}

	if (submit)
		io_uring_submit(&iou_pt->ring);
}
#endif

static void virtblk_iouring_cq_poll(struct io_uring_pt *iou_pt)
{
	struct io_uring_cqe *cqe;
	bool req_done = false;

#if 0
	if (!(*iou_pt->ring.cq.ktail - *iou_pt->ring.cq.khead)) {
		return;
	}
#endif
	while (io_uring_cq_ready(&iou_pt->ring)) {
		struct virtblk_req *vbr;
		struct request *req;

		io_uring_peek_cqe(&iou_pt->ring, &cqe);
		if (!cqe)
			break;

		vbr = io_uring_cqe_get_data(cqe);
		io_uring_cqe_seen(&iou_pt->ring, cqe);

		if (cqe->res < 0) {
			printk("cq_poll ERROR- vbr: %p res: %d\n", vbr, cqe->res);
			continue;
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
	if (req_done)
		blk_mq_start_stopped_hw_queues(iou_pt->disk->queue,
					       true);
}

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

#ifdef IOUPT_SQ_KTHREAD_DEDICATED
static int iou_pt_kthread_sq(void *data)
{
	struct io_uring_pt *iou_pt = (struct io_uring_pt *)data;

	while (!kthread_should_stop()) {
		if (kthread_should_park())
			kthread_parkme();

		virtblk_iouring_sq_poll(iou_pt);

		cond_resched();
	}

	return 0;
}
#endif

static int iou_pt_kthread(void *data)
{
	struct io_uring_pt *iou_pt = (struct io_uring_pt *)data;

	while (!kthread_should_stop()) {
		if (kthread_should_park())
			kthread_parkme();

#if defined(IOUPT_SQ_KTHREAD) && !defined(IOUPT_SQ_KTHREAD_DEDICATED)
		virtblk_iouring_sq_poll(iou_pt);
#endif

		virtblk_iouring_cq_poll(iou_pt);

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

#ifdef IOUPT_SQ_WORKER
static void virtblk_iouring_sq_work(struct work_struct *work)
{
	struct io_uring_pt *iou_pt =
		container_of(work, struct io_uring_pt, sq_work);

	virtblk_iouring_sq_poll(iou_pt);
}
#endif

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

#ifdef IOUPT_SQ_KTHREAD_DEDICATED
	iou_pt->kthread_sq = kthread_run(iou_pt_kthread_sq, iou_pt,
				      "io_uring kthread_sq");
	if (IS_ERR(iou_pt->kthread_sq)) {
		ret = PTR_ERR(iou_pt->kthread_sq);
		goto out_kthread;
	}
#endif

	iou_pt->sq_head = 0;
	iou_pt->sq_tail = 0;
	iou_pt->sq_reqs_size = REQ_MAX_ENTRIES;

#ifdef IOUPT_SQ_WORKER
	virtblk_iouring_workqueue = alloc_workqueue("io_uring wq", 0, 0);
	if (!virtblk_iouring_workqueue) {
		ret = -ENOMEM;
		goto out_kthread;
	}

	INIT_WORK(&iou_pt->sq_work, virtblk_iouring_sq_work);
#endif

	return 0;
#ifdef IOUPT_SQ_WORKER
out_kthread_sq:
	kthread_stop(iou_pt->kthread_sq);
#endif
#ifdef IOUPT_SQ_KTHREAD_DEDICATED
out_kthread:
	kthread_stop(iou_pt->kthread);
#endif
out:
	release_mem_region(IO_URING_MR_BASE, IO_URING_MR_SIZE);
	return ret;
}

static void virtblk_iouring_fini(struct io_uring_pt *iou_pt)
{
#ifdef IOUPT_SQ_WORKER
	flush_work(&iou_pt->sq_work);

	destroy_workqueue(virtblk_iouring_workqueue);
#endif

	if (iou_pt->kthread_sq)
		kthread_stop(iou_pt->kthread);

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
#if defined(IOUPT_SQ_WORKER) || defined(IOUPT_SQ_KTHREAD)
	int sq_tail = smp_load_acquire(&iou_pt->sq_tail);
	int sq_head = iou_pt->sq_head;
	struct virtblk_iouring_req *sq_req;

	if (CIRC_SPACE(sq_head, sq_tail, iou_pt->sq_reqs_size) == 0)
		return -EAGAIN;

	sq_req = &iou_pt->sq_reqs[sq_head];

	sq_req->vbr = vbr;
	sq_req->direction = direction;
	sq_req->type = type;
	sq_req->sg_num = sg_num;
	sq_req->offset = offset;

	smp_store_release(&iou_pt->sq_head,
			  (sq_head + 1) & (iou_pt->sq_reqs_size - 1));

#ifdef IOUPT_SQ_WORKER
	queue_work(virtblk_iouring_workqueue, &iou_pt->sq_work);
#endif
	return 0;
#else
	return virtblk_iouring_queue_req(iou_pt, vbr, direction, type,
					 sg_num, offset);
#endif /* defined(IOUPT_SQ_WORKER) || defined(IOUPT_SQ_KTHREAD) */

}

#endif /* _VIRTIO_BLK_IO_URING_PT_H */
