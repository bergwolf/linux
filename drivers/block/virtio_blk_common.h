#ifndef _VIRTIO_BLK_COMMON_H
#define _VIRTIO_BLK_COMMON_H

#define VIRTIO_BLK_IOURING

#ifdef VIRTIO_BLK_IOURING
struct virtblk_req;
struct virtio_blk;
#include "io_uring_pt/virtio_blk_io_uring_pt.h"
#endif /* VIRTIO_BLK_IOURING */

#define VQ_NAME_LEN 16

struct virtblk_req {
	struct virtio_blk_outhdr out_hdr;
	u8 status;
#ifdef VIRTIO_BLK_IOURING
	struct iovec *vec;
	u8 sub_requests;
#endif /* VIRTIO_BLK_IOURING */
	struct scatterlist sg[];
};

struct virtio_blk_vq {
	struct virtqueue *vq;
	spinlock_t lock;
	char name[VQ_NAME_LEN];
} ____cacheline_aligned_in_smp;

struct virtio_blk {
	struct virtio_device *vdev;

	/* The disk structure for the kernel. */
	struct gendisk *disk;

	/* Block layer tags. */
	struct blk_mq_tag_set tag_set;

	/* Process context for config space updates */
	struct work_struct config_work;

	/* What host tells us, plus 2 for header & tailer. */
	unsigned int sg_elems;

	/* Ida index - used to track minor number allocations. */
	int index;

	/* num of vqs */
	int num_vqs;
	struct virtio_blk_vq *vqs;

#ifdef VIRTIO_BLK_IOURING
	struct io_uring_pt *iou_pt;
	struct task_struct *kthread;
#endif /* VIRTIO_BLK_IOURING */
};

#endif /* _VIRTIO_BLK_COMMON_H */
