#ifndef _VIRTIO_BLK_COMMON_H
#define _VIRTIO_BLK_COMMON_H

#include <linux/uio.h>

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
	/*
	 * This mutex must be held by anything that may run after
	 * virtblk_remove() sets vblk->vdev to NULL.
	 *
	 * blk-mq, virtqueue processing, and sysfs attribute code paths are
	 * shut down before vblk->vdev is set to NULL and therefore do not need
	 * to hold this mutex.
	 */
	struct mutex vdev_mutex;
	struct virtio_device *vdev;

	/* The disk structure for the kernel. */
	struct gendisk *disk;

	/* Block layer tags. */
	struct blk_mq_tag_set tag_set;

	/* Process context for config space updates */
	struct work_struct config_work;

	/*
	 * Tracks references from block_device_operations open/release and
	 * virtio_driver probe/remove so this object can be freed once no
	 * longer in use.
	 */
	refcount_t refs;

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
