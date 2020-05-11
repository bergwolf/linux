#ifndef _VIRTIO_BLK_IO_URING_PT_H
#define _VIRTIO_BLK_IO_URING_PT_H

#define VIRTIO_BLK_F_IO_URING   15
#define VIRTIO_BLK_F_KTHREAD    16

struct io_uring_pt;

int virtblk_iouring_init(struct virtio_blk *vblk);
void virtblk_iouring_fini(struct virtio_blk *vblk);
int virtblk_iouring_cq_poll(struct io_uring_pt *iou_pt);
void virtblk_iouring_commit_rqs(struct io_uring_pt *iou_pt);
blk_status_t virtblk_iouring_queue_rq(struct virtio_blk *vblk,
				      struct virtblk_req *vbr,
				      struct request *req,
				      struct blk_mq_hw_ctx *hctx);

#endif /* _VIRTIO_BLK_IO_URING_PT_H */
