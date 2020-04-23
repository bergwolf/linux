#ifndef _VIRTIO_BLK_IO_URING_PT_H
#define _VIRTIO_BLK_IO_URING_PT_H

#define VIRTIO_BLK_F_IO_URING   15
#define VIRTIO_BLK_F_KTHREAD    16

struct io_uring_pt;

int virtblk_iouring_init(struct virtio_blk *vblk);
void virtblk_iouring_fini(struct virtio_blk *vblk);
bool virtblk_iouring_cq_poll(struct io_uring_pt *iou_pt);
void virtblk_iouring_commit_rqs(struct io_uring_pt *iou_pt);
int virtblk_iouring_add_req(struct io_uring_pt *iou_pt,
		struct virtblk_req *vbr, int direction, uint32_t type,
		unsigned int sg_num, uint64_t offset);

#endif /* _VIRTIO_BLK_IO_URING_PT_H */
