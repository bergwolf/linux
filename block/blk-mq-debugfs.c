// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2017 Facebook
 */

#include <linux/kernel.h>
#include <linux/blkdev.h>
#include <linux/build_bug.h>
#include <linux/debugfs.h>

#include "blk.h"
#include "blk-mq.h"
#include "blk-mq-debugfs.h"
#include "blk-mq-sched.h"
#include "blk-rq-qos.h"

static int queue_poll_stat_show(void *data, struct seq_file *m)
{
	return 0;
}

static void *queue_requeue_list_start(struct seq_file *m, loff_t *pos)
	__acquires(&q->requeue_lock)
{
	struct request_queue *q = m->private;

	spin_lock_irq(&q->requeue_lock);
	return seq_list_start(&q->requeue_list, *pos);
}

static void *queue_requeue_list_next(struct seq_file *m, void *v, loff_t *pos)
{
	struct request_queue *q = m->private;

	return seq_list_next(v, &q->requeue_list, pos);
}

static void queue_requeue_list_stop(struct seq_file *m, void *v)
	__releases(&q->requeue_lock)
{
	struct request_queue *q = m->private;

	spin_unlock_irq(&q->requeue_lock);
}

static const struct seq_operations queue_requeue_list_seq_ops = {
	.start	= queue_requeue_list_start,
	.next	= queue_requeue_list_next,
	.stop	= queue_requeue_list_stop,
	.show	= blk_mq_debugfs_rq_show,
};

static int blk_flags_show(struct seq_file *m, const unsigned long flags,
			  const char *const *flag_name, int flag_name_count)
{
	bool sep = false;
	int i;

	for (i = 0; i < sizeof(flags) * BITS_PER_BYTE; i++) {
		if (!(flags & BIT(i)))
			continue;
		if (sep)
			seq_puts(m, "|");
		sep = true;
		if (i < flag_name_count && flag_name[i])
			seq_puts(m, flag_name[i]);
		else
			seq_printf(m, "%d", i);
	}
	return 0;
}

static int queue_pm_only_show(void *data, struct seq_file *m)
{
	struct request_queue *q = data;

	seq_printf(m, "%d\n", atomic_read(&q->pm_only));
	return 0;
}

#define QUEUE_FLAG_NAME(name) [QUEUE_FLAG_##name] = #name
static const char *const blk_queue_flag_name[] = {
	QUEUE_FLAG_NAME(DYING),
	QUEUE_FLAG_NAME(NOMERGES),
	QUEUE_FLAG_NAME(SAME_COMP),
	QUEUE_FLAG_NAME(FAIL_IO),
	QUEUE_FLAG_NAME(NOXMERGES),
	QUEUE_FLAG_NAME(SAME_FORCE),
	QUEUE_FLAG_NAME(INIT_DONE),
	QUEUE_FLAG_NAME(STATS),
	QUEUE_FLAG_NAME(REGISTERED),
	QUEUE_FLAG_NAME(QUIESCED),
	QUEUE_FLAG_NAME(RQ_ALLOC_TIME),
	QUEUE_FLAG_NAME(HCTX_ACTIVE),
	QUEUE_FLAG_NAME(SQ_SCHED),
	QUEUE_FLAG_NAME(DISABLE_WBT_DEF),
	QUEUE_FLAG_NAME(NO_ELV_SWITCH),
};
#undef QUEUE_FLAG_NAME

static int queue_state_show(void *data, struct seq_file *m)
{
	struct request_queue *q = data;

	BUILD_BUG_ON(ARRAY_SIZE(blk_queue_flag_name) != QUEUE_FLAG_MAX);
	blk_flags_show(m, q->queue_flags, blk_queue_flag_name,
		       ARRAY_SIZE(blk_queue_flag_name));
	seq_puts(m, "\n");
	return 0;
}

static ssize_t queue_state_write(void *data, const char __user *buf,
				 size_t count, loff_t *ppos)
{
	struct request_queue *q = data;
	char opbuf[16] = { }, *op;

	/*
	 * The "state" attribute is removed when the queue is removed.  Don't
	 * allow setting the state on a dying queue to avoid a use-after-free.
	 */
	if (blk_queue_dying(q))
		return -ENOENT;

	if (count >= sizeof(opbuf)) {
		pr_err("%s: operation too long\n", __func__);
		goto inval;
	}

	if (copy_from_user(opbuf, buf, count))
		return -EFAULT;
	op = strstrip(opbuf);
	if (strcmp(op, "run") == 0) {
		blk_mq_run_hw_queues(q, true);
	} else if (strcmp(op, "start") == 0) {
		blk_mq_start_stopped_hw_queues(q, true);
	} else if (strcmp(op, "kick") == 0) {
		blk_mq_kick_requeue_list(q);
	} else {
		pr_err("%s: unsupported operation '%s'\n", __func__, op);
inval:
		pr_err("%s: use 'run', 'start' or 'kick'\n", __func__);
		return -EINVAL;
	}
	return count;
}

static const struct blk_mq_debugfs_attr blk_mq_debugfs_queue_attrs[] = {
	{ "poll_stat", 0400, queue_poll_stat_show },
	{ "requeue_list", 0400, .seq_ops = &queue_requeue_list_seq_ops },
	{ "pm_only", 0600, queue_pm_only_show, NULL },
	{ "state", 0600, queue_state_show, queue_state_write },
	{ "zone_wplugs", 0400, queue_zone_wplugs_show, NULL },
	{ },
};

#define HCTX_STATE_NAME(name) [BLK_MQ_S_##name] = #name
static const char *const hctx_state_name[] = {
	HCTX_STATE_NAME(STOPPED),
	HCTX_STATE_NAME(TAG_ACTIVE),
	HCTX_STATE_NAME(SCHED_RESTART),
	HCTX_STATE_NAME(INACTIVE),
};
#undef HCTX_STATE_NAME

static int hctx_state_show(void *data, struct seq_file *m)
{
	struct blk_mq_hw_ctx *hctx = data;

	BUILD_BUG_ON(ARRAY_SIZE(hctx_state_name) != BLK_MQ_S_MAX);
	blk_flags_show(m, hctx->state, hctx_state_name,
		       ARRAY_SIZE(hctx_state_name));
	seq_puts(m, "\n");
	return 0;
}

#define HCTX_FLAG_NAME(name) [ilog2(BLK_MQ_F_##name)] = #name
static const char *const hctx_flag_name[] = {
	HCTX_FLAG_NAME(TAG_QUEUE_SHARED),
	HCTX_FLAG_NAME(STACKING),
	HCTX_FLAG_NAME(TAG_HCTX_SHARED),
	HCTX_FLAG_NAME(BLOCKING),
	HCTX_FLAG_NAME(TAG_RR),
	HCTX_FLAG_NAME(NO_SCHED_BY_DEFAULT),
};
#undef HCTX_FLAG_NAME

static int hctx_flags_show(void *data, struct seq_file *m)
{
	struct blk_mq_hw_ctx *hctx = data;

	BUILD_BUG_ON(ARRAY_SIZE(hctx_flag_name) != ilog2(BLK_MQ_F_MAX));

	blk_flags_show(m, hctx->flags, hctx_flag_name,
			ARRAY_SIZE(hctx_flag_name));
	seq_puts(m, "\n");
	return 0;
}

#define CMD_FLAG_NAME(name) [__REQ_##name] = #name
static const char *const cmd_flag_name[] = {
	CMD_FLAG_NAME(FAILFAST_DEV),
	CMD_FLAG_NAME(FAILFAST_TRANSPORT),
	CMD_FLAG_NAME(FAILFAST_DRIVER),
	CMD_FLAG_NAME(SYNC),
	CMD_FLAG_NAME(META),
	CMD_FLAG_NAME(PRIO),
	CMD_FLAG_NAME(NOMERGE),
	CMD_FLAG_NAME(IDLE),
	CMD_FLAG_NAME(INTEGRITY),
	CMD_FLAG_NAME(FUA),
	CMD_FLAG_NAME(PREFLUSH),
	CMD_FLAG_NAME(RAHEAD),
	CMD_FLAG_NAME(BACKGROUND),
	CMD_FLAG_NAME(NOWAIT),
	CMD_FLAG_NAME(POLLED),
	CMD_FLAG_NAME(ALLOC_CACHE),
	CMD_FLAG_NAME(SWAP),
	CMD_FLAG_NAME(DRV),
	CMD_FLAG_NAME(FS_PRIVATE),
	CMD_FLAG_NAME(ATOMIC),
	CMD_FLAG_NAME(NOUNMAP),
};
#undef CMD_FLAG_NAME

#define RQF_NAME(name) [__RQF_##name] = #name
static const char *const rqf_name[] = {
	RQF_NAME(STARTED),
	RQF_NAME(FLUSH_SEQ),
	RQF_NAME(MIXED_MERGE),
	RQF_NAME(DONTPREP),
	RQF_NAME(SCHED_TAGS),
	RQF_NAME(USE_SCHED),
	RQF_NAME(FAILED),
	RQF_NAME(QUIET),
	RQF_NAME(IO_STAT),
	RQF_NAME(PM),
	RQF_NAME(HASHED),
	RQF_NAME(STATS),
	RQF_NAME(SPECIAL_PAYLOAD),
	RQF_NAME(ZONE_WRITE_PLUGGING),
	RQF_NAME(TIMED_OUT),
	RQF_NAME(RESV),
};
#undef RQF_NAME

static const char *const blk_mq_rq_state_name_array[] = {
	[MQ_RQ_IDLE]		= "idle",
	[MQ_RQ_IN_FLIGHT]	= "in_flight",
	[MQ_RQ_COMPLETE]	= "complete",
};

static const char *blk_mq_rq_state_name(enum mq_rq_state rq_state)
{
	if (WARN_ON_ONCE((unsigned int)rq_state >=
			 ARRAY_SIZE(blk_mq_rq_state_name_array)))
		return "(?)";
	return blk_mq_rq_state_name_array[rq_state];
}

int __blk_mq_debugfs_rq_show(struct seq_file *m, struct request *rq)
{
	const struct blk_mq_ops *const mq_ops = rq->q->mq_ops;
	const enum req_op op = req_op(rq);
	const char *op_str = blk_op_str(op);

	BUILD_BUG_ON(ARRAY_SIZE(cmd_flag_name) != __REQ_NR_BITS);
	BUILD_BUG_ON(ARRAY_SIZE(rqf_name) != __RQF_BITS);

	seq_printf(m, "%p {.op=", rq);
	if (strcmp(op_str, "UNKNOWN") == 0)
		seq_printf(m, "%u", op);
	else
		seq_printf(m, "%s", op_str);
	seq_puts(m, ", .cmd_flags=");
	blk_flags_show(m, (__force unsigned int)(rq->cmd_flags & ~REQ_OP_MASK),
		       cmd_flag_name, ARRAY_SIZE(cmd_flag_name));
	seq_puts(m, ", .rq_flags=");
	blk_flags_show(m, (__force unsigned int)rq->rq_flags, rqf_name,
		       ARRAY_SIZE(rqf_name));
	seq_printf(m, ", .state=%s", blk_mq_rq_state_name(blk_mq_rq_state(rq)));
	seq_printf(m, ", .tag=%d, .internal_tag=%d", rq->tag,
		   rq->internal_tag);
	if (mq_ops->show_rq)
		mq_ops->show_rq(m, rq);
	seq_puts(m, "}\n");
	return 0;
}
EXPORT_SYMBOL_GPL(__blk_mq_debugfs_rq_show);

int blk_mq_debugfs_rq_show(struct seq_file *m, void *v)
{
	return __blk_mq_debugfs_rq_show(m, list_entry_rq(v));
}
EXPORT_SYMBOL_GPL(blk_mq_debugfs_rq_show);

static void *hctx_dispatch_start(struct seq_file *m, loff_t *pos)
	__acquires(&hctx->lock)
{
	struct blk_mq_hw_ctx *hctx = m->private;

	spin_lock(&hctx->lock);
	return seq_list_start(&hctx->dispatch, *pos);
}

static void *hctx_dispatch_next(struct seq_file *m, void *v, loff_t *pos)
{
	struct blk_mq_hw_ctx *hctx = m->private;

	return seq_list_next(v, &hctx->dispatch, pos);
}

static void hctx_dispatch_stop(struct seq_file *m, void *v)
	__releases(&hctx->lock)
{
	struct blk_mq_hw_ctx *hctx = m->private;

	spin_unlock(&hctx->lock);
}

static const struct seq_operations hctx_dispatch_seq_ops = {
	.start	= hctx_dispatch_start,
	.next	= hctx_dispatch_next,
	.stop	= hctx_dispatch_stop,
	.show	= blk_mq_debugfs_rq_show,
};

struct show_busy_params {
	struct seq_file		*m;
	struct blk_mq_hw_ctx	*hctx;
};

/*
 * Note: the state of a request may change while this function is in progress,
 * e.g. due to a concurrent blk_mq_finish_request() call. Returns true to
 * keep iterating requests.
 */
static bool hctx_show_busy_rq(struct request *rq, void *data)
{
	const struct show_busy_params *params = data;

	if (rq->mq_hctx == params->hctx)
		__blk_mq_debugfs_rq_show(params->m, rq);

	return true;
}

static int hctx_busy_show(void *data, struct seq_file *m)
{
	struct blk_mq_hw_ctx *hctx = data;
	struct show_busy_params params = { .m = m, .hctx = hctx };
	int res;

	res = mutex_lock_interruptible(&hctx->queue->elevator_lock);
	if (res)
		return res;
	blk_mq_tagset_busy_iter(hctx->queue->tag_set, hctx_show_busy_rq,
				&params);
	mutex_unlock(&hctx->queue->elevator_lock);

	return 0;
}

static const char *const hctx_types[] = {
	[HCTX_TYPE_DEFAULT]	= "default",
	[HCTX_TYPE_READ]	= "read",
	[HCTX_TYPE_POLL]	= "poll",
};

static int hctx_type_show(void *data, struct seq_file *m)
{
	struct blk_mq_hw_ctx *hctx = data;

	BUILD_BUG_ON(ARRAY_SIZE(hctx_types) != HCTX_MAX_TYPES);
	seq_printf(m, "%s\n", hctx_types[hctx->type]);
	return 0;
}

static int hctx_ctx_map_show(void *data, struct seq_file *m)
{
	struct blk_mq_hw_ctx *hctx = data;

	sbitmap_bitmap_show(&hctx->ctx_map, m);
	return 0;
}

static void blk_mq_debugfs_tags_show(struct seq_file *m,
				     struct blk_mq_tags *tags)
{
	seq_printf(m, "nr_tags=%u\n", tags->nr_tags);
	seq_printf(m, "nr_reserved_tags=%u\n", tags->nr_reserved_tags);
	seq_printf(m, "active_queues=%d\n",
		   READ_ONCE(tags->active_queues));

	seq_puts(m, "\nbitmap_tags:\n");
	sbitmap_queue_show(&tags->bitmap_tags, m);

	if (tags->nr_reserved_tags) {
		seq_puts(m, "\nbreserved_tags:\n");
		sbitmap_queue_show(&tags->breserved_tags, m);
	}
}

static int hctx_tags_show(void *data, struct seq_file *m)
{
	struct blk_mq_hw_ctx *hctx = data;
	struct request_queue *q = hctx->queue;
	int res;

	res = mutex_lock_interruptible(&q->elevator_lock);
	if (res)
		return res;
	if (hctx->tags)
		blk_mq_debugfs_tags_show(m, hctx->tags);
	mutex_unlock(&q->elevator_lock);

	return 0;
}

static int hctx_tags_bitmap_show(void *data, struct seq_file *m)
{
	struct blk_mq_hw_ctx *hctx = data;
	struct request_queue *q = hctx->queue;
	int res;

	res = mutex_lock_interruptible(&q->elevator_lock);
	if (res)
		return res;
	if (hctx->tags)
		sbitmap_bitmap_show(&hctx->tags->bitmap_tags.sb, m);
	mutex_unlock(&q->elevator_lock);

	return 0;
}

static int hctx_sched_tags_show(void *data, struct seq_file *m)
{
	struct blk_mq_hw_ctx *hctx = data;
	struct request_queue *q = hctx->queue;
	int res;

	res = mutex_lock_interruptible(&q->elevator_lock);
	if (res)
		return res;
	if (hctx->sched_tags)
		blk_mq_debugfs_tags_show(m, hctx->sched_tags);
	mutex_unlock(&q->elevator_lock);

	return 0;
}

static int hctx_sched_tags_bitmap_show(void *data, struct seq_file *m)
{
	struct blk_mq_hw_ctx *hctx = data;
	struct request_queue *q = hctx->queue;
	int res;

	res = mutex_lock_interruptible(&q->elevator_lock);
	if (res)
		return res;
	if (hctx->sched_tags)
		sbitmap_bitmap_show(&hctx->sched_tags->bitmap_tags.sb, m);
	mutex_unlock(&q->elevator_lock);

	return 0;
}

static int hctx_active_show(void *data, struct seq_file *m)
{
	struct blk_mq_hw_ctx *hctx = data;

	seq_printf(m, "%d\n", __blk_mq_active_requests(hctx));
	return 0;
}

static int hctx_dispatch_busy_show(void *data, struct seq_file *m)
{
	struct blk_mq_hw_ctx *hctx = data;

	seq_printf(m, "%u\n", hctx->dispatch_busy);
	return 0;
}

#define CTX_RQ_SEQ_OPS(name, type)					\
static void *ctx_##name##_rq_list_start(struct seq_file *m, loff_t *pos) \
	__acquires(&ctx->lock)						\
{									\
	struct blk_mq_ctx *ctx = m->private;				\
									\
	spin_lock(&ctx->lock);						\
	return seq_list_start(&ctx->rq_lists[type], *pos);		\
}									\
									\
static void *ctx_##name##_rq_list_next(struct seq_file *m, void *v,	\
				     loff_t *pos)			\
{									\
	struct blk_mq_ctx *ctx = m->private;				\
									\
	return seq_list_next(v, &ctx->rq_lists[type], pos);		\
}									\
									\
static void ctx_##name##_rq_list_stop(struct seq_file *m, void *v)	\
	__releases(&ctx->lock)						\
{									\
	struct blk_mq_ctx *ctx = m->private;				\
									\
	spin_unlock(&ctx->lock);					\
}									\
									\
static const struct seq_operations ctx_##name##_rq_list_seq_ops = {	\
	.start	= ctx_##name##_rq_list_start,				\
	.next	= ctx_##name##_rq_list_next,				\
	.stop	= ctx_##name##_rq_list_stop,				\
	.show	= blk_mq_debugfs_rq_show,				\
}

CTX_RQ_SEQ_OPS(default, HCTX_TYPE_DEFAULT);
CTX_RQ_SEQ_OPS(read, HCTX_TYPE_READ);
CTX_RQ_SEQ_OPS(poll, HCTX_TYPE_POLL);

static int blk_mq_debugfs_show(struct seq_file *m, void *v)
{
	const struct blk_mq_debugfs_attr *attr = m->private;
	void *data = debugfs_get_aux(m->file);

	return attr->show(data, m);
}

static ssize_t blk_mq_debugfs_write(struct file *file, const char __user *buf,
				    size_t count, loff_t *ppos)
{
	struct seq_file *m = file->private_data;
	const struct blk_mq_debugfs_attr *attr = m->private;
	void *data = debugfs_get_aux(file);

	/*
	 * Attributes that only implement .seq_ops are read-only and 'attr' is
	 * the same with 'data' in this case.
	 */
	if (attr == data || !attr->write)
		return -EPERM;

	return attr->write(data, buf, count, ppos);
}

static int blk_mq_debugfs_open(struct inode *inode, struct file *file)
{
	const struct blk_mq_debugfs_attr *attr = inode->i_private;
	void *data = debugfs_get_aux(file);
	struct seq_file *m;
	int ret;

	if (attr->seq_ops) {
		ret = seq_open(file, attr->seq_ops);
		if (!ret) {
			m = file->private_data;
			m->private = data;
		}
		return ret;
	}

	if (WARN_ON_ONCE(!attr->show))
		return -EPERM;

	return single_open(file, blk_mq_debugfs_show, inode->i_private);
}

static int blk_mq_debugfs_release(struct inode *inode, struct file *file)
{
	const struct blk_mq_debugfs_attr *attr = inode->i_private;

	if (attr->show)
		return single_release(inode, file);

	return seq_release(inode, file);
}

static const struct file_operations blk_mq_debugfs_fops = {
	.open		= blk_mq_debugfs_open,
	.read		= seq_read,
	.write		= blk_mq_debugfs_write,
	.llseek		= seq_lseek,
	.release	= blk_mq_debugfs_release,
};

static const struct blk_mq_debugfs_attr blk_mq_debugfs_hctx_attrs[] = {
	{"state", 0400, hctx_state_show},
	{"flags", 0400, hctx_flags_show},
	{"dispatch", 0400, .seq_ops = &hctx_dispatch_seq_ops},
	{"busy", 0400, hctx_busy_show},
	{"ctx_map", 0400, hctx_ctx_map_show},
	{"tags", 0400, hctx_tags_show},
	{"tags_bitmap", 0400, hctx_tags_bitmap_show},
	{"sched_tags", 0400, hctx_sched_tags_show},
	{"sched_tags_bitmap", 0400, hctx_sched_tags_bitmap_show},
	{"active", 0400, hctx_active_show},
	{"dispatch_busy", 0400, hctx_dispatch_busy_show},
	{"type", 0400, hctx_type_show},
	{},
};

static const struct blk_mq_debugfs_attr blk_mq_debugfs_ctx_attrs[] = {
	{"default_rq_list", 0400, .seq_ops = &ctx_default_rq_list_seq_ops},
	{"read_rq_list", 0400, .seq_ops = &ctx_read_rq_list_seq_ops},
	{"poll_rq_list", 0400, .seq_ops = &ctx_poll_rq_list_seq_ops},
	{},
};

static void debugfs_create_files(struct dentry *parent, void *data,
				 const struct blk_mq_debugfs_attr *attr)
{
	if (IS_ERR_OR_NULL(parent))
		return;

	for (; attr->name; attr++)
		debugfs_create_file_aux(attr->name, attr->mode, parent,
				    (void *)attr, data, &blk_mq_debugfs_fops);
}

void blk_mq_debugfs_register(struct request_queue *q)
{
	struct blk_mq_hw_ctx *hctx;
	unsigned long i;

	debugfs_create_files(q->debugfs_dir, q, blk_mq_debugfs_queue_attrs);

	queue_for_each_hw_ctx(q, hctx, i) {
		if (!hctx->debugfs_dir)
			blk_mq_debugfs_register_hctx(q, hctx);
	}

	if (q->rq_qos) {
		struct rq_qos *rqos = q->rq_qos;

		while (rqos) {
			blk_mq_debugfs_register_rqos(rqos);
			rqos = rqos->next;
		}
	}
}

static void blk_mq_debugfs_register_ctx(struct blk_mq_hw_ctx *hctx,
					struct blk_mq_ctx *ctx)
{
	struct dentry *ctx_dir;
	char name[20];

	snprintf(name, sizeof(name), "cpu%u", ctx->cpu);
	ctx_dir = debugfs_create_dir(name, hctx->debugfs_dir);

	debugfs_create_files(ctx_dir, ctx, blk_mq_debugfs_ctx_attrs);
}

void blk_mq_debugfs_register_hctx(struct request_queue *q,
				  struct blk_mq_hw_ctx *hctx)
{
	struct blk_mq_ctx *ctx;
	char name[20];
	int i;

	if (!q->debugfs_dir)
		return;

	snprintf(name, sizeof(name), "hctx%u", hctx->queue_num);
	hctx->debugfs_dir = debugfs_create_dir(name, q->debugfs_dir);

	debugfs_create_files(hctx->debugfs_dir, hctx, blk_mq_debugfs_hctx_attrs);

	hctx_for_each_ctx(hctx, ctx, i)
		blk_mq_debugfs_register_ctx(hctx, ctx);
}

void blk_mq_debugfs_unregister_hctx(struct blk_mq_hw_ctx *hctx)
{
	if (!hctx->queue->debugfs_dir)
		return;
	debugfs_remove_recursive(hctx->debugfs_dir);
	hctx->sched_debugfs_dir = NULL;
	hctx->debugfs_dir = NULL;
}

void blk_mq_debugfs_register_hctxs(struct request_queue *q)
{
	struct blk_mq_hw_ctx *hctx;
	unsigned long i;

	queue_for_each_hw_ctx(q, hctx, i)
		blk_mq_debugfs_register_hctx(q, hctx);
}

void blk_mq_debugfs_unregister_hctxs(struct request_queue *q)
{
	struct blk_mq_hw_ctx *hctx;
	unsigned long i;

	queue_for_each_hw_ctx(q, hctx, i)
		blk_mq_debugfs_unregister_hctx(hctx);
}

void blk_mq_debugfs_register_sched(struct request_queue *q)
{
	struct elevator_type *e = q->elevator->type;

	lockdep_assert_held(&q->debugfs_mutex);

	/*
	 * If the parent directory has not been created yet, return, we will be
	 * called again later on and the directory/files will be created then.
	 */
	if (!q->debugfs_dir)
		return;

	if (!e->queue_debugfs_attrs)
		return;

	q->sched_debugfs_dir = debugfs_create_dir("sched", q->debugfs_dir);

	debugfs_create_files(q->sched_debugfs_dir, q, e->queue_debugfs_attrs);
}

void blk_mq_debugfs_unregister_sched(struct request_queue *q)
{
	lockdep_assert_held(&q->debugfs_mutex);

	debugfs_remove_recursive(q->sched_debugfs_dir);
	q->sched_debugfs_dir = NULL;
}

static const char *rq_qos_id_to_name(enum rq_qos_id id)
{
	switch (id) {
	case RQ_QOS_WBT:
		return "wbt";
	case RQ_QOS_LATENCY:
		return "latency";
	case RQ_QOS_COST:
		return "cost";
	}
	return "unknown";
}

void blk_mq_debugfs_unregister_rqos(struct rq_qos *rqos)
{
	lockdep_assert_held(&rqos->disk->queue->debugfs_mutex);

	if (!rqos->disk->queue->debugfs_dir)
		return;
	debugfs_remove_recursive(rqos->debugfs_dir);
	rqos->debugfs_dir = NULL;
}

void blk_mq_debugfs_register_rqos(struct rq_qos *rqos)
{
	struct request_queue *q = rqos->disk->queue;
	const char *dir_name = rq_qos_id_to_name(rqos->id);

	lockdep_assert_held(&q->debugfs_mutex);

	if (rqos->debugfs_dir || !rqos->ops->debugfs_attrs)
		return;

	if (!q->rqos_debugfs_dir)
		q->rqos_debugfs_dir = debugfs_create_dir("rqos",
							 q->debugfs_dir);

	rqos->debugfs_dir = debugfs_create_dir(dir_name, q->rqos_debugfs_dir);
	debugfs_create_files(rqos->debugfs_dir, rqos, rqos->ops->debugfs_attrs);
}

void blk_mq_debugfs_register_sched_hctx(struct request_queue *q,
					struct blk_mq_hw_ctx *hctx)
{
	struct elevator_type *e = q->elevator->type;

	lockdep_assert_held(&q->debugfs_mutex);

	/*
	 * If the parent debugfs directory has not been created yet, return;
	 * We will be called again later on with appropriate parent debugfs
	 * directory from blk_register_queue()
	 */
	if (!hctx->debugfs_dir)
		return;

	if (!e->hctx_debugfs_attrs)
		return;

	hctx->sched_debugfs_dir = debugfs_create_dir("sched",
						     hctx->debugfs_dir);
	debugfs_create_files(hctx->sched_debugfs_dir, hctx,
			     e->hctx_debugfs_attrs);
}

void blk_mq_debugfs_unregister_sched_hctx(struct blk_mq_hw_ctx *hctx)
{
	lockdep_assert_held(&hctx->queue->debugfs_mutex);

	if (!hctx->queue->debugfs_dir)
		return;
	debugfs_remove_recursive(hctx->sched_debugfs_dir);
	hctx->sched_debugfs_dir = NULL;
}
