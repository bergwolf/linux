#ifndef _LINUX_SHRINKER_H
#define _LINUX_SHRINKER_H

/*
 * This struct is used to pass information from page reclaim to the shrinkers.
 * We consolidate the values for easier extention later.
 *
 * The 'gfpmask' refers to the allocation we are currently trying to
 * fulfil.
 */
struct shrink_control {
	gfp_t gfp_mask;

	/*
	 * How many objects scan_objects should scan and try to reclaim.
	 * This is reset before every call, so it is safe for callees
	 * to modify.
	 */
	long nr_to_scan;

	/* shrink from these nodes */
	nodemask_t nodes_to_scan;
	/* current node being shrunk (for NUMA aware shrinkers) */
	int nid;

	/* reclaim from this memcg only (if not NULL) */
	struct mem_cgroup *target_mem_cgroup;
};

/*
 * A callback you can register to apply pressure to ageable caches.
 *
 * @count_objects should return the number of freeable items in the cache. If
 * there are no objects to free or the number of freeable items cannot be
 * determined, it should return 0. No deadlock checks should be done during the
 * count callback - the shrinker relies on aggregating scan counts that couldn't
 * be executed due to potential deadlocks to be run at a later call when the
 * deadlock condition is no longer pending.
 *
 * @scan_objects will only be called if @count_objects returned a positive
 * value for the number of freeable objects. The callout should scan the cache
 * and attempt to free items from the cache. It should then return the number of
 * objects freed during the scan, or -1 if progress cannot be made due to
 * potential deadlocks. If -1 is returned, then no further attempts to call the
 * @scan_objects will be made from the current reclaim context.
 *
 * @flags determine the shrinker abilities, like numa awareness 
 */
struct shrinker {
	long (*count_objects)(struct shrinker *, struct shrink_control *sc);
	long (*scan_objects)(struct shrinker *, struct shrink_control *sc);

	int seeks;	/* seeks to recreate an obj */
	long batch;	/* reclaim batch size, 0 = default */
	unsigned long flags;

	/* These are for internal use */
	struct list_head list;
	/*
	 * We would like to avoid allocating memory when registering a new
	 * shrinker. All shrinkers will need to keep track of deferred objects,
	 * and we need a counter for this. If the shrinkers are not NUMA aware,
	 * this is a small and bounded space that fits into an atomic_long_t.
	 * This is because that the deferring decisions are global, and we will
	 * not allocate in this case.
	 *
	 * When the shrinker is NUMA aware, we will need this to be a per-node
	 * array. Numerically speaking, the minority of shrinkers are NUMA
	 * aware, so this saves quite a bit.
	 */
	union {
		/* objs pending delete */
		atomic_long_t nr_deferred;
		/* objs pending delete, per node */
		atomic_long_t *nr_deferred_node;
	};
};
#define DEFAULT_SEEKS 2 /* A good number if you don't know better. */

/* Flags */
#define SHRINKER_NUMA_AWARE	(1 << 0)
#define SHRINKER_MEMCG_AWARE	(1 << 1)

extern int register_shrinker(struct shrinker *);
extern void unregister_shrinker(struct shrinker *);
#endif
