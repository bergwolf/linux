/*
 * Copyright (c) 2010-2012 Red Hat, Inc. All rights reserved.
 * Author: David Chinner
 *
 * Generic LRU infrastructure
 */
#ifndef _LRU_LIST_H
#define _LRU_LIST_H

#include <linux/list.h>
#include <linux/nodemask.h>

enum lru_status {
	LRU_REMOVED,		/* item removed from list */
	LRU_ROTATE,		/* item referenced, give another pass */
	LRU_SKIP,		/* item cannot be locked, skip */
	LRU_RETRY,		/* item not freeable. May drop the lock
				   internally, but has to return locked. */
};

struct list_lru_node {
	spinlock_t		lock;
	struct list_head	list;
	long			nr_items;
} ____cacheline_aligned_in_smp;

/*
 * This is supposed to be M x N matrix, where M is kmem-limited memcg, and N is
 * the number of nodes. Both dimensions are likely to be very small, but are
 * potentially very big. Therefore we will allocate or grow them dynamically.
 *
 * The size of M will increase as new memcgs appear and can be 0 if no memcgs
 * are being used. This is done in mm/memcontrol.c in a way quite similar than
 * the way we use for the slab cache management.
 *
 * The size o N can't be determined at compile time, but won't increase once we
 * determine it. It is nr_node_ids, the firmware-provided maximum number of
 * nodes in a system.
 */
struct list_lru_array {
	struct list_lru_node node[1];
};

struct list_lru {
	/*
	 * Because we use a fixed-size array, this struct can be very big if
	 * MAX_NUMNODES is big. If this becomes a problem this is fixable by
	 * turning this into a pointer and dynamically allocating this to
	 * nr_node_ids. This quantity is firwmare-provided, and still would
	 * provide room for all nodes at the cost of a pointer lookup and an
	 * extra allocation. Because that allocation will most likely come from
	 * a different slab cache than the main structure holding this
	 * structure, we may very well fail.
	 */
	struct list_lru_node	node[MAX_NUMNODES];
	atomic_long_t		node_totals[MAX_NUMNODES];
	nodemask_t		active_nodes;
#ifdef CONFIG_MEMCG_KMEM
	/* All memcg-aware LRUs will be chained in the lrus list */
	struct list_head	lrus;
	/* M x N matrix as described above */
	struct list_lru_array	**memcg_lrus;
	/*
	 * The memcg_lrus is RCU protected, so we need to keep the previous
	 * array around when we update it. But we can only do that after
	 * synchronize_rcu(). A typical system has many LRUs, which means
	 * that if we call synchronize_rcu after each LRU update, this
	 * will become very expensive. We add this pointer here, and then
	 * after all LRUs are update, we call synchronize_rcu() once, and
	 * free all the old_arrays.
	 */
	void *old_array;
#endif
};

struct mem_cgroup;
#ifdef CONFIG_MEMCG_KMEM
struct list_lru_array *lru_alloc_array(void);
int memcg_update_all_lrus(unsigned long num);
void memcg_destroy_all_lrus(struct mem_cgroup *memcg);
void list_lru_destroy(struct list_lru *lru);
int __memcg_init_lru(struct list_lru *lru);
#else
static inline void list_lru_destroy(struct list_lru *lru)
{
}
#endif

int __list_lru_init(struct list_lru *lru, bool memcg_enabled);
static inline int list_lru_init(struct list_lru *lru)
{
	return __list_lru_init(lru, false);
}

static inline int list_lru_init_memcg(struct list_lru *lru)
{
	return __list_lru_init(lru, true);
}

int list_lru_add(struct list_lru *lru, struct list_head *item);
int list_lru_del(struct list_lru *lru, struct list_head *item);

unsigned long list_lru_count_node_memcg(struct list_lru *lru, int nid,
					struct mem_cgroup *memcg);

static inline unsigned long
list_lru_count_node(struct list_lru *lru, int nid)
{
	return list_lru_count_node_memcg(lru, nid, NULL);
}

static inline unsigned long list_lru_count(struct list_lru *lru)
{
	long count = 0;
	int nid;

	for_each_node_mask(nid, lru->active_nodes)
		count += list_lru_count_node(lru, nid);

	return count;
}

typedef enum lru_status
(*list_lru_walk_cb)(struct list_head *item, spinlock_t *lock, void *cb_arg);

typedef void (*list_lru_dispose_cb)(struct list_head *dispose_list);


unsigned long
list_lru_walk_node_memcg(struct list_lru *lru, int nid,
			 list_lru_walk_cb isolate, void *cb_arg,
			 unsigned long *nr_to_walk, struct mem_cgroup *memcg);

static inline unsigned long
list_lru_walk_node(struct list_lru *lru, int nid,
		 list_lru_walk_cb isolate, void *cb_arg,
		 unsigned long *nr_to_walk)
{
	return list_lru_walk_node_memcg(lru, nid, isolate, cb_arg,
					nr_to_walk, NULL);
}

static inline unsigned long
list_lru_walk(struct list_lru *lru, list_lru_walk_cb isolate,
	      void *cb_arg, unsigned long nr_to_walk)
{
	long isolated = 0;
	int nid;

	for_each_node_mask(nid, lru->active_nodes) {
		isolated += list_lru_walk_node(lru, nid, isolate,
					       cb_arg, &nr_to_walk);
		if (nr_to_walk <= 0)
			break;
	}
	return isolated;
}

unsigned long
list_lru_dispose_all(struct list_lru *lru, list_lru_dispose_cb dispose);

#endif /* _LRU_LIST_H */
