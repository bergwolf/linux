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
	nodemask_t		active_nodes;
};

int list_lru_init(struct list_lru *lru);
int list_lru_add(struct list_lru *lru, struct list_head *item);
int list_lru_del(struct list_lru *lru, struct list_head *item);
unsigned long list_lru_count(struct list_lru *lru);

typedef enum lru_status
(*list_lru_walk_cb)(struct list_head *item, spinlock_t *lock, void *cb_arg);

typedef void (*list_lru_dispose_cb)(struct list_head *dispose_list);

unsigned long list_lru_walk(struct list_lru *lru, list_lru_walk_cb isolate,
		   void *cb_arg, unsigned long nr_to_walk);

unsigned long
list_lru_dispose_all(struct list_lru *lru, list_lru_dispose_cb dispose);

#endif /* _LRU_LIST_H */
