/*
 * Copyright (c) 2010-2012 Red Hat, Inc. All rights reserved.
 * Author: David Chinner
 *
 * Generic LRU infrastructure
 */
#ifndef _LRU_LIST_H
#define _LRU_LIST_H

#include <linux/list.h>

enum lru_status {
	LRU_REMOVED,		/* item removed from list */
	LRU_ROTATE,		/* item referenced, give another pass */
	LRU_SKIP,		/* item cannot be locked, skip */
	LRU_RETRY,		/* item not freeable. May drop the lock
				   internally, but has to return locked. */
};

struct list_lru {
	spinlock_t		lock;
	struct list_head	list;
	long			nr_items;
};

int list_lru_init(struct list_lru *lru);
int list_lru_add(struct list_lru *lru, struct list_head *item);
int list_lru_del(struct list_lru *lru, struct list_head *item);

static inline unsigned long list_lru_count(struct list_lru *lru)
{
	return lru->nr_items;
}

typedef enum lru_status
(*list_lru_walk_cb)(struct list_head *item, spinlock_t *lock, void *cb_arg);

typedef void (*list_lru_dispose_cb)(struct list_head *dispose_list);

unsigned long list_lru_walk(struct list_lru *lru, list_lru_walk_cb isolate,
		   void *cb_arg, unsigned long nr_to_walk);

unsigned long
list_lru_dispose_all(struct list_lru *lru, list_lru_dispose_cb dispose);

#endif /* _LRU_LIST_H */
