/*
 * Copyright (c) 2010-2012 Red Hat, Inc. All rights reserved.
 * Author: David Chinner
 *
 * Memcg Awareness
 * Copyright (C) 2013 Parallels Inc.
 * Author: Glauber Costa
 *
 * Generic LRU infrastructure
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/list_lru.h>
#include <linux/memcontrol.h>

int
list_lru_add(
	struct list_lru	*lru,
	struct list_head *item)
{
	int nid = page_to_nid(virt_to_page(item));
	struct list_lru_node *nlru = &lru->node[nid];

	spin_lock(&nlru->lock);
	BUG_ON(nlru->nr_items < 0);
	if (list_empty(item)) {
		list_add_tail(item, &nlru->list);
		if (nlru->nr_items++ == 0)
			node_set(nid, lru->active_nodes);
		spin_unlock(&nlru->lock);
		return 1;
	}
	spin_unlock(&nlru->lock);
	return 0;
}
EXPORT_SYMBOL_GPL(list_lru_add);

int
list_lru_del(
	struct list_lru	*lru,
	struct list_head *item)
{
	int nid = page_to_nid(virt_to_page(item));
	struct list_lru_node *nlru = &lru->node[nid];

	spin_lock(&nlru->lock);
	if (!list_empty(item)) {
		list_del_init(item);
		if (--nlru->nr_items == 0)
			node_clear(nid, lru->active_nodes);
		BUG_ON(nlru->nr_items < 0);
		spin_unlock(&nlru->lock);
		return 1;
	}
	spin_unlock(&nlru->lock);
	return 0;
}
EXPORT_SYMBOL_GPL(list_lru_del);

unsigned long
list_lru_count_node(struct list_lru *lru, int nid)
{
	long count = 0;
	struct list_lru_node *nlru = &lru->node[nid];

	spin_lock(&nlru->lock);
	BUG_ON(nlru->nr_items < 0);
	count += nlru->nr_items;
	spin_unlock(&nlru->lock);

	return count;
}
EXPORT_SYMBOL_GPL(list_lru_count_node);

unsigned long
list_lru_walk_node(
	struct list_lru		*lru,
	int			nid,
	list_lru_walk_cb	isolate,
	void			*cb_arg,
	unsigned long		*nr_to_walk)
{
	struct list_lru_node	*nlru = &lru->node[nid];
	struct list_head *item, *n;
	unsigned long isolated = 0;

	spin_lock(&nlru->lock);
	list_for_each_safe(item, n, &nlru->list) {
		enum lru_status ret;
		bool first_pass = true;
restart:
		ret = isolate(item, &nlru->lock, cb_arg);
		switch (ret) {
		case LRU_REMOVED:
			if (--nlru->nr_items == 0)
				node_clear(nid, lru->active_nodes);
			BUG_ON(nlru->nr_items < 0);
			isolated++;
			break;
		case LRU_ROTATE:
			list_move_tail(item, &nlru->list);
			break;
		case LRU_SKIP:
			break;
		case LRU_RETRY:
			if (!first_pass)
				break;
			first_pass = false;
			goto restart;
		default:
			BUG();
		}

		if ((*nr_to_walk)-- == 0)
			break;

	}
	spin_unlock(&nlru->lock);
	return isolated;
}
EXPORT_SYMBOL_GPL(list_lru_walk_node);

static unsigned long
list_lru_dispose_all_node(
	struct list_lru		*lru,
	int			nid,
	list_lru_dispose_cb	dispose)
{
	struct list_lru_node	*nlru = &lru->node[nid];
	LIST_HEAD(dispose_list);
	unsigned long disposed = 0;

	spin_lock(&nlru->lock);
	while (!list_empty(&nlru->list)) {
		list_splice_init(&nlru->list, &dispose_list);
		disposed += nlru->nr_items;
		nlru->nr_items = 0;
		node_clear(nid, lru->active_nodes);
		spin_unlock(&nlru->lock);

		dispose(&dispose_list);

		spin_lock(&nlru->lock);
	}
	spin_unlock(&nlru->lock);
	return disposed;
}

unsigned long
list_lru_dispose_all(
	struct list_lru		*lru,
	list_lru_dispose_cb	dispose)
{
	unsigned long disposed;
	unsigned long total = 0;
	int nid;

	do {
		disposed = 0;
		for_each_node_mask(nid, lru->active_nodes) {
			disposed += list_lru_dispose_all_node(lru, nid,
							      dispose);
		}
		total += disposed;
	} while (disposed != 0);

	return total;
}

/*
 * This protects the list of all LRU in the system. One only needs
 * to take when registering an LRU, or when duplicating the list of lrus.
 * Transversing an LRU can and should be done outside the lock
 */
static DEFINE_MUTEX(all_memcg_lrus_mutex);
static LIST_HEAD(all_memcg_lrus);

static void list_lru_init_one(struct list_lru_node *lru)
{
	spin_lock_init(&lru->lock);
	INIT_LIST_HEAD(&lru->list);
	lru->nr_items = 0;
}

struct list_lru_array *lru_alloc_array(void)
{
	struct list_lru_array *lru_array;
	int i;

	lru_array = kzalloc(nr_node_ids * sizeof(struct list_lru_node),
				GFP_KERNEL);
	if (!lru_array)
		return NULL;

	for (i = 0; i < nr_node_ids; i++)
		list_lru_init_one(&lru_array->node[i]);

	return lru_array;
}

#ifdef CONFIG_MEMCG_KMEM
int __memcg_init_lru(struct list_lru *lru)
{
	int ret;

	INIT_LIST_HEAD(&lru->lrus);
	mutex_lock(&all_memcg_lrus_mutex);
	list_add(&lru->lrus, &all_memcg_lrus);
	ret = memcg_new_lru(lru);
	mutex_unlock(&all_memcg_lrus_mutex);
	return ret;
}

int memcg_update_all_lrus(unsigned long num)
{
	int ret = 0;
	struct list_lru *lru;

	mutex_lock(&all_memcg_lrus_mutex);
	list_for_each_entry(lru, &all_memcg_lrus, lrus) {
		ret = memcg_kmem_update_lru_size(lru, num, false);
		if (ret)
			goto out;
	}
out:
	mutex_unlock(&all_memcg_lrus_mutex);
	return ret;
}

void list_lru_destroy(struct list_lru *lru)
{
	mutex_lock(&all_memcg_lrus_mutex);
	list_del(&lru->lrus);
	mutex_unlock(&all_memcg_lrus_mutex);
}

void memcg_destroy_all_lrus(struct mem_cgroup *memcg)
{
	struct list_lru *lru;
	mutex_lock(&all_memcg_lrus_mutex);
	list_for_each_entry(lru, &all_memcg_lrus, lrus) {
		kfree(lru->memcg_lrus[memcg_cache_id(memcg)]);
		lru->memcg_lrus[memcg_cache_id(memcg)] = NULL;
		/* everybody must beaware that this memcg is no longer valid */
		wmb();
	}
	mutex_unlock(&all_memcg_lrus_mutex);
}
#endif

int __list_lru_init(struct list_lru *lru, bool memcg_enabled)
{
	int i;

	nodes_clear(lru->active_nodes);
	for (i = 0; i < MAX_NUMNODES; i++)
		list_lru_init_one(&lru->node[i]);

	if (memcg_enabled)
		return memcg_init_lru(lru);
	return 0;
}
EXPORT_SYMBOL_GPL(__list_lru_init);
