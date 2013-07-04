/*
 * Timer based watchdog.
 * Detect anything that isn't finishing within a certain time frame.
 *
 * Based on Lustre's watchdog written by Jacob Berkman <jacob@clusterfs.com>
 * Rewrite as kernel generic watchdog by Peng Tao <bergwolf@gmail.com>
 *
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates.
 * Copyright (c) 2012, Intel Corporation.
 * Copyright (c) 2013, EMC Corporation.
 */

#include <linux/mm.h>
#include <linux/cpu.h>
#include <linux/delay.h>
#include <linux/vmalloc.h>
#include <linux/freezer.h>
#include <linux/kthread.h>
#include <linux/lockdep.h>
#include <linux/notifier.h>
#include <linux/timer.h>
#include <linux/sched.h>
#include <linux/slab.h>

enum tm_watchdog_item_state {
	TM_WATCHDOG_DISABLED,
	TM_WATCHDOG_ENABLED,
	TM_WATCHDOG_EXPIRED
};

struct tm_watchdog_item {
	/* protect lcw_list, twi_last_touched, twi_refcount, twi_state. */
	spinlock_t			twi_lock;
	struct timer_list		twi_timer;	/* kernel timer */
	struct list_head		twi_list;	/* chain on timeout list */
	unsigned long long		twi_last_touched; /* last touched stamp */
	unsigned long long		twi_refcount;
	struct task_struct		*twi_task;	/* owner task */
	void				(*twi_callback)(pid_t, void *);
	void				(*twi_freedata)(void *);
	void				*twi_data;
	pid_t				twi_pid;	/* owner pid */
	enum tm_watchdog_item_state	twi_state;
};

static unsigned long tm_watchdog_flags;
static DEFINE_SPINLOCK(tm_pending_timers_lock);
static struct list_head tm_pending_timers = LIST_HEAD_INIT(tm_pending_timers);

/* each item and kthread takes a refcount */
static DEFINE_MUTEX(tm_refcount_mutex);
static unsigned long long tm_refcount;

static struct completion tm_start_completion;
static struct completion tm_stop_completion;
static wait_queue_head_t tm_watchdog_eq;

static const int TM_WATCHDOG_STOP = 0;

static int is_tm_watchdog_fired(void)
{
	int rc;

	if (test_bit(TM_WATCHDOG_STOP, &tm_watchdog_flags))
		return 1;

	spin_lock_bh(&tm_pending_timers_lock);
	rc = !list_empty(&tm_pending_timers);
	spin_unlock_bh(&tm_pending_timers_lock);
	return rc;
}

/* unlock twi->twi_lock */
static void tm_watchdog_item_put_locked(struct tm_watchdog_item *twi)
{
	bool free = false;

	if (--twi->twi_refcount == 0)
		free = true;
	spin_unlock_bh(&twi->twi_lock);

	if (free) {
		BUG_ON(!list_empty(&twi->twi_list));
		if (twi->twi_data && twi->twi_freedata)
			twi->twi_freedata(twi->twi_data);
		kfree(twi);
	}
}

static void tm_watchdog_item_put(struct tm_watchdog_item *twi)
{
	spin_lock_bh(&twi->twi_lock);
	tm_watchdog_item_put_locked(twi);
}

static const int TM_WATCHDOG_RATELIMIT_COUNT = 3;
static const int TM_WATCHDOG_RATELIMIT_SEC = 300;

static void tm_watchdog_dump_stack(struct tm_watchdog_item *twi)
{
	dump_stack_print_info(KERN_DEFAULT);
	show_stack(twi->twi_task, NULL);
}

static void tm_watchdog_dump(struct tm_watchdog_item *twi,
			     struct timeval *timediff)
{
	static unsigned long tm_watchdog_last_print = 0;
	static int tm_watchdog_print_count = 0;
	struct timeval print_delta;
	jiffies_to_timeval(jiffies - tm_watchdog_last_print, &print_delta);

	if (tm_watchdog_print_count > TM_WATCHDOG_RATELIMIT_COUNT &&
	    print_delta.tv_sec < TM_WATCHDOG_RATELIMIT_SEC) {
		printk(KERN_WARNING "Service thread pid %u was inactive for "
				    "%lu.%.02lus. Watchdog stack traces are "
				    "limited to %d per %d seconds, skipping "
				    "this one.\n",
				    (int)twi->twi_pid,
				    timediff->tv_sec,
				    timediff->tv_usec / 10000,
				    TM_WATCHDOG_RATELIMIT_COUNT,
				    TM_WATCHDOG_RATELIMIT_SEC);
	} else {
		if (print_delta.tv_sec > TM_WATCHDOG_RATELIMIT_SEC) {
			tm_watchdog_print_count = 0;
			tm_watchdog_last_print = jiffies;
		} else {
			tm_watchdog_print_count++;
		}

		printk(KERN_WARNING "Service thread pid %u was inactive for "
				    "%lu.%.02lus. The thread might be hung, "
				    "or it might only be slow and will resume "
				    "later. Dumping the stack trace for "
				    "debugging purposes:\n",
				    (int)twi->twi_pid,
				    timediff->tv_sec,
				    timediff->tv_usec / 10000);
		tm_watchdog_dump_stack(twi);
	}
}

static int tm_watchdog_thread(void *unused)
{
	struct list_head dump_list, *itr, *n;
	struct tm_watchdog_item *twi;

	complete(&tm_start_completion);

	while (1) {
		wait_event_interruptible(tm_watchdog_eq,
					 is_tm_watchdog_fired());
		if (test_bit(TM_WATCHDOG_STOP, &tm_watchdog_flags))
			break;

		INIT_LIST_HEAD(&dump_list);
		spin_lock_bh(&tm_pending_timers_lock);
		list_splice_init(&tm_pending_timers, &dump_list);
		spin_unlock_bh(&tm_pending_timers_lock);

		list_for_each_safe(itr, n, &dump_list) {
			struct timeval timediff;
			twi = list_entry(itr, struct tm_watchdog_item, twi_list);

			spin_lock_bh(&twi->twi_lock);
			list_del_init(&twi->twi_list);
			if (twi->twi_state != TM_WATCHDOG_EXPIRED) {
				/* drop ref on behalf of tm_pending_timers */
				tm_watchdog_item_put_locked(twi);
				continue;
			}
			jiffies_to_timeval(jiffies - twi->twi_last_touched,
					   &timediff);
			spin_unlock_bh(&twi->twi_lock);
			tm_watchdog_dump(twi, &timediff);
			if (twi->twi_callback)
				twi->twi_callback(twi->twi_pid, twi->twi_data);
			tm_watchdog_item_put(twi);
		}
	}
	complete(&tm_stop_completion);

	return 0;
}

static int tm_watchdog_start(void)
{
	struct task_struct *thread;
	init_completion(&tm_start_completion);
	init_completion(&tm_stop_completion);
	init_waitqueue_head(&tm_watchdog_eq);

	thread = kthread_run(tm_watchdog_thread, NULL, "tm_watchdog");
	if (IS_ERR(thread))
		return -ENOMEM;
	wait_for_completion(&tm_start_completion);
	return 0;
}

static void tm_watchdog_stop(void)
{
	struct tm_watchdog_item *twi, *n;

	set_bit(TM_WATCHDOG_STOP, &tm_watchdog_flags);
	wake_up(&tm_watchdog_eq);

	wait_for_completion(&tm_stop_completion);
	/* might have some pending items... */
	list_for_each_entry_safe(twi, n, &tm_pending_timers, twi_list)
		tm_watchdog_item_put(twi);
	clear_bit(TM_WATCHDOG_STOP, &tm_watchdog_flags);
}

static void tm_watchdog_timer_cb(unsigned long data)
{
	struct tm_watchdog_item *twi = (struct tm_watchdog_item *)data;

	spin_lock_bh(&twi->twi_lock);
	if (twi->twi_state != TM_WATCHDOG_ENABLED) {
		spin_unlock_bh(&twi->twi_lock);
		return;
	}
	twi->twi_state = TM_WATCHDOG_EXPIRED;
	twi->twi_refcount++;
	BUG_ON(!list_empty(&twi->twi_list));

	spin_lock_bh(&tm_pending_timers_lock);
	list_add(&twi->twi_list, &tm_pending_timers);
	spin_unlock_bh(&tm_pending_timers_lock);
	spin_unlock_bh(&twi->twi_lock);

	wake_up(&tm_watchdog_eq);
}

struct tm_watchdog_item *tm_watchdog_add_item(void (*callback)(pid_t, void *),
					      void (*freedata)(void *),
					      void *data, gfp_t flags)
{
	struct tm_watchdog_item *twi;

	twi = kmalloc(sizeof(*twi), flags);
	if (twi == NULL)
		return ERR_PTR(-ENOMEM);

	mutex_lock(&tm_refcount_mutex);
	if (tm_refcount++ == 0 && tm_watchdog_start()) {
		tm_refcount--;
		mutex_unlock(&tm_refcount_mutex);
		kfree(twi);
		return ERR_PTR(-ENOMEM);
	}
	mutex_unlock(&tm_refcount_mutex);

	spin_lock_init(&twi->twi_lock);
	INIT_LIST_HEAD(&twi->twi_list);
	twi->twi_last_touched = jiffies;
	twi->twi_task = current;
	twi->twi_pid = current->pid;
	twi->twi_state = TM_WATCHDOG_DISABLED;
	twi->twi_refcount = 1;
	twi->twi_callback = callback;
	twi->twi_data = data;
	twi->twi_freedata = freedata;

	init_timer(&twi->twi_timer);
	twi->twi_timer.function = tm_watchdog_timer_cb;
	twi->twi_timer.data = (unsigned long)twi;

	return twi;
}
EXPORT_SYMBOL_GPL(tm_watchdog_add_item);

static void tm_watchdog_update_time(struct tm_watchdog_item *twi,
				    const char *message)
{
	unsigned long newtime = jiffies;

	if (twi->twi_state == TM_WATCHDOG_EXPIRED) {
		struct timeval timediff;
		unsigned long delta_time = newtime - twi->twi_last_touched;
		jiffies_to_timeval(delta_time, &timediff);

		printk(KERN_WARNING "Service thread pid %u %s after "
				    "%lu.%.02lus. This indicates the system "
				    " was overloaded (too many service "
				    "threads, or there were not enough "
				    "hardware resources).\n",
				    twi->twi_pid,
				    message,
				    timediff.tv_sec,
				    timediff.tv_usec / 10000);
	}
	twi->twi_last_touched = newtime;
}

void tm_watchdog_delete_item(struct tm_watchdog_item *twi)
{
	del_timer_sync(&twi->twi_timer);
	spin_lock_bh(&twi->twi_lock);
	tm_watchdog_update_time(twi, "stopped");
	twi->twi_state = TM_WATCHDOG_DISABLED;
	tm_watchdog_item_put_locked(twi);

	mutex_lock(&tm_refcount_mutex);
	if (--tm_refcount == 0)
		tm_watchdog_stop();
	mutex_unlock(&tm_refcount_mutex);
}
EXPORT_SYMBOL_GPL(tm_watchdog_delete_item);

static void tm_watchdog_item_set_locked(struct tm_watchdog_item *twi,
					enum tm_watchdog_item_state state)
{
	twi->twi_state = state;
	if (unlikely(!list_empty(&twi->twi_list))) {
		/* can be either on pending list or dumping list */
		spin_lock_bh(&tm_pending_timers_lock);
		list_del_init(&twi->twi_list);
		spin_unlock_bh(&tm_pending_timers_lock);
		twi->twi_refcount--;
	}
}

void tm_watchdog_touch_item(struct tm_watchdog_item *twi, int time)
{
	spin_lock_bh(&twi->twi_lock);
	tm_watchdog_update_time(twi, "resumed");
	tm_watchdog_item_set_locked(twi, TM_WATCHDOG_ENABLED);
	spin_unlock_bh(&twi->twi_lock);

	mod_timer(&twi->twi_timer, jiffies + time * HZ);
}
EXPORT_SYMBOL_GPL(tm_watchdog_touch_item);

void tm_watchdog_disable_item(struct tm_watchdog_item *twi)
{
	spin_lock_bh(&twi->twi_lock);
	tm_watchdog_update_time(twi, "completed");
	tm_watchdog_item_set_locked(twi, TM_WATCHDOG_DISABLED);
	spin_unlock_bh(&twi->twi_lock);
}
EXPORT_SYMBOL_GPL(tm_watchdog_disable_item);
