// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Support for INET connection oriented protocols.
 *
 * Authors:	See the TCP sources
 */

#include <linux/module.h>
#include <linux/jhash.h>

#include <net/inet_connection_sock.h>
#include <net/inet_hashtables.h>
#include <net/inet_timewait_sock.h>
#include <net/ip.h>
#include <net/route.h>
#include <net/tcp_states.h>
#include <net/xfrm.h>
#include <net/tcp.h>
#include <net/sock_reuseport.h>
#include <net/addrconf.h>

#if IS_ENABLED(CONFIG_IPV6)
/* match_sk*_wildcard == true:  IPV6_ADDR_ANY equals to any IPv6 addresses
 *				if IPv6 only, and any IPv4 addresses
 *				if not IPv6 only
 * match_sk*_wildcard == false: addresses must be exactly the same, i.e.
 *				IPV6_ADDR_ANY only equals to IPV6_ADDR_ANY,
 *				and 0.0.0.0 equals to 0.0.0.0 only
 */
static bool ipv6_rcv_saddr_equal(const struct in6_addr *sk1_rcv_saddr6,
				 const struct in6_addr *sk2_rcv_saddr6,
				 __be32 sk1_rcv_saddr, __be32 sk2_rcv_saddr,
				 bool sk1_ipv6only, bool sk2_ipv6only,
				 bool match_sk1_wildcard,
				 bool match_sk2_wildcard)
{
	int addr_type = ipv6_addr_type(sk1_rcv_saddr6);
	int addr_type2 = sk2_rcv_saddr6 ? ipv6_addr_type(sk2_rcv_saddr6) : IPV6_ADDR_MAPPED;

	/* if both are mapped, treat as IPv4 */
	if (addr_type == IPV6_ADDR_MAPPED && addr_type2 == IPV6_ADDR_MAPPED) {
		if (!sk2_ipv6only) {
			if (sk1_rcv_saddr == sk2_rcv_saddr)
				return true;
			return (match_sk1_wildcard && !sk1_rcv_saddr) ||
				(match_sk2_wildcard && !sk2_rcv_saddr);
		}
		return false;
	}

	if (addr_type == IPV6_ADDR_ANY && addr_type2 == IPV6_ADDR_ANY)
		return true;

	if (addr_type2 == IPV6_ADDR_ANY && match_sk2_wildcard &&
	    !(sk2_ipv6only && addr_type == IPV6_ADDR_MAPPED))
		return true;

	if (addr_type == IPV6_ADDR_ANY && match_sk1_wildcard &&
	    !(sk1_ipv6only && addr_type2 == IPV6_ADDR_MAPPED))
		return true;

	if (sk2_rcv_saddr6 &&
	    ipv6_addr_equal(sk1_rcv_saddr6, sk2_rcv_saddr6))
		return true;

	return false;
}
#endif

/* match_sk*_wildcard == true:  0.0.0.0 equals to any IPv4 addresses
 * match_sk*_wildcard == false: addresses must be exactly the same, i.e.
 *				0.0.0.0 only equals to 0.0.0.0
 */
static bool ipv4_rcv_saddr_equal(__be32 sk1_rcv_saddr, __be32 sk2_rcv_saddr,
				 bool sk2_ipv6only, bool match_sk1_wildcard,
				 bool match_sk2_wildcard)
{
	if (!sk2_ipv6only) {
		if (sk1_rcv_saddr == sk2_rcv_saddr)
			return true;
		return (match_sk1_wildcard && !sk1_rcv_saddr) ||
			(match_sk2_wildcard && !sk2_rcv_saddr);
	}
	return false;
}

bool inet_rcv_saddr_equal(const struct sock *sk, const struct sock *sk2,
			  bool match_wildcard)
{
#if IS_ENABLED(CONFIG_IPV6)
	if (sk->sk_family == AF_INET6)
		return ipv6_rcv_saddr_equal(&sk->sk_v6_rcv_saddr,
					    inet6_rcv_saddr(sk2),
					    sk->sk_rcv_saddr,
					    sk2->sk_rcv_saddr,
					    ipv6_only_sock(sk),
					    ipv6_only_sock(sk2),
					    match_wildcard,
					    match_wildcard);
#endif
	return ipv4_rcv_saddr_equal(sk->sk_rcv_saddr, sk2->sk_rcv_saddr,
				    ipv6_only_sock(sk2), match_wildcard,
				    match_wildcard);
}
EXPORT_SYMBOL(inet_rcv_saddr_equal);

bool inet_rcv_saddr_any(const struct sock *sk)
{
#if IS_ENABLED(CONFIG_IPV6)
	if (sk->sk_family == AF_INET6)
		return ipv6_addr_any(&sk->sk_v6_rcv_saddr);
#endif
	return !sk->sk_rcv_saddr;
}

/**
 *	inet_sk_get_local_port_range - fetch ephemeral ports range
 *	@sk: socket
 *	@low: pointer to low port
 *	@high: pointer to high port
 *
 *	Fetch netns port range (/proc/sys/net/ipv4/ip_local_port_range)
 *	Range can be overridden if socket got IP_LOCAL_PORT_RANGE option.
 *	Returns true if IP_LOCAL_PORT_RANGE was set on this socket.
 */
bool inet_sk_get_local_port_range(const struct sock *sk, int *low, int *high)
{
	int lo, hi, sk_lo, sk_hi;
	bool local_range = false;
	u32 sk_range;

	inet_get_local_port_range(sock_net(sk), &lo, &hi);

	sk_range = READ_ONCE(inet_sk(sk)->local_port_range);
	if (unlikely(sk_range)) {
		sk_lo = sk_range & 0xffff;
		sk_hi = sk_range >> 16;

		if (lo <= sk_lo && sk_lo <= hi)
			lo = sk_lo;
		if (lo <= sk_hi && sk_hi <= hi)
			hi = sk_hi;
		local_range = true;
	}

	*low = lo;
	*high = hi;
	return local_range;
}
EXPORT_SYMBOL(inet_sk_get_local_port_range);

static bool inet_use_bhash2_on_bind(const struct sock *sk)
{
#if IS_ENABLED(CONFIG_IPV6)
	if (sk->sk_family == AF_INET6) {
		if (ipv6_addr_any(&sk->sk_v6_rcv_saddr))
			return false;

		if (!ipv6_addr_v4mapped(&sk->sk_v6_rcv_saddr))
			return true;
	}
#endif
	return sk->sk_rcv_saddr != htonl(INADDR_ANY);
}

static bool inet_bind_conflict(const struct sock *sk, struct sock *sk2,
			       kuid_t uid, bool relax,
			       bool reuseport_cb_ok, bool reuseport_ok)
{
	int bound_dev_if2;

	if (sk == sk2)
		return false;

	bound_dev_if2 = READ_ONCE(sk2->sk_bound_dev_if);

	if (!sk->sk_bound_dev_if || !bound_dev_if2 ||
	    sk->sk_bound_dev_if == bound_dev_if2) {
		if (sk->sk_reuse && sk2->sk_reuse &&
		    sk2->sk_state != TCP_LISTEN) {
			if (!relax || (!reuseport_ok && sk->sk_reuseport &&
				       sk2->sk_reuseport && reuseport_cb_ok &&
				       (sk2->sk_state == TCP_TIME_WAIT ||
					uid_eq(uid, sk_uid(sk2)))))
				return true;
		} else if (!reuseport_ok || !sk->sk_reuseport ||
			   !sk2->sk_reuseport || !reuseport_cb_ok ||
			   (sk2->sk_state != TCP_TIME_WAIT &&
			    !uid_eq(uid, sk_uid(sk2)))) {
			return true;
		}
	}
	return false;
}

static bool __inet_bhash2_conflict(const struct sock *sk, struct sock *sk2,
				   kuid_t uid, bool relax,
				   bool reuseport_cb_ok, bool reuseport_ok)
{
	if (ipv6_only_sock(sk2)) {
		if (sk->sk_family == AF_INET)
			return false;

#if IS_ENABLED(CONFIG_IPV6)
		if (ipv6_addr_v4mapped(&sk->sk_v6_rcv_saddr))
			return false;
#endif
	}

	return inet_bind_conflict(sk, sk2, uid, relax,
				  reuseport_cb_ok, reuseport_ok);
}

static bool inet_bhash2_conflict(const struct sock *sk,
				 const struct inet_bind2_bucket *tb2,
				 kuid_t uid,
				 bool relax, bool reuseport_cb_ok,
				 bool reuseport_ok)
{
	struct sock *sk2;

	sk_for_each_bound(sk2, &tb2->owners) {
		if (__inet_bhash2_conflict(sk, sk2, uid, relax,
					   reuseport_cb_ok, reuseport_ok))
			return true;
	}

	return false;
}

#define sk_for_each_bound_bhash(__sk, __tb2, __tb)			\
	hlist_for_each_entry(__tb2, &(__tb)->bhash2, bhash_node)	\
		sk_for_each_bound((__sk), &(__tb2)->owners)

/* This should be called only when the tb and tb2 hashbuckets' locks are held */
static int inet_csk_bind_conflict(const struct sock *sk,
				  const struct inet_bind_bucket *tb,
				  const struct inet_bind2_bucket *tb2, /* may be null */
				  bool relax, bool reuseport_ok)
{
	struct sock_reuseport *reuseport_cb;
	kuid_t uid = sk_uid(sk);
	bool reuseport_cb_ok;
	struct sock *sk2;

	rcu_read_lock();
	reuseport_cb = rcu_dereference(sk->sk_reuseport_cb);
	/* paired with WRITE_ONCE() in __reuseport_(add|detach)_closed_sock */
	reuseport_cb_ok = !reuseport_cb || READ_ONCE(reuseport_cb->num_closed_socks);
	rcu_read_unlock();

	/* Conflicts with an existing IPV6_ADDR_ANY (if ipv6) or INADDR_ANY (if
	 * ipv4) should have been checked already. We need to do these two
	 * checks separately because their spinlocks have to be acquired/released
	 * independently of each other, to prevent possible deadlocks
	 */
	if (inet_use_bhash2_on_bind(sk))
		return tb2 && inet_bhash2_conflict(sk, tb2, uid, relax,
						   reuseport_cb_ok, reuseport_ok);

	/* Unlike other sk lookup places we do not check
	 * for sk_net here, since _all_ the socks listed
	 * in tb->owners and tb2->owners list belong
	 * to the same net - the one this bucket belongs to.
	 */
	sk_for_each_bound_bhash(sk2, tb2, tb) {
		if (!inet_bind_conflict(sk, sk2, uid, relax, reuseport_cb_ok, reuseport_ok))
			continue;

		if (inet_rcv_saddr_equal(sk, sk2, true))
			return true;
	}

	return false;
}

/* Determine if there is a bind conflict with an existing IPV6_ADDR_ANY (if ipv6) or
 * INADDR_ANY (if ipv4) socket.
 *
 * Caller must hold bhash hashbucket lock with local bh disabled, to protect
 * against concurrent binds on the port for addr any
 */
static bool inet_bhash2_addr_any_conflict(const struct sock *sk, int port, int l3mdev,
					  bool relax, bool reuseport_ok)
{
	const struct net *net = sock_net(sk);
	struct sock_reuseport *reuseport_cb;
	struct inet_bind_hashbucket *head2;
	struct inet_bind2_bucket *tb2;
	kuid_t uid = sk_uid(sk);
	bool conflict = false;
	bool reuseport_cb_ok;

	rcu_read_lock();
	reuseport_cb = rcu_dereference(sk->sk_reuseport_cb);
	/* paired with WRITE_ONCE() in __reuseport_(add|detach)_closed_sock */
	reuseport_cb_ok = !reuseport_cb || READ_ONCE(reuseport_cb->num_closed_socks);
	rcu_read_unlock();

	head2 = inet_bhash2_addr_any_hashbucket(sk, net, port);

	spin_lock(&head2->lock);

	inet_bind_bucket_for_each(tb2, &head2->chain) {
		if (!inet_bind2_bucket_match_addr_any(tb2, net, port, l3mdev, sk))
			continue;

		if (!inet_bhash2_conflict(sk, tb2, uid, relax, reuseport_cb_ok,	reuseport_ok))
			continue;

		conflict = true;
		break;
	}

	spin_unlock(&head2->lock);

	return conflict;
}

/*
 * Find an open port number for the socket.  Returns with the
 * inet_bind_hashbucket locks held if successful.
 */
static struct inet_bind_hashbucket *
inet_csk_find_open_port(const struct sock *sk, struct inet_bind_bucket **tb_ret,
			struct inet_bind2_bucket **tb2_ret,
			struct inet_bind_hashbucket **head2_ret, int *port_ret)
{
	struct inet_hashinfo *hinfo = tcp_get_hashinfo(sk);
	int i, low, high, attempt_half, port, l3mdev;
	struct inet_bind_hashbucket *head, *head2;
	struct net *net = sock_net(sk);
	struct inet_bind2_bucket *tb2;
	struct inet_bind_bucket *tb;
	u32 remaining, offset;
	bool relax = false;

	l3mdev = inet_sk_bound_l3mdev(sk);
ports_exhausted:
	attempt_half = (sk->sk_reuse == SK_CAN_REUSE) ? 1 : 0;
other_half_scan:
	inet_sk_get_local_port_range(sk, &low, &high);
	high++; /* [32768, 60999] -> [32768, 61000[ */
	if (high - low < 4)
		attempt_half = 0;
	if (attempt_half) {
		int half = low + (((high - low) >> 2) << 1);

		if (attempt_half == 1)
			high = half;
		else
			low = half;
	}
	remaining = high - low;
	if (likely(remaining > 1))
		remaining &= ~1U;

	offset = get_random_u32_below(remaining);
	/* __inet_hash_connect() favors ports having @low parity
	 * We do the opposite to not pollute connect() users.
	 */
	offset |= 1U;

other_parity_scan:
	port = low + offset;
	for (i = 0; i < remaining; i += 2, port += 2) {
		if (unlikely(port >= high))
			port -= remaining;
		if (inet_is_local_reserved_port(net, port))
			continue;
		head = &hinfo->bhash[inet_bhashfn(net, port,
						  hinfo->bhash_size)];
		spin_lock_bh(&head->lock);
		if (inet_use_bhash2_on_bind(sk)) {
			if (inet_bhash2_addr_any_conflict(sk, port, l3mdev, relax, false))
				goto next_port;
		}

		head2 = inet_bhashfn_portaddr(hinfo, sk, net, port);
		spin_lock(&head2->lock);
		tb2 = inet_bind2_bucket_find(head2, net, port, l3mdev, sk);
		inet_bind_bucket_for_each(tb, &head->chain)
			if (inet_bind_bucket_match(tb, net, port, l3mdev)) {
				if (!inet_csk_bind_conflict(sk, tb, tb2,
							    relax, false))
					goto success;
				spin_unlock(&head2->lock);
				goto next_port;
			}
		tb = NULL;
		goto success;
next_port:
		spin_unlock_bh(&head->lock);
		cond_resched();
	}

	offset--;
	if (!(offset & 1))
		goto other_parity_scan;

	if (attempt_half == 1) {
		/* OK we now try the upper half of the range */
		attempt_half = 2;
		goto other_half_scan;
	}

	if (READ_ONCE(net->ipv4.sysctl_ip_autobind_reuse) && !relax) {
		/* We still have a chance to connect to different destinations */
		relax = true;
		goto ports_exhausted;
	}
	return NULL;
success:
	*port_ret = port;
	*tb_ret = tb;
	*tb2_ret = tb2;
	*head2_ret = head2;
	return head;
}

static inline int sk_reuseport_match(struct inet_bind_bucket *tb,
				     struct sock *sk)
{
	if (tb->fastreuseport <= 0)
		return 0;
	if (!sk->sk_reuseport)
		return 0;
	if (rcu_access_pointer(sk->sk_reuseport_cb))
		return 0;
	if (!uid_eq(tb->fastuid, sk_uid(sk)))
		return 0;
	/* We only need to check the rcv_saddr if this tb was once marked
	 * without fastreuseport and then was reset, as we can only know that
	 * the fast_*rcv_saddr doesn't have any conflicts with the socks on the
	 * owners list.
	 */
	if (tb->fastreuseport == FASTREUSEPORT_ANY)
		return 1;
#if IS_ENABLED(CONFIG_IPV6)
	if (tb->fast_sk_family == AF_INET6)
		return ipv6_rcv_saddr_equal(&tb->fast_v6_rcv_saddr,
					    inet6_rcv_saddr(sk),
					    tb->fast_rcv_saddr,
					    sk->sk_rcv_saddr,
					    tb->fast_ipv6_only,
					    ipv6_only_sock(sk), true, false);
#endif
	return ipv4_rcv_saddr_equal(tb->fast_rcv_saddr, sk->sk_rcv_saddr,
				    ipv6_only_sock(sk), true, false);
}

void inet_csk_update_fastreuse(struct inet_bind_bucket *tb,
			       struct sock *sk)
{
	bool reuse = sk->sk_reuse && sk->sk_state != TCP_LISTEN;

	if (hlist_empty(&tb->bhash2)) {
		tb->fastreuse = reuse;
		if (sk->sk_reuseport) {
			tb->fastreuseport = FASTREUSEPORT_ANY;
			tb->fastuid = sk_uid(sk);
			tb->fast_rcv_saddr = sk->sk_rcv_saddr;
			tb->fast_ipv6_only = ipv6_only_sock(sk);
			tb->fast_sk_family = sk->sk_family;
#if IS_ENABLED(CONFIG_IPV6)
			tb->fast_v6_rcv_saddr = sk->sk_v6_rcv_saddr;
#endif
		} else {
			tb->fastreuseport = 0;
		}
	} else {
		if (!reuse)
			tb->fastreuse = 0;
		if (sk->sk_reuseport) {
			/* We didn't match or we don't have fastreuseport set on
			 * the tb, but we have sk_reuseport set on this socket
			 * and we know that there are no bind conflicts with
			 * this socket in this tb, so reset our tb's reuseport
			 * settings so that any subsequent sockets that match
			 * our current socket will be put on the fast path.
			 *
			 * If we reset we need to set FASTREUSEPORT_STRICT so we
			 * do extra checking for all subsequent sk_reuseport
			 * socks.
			 */
			if (!sk_reuseport_match(tb, sk)) {
				tb->fastreuseport = FASTREUSEPORT_STRICT;
				tb->fastuid = sk_uid(sk);
				tb->fast_rcv_saddr = sk->sk_rcv_saddr;
				tb->fast_ipv6_only = ipv6_only_sock(sk);
				tb->fast_sk_family = sk->sk_family;
#if IS_ENABLED(CONFIG_IPV6)
				tb->fast_v6_rcv_saddr = sk->sk_v6_rcv_saddr;
#endif
			}
		} else {
			tb->fastreuseport = 0;
		}
	}
}

/* Obtain a reference to a local port for the given sock,
 * if snum is zero it means select any available local port.
 * We try to allocate an odd port (and leave even ports for connect())
 */
int inet_csk_get_port(struct sock *sk, unsigned short snum)
{
	bool reuse = sk->sk_reuse && sk->sk_state != TCP_LISTEN;
	bool found_port = false, check_bind_conflict = true;
	bool bhash_created = false, bhash2_created = false;
	struct inet_hashinfo *hinfo = tcp_get_hashinfo(sk);
	int ret = -EADDRINUSE, port = snum, l3mdev;
	struct inet_bind_hashbucket *head, *head2;
	struct inet_bind2_bucket *tb2 = NULL;
	struct inet_bind_bucket *tb = NULL;
	bool head2_lock_acquired = false;
	struct net *net = sock_net(sk);

	l3mdev = inet_sk_bound_l3mdev(sk);

	if (!port) {
		head = inet_csk_find_open_port(sk, &tb, &tb2, &head2, &port);
		if (!head)
			return ret;

		head2_lock_acquired = true;

		if (tb && tb2)
			goto success;
		found_port = true;
	} else {
		head = &hinfo->bhash[inet_bhashfn(net, port,
						  hinfo->bhash_size)];
		spin_lock_bh(&head->lock);
		inet_bind_bucket_for_each(tb, &head->chain)
			if (inet_bind_bucket_match(tb, net, port, l3mdev))
				break;
	}

	if (!tb) {
		tb = inet_bind_bucket_create(hinfo->bind_bucket_cachep, net,
					     head, port, l3mdev);
		if (!tb)
			goto fail_unlock;
		bhash_created = true;
	}

	if (!found_port) {
		if (!hlist_empty(&tb->bhash2)) {
			if (sk->sk_reuse == SK_FORCE_REUSE ||
			    (tb->fastreuse > 0 && reuse) ||
			    sk_reuseport_match(tb, sk))
				check_bind_conflict = false;
		}

		if (check_bind_conflict && inet_use_bhash2_on_bind(sk)) {
			if (inet_bhash2_addr_any_conflict(sk, port, l3mdev, true, true))
				goto fail_unlock;
		}

		head2 = inet_bhashfn_portaddr(hinfo, sk, net, port);
		spin_lock(&head2->lock);
		head2_lock_acquired = true;
		tb2 = inet_bind2_bucket_find(head2, net, port, l3mdev, sk);
	}

	if (!tb2) {
		tb2 = inet_bind2_bucket_create(hinfo->bind2_bucket_cachep,
					       net, head2, tb, sk);
		if (!tb2)
			goto fail_unlock;
		bhash2_created = true;
	}

	if (!found_port && check_bind_conflict) {
		if (inet_csk_bind_conflict(sk, tb, tb2, true, true))
			goto fail_unlock;
	}

success:
	inet_csk_update_fastreuse(tb, sk);

	if (!inet_csk(sk)->icsk_bind_hash)
		inet_bind_hash(sk, tb, tb2, port);
	WARN_ON(inet_csk(sk)->icsk_bind_hash != tb);
	WARN_ON(inet_csk(sk)->icsk_bind2_hash != tb2);
	ret = 0;

fail_unlock:
	if (ret) {
		if (bhash2_created)
			inet_bind2_bucket_destroy(hinfo->bind2_bucket_cachep, tb2);
		if (bhash_created)
			inet_bind_bucket_destroy(tb);
	}
	if (head2_lock_acquired)
		spin_unlock(&head2->lock);
	spin_unlock_bh(&head->lock);
	return ret;
}
EXPORT_SYMBOL_GPL(inet_csk_get_port);

/*
 * Wait for an incoming connection, avoid race conditions. This must be called
 * with the socket locked.
 */
static int inet_csk_wait_for_connect(struct sock *sk, long timeo)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	DEFINE_WAIT(wait);
	int err;

	/*
	 * True wake-one mechanism for incoming connections: only
	 * one process gets woken up, not the 'whole herd'.
	 * Since we do not 'race & poll' for established sockets
	 * anymore, the common case will execute the loop only once.
	 *
	 * Subtle issue: "add_wait_queue_exclusive()" will be added
	 * after any current non-exclusive waiters, and we know that
	 * it will always _stay_ after any new non-exclusive waiters
	 * because all non-exclusive waiters are added at the
	 * beginning of the wait-queue. As such, it's ok to "drop"
	 * our exclusiveness temporarily when we get woken up without
	 * having to remove and re-insert us on the wait queue.
	 */
	for (;;) {
		prepare_to_wait_exclusive(sk_sleep(sk), &wait,
					  TASK_INTERRUPTIBLE);
		release_sock(sk);
		if (reqsk_queue_empty(&icsk->icsk_accept_queue))
			timeo = schedule_timeout(timeo);
		sched_annotate_sleep();
		lock_sock(sk);
		err = 0;
		if (!reqsk_queue_empty(&icsk->icsk_accept_queue))
			break;
		err = -EINVAL;
		if (sk->sk_state != TCP_LISTEN)
			break;
		err = sock_intr_errno(timeo);
		if (signal_pending(current))
			break;
		err = -EAGAIN;
		if (!timeo)
			break;
	}
	finish_wait(sk_sleep(sk), &wait);
	return err;
}

/*
 * This will accept the next outstanding connection.
 */
struct sock *inet_csk_accept(struct sock *sk, struct proto_accept_arg *arg)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct request_sock_queue *queue = &icsk->icsk_accept_queue;
	struct request_sock *req;
	struct sock *newsk;
	int error;

	lock_sock(sk);

	/* We need to make sure that this socket is listening,
	 * and that it has something pending.
	 */
	error = -EINVAL;
	if (sk->sk_state != TCP_LISTEN)
		goto out_err;

	/* Find already established connection */
	if (reqsk_queue_empty(queue)) {
		long timeo = sock_rcvtimeo(sk, arg->flags & O_NONBLOCK);

		/* If this is a non blocking socket don't sleep */
		error = -EAGAIN;
		if (!timeo)
			goto out_err;

		error = inet_csk_wait_for_connect(sk, timeo);
		if (error)
			goto out_err;
	}
	req = reqsk_queue_remove(queue, sk);
	arg->is_empty = reqsk_queue_empty(queue);
	newsk = req->sk;

	if (sk->sk_protocol == IPPROTO_TCP &&
	    tcp_rsk(req)->tfo_listener) {
		spin_lock_bh(&queue->fastopenq.lock);
		if (tcp_rsk(req)->tfo_listener) {
			/* We are still waiting for the final ACK from 3WHS
			 * so can't free req now. Instead, we set req->sk to
			 * NULL to signify that the child socket is taken
			 * so reqsk_fastopen_remove() will free the req
			 * when 3WHS finishes (or is aborted).
			 */
			req->sk = NULL;
			req = NULL;
		}
		spin_unlock_bh(&queue->fastopenq.lock);
	}

out:
	release_sock(sk);
	if (newsk && mem_cgroup_sockets_enabled) {
		gfp_t gfp = GFP_KERNEL | __GFP_NOFAIL;
		int amt = 0;

		/* atomically get the memory usage, set and charge the
		 * newsk->sk_memcg.
		 */
		lock_sock(newsk);

		mem_cgroup_sk_alloc(newsk);
		if (newsk->sk_memcg) {
			/* The socket has not been accepted yet, no need
			 * to look at newsk->sk_wmem_queued.
			 */
			amt = sk_mem_pages(newsk->sk_forward_alloc +
					   atomic_read(&newsk->sk_rmem_alloc));
		}

		if (amt)
			mem_cgroup_charge_skmem(newsk->sk_memcg, amt, gfp);
		kmem_cache_charge(newsk, gfp);

		release_sock(newsk);
	}
	if (req)
		reqsk_put(req);

	if (newsk)
		inet_init_csk_locks(newsk);

	return newsk;
out_err:
	newsk = NULL;
	req = NULL;
	arg->err = error;
	goto out;
}
EXPORT_SYMBOL(inet_csk_accept);

/*
 * Using different timers for retransmit, delayed acks and probes
 * We may wish use just one timer maintaining a list of expire jiffies
 * to optimize.
 */
void inet_csk_init_xmit_timers(struct sock *sk,
			       void (*retransmit_handler)(struct timer_list *t),
			       void (*delack_handler)(struct timer_list *t),
			       void (*keepalive_handler)(struct timer_list *t))
{
	struct inet_connection_sock *icsk = inet_csk(sk);

	timer_setup(&icsk->icsk_retransmit_timer, retransmit_handler, 0);
	timer_setup(&icsk->icsk_delack_timer, delack_handler, 0);
	timer_setup(&sk->sk_timer, keepalive_handler, 0);
	icsk->icsk_pending = icsk->icsk_ack.pending = 0;
}

void inet_csk_clear_xmit_timers(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);

	smp_store_release(&icsk->icsk_pending, 0);
	smp_store_release(&icsk->icsk_ack.pending, 0);

	sk_stop_timer(sk, &icsk->icsk_retransmit_timer);
	sk_stop_timer(sk, &icsk->icsk_delack_timer);
	sk_stop_timer(sk, &sk->sk_timer);
}

void inet_csk_clear_xmit_timers_sync(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);

	/* ongoing timer handlers need to acquire socket lock. */
	sock_not_owned_by_me(sk);

	smp_store_release(&icsk->icsk_pending, 0);
	smp_store_release(&icsk->icsk_ack.pending, 0);

	sk_stop_timer_sync(sk, &icsk->icsk_retransmit_timer);
	sk_stop_timer_sync(sk, &icsk->icsk_delack_timer);
	sk_stop_timer_sync(sk, &sk->sk_timer);
}

struct dst_entry *inet_csk_route_req(const struct sock *sk,
				     struct flowi4 *fl4,
				     const struct request_sock *req)
{
	const struct inet_request_sock *ireq = inet_rsk(req);
	struct net *net = read_pnet(&ireq->ireq_net);
	struct ip_options_rcu *opt;
	struct rtable *rt;

	rcu_read_lock();
	opt = rcu_dereference(ireq->ireq_opt);

	flowi4_init_output(fl4, ireq->ir_iif, ireq->ir_mark,
			   ip_sock_rt_tos(sk), ip_sock_rt_scope(sk),
			   sk->sk_protocol, inet_sk_flowi_flags(sk),
			   (opt && opt->opt.srr) ? opt->opt.faddr : ireq->ir_rmt_addr,
			   ireq->ir_loc_addr, ireq->ir_rmt_port,
			   htons(ireq->ir_num), sk_uid(sk));
	security_req_classify_flow(req, flowi4_to_flowi_common(fl4));
	rt = ip_route_output_flow(net, fl4, sk);
	if (IS_ERR(rt))
		goto no_route;
	if (opt && opt->opt.is_strictroute && rt->rt_uses_gateway)
		goto route_err;
	rcu_read_unlock();
	return &rt->dst;

route_err:
	ip_rt_put(rt);
no_route:
	rcu_read_unlock();
	__IP_INC_STATS(net, IPSTATS_MIB_OUTNOROUTES);
	return NULL;
}

struct dst_entry *inet_csk_route_child_sock(const struct sock *sk,
					    struct sock *newsk,
					    const struct request_sock *req)
{
	const struct inet_request_sock *ireq = inet_rsk(req);
	struct net *net = read_pnet(&ireq->ireq_net);
	struct inet_sock *newinet = inet_sk(newsk);
	struct ip_options_rcu *opt;
	struct flowi4 *fl4;
	struct rtable *rt;

	opt = rcu_dereference(ireq->ireq_opt);
	fl4 = &newinet->cork.fl.u.ip4;

	flowi4_init_output(fl4, ireq->ir_iif, ireq->ir_mark,
			   ip_sock_rt_tos(sk), ip_sock_rt_scope(sk),
			   sk->sk_protocol, inet_sk_flowi_flags(sk),
			   (opt && opt->opt.srr) ? opt->opt.faddr : ireq->ir_rmt_addr,
			   ireq->ir_loc_addr, ireq->ir_rmt_port,
			   htons(ireq->ir_num), sk_uid(sk));
	security_req_classify_flow(req, flowi4_to_flowi_common(fl4));
	rt = ip_route_output_flow(net, fl4, sk);
	if (IS_ERR(rt))
		goto no_route;
	if (opt && opt->opt.is_strictroute && rt->rt_uses_gateway)
		goto route_err;
	return &rt->dst;

route_err:
	ip_rt_put(rt);
no_route:
	__IP_INC_STATS(net, IPSTATS_MIB_OUTNOROUTES);
	return NULL;
}
EXPORT_SYMBOL_GPL(inet_csk_route_child_sock);

/* Decide when to expire the request and when to resend SYN-ACK */
static void syn_ack_recalc(struct request_sock *req,
			   const int max_syn_ack_retries,
			   const u8 rskq_defer_accept,
			   int *expire, int *resend)
{
	if (!rskq_defer_accept) {
		*expire = req->num_timeout >= max_syn_ack_retries;
		*resend = 1;
		return;
	}
	*expire = req->num_timeout >= max_syn_ack_retries &&
		  (!inet_rsk(req)->acked || req->num_timeout >= rskq_defer_accept);
	/* Do not resend while waiting for data after ACK,
	 * start to resend on end of deferring period to give
	 * last chance for data or ACK to create established socket.
	 */
	*resend = !inet_rsk(req)->acked ||
		  req->num_timeout >= rskq_defer_accept - 1;
}

static struct request_sock *
reqsk_alloc_noprof(const struct request_sock_ops *ops, struct sock *sk_listener,
		   bool attach_listener)
{
	struct request_sock *req;

	req = kmem_cache_alloc_noprof(ops->slab, GFP_ATOMIC | __GFP_NOWARN);
	if (!req)
		return NULL;
	req->rsk_listener = NULL;
	if (attach_listener) {
		if (unlikely(!refcount_inc_not_zero(&sk_listener->sk_refcnt))) {
			kmem_cache_free(ops->slab, req);
			return NULL;
		}
		req->rsk_listener = sk_listener;
	}
	req->rsk_ops = ops;
	req_to_sk(req)->sk_prot = sk_listener->sk_prot;
	sk_node_init(&req_to_sk(req)->sk_node);
	sk_tx_queue_clear(req_to_sk(req));
	req->saved_syn = NULL;
	req->syncookie = 0;
	req->timeout = 0;
	req->num_timeout = 0;
	req->num_retrans = 0;
	req->sk = NULL;
	refcount_set(&req->rsk_refcnt, 0);

	return req;
}
#define reqsk_alloc(...)	alloc_hooks(reqsk_alloc_noprof(__VA_ARGS__))

struct request_sock *inet_reqsk_alloc(const struct request_sock_ops *ops,
				      struct sock *sk_listener,
				      bool attach_listener)
{
	struct request_sock *req = reqsk_alloc(ops, sk_listener,
					       attach_listener);

	if (req) {
		struct inet_request_sock *ireq = inet_rsk(req);

		ireq->ireq_opt = NULL;
#if IS_ENABLED(CONFIG_IPV6)
		ireq->pktopts = NULL;
#endif
		atomic64_set(&ireq->ir_cookie, 0);
		ireq->ireq_state = TCP_NEW_SYN_RECV;
		write_pnet(&ireq->ireq_net, sock_net(sk_listener));
		ireq->ireq_family = sk_listener->sk_family;
		req->timeout = TCP_TIMEOUT_INIT;
	}

	return req;
}
EXPORT_SYMBOL(inet_reqsk_alloc);

static struct request_sock *inet_reqsk_clone(struct request_sock *req,
					     struct sock *sk)
{
	struct sock *req_sk, *nreq_sk;
	struct request_sock *nreq;

	nreq = kmem_cache_alloc(req->rsk_ops->slab, GFP_ATOMIC | __GFP_NOWARN);
	if (!nreq) {
		__NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPMIGRATEREQFAILURE);

		/* paired with refcount_inc_not_zero() in reuseport_migrate_sock() */
		sock_put(sk);
		return NULL;
	}

	req_sk = req_to_sk(req);
	nreq_sk = req_to_sk(nreq);

	memcpy(nreq_sk, req_sk,
	       offsetof(struct sock, sk_dontcopy_begin));
	unsafe_memcpy(&nreq_sk->sk_dontcopy_end, &req_sk->sk_dontcopy_end,
		      req->rsk_ops->obj_size - offsetof(struct sock, sk_dontcopy_end),
		      /* alloc is larger than struct, see above */);

	sk_node_init(&nreq_sk->sk_node);
	nreq_sk->sk_tx_queue_mapping = req_sk->sk_tx_queue_mapping;
#ifdef CONFIG_SOCK_RX_QUEUE_MAPPING
	nreq_sk->sk_rx_queue_mapping = req_sk->sk_rx_queue_mapping;
#endif
	nreq_sk->sk_incoming_cpu = req_sk->sk_incoming_cpu;

	nreq->rsk_listener = sk;

	/* We need not acquire fastopenq->lock
	 * because the child socket is locked in inet_csk_listen_stop().
	 */
	if (sk->sk_protocol == IPPROTO_TCP && tcp_rsk(nreq)->tfo_listener)
		rcu_assign_pointer(tcp_sk(nreq->sk)->fastopen_rsk, nreq);

	return nreq;
}

static void reqsk_queue_migrated(struct request_sock_queue *queue,
				 const struct request_sock *req)
{
	if (req->num_timeout == 0)
		atomic_inc(&queue->young);
	atomic_inc(&queue->qlen);
}

static void reqsk_migrate_reset(struct request_sock *req)
{
	req->saved_syn = NULL;
#if IS_ENABLED(CONFIG_IPV6)
	inet_rsk(req)->ipv6_opt = NULL;
	inet_rsk(req)->pktopts = NULL;
#else
	inet_rsk(req)->ireq_opt = NULL;
#endif
}

/* return true if req was found in the ehash table */
static bool reqsk_queue_unlink(struct request_sock *req)
{
	struct sock *sk = req_to_sk(req);
	bool found = false;

	if (sk_hashed(sk)) {
		struct inet_hashinfo *hashinfo = tcp_get_hashinfo(sk);
		spinlock_t *lock;

		lock = inet_ehash_lockp(hashinfo, req->rsk_hash);
		spin_lock(lock);
		found = __sk_nulls_del_node_init_rcu(sk);
		spin_unlock(lock);
	}

	return found;
}

static bool __inet_csk_reqsk_queue_drop(struct sock *sk,
					struct request_sock *req,
					bool from_timer)
{
	bool unlinked = reqsk_queue_unlink(req);

	if (!from_timer && timer_delete_sync(&req->rsk_timer))
		reqsk_put(req);

	if (unlinked) {
		reqsk_queue_removed(&inet_csk(sk)->icsk_accept_queue, req);
		reqsk_put(req);
	}

	return unlinked;
}

bool inet_csk_reqsk_queue_drop(struct sock *sk, struct request_sock *req)
{
	return __inet_csk_reqsk_queue_drop(sk, req, false);
}

void inet_csk_reqsk_queue_drop_and_put(struct sock *sk, struct request_sock *req)
{
	inet_csk_reqsk_queue_drop(sk, req);
	reqsk_put(req);
}
EXPORT_IPV6_MOD(inet_csk_reqsk_queue_drop_and_put);

static void reqsk_timer_handler(struct timer_list *t)
{
	struct request_sock *req = timer_container_of(req, t, rsk_timer);
	struct request_sock *nreq = NULL, *oreq = req;
	struct sock *sk_listener = req->rsk_listener;
	struct inet_connection_sock *icsk;
	struct request_sock_queue *queue;
	struct net *net;
	int max_syn_ack_retries, qlen, expire = 0, resend = 0;

	if (inet_sk_state_load(sk_listener) != TCP_LISTEN) {
		struct sock *nsk;

		nsk = reuseport_migrate_sock(sk_listener, req_to_sk(req), NULL);
		if (!nsk)
			goto drop;

		nreq = inet_reqsk_clone(req, nsk);
		if (!nreq)
			goto drop;

		/* The new timer for the cloned req can decrease the 2
		 * by calling inet_csk_reqsk_queue_drop_and_put(), so
		 * hold another count to prevent use-after-free and
		 * call reqsk_put() just before return.
		 */
		refcount_set(&nreq->rsk_refcnt, 2 + 1);
		timer_setup(&nreq->rsk_timer, reqsk_timer_handler, TIMER_PINNED);
		reqsk_queue_migrated(&inet_csk(nsk)->icsk_accept_queue, req);

		req = nreq;
		sk_listener = nsk;
	}

	icsk = inet_csk(sk_listener);
	net = sock_net(sk_listener);
	max_syn_ack_retries = READ_ONCE(icsk->icsk_syn_retries) ? :
		READ_ONCE(net->ipv4.sysctl_tcp_synack_retries);
	/* Normally all the openreqs are young and become mature
	 * (i.e. converted to established socket) for first timeout.
	 * If synack was not acknowledged for 1 second, it means
	 * one of the following things: synack was lost, ack was lost,
	 * rtt is high or nobody planned to ack (i.e. synflood).
	 * When server is a bit loaded, queue is populated with old
	 * open requests, reducing effective size of queue.
	 * When server is well loaded, queue size reduces to zero
	 * after several minutes of work. It is not synflood,
	 * it is normal operation. The solution is pruning
	 * too old entries overriding normal timeout, when
	 * situation becomes dangerous.
	 *
	 * Essentially, we reserve half of room for young
	 * embrions; and abort old ones without pity, if old
	 * ones are about to clog our table.
	 */
	queue = &icsk->icsk_accept_queue;
	qlen = reqsk_queue_len(queue);
	if ((qlen << 1) > max(8U, READ_ONCE(sk_listener->sk_max_ack_backlog))) {
		int young = reqsk_queue_len_young(queue) << 1;

		while (max_syn_ack_retries > 2) {
			if (qlen < young)
				break;
			max_syn_ack_retries--;
			young <<= 1;
		}
	}
	syn_ack_recalc(req, max_syn_ack_retries, READ_ONCE(queue->rskq_defer_accept),
		       &expire, &resend);
	req->rsk_ops->syn_ack_timeout(req);
	if (!expire &&
	    (!resend ||
	     !tcp_rtx_synack(sk_listener, req) ||
	     inet_rsk(req)->acked)) {
		if (req->num_timeout++ == 0)
			atomic_dec(&queue->young);
		mod_timer(&req->rsk_timer, jiffies + reqsk_timeout(req, TCP_RTO_MAX));

		if (!nreq)
			return;

		if (!inet_ehash_insert(req_to_sk(nreq), req_to_sk(oreq), NULL)) {
			/* delete timer */
			__inet_csk_reqsk_queue_drop(sk_listener, nreq, true);
			goto no_ownership;
		}

		__NET_INC_STATS(net, LINUX_MIB_TCPMIGRATEREQSUCCESS);
		reqsk_migrate_reset(oreq);
		reqsk_queue_removed(&inet_csk(oreq->rsk_listener)->icsk_accept_queue, oreq);
		reqsk_put(oreq);

		reqsk_put(nreq);
		return;
	}

	/* Even if we can clone the req, we may need not retransmit any more
	 * SYN+ACKs (nreq->num_timeout > max_syn_ack_retries, etc), or another
	 * CPU may win the "own_req" race so that inet_ehash_insert() fails.
	 */
	if (nreq) {
		__NET_INC_STATS(net, LINUX_MIB_TCPMIGRATEREQFAILURE);
no_ownership:
		reqsk_migrate_reset(nreq);
		reqsk_queue_removed(queue, nreq);
		__reqsk_free(nreq);
	}

drop:
	__inet_csk_reqsk_queue_drop(sk_listener, oreq, true);
	reqsk_put(oreq);
}

static bool reqsk_queue_hash_req(struct request_sock *req,
				 unsigned long timeout)
{
	bool found_dup_sk = false;

	if (!inet_ehash_insert(req_to_sk(req), NULL, &found_dup_sk))
		return false;

	/* The timer needs to be setup after a successful insertion. */
	timer_setup(&req->rsk_timer, reqsk_timer_handler, TIMER_PINNED);
	mod_timer(&req->rsk_timer, jiffies + timeout);

	/* before letting lookups find us, make sure all req fields
	 * are committed to memory and refcnt initialized.
	 */
	smp_wmb();
	refcount_set(&req->rsk_refcnt, 2 + 1);
	return true;
}

bool inet_csk_reqsk_queue_hash_add(struct sock *sk, struct request_sock *req,
				   unsigned long timeout)
{
	if (!reqsk_queue_hash_req(req, timeout))
		return false;

	inet_csk_reqsk_queue_added(sk);
	return true;
}

static void inet_clone_ulp(const struct request_sock *req, struct sock *newsk,
			   const gfp_t priority)
{
	struct inet_connection_sock *icsk = inet_csk(newsk);

	if (!icsk->icsk_ulp_ops)
		return;

	icsk->icsk_ulp_ops->clone(req, newsk, priority);
}

/**
 *	inet_csk_clone_lock - clone an inet socket, and lock its clone
 *	@sk: the socket to clone
 *	@req: request_sock
 *	@priority: for allocation (%GFP_KERNEL, %GFP_ATOMIC, etc)
 *
 *	Caller must unlock socket even in error path (bh_unlock_sock(newsk))
 */
struct sock *inet_csk_clone_lock(const struct sock *sk,
				 const struct request_sock *req,
				 const gfp_t priority)
{
	struct sock *newsk = sk_clone_lock(sk, priority);
	struct inet_connection_sock *newicsk;
	struct inet_request_sock *ireq;
	struct inet_sock *newinet;

	if (!newsk)
		return NULL;

	newicsk = inet_csk(newsk);
	newinet = inet_sk(newsk);
	ireq = inet_rsk(req);

	newicsk->icsk_bind_hash = NULL;
	newicsk->icsk_bind2_hash = NULL;

	newinet->inet_dport = ireq->ir_rmt_port;
	newinet->inet_num = ireq->ir_num;
	newinet->inet_sport = htons(ireq->ir_num);

	newsk->sk_bound_dev_if = ireq->ir_iif;

	newsk->sk_daddr = ireq->ir_rmt_addr;
	newsk->sk_rcv_saddr = ireq->ir_loc_addr;
	newinet->inet_saddr = ireq->ir_loc_addr;

#if IS_ENABLED(CONFIG_IPV6)
	newsk->sk_v6_daddr = ireq->ir_v6_rmt_addr;
	newsk->sk_v6_rcv_saddr = ireq->ir_v6_loc_addr;
#endif

	/* listeners have SOCK_RCU_FREE, not the children */
	sock_reset_flag(newsk, SOCK_RCU_FREE);

	inet_sk(newsk)->mc_list = NULL;

	newsk->sk_mark = inet_rsk(req)->ir_mark;
	atomic64_set(&newsk->sk_cookie,
		     atomic64_read(&inet_rsk(req)->ir_cookie));

	newicsk->icsk_retransmits = 0;
	newicsk->icsk_backoff	  = 0;
	newicsk->icsk_probes_out  = 0;
	newicsk->icsk_probes_tstamp = 0;

	/* Deinitialize accept_queue to trap illegal accesses. */
	memset(&newicsk->icsk_accept_queue, 0,
	       sizeof(newicsk->icsk_accept_queue));

	inet_sk_set_state(newsk, TCP_SYN_RECV);

	inet_clone_ulp(req, newsk, priority);

	security_inet_csk_clone(newsk, req);

	return newsk;
}

/*
 * At this point, there should be no process reference to this
 * socket, and thus no user references at all.  Therefore we
 * can assume the socket waitqueue is inactive and nobody will
 * try to jump onto it.
 */
void inet_csk_destroy_sock(struct sock *sk)
{
	WARN_ON(sk->sk_state != TCP_CLOSE);
	WARN_ON(!sock_flag(sk, SOCK_DEAD));

	/* It cannot be in hash table! */
	WARN_ON(!sk_unhashed(sk));

	/* If it has not 0 inet_sk(sk)->inet_num, it must be bound */
	WARN_ON(inet_sk(sk)->inet_num && !inet_csk(sk)->icsk_bind_hash);

	sk->sk_prot->destroy(sk);

	sk_stream_kill_queues(sk);

	xfrm_sk_free_policy(sk);

	this_cpu_dec(*sk->sk_prot->orphan_count);

	sock_put(sk);
}
EXPORT_SYMBOL(inet_csk_destroy_sock);

/* This function allows to force a closure of a socket after the call to
 * tcp_create_openreq_child().
 */
void inet_csk_prepare_forced_close(struct sock *sk)
	__releases(&sk->sk_lock.slock)
{
	/* sk_clone_lock locked the socket and set refcnt to 2 */
	bh_unlock_sock(sk);
	sock_put(sk);
	inet_csk_prepare_for_destroy_sock(sk);
	inet_sk(sk)->inet_num = 0;
}
EXPORT_SYMBOL(inet_csk_prepare_forced_close);

static int inet_ulp_can_listen(const struct sock *sk)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);

	if (icsk->icsk_ulp_ops && !icsk->icsk_ulp_ops->clone)
		return -EINVAL;

	return 0;
}

int inet_csk_listen_start(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct inet_sock *inet = inet_sk(sk);
	int err;

	err = inet_ulp_can_listen(sk);
	if (unlikely(err))
		return err;

	reqsk_queue_alloc(&icsk->icsk_accept_queue);

	sk->sk_ack_backlog = 0;
	inet_csk_delack_init(sk);

	/* There is race window here: we announce ourselves listening,
	 * but this transition is still not validated by get_port().
	 * It is OK, because this socket enters to hash table only
	 * after validation is complete.
	 */
	inet_sk_state_store(sk, TCP_LISTEN);
	err = sk->sk_prot->get_port(sk, inet->inet_num);
	if (!err) {
		inet->inet_sport = htons(inet->inet_num);

		sk_dst_reset(sk);
		err = sk->sk_prot->hash(sk);

		if (likely(!err))
			return 0;
	}

	inet_sk_set_state(sk, TCP_CLOSE);
	return err;
}

static void inet_child_forget(struct sock *sk, struct request_sock *req,
			      struct sock *child)
{
	sk->sk_prot->disconnect(child, O_NONBLOCK);

	sock_orphan(child);

	this_cpu_inc(*sk->sk_prot->orphan_count);

	if (sk->sk_protocol == IPPROTO_TCP && tcp_rsk(req)->tfo_listener) {
		BUG_ON(rcu_access_pointer(tcp_sk(child)->fastopen_rsk) != req);
		BUG_ON(sk != req->rsk_listener);

		/* Paranoid, to prevent race condition if
		 * an inbound pkt destined for child is
		 * blocked by sock lock in tcp_v4_rcv().
		 * Also to satisfy an assertion in
		 * tcp_v4_destroy_sock().
		 */
		RCU_INIT_POINTER(tcp_sk(child)->fastopen_rsk, NULL);
	}
	inet_csk_destroy_sock(child);
}

struct sock *inet_csk_reqsk_queue_add(struct sock *sk,
				      struct request_sock *req,
				      struct sock *child)
{
	struct request_sock_queue *queue = &inet_csk(sk)->icsk_accept_queue;

	spin_lock(&queue->rskq_lock);
	if (unlikely(sk->sk_state != TCP_LISTEN)) {
		inet_child_forget(sk, req, child);
		child = NULL;
	} else {
		req->sk = child;
		req->dl_next = NULL;
		if (queue->rskq_accept_head == NULL)
			WRITE_ONCE(queue->rskq_accept_head, req);
		else
			queue->rskq_accept_tail->dl_next = req;
		queue->rskq_accept_tail = req;
		sk_acceptq_added(sk);
	}
	spin_unlock(&queue->rskq_lock);
	return child;
}
EXPORT_SYMBOL(inet_csk_reqsk_queue_add);

struct sock *inet_csk_complete_hashdance(struct sock *sk, struct sock *child,
					 struct request_sock *req, bool own_req)
{
	if (own_req) {
		inet_csk_reqsk_queue_drop(req->rsk_listener, req);
		reqsk_queue_removed(&inet_csk(req->rsk_listener)->icsk_accept_queue, req);

		if (sk != req->rsk_listener) {
			/* another listening sk has been selected,
			 * migrate the req to it.
			 */
			struct request_sock *nreq;

			/* hold a refcnt for the nreq->rsk_listener
			 * which is assigned in inet_reqsk_clone()
			 */
			sock_hold(sk);
			nreq = inet_reqsk_clone(req, sk);
			if (!nreq) {
				inet_child_forget(sk, req, child);
				goto child_put;
			}

			refcount_set(&nreq->rsk_refcnt, 1);
			if (inet_csk_reqsk_queue_add(sk, nreq, child)) {
				__NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPMIGRATEREQSUCCESS);
				reqsk_migrate_reset(req);
				reqsk_put(req);
				return child;
			}

			__NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPMIGRATEREQFAILURE);
			reqsk_migrate_reset(nreq);
			__reqsk_free(nreq);
		} else if (inet_csk_reqsk_queue_add(sk, req, child)) {
			return child;
		}
	}
	/* Too bad, another child took ownership of the request, undo. */
child_put:
	bh_unlock_sock(child);
	sock_put(child);
	return NULL;
}

/*
 *	This routine closes sockets which have been at least partially
 *	opened, but not yet accepted.
 */
void inet_csk_listen_stop(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct request_sock_queue *queue = &icsk->icsk_accept_queue;
	struct request_sock *next, *req;

	/* Following specs, it would be better either to send FIN
	 * (and enter FIN-WAIT-1, it is normal close)
	 * or to send active reset (abort).
	 * Certainly, it is pretty dangerous while synflood, but it is
	 * bad justification for our negligence 8)
	 * To be honest, we are not able to make either
	 * of the variants now.			--ANK
	 */
	while ((req = reqsk_queue_remove(queue, sk)) != NULL) {
		struct sock *child = req->sk, *nsk;
		struct request_sock *nreq;

		local_bh_disable();
		bh_lock_sock(child);
		WARN_ON(sock_owned_by_user(child));
		sock_hold(child);

		nsk = reuseport_migrate_sock(sk, child, NULL);
		if (nsk) {
			nreq = inet_reqsk_clone(req, nsk);
			if (nreq) {
				refcount_set(&nreq->rsk_refcnt, 1);

				if (inet_csk_reqsk_queue_add(nsk, nreq, child)) {
					__NET_INC_STATS(sock_net(nsk),
							LINUX_MIB_TCPMIGRATEREQSUCCESS);
					reqsk_migrate_reset(req);
				} else {
					__NET_INC_STATS(sock_net(nsk),
							LINUX_MIB_TCPMIGRATEREQFAILURE);
					reqsk_migrate_reset(nreq);
					__reqsk_free(nreq);
				}

				/* inet_csk_reqsk_queue_add() has already
				 * called inet_child_forget() on failure case.
				 */
				goto skip_child_forget;
			}
		}

		inet_child_forget(sk, req, child);
skip_child_forget:
		reqsk_put(req);
		bh_unlock_sock(child);
		local_bh_enable();
		sock_put(child);

		cond_resched();
	}
	if (queue->fastopenq.rskq_rst_head) {
		/* Free all the reqs queued in rskq_rst_head. */
		spin_lock_bh(&queue->fastopenq.lock);
		req = queue->fastopenq.rskq_rst_head;
		queue->fastopenq.rskq_rst_head = NULL;
		spin_unlock_bh(&queue->fastopenq.lock);
		while (req != NULL) {
			next = req->dl_next;
			reqsk_put(req);
			req = next;
		}
	}
	WARN_ON_ONCE(sk->sk_ack_backlog);
}
EXPORT_SYMBOL_GPL(inet_csk_listen_stop);

static struct dst_entry *inet_csk_rebuild_route(struct sock *sk, struct flowi *fl)
{
	const struct inet_sock *inet = inet_sk(sk);
	struct flowi4 *fl4;
	struct rtable *rt;

	rcu_read_lock();
	fl4 = &fl->u.ip4;
	inet_sk_init_flowi4(inet, fl4);
	rt = ip_route_output_flow(sock_net(sk), fl4, sk);
	if (IS_ERR(rt))
		rt = NULL;
	if (rt)
		sk_setup_caps(sk, &rt->dst);
	rcu_read_unlock();

	return &rt->dst;
}

struct dst_entry *inet_csk_update_pmtu(struct sock *sk, u32 mtu)
{
	struct dst_entry *dst = __sk_dst_check(sk, 0);
	struct inet_sock *inet = inet_sk(sk);

	if (!dst) {
		dst = inet_csk_rebuild_route(sk, &inet->cork.fl);
		if (!dst)
			goto out;
	}
	dst->ops->update_pmtu(dst, sk, NULL, mtu, true);

	dst = __sk_dst_check(sk, 0);
	if (!dst)
		dst = inet_csk_rebuild_route(sk, &inet->cork.fl);
out:
	return dst;
}
