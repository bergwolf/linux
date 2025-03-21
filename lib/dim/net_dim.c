// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2018, Mellanox Technologies inc.  All rights reserved.
 */

#include <linux/dim.h>
#include <linux/rtnetlink.h>

/*
 * Net DIM profiles:
 *        There are different set of profiles for each CQ period mode.
 *        There are different set of profiles for RX/TX CQs.
 *        Each profile size must be of NET_DIM_PARAMS_NUM_PROFILES
 */
#define NET_DIM_RX_EQE_PROFILES { \
	{.usec = 1,   .pkts = NET_DIM_DEFAULT_RX_CQ_PKTS_FROM_EQE,}, \
	{.usec = 8,   .pkts = NET_DIM_DEFAULT_RX_CQ_PKTS_FROM_EQE,}, \
	{.usec = 64,  .pkts = NET_DIM_DEFAULT_RX_CQ_PKTS_FROM_EQE,}, \
	{.usec = 128, .pkts = NET_DIM_DEFAULT_RX_CQ_PKTS_FROM_EQE,}, \
	{.usec = 256, .pkts = NET_DIM_DEFAULT_RX_CQ_PKTS_FROM_EQE,}  \
}

#define NET_DIM_RX_CQE_PROFILES { \
	{.usec = 2,  .pkts = 256,},             \
	{.usec = 8,  .pkts = 128,},             \
	{.usec = 16, .pkts = 64,},              \
	{.usec = 32, .pkts = 64,},              \
	{.usec = 64, .pkts = 64,}               \
}

#define NET_DIM_TX_EQE_PROFILES { \
	{.usec = 1,   .pkts = NET_DIM_DEFAULT_TX_CQ_PKTS_FROM_EQE,},  \
	{.usec = 8,   .pkts = NET_DIM_DEFAULT_TX_CQ_PKTS_FROM_EQE,},  \
	{.usec = 32,  .pkts = NET_DIM_DEFAULT_TX_CQ_PKTS_FROM_EQE,},  \
	{.usec = 64,  .pkts = NET_DIM_DEFAULT_TX_CQ_PKTS_FROM_EQE,},  \
	{.usec = 128, .pkts = NET_DIM_DEFAULT_TX_CQ_PKTS_FROM_EQE,}   \
}

#define NET_DIM_TX_CQE_PROFILES { \
	{.usec = 5,  .pkts = 128,},  \
	{.usec = 8,  .pkts = 64,},  \
	{.usec = 16, .pkts = 32,},  \
	{.usec = 32, .pkts = 32,},  \
	{.usec = 64, .pkts = 32,}   \
}

static const struct dim_cq_moder
rx_profile[DIM_CQ_PERIOD_NUM_MODES][NET_DIM_PARAMS_NUM_PROFILES] = {
	NET_DIM_RX_EQE_PROFILES,
	NET_DIM_RX_CQE_PROFILES,
};

static const struct dim_cq_moder
tx_profile[DIM_CQ_PERIOD_NUM_MODES][NET_DIM_PARAMS_NUM_PROFILES] = {
	NET_DIM_TX_EQE_PROFILES,
	NET_DIM_TX_CQE_PROFILES,
};

struct dim_cq_moder
net_dim_get_rx_moderation(u8 cq_period_mode, int ix)
{
	struct dim_cq_moder cq_moder = rx_profile[cq_period_mode][ix];

	cq_moder.cq_period_mode = cq_period_mode;
	return cq_moder;
}
EXPORT_SYMBOL(net_dim_get_rx_moderation);

struct dim_cq_moder
net_dim_get_def_rx_moderation(u8 cq_period_mode)
{
	u8 profile_ix = cq_period_mode == DIM_CQ_PERIOD_MODE_START_FROM_CQE ?
			NET_DIM_DEF_PROFILE_CQE : NET_DIM_DEF_PROFILE_EQE;

	return net_dim_get_rx_moderation(cq_period_mode, profile_ix);
}
EXPORT_SYMBOL(net_dim_get_def_rx_moderation);

struct dim_cq_moder
net_dim_get_tx_moderation(u8 cq_period_mode, int ix)
{
	struct dim_cq_moder cq_moder = tx_profile[cq_period_mode][ix];

	cq_moder.cq_period_mode = cq_period_mode;
	return cq_moder;
}
EXPORT_SYMBOL(net_dim_get_tx_moderation);

struct dim_cq_moder
net_dim_get_def_tx_moderation(u8 cq_period_mode)
{
	u8 profile_ix = cq_period_mode == DIM_CQ_PERIOD_MODE_START_FROM_CQE ?
			NET_DIM_DEF_PROFILE_CQE : NET_DIM_DEF_PROFILE_EQE;

	return net_dim_get_tx_moderation(cq_period_mode, profile_ix);
}
EXPORT_SYMBOL(net_dim_get_def_tx_moderation);

int net_dim_init_irq_moder(struct net_device *dev, u8 profile_flags,
			   u8 coal_flags, u8 rx_mode, u8 tx_mode,
			   void (*rx_dim_work)(struct work_struct *work),
			   void (*tx_dim_work)(struct work_struct *work))
{
	struct dim_cq_moder *rxp = NULL, *txp;
	struct dim_irq_moder *moder;
	int len;

	dev->irq_moder = kzalloc(sizeof(*dev->irq_moder), GFP_KERNEL);
	if (!dev->irq_moder)
		return -ENOMEM;

	moder = dev->irq_moder;
	len = NET_DIM_PARAMS_NUM_PROFILES * sizeof(*moder->rx_profile);

	moder->coal_flags = coal_flags;
	moder->profile_flags = profile_flags;

	if (profile_flags & DIM_PROFILE_RX) {
		moder->rx_dim_work = rx_dim_work;
		moder->dim_rx_mode = rx_mode;
		rxp = kmemdup(rx_profile[rx_mode], len, GFP_KERNEL);
		if (!rxp)
			goto free_moder;

		rcu_assign_pointer(moder->rx_profile, rxp);
	}

	if (profile_flags & DIM_PROFILE_TX) {
		moder->tx_dim_work = tx_dim_work;
		moder->dim_tx_mode = tx_mode;
		txp = kmemdup(tx_profile[tx_mode], len, GFP_KERNEL);
		if (!txp)
			goto free_rxp;

		rcu_assign_pointer(moder->tx_profile, txp);
	}

	return 0;

free_rxp:
	kfree(rxp);
free_moder:
	kfree(moder);
	return -ENOMEM;
}
EXPORT_SYMBOL(net_dim_init_irq_moder);

/* RTNL lock is held. */
void net_dim_free_irq_moder(struct net_device *dev)
{
	struct dim_cq_moder *rxp, *txp;

	if (!dev->irq_moder)
		return;

	rxp = rtnl_dereference(dev->irq_moder->rx_profile);
	txp = rtnl_dereference(dev->irq_moder->tx_profile);

	rcu_assign_pointer(dev->irq_moder->rx_profile, NULL);
	rcu_assign_pointer(dev->irq_moder->tx_profile, NULL);

	kfree_rcu(rxp, rcu);
	kfree_rcu(txp, rcu);
	kfree(dev->irq_moder);
}
EXPORT_SYMBOL(net_dim_free_irq_moder);

void net_dim_setting(struct net_device *dev, struct dim *dim, bool is_tx)
{
	struct dim_irq_moder *irq_moder = dev->irq_moder;

	if (!irq_moder)
		return;

	if (is_tx) {
		INIT_WORK(&dim->work, irq_moder->tx_dim_work);
		dim->mode = READ_ONCE(irq_moder->dim_tx_mode);
		return;
	}

	INIT_WORK(&dim->work, irq_moder->rx_dim_work);
	dim->mode = READ_ONCE(irq_moder->dim_rx_mode);
}
EXPORT_SYMBOL(net_dim_setting);

void net_dim_work_cancel(struct dim *dim)
{
	cancel_work_sync(&dim->work);
}
EXPORT_SYMBOL(net_dim_work_cancel);

struct dim_cq_moder net_dim_get_rx_irq_moder(struct net_device *dev,
					     struct dim *dim)
{
	struct dim_cq_moder res, *profile;

	rcu_read_lock();
	profile = rcu_dereference(dev->irq_moder->rx_profile);
	res = profile[dim->profile_ix];
	rcu_read_unlock();

	res.cq_period_mode = dim->mode;

	return res;
}
EXPORT_SYMBOL(net_dim_get_rx_irq_moder);

struct dim_cq_moder net_dim_get_tx_irq_moder(struct net_device *dev,
					     struct dim *dim)
{
	struct dim_cq_moder res, *profile;

	rcu_read_lock();
	profile = rcu_dereference(dev->irq_moder->tx_profile);
	res = profile[dim->profile_ix];
	rcu_read_unlock();

	res.cq_period_mode = dim->mode;

	return res;
}
EXPORT_SYMBOL(net_dim_get_tx_irq_moder);

void net_dim_set_rx_mode(struct net_device *dev, u8 rx_mode)
{
	WRITE_ONCE(dev->irq_moder->dim_rx_mode, rx_mode);
}
EXPORT_SYMBOL(net_dim_set_rx_mode);

void net_dim_set_tx_mode(struct net_device *dev, u8 tx_mode)
{
	WRITE_ONCE(dev->irq_moder->dim_tx_mode, tx_mode);
}
EXPORT_SYMBOL(net_dim_set_tx_mode);

static int net_dim_step(struct dim *dim)
{
	if (dim->tired == (NET_DIM_PARAMS_NUM_PROFILES * 2))
		return DIM_TOO_TIRED;

	switch (dim->tune_state) {
	case DIM_PARKING_ON_TOP:
	case DIM_PARKING_TIRED:
		break;
	case DIM_GOING_RIGHT:
		if (dim->profile_ix == (NET_DIM_PARAMS_NUM_PROFILES - 1))
			return DIM_ON_EDGE;
		dim->profile_ix++;
		dim->steps_right++;
		break;
	case DIM_GOING_LEFT:
		if (dim->profile_ix == 0)
			return DIM_ON_EDGE;
		dim->profile_ix--;
		dim->steps_left++;
		break;
	}

	dim->tired++;
	return DIM_STEPPED;
}

static void net_dim_exit_parking(struct dim *dim)
{
	dim->tune_state = dim->profile_ix ? DIM_GOING_LEFT : DIM_GOING_RIGHT;
	net_dim_step(dim);
}

static int net_dim_stats_compare(struct dim_stats *curr,
				 struct dim_stats *prev)
{
	if (!prev->bpms)
		return curr->bpms ? DIM_STATS_BETTER : DIM_STATS_SAME;

	if (IS_SIGNIFICANT_DIFF(curr->bpms, prev->bpms))
		return (curr->bpms > prev->bpms) ? DIM_STATS_BETTER :
						   DIM_STATS_WORSE;

	if (!prev->ppms)
		return curr->ppms ? DIM_STATS_BETTER :
				    DIM_STATS_SAME;

	if (IS_SIGNIFICANT_DIFF(curr->ppms, prev->ppms))
		return (curr->ppms > prev->ppms) ? DIM_STATS_BETTER :
						   DIM_STATS_WORSE;

	if (!prev->epms)
		return DIM_STATS_SAME;

	if (IS_SIGNIFICANT_DIFF(curr->epms, prev->epms))
		return (curr->epms < prev->epms) ? DIM_STATS_BETTER :
						   DIM_STATS_WORSE;

	return DIM_STATS_SAME;
}

static bool net_dim_decision(struct dim_stats *curr_stats, struct dim *dim)
{
	int prev_state = dim->tune_state;
	int prev_ix = dim->profile_ix;
	int stats_res;
	int step_res;

	switch (dim->tune_state) {
	case DIM_PARKING_ON_TOP:
		stats_res = net_dim_stats_compare(curr_stats,
						  &dim->prev_stats);
		if (stats_res != DIM_STATS_SAME)
			net_dim_exit_parking(dim);
		break;

	case DIM_PARKING_TIRED:
		dim->tired--;
		if (!dim->tired)
			net_dim_exit_parking(dim);
		break;

	case DIM_GOING_RIGHT:
	case DIM_GOING_LEFT:
		stats_res = net_dim_stats_compare(curr_stats,
						  &dim->prev_stats);
		if (stats_res != DIM_STATS_BETTER)
			dim_turn(dim);

		if (dim_on_top(dim)) {
			dim_park_on_top(dim);
			break;
		}

		step_res = net_dim_step(dim);
		switch (step_res) {
		case DIM_ON_EDGE:
			dim_park_on_top(dim);
			break;
		case DIM_TOO_TIRED:
			dim_park_tired(dim);
			break;
		}

		break;
	}

	if (prev_state != DIM_PARKING_ON_TOP ||
	    dim->tune_state != DIM_PARKING_ON_TOP)
		dim->prev_stats = *curr_stats;

	return dim->profile_ix != prev_ix;
}

void net_dim(struct dim *dim, const struct dim_sample *end_sample)
{
	struct dim_stats curr_stats;
	u16 nevents;

	switch (dim->state) {
	case DIM_MEASURE_IN_PROGRESS:
		nevents = BIT_GAP(BITS_PER_TYPE(u16),
				  end_sample->event_ctr,
				  dim->start_sample.event_ctr);
		if (nevents < DIM_NEVENTS)
			break;
		if (!dim_calc_stats(&dim->start_sample, end_sample, &curr_stats))
			break;
		if (net_dim_decision(&curr_stats, dim)) {
			dim->state = DIM_APPLY_NEW_PROFILE;
			schedule_work(&dim->work);
			break;
		}
		fallthrough;
	case DIM_START_MEASURE:
		dim_update_sample(end_sample->event_ctr, end_sample->pkt_ctr,
				  end_sample->byte_ctr, &dim->start_sample);
		dim->state = DIM_MEASURE_IN_PROGRESS;
		break;
	case DIM_APPLY_NEW_PROFILE:
		break;
	}
}
EXPORT_SYMBOL(net_dim);
