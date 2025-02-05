// SPDX-License-Identifier: GPL-2.0
/* Original xdp_fwd sample Copyright (c) 2017-18 David Ahern <dsahern@gmail.com>
 */

#include <bpf/vmlinux.h>
#include <linux/bpf.h>
#include <stdbool.h>
#include <linux/errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <xdp/parsing_helpers.h>

#include "xdp-forward.h"

#define DEBUG_PRINT 1 // Set to 1 for debugging, 0 to disable bpf_printk

#if DEBUG_PRINT
#define debug_printk(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
#define debug_printk(fmt, ...)
#endif

#define AF_INET	2
#define AF_INET6	10

#define IPV6_FLOWINFO_MASK              bpf_htons(0x0FFFFFFF)
#define CLOCK_MONOTONIC			1
#define META_COOKIE_VAL 0x4242424242424242UL

#define MAX_TX_PORTS 64
#define TX_BATCH_SIZE 256

#define IFINDEX_MASK 0xFFFFFFFF
#define STATE_KEY(cpu, ifindex) (((__u64)cpu << 32) + ifindex)

#define PORT_QUEUE_THRESHOLD (1024 * 1024 * 1024)

#define BPF_MAP_TYPE_XDP_FIFO 36

#define MAP_PTR(map) ((struct bpf_map *)&map)

/* DQL: Define static maximums and some operations */
#define HZ 1000
// #define JIFFIES (bpf_ktime_get_ns() / (1000000000 / HZ))
#define JIFFIES (bpf_jiffies64())
#define U32_MAX ((__u32) -1)

#define POSDIFF(A, B) ((A) > (B) ? (A) - (B) : 0)
#define AFTER_EQ(A, B) ((__s32)((A) - (B)) >= 0)
#define MAX(A,B) (A > B ? A : B)

#define DQL_MAX_OBJECT (U32_MAX / 16)
#define DQL_MAX_LIMIT  ((U32_MAX / 2) - DQL_MAX_OBJECT)

extern struct xdp_frame *xdp_packet_dequeue(struct bpf_map *map, __u64 flags,
                                            __u64 *rank) __ksym;
extern int xdp_packet_drop(struct xdp_frame *pkt) __ksym;
extern int xdp_packet_send(struct xdp_frame *pkt, int ifindex, __u64 flags) __ksym;
extern int xdp_packet_flush(void) __ksym;
extern int bpf_dynptr_from_xdp_frame(struct xdp_frame *xdp, __u64 flags,
                                     struct bpf_dynptr *ptr__uninit) __ksym;

struct port_state {
        __u64 outstanding_bytes;
        struct bpf_timer timer;
        __u32 tx_port_idx;

        /* DQL STATE */
        /* Fields accessed in enqueue path (dql_queued) */
        __u64	num_queued;		/* Total ever queued */
        __u64	adj_limit;		/* limit + num_completed */
        __u64	last_obj_cnt;		/* Count at last queuing */

        /* Fields accessed only by completion path (dql_completed) */

        __u64	limit;                  /* Current limit, was aligned*/
        __u64	num_completed;		/* Total ever completed */

        __u64	prev_ovlimit;		/* Previous over limit */
        __u64	prev_num_queued;	/* Previous queue total */
        __u64	prev_last_obj_cnt;	/* Previous queuing cnt */

        __u64	lowest_slack;		/* Lowest slack found */
        __u64	slack_start_time;	/* Time slacks seen */

        /* Configuration */
        __u32	max_limit;		/* Max limit */
        __u32	min_limit;		/* Minimum limit */
        __u32	slack_hold_time;	/* Time to measure slack */
};

struct meta_val {
        __u64 state_key;
        __u64 cookie;
};

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __type(key, __u64);
        __type(value, struct port_state);
        __uint(max_entries, MAX_TX_PORTS);
        __uint(pinning, LIBBPF_PIN_BY_NAME);
} dst_port_state SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_XDP_FIFO);
        __uint(key_size, sizeof(__u32));
        __uint(value_size, sizeof(__u32));
        __uint(max_entries, 10240);
        __uint(map_extra, MAX_TX_PORTS);
} xdp_queues SEC(".maps");

// TODO remove
bool time_set = false;
__u64 timer_start;
__u16 bulk_seen;

static int dql_completed(struct port_state *state, __u32 count)
{
        __u32 inprogress, prev_inprogress, limit;
	__u32 ovlimit, completed, num_queued;
	bool all_prev_completed;

	num_queued = state->num_queued;

	/* Can't complete more than what's in queue */
	if(count > num_queued - state->num_completed) {
                // debug_printk("dql_completed %d: Completing more than queued", state->tx_port_idx);
                // TODO make negative since this is an error
                return 0;
        }

	completed = state->num_completed + count;
	limit = state->limit;
	ovlimit = POSDIFF(num_queued - state->num_completed, limit);
	inprogress = num_queued - completed;
	prev_inprogress = state->prev_num_queued - state->num_completed;
	all_prev_completed = AFTER_EQ(completed, state->prev_num_queued);

        // debug_printk("dql_completed %d: ovlimit %u, inprogress %u, prev_ovlimit %u, all_prev_completed %u, prev_inprogress %u", state->tx_port_idx, ovlimit, inprogress, state->prev_ovlimit, all_prev_completed, prev_inprogress);

	if ((ovlimit && !inprogress) ||
	    (state->prev_ovlimit && all_prev_completed)) {
		/*
		 * Queue considered starved if:
		 *   - The queue was over-limit in the last interval,
		 *     and there is no more data in the queue.
		 *  OR
		 *   - The queue was over-limit in the previous interval and
		 *     when enqueuing it was possible that all queued data
		 *     had been consumed.  This covers the case when queue
		 *     may have becomes starved between completion processing
		 *     running and next time enqueue was scheduled.
		 *
		 *     When queue is starved increase the limit by the amount
		 *     of bytes both sent and completed in the last interval,
		 *     plus any previous over-limit.
		 */
		limit += POSDIFF(completed, state->prev_num_queued) +
		     state->prev_ovlimit;
                debug_printk("dql_completed %u: queue starved, new limit %u, POSDIFF %u, prev_ovlimit %u",state->tx_port_idx, limit, POSDIFF(completed, state->prev_num_queued), state->prev_ovlimit);
		state->slack_start_time = JIFFIES;
		state->lowest_slack = U32_MAX;
	} else if (inprogress && prev_inprogress && !all_prev_completed) {
		/*
		 * Queue was not starved, check if the limit can be decreased.
		 * A decrease is only considered if the queue has been busy in
		 * the whole interval (the check above).
		 *
		 * If there is slack, the amount of excess data queued above
		 * the amount needed to prevent starvation, the queue limit
		 * can be decreased.  To avoid hysteresis we consider the
		 * minimum amount of slack found over several iterations of the
		 * completion routine.
		 */
		unsigned int slack, slack_last_objs;

		/*
		 * Slack is the maximum of
		 *   - The queue limit plus previous over-limit minus twice
		 *     the number of objects completed.  Note that two times
		 *     number of completed bytes is a basis for an upper bound
		 *     of the limit.
		 *   - Portion of objects in the last queuing operation that
		 *     was not part of non-zero previous over-limit.  That is
		 *     "round down" by non-overlimit portion of the last
		 *     queueing operation.
		 */
		slack = POSDIFF(limit + state->prev_ovlimit,
		    2 * (completed - state->num_completed));
		slack_last_objs = state->prev_ovlimit ?
		    POSDIFF(state->prev_last_obj_cnt, state->prev_ovlimit) : 0;

		slack = MAX(slack, slack_last_objs);

		if (slack < state->lowest_slack)
			state->lowest_slack = slack;

                /* Check if current time past slack_start + slack_hold*/
		if ((JIFFIES >= (state->slack_start_time + state->slack_hold_time))) {
                        debug_printk("dql_completed %u: queue not starved, limit %u, lowest_slack %u",state->tx_port_idx, limit, state->lowest_slack);
			limit = POSDIFF(limit, state->lowest_slack);
                        debug_printk("dql_completed %u: queue not starved, new limit %u", state->tx_port_idx, limit);
			state->slack_start_time = JIFFIES;
			state->lowest_slack = U32_MAX;
		}
	}

	/* Enforce bounds on limit */
        /* likely branch false */
	limit = limit > state->max_limit ? state->max_limit :
                       limit < state-> min_limit ? state->min_limit : limit;

        // debug_printk("dql_completed %d: after bounds checking from %u set to %u", state->tx_port_idx, tmp, limit);

	if (limit != state->limit) {
		state->limit = limit;
		ovlimit = 0;
	}

	state->adj_limit = limit + completed;
	state->prev_ovlimit = ovlimit;
	state->prev_last_obj_cnt = state->last_obj_cnt;
	state->num_completed = completed;
	state->prev_num_queued = num_queued;

        debug_printk("dql_completed %u: limit %u, adj_limit %u, prev_num_queued %u, prev_ovlimit %u\n",
                state->tx_port_idx, limit, state->adj_limit, num_queued, ovlimit);
        
        return 0;
}

static int xdp_timer_cb(struct bpf_map *map, __u64 *key, struct bpf_timer *timer)
{
        struct port_state *state;
        struct xdp_frame *pkt;
        int i, tgt_ifindex;
        __u64 index;

        state = bpf_map_lookup_elem(map, key);
        if (!state) {
                debug_printk("xdp_timer_cb: No state found for key %lu", *key);
                goto out;
        }

        // debug_printk("xdp_timer_cb %d: key %lu", state->tx_port_idx, *key);

        index = state->tx_port_idx;
        tgt_ifindex = (*key) & IFINDEX_MASK;
        // debug_printk("xdp_timer_cb %d: tgt_ifindex %d tx_port_idx %lu", index, tgt_ifindex, index);

        // TODO check available space in tx_queue
        if(state->adj_limit < state->num_queued){
                debug_printk("forward_to_dst %u: not enough space", state->tx_port_idx);
                return XDP_DROP;
        }

        for (i = 0; i < TX_BATCH_SIZE; i++) {
                pkt = xdp_packet_dequeue(MAP_PTR(xdp_queues), index, NULL);
                if (time_set) {
                        debug_printk("xdp_timer_cb %u: callback time %u", state->tx_port_idx, bpf_ktime_get_ns() - timer_start);
                        time_set = false;
                }
                if (!pkt) {
                        debug_printk("xdp_timer_cb %u: No packet returned at iteration %d", state->tx_port_idx, i);
                        break;
                }
                // TODO remove debugging prints
                debug_printk("xdp_timer_cb: frm.len      %u", pkt->len);
                debug_printk("xdp_timer_cb: frm.headroom %u", pkt->headroom);
                debug_printk("xdp_timer_cb: frm.metasize %u", pkt->metasize);
                debug_printk("xdp_timer_cb: frm.frame_sz %u", pkt->frame_sz);
                debug_printk("xdp_timer_cb: frm.flags    %u", pkt->flags);

                // debug_printk("xdp_timer_cb %d: Sending to ifindex %d", state->tx_port_idx, tgt_ifindex),;
                xdp_packet_send(pkt, tgt_ifindex, 0);
        }

        xdp_packet_flush();

out:      
        return 0;
}

static __u32 next_port_idx = 0;

static int init_tx_port(int ifindex, __u32 cpu)
{
        __u64 state_key = STATE_KEY(cpu, ifindex);
        struct port_state *state, new_state = {};
        int ret;

        if (next_port_idx >= MAX_TX_PORTS)
                return -E2BIG;

        new_state.tx_port_idx = next_port_idx++;
        /* DQL: Initialize state */
        new_state.max_limit = DQL_MAX_LIMIT;
        // TODO: Does this min_limit make sense?
        new_state.min_limit = 0;
        new_state.adj_limit = new_state.min_limit;
        new_state.slack_hold_time = HZ;
	new_state.lowest_slack = U32_MAX;
	new_state.slack_start_time = JIFFIES;

        ret = bpf_map_update_elem(&dst_port_state, &state_key, &new_state, 0);
        if (ret)
                return ret;

        state = bpf_map_lookup_elem(&dst_port_state, &state_key);
        if (!state)
                return -1;

        ret = bpf_timer_init(&state->timer, &dst_port_state, CLOCK_MONOTONIC) ?:
                      bpf_timer_set_callback(&state->timer, xdp_timer_cb)     ?:
                                                                                0;
        if (!ret)
                debug_printk("TX port init OK ifindex %d cpu %u\n", ifindex, cpu);

        return ret;
}

static __always_inline bool forward_dst_enabled(int ifindex)
{
        __u32 cpu = bpf_get_smp_processor_id();
        __u64 state_key = STATE_KEY(cpu, ifindex);

        return !!bpf_map_lookup_elem(&dst_port_state, &state_key);
}

static bool port_can_xmit(struct port_state *state)
{
        return state->outstanding_bytes < DQL_MAX_LIMIT;
}

static int forward_to_dst(struct xdp_md *ctx, int ifindex)
{
        __u32 cpu = bpf_get_smp_processor_id();
        __u64 state_key = STATE_KEY(cpu, ifindex);
        struct port_state *state;
        __u32 len = ctx->data_end - ctx->data;
        void *data, *data_meta;
        struct meta_val *mval;
        int ret;

        state = bpf_map_lookup_elem(&dst_port_state, &state_key);
        if (!state)
                return XDP_DROP;

        if (bpf_xdp_adjust_meta(ctx, -(int)sizeof(*mval)))
                return XDP_ABORTED;

        data  = (void *)(long)ctx->data;
        data_meta = (void *)(long)ctx->data_meta;
        mval = data_meta;

        if (mval + 1 > data)
                return XDP_ABORTED;

        mval->state_key = state_key;
        mval->cookie = META_COOKIE_VAL;
        
        /* DQL: Check for available space */
        /* TODO check for packet length? */
        // debug_printk("========== New packet to XDP queue %d ==========", state->tx_port_idx);
        // debug_printk("forward_to_dst %d: checking space with adj_limit %u num_queued %u len %u", state->tx_port_idx, state->adj_limit, state->num_queued, len);
        // if(state->adj_limit < state->num_queued){
        //         debug_printk("forward_to_dst %d: not enough space", state->tx_port_idx);
        //         return XDP_DROP;
        // }

        ret = bpf_redirect_map(&xdp_queues, state->tx_port_idx, 0);

        if (ret == XDP_REDIRECT) {
                /* Use data length as packet length */
                state->last_obj_cnt = len;
                state->num_queued += len;
                if (port_can_xmit(state)) {
                        if(!time_set){
                                time_set = true;
                                timer_start = bpf_ktime_get_ns();
                        }
                        bpf_timer_start(&state->timer, 0 /* call asap */, 0);
                        // int r = bpf_timer_start(&state->timer, 0 /* call asap */, 0);
                        // debug_printk("forward_to_dst %d: Started BPF timer: %d", state->tx_port_idx, r);
                }
        }

        return ret;
}

SEC("raw_tracepoint/xdp_frame_return")
int xdp_check_return(struct bpf_raw_tracepoint_args* ctx)
{
        struct xdp_frame *frm = (struct xdp_frame *)ctx->args[0];
        __u16 bulk_remaining = ctx->args[1];
        struct port_state *state;
        struct meta_val meta;
        __u32 metasize;
        __u16 pkt_len;
        bool can_xmit;
        void *data;

        bulk_seen += bulk_remaining;

        debug_printk("xdp_check_return: bulk_remaining %u bulk_seen %u", bulk_remaining, bulk_seen);
	__u16 headroom;
        __u32 frame_sz;
	__u32 flags;

        pkt_len = BPF_CORE_READ(frm, len);
        debug_printk("xdp_check_return: frm.len      %u", pkt_len);
        headroom = BPF_CORE_READ(frm, headroom);
        debug_printk("xdp_check_return: frm.headroom %u", headroom);
        metasize = BPF_CORE_READ(frm, metasize);
        debug_printk("xdp_check_return: frm.metasize %u, sizeof(meta)=%d", metasize, sizeof(meta));
        frame_sz = BPF_CORE_READ(frm, frame_sz);
        debug_printk("xdp_check_return: frm.frame_sz %u", frame_sz);
        flags = BPF_CORE_READ(frm, flags);
        debug_printk("xdp_check_return: frm.flags    %u", flags);

        if (metasize != sizeof(meta))
                goto out;
        debug_printk("xdp_check_return: metasize match");

        data = BPF_CORE_READ(frm, data);
        if (!data)
                goto out;
        debug_printk("xdp_check_return: data exists");

        if (bpf_probe_read_kernel(&meta, sizeof(meta), data-sizeof(meta)))
                goto out;
        debug_printk("xdp_check_return: successfully read meta");

        if (meta.cookie != META_COOKIE_VAL)
                goto out;
        debug_printk("xdp_check_return: meta.cookie match");

        state = bpf_map_lookup_elem(&dst_port_state, &meta.state_key);
        if (!state)
                goto out;
        debug_printk("xdp_check_return: state exists");

        can_xmit = port_can_xmit(state);
        state->outstanding_bytes -= pkt_len;
        return dql_completed(state, pkt_len);
        debug_printk("xdp_check_return: completed %uB", pkt_len);

        if (!can_xmit && port_can_xmit(state))
                bpf_timer_start(&state->timer, 0, 0);

out:
        return 0;
}


/* from include/net/ip.h */
static __always_inline int ip_decrease_ttl(struct iphdr *iph)
{
        __u32 check = (__u32)iph->check;

        check += (__u32)bpf_htons(0x0100);
        iph->check = (__sum16)(check + (check >= 0xFFFF));
        return --iph->ttl;
}

static __always_inline int xdp_fwd_flags(struct xdp_md *ctx, __u32 flags)
{
        void *data_end = (void *)(long)ctx->data_end;
        void *data = (void *)(long)ctx->data;
        struct bpf_fib_lookup fib_params;
        struct ethhdr *eth = data;
        struct ipv6hdr *ip6h;
        struct iphdr *iph;
        __u16 h_proto;
        __u64 nh_off;
        int rc;

        nh_off = sizeof(*eth);
        if (data + nh_off > data_end)
                return XDP_DROP;

        __builtin_memset(&fib_params, 0, sizeof(fib_params));

        h_proto = eth->h_proto;
        if (h_proto == bpf_htons(ETH_P_IP)) {
                iph = data + nh_off;

                if (iph + 1 > data_end)
                        return XDP_DROP;

                if (iph->ttl <= 1)
                        return XDP_PASS;

                fib_params.family	= AF_INET;
                fib_params.tos		= iph->tos;
                fib_params.l4_protocol	= iph->protocol;
                fib_params.sport	= 0;
                fib_params.dport	= 0;
                fib_params.tot_len	= bpf_ntohs(iph->tot_len);
                fib_params.ipv4_src	= iph->saddr;
                fib_params.ipv4_dst	= iph->daddr;
        } else if (h_proto == bpf_htons(ETH_P_IPV6)) {
                struct in6_addr *src = (struct in6_addr *) fib_params.ipv6_src;
                struct in6_addr *dst = (struct in6_addr *) fib_params.ipv6_dst;

                ip6h = data + nh_off;
                if (ip6h + 1 > data_end)
                        return XDP_DROP;

                if (ip6h->hop_limit <= 1)
                        return XDP_PASS;

                fib_params.family	= AF_INET6;
                fib_params.flowinfo	= *(__be32 *)ip6h & IPV6_FLOWINFO_MASK;
                fib_params.l4_protocol	= ip6h->nexthdr;
                fib_params.sport	= 0;
                fib_params.dport	= 0;
                fib_params.tot_len	= bpf_ntohs(ip6h->payload_len);
                *src			= ip6h->saddr;
                *dst			= ip6h->daddr;
        } else {
                return XDP_PASS;
        }

        fib_params.ifindex = ctx->ingress_ifindex;

        rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), flags);
        /*
         * Some rc (return codes) from bpf_fib_lookup() are important,
         * to understand how this XDP-prog interacts with network stack.
         *
         * BPF_FIB_LKUP_RET_NO_NEIGH:
         *  Even if route lookup was a success, then the MAC-addresses are also
         *  needed.  This is obtained from arp/neighbour table, but if table is
         *  (still) empty then BPF_FIB_LKUP_RET_NO_NEIGH is returned.  To avoid
         *  doing ARP lookup directly from XDP, then send packet to normal
         *  network stack via XDP_PASS and expect it will do ARP resolution.
         *
         * BPF_FIB_LKUP_RET_FWD_DISABLED:
         *  The bpf_fib_lookup respect sysctl net.ipv{4,6}.conf.all.forwarding
         *  setting, and will return BPF_FIB_LKUP_RET_FWD_DISABLED if not
         *  enabled this on ingress device.
         */
        if (rc == BPF_FIB_LKUP_RET_SUCCESS) {
                /* Verify egress index has been configured as TX-port.
                 * (Note: User can still have inserted an egress ifindex that
                 * doesn't support XDP xmit, which will result in packet drops).
                 *
                 * Note: lookup in devmap supported since 0cdbb4b09a0.
                 * If not supported will fail with:
                 *  cannot pass map_type 14 into func bpf_map_lookup_elem#1:
                 */
                if (!forward_dst_enabled(fib_params.ifindex))
                        return XDP_PASS;

                if (h_proto == bpf_htons(ETH_P_IP))
                        ip_decrease_ttl(iph);
                else if (h_proto == bpf_htons(ETH_P_IPV6))
                        ip6h->hop_limit--;

                __builtin_memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
                __builtin_memcpy(eth->h_source, fib_params.smac, ETH_ALEN);
                return forward_to_dst(ctx, fib_params.ifindex);
        }

        return XDP_PASS;
}

SEC("xdp")
int xdp_fwd_fib_full_dql(struct xdp_md *ctx)
{
        return xdp_fwd_flags(ctx, 0);
}

SEC("xdp")
int xdp_fwd_fib_direct(struct xdp_md *ctx)
{
        return xdp_fwd_flags(ctx, BPF_FIB_LOOKUP_DIRECT);
}

SEC("xdp")
int init_port(struct xdp_md *ctx)
{
        void *data = (void *)(long)ctx->data;
        void *data_end = (void *)(long)ctx->data_end;

        /* we need this program to be an XDP type program, so we stash the
         * parameters in the data member and call it using BPF_PROG_RUN
         */
        struct port_init_config *cfg = data;

        if (cfg + 1 > data_end)
                return XDP_ABORTED;

        return init_tx_port(cfg->ifindex, cfg->cpu) ? XDP_ABORTED : XDP_PASS;
}

char _license[] SEC("license") = "GPL";
