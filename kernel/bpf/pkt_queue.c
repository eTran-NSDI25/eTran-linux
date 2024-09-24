// SPDX-License-Identifier: GPL-2.0
// This code is based on Toke (Toke Høiland-Jørgensen <toke@toke.dk>)'s implementation of xdpmap_fifo.c with bug fixes.
#include <linux/bpf.h>
#include <linux/slab.h>
#include <linux/netdevice.h>
#include <linux/capability.h>
#include <linux/btf_ids.h>
#include <linux/filter.h>
#include <net/xdp.h>

#define PKT_QUEUE_CREATE_FLAG_MASK \
	(BPF_F_NUMA_NODE | BPF_F_ACCESS_MASK)

struct bpf_pkt_queue_bucket {
	struct xdp_frame *head, *tail;
	spinlock_t lock;
	u32 elem_count;
};

struct bpf_pkt_queue {
	struct bpf_map map;
	struct bpf_pkt_queue_bucket *buckets;
	unsigned long num_buckets;
};

static void fifo_item_set_next(struct xdp_frame *xdpf, void *next)
{
	xdpf->next = next;
}

static inline struct bpf_pkt_queue *bpf_pkt_queue(struct bpf_map *map)
{
	return container_of(map, struct bpf_pkt_queue, map);
}

/* Called from syscall */
static int pkt_queue_alloc_check(union bpf_attr *attr)
{
	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	/* check sanity of attributes */
	if (attr->max_entries == 0 || attr->key_size != 4 ||
	    attr->value_size != 4 ||
	    attr->map_flags & ~PKT_QUEUE_CREATE_FLAG_MASK ||
	    !bpf_map_flags_access_ok(attr->map_flags))
		return -EINVAL;

	if (attr->map_extra > U32_MAX / sizeof(struct bpf_pkt_queue_bucket))
		return -E2BIG;

	return 0;
}

static struct bpf_map *pkt_queue_alloc(union bpf_attr *attr)
{
	int i, numa_node = bpf_map_attr_numa_node(attr);
	struct bpf_pkt_queue *fifo;

	fifo = bpf_map_area_alloc(sizeof(*fifo), numa_node);
	if (!fifo)
		return ERR_PTR(-ENOMEM);

	fifo->num_buckets = attr->map_extra;
	fifo->buckets = bpf_map_area_alloc(sizeof(*fifo->buckets) * fifo->num_buckets, numa_node);
	if (!fifo->buckets) {
		bpf_map_area_free(fifo);
		return ERR_PTR(-ENOMEM);
	}

	bpf_map_init_from_attr(&fifo->map, attr);
	for (i = 0; i < fifo->num_buckets; i++) {
		fifo->buckets[i].head = NULL;
		fifo->buckets[i].tail = NULL;
		fifo->buckets[i].elem_count = 0;
		spin_lock_init(&fifo->buckets[i].lock);
	}

	return &fifo->map;
}

static void pkt_queue_purge(struct bpf_pkt_queue *fifo)
{
	int i;
    /* Packets in BPF_MAP_TYPE_PKT_QUEUE are managed by userspace AF_XDP, don't free them here */
	for (i = 0; i < fifo->num_buckets; i++) {
		struct bpf_pkt_queue_bucket *bucket;

		bucket = &fifo->buckets[i];
        spin_lock(&bucket->lock);
        bucket->head = bucket->tail = NULL;
        bucket->elem_count = 0;
        spin_unlock(&bucket->lock);
	}
}

static void pkt_queue_free(struct bpf_map *map)
{
	struct bpf_pkt_queue *fifo = bpf_pkt_queue(map);

	synchronize_rcu();

	pkt_queue_purge(fifo);
	bpf_map_area_free(fifo->buckets);
	bpf_map_area_free(fifo);
}

/* Called from syscall */
static void *pkt_queue_lookup_elem_sys(struct bpf_map *map, void *key)
{
	struct bpf_pkt_queue *fifo = bpf_pkt_queue(map);
	struct bpf_pkt_queue_bucket *bucket;
	u32 index = *(u32 *)key;

	if (index >= fifo->num_buckets)
		return ERR_PTR(-ENOENT);

	bucket = &fifo->buckets[index];

	return &bucket->elem_count;
}

/* Called from eBPF program */
static void *pkt_queue_lookup_elem(struct bpf_map *map, void *key)
{
	return ERR_PTR(-EOPNOTSUPP);
}

/* Called from syscall or from eBPF program */
static long pkt_queue_update_elem(struct bpf_map *map, void *key, void *value,
			       u64 flags)
{
	return -EOPNOTSUPP;
}

/* Called from syscall or from eBPF program */
static long pkt_queue_delete_elem(struct bpf_map *map, void *key)
{
	return -EOPNOTSUPP;
}

/* Called from syscall */
static int pkt_queue_get_next_key(struct bpf_map *map, void *key, void *next_key)
{
	struct bpf_pkt_queue *fifo = bpf_pkt_queue(map);
	u64 nkey = 0;

	if (!key)
		goto out;

	nkey = *(u64 *) key + 1;
	if (nkey >= fifo->num_buckets)
		return -ENOENT;
out:
	*(u64 *) next_key = nkey;
	return 0;
}

int pkt_queue_map_enqueue(struct bpf_map *map, struct xdp_frame *xdpf, u64 index)
{
	struct bpf_pkt_queue *fifo = bpf_pkt_queue(map);
	struct bpf_pkt_queue_bucket *bucket;
	int err = -EOVERFLOW;

	if (index >= fifo->num_buckets)
		return -E2BIG;

	fifo_item_set_next(xdpf, NULL);

	bucket = &fifo->buckets[index];

	/* called under local_bh_disable() so no need to use irqsave variant */
	spin_lock(&bucket->lock);

	if (unlikely(bucket->elem_count >= fifo->map.max_entries))
		goto out;

	if (likely(!bucket->head)) {
		bucket->head = xdpf;
		bucket->tail = xdpf;
	} else {
		fifo_item_set_next(bucket->tail, xdpf);
		bucket->tail = xdpf;
	}

	bucket->elem_count++;
	err = 0;

out:
	spin_unlock(&bucket->lock);
	return err;
}

int pkt_queue_map_enqueue_front(struct bpf_map *map, struct xdp_frame *xdpf, u64 index)
{
	struct bpf_pkt_queue *fifo = bpf_pkt_queue(map);
	struct bpf_pkt_queue_bucket *bucket;
	int err = -EOVERFLOW;
	unsigned long lflags;

	if (index >= fifo->num_buckets)
		return -E2BIG;

	fifo_item_set_next(xdpf, NULL);

	bucket = &fifo->buckets[index];

	spin_lock_irqsave(&bucket->lock, lflags);

	if (unlikely(bucket->elem_count >= fifo->map.max_entries))
		goto out;

	if (likely(!bucket->head)) {
		bucket->head = xdpf;
		bucket->tail = xdpf;
	} else {
		fifo_item_set_next(xdpf, bucket->head);
		bucket->head = xdpf;
	}

	bucket->elem_count++;
	err = 0;

out:
	spin_unlock_irqrestore(&bucket->lock, lflags);
	return err;
}

struct xdp_frame *pkt_queue_map_dequeue(struct bpf_map *map, u64 flags, u64 *rank)
{
	struct bpf_pkt_queue *fifo = bpf_pkt_queue(map);
	struct bpf_pkt_queue_bucket *bucket;
	struct xdp_frame *frm;
	u64 index = flags;
	unsigned long lflags;

	(void)rank;

	if (index >= fifo->num_buckets)
		return NULL;

	bucket = &fifo->buckets[index];

	spin_lock_irqsave(&bucket->lock, lflags);

	frm = bucket->head;
	if (!frm)
		goto out;

	prefetchw(frm);

	bucket->head = frm->next;

	if (!bucket->head)
		bucket->tail = NULL;

	fifo_item_set_next(frm, NULL);

	bucket->elem_count--;

out:
	spin_unlock_irqrestore(&bucket->lock, lflags);
	return frm;
}

bool pkt_queue_map_empty(struct bpf_map *map, u64 flags, u64 *rank)
{
    struct bpf_pkt_queue *fifo = bpf_pkt_queue(map);
    struct bpf_pkt_queue_bucket *bucket;
    u64 index = flags;

    (void)rank;

    if (index >= fifo->num_buckets)
        return true;

    bucket = &fifo->buckets[index];

    return !bucket->head;
}

static u64 pkt_queue_mem_usage(const struct bpf_map *map)
{
	struct bpf_pkt_queue *fifo = container_of(map, struct bpf_pkt_queue, map);
	u64 usage = sizeof(struct bpf_pkt_queue);
	unsigned long i;

	usage += fifo->num_buckets * sizeof(struct bpf_pkt_queue_bucket);

	for (i = 0; i < fifo->num_buckets; i++)
		usage += fifo->buckets[i].elem_count * PAGE_SIZE; /* FIXME: not always accurate */

	return usage;
}

static long pkt_queue_map_redirect(struct bpf_map *map, u64 index, u64 flags)
{
	struct bpf_redirect_info *ri = this_cpu_ptr(&bpf_redirect_info);
	const u64 action_mask = XDP_ABORTED | XDP_DROP | XDP_PASS | XDP_TX;

	/* Lower bits of the flags are used as return code on lookup failure */
	if (unlikely(flags & ~action_mask))
		return XDP_ABORTED;

	ri->tgt_value = NULL;
	ri->tgt_index = index;
	ri->map_id = map->id;
	ri->map_type = map->map_type;
	ri->flags = flags;
	WRITE_ONCE(ri->map, map);
	return XDP_REDIRECT;
}

BTF_ID_LIST_SINGLE(pkt_queue_btf_ids, struct, bpf_pkt_queue)
const struct bpf_map_ops pkt_queue_ops = {
	.map_meta_equal = bpf_map_meta_equal,
	.map_alloc_check = pkt_queue_alloc_check,
	.map_alloc = pkt_queue_alloc,
	.map_free = pkt_queue_free,
	.map_lookup_elem_sys_only = pkt_queue_lookup_elem_sys,
	.map_lookup_elem = pkt_queue_lookup_elem,
	.map_update_elem = pkt_queue_update_elem,
	.map_delete_elem = pkt_queue_delete_elem,
	.map_get_next_key = pkt_queue_get_next_key,
	.map_btf_id = &pkt_queue_btf_ids[0],
	.map_mem_usage = pkt_queue_mem_usage,
	.map_check_btf = map_check_no_btf,
	.map_redirect = pkt_queue_map_redirect,
};
