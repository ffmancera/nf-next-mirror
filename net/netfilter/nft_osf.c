/*
 * Copyright (c) 2018 Fernando Fernandez Mancera <ffmancera@riseup.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#include <net/netfilter/nf_tables.h>
#include <linux/tcp.h>
#include <net/netfilter/nft_osf.h>

#define OSF_GENRE_SIZE 32

struct nft_osf {
	char	genre[OSF_GENRE_SIZE];
	__u32	flags;
	__u32	loglevel;
	__u32	ttl;
	__u32	len;
};

/* placeholder function WIP */
static inline bool match_packet(struct nft_osf *priv, struct sk_buff *skb)
{
	return 0;
}

static const struct nla_policy nft_osf_policy[NFTA_OSF_MAX + 1] = {
	[NFTA_OSF_GENRE]	= { .type = NLA_STRING, .len = OSF_GENRE_SIZE }
};

static void nft_osf_eval(const struct nft_expr *expr, struct nft_regs *regs,
			 const struct nft_pktinfo *pkt)
{
	struct nft_osf *priv = nft_expr_priv(expr);
	struct sk_buff *skb = pkt->skb;

	if (match_packet(priv, skb))
		regs->verdict.code = NFT_CONTINUE;
	else
		regs->verdict.code = NFT_BREAK;
}

static int nft_osf_init(const struct nft_ctx *ctx,
			const struct nft_expr *expr,
			const struct nlattr * const tb[])
{
	struct nft_osf *priv = nft_expr_priv(expr);

	if (tb[NFTA_OSF_GENRE] == NULL)
		return -EINVAL;
	nla_strlcpy(priv->genre, tb[NFTA_OSF_GENRE], OSF_GENRE_SIZE);
	priv->len = strlen(priv->genre);
	return 0;
}

static int nft_osf_dump(struct sk_buff *skb, const struct nft_expr *expr)
{
	const struct nft_osf *priv = nft_expr_priv(expr);

	if (nla_put_string(skb, NFTA_OSF_GENRE, priv->genre))
		return -1;
	return 0;
}

static struct nft_expr_type nft_osf_type;

static const struct nft_expr_ops nft_osf_op = {
	.eval = nft_osf_eval,
	.size = NFT_EXPR_SIZE(sizeof(struct nft_osf)),
	.init = nft_osf_init,
	.dump = nft_osf_dump,
	.type = &nft_osf_type,
};

static struct nft_expr_type nft_osf_type __read_mostly = {
	.ops = &nft_osf_op,
	.name = "osf",
	.owner = THIS_MODULE,
	.policy = nft_osf_policy,
	.maxattr = NFTA_OSF_MAX,
};

static int __init nft_osf_module_init(void)
{
	return nft_register_expr(&nft_osf_type);
}

static void __exit nft_osf_module_exit(void)
{
	return nft_unregister_expr(&nft_osf_type);
}

module_init(nft_osf_module_init);
module_exit(nft_osf_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Fernando Fernandez <ffmancera@riseup.net>");
