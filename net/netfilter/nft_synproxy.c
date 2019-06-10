// SPDX-License-Identifier: GPL-2.0

#include <linux/types.h>

#include <net/ip.h>
#include <net/tcp.h>
#include <net/netlink.h>

#include <net/netfilter/nf_tables.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_ecache.h>
#include <net/netfilter/nf_conntrack_extend.h>
#include <net/netfilter/nf_conntrack_seqadj.h>
#include <net/netfilter/nf_conntrack_synproxy.h>
#include <net/netfilter/nf_synproxy.h>

#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nf_SYNPROXY.h>

struct nft_synproxy {
	u8			mss;
	u8			wscale;
	u32			flags;
};

static const struct nla_policy nft_synproxy_policy[NFTA_SYNPROXY_MAX + 1] = {
	[NFTA_SYNPROXY_MSS]		= { .type = NLA_U8 },
	[NFTA_SYNPROXY_WSCALE]		= { .type = NLA_U8 },
	[NFTA_SYNPROXY_FLAGS]		= { .type = NLA_U32 },
};

static struct nf_synproxy_info create_synproxy_info(struct nft_synproxy *expr)
{
	struct nf_synproxy_info info;

	info.options = expr->flags;
	info.wscale = expr->wscale;
	info.mss = expr->mss;

	return info;
}

static void nft_synproxy_eval_v4(const struct nft_expr *expr,
				 struct nft_regs *regs,
				 const struct nft_pktinfo *pkt)
{
	struct nft_synproxy *priv = nft_expr_priv(expr);
	struct nf_synproxy_info info = create_synproxy_info(priv);
	struct synproxy_options opts = {};
	struct net *net = nft_net(pkt);
	struct synproxy_net *snet = synproxy_pernet(net);
	struct sk_buff *skb = pkt->skb;
	int thoff = pkt->xt.thoff;
	const struct tcphdr *tcp;
	struct tcphdr _tcph;

	if (nf_ip_checksum(skb, nft_hook(pkt), thoff, IPPROTO_TCP)) {
		regs->verdict.code = NF_DROP;
		return;
	}

	tcp = skb_header_pointer(skb, ip_hdrlen(skb),
				 sizeof(struct tcphdr), &_tcph);
	if (!tcp) {
		regs->verdict.code = NF_DROP;
		return;
	}

	if (!synproxy_parse_options(skb, thoff, tcp, &opts)) {
		regs->verdict.code = NF_DROP;
		return;
	}

	if (tcp->syn) {
		/* Initial SYN from client */
		this_cpu_inc(snet->stats->syn_received);

		if (tcp->ece && tcp->cwr)
			opts.options |= NF_SYNPROXY_OPT_ECN;

		opts.options &= priv->flags;
		if (opts.options & NF_SYNPROXY_OPT_TIMESTAMP)
			synproxy_init_timestamp_cookie(&info, &opts);
		else
			opts.options &= ~(NF_SYNPROXY_OPT_WSCALE |
					  NF_SYNPROXY_OPT_SACK_PERM |
					  NF_SYNPROXY_OPT_ECN);

		synproxy_send_client_synack(net, skb, tcp, &opts);
		consume_skb(skb);
		regs->verdict.code = NF_STOLEN;
		return;
	} else if (tcp->ack) {
		/* ACK from client */
		if (synproxy_recv_client_ack(net, skb, tcp, &opts,
					     ntohl(tcp->seq))) {
			consume_skb(skb);
			regs->verdict.code = NF_STOLEN;
		} else {
			regs->verdict.code = NF_DROP;
		}
		return;
	}

	regs->verdict.code = NFT_CONTINUE;
}

#if IS_ENABLED(CONFIG_NF_TABLES_IPV6)
static void nft_synproxy_eval_v6(const struct nft_expr *expr,
				 struct nft_regs *regs,
				 const struct nft_pktinfo *pkt)
{
	struct nft_synproxy *priv = nft_expr_priv(expr);
	struct nf_synproxy_info info = create_synproxy_info(priv);
	struct synproxy_options opts = {};
	struct net *net = nft_net(pkt);
	struct synproxy_net *snet = synproxy_pernet(net);
	struct sk_buff *skb = pkt->skb;
	int thoff = pkt->xt.thoff;
	const struct tcphdr *tcp;
	struct tcphdr _tcph;

	if (nf_ip_checksum(skb, nft_hook(pkt), thoff, IPPROTO_TCP)) {
		regs->verdict.code = NF_DROP;
		return;
	}

	tcp = skb_header_pointer(skb, ip_hdrlen(skb),
				 sizeof(struct tcphdr), &_tcph);
	if (!tcp) {
		regs->verdict.code = NF_DROP;
		return;
	}

	if (!synproxy_parse_options(skb, thoff, tcp, &opts)) {
		regs->verdict.code = NF_DROP;
		return;
	}

	if (tcp->syn) {
		/* Initial SYN from client */
		this_cpu_inc(snet->stats->syn_received);

		if (tcp->ece && tcp->cwr)
			opts.options |= NF_SYNPROXY_OPT_ECN;

		opts.options &= priv->flags;
		if (opts.options & NF_SYNPROXY_OPT_TIMESTAMP)
			synproxy_init_timestamp_cookie(&info, &opts);
		else
			opts.options &= ~(NF_SYNPROXY_OPT_WSCALE |
					  NF_SYNPROXY_OPT_SACK_PERM |
					  NF_SYNPROXY_OPT_ECN);

		synproxy_send_client_synack_ipv6(net, skb, tcp, &opts);
		consume_skb(skb);
		regs->verdict.code = NF_STOLEN;
		return;
	} else if (tcp->ack) {
		/* ACK from client */
		if (synproxy_recv_client_ack_ipv6(net, skb, tcp, &opts,
						  ntohl(tcp->seq))) {
			consume_skb(skb);
			regs->verdict.code = NF_STOLEN;
		} else {
			regs->verdict.code = NF_DROP;
		}
		return;
	}

	regs->verdict.code = NFT_CONTINUE;
}
#endif /* IPv6 support */

static void nft_synproxy_eval(const struct nft_expr *expr,
			      struct nft_regs *regs,
			      const struct nft_pktinfo *pkt)
{
	switch (nft_pf(pkt)) {
	case NFPROTO_IPV4:
		nft_synproxy_eval_v4(expr, regs, pkt);
		return;
#if IS_ENABLED(CONFIG_NF_TABLES_IPV6)
	case NFPROTO_IPV6:
		nft_synproxy_eval_v6(expr, regs, pkt);
		return;
#endif
	}
	regs->verdict.code = NFT_BREAK;
}

static int nft_synproxy_init(const struct nft_ctx *ctx,
			     const struct nft_expr *expr,
			     const struct nlattr * const tb[])
{
	struct nft_synproxy *priv = nft_expr_priv(expr);
	u32 flags;

	if (tb[NFTA_SYNPROXY_MSS])
		priv->mss = nla_get_u8(tb[NFTA_SYNPROXY_MSS]);
	if (tb[NFTA_SYNPROXY_WSCALE])
		priv->wscale = nla_get_u8(tb[NFTA_SYNPROXY_WSCALE]);
	if (tb[NFTA_SYNPROXY_FLAGS]) {
		flags = ntohl(nla_get_be32(tb[NFTA_SYNPROXY_FLAGS]));
		if (flags != 0 && (flags & NF_SYNPROXY_FLAGMASK) == 0)
			return -EINVAL;
		priv->flags = flags;
	}
	return 0;
}

static int nft_synproxy_dump(struct sk_buff *skb, const struct nft_expr *expr)
{
	const struct nft_synproxy *priv = nft_expr_priv(expr);

	if (nla_put_u8(skb, NFTA_SYNPROXY_MSS, priv->mss))
		goto nla_put_failure;

	if (nla_put_u8(skb, NFTA_SYNPROXY_WSCALE, priv->wscale))
		goto nla_put_failure;

	if (nla_put_be32(skb, NFTA_SYNPROXY_FLAGS, ntohl(priv->flags)))
		goto nla_put_failure;

	return 0;

nla_put_failure:
	return -1;
}

static int nft_synproxy_validate(const struct nft_ctx *ctx,
				 const struct nft_expr *expr,
				 const struct nft_data **data)
{
	return nft_chain_validate_hooks(ctx->chain, (1 << NF_INET_LOCAL_IN) |
						    (1 << NF_INET_FORWARD));
}

static struct nft_expr_type nft_synproxy_type;
static const struct nft_expr_ops nft_synproxy_ops = {
	.eval		= nft_synproxy_eval,
	.size		= NFT_EXPR_SIZE(sizeof(struct nft_synproxy)),
	.init		= nft_synproxy_init,
	.dump		= nft_synproxy_dump,
	.type		= &nft_synproxy_type,
	.validate	= nft_synproxy_validate,
};

static struct nft_expr_type nft_synproxy_type __read_mostly = {
	.ops		= &nft_synproxy_ops,
	.name		= "synproxy",
	.owner		= THIS_MODULE,
	.policy		= nft_synproxy_policy,
	.maxattr	= NFTA_OSF_MAX,
};

static int __init nft_synproxy_module_init(void)
{
	return nft_register_expr(&nft_synproxy_type);
}

static void __exit nft_synproxy_module_exit(void)
{
	return nft_unregister_expr(&nft_synproxy_type);
}

module_init(nft_synproxy_module_init);
module_exit(nft_synproxy_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Fernando Fernandez <ffmancera@riseup.net>");
MODULE_ALIAS_NFT_EXPR("synproxy");
