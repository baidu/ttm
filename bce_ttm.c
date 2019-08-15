/* Copyright (c) 2019 Baidu, Inc. All Rights Reserved.

* Bce-ttm is free software; you can redistribute it and/or modify it under the terms of 
* the GNU General Public License as published by the Free Software Foundation; 
* either version 2 of the License, or (at your option) any later version.

* Bce-ttm is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; 
* without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
* See the GNU General Public License for more details.

* You should have received a copy of the GNU General Public License along with bce-ttm; 
* if not, see <http://www.gnu.org/licenses/>.

* Authors: Yi,Xiayu
*/

#include "bce_ttm.h"

MODULE_AUTHOR("yixiayu");
MODULE_DESCRIPTION("Tunnel Though Module FOR BCE (Baidu Compute Engine), you can get real client ip from this module");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0.1.8");
unsigned long sk_data_ready_addr = 0;

int __read_mostly g_tcpopt_ttm = TCPOPT_TTM;

module_param_named(tcpopt_ttm, g_tcpopt_ttm, int, 0664);

struct proc_dir_entry *ttm_stats_entry = NULL;


/*******************************************************
 * Statistics of ttm in /proc/net/ttm_all_stats *
 *******************************************************/

struct ttm_stats_entry ttm_stats[] = {
    TTM_STAT_ITEM("synrecv_sock_ttm", SYN_RECV_SOCK_TTM_CNT),
    TTM_STAT_ITEM("synrecv_sock_no_ttm", SYN_RECV_SOCK_NO_TTM_CNT),
    TTM_STAT_ITEM("getname_ttm_ok", GETNAME_TTM_OK_CNT),
    TTM_STAT_ITEM("getname_ttm_mismatch", GETNAME_TTM_MISMATCH_CNT),
    TTM_STAT_ITEM("getname_ttm_bypass", GETNAME_TTM_BYPASS_CNT),
    TTM_STAT_ITEM("getname_ttm_empty", GETNAME_TTM_EMPTY_CNT),
    TTM_STAT_END
};


DEFINE_TTM_STAT(struct ttm_stat_mib, ext_stats);
#if LINUX_VERSION_CODE == KERNEL_VERSION(2,6,32)
#define  proc_net_fops_create(name,mode, fops) proc_net_fops_create(&init_net,name,mode, fops)
#define  proc_net_remove(name) proc_net_remove(&init_net,name)
#endif


static int
ttm_stats_show(struct seq_file *seq, void *v)
{
    int i = 0;
    int j = 0;

    /* print CPU first */
    seq_printf(seq, "                                  ");
    for (i = 0; i < NR_CPUS; i++) {
        if (cpu_online(i)) {
            seq_printf(seq, "CPU%d       ", i);
        }
    }
    seq_putc(seq, '\n');

    i = 0;
    while (NULL != ttm_stats[i].name) {
        seq_printf(seq, "%-25s:", ttm_stats[i].name);
        for (j = 0; j < NR_CPUS; j++) {
            if (cpu_online(j)) {
                seq_printf(seq, "%10lu ",
                        *(((unsigned long *) per_cpu_ptr(ext_stats, j)) + ttm_stats[i].entry));
            }
        }
        seq_putc(seq, '\n');
        i++;
    }

    return 0;
}

static int ttm_stats_seq_open(struct inode *inode, struct file *file)
{
    return single_open(file, ttm_stats_show, NULL);
}

static const struct file_operations ttm_stats_fops = {
    .owner = THIS_MODULE,
    .open = ttm_stats_seq_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};

/* @brief Parse TCP options in skb, try to get client ip, port
          NOTE: due to historical issue, byte order of some option is different,
          in syn packet and ack packet, we have to parse both.
 * @param skb [in] received skb, it should be a ack/ack-get packet.
 * @return NULL if we don't get client ip/port;
 *  pointer of ttm_data in ret_ptr if we get client ip/port.
 */
static void  get_ttm_data_from_ack(struct sk_buff *skb,struct ttm_data *ttm_data)
{
    struct iphdr *iph = NULL;
    struct tcphdr *th = NULL;
    unsigned char *ptr = NULL;
    int length = 0;

    if (NULL != skb) {
        iph = ip_hdr(skb);
        th = (struct tcphdr *)((char *)iph + iph->ihl*4);
        length = (th->doff * 4) - sizeof (struct tcphdr);
        ptr = (unsigned char *) (th + 1);

        while (length > 0) {
            int opcode = *ptr++;
            int opsize = 0;
            switch (opcode) {
            case TCPOPT_EOL:
                goto end;
            case TCPOPT_NOP:    /* Ref: RFC 793 section 3.1 */
                length--;
                continue;
            default:
                opsize = *ptr++;
                if (opsize < 2) {
                    goto end;
                }
                if (opsize > length) {
                    goto end;   /* don't parse partial options */
                }
                
                if (g_tcpopt_ttm == opcode && TCPOLEN_TTM == opsize) {
                    ttm_data->opcode = g_tcpopt_ttm;
                    ttm_data->opsize = opsize;
                    memcpy(&ttm_data->port, ptr, sizeof(u16));
                    memcpy(&ttm_data->ip, ptr+2, sizeof(u32));
                    TTM_DBG( "find ttm data: ip = %u.%u.%u.%u, port = %u\n", NIPQUAD(ttm_data->ip),
                        ntohs(ttm_data->port));
                }
                ptr += opsize - 2;
                length -= opsize;
            }
        }
        }
end:
    return ;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,1)
static int
inet_getname_ttm(struct socket *sock, struct sockaddr *uaddr, int peer)
#else
static int
inet_getname_ttm(struct socket *sock, struct sockaddr *uaddr, int *uaddr_len, int peer)
#endif
{
    struct sock *sk = sock->sk;
    struct sockaddr_in *sin = (struct sockaddr_in *) uaddr;
    struct ttm_data tdata;
    int retval = 0;

    TTM_DBG( "inet_getname_ttm called, sk->sk_user_data is %p\n", sk->sk_user_data);

    /* call orginal one */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,1)
    retval = inet_getname(sock, uaddr, peer);
#else
    retval = inet_getname(sock, uaddr, uaddr_len, peer);
#endif

    /* set our value if need */
    if (retval >= 0 && NULL != sk->sk_user_data && peer) {
        if (sk_data_ready_addr == (unsigned long) sk->sk_data_ready) {
            memcpy(&tdata, &sk->sk_user_data, sizeof (sk->sk_user_data));
            if (g_tcpopt_ttm == tdata.opcode && TCPOLEN_TTM == tdata.opsize) {
                TTM_INC_STATS(ext_stats, GETNAME_TTM_OK_CNT);
                TTM_DBG( "inet_getname_ttm: set new bce ttm sockaddr, ip %u.%u.%u.%u -> %u.%u.%u.%u, port %u -> %u\n",
                        NIPQUAD(sin->sin_addr.s_addr), NIPQUAD(tdata.ip), ntohs(sin->sin_port),
                        ntohs(tdata.port));
                sin->sin_port = tdata.port;
                sin->sin_addr.s_addr = tdata.ip;
            }
            else {
                TTM_INC_STATS(ext_stats, GETNAME_TTM_MISMATCH_CNT);
                TTM_DBG( "inet_getname_ttm: invalid ttm data, ip %u.%u.%u.%u port %u opcode %u opsize %u\n",
                        NIPQUAD(tdata.ip), ntohs(tdata.port), tdata.opcode, tdata.opsize);
            }
        }
        else {
            TTM_INC_STATS(ext_stats, GETNAME_TTM_BYPASS_CNT);
        }
    }
    else {
        TTM_INC_STATS(ext_stats, GETNAME_TTM_EMPTY_CNT);
    }
    return retval;
}



/* The three way handshake has completed - we got a valid synack -
 * now create the new socket.
 * We need to save ttm data into the new socket.
 * @param sk [out]  the socket
 * @param skb [in] the ack/ack-get packet
 * @param req [in] the open request for this connection
 * @param dst [out] route cache entry
 * @return NULL if fail new socket if succeed.
 */

 #if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
 static struct sock *
 tcp_v4_syn_recv_sock_ttm(const struct sock *sk, struct sk_buff *skb,
        struct request_sock *req,
        struct dst_entry *dst,
        struct request_sock *req_unhash,
        bool *own_req)
#elif (LINUX_VERSION_CODE == KERNEL_VERSION(2,6,9))
static struct sock *
tcp_v4_syn_recv_sock_ttm(struct sock *sk, struct sk_buff *skb, 
        struct open_request *req, 
        struct dst_entry *dst)
#else
static struct sock *
tcp_v4_syn_recv_sock_ttm(struct sock *sk, struct sk_buff *skb, 
        struct request_sock *req, 
        struct dst_entry *dst)
#endif
{
    struct sock *newsock = NULL;
    struct ttm_data ttmd;

    memset(&ttmd,0,sizeof(ttmd));

    TTM_DBG( "tcp_v4_syn_recv_sock_ttm called\n");

    /* call orginal one */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
    newsock = tcp_v4_syn_recv_sock(sk, skb, req, dst, req_unhash, own_req);
#else
    newsock = tcp_v4_syn_recv_sock(sk, skb, req, dst);
#endif

    /* set our value if need */
    if (NULL != newsock && NULL == newsock->sk_user_data) {
        get_ttm_data_from_ack(skb, &ttmd);
        if (g_tcpopt_ttm == ttmd.opcode) {
            memcpy(&newsock->sk_user_data,&ttmd,sizeof(newsock->sk_user_data));
            TTM_INC_STATS(ext_stats, SYN_RECV_SOCK_TTM_CNT);
            TTM_DBG( "tcp_v4_syn_recv_sock_ttm: set sk->sk_user_data to %p\n", newsock->sk_user_data);
        }
        else {
            TTM_INC_STATS(ext_stats, SYN_RECV_SOCK_NO_TTM_CNT);
        }
    }

    return newsock;
}

extern struct proto tcp_prot;
#if (LINUX_VERSION_CODE == KERNEL_VERSION(2,6,9))
extern struct tcp_func ipv4_specific;
#else
extern struct inet_connection_sock_af_ops ipv4_specific;
#endif


static int
hook_tcp_ttm_functions(void)
{
    struct proto_ops * inet_stream_ops_p = NULL;
    pte_t *pte_ops = NULL;
    pte_t *pte_spec = NULL;
    int rw_ops_enable = 0;
    int rw_spec_enable = 0;
    unsigned int level = 0;
    int ret = 0;

    inet_stream_ops_p = (struct proto_ops *)&inet_stream_ops;

    pte_ops = lookup_address((unsigned long )&inet_stream_ops.getname, &level);
    if (pte_ops == NULL) {
        ret = -1;
        goto end;
    }

    if ((pte_ops->pte & _PAGE_RW) == 0) {
        pte_ops->pte |= _PAGE_RW;
        rw_ops_enable = 1;
    }

    inet_stream_ops_p->getname = inet_getname_ttm;

    TTM_INFO("CPU [%u] hooked inet_getname <%p> --> <%p>\n", smp_processor_id(), inet_getname,
    inet_stream_ops_p->getname);

    pte_spec = lookup_address((unsigned long )&ipv4_specific.syn_recv_sock, &level);
    if (pte_spec == NULL) {
        inet_stream_ops_p->getname = inet_getname;
        ret = -1;
        goto end;
    }

    if ((pte_spec->pte & _PAGE_RW) == 0) {
        pte_spec->pte |= _PAGE_RW;
        rw_spec_enable = 1;
    }

    ipv4_specific.syn_recv_sock = tcp_v4_syn_recv_sock_ttm;

    TTM_INFO("CPU [%u] hooked tcp_v4_syn_recv_sock <%p> --> <%p>\n", smp_processor_id(), tcp_v4_syn_recv_sock,
    ipv4_specific.syn_recv_sock);

end:

    if(rw_ops_enable == 1) {
        pte_ops->pte = pte_ops->pte & ~_PAGE_RW;
        rw_ops_enable = 0;
    }

    if(rw_spec_enable == 1) {
        pte_spec->pte = pte_spec->pte & ~_PAGE_RW;
        rw_spec_enable = 0;
    }

    return ret;

}

static int unhook_tcp_ttm_functions(void)
{
    /* unhook inet_getname */
    struct proto_ops * inet_stream_ops_p = NULL;
    pte_t *pte_ops = NULL;
    pte_t *pte_spec = NULL;
    int rw_ops_enable = 0;
    int rw_spec_enable = 0;
    unsigned int level = 0;
    int ret = 0;

    inet_stream_ops_p = (struct proto_ops *)&inet_stream_ops;

    pte_ops = lookup_address((unsigned long )&inet_stream_ops.getname, &level);
    if (pte_ops == NULL) {
        ret = -1;
        TTM_INFO("proc_err\n");
        goto end;
    }

    if ((pte_ops->pte & _PAGE_RW) == 0) {
        pte_ops->pte |= _PAGE_RW;
        rw_ops_enable = 1;
    }

    inet_stream_ops_p->getname = inet_getname;
    TTM_INFO("CPU [%u] unhooked inet_getname\n", smp_processor_id());


    pte_spec = lookup_address((unsigned long )&ipv4_specific.syn_recv_sock, &level);
    if (pte_spec == NULL) {
        ret = -1;
        TTM_INFO("proc_err\n");
        goto end;
    }

    if ((pte_spec->pte & _PAGE_RW) == 0) {
        pte_spec->pte |= _PAGE_RW;
        rw_spec_enable = 1;
    }

    ipv4_specific.syn_recv_sock = tcp_v4_syn_recv_sock;
    TTM_INFO("CPU [%u] unhooked tcp_v4_syn_recv_sock\n", smp_processor_id());

end:

    if(rw_ops_enable == 1) {
        pte_ops->pte = pte_ops->pte & ~_PAGE_RW;
        rw_ops_enable = 0;
    }

    if(rw_spec_enable == 1) {
        pte_spec->pte = pte_spec->pte & ~_PAGE_RW;
        rw_spec_enable = 0;
    }

    return ret;
}

static int ttm_init(void)
{
    void *sk_user_data = NULL;

    /* We need to put the ttm data in the sk_user_data, it is a pointer */
    if (sizeof(struct ttm_data) > sizeof(sk_user_data)) {
        TTM_INFO("Unsupported operating system.\n");
        goto proc_err;
    }

    TTM_INFO("bce ttm init\n");

    /* alloc statistics array for ttm */
    if (NULL == (ext_stats = alloc_percpu(struct ttm_stat_mib))) {
        TTM_DBG("alloc_percpu ext_stats error.\n");
        goto proc_err;
    }


#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
    ttm_stats_entry = proc_create( "ttm_all_stats", 0, init_net.proc_net,&ttm_stats_fops);
#else
    ttm_stats_entry = proc_net_fops_create( "ttm_all_stats", 0, &ttm_stats_fops);
#endif
    if (NULL == ttm_stats_entry) {
        TTM_INFO("cannot register ttm_all_stats.\n");
        goto proc_err;
    }
    /* get the address of function sock_def_readable
        * so later we can know whether the sock is for rpc, tux or others */
    sk_data_ready_addr = kallsyms_lookup_name("sock_def_readable");
    TTM_INFO("CPU [%u] sk_data_ready_addr = kallsyms_lookup_name(sock_def_readable) = %p\n",
            smp_processor_id(), (void *)sk_data_ready_addr);
    if (0 == sk_data_ready_addr) {
        TTM_INFO("cannot find sock_def_readable.\n");
        goto proc_err;
    }

    if (hook_tcp_ttm_functions() < 0) {
        goto proc_err;
    }

    TTM_INFO("ttm loaded\n");
    return 0;

proc_err:
    TTM_INFO("proc_err\n");

    if (NULL != ttm_stats_entry) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
        remove_proc_entry("ttm_all_stats", init_net.proc_net);
#else
        proc_net_remove( "ttm_all_stats");
#endif
        ttm_stats_entry = NULL;
    }
    if (NULL != ext_stats) {
        free_percpu(ext_stats);
        ext_stats = NULL;
    }

    return -1;
}


/* module cleanup*/
static void
ttm_exit(void)
{
    unhook_tcp_ttm_functions();
    synchronize_net();

    /* remove proc entries */
    if (NULL != ttm_stats_entry) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
        remove_proc_entry("ttm_all_stats", init_net.proc_net);
#else
        proc_net_remove( "ttm_all_stats");
#endif
        ttm_stats_entry = NULL;
    }

    if (NULL != ext_stats) {
        free_percpu(ext_stats);
        ext_stats = NULL;
    }
    TTM_INFO("ttm unloaded\n");
}

module_init(ttm_init);
module_exit(ttm_exit);

