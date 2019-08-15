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


#ifndef __TCP_TTM_H__
#define __TCP_TTM_H__

#include <linux/init.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/proc_fs.h>
#include <linux/err.h>
#include <linux/time.h>
#include <net/sock.h>

#include <linux/skbuff.h>
#include <net/inet_common.h>


#include <net/tcp.h>
#include <asm/uaccess.h>
#include <linux/netdevice.h>
#include <linux/kallsyms.h>

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,9))
#include <net/net_namespace.h>
#include <net/inet_sock.h>
#endif

#include <linux/ip.h>

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0))
 #define NIPQUAD(addr) \
    ((unsigned char *)&addr)[0], \
    ((unsigned char *)&addr)[1], \
    ((unsigned char *)&addr)[2], \
    ((unsigned char *)&addr)[3]
#endif

//#define DEBUG
#ifdef DEBUG
#define TTM_DBG(msg...) \
    do { \
        printk("[DEBUG] TTM: " msg); \
    }while (0)
#else
#define TTM_DBG(msg...)
#endif

#define TTM_INFO(msg...)            \
    do { \
        if (net_ratelimit())      \
            printk(KERN_INFO "[INFO] TTM: " msg);\
    }while(0)

#define TTM_WARNING(msg...)         \
    do { \
        if (net_ratelimit()) \
            printk(KERN_WARNING "[WARN] TTM: " msg);\
    }while(0)

#define TCPOPT_TTM  (254)

/* MUST be 4n !!!! */
#define TCPOLEN_TTM (8)     /* |opcode|size|ip+port| = 1 + 1 + 6 */

/* MUST be 4 bytes alignment */
struct ttm_data {
    u8 opcode;
    u8 opsize;
    u16 port;
    u32 ip;
};

/* MUST be 4 bytes alignment */
struct ttm_data_ipv6 {
    u8 opcode;
    u8 opsize;
    u16 port;
    u32 magic;
    u32 ip6_addr[4];
};

enum {
    /* statistics for syn proxy */
    SYN_RECV_SOCK_TTM_CNT = 1,
    SYN_RECV_SOCK_NO_TTM_CNT,
    GETNAME_TTM_OK_CNT,
    GETNAME_TTM_MISMATCH_CNT,
    GETNAME_TTM_BYPASS_CNT,
    GETNAME_TTM_EMPTY_CNT,
    TTM_STAT_LAST
};

struct ttm_stats_entry {
    char *name;
    int entry;
};

#define TTM_STAT_ITEM(_name, _entry) { \
        .name = _name,            \
        .entry = _entry,          \
}

#define TTM_STAT_END {    \
        NULL,           \
        0,              \
}

struct ttm_stat_mib {
    unsigned long mibs[TTM_STAT_LAST];
};

#define DEFINE_TTM_STAT(type, name)       \
        __typeof__(type) *name
#define DECLARE_TTM_STAT(type, name)      \
        extern __typeof__(type) *name
#define TTM_INC_STATS(mib, field)         \
        (per_cpu_ptr(mib, smp_processor_id())->mibs[field]++)
#define TTM_DEC_STATS(mib, field)         \
        (per_cpu_ptr(mib, smp_processor_id())->mibs[field]--)

#endif

