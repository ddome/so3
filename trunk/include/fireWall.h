/*Magic Code*/
/*
io.c
Copyright 1995 Philip Homburg
*/
#include <stdlib.h>
/*
inet/inet.h
Created:	Dec 30, 1991 by Philip Homburg
Copyright 1995 Philip Homburg
*/

#ifndef INET__INET_H
#define INET__INET_H

#define _SYSTEM	1	/* get OK and negative error codes */

#include <ansi.h>

#define CRAMPED (_EM_WSIZE==2)	/* 64K code and data is quite cramped. */
#define ZERO 0	/* Used to comment out initialization code that does nothing. */

#include <sys/types.h>
#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <minix/config.h>
#include <minix/type.h>
#include <minix/const.h>
#include <minix/com.h>
#include <minix/syslib.h>
#include <net/hton.h>
#include <net/gen/ether.h>
#include <net/gen/eth_hdr.h>
#include <net/gen/eth_io.h>
#include <net/gen/in.h>
#include <net/gen/ip_hdr.h>
#include <net/gen/ip_io.h>
#include <net/gen/icmp.h>
#include <net/gen/icmp_hdr.h>
#include <net/gen/oneCsum.h>
#include <net/gen/psip_hdr.h>
#include <net/gen/psip_io.h>
#include <net/gen/route.h>
#include <net/gen/tcp.h>
#include <net/gen/tcp_hdr.h>
#include <net/gen/tcp_io.h>
#include <net/gen/udp.h>
#include <net/gen/udp_hdr.h>
#include <net/gen/udp_io.h>
#include <net/ioctl.h>

#include "/usr/src/inet/const.h"
#include "/usr/src/inet/inet_config.h"

#define PUBLIC
#define EXTERN	extern
#define PRIVATE	static
#define FORWARD	static

typedef int ioreq_t;

#define THIS_FILE static char *this_file= __FILE__;

#if CRAMPED

/* Minimum panic info. */
#define ip_panic(print_list)  panic(this_file, __LINE__)
_PROTOTYPE( void panic, (char *file, int line) );

#else /* !CRAMPED */

/* Maximum panic info. */
#define ip_panic(print_list)  \
	(panic0(this_file, __LINE__), printf print_list, panic())
_PROTOTYPE( void panic0, (char *file, int line) );
_PROTOTYPE( void panic, (void) );

#endif /* !CRAMPED */

#if DEBUG
#define ip_warning(print_list)  \
	( \
		printf("warning at %s, %d: ", this_file, __LINE__), \
		printf print_list, \
		printf("\ninet stacktrace: "), \
		stacktrace() \
	)

#define DBLOCK(level, code) \
	do { if ((level) & DEBUG) { where(); code; } } while(0)
#define DIFBLOCK(level, condition, code) \
	do { if (((level) & DEBUG) && (condition)) \
		{ where(); code; } } while(0)

#else /* !DEBUG */
#define ip_warning(print_list)	0
#define DBLOCK(level, code)	0
#define DIFBLOCK(level, condition, code)	0
#endif

#define ARGS(x) _ARGS(x)

extern char version[];
extern int this_proc, synal_tasknr;

void stacktrace ARGS(( void ));

#endif /* INET__INET_H */

/*
 * $PchId: inet.h,v 1.8 1996/05/07 21:05:04 philip Exp $
 */


/*
io.h

Created Sept 30, 1991 by Philip Homburg

Copyright 1995 Philip Homburg
*/

#ifndef IO_H
#define IO_H

/* Prototypes */

void writeIpAddr ARGS(( ipaddr_t addr ));
void writeEtherAddr ARGS(( ether_addr_t *addr ));

#endif /* IO_H */

/*
 * $PchId: io.h,v 1.4 1995/11/21 06:45:27 philip Exp $
 */


PUBLIC void writeIpAddr(addr)
ipaddr_t addr;
{
#define addrInBytes ((u8_t *)&addr)

	printf("%d.%d.%d.%d", addrInBytes[0], addrInBytes[1],
		addrInBytes[2], addrInBytes[3]);
#undef addrInBytes
}

PUBLIC void writeEtherAddr(addr)
ether_addr_t *addr;
{
#define addrInBytes ((u8_t *)addr->ea_addr)

	printf("%x:%x:%x:%x:%x:%x", addrInBytes[0], addrInBytes[1],
		addrInBytes[2], addrInBytes[3], addrInBytes[4], addrInBytes[5]);
#undef addrInBytes
}

/*
 * $PchId: io.c,v 1.5 1995/11/21 06:45:27 philip Exp $
 */
/*----------------------------------------------------------------------*/
/*Aca comienza el nuevo codigo*/
/*
vmd/cmd/simple/fireWall.c
*/

#define _POSIX_C_SOURCE 2
#include <sys/types.h>
#include <errno.h>
#include <math.h>
#include <signal.h>
#include <net/gen/netdb.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <net/gen/oneCsum.h>
#include <fcntl.h>
#include <net/gen/in.h>
#include <net/gen/inet.h>
#include <net/gen/ip_hdr.h>
#include <net/gen/icmp_hdr.h>
#include <net/gen/ip_io.h>
#include <stdarg.h>
#include <string.h>
#include <net/netlib.h>
#include <net/hton.h>
#include <net/gen/route.h>
#include <net/gen/netdb.h>



