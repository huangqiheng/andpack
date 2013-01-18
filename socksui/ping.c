/* Copyright (c) Microsoft Corporation. All rights reserved. */
/*
 * Copyright (c) 1989, 1993
 *      The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Mike Muuss.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by the University of
 *      California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#if 0
static char copyright[] =
"@(#) Copyright (c) 1989, 1993\n\
        The Regents of the University of California.  All rights reserved.\n";

static char sccsid[] = "@(#)ping.c      8.1 (Berkeley) 6/5/93";
#endif

/*
 *                      P I N G . C
 *
 * Using the InterNet Control Message Protocol (ICMP) "ECHO" facility,
 * measure round-trip-delays and packet loss across network paths.
 *
 * Author -
 *      Mike Muuss
 *      U. S. Army Ballistic Research Laboratory
 *      December, 1983
 *
 * Status -
 *      Public Domain.  Distribution Unlimited.
 * Bugs -
 *      More statistics could always be gathered.
 *      This program has to run SUID to ROOT to access the ICMP socket.
 */

#define UNIX 0

#if UNIX
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <sys/time.h>
#include <sys/signal.h>

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip_var.h>
#include <netdb.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>

extern int errno;

#else

#include <stdio.h>
#include <mmlite.h>
#include <mmhal.h>
#include <stdlib.h>
#include <tchar.h>
#include <winsock.h>
typedef UINT16 n_short;
typedef UINT32 n_long;   /* long as received from the net */
typedef UINT32 n_time;   /* ms since 00:00 GMT, byte rev */

#ifdef _MSC_VER
#pragma warning(disable:4706)   /* assignment within conditional */
#endif
#include "getopt.c"

BOOL NewThread( void THREAD_LINKAGE ThreadFunction(THREAD_ARGUMENT),
                THREAD_ARGUMENT ThreadArgument);
static void THREAD_LINKAGE InputThread (THREAD_ARGUMENT Arg );

#define MAXHOSTNAMELEN 128
//FILE *stderr, *stdin;

_TCHAR *__progname = _T("ping");
volatile BOOL Exiting = FALSE;

char *_itot( _TCHAR *s);
TIME tvtoE( struct timeval *tv);

extern int optind;
extern _TCHAR *optarg;
extern int getopt(
        int nargc,
        _TCHAR * const *nargv,
        const _TCHAR *ostr);

#define bzero(p,s) memset(p,0,s)
#define bcopy(from,to,count) memcpy(to,from,count)
#define bcmp(a,b,c) memcmp(a,b,c)
void perror(char *msg);
#define putchar(c) _tprintf(_T("%c"),c)

typedef void (*SignalHandler)(void);
#define SIG_IGN NULL
#define SIGINT 0
#define SIGALRM 1
#define NSIG 2
SignalHandler signal(UINT SigNo, SignalHandler Handler);
void alarm(UINT nSeconds);

struct timezone {
 int unused;
};
void gettimeofday(struct timeval *now, struct timezone *zone);
void tvsub(struct timeval *out, struct timeval *in);

/* .... ip.h .... */

/*
 * Definitions for internet protocol version 4.
 * Per RFC 791, September 1981.
 */
#define IPVERSION 4

/*
 * Structure of an internet header, naked of options.
 */
#ifdef _MSC_VER
#pragma warning(disable:4214) /* nonstandard: bit field types other than int */
#endif

#ifdef __STDC__
#define BITFIELD_UINT8 UINT
#else
#define BITFIELD_UINT8 UINT8
#endif

struct ip {
    BITFIELD_UINT8
#if BYTE_ORDER == LITTLE_ENDIAN
          ip_hl:4,                  /* header length */
          ip_v:4;                   /* version */
#endif
#if BYTE_ORDER == BIG_ENDIAN
          ip_v:4,                   /* version */
          ip_hl:4;                  /* header length */
#endif
    UINT8 ip_tos;                   /* type of service */
    UINT16 ip_len;                  /* total length */
    UINT16 ip_id;                   /* identification */
    UINT16 ip_off;                  /* flags and fragment offset */
#define IP_DF 0x4000                /* dont fragment flag */
#define IP_MF 0x2000                /* more fragments flag */
#define IP_OFFMASK 0x1fff           /* mask for fragmenting bits */
    UINT8 ip_ttl;                   /* time to live */
    UINT8 ip_p;                     /* protocol */
    UINT16 ip_sum;                  /* checksum */
    struct in_addr ip_src, ip_dst;  /* source and dest address */
};

#define IP_MAXPACKET 65535          /* maximum packet size */

/*
 * Definitions for IP type of service (ip_tos)
 */
#define IPTOS_LOWDELAY    0x10
#define IPTOS_THROUGHPUT  0x08
#define IPTOS_RELIABILITY 0x04

/*
 * Definitions for IP precedence (also in ip_tos) (hopefully unused)
 */
#define IPTOS_PREC_NETCONTROL      0xe0
#define IPTOS_PREC_INTERNETCONTROL 0xc0
#define IPTOS_PREC_CRITIC_ECP      0xa0
#define IPTOS_PREC_FLASHOVERRIDE   0x80
#define IPTOS_PREC_FLASH           0x60
#define IPTOS_PREC_IMMEDIATE       0x40
#define IPTOS_PREC_PRIORITY        0x20
#define IPTOS_PREC_ROUTINE         0x10

/*
 * Definitions for options.
 */
#define IPOPT_COPIED(o) ((o)&0x80)
#define IPOPT_CLASS(o) ((o)&0x60)
#define IPOPT_NUMBER(o) ((o)&0x1f)

#define IPOPT_CONTROL   0x00
#define IPOPT_RESERVED1 0x20
#define IPOPT_DEBMEAS   0x40
#define IPOPT_RESERVED2 0x60

#define IPOPT_EOL      0    /* end of option list */
#define IPOPT_NOP      1    /* no operation */

#define IPOPT_RR       7    /* record packet route */
#define IPOPT_TS       68   /* timestamp */
#define IPOPT_SECURITY 130  /* provide s,c,h,tcc */
#define IPOPT_LSRR     131  /* loose source route */
#define IPOPT_SATID    136  /* satnet id */
#define IPOPT_SSRR     137  /* strict source route */

/*
 * Offsets to fields in options other than EOL and NOP.
 */
#define IPOPT_OPTVAL 0  /* option ID */
#define IPOPT_OLEN   1  /* option length */
#define IPOPT_OFFSET 2  /* offset within option */
#define IPOPT_MINOFF 4  /* min value of above */


/* .... ip.h .... */

/* ... ip_var.h ... */

#define MAX_IPOPTLEN 40

/* ... ip_var.h ... */

/* ... ip_icmp.h ... */

/*
 * Structure of an icmp header.
 */
struct icmp {
    UINT8 icmp_type;    /* type of message, see below */
    UINT8 icmp_code;    /* type sub code */
    UINT16 icmp_cksum;  /* ones complement cksum of struct */
    union {
        UINT8 ih_pptr;             /* ICMP_PARAMPROB */
        struct in_addr ih_gwaddr;  /* ICMP_REDIRECT */
        struct ih_idseq {
            n_short icd_id;
            n_short icd_seq;
        } ih_idseq;
        INT ih_void;

        /* ICMP_UNREACH_NEEDFRAG -- Path MTU Discovery (RFC1191) */
        struct ih_pmtu {
            n_short ipm_void;    
            n_short ipm_nextmtu;
        } ih_pmtu;
    } icmp_hun;
#define icmp_pptr icmp_hun.ih_pptr
#define icmp_gwaddr icmp_hun.ih_gwaddr
#define icmp_id icmp_hun.ih_idseq.icd_id
#define icmp_seq icmp_hun.ih_idseq.icd_seq
#define icmp_void icmp_hun.ih_void
#define icmp_pmvoid icmp_hun.ih_pmtu.ipm_void
#define icmp_nextmtu icmp_hun.ih_pmtu.ipm_nextmtu
    union {
        struct id_ts {
            n_time its_otime;
            n_time its_rtime;
            n_time its_ttime;
        } id_ts;
        struct id_ip  {
            struct ip idi_ip;
            /* options and then 64 bits of data */
        } id_ip;
        UINT32 id_mask;
        char id_data[1];
    } icmp_dun;
#define icmp_otime icmp_dun.id_ts.its_otime
#define icmp_rtime icmp_dun.id_ts.its_rtime
#define icmp_ttime icmp_dun.id_ts.its_ttime
#define icmp_ip icmp_dun.id_ip.idi_ip
#define icmp_mask icmp_dun.id_mask
#define icmp_data icmp_dun.id_data
};

/*
 * Lower bounds on packet lengths for various types.
 * For the error advice packets must first insure that the
 * packet is large enought to contain the returned ip header.
 * Only then can we do the check to see if 64 bits of packet
 * data have been returned, since we need to check the returned
 * ip header length.
 */
#define ICMP_MINLEN 8                                /* abs minimum */
#define ICMP_TSLEN (8 + 3 * sizeof (n_time))         /* timestamp */
#define ICMP_MASKLEN 12                              /* address mask */
#define ICMP_ADVLENMIN (8 + sizeof (struct ip) + 8)  /* min */
#define ICMP_ADVLEN(p) (8 + ((p)->icmp_ip.ip_hl << 2) + 8)
                       /* N.B.: must separately check that ip_hl >= 5 */

/*
 * Definition of type and code field values.
 */
#define ICMP_ECHOREPLY            0  /* echo reply */
#define ICMP_UNREACH              3  /* dest unreachable, codes: */
#define ICMP_UNREACH_NET                0  /* bad net */
#define ICMP_UNREACH_HOST               1  /* bad host */
#define ICMP_UNREACH_PROTOCOL           2  /* bad protocol */
#define ICMP_UNREACH_PORT               3  /* bad port */
#define ICMP_UNREACH_NEEDFRAG           4  /* IP_DF caused drop */
#define ICMP_UNREACH_SRCFAIL            5  /* src route failed */
#define ICMP_UNREACH_NET_UNKNOWN        6  /* unknown net */
#define ICMP_UNREACH_HOST_UNKNOWN       7  /* unknown host */
#define ICMP_UNREACH_ISOLATED           8  /* src host isolated */
#define ICMP_UNREACH_NET_PROHIB         9  /* prohibited access */
#define ICMP_UNREACH_HOST_PROHIB       10  /* ditto */
#define ICMP_UNREACH_TOSNET            11  /* bad tos for net */
#define ICMP_UNREACH_TOSHOST           12  /* bad tos for host */
#define ICMP_SOURCEQUENCH         4  /* packet lost, slow down */
#define ICMP_REDIRECT             5  /* shorter route, codes: */
#define ICMP_REDIRECT_NET               0  /* for network */
#define ICMP_REDIRECT_HOST              1  /* for host */
#define ICMP_REDIRECT_TOSNET            2  /* for tos and net */
#define ICMP_REDIRECT_TOSHOST           3  /* for tos and host */
#define ICMP_ECHO                 8  /* echo service */
#define ICMP_ROUTERADVERT         9  /* router advertisement */
#define ICMP_ROUTERSOLICIT       10  /* router solicitation */
#define ICMP_TIMXCEED            11  /* time exceeded, codes: */
#define ICMP_TIMXCEED_INTRANS           0  /* ttl==0 in transit */
#define ICMP_TIMXCEED_REASS             1  /* ttl==0 in reass */
#define ICMP_PARAMPROB           12  /* ip header bad */
#define ICMP_PARAMPROB_OPTABSENT        1  /* req. opt. absent */
#define ICMP_TSTAMP              13  /* timestamp request */
#define ICMP_TSTAMPREPLY         14  /* timestamp reply */
#define ICMP_IREQ                15  /* information request */
#define ICMP_IREQREPLY           16  /* information reply */
#define ICMP_MASKREQ             17  /* address mask request */
#define ICMP_MASKREPLY           18  /* address mask reply */

#define ICMP_MAXTYPE             18

#define ICMP_INFOTYPE(type) \
    ((type) == ICMP_ECHOREPLY || (type) == ICMP_ECHO || \
    (type) == ICMP_ROUTERADVERT || (type) == ICMP_ROUTERSOLICIT || \
    (type) == ICMP_TSTAMP || (type) == ICMP_TSTAMPREPLY || \
    (type) == ICMP_IREQ || (type) == ICMP_IREQREPLY || \
    (type) == ICMP_MASKREQ || (type) == ICMP_MASKREPLY)

/* ... ip_icmp.h ... */

#endif


#define DEFDATALEN      (64 - 8)        /* default data length */
#define MAXIPLEN        60
#define MAXICMPLEN      76
#define MAXPACKET       (65536 - 60 - 8)/* max packet size */
#define MAXWAIT         10              /* max seconds to wait for response */
#define NROUTES         9               /* number of record route slots */

#define A(bit)          rcvd_tbl[(bit)>>3]      /* identify byte in array */
#define B(bit)          (1 << ((bit) & 0x07))   /* identify bit in byte */
#define SET(bit)        (A(bit) |= B(bit))
#define CLR(bit)        (A(bit) &= (~B(bit)))
#define TST(bit)        (A(bit) & B(bit))

/* various options */
int options;
#define F_FLOOD         0x001
#define F_INTERVAL      0x002
#define F_NUMERIC       0x004
#define F_PINGFILLED    0x008
#define F_QUIET         0x010
#define F_RROUTE        0x020
#define F_SO_DEBUG      0x040
#define F_SO_DONTROUTE  0x080
#define F_VERBOSE       0x100

/*
 * MAX_DUP_CHK is the number of bits in received table, i.e. the maximum
 * number of received sequence numbers we can keep track of.  Change 128
 * to 8192 for complete accuracy...
 */
#define MAX_DUP_CHK     (8 * 128)
int mx_dup_ck = MAX_DUP_CHK;
char rcvd_tbl[MAX_DUP_CHK / 8];

struct sockaddr whereto;        /* who to ping */
int datalen = DEFDATALEN;
int s;                          /* socket file descriptor */
u_char outpack[MAXPACKET];
char BSPACE = '\b';             /* characters written for flood */
char DOT = '.';
char *hostname;
UINT16 ident;                   /* id to identify our packets */

char hnamebuf[MAXHOSTNAMELEN];

/* counters */
UINT npackets;                  /* max packets to transmit */
UINT nreceived;                 /* # of packets we got back */
UINT nrepeats;                  /* number of duplicates */
UINT ntransmitted;              /* sequence # for outbound packets = #sent */
int interval = 1;               /* interval between packets */

/* timing */
int timing;                     /* flag to do timing */
UINT64 tmin = Int64Initializer(0,999999999);    /* minimum round trip time */
UINT64 tmax = Int64Initializer(0,0);            /* maximum round trip time */
UINT64 tsum = Int64Initializer(0,0);            /* sum of all times, for doing average */

/* Made global so that they can be freed at the end */
char *target=NULL;
u_char *packet=NULL;

void usage(void);
void pinger(void);
void pr_pack(char *buf, int cc, struct sockaddr_in *from);
void fill(char *bp, _TCHAR *patp);
UINT16 in_cksum(UINT16 *addr, int len);
void pr_icmph(struct icmp *icp);
void pr_iph(struct ip *ip);
_TCHAR *pr_addr(u_long l);
void pr_retip(struct ip *ip);
void catcher(void), finish(void);

/*  MyExit is called twice (by two threads). So, in order to make sure that
 *  the same memory is not freed twice, pointers 'target' and 'packet' are
 *  made NULL after freeing the memory once.
 */

void MyExit(int value)
{
    Exiting = TRUE;
#if !UNIX
    FreeCmdLine(0,0);
#endif
    if (target) {
        free(target);
        target = NULL;
    }
    if (packet) {
        free(packet);
        packet = NULL;
    }
    exit(value);
}

int _tmain(INT argc, _TCHAR *argv[])
{
        struct timeval timeout;
        struct hostent *hp;
        struct sockaddr_in *to;
#if UNIX || GET_X_BY_Y
        struct protoent *proto;
#endif
        register int i;
        int ch, hold, packlen, preload;
        fd_set fdmask;
        u_char *datap;
#ifdef IP_OPTIONS
        char rspace[3 + 4 * NROUTES + 1];       /* record route space */
#endif

#if !UNIX
        SCODE sc;
        if (argv == NULL) {
            sc = ParseCmdLine(&argc, &argv);
            if (FAILED(sc))
                MyExit(sc);
        }
#endif
        preload = 0;
        datap = &outpack[8 + sizeof(struct timeval)];
        while ((ch = getopt(argc, argv, _T("Rc:dfh:i:l:np:qrs:v"))) != EOF)
                switch(ch) {
                case 'c':
                        npackets = _ttoi(optarg);
                        if (npackets <= 0) {
                                (void)_ftprintf(stderr,
                                    _T("ping: bad number of packets to transmit.\n"));
                                MyExit(1);
                        }
                        break;
                case 'd':
                        options |= F_SO_DEBUG;
                        break;
                case 'f':
#if UNIX
                        if (getuid()) {
                                (void)_ftprintf(stderr,
                                    _T("ping: %s\n"), strerror(EPERM));
                                MyExit(1);
                        }
                        setbuf(stdout, (char *)NULL);
#endif
                        options |= F_FLOOD;
                        break;
                case 'i':               /* wait between sending packets */
                        interval = _ttoi(optarg);
                        if (interval <= 0) {
                                (void)_ftprintf(stderr,
                                    _T("ping: bad timing interval.\n"));
                                MyExit(1);
                        }
                        options |= F_INTERVAL;
                        break;
                case 'l':
                        preload = _ttoi(optarg);
                        if (preload < 0) {
                                (void)_ftprintf(stderr,
                                    _T("ping: bad preload value.\n"));
                                MyExit(1);
                        }
                        break;
                case 'n':
                        options |= F_NUMERIC;
                        break;
#if UNIX
                case 'p':               /* fill buffer with user pattern */
                        options |= F_PINGFILLED;
                        fill((char *)datap, optarg);
                                break;
#endif
                case 'q':
                        options |= F_QUIET;
                        break;
                case 'R':
                        options |= F_RROUTE;
                        break;
                case 'r':
                        options |= F_SO_DONTROUTE;
                        break;
                case 's':               /* size of packet to send */
                        datalen = _ttoi(optarg);
                        if (datalen > MAXPACKET) {
                                (void)_ftprintf(stderr,
                                    _T("ping: packet size too large.\n"));
                                MyExit(1);
                        }
                        if (datalen <= 0) {
                                (void)_ftprintf(stderr,
                                    _T("ping: illegal packet size.\n"));
                                MyExit(1);
                        }
                        break;
                case 'v':
                        options |= F_VERBOSE;
                        break;
                default:
                        usage();
                }
        argc -= optind;
        argv += optind;

        if (argc != 1)
                usage();
        target = _itot(*argv);

        bzero((char *)&whereto, sizeof(struct sockaddr));
        to = (struct sockaddr_in *)&whereto;
        to->sin_family = AF_INET;
        to->sin_len = 16;
        to->sin_addr.s_addr = inet_addr(target);
        if (to->sin_addr.s_addr != (u_int)-1)
                hostname = target;
        else {
                hp = gethostbyname(target);
                if (!hp) {
                        (void)_ftprintf(stderr,
                            _T("ping: unknown host %hs\n"), target);
                        MyExit(1);
                }
                to->sin_family = (UINT8) hp->h_addrtype;
                bcopy(hp->h_addr, (PTR)&to->sin_addr, hp->h_length);
                (void)strncpy(hnamebuf, hp->h_name, sizeof(hnamebuf) - 1);
                hostname = hnamebuf;
        }

        if (options & F_FLOOD && options & F_INTERVAL) {
                (void)_ftprintf(stderr,
                    _T("ping: -f and -i incompatible options.\n"));
                MyExit(1);
        }

        if (datalen >= sizeof(struct timeval))  /* can we time transfer */
                timing = 1;
        packlen = datalen + MAXIPLEN + MAXICMPLEN;
        packet = (u_char *)malloc((u_int)packlen);
        if (!packet) {
                (void)_ftprintf(stderr, _T("ping: out of memory.\n"));
                MyExit(1);
        }
        if (!(options & F_PINGFILLED))
                for (i = 8; i < datalen; ++i)
                        *datap++ = (u_char)i;

        ident = (UINT16)Int64ToInt32(CurrentTime());

#if UNIX || GET_X_BY_Y
        if (!(proto = getprotobyname("icmp"))) {
                (void)_ftprintf(stderr, _T("ping: unknown protocol icmp.\n"));
                MyExit(1);
        }
        if ((s = socket(AF_INET, SOCK_RAW, proto->p_proto)) == -1)
#else
        if ((s = socket(AF_INET, SOCK_RAW, 1)) == INVALID_SOCKET)
#endif
        {
                perror("ping: socket");
                MyExit(1);
        }

#define IGOTABUG 1
#if IGOTABUG
        /* BUGBUG why do I have to bind it ? why is inp_laddr 0 ?
         * If I dont say I have an IP header the IP address should come
         * from the interface this gets sent from. Damn.
         */
    {

#define USE_IP_ADDR_DIRECTLY 1
#if USE_IP_ADDR_DIRECTLY

        /*  NOW -> uses ip address directly using gethostaddr() and 
         *         if doesn't work then try dns on own name
         *  OLD -> tries to map host name to ip assuming stringified ipaddress and 
         *         if it doesn't work then using dns query on name to get own ip address
         */

        struct sockaddr_in sinme;
        char myname[32];
        memset(&sinme,0,sizeof sinme);
        sinme.sin_family = AF_INET;
        sinme.sin_len = 16;
        sinme.sin_addr.s_addr = gethostaddr();
        if (sinme.sin_addr.s_addr == INADDR_NONE) {
            /* Try DNS */

            gethostname(myname,32);
            hp = gethostbyname(myname);
            if (!hp) {
                (void) fprintf(stderr,
                               "ping: who am I? unknown host %hs\n",
                               myname);
                MyExit(1);
            }
            sinme.sin_family = (UINT8) hp->h_addrtype;
            bcopy(hp->h_addr, (PTR)&sinme.sin_addr, hp->h_length);

        }
#else
        struct sockaddr_in sinme;
        char myname[32];
        gethostname(myname,32);
        memset(&sinme,0,sizeof sinme);
        sinme.sin_family = AF_INET;
        sinme.sin_len = 16;
        sinme.sin_addr.s_addr = inet_addr(myname);
        if (sinme.sin_addr.s_addr == INADDR_NONE) {
            /* Try DNS */
            struct hostent *hp;
            hp = gethostbyname(myname);
            if (!hp) {
                (void) fprintf(stderr,
                               "ping: who am I? unknown host %hs\n",
                               myname);
                MyExit(1);
            }
            sinme.sin_family = (UINT8) hp->h_addrtype;
            bcopy(hp->h_addr, (PTR)&sinme.sin_addr, hp->h_length);

        }
#endif
        if (bind(s, (const struct sockaddr *)&sinme, sizeof(sinme)) < 0) {
            perror("ping: bind");
            MyExit(1);
        }
    }
#endif
        hold = 1;
        if (options & F_SO_DEBUG)
                (void)setsockopt(s, SOL_SOCKET, SO_DEBUG, (char *)&hold,
                    sizeof(hold));
        if (options & F_SO_DONTROUTE)
                (void)setsockopt(s, SOL_SOCKET, SO_DONTROUTE, (char *)&hold,
                    sizeof(hold));

        /* record route option */
        if (options & F_RROUTE) {
#ifdef IP_OPTIONS
                rspace[IPOPT_OPTVAL] = IPOPT_RR;
                rspace[IPOPT_OLEN] = sizeof(rspace)-1;
                rspace[IPOPT_OFFSET] = IPOPT_MINOFF;
                if (setsockopt(s, IPPROTO_IP, IP_OPTIONS, rspace,
                    sizeof(rspace)) < 0) {
                        perror("ping: record route");
                        MyExit(1);
                }
#else
                (void)_ftprintf(stderr,
                  _T("ping: record route not available in this implementation.\n"));
                MyExit(1);
#endif /* IP_OPTIONS */
        }

        /*
         * When pinging the broadcast address, you can get a lot of answers.
         * Doing something so evil is useful if you are trying to stress the
         * ethernet, or just want to fill the arp cache to get some stuff for
         * /etc/ethers.
         */
        hold = 48 * 1024;
        (void)setsockopt(s, SOL_SOCKET, SO_RCVBUF, (char *)&hold,
            sizeof(hold));

        if (to->sin_family == AF_INET)
                (void)_tprintf(_T("PING %hs (%hs): %d data bytes\n"), hostname,
                    inet_ntoa(*(struct in_addr *)&to->sin_addr.s_addr),
                    datalen);
        else
                (void)_tprintf(_T("PING %hs: %d data bytes\n"), hostname, datalen);

#if !UNIX
        NewThread( InputThread, stdin );
#endif

        (void)signal(SIGINT, finish);
        (void)signal(SIGALRM, catcher);

        while (preload--)               /* fire off them quickies */
                pinger();

        if ((options & F_FLOOD) == 0)
                catcher();              /* start things going */

        while (!Exiting) {
                struct sockaddr_in from;
                register int cc;
                int fromlen;

                if (options & F_FLOOD) {
                        pinger();
                        timeout.tv_sec = 0;
                        timeout.tv_usec = 10000;
                        FD_ZERO(&fdmask);
                        FD_SET(s,&fdmask);
                        if (select(s + 1, &fdmask, NULL, NULL, &timeout) < 1)
                                continue;
                }
                fromlen = sizeof(from);
                if ((cc = recvfrom(s, (char *)packet, packlen, 0,
                    (struct sockaddr *)&from, &fromlen)) < 0) {
#if UNIX
                        if (errno == EINTR)
                                continue;
#endif
                        perror("ping: recvfrom");
                        continue;
                }
                pr_pack((char *)packet, cc, &from);
                if (npackets && nreceived >= npackets)
                        break;
        }
        finish();
        /* NOTREACHED */
        return 0;
}

/*
 * catcher --
 *      This routine causes another PING to be transmitted, and then
 * schedules another SIGALRM for 1 second from now.
 *
 * bug --
 *      Our sense of time will slowly skew (i.e., packets will not be
 * launched exactly at 1-second intervals).  This does not affect the
 * quality of the delay and loss statistics.
 */
void
catcher(void)
{
        u_int waittime;

        pinger();
        (void)signal(SIGALRM, catcher);
        if (!npackets || ntransmitted < npackets)
                alarm((u_int)interval);
        else {
                if (nreceived) {
                        waittime = (u_int)(2 * Int64ToInt32(Int64DividedByInt32(Uint64ToInt64(tmax), 10000000)));
                        if (waittime == 0)
                                waittime = 1;
                } else
                        waittime = MAXWAIT;
                (void)signal(SIGALRM, finish);
                (void)alarm(waittime);
        }
}

/*
 * pinger --
 *      Compose and transmit an ICMP ECHO REQUEST packet.  The IP packet
 * will be added on by the kernel.  The ID field is our UNIX process ID,
 * and the sequence number is an ascending integer.  The first 8 bytes
 * of the data portion are used to hold a UNIX "timeval" struct in <xxx>
 * byte-order, to compute the round-trip time.
 */
void pinger(void)
{
        register struct icmp *icp;
        register int cc;
        int i;

        if (s == INVALID_SOCKET) return;

        icp = (struct icmp *)outpack;
        icp->icmp_type = ICMP_ECHO;
        icp->icmp_code = 0;
        icp->icmp_cksum = 0;
        icp->icmp_seq = (UINT16)ntransmitted++;
        icp->icmp_id = ident;                   /* ID */

        CLR(icp->icmp_seq % mx_dup_ck);

        if (timing)
                (void)gettimeofday((struct timeval *)&outpack[8],
                    (struct timezone *)NULL);

        cc = datalen + 8;                       /* skips ICMP portion */

        /* compute ICMP checksum here */
        icp->icmp_cksum = in_cksum((UINT16 *)icp, cc);

        i = sendto(s, (char *)outpack, cc, 0, &whereto,
            sizeof(struct sockaddr));

        if (i < 0 || i != cc)  {
                if (i < 0)
                        perror("ping: sendto");
                (void)_tprintf(_T("ping: wrote %hs %d chars, ret=%d\n"),
                    hostname, cc, i);
        }
        if (!(options & F_QUIET) && options & F_FLOOD)
                (void)_tprintf(_T("%c"), DOT);
}

/*
 * pr_pack --
 *      Print out the packet, if it came from us.  This logic is necessary
 * because ALL readers of the ICMP socket get a copy of ALL ICMP packets
 * which arrive ('tis only fair).  This permits multiple copies of this
 * program to be run without having intermingled output (or statistics!).
 */
void pr_pack(char *buf, int cc, struct sockaddr_in *from)
{
        register struct icmp *icp;
        register u_long l;
        register int i, j;
        register u_char *cp,*dp;
        static int old_rrlen;
        static char old_rr[MAX_IPOPTLEN];
        struct ip *ip;
        struct timeval tv, *tp;
        TIME triptime;
        int hlen, dupflag;

        Int32ToInt64(triptime,0);

        (void)gettimeofday(&tv, (struct timezone *)NULL);

        /* Check the IP header */
        ip = (struct ip *)buf;
        hlen = ip->ip_hl << 2;
        if (cc < hlen + ICMP_MINLEN) {
                if (options & F_VERBOSE)
                        (void)_ftprintf(stderr,
                          _T("ping: packet too short (%d bytes) from %hs\n"), cc,
                          inet_ntoa(*(struct in_addr *)&from->sin_addr.s_addr));
                return;
        }

        /* Now the ICMP part */
        cc -= hlen;
        icp = (struct icmp *)(buf + hlen);
        if (icp->icmp_type == ICMP_ECHOREPLY) {
                if (icp->icmp_id != ident)
                        return;                 /* 'Twas not our ECHO */
                ++nreceived;
                if (timing) {
#ifndef icmp_data
                        tp = (struct timeval *)&icp->icmp_ip;
#else
                        tp = (struct timeval *)icp->icmp_data;
#endif
                        tvsub(&tv, tp);
                        triptime = tvtoE(&tv);
                        if (Uint64Less(Int64ToUint64(triptime), tmin))
                                tmin = Int64ToUint64(triptime);
                        if (Uint64Less(tmax, Int64ToUint64(triptime)))
                                tmax = Int64ToUint64(triptime);
#if whenabugisfixed
                        tsum = Uint64Add(tsum, Int64ToUint64(triptime));
#else
                        triptime = Int64Add(Uint64ToInt64(tsum),triptime);
                        tsum = Int64ToUint64(triptime);
#endif
                }

                if (TST(icp->icmp_seq % mx_dup_ck)) {
                        ++nrepeats;
                        --nreceived;
                        dupflag = 1;
                } else {
                        SET(icp->icmp_seq % mx_dup_ck);
                        dupflag = 0;
                }

                if (options & F_QUIET)
                        return;

                if (options & F_FLOOD)
                        (void)_tprintf(_T("%c"), BSPACE);
                else {
                        (void)_tprintf(_T("%d bytes from %hs: icmp_seq=%u"),cc,
                           inet_ntoa(*(struct in_addr *)&from->sin_addr.s_addr),
                           icp->icmp_seq);
                        (void)_tprintf(_T(" ttl=%d"), ip->ip_ttl);
                        if (timing)
                                (void)_tprintf(_T(" time=%d micros"), Int64ToInt32(triptime)/10);
                        if (dupflag)
                                (void)_tprintf(_T(" (DUP!)"));
                        /* check the data */
                        cp = (u_char*)&icp->icmp_data[8];
                        dp = &outpack[8 + sizeof(struct timeval)];
                        for (i = 8; i < datalen; ++i, ++cp, ++dp) {
                                if (*cp != *dp) {
        (void)_tprintf(_T("\nwrong data byte #%d should be 0x%x but was 0x%x"),
            i, *dp, *cp);
                                        cp = (u_char*)&icp->icmp_data[0];
                                        for (i = 8; i < datalen; ++i, ++cp) {
                                                if ((i % 32) == 8)
                                                        (void)_tprintf(_T("\n\t"));
                                                (void)_tprintf(_T("%x "), *cp);
                                        }
                                        break;
                                }
                        }
                }
        } else {
                /* We've got something other than an ECHOREPLY */
                if (!(options & F_VERBOSE))
                        return;
                (void)_tprintf(_T("%d bytes from %s: "), cc,
                    pr_addr(from->sin_addr.s_addr));
                pr_icmph(icp);
        }

        /* Display any IP options */
        cp = (u_char *)buf + sizeof(struct ip);

        for (; hlen > (int)sizeof(struct ip); --hlen, ++cp)
                switch (*cp) {
                case IPOPT_EOL:
                        hlen = 0;
                        break;
                case IPOPT_LSRR:
                        (void)_tprintf(_T("\nLSRR: "));
                        hlen -= 2;
                        j = *++cp;
                        ++cp;
                        if (j > IPOPT_MINOFF)
                                for (;;) {
                                        l = *++cp;
                                        l = (l<<8) + *++cp;
                                        l = (l<<8) + *++cp;
                                        l = (l<<8) + *++cp;
                                        if (l == 0)
                                                (void)_tprintf(_T("\t0.0.0.0"));
                                else
                                        (void)_tprintf(_T("\t%s"), pr_addr(ntohl(l)));
                                hlen -= 4;
                                j -= 4;
                                if (j <= IPOPT_MINOFF)
                                        break;
                                (void)putchar('\n');
                        }
                        break;
                case IPOPT_RR:
                        j = *++cp;              /* get length */
                        i = *++cp;              /* and pointer */
                        hlen -= 2;
                        if (i > j)
                                i = j;
                        i -= IPOPT_MINOFF;
                        if (i <= 0)
                                continue;
                        if (i == old_rrlen
                            && cp == (u_char *)buf + sizeof(struct ip) + 2
                            && !bcmp((char *)cp, old_rr, i)
                            && !(options & F_FLOOD)) {
                                (void)_tprintf(_T("\t(same route)"));
                                i = ((i + 3) / 4) * 4;
                                hlen -= i;
                                cp += i;
                                break;
                        }
                        old_rrlen = i;
                        bcopy((char *)cp, old_rr, i);
                        (void)_tprintf(_T("\nRR: "));
                        for (;;) {
                                l = *++cp;
                                l = (l<<8) + *++cp;
                                l = (l<<8) + *++cp;
                                l = (l<<8) + *++cp;
                                if (l == 0)
                                        (void)_tprintf(_T("\t0.0.0.0"));
                                else
                                        (void)_tprintf(_T("\t%s"), pr_addr(ntohl(l)));
                                hlen -= 4;
                                i -= 4;
                                if (i <= 0)
                                        break;
                                (void)putchar('\n');
                        }
                        break;
                case IPOPT_NOP:
                        (void)_tprintf(_T("\nNOP"));
                        break;
                default:
                        (void)_tprintf(_T("\nunknown option %x"), *cp);
                        break;
                }
        if (!(options & F_FLOOD)) {
                (void)putchar('\n');
        }
}

/*
 * in_cksum --
 *      Checksum routine for Internet Protocol family headers (C Version)
 */
UINT16 in_cksum(UINT16 *addr, int len)
{
        register int nleft = len;
        register UINT16 *w = addr;
        register int sum = 0;
        UINT16 answer = 0;

        /*
         * Our algorithm is simple, using a 32 bit accumulator (sum), we add
         * sequential 16 bit words to it, and at the end, fold back all the
         * carry bits from the top 16 bits into the lower 16 bits.
         */
        while (nleft > 1)  {
                sum += *w++;
                nleft -= 2;
        }

        /* mop up an odd byte, if necessary */
        if (nleft == 1) {
                *(u_char *)(&answer) = *(u_char *)w ;
                sum += answer;
        }

        /* add back carry outs from top 16 bits to low 16 bits */
        sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
        sum += (sum >> 16);                     /* add carry */
        answer = (UINT16)(~sum);                /* truncate to 16 bits */
        return(answer);
}

/*
 * tvsub --
 *      Subtract 2 timeval structs:  out = out - in.  Out is assumed to
 * be >= in.
 */
void tvsub(struct timeval *out, struct timeval *in)
{
        if ((out->tv_usec -= in->tv_usec) < 0) {
                --out->tv_sec;
                out->tv_usec += 1000000;
        }
        out->tv_sec -= in->tv_sec;
}

/*
 * finish --
 *      Print out statistics, and give up.
 */
void
finish(void)
{
        int ss = s;
        (void)signal(SIGINT, SIG_IGN);
        (void)putchar('\n');
        (void)_tprintf(_T("--- %hs ping statistics ---\n"), hostname);
        (void)_tprintf(_T("%d packets transmitted, "), ntransmitted);
        (void)_tprintf(_T("%d packets received, "), nreceived);
        if (nrepeats)
                (void)_tprintf(_T("+%d duplicates, "), nrepeats);
        if (ntransmitted) {
                if (nreceived > ntransmitted)
                        (void)_tprintf(_T("-- somebody's printing up packets!"));
                else
                        (void)_tprintf(_T("%d%% packet loss"),
                            (int) (((ntransmitted - nreceived) * 100) /
                            ntransmitted));
        }
        (void)putchar('\n');
        if (nreceived && timing) {
                /* Only display average to microseconds */
                UINT32 m, a, M;
                m = Uint64ToUint32(tmin) / 10;
                a = Uint64ToUint32(tsum) / ((nreceived + nrepeats) * 10);
                M = Uint64ToUint32(tmax) / 10;
                (void)_tprintf(_T("round-trip min/avg/max = %d/%d/%d micros\n"),
                             m, a, M);
        }
        
        s = INVALID_SOCKET;
        closesocket(ss);
        MyExit(0);
}

#ifdef notdef
static char *ttab[] = {
        "Echo Reply",           /* ip + seq + udata */
        "Dest Unreachable",     /* net, host, proto, port, frag, sr + IP */
        "Source Quench",        /* IP */
        "Redirect",             /* redirect type, gateway, + IP  */
        "Echo",
        "Time Exceeded",        /* transit, frag reassem + IP */
        "Parameter Problem",    /* pointer + IP */
        "Timestamp",            /* id + seq + three timestamps */
        "Timestamp Reply",      /* " */
        "Info Request",         /* id + sq */
        "Info Reply"            /* " */
};
#endif

/*
 * pr_icmph --
 *      Print a descriptive string about an ICMP header.
 */
void pr_icmph(struct icmp *icp)
{
        switch(icp->icmp_type) {
        case ICMP_ECHOREPLY:
                (void)_tprintf(_T("Echo Reply\n"));
                /* XXX ID + Seq + Data */
                break;
        case ICMP_UNREACH:
                switch(icp->icmp_code) {
                case ICMP_UNREACH_NET:
                        (void)_tprintf(_T("Destination Net Unreachable\n"));
                        break;
                case ICMP_UNREACH_HOST:
                        (void)_tprintf(_T("Destination Host Unreachable\n"));
                        break;
                case ICMP_UNREACH_PROTOCOL:
                        (void)_tprintf(_T("Destination Protocol Unreachable\n"));
                        break;
                case ICMP_UNREACH_PORT:
                        (void)_tprintf(_T("Destination Port Unreachable\n"));
                        break;
                case ICMP_UNREACH_NEEDFRAG:
                        (void)_tprintf(_T("frag needed and DF set\n"));
                        break;
                case ICMP_UNREACH_SRCFAIL:
                        (void)_tprintf(_T("Source Route Failed\n"));
                        break;
                default:
                        (void)_tprintf(_T("Dest Unreachable, Bad Code: %d\n"),
                            icp->icmp_code);
                        break;
                }
                /* Print returned IP header information */
#ifndef icmp_data
                pr_retip(&icp->icmp_ip);
#else
                pr_retip((struct ip *)icp->icmp_data);
#endif
                break;
        case ICMP_SOURCEQUENCH:
                (void)_tprintf(_T("Source Quench\n"));
#ifndef icmp_data
                pr_retip(&icp->icmp_ip);
#else
                pr_retip((struct ip *)icp->icmp_data);
#endif
                break;
        case ICMP_REDIRECT:
                switch(icp->icmp_code) {
                case ICMP_REDIRECT_NET:
                        (void)_tprintf(_T("Redirect Network"));
                        break;
                case ICMP_REDIRECT_HOST:
                        (void)_tprintf(_T("Redirect Host"));
                        break;
                case ICMP_REDIRECT_TOSNET:
                        (void)_tprintf(_T("Redirect Type of Service and Network"));
                        break;
                case ICMP_REDIRECT_TOSHOST:
                        (void)_tprintf(_T("Redirect Type of Service and Host"));
                        break;
                default:
                        (void)_tprintf(_T("Redirect, Bad Code: %d"), icp->icmp_code);
                        break;
                }
                (void)_tprintf(_T("(New addr: 0x%08x)\n"), icp->icmp_gwaddr.s_addr);
#ifndef icmp_data
                pr_retip(&icp->icmp_ip);
#else
                pr_retip((struct ip *)icp->icmp_data);
#endif
                break;
        case ICMP_ECHO:
                (void)_tprintf(_T("Echo Request\n"));
                /* XXX ID + Seq + Data */
                break;
        case ICMP_TIMXCEED:
                switch(icp->icmp_code) {
                case ICMP_TIMXCEED_INTRANS:
                        (void)_tprintf(_T("Time to live exceeded\n"));
                        break;
                case ICMP_TIMXCEED_REASS:
                        (void)_tprintf(_T("Frag reassembly time exceeded\n"));
                        break;
                default:
                        (void)_tprintf(_T("Time exceeded, Bad Code: %d\n"),
                            icp->icmp_code);
                        break;
                }
#ifndef icmp_data
                pr_retip(&icp->icmp_ip);
#else
                pr_retip((struct ip *)icp->icmp_data);
#endif
                break;
        case ICMP_PARAMPROB:
                (void)_tprintf(_T("Parameter problem: pointer = 0x%02x\n"),
                    icp->icmp_hun.ih_pptr);
#ifndef icmp_data
                pr_retip(&icp->icmp_ip);
#else
                pr_retip((struct ip *)icp->icmp_data);
#endif
                break;
        case ICMP_TSTAMP:
                (void)_tprintf(_T("Timestamp\n"));
                /* XXX ID + Seq + 3 timestamps */
                break;
        case ICMP_TSTAMPREPLY:
                (void)_tprintf(_T("Timestamp Reply\n"));
                /* XXX ID + Seq + 3 timestamps */
                break;
        case ICMP_IREQ:
                (void)_tprintf(_T("Information Request\n"));
                /* XXX ID + Seq */
                break;
        case ICMP_IREQREPLY:
                (void)_tprintf(_T("Information Reply\n"));
                /* XXX ID + Seq */
                break;
#ifdef ICMP_MASKREQ
        case ICMP_MASKREQ:
                (void)_tprintf(_T("Address Mask Request\n"));
                break;
#endif
#ifdef ICMP_MASKREPLY
        case ICMP_MASKREPLY:
                (void)_tprintf(_T("Address Mask Reply\n"));
                break;
#endif
        default:
                (void)_tprintf(_T("Bad ICMP type: %d\n"), icp->icmp_type);
        }
}

/*
 * pr_iph --
 *      Print an IP header with options.
 */
void pr_iph(struct ip *ip)
{
        int hlen;
        u_char *cp;

        hlen = ip->ip_hl << 2;
        cp = (u_char *)ip + 20;         /* point to options */

        (void)_tprintf(_T("Vr HL TOS  Len   ID Flg  off TTL Pro  cks      Src      Dst Data\n"));
        (void)_tprintf(_T(" %1x  %1x  %02x %04x %04x"),
            ip->ip_v, ip->ip_hl, ip->ip_tos, ip->ip_len, ip->ip_id);
        (void)_tprintf(_T("   %1x %04x"), ((ip->ip_off) & 0xe000) >> 13,
            (ip->ip_off) & 0x1fff);
        (void)_tprintf(_T("  %02x  %02x %04x"), ip->ip_ttl, ip->ip_p, ip->ip_sum);
        (void)_tprintf(_T(" %hs "), inet_ntoa(*(struct in_addr *)&ip->ip_src.s_addr));
        (void)_tprintf(_T(" %hs "), inet_ntoa(*(struct in_addr *)&ip->ip_dst.s_addr));
        /* dump and option bytes */
        while (hlen-- > 20) {
                (void)_tprintf(_T("%02x"), *cp++);
        }
        (void)putchar('\n');
}

/*
 * pr_addr --
 *      Return an ascii host address as a dotted quad and optionally with
 * a hostname.
 */
_TCHAR *pr_addr(u_long l)
{
        struct hostent *hp;
        static _TCHAR buf[80];

        if ((options & F_NUMERIC) ||
            !(hp = gethostbyaddr((char *)&l, 4, AF_INET)))
                (void)_stprintf(buf, _T("%hs"), inet_ntoa(*(struct in_addr *)&l));
        else
                (void)_stprintf(buf, _T("%hs (%hs)"), hp->h_name,
                    inet_ntoa(*(struct in_addr *)&l));
        return(buf);
}

/*
 * pr_retip --
 *      Dump some info on a returned (via ICMP) IP packet.
 */
void pr_retip(struct ip *ip)
{
        int hlen;
        u_char *cp;

        pr_iph(ip);
        hlen = ip->ip_hl << 2;
        cp = (u_char *)ip + hlen;

        if (ip->ip_p == 6)
                (void)_tprintf(_T("TCP: from port %u, to port %u (decimal)\n"),
                    (*cp * 256 + *(cp + 1)), (*(cp + 2) * 256 + *(cp + 3)));
        else if (ip->ip_p == 17)
                (void)_tprintf(_T("UDP: from port %u, to port %u (decimal)\n"),
                        (*cp * 256 + *(cp + 1)), (*(cp + 2) * 256 + *(cp + 3)));
}

#if UNIX
void fill(char *bp, _TCHAR *patp)
{
        register u_int ii, jj, kk;
        int pat[16];
        char *cp;

        for (cp = patp; *cp; cp++)
                if (!isxdigit(*cp)) {
                        (void)_ftprintf(stderr,
                            "ping: patterns must be specified as hex digits.\n");
                        MyExit(1);
                }
        ii = sscanf(patp,
            "%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x",
            &pat[0], &pat[1], &pat[2], &pat[3], &pat[4], &pat[5], &pat[6],
            &pat[7], &pat[8], &pat[9], &pat[10], &pat[11], &pat[12],
            &pat[13], &pat[14], &pat[15]);

        if (ii > 0)
                for (kk = 0;
                    kk <= MAXPACKET - (8 + sizeof(struct timeval) + ii);
                    kk += ii)
                        for (jj = 0; jj < ii; ++jj)
                                bp[jj + kk] = (u_char)pat[jj];
        if (!(options & F_QUIET)) {
                (void)printf("PATTERN: 0x");
                for (jj = 0; jj < ii; ++jj)
                        (void)printf("%02x", bp[jj] & 0xFF);
                (void)printf("\n");
        }
}
#endif

void usage(void)
{
        (void)_ftprintf(stderr,
            _T("usage: ping [-Rdfnqrv] [-c count] [-i wait] [-l preload]\n\t[-p pattern] [-s packetsize] host\n"));
        MyExit(1);
}

#if !UNIX

BOOL NewThread( void THREAD_LINKAGE ThreadFunction(THREAD_ARGUMENT),
                THREAD_ARGUMENT ThreadArgument)
{
    PIPROCESS pPrc;
    SCODE Sc;
    PITHREAD pThd;

    /* create a new thread to invoke the signal handler after nsecs
     */
    pPrc = CurrentProcess();
    Sc = pPrc->v->CreateThread( pPrc, 0, ThreadFunction, ThreadArgument,
                                0, NULL, &pThd);
    if (FAILED(Sc)) {
        _ftprintf(stderr,_T("Could not create a thread (%x)\n"), Sc);
        MyExit(1);
    }

    pThd->v->Release(pThd);
    return TRUE;
}

void perror(char *msg)
{
    UINT e = WSAGetLastError();
    _ftprintf(stderr, _T("%hs error x%x\n"), msg, e);
}

char *_itot( _TCHAR *str)
{
    char *r = malloc(_tcslen(str) + 1);
    char *p = r;
    while (*str)
        *p++ = (unsigned char)*str++;
    *p = 0;
    return r;
}

static struct {
    SignalHandler Handler;
} SigTab[NSIG];

SignalHandler signal(UINT SigNo, SignalHandler Handler)
{
    SignalHandler Old = SigTab[SigNo].Handler;
    SigTab[SigNo].Handler = Handler;

    return Old;
}

#define CTRL_C 3

static void THREAD_LINKAGE InputThread (THREAD_ARGUMENT Arg )
{
    FILE *InFile = (FILE *)Arg;
    INT ch;

    for (;;) {
        ch = fgetc(InFile);
        if (ch != CTRL_C && ch != '.' && !Exiting)
            continue;

        _tprintf(_T("^C"));

        if (SigTab[SIGINT].Handler == SIG_IGN)
            ThreadExit();
        else
            SigTab[SIGINT].Handler();
    }
}


static void THREAD_LINKAGE AlarmThread (THREAD_ARGUMENT Arg )
{
    INT nSeconds = (UINT) Arg;
    TIME t;

    Int32ToInt64(t, TIME_RELATIVE(TIME_SECONDS(nSeconds)));
    SleepUntil(t);
    if (SigTab[SIGALRM].Handler)
        SigTab[SIGALRM].Handler();
    /* and we are done */
    ThreadExit();
}


void alarm(UINT nSeconds)
{
    if (!Exiting) {
        (void) NewThread( AlarmThread, (THREAD_ARGUMENT) nSeconds );
    }
}

void Etotv(TIME e, struct timeval *tv)
{
    INT64 t;

    tv->tv_sec = Int64ToInt32(Int64DividedByInt32(e, 10000000));
    Int32ToInt64(t, tv->tv_sec);
    t = Int64TimesInt32(t, 10000000);
    t = Int64Subtract(e, t);
    t = Int64DividedByInt32(t, 10);
    tv->tv_usec = Int64ToInt32(t);
}

TIME tvtoE( struct timeval *tv)
{
    TIME t;
    TIME t2;

    Int32ToInt64(t, tv->tv_sec);
    Int32ToInt64(t2, tv->tv_sec);

    t2 = Int64TimesInt32(t2, 10);

    t = Int64TimesInt32(t, 10000000);
    t = Int64Add(t, t2);
    return t;
}

void gettimeofday(struct timeval *now, struct timezone *zone)
{
    UnusedParameter(zone);
    Etotv(CurrentTime(),now);
}
#endif
