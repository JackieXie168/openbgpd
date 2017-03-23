#ifndef lint
static const char yysccsid[] = "@(#)yaccpar	1.9 (Berkeley) 02/21/93";
#endif

#include <stdlib.h>
#include <string.h>

#define YYBYACC 1
#define YYMAJOR 1
#define YYMINOR 9
#define YYPATCH 20100216

#define YYEMPTY        (-1)
#define yyclearin      (yychar = YYEMPTY)
#define yyerrok        (yyerrflag = 0)
#define YYRECOVERING() (yyerrflag != 0)

#define YYPREFIX "yy"

/* compatibility with bison */
#ifdef YYPARSE_PARAM
/* compatibility with FreeBSD */
#ifdef YYPARSE_PARAM_TYPE
#define YYPARSE_DECL() yyparse(YYPARSE_PARAM_TYPE YYPARSE_PARAM)
#else
#define YYPARSE_DECL() yyparse(void *YYPARSE_PARAM)
#endif
#else
#define YYPARSE_DECL() yyparse(void)
#endif /* YYPARSE_PARAM */

extern int YYPARSE_DECL();

#line 25 "parse.y"
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#if defined(__FreeBSD__) || defined(darwin) || defined(__APPLE__) || defined(MACOSX)
#include <net/pfkeyv2.h>
#elif __linux__
#include <linux/pfkeyv2.h>
#else
#include <netinet/ip_ipsp.h>
#include <netmpls/mpls.h>
#endif

#include <ctype.h>
#include <err.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>

#include "bgpd.h"
#include "mrt.h"
#include "session.h"
#include "rde.h"
#include "log.h"

TAILQ_HEAD(files, file)		 files = TAILQ_HEAD_INITIALIZER(files);
static struct file {
	TAILQ_ENTRY(file)	 entry;
	FILE			*stream;
	char			*name;
	int			 lineno;
	int			 errors;
} *file, *topfile;
struct file	*pushfile(const char *, int);
int		 popfile(void);
int		 check_file_secrecy(int, const char *);
int		 yyparse(void);
int		 yylex(void);
int		 yyerror(const char *, ...)
    __attribute__((__format__ (printf, 1, 2)))
    __attribute__((__nonnull__ (1)));
int		 kw_cmp(const void *, const void *);
int		 lookup(char *);
int		 lgetc(int);
int		 lungetc(int);
int		 findeol(void);

TAILQ_HEAD(symhead, sym)	 symhead = TAILQ_HEAD_INITIALIZER(symhead);
struct sym {
	TAILQ_ENTRY(sym)	 entry;
	int			 used;
	int			 persist;
	char			*nam;
	char			*val;
};
int		 symset(const char *, const char *, int);
char		*symget(const char *);

static struct bgpd_config	*conf;
static struct network_head	*netconf;
static struct peer		*peer_l, *peer_l_old;
static struct peer		*curpeer;
static struct peer		*curgroup;
static struct rdomain		*currdom;
static struct filter_head	*filter_l;
static struct filter_head	*peerfilter_l;
static struct filter_head	*groupfilter_l;
static struct filter_rule	*curpeer_filter[2];
static struct filter_rule	*curgroup_filter[2];
static u_int32_t		 id;

struct filter_peers_l {
	struct filter_peers_l	*next;
	struct filter_peers	 p;
};

struct filter_prefix_l {
	struct filter_prefix_l	*next;
	struct filter_prefix	 p;
};

struct filter_prefixlen {
	enum comp_ops		op;
	int			len_min;
	int			len_max;
};

struct filter_as_l {
	struct filter_as_l	*next;
	struct filter_as	 a;
};

struct filter_match_l {
	struct filter_match	 m;
	struct filter_prefix_l	*prefix_l;
	struct filter_as_l	*as_l;
} fmopts;

struct peer	*alloc_peer(void);
struct peer	*new_peer(void);
struct peer	*new_group(void);
int		 add_mrtconfig(enum mrt_type, char *, int, struct peer *,
		    char *);
int		 add_rib(char *, u_int, u_int16_t);
struct rde_rib	*find_rib(char *);
int		 get_id(struct peer *);
int		 merge_prefixspec(struct filter_prefix_l *,
		    struct filter_prefixlen *);
int		 expand_rule(struct filter_rule *, struct filter_peers_l *,
		    struct filter_match_l *, struct filter_set_head *);
int		 str2key(char *, char *, size_t);
int		 neighbor_consistent(struct peer *);
int		 merge_filterset(struct filter_set_head *, struct filter_set *);
void		 copy_filterset(struct filter_set_head *,
		    struct filter_set_head *);
void		 merge_filter_lists(struct filter_head *, struct filter_head *);
struct filter_rule	*get_rule(enum action_types);

int		 getcommunity(char *);
int		 parsecommunity(struct filter_community *, char *);
int64_t 	 getlargecommunity(char *);
int		 parselargecommunity(struct filter_largecommunity *, char *);
int		 parsesubtype(char *);
int		 parseextvalue(char *, u_int32_t *);
int		 parseextcommunity(struct filter_extcommunity *, char *,
		    char *);

typedef struct {
	union {
		int64_t			 number;
		char			*string;
		struct bgpd_addr	 addr;
		u_int8_t		 u8;
		struct filter_peers_l	*filter_peers;
		struct filter_match_l	 filter_match;
		struct filter_prefix_l	*filter_prefix;
		struct filter_as_l	*filter_as;
		struct filter_set	*filter_set;
		struct filter_set_head	*filter_set_head;
		struct {
			struct bgpd_addr	prefix;
			u_int8_t		len;
		}			prefix;
		struct filter_prefixlen	prefixlen;
		struct {
			u_int8_t		enc_alg;
			char			enc_key[IPSEC_ENC_KEY_LEN];
			u_int8_t		enc_key_len;
		}			encspec;
	} v;
	int lineno;
} YYSTYPE;

#line 194 "parse.c"
#define AS 257
#define ROUTERID 258
#define HOLDTIME 259
#define YMIN 260
#define LISTEN 261
#define ON 262
#define FIBUPDATE 263
#define FIBPRIORITY 264
#define RTABLE 265
#define RDOMAIN 266
#define RD 267
#define EXPORTTRGT 268
#define IMPORTTRGT 269
#define RDE 270
#define RIB 271
#define EVALUATE 272
#define IGNORE 273
#define COMPARE 274
#define GROUP 275
#define NEIGHBOR 276
#define NETWORK 277
#define REMOTEAS 278
#define DESCR 279
#define LOCALADDR 280
#define MULTIHOP 281
#define PASSIVE 282
#define MAXPREFIX 283
#define RESTART 284
#define ANNOUNCE 285
#define CAPABILITIES 286
#define REFRESH 287
#define AS4BYTE 288
#define CONNECTRETRY 289
#define DEMOTE 290
#define ENFORCE 291
#define NEIGHBORAS 292
#define REFLECTOR 293
#define DEPEND 294
#define DOWN 295
#define SOFTRECONFIG 296
#define DUMP 297
#define IN 298
#define OUT 299
#define SOCKET 300
#define RESTRICTED 301
#define LOG 302
#define ROUTECOLL 303
#define TRANSPARENT 304
#define TCP 305
#define MD5SIG 306
#define PASSWORD 307
#define KEY 308
#define TTLSECURITY 309
#define ALLOW 310
#define DENY 311
#define MATCH 312
#define QUICK 313
#define FROM 314
#define TO 315
#define ANY 316
#define CONNECTED 317
#define STATIC 318
#define COMMUNITY 319
#define EXTCOMMUNITY 320
#define LARGECOMMUNITY 321
#define PREFIX 322
#define PREFIXLEN 323
#define SOURCEAS 324
#define TRANSITAS 325
#define PEERAS 326
#define DELETE 327
#define MAXASLEN 328
#define MAXASSEQ 329
#define SET 330
#define LOCALPREF 331
#define MED 332
#define METRIC 333
#define NEXTHOP 334
#define REJECT 335
#define BLACKHOLE 336
#define NOMODIFY 337
#define SELF 338
#define PREPEND_SELF 339
#define PREPEND_PEER 340
#define PFTABLE 341
#define WEIGHT 342
#define RTLABEL 343
#define ORIGIN 344
#define ERROR 345
#define INCLUDE 346
#define IPSEC 347
#define ESP 348
#define AH 349
#define SPI 350
#define IKE 351
#define IPV4 352
#define IPV6 353
#define QUALIFY 354
#define VIA 355
#define NE 356
#define LE 357
#define GE 358
#define XRANGE 359
#define LONGER 360
#define STRING 361
#define NUMBER 362
#define YYERRCODE 256
static const short yylhs[] = {                           -1,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    1,    2,    2,    3,    3,   13,   13,   10,   48,   46,
   47,   47,   47,   47,   47,   47,   47,   47,   47,   47,
   47,   47,   47,   47,   47,   47,   47,   47,   47,   47,
   47,   47,   47,   47,   47,   47,   54,   53,   53,   53,
   11,   11,   12,   12,   15,   16,   16,   17,   17,   55,
   55,   56,    4,    4,   58,   49,   57,   57,   59,   60,
   60,   60,   60,   60,   60,   60,   61,   63,   50,   65,
   51,   64,   64,   66,   66,   66,   62,   62,   68,   68,
   69,   67,   67,   67,   67,   67,   67,   67,   67,   67,
   67,   67,   67,   67,   67,   67,   67,   67,   67,   67,
   67,   67,   67,   67,   67,   67,   67,   67,   67,   67,
   67,   67,   67,   67,   67,    7,    7,    6,    6,    9,
    9,    5,    5,   45,   45,   52,   18,   18,   18,   19,
   19,   20,   20,   14,   14,   24,   24,   23,   23,   22,
   22,   22,   22,   40,   40,   40,   40,   39,   39,   38,
   30,   30,   32,   32,   31,   31,   33,   33,   33,   29,
   29,   28,   28,   28,   28,   27,   71,   27,   25,   25,
   26,   26,   26,   26,   26,   26,   26,   26,   26,   34,
   34,   34,   34,   44,   44,   44,   44,   36,   36,   36,
   37,   37,   21,   21,   35,   35,   35,   35,   35,   35,
   35,   35,   35,   35,   35,   35,   35,   35,   35,   35,
   35,   35,   35,   35,   35,   35,   35,   35,   35,    8,
   70,   70,   41,   41,   41,   41,   41,   41,   42,   42,
   43,   43,
};
static const short yylen[] = {                            2,
    0,    2,    3,    3,    3,    3,    3,    3,    3,    3,
    1,    1,    1,    1,    1,    2,    1,    1,    3,    2,
    2,    3,    2,    2,    3,    3,    2,    2,    2,    3,
    5,    5,    7,    2,    2,    1,    4,    6,    1,    3,
    3,    4,    4,    2,    2,    3,    5,    3,    5,    4,
    1,    1,    1,    0,    1,    3,    3,    1,    1,    2,
    0,    2,    0,    1,    0,    8,    2,    1,    2,    2,
    3,    3,    2,    2,    1,    3,    0,    0,    5,    0,
    8,    2,    1,    2,    2,    2,    4,    0,    2,    1,
    2,    2,    2,    2,    2,    1,    1,    2,    2,    2,
    3,    3,    3,    3,    3,    3,    2,    2,    3,    3,
    4,    4,    3,    8,    2,    2,    7,    1,    1,    2,
    3,    2,    3,    2,    2,    0,    2,    1,    1,    1,
    1,    1,    1,    0,    2,    7,    1,    1,    1,    0,
    1,    1,    1,    0,    2,    1,    3,    1,    3,    1,
    1,    2,    2,    2,    2,    2,    4,    1,    3,    2,
    1,    3,    1,    3,    2,    4,    1,    3,    4,    1,
    3,    1,    1,    2,    3,    0,    0,    2,    1,    2,
    1,    1,    2,    2,    2,    2,    3,    2,    2,    0,
    1,    3,    4,    1,    1,    1,    1,    0,    2,    7,
    3,    1,    0,    1,    2,    3,    3,    2,    3,    3,
    2,    3,    3,    2,    3,    3,    2,    2,    2,    2,
    2,    2,    2,    2,    2,    3,    3,    4,    2,    1,
    1,    0,    1,    1,    1,    1,    1,    1,    1,    1,
    1,    1,
};
static const short yydefred[] = {                         1,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,  137,
  138,  139,    0,    0,    0,    2,    0,    0,    0,    0,
    0,    0,    0,    0,   36,   39,    0,   10,   12,   11,
   13,    0,   55,   23,    0,   24,    0,   18,   28,   27,
   44,    0,    0,    0,    0,   17,    0,  128,  129,    0,
    0,    0,    0,   45,    0,    0,    0,   35,   29,   34,
    0,   20,    0,  141,    0,    3,    4,    5,    6,    7,
    8,    9,    0,   22,   25,   26,    0,    0,    0,    0,
   40,   41,   16,    0,    0,    0,  131,  130,    0,    0,
    0,   48,    0,   51,   52,    0,    0,   53,   46,    0,
    0,    0,    0,    0,   58,   59,   78,   60,    0,    0,
    0,   42,    0,   56,   57,    0,   50,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
  199,    0,    0,   64,   37,    0,   43,  145,  142,  143,
    0,    0,   65,    0,   31,   80,   49,  204,    0,    0,
    0,  205,    0,    0,  208,    0,    0,  211,    0,    0,
  219,  218,  220,  221,  217,  222,  223,  224,  214,    0,
    0,  225,  229,    0,    0,    0,   47,    0,    0,  150,
    0,  151,  146,    0,    0,   79,    0,    0,    0,  226,
    0,  227,  206,  207,  209,  210,  212,  213,  215,  216,
    0,   38,  152,  153,  148,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,   75,    0,   68,    0,   33,
    0,    0,    0,    0,    0,    0,    0,   96,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,  118,    0,   83,    0,  228,  202,
    0,  147,  231,    0,  136,  194,    0,    0,    0,    0,
  195,  196,  197,    0,    0,    0,    0,    0,    0,    0,
  179,  182,  161,  181,    0,    0,    0,   90,   74,   70,
    0,    0,    0,    0,   66,   67,    0,   69,   86,    0,
  100,   99,   92,    0,   94,   95,    0,    0,    0,    0,
    0,  107,  108,    0,  122,    0,  120,    0,   98,    0,
    0,  125,  124,    0,  115,  116,    0,  132,  133,    0,
   85,   81,   82,   84,    0,    0,  149,  185,    0,  186,
    0,    0,  156,  183,  184,  189,  188,    0,  191,  154,
  155,  163,    0,  180,  173,  240,   14,  239,    0,   15,
    0,  165,    0,   91,   87,   89,   71,   72,   76,   62,
  101,    0,  110,  105,  103,  104,  106,  102,  109,  121,
  123,    0,    0,    0,  113,    0,  200,  201,  187,  158,
    0,  160,  234,  235,  237,    0,  233,  236,  238,    0,
  162,    0,    0,  170,    0,    0,  242,  241,    0,  174,
  127,    0,    0,    0,    0,  157,    0,    0,  192,  164,
    0,    0,  166,  175,    0,    0,  159,  193,    0,  171,
    0,    0,  169,  117,    0,    0,  114,  135,
};
static const short yydgoto[] = {                          1,
  360,   42,  361,  145,  330,   62,  373,  183,  100,   49,
  107,  109,   57,  113,  192,  342,  117,   27,   75,  151,
  159,  193,  216,  194,  280,  281,  217,  404,  405,  282,
  283,  353,  406,  350,  260,  102,  261,  343,  391,  284,
  400,  363,  409,  285,  437,   28,   29,   30,   31,  254,
   33,   34,  226,  255,   88,  298,  227,  197,  228,  229,
   37,  196,  152,  256,  199,  257,  258,  287,  288,  336,
  218,
};
static const short yysindex[] = {                         0,
  119,   75, -290, -273, -237, -159, -243, -261, -220, -198,
 -242, -239, -195, -187, -240, -228, -181, -243, -243,    0,
    0,    0, -139, -168,  144,    0,  -97,  207,  209,  213,
  215,  216,  217,  219,    0,    0,  -48,    0,    0,    0,
    0, -132,    0,    0, -131,    0, -273,    0,    0,    0,
    0,  223, -127,  -36, -190,    0,   -7,    0,    0,  188,
  189, -136,  -89,    0, -119, -224,  -58,    0,    0,    0,
 -111,    0, -239,    0,  -24,    0,    0,    0,    0,    0,
    0,    0, -268,    0,    0,    0,  223,  127, -231, -110,
    0,    0,    0,  134, -104, -103,    0,    0,  -90,  -89,
  153,    0,  -88,    0,    0,  -98,  -82,    0,    0,  -77,
  -73,  -72, -216,  188,    0,    0,    0,    0,  223,  -71,
    2,    0,  223,    0,    0,  -89,    0,  -30,  -30,  -30,
  -39,  -38,  -34, -259,  -64,  -63,  -61,  -33,  -60, -239,
    0,  179,  -56,    0,    0,  -98,    0,    0,    0,    0,
 -105,  181,    0,   43,    0,    0,    0,    0,  -47,  -43,
  -23,    0,  -20,  -16,    0,  -13,   -4,    0,   -3,    5,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    7,
    8,    0,    0,  -73,  223,  -98,    0, -290,    1,    0,
 -230,    0,    0,    0,  223,    0,  -80, -243,  595,    0,
   18,    0,    0,    0,    0,    0,    0,    0,    0,    0,
  184,    0,    0,    0,    0,   -2,  -89,  -59,  636, -243,
   20,   25,   27, -239,  112,    0, -108,    0,  383,    0,
  383, -227,   34, -290, -239, -273,   35,    0,   36,  -66,
   39,  109, -273,  147,   45, -148,   56,   57, -243,  118,
 -243,  153, -202,  383,    0,  455,    0,  383,    0,    0,
   63,    0,    0, -230,    0,    0,   59,   64,   65, -107,
    0,    0,    0,   66,   70, -244, -254, -254, -152,  -59,
    0,    0,    0,    0,  -53,  383,  496,    0,    0,    0,
   85,  100,  -73,  101,    0,    0,  223,    0,    0,   79,
    0,    0,    0,  -73,    0,    0,  143, -243, -243, -243,
 -243,    0,    0,  117,    0, -243,    0,  120,    0, -243,
 -148,    0,    0, -154,    0,    0,  347,    0,    0, -251,
    0,    0,    0,    0,  350,  184,    0,    0,  128,    0,
 -177, -254,    0,    0,    0,    0,    0,   -1,    0,    0,
    0,    0,   19,    0,    0,    0,    0,    0,    4,    0,
  -25,    0, -171,    0,    0,    0,    0,    0,    0,    0,
    0,  126,    0,    0,    0,    0,    0,    0,    0,    0,
    0, -239, -239,  223,    0,  140,    0,    0,    0,    0,
   23,    0,    0,    0,    0,  -25,    0,    0,    0,  129,
    0, -152,  115,    0,  454,  374,    0,    0, -171,    0,
    0,  -73,  -73,  184,  138,    0, -177,  149,    0,    0,
   24,  115,    0,    0,   63,  141,    0,    0,    4,    0,
  384,  151,    0,    0,  152,  158,    0,    0,
};
static const short yyrindex[] = {                         0,
  238,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0, -218,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  519,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  407,    0,    0,    0,    0,  407,    0,    0,    0,
    0,    0,  521,    0,    0,    0,  536,    0,    0,    0,
    0,    0,    0,    0, -113,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,  322,    0,  537,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,  521,
  407,    0,    0,    0,    0,  538,    0,    0,    0,    0,
  543,    0,    0,   16,    0,    0,    0,    0,   13,    0,
    0,    0,  540,    0,    0,  521,    0,  193,  193,  193,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,  538,    0,    0,    0,    0,
    0,  545,    0,  546,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,   71,  218,  538,    0,    0,    0,    0,
    0,    0,    0,  114,  677,    0,    0,    0,  238,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0, -229,  521,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,  553,    0,  554,    0,    0,    0,    0,    0,
    0,  407,    0,    0,    0,  238,    0,    0,    0,    0,
  201,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,  130,  130,    0,   -8,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,  555,    0,    0,    0,  411,    0,    0,    0,
    0,    0,    0,  556,    0,    0,  561,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,   11,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0, -147,    0,    0,    0,    0,    0,    0,    0,
   -9,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,  218,    0,    0,    0,    0,    0,    0,
 -149,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,  107,    0,    0,    0,    0,    0,
    0,  562,  563,    0,    0,    0,    0,    0,    0,    0,
  145,    0,    0,    0,  201,    0,    0,    0,  449,    0,
    0,    0,    0,    0,  566,    0,    0,    0,
};
static const short yygindex[] = {                         0,
   12, -145, -314,  -95,    0,  337,    0,    0,    0,  259,
 -210,    0,  -32,    0,    9,   26,    0,    0,    0,    0,
   80, -153,    0,    0,    0,  302,    0, -260,  180,    0,
 -257,    0,  155, -238,  -87,  -76,  172, -304,    0,    0,
    0,    0,  191,    0,    0,    0,    0,    0,    0,  587,
    0,    0,  591,  593,  -57, -174,    0,    0,  368,    0,
    0,    0,    0,    0,    0,  340, -161,    0,  310, -197,
    0,
};
#define YYTABLESIZE 1024
static const short yytable[] = {                         94,
  172,  178,   87,  163,  166,  164,  167,  358,  169,  180,
  170,  181,   44,  141,   41,  341,  295,  191,  264,  408,
  190,  352,   45,  127,  362,   55,  188,  232,   53,  118,
   65,  346,  300,  120,  172,  320,  390,  215,   63,  351,
  111,  263,  213,  142,  189,  232,  104,  105,  410,  157,
  187,  172,  140,   84,  190,   86,  299,  286,  398,  397,
  399,  153,  263,  279,  358,  156,  263,  263,  348,  359,
   39,   40,   87,  104,  105,  171,  172,  173,  174,  331,
  230,   91,   92,  334,   38,  190,  232,   43,  303,   54,
  212,  115,  114,   61,  424,  140,  140,  149,  150,  385,
   50,   43,   47,  392,  266,  349,  263,  184,  116,  232,
  337,  364,  427,  172,  230,  172,   43,   48,   55,  386,
   66,   56,  262,  176,   46,  286,  403,  211,   26,   48,
   43,  232,   67,  190,  301,  190,  106,  219,   55,  190,
  265,   51,  175,  401,  420,  328,  329,  416,  429,  104,
  105,  188,  382,  383,  220,  402,   58,   59,  221,  222,
  223,  430,   87,   52,  326,   60,   61,  232,   13,  189,
  224,  271,  272,  273,   64,  358,  232,  232,  232,   68,
   97,   98,  220,   60,   61,  225,  221,  222,  223,  357,
   40,  293,   72,  417,  327,  230,   13,  266,  224,   41,
  144,  144,  304,  335,   73,  232,   99,  422,  160,  161,
  190,  232,  232,  225,   71,   74,   76,  308,   77,  309,
  310,  311,   78,  422,   79,   80,   81,   83,   82,   40,
   85,  167,   87,   89,   95,   96,  177,   90,  355,  370,
  101,  103,  108,  110,  305,   41,  112,  172,  388,  119,
  122,  317,  190,   60,   61,   43,  123,  124,  125,  267,
  268,  269,  270,  144,  271,  272,  273,  190,  274,  275,
  126,  312,  143,  155,  276,   61,   69,   70,  146,   61,
   61,   61,  172,  147,  347,   58,   59,   93,  148,   61,
  154,   61,  277,  278,  313,  355,  158,  176,  177,  178,
  182,  185,  356,  195,  186,  198,   61,  357,   40,  172,
  172,  172,  172,  200,  172,  172,  172,  201,  172,  172,
  172,  178,  162,  165,  172,   61,  414,  168,  179,  190,
  190,  190,  190,  407,  190,  190,  190,  202,  190,  190,
  190,  203,  172,  172,  190,  204,  172,  121,  205,  412,
  413,  172,  172,   93,  393,  394,  395,  206,  207,  356,
  396,  214,  190,  190,  357,   40,  208,  431,  209,  210,
  177,  190,  190,  294,    2,    3,    4,    5,  259,    6,
  290,    7,    8,    9,   10,  291,  190,  292,   11,  230,
  230,  230,  297,   12,  302,   13,  306,  307,  232,  315,
  316,  230,  230,  230,  230,  319,  355,   14,  318,  230,
  230,  230,  230,  230,  230,   15,  321,  322,   16,  338,
   17,   18,   19,  324,  339,  340,  372,  344,   20,   21,
   22,  345,  177,  177,  177,  177,  232,  177,  177,  177,
  371,  177,  177,  176,   61,  367,   61,  177,  190,  190,
  190,  190,   23,  190,  190,  190,  230,  190,  190,  190,
  368,  369,  232,  190,   24,  177,  177,  232,  232,  384,
  356,  128,  129,  130,  387,  357,   40,  378,  289,   25,
  380,  190,  190,  131,  132,  133,  134,  411,  389,  415,
  419,  135,  136,  137,  138,  139,  140,  263,  423,  426,
  232,  432,  128,  129,  130,  232,  232,  323,  434,  325,
  428,  435,  436,   77,  131,  132,  133,  134,  438,  232,
  232,  232,  135,  136,  137,  138,  139,  140,   21,   61,
  198,  232,  232,  232,  232,   61,   61,   61,   61,  232,
  232,  232,  232,  232,  232,   54,   30,   63,   61,   61,
   61,   61,   19,  203,   88,   32,   61,   61,   61,   61,
   61,   61,  119,   97,   73,   93,  374,  375,  376,  377,
  126,  111,  112,  168,  379,  134,  314,   61,  381,  332,
   61,  354,  421,  433,   61,  425,  418,   32,   61,   61,
   61,   35,   61,   36,  296,  333,  366,   61,   61,   61,
   61,   61,   61,   61,   61,    0,   61,    0,    0,    0,
    0,   61,   61,    0,   61,   61,   61,   61,   61,    0,
  365,    0,    0,   61,    0,   61,   61,    0,    0,    0,
   61,    0,    0,    0,    0,    0,    0,    0,    0,    0,
   61,   61,   61,    0,    0,    0,    0,    0,    0,    0,
    0,   61,   61,   61,   61,   61,    0,    0,    0,    0,
   61,   61,   61,   61,   61,   61,   61,    0,   61,   61,
    0,    0,    0,   61,    0,    0,    0,   61,   61,   61,
    0,   61,    0,    0,    0,    0,   61,   61,   61,   61,
   61,   61,   61,   61,    0,   61,    0,    0,    0,    0,
   61,   61,    0,   61,   61,   61,   61,   61,    0,    0,
  231,    0,   61,  232,   61,   61,    0,    0,    0,   61,
    0,    0,    0,    0,    0,  233,    0,    0,    0,    0,
    0,    0,  234,  235,  236,  237,  238,  239,    0,  240,
   61,    0,    0,    0,  241,  242,    0,  243,  244,  245,
  246,  247,    0,    0,  232,    0,  248,   61,  249,  250,
    0,    0,    0,  251,    0,    0,  233,    0,    0,    0,
    0,    0,    0,  234,  235,  236,  237,  238,  239,    0,
  240,    0,    0,    0,  252,  241,  242,    0,  243,  244,
  245,  246,  247,    0,    0,   61,    0,  248,   61,  249,
  250,  253,    0,    0,  251,    0,    0,    0,    0,    0,
   61,    0,    0,    0,    0,   61,    0,   61,   61,   61,
   61,   61,   61,    0,   61,  252,    0,    0,    0,   61,
   61,    0,   61,   61,   61,   61,   61,    0,    0,    0,
    0,   61,  253,   61,   61,    0,    0,    0,   61,    0,
  231,    0,    0,  232,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,  233,    0,    0,    0,   61,
    0,    0,  234,  235,  236,  237,  238,  239,    0,  240,
    0,    0,    0,    0,  241,  242,   61,  243,  244,  245,
  246,  247,    0,    0,  232,    0,  248,    0,  249,  250,
    0,    0,    0,  251,    0,    0,  233,    0,    0,    0,
    0,    0,    0,  234,  235,  236,  237,  238,  239,    0,
  240,    0,    0,    0,  252,  241,  242,    0,  243,  244,
  245,  246,  247,    0,    0,   61,    0,  248,    0,  249,
  250,  253,    0,    0,  251,    0,    0,   61,    0,    0,
    0,    0,    0,    0,   61,   61,   61,   61,   61,   61,
    0,   61,    0,    0,    0,  252,   61,   61,    0,   61,
   61,   61,   61,   61,    0,    0,    0,    0,   61,    0,
   61,   61,  253,    0,    0,   61,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,   61,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,   61,
};
static const short yycheck[] = {                         57,
   10,   10,   10,   43,   43,   45,   45,   61,   43,   43,
   45,   45,    4,  101,    3,  123,  125,  123,  216,   45,
   10,  279,  260,  100,  285,   10,  257,  257,  271,   87,
  271,  276,  260,  265,   44,  246,  341,  191,   13,  278,
   73,   44,  188,  101,  275,  275,  298,  299,  363,  126,
  146,   61,  271,   42,   44,   47,  231,  219,   60,   61,
   62,  119,   44,  123,   61,  123,   44,   44,  323,  123,
  361,  362,   10,  298,  299,  335,  336,  337,  338,  254,
   10,  272,  273,  258,   10,  316,  316,  361,  234,  332,
  186,   83,  361,  362,  409,  314,  315,  314,  315,  351,
  362,  361,  262,  342,  257,  360,   44,  140,   83,  257,
  264,  286,  417,  123,   44,  125,  361,  361,  361,  330,
  361,  361,  125,   10,  362,  287,  123,  185,   10,  361,
  361,  361,  361,  123,  362,  125,  361,  195,  123,   10,
  217,  362,  134,  125,  402,  348,  349,  125,  125,  298,
  299,  257,  307,  308,  263,  353,  352,  353,  267,  268,
  269,  422,   10,  362,  252,  361,  362,   61,  277,  275,
  279,  324,  325,  326,  362,   61,  324,  325,  326,  361,
  317,  318,  263,  361,  362,  294,  267,  268,  269,  361,
  362,  224,  361,  391,  252,  125,  277,  257,  279,  188,
  314,  315,  235,  261,   61,   61,  343,  405,  129,  130,
  316,  361,  362,  294,  354,  313,   10,  284,   10,  286,
  287,  288,   10,  421,   10,   10,   10,  276,   10,  362,
  362,  125,   10,  361,   47,   47,  123,  274,  292,  297,
  330,  361,  301,  355,  236,  234,  271,  257,  336,  123,
  361,  243,  123,  361,  362,  361,  123,  362,  362,  319,
  320,  321,  322,  362,  324,  325,  326,  257,  328,  329,
  361,  338,  361,  272,  334,  263,   18,   19,  361,  267,
  268,  269,  292,  361,  276,  352,  353,  361,  361,  277,
  362,  279,  352,  353,  361,  292,  327,  362,  362,  361,
  361,  123,  356,  123,  361,  263,  294,  361,  362,  319,
  320,  321,  322,  361,  324,  325,  326,  361,  328,  329,
  330,  330,  362,  362,  334,  125,  384,  362,  362,  319,
  320,  321,  322,  359,  324,  325,  326,  361,  328,  329,
  330,  362,  352,  353,  334,  362,  356,   89,  362,  382,
  383,  361,  362,  361,  356,  357,  358,  362,  362,  356,
  362,  361,  352,  353,  361,  362,  362,  425,  362,  362,
  257,  361,  362,  262,  256,  257,  258,  259,  361,  261,
  361,  263,  264,  265,  266,  361,  257,  361,  270,  319,
  320,  321,   10,  275,  361,  277,  362,  362,  292,  361,
  292,  331,  332,  333,  334,  361,  292,  289,  262,  339,
  340,  341,  342,  343,  344,  297,  361,  361,  300,  361,
  302,  303,  304,  306,  361,  361,  284,  362,  310,  311,
  312,  362,  319,  320,  321,  322,  292,  324,  325,  326,
  362,  328,  329,  330,  123,  361,  125,  334,  319,  320,
  321,  322,  334,  324,  325,  326,  198,  328,  329,  330,
  361,  361,  356,  334,  346,  352,  353,  361,  362,  123,
  356,  319,  320,  321,  125,  361,  362,  361,  220,  361,
  361,  352,  353,  331,  332,  333,  334,  362,  361,  350,
  362,  339,  340,  341,  342,  343,  344,   44,  125,  362,
  356,  361,  319,  320,  321,  361,  362,  249,  125,  251,
  362,  361,  361,  276,  331,  332,  333,  334,  361,  319,
  320,  321,  339,  340,  341,  342,  343,  344,   10,  123,
   10,  331,  332,  333,  334,  125,  319,  320,  321,  339,
  340,  341,  342,  343,  344,   10,   10,   10,  331,  332,
  333,  334,   10,  361,   10,   10,  339,  340,  341,  342,
  343,  344,   10,   10,   10,   10,  308,  309,  310,  311,
   10,   10,   10,  125,  316,   10,  240,  256,  320,  125,
  259,  280,  403,  429,  263,  414,  396,    1,  267,  268,
  269,    1,  271,    1,  227,  256,  287,  276,  277,  278,
  279,  280,  281,  282,  283,   -1,  285,   -1,   -1,   -1,
   -1,  290,  291,   -1,  293,  294,  295,  296,  297,   -1,
  125,   -1,   -1,  302,   -1,  304,  305,   -1,   -1,   -1,
  309,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  319,  320,  321,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  330,  331,  332,  333,  334,   -1,   -1,   -1,   -1,
  339,  340,  341,  342,  343,  344,  256,   -1,  347,  259,
   -1,   -1,   -1,  263,   -1,   -1,   -1,  267,  268,  269,
   -1,  271,   -1,   -1,   -1,   -1,  276,  277,  278,  279,
  280,  281,  282,  283,   -1,  285,   -1,   -1,   -1,   -1,
  290,  291,   -1,  293,  294,  295,  296,  297,   -1,   -1,
  256,   -1,  302,  259,  304,  305,   -1,   -1,   -1,  309,
   -1,   -1,   -1,   -1,   -1,  271,   -1,   -1,   -1,   -1,
   -1,   -1,  278,  279,  280,  281,  282,  283,   -1,  285,
  330,   -1,   -1,   -1,  290,  291,   -1,  293,  294,  295,
  296,  297,   -1,   -1,  259,   -1,  302,  347,  304,  305,
   -1,   -1,   -1,  309,   -1,   -1,  271,   -1,   -1,   -1,
   -1,   -1,   -1,  278,  279,  280,  281,  282,  283,   -1,
  285,   -1,   -1,   -1,  330,  290,  291,   -1,  293,  294,
  295,  296,  297,   -1,   -1,  256,   -1,  302,  259,  304,
  305,  347,   -1,   -1,  309,   -1,   -1,   -1,   -1,   -1,
  271,   -1,   -1,   -1,   -1,  276,   -1,  278,  279,  280,
  281,  282,  283,   -1,  285,  330,   -1,   -1,   -1,  290,
  291,   -1,  293,  294,  295,  296,  297,   -1,   -1,   -1,
   -1,  302,  347,  304,  305,   -1,   -1,   -1,  309,   -1,
  256,   -1,   -1,  259,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,  271,   -1,   -1,   -1,  330,
   -1,   -1,  278,  279,  280,  281,  282,  283,   -1,  285,
   -1,   -1,   -1,   -1,  290,  291,  347,  293,  294,  295,
  296,  297,   -1,   -1,  259,   -1,  302,   -1,  304,  305,
   -1,   -1,   -1,  309,   -1,   -1,  271,   -1,   -1,   -1,
   -1,   -1,   -1,  278,  279,  280,  281,  282,  283,   -1,
  285,   -1,   -1,   -1,  330,  290,  291,   -1,  293,  294,
  295,  296,  297,   -1,   -1,  259,   -1,  302,   -1,  304,
  305,  347,   -1,   -1,  309,   -1,   -1,  271,   -1,   -1,
   -1,   -1,   -1,   -1,  278,  279,  280,  281,  282,  283,
   -1,  285,   -1,   -1,   -1,  330,  290,  291,   -1,  293,
  294,  295,  296,  297,   -1,   -1,   -1,   -1,  302,   -1,
  304,  305,  347,   -1,   -1,  309,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,  330,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  347,
};
#define YYFINAL 1
#ifndef YYDEBUG
#define YYDEBUG 0
#endif
#define YYMAXTOKEN 362
#if YYDEBUG
static const char *yyname[] = {

"end-of-file",0,0,0,0,0,0,0,0,0,"'\\n'",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,"'+'","','","'-'",0,"'/'",0,0,0,0,0,0,0,0,0,0,0,0,"'<'",
"'='","'>'",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"'{'",0,"'}'",0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,"AS","ROUTERID","HOLDTIME","YMIN","LISTEN","ON","FIBUPDATE",
"FIBPRIORITY","RTABLE","RDOMAIN","RD","EXPORTTRGT","IMPORTTRGT","RDE","RIB",
"EVALUATE","IGNORE","COMPARE","GROUP","NEIGHBOR","NETWORK","REMOTEAS","DESCR",
"LOCALADDR","MULTIHOP","PASSIVE","MAXPREFIX","RESTART","ANNOUNCE",
"CAPABILITIES","REFRESH","AS4BYTE","CONNECTRETRY","DEMOTE","ENFORCE",
"NEIGHBORAS","REFLECTOR","DEPEND","DOWN","SOFTRECONFIG","DUMP","IN","OUT",
"SOCKET","RESTRICTED","LOG","ROUTECOLL","TRANSPARENT","TCP","MD5SIG","PASSWORD",
"KEY","TTLSECURITY","ALLOW","DENY","MATCH","QUICK","FROM","TO","ANY",
"CONNECTED","STATIC","COMMUNITY","EXTCOMMUNITY","LARGECOMMUNITY","PREFIX",
"PREFIXLEN","SOURCEAS","TRANSITAS","PEERAS","DELETE","MAXASLEN","MAXASSEQ",
"SET","LOCALPREF","MED","METRIC","NEXTHOP","REJECT","BLACKHOLE","NOMODIFY",
"SELF","PREPEND_SELF","PREPEND_PEER","PFTABLE","WEIGHT","RTLABEL","ORIGIN",
"ERROR","INCLUDE","IPSEC","ESP","AH","SPI","IKE","IPV4","IPV6","QUALIFY","VIA",
"NE","LE","GE","XRANGE","LONGER","STRING","NUMBER",
};
static const char *yyrule[] = {
"$accept : grammar",
"grammar :",
"grammar : grammar '\\n'",
"grammar : grammar include '\\n'",
"grammar : grammar conf_main '\\n'",
"grammar : grammar varset '\\n'",
"grammar : grammar rdomain '\\n'",
"grammar : grammar neighbor '\\n'",
"grammar : grammar group '\\n'",
"grammar : grammar filterrule '\\n'",
"grammar : grammar error '\\n'",
"asnumber : NUMBER",
"as4number : STRING",
"as4number : asnumber",
"as4number_any : STRING",
"as4number_any : asnumber",
"string : string STRING",
"string : STRING",
"yesno : STRING",
"varset : STRING '=' string",
"include : INCLUDE STRING",
"conf_main : AS as4number",
"conf_main : AS as4number asnumber",
"conf_main : ROUTERID address",
"conf_main : HOLDTIME NUMBER",
"conf_main : HOLDTIME YMIN NUMBER",
"conf_main : LISTEN ON address",
"conf_main : FIBPRIORITY NUMBER",
"conf_main : FIBUPDATE yesno",
"conf_main : ROUTECOLL yesno",
"conf_main : RDE RIB STRING",
"conf_main : RDE RIB STRING yesno EVALUATE",
"conf_main : RDE RIB STRING RTABLE NUMBER",
"conf_main : RDE RIB STRING RTABLE NUMBER FIBUPDATE yesno",
"conf_main : TRANSPARENT yesno",
"conf_main : LOG STRING",
"conf_main : network",
"conf_main : DUMP STRING STRING optnumber",
"conf_main : DUMP RIB STRING STRING STRING optnumber",
"conf_main : mrtdump",
"conf_main : RDE STRING EVALUATE",
"conf_main : RDE STRING IGNORE",
"conf_main : RDE MED COMPARE STRING",
"conf_main : NEXTHOP QUALIFY VIA STRING",
"conf_main : RTABLE NUMBER",
"conf_main : CONNECTRETRY NUMBER",
"conf_main : SOCKET STRING restricted",
"mrtdump : DUMP STRING inout STRING optnumber",
"network : NETWORK prefix filter_set",
"network : NETWORK family RTLABEL STRING filter_set",
"network : NETWORK family nettype filter_set",
"inout : IN",
"inout : OUT",
"restricted : RESTRICTED",
"restricted :",
"address : STRING",
"prefix : STRING '/' NUMBER",
"prefix : NUMBER '/' NUMBER",
"addrspec : address",
"addrspec : prefix",
"optnl : '\\n' optnl",
"optnl :",
"nl : '\\n' optnl",
"optnumber :",
"optnumber : NUMBER",
"$$1 :",
"rdomain : RDOMAIN NUMBER optnl '{' optnl $$1 rdomainopts_l '}'",
"rdomainopts_l : rdomainopts_l rdomainoptsl",
"rdomainopts_l : rdomainoptsl",
"rdomainoptsl : rdomainopts nl",
"rdomainopts : RD STRING",
"rdomainopts : EXPORTTRGT STRING STRING",
"rdomainopts : IMPORTTRGT STRING STRING",
"rdomainopts : DESCR string",
"rdomainopts : FIBUPDATE yesno",
"rdomainopts : network",
"rdomainopts : DEPEND ON STRING",
"$$2 :",
"$$3 :",
"neighbor : $$2 NEIGHBOR addrspec $$3 peeropts_h",
"$$4 :",
"group : GROUP string optnl '{' optnl $$4 groupopts_l '}'",
"groupopts_l : groupopts_l groupoptsl",
"groupopts_l : groupoptsl",
"groupoptsl : peeropts nl",
"groupoptsl : neighbor nl",
"groupoptsl : error nl",
"peeropts_h : '{' optnl peeropts_l '}'",
"peeropts_h :",
"peeropts_l : peeropts_l peeroptsl",
"peeropts_l : peeroptsl",
"peeroptsl : peeropts nl",
"peeropts : REMOTEAS as4number",
"peeropts : DESCR string",
"peeropts : LOCALADDR address",
"peeropts : MULTIHOP NUMBER",
"peeropts : PASSIVE",
"peeropts : DOWN",
"peeropts : DOWN STRING",
"peeropts : RIB STRING",
"peeropts : HOLDTIME NUMBER",
"peeropts : HOLDTIME YMIN NUMBER",
"peeropts : ANNOUNCE family STRING",
"peeropts : ANNOUNCE CAPABILITIES yesno",
"peeropts : ANNOUNCE REFRESH yesno",
"peeropts : ANNOUNCE RESTART yesno",
"peeropts : ANNOUNCE AS4BYTE yesno",
"peeropts : ANNOUNCE SELF",
"peeropts : ANNOUNCE STRING",
"peeropts : ENFORCE NEIGHBORAS yesno",
"peeropts : MAXPREFIX NUMBER restart",
"peeropts : TCP MD5SIG PASSWORD string",
"peeropts : TCP MD5SIG KEY string",
"peeropts : IPSEC espah IKE",
"peeropts : IPSEC espah inout SPI NUMBER STRING STRING encspec",
"peeropts : TTLSECURITY yesno",
"peeropts : SET filter_set_opt",
"peeropts : SET optnl '{' optnl filter_set_l optnl '}'",
"peeropts : mrtdump",
"peeropts : REFLECTOR",
"peeropts : REFLECTOR address",
"peeropts : DEPEND ON STRING",
"peeropts : DEMOTE STRING",
"peeropts : SOFTRECONFIG inout yesno",
"peeropts : TRANSPARENT yesno",
"peeropts : LOG STRING",
"restart :",
"restart : RESTART NUMBER",
"family : IPV4",
"family : IPV6",
"nettype : STATIC",
"nettype : CONNECTED",
"espah : ESP",
"espah : AH",
"encspec :",
"encspec : STRING STRING",
"filterrule : action quick filter_rib direction filter_peer_h filter_match_h filter_set",
"action : ALLOW",
"action : DENY",
"action : MATCH",
"quick :",
"quick : QUICK",
"direction : FROM",
"direction : TO",
"filter_rib :",
"filter_rib : RIB STRING",
"filter_peer_h : filter_peer",
"filter_peer_h : '{' filter_peer_l '}'",
"filter_peer_l : filter_peer",
"filter_peer_l : filter_peer_l comma filter_peer",
"filter_peer : ANY",
"filter_peer : address",
"filter_peer : AS as4number",
"filter_peer : GROUP STRING",
"filter_prefix_h : IPV4 prefixlenop",
"filter_prefix_h : IPV6 prefixlenop",
"filter_prefix_h : PREFIX filter_prefix",
"filter_prefix_h : PREFIX '{' filter_prefix_l '}'",
"filter_prefix_l : filter_prefix",
"filter_prefix_l : filter_prefix_l comma filter_prefix",
"filter_prefix : prefix prefixlenop",
"filter_as_h : filter_as_t",
"filter_as_h : '{' filter_as_t_l '}'",
"filter_as_t_l : filter_as_t",
"filter_as_t_l : filter_as_t_l comma filter_as_t",
"filter_as_t : filter_as_type filter_as",
"filter_as_t : filter_as_type '{' filter_as_l_h '}'",
"filter_as_l_h : filter_as_l",
"filter_as_l_h : '{' filter_as_l '}'",
"filter_as_l_h : '{' filter_as_l '}' filter_as_l_h",
"filter_as_l : filter_as",
"filter_as_l : filter_as_l comma filter_as",
"filter_as : as4number_any",
"filter_as : NEIGHBORAS",
"filter_as : equalityop as4number_any",
"filter_as : as4number_any binaryop as4number_any",
"filter_match_h :",
"$$5 :",
"filter_match_h : $$5 filter_match",
"filter_match : filter_elm",
"filter_match : filter_match filter_elm",
"filter_elm : filter_prefix_h",
"filter_elm : filter_as_h",
"filter_elm : MAXASLEN NUMBER",
"filter_elm : MAXASSEQ NUMBER",
"filter_elm : COMMUNITY STRING",
"filter_elm : LARGECOMMUNITY STRING",
"filter_elm : EXTCOMMUNITY STRING STRING",
"filter_elm : NEXTHOP address",
"filter_elm : NEXTHOP NEIGHBOR",
"prefixlenop :",
"prefixlenop : LONGER",
"prefixlenop : PREFIXLEN unaryop NUMBER",
"prefixlenop : PREFIXLEN NUMBER binaryop NUMBER",
"filter_as_type : AS",
"filter_as_type : SOURCEAS",
"filter_as_type : TRANSITAS",
"filter_as_type : PEERAS",
"filter_set :",
"filter_set : SET filter_set_opt",
"filter_set : SET optnl '{' optnl filter_set_l optnl '}'",
"filter_set_l : filter_set_l comma filter_set_opt",
"filter_set_l : filter_set_opt",
"delete :",
"delete : DELETE",
"filter_set_opt : LOCALPREF NUMBER",
"filter_set_opt : LOCALPREF '+' NUMBER",
"filter_set_opt : LOCALPREF '-' NUMBER",
"filter_set_opt : MED NUMBER",
"filter_set_opt : MED '+' NUMBER",
"filter_set_opt : MED '-' NUMBER",
"filter_set_opt : METRIC NUMBER",
"filter_set_opt : METRIC '+' NUMBER",
"filter_set_opt : METRIC '-' NUMBER",
"filter_set_opt : WEIGHT NUMBER",
"filter_set_opt : WEIGHT '+' NUMBER",
"filter_set_opt : WEIGHT '-' NUMBER",
"filter_set_opt : NEXTHOP address",
"filter_set_opt : NEXTHOP BLACKHOLE",
"filter_set_opt : NEXTHOP REJECT",
"filter_set_opt : NEXTHOP NOMODIFY",
"filter_set_opt : NEXTHOP SELF",
"filter_set_opt : PREPEND_SELF NUMBER",
"filter_set_opt : PREPEND_PEER NUMBER",
"filter_set_opt : PFTABLE STRING",
"filter_set_opt : RTLABEL STRING",
"filter_set_opt : COMMUNITY delete STRING",
"filter_set_opt : LARGECOMMUNITY delete STRING",
"filter_set_opt : EXTCOMMUNITY delete STRING STRING",
"filter_set_opt : ORIGIN origincode",
"origincode : string",
"comma : ','",
"comma :",
"unaryop : '='",
"unaryop : NE",
"unaryop : LE",
"unaryop : '<'",
"unaryop : GE",
"unaryop : '>'",
"equalityop : '='",
"equalityop : NE",
"binaryop : '-'",
"binaryop : XRANGE",

};
#endif
#if YYDEBUG
#include <stdio.h>
#endif

/* define the initial stack-sizes */
#ifdef YYSTACKSIZE
#undef YYMAXDEPTH
#define YYMAXDEPTH  YYSTACKSIZE
#else
#ifdef YYMAXDEPTH
#define YYSTACKSIZE YYMAXDEPTH
#else
#define YYSTACKSIZE 500
#define YYMAXDEPTH  500
#endif
#endif

#define YYINITSTACKSIZE 500

int      yydebug;
int      yynerrs;

typedef struct {
    unsigned stacksize;
    short    *s_base;
    short    *s_mark;
    short    *s_last;
    YYSTYPE  *l_base;
    YYSTYPE  *l_mark;
} YYSTACKDATA;

#define YYPURE 0

int      yyerrflag;
int      yychar;
YYSTYPE  yyval;
YYSTYPE  yylval;

/* variables for the parser stack */
static YYSTACKDATA yystack;
#line 2258 "parse.y"

struct keywords {
	const char	*k_name;
	int		 k_val;
};

int
yyerror(const char *fmt, ...)
{
	va_list		 ap;
	char		*msg;

	file->errors++;
	va_start(ap, fmt);
	if (vasprintf(&msg, fmt, ap) == -1)
		fatalx("yyerror vasprintf");
	va_end(ap);
	logit(LOG_CRIT, "%s:%d: %s", file->name, yylval.lineno, msg);
	free(msg);
	return (0);
}

int
kw_cmp(const void *k, const void *e)
{
	return (strcmp(k, ((const struct keywords *)e)->k_name));
}

int
lookup(char *s)
{
	/* this has to be sorted always */
	static const struct keywords keywords[] = {
		{ "AS",			AS},
		{ "IPv4",		IPV4},
		{ "IPv6",		IPV6},
		{ "ah",			AH},
		{ "allow",		ALLOW},
		{ "announce",		ANNOUNCE},
		{ "any",		ANY},
		{ "as-4byte",		AS4BYTE },
		{ "blackhole",		BLACKHOLE},
		{ "capabilities",	CAPABILITIES},
		{ "community",		COMMUNITY},
		{ "compare",		COMPARE},
		{ "connect-retry",	CONNECTRETRY},
		{ "connected",		CONNECTED},
		{ "delete",		DELETE},
		{ "demote",		DEMOTE},
		{ "deny",		DENY},
		{ "depend",		DEPEND},
		{ "descr",		DESCR},
		{ "down",		DOWN},
		{ "dump",		DUMP},
		{ "enforce",		ENFORCE},
		{ "esp",		ESP},
		{ "evaluate",		EVALUATE},
		{ "export-target",	EXPORTTRGT},
		{ "ext-community",	EXTCOMMUNITY},
		{ "fib-priority",	FIBPRIORITY},
		{ "fib-update",		FIBUPDATE},
		{ "from",		FROM},
		{ "group",		GROUP},
		{ "holdtime",		HOLDTIME},
		{ "ignore",		IGNORE},
		{ "ike",		IKE},
		{ "import-target",	IMPORTTRGT},
		{ "in",			IN},
		{ "include",		INCLUDE},
		{ "inet",		IPV4},
		{ "inet6",		IPV6},
		{ "ipsec",		IPSEC},
		{ "key",		KEY},
		{ "large-community",	LARGECOMMUNITY},
		{ "listen",		LISTEN},
		{ "local-address",	LOCALADDR},
		{ "localpref",		LOCALPREF},
		{ "log",		LOG},
		{ "match",		MATCH},
		{ "max-as-len",		MAXASLEN},
		{ "max-as-seq",		MAXASSEQ},
		{ "max-prefix",		MAXPREFIX},
		{ "md5sig",		MD5SIG},
		{ "med",		MED},
		{ "metric",		METRIC},
		{ "min",		YMIN},
		{ "multihop",		MULTIHOP},
		{ "neighbor",		NEIGHBOR},
		{ "neighbor-as",	NEIGHBORAS},
		{ "network",		NETWORK},
		{ "nexthop",		NEXTHOP},
		{ "no-modify",		NOMODIFY},
		{ "on",			ON},
		{ "or-longer",		LONGER},
		{ "origin",		ORIGIN},
		{ "out",		OUT},
		{ "passive",		PASSIVE},
		{ "password",		PASSWORD},
		{ "peer-as",		PEERAS},
		{ "pftable",		PFTABLE},
		{ "prefix",		PREFIX},
		{ "prefixlen",		PREFIXLEN},
		{ "prepend-neighbor",	PREPEND_PEER},
		{ "prepend-self",	PREPEND_SELF},
		{ "qualify",		QUALIFY},
		{ "quick",		QUICK},
		{ "rd",			RD},
		{ "rde",		RDE},
		{ "rdomain",		RDOMAIN},
		{ "refresh",		REFRESH },
		{ "reject",		REJECT},
		{ "remote-as",		REMOTEAS},
		{ "restart",		RESTART},
		{ "restricted",		RESTRICTED},
		{ "rib",		RIB},
		{ "route-collector",	ROUTECOLL},
		{ "route-reflector",	REFLECTOR},
		{ "router-id",		ROUTERID},
		{ "rtable",		RTABLE},
		{ "rtlabel",		RTLABEL},
		{ "self",		SELF},
		{ "set",		SET},
		{ "socket",		SOCKET },
		{ "softreconfig",	SOFTRECONFIG},
		{ "source-as",		SOURCEAS},
		{ "spi",		SPI},
		{ "static",		STATIC},
		{ "tcp",		TCP},
		{ "to",			TO},
		{ "transit-as",		TRANSITAS},
		{ "transparent-as",	TRANSPARENT},
		{ "ttl-security",	TTLSECURITY},
		{ "via",		VIA},
		{ "weight",		WEIGHT}
	};
	const struct keywords	*p;

	p = bsearch(s, keywords, sizeof(keywords)/sizeof(keywords[0]),
	    sizeof(keywords[0]), kw_cmp);

	if (p)
		return (p->k_val);
	else
		return (STRING);
}

#define MAXPUSHBACK	128

u_char	*parsebuf;
int	 parseindex;
u_char	 pushback_buffer[MAXPUSHBACK];
int	 pushback_index = 0;

int
lgetc(int quotec)
{
	int		c, next;

	if (parsebuf) {
		/* Read character from the parsebuffer instead of input. */
		if (parseindex >= 0) {
			c = parsebuf[parseindex++];
			if (c != '\0')
				return (c);
			parsebuf = NULL;
		} else
			parseindex++;
	}

	if (pushback_index)
		return (pushback_buffer[--pushback_index]);

	if (quotec) {
		if ((c = getc(file->stream)) == EOF) {
			yyerror("reached end of file while parsing "
			    "quoted string");
			if (file == topfile || popfile() == EOF)
				return (EOF);
			return (quotec);
		}
		return (c);
	}

	while ((c = getc(file->stream)) == '\\') {
		next = getc(file->stream);
		if (next != '\n') {
			c = next;
			break;
		}
		yylval.lineno = file->lineno;
		file->lineno++;
	}

	while (c == EOF) {
		if (file == topfile || popfile() == EOF)
			return (EOF);
		c = getc(file->stream);
	}
	return (c);
}

int
lungetc(int c)
{
	if (c == EOF)
		return (EOF);
	if (parsebuf) {
		parseindex--;
		if (parseindex >= 0)
			return (c);
	}
	if (pushback_index < MAXPUSHBACK-1)
		return (pushback_buffer[pushback_index++] = c);
	else
		return (EOF);
}

int
findeol(void)
{
	int	c;

	parsebuf = NULL;

	/* skip to either EOF or the first real EOL */
	while (1) {
		if (pushback_index)
			c = pushback_buffer[--pushback_index];
		else
			c = lgetc(0);
		if (c == '\n') {
			file->lineno++;
			break;
		}
		if (c == EOF)
			break;
	}
	return (ERROR);
}

int
yylex(void)
{
	u_char	 buf[8096];
	u_char	*p, *val;
	int	 quotec, next, c;
	int	 token;

top:
	p = buf;
	while ((c = lgetc(0)) == ' ' || c == '\t')
		; /* nothing */

	yylval.lineno = file->lineno;
	if (c == '#')
		while ((c = lgetc(0)) != '\n' && c != EOF)
			; /* nothing */
	if (c == '$' && parsebuf == NULL) {
		while (1) {
			if ((c = lgetc(0)) == EOF)
				return (0);

			if (p + 1 >= buf + sizeof(buf) - 1) {
				yyerror("string too long");
				return (findeol());
			}
			if (isalnum(c) || c == '_') {
				*p++ = c;
				continue;
			}
			*p = '\0';
			lungetc(c);
			break;
		}
		val = symget(buf);
		if (val == NULL) {
			yyerror("macro '%s' not defined", buf);
			return (findeol());
		}
		parsebuf = val;
		parseindex = 0;
		goto top;
	}

	switch (c) {
	case '\'':
	case '"':
		quotec = c;
		while (1) {
			if ((c = lgetc(quotec)) == EOF)
				return (0);
			if (c == '\n') {
				file->lineno++;
				continue;
			} else if (c == '\\') {
				if ((next = lgetc(quotec)) == EOF)
					return (0);
				if (next == quotec || c == ' ' || c == '\t')
					c = next;
				else if (next == '\n') {
					file->lineno++;
					continue;
				} else
					lungetc(next);
			} else if (c == quotec) {
				*p = '\0';
				break;
			} else if (c == '\0') {
				yyerror("syntax error");
				return (findeol());
			}
			if (p + 1 >= buf + sizeof(buf) - 1) {
				yyerror("string too long");
				return (findeol());
			}
			*p++ = c;
		}
		yylval.v.string = strdup(buf);
		if (yylval.v.string == NULL)
			fatal("yylex: strdup");
		return (STRING);
	case '!':
		next = lgetc(0);
		if (next == '=')
			return (NE);
		lungetc(next);
		break;
	case '<':
		next = lgetc(0);
		if (next == '=')
			return (LE);
		lungetc(next);
		break;
	case '>':
		next = lgetc(0);
		if (next == '<')
			return (XRANGE);
		else if (next == '=')
			return (GE);
		lungetc(next);
		break;
	}

#define allowed_to_end_number(x) \
	(isspace(x) || x == ')' || x ==',' || x == '/' || x == '}' || x == '=')

	if (c == '-' || isdigit(c)) {
		do {
			*p++ = c;
			if ((unsigned)(p-buf) >= sizeof(buf)) {
				yyerror("string too long");
				return (findeol());
			}
		} while ((c = lgetc(0)) != EOF && isdigit(c));
		lungetc(c);
		if (p == buf + 1 && buf[0] == '-')
			goto nodigits;
		if (c == EOF || allowed_to_end_number(c)) {
			const char *errstr = NULL;

			*p = '\0';
			yylval.v.number = strtonum(buf, LLONG_MIN,
			    LLONG_MAX, &errstr);
			if (errstr) {
				yyerror("\"%s\" invalid number: %s",
				    buf, errstr);
				return (findeol());
			}
			return (NUMBER);
		} else {
nodigits:
			while (p > buf + 1)
				lungetc(*--p);
			c = *--p;
			if (c == '-')
				return (c);
		}
	}

#define allowed_in_string(x) \
	(isalnum(x) || (ispunct(x) && x != '(' && x != ')' && \
	x != '{' && x != '}' && x != '<' && x != '>' && \
	x != '!' && x != '=' && x != '/' && x != '#' && \
	x != ','))

	if (isalnum(c) || c == ':' || c == '_' || c == '*') {
		do {
			*p++ = c;
			if ((unsigned)(p-buf) >= sizeof(buf)) {
				yyerror("string too long");
				return (findeol());
			}
		} while ((c = lgetc(0)) != EOF && (allowed_in_string(c)));
		lungetc(c);
		*p = '\0';
		if ((token = lookup(buf)) == STRING)
			if ((yylval.v.string = strdup(buf)) == NULL)
				fatal("yylex: strdup");
		return (token);
	}
	if (c == '\n') {
		yylval.lineno = file->lineno;
		file->lineno++;
	}
	if (c == EOF)
		return (0);
	return (c);
}

int
check_file_secrecy(int fd, const char *fname)
{
	struct stat	st;

	if (fstat(fd, &st)) {
		log_warn("cannot stat %s", fname);
		return (-1);
	}
	if (st.st_uid != 0 && st.st_uid != getuid()) {
		log_warnx("%s: owner not root or current user", fname);
		return (-1);
	}
	if (st.st_mode & (S_IWGRP | S_IXGRP | S_IRWXO)) {
		log_warnx("%s: group writable or world read/writeable", fname);
		return (-1);
	}
	return (0);
}

struct file *
pushfile(const char *name, int secret)
{
	struct file	*nfile;

	if ((nfile = calloc(1, sizeof(struct file))) == NULL) {
		log_warn("malloc");
		return (NULL);
	}
	if ((nfile->name = strdup(name)) == NULL) {
		log_warn("malloc");
		free(nfile);
		return (NULL);
	}
	if ((nfile->stream = fopen(nfile->name, "r")) == NULL) {
		log_warn("%s", nfile->name);
		free(nfile->name);
		free(nfile);
		return (NULL);
	}
	if (secret &&
	    check_file_secrecy(fileno(nfile->stream), nfile->name)) {
		fclose(nfile->stream);
		free(nfile->name);
		free(nfile);
		return (NULL);
	}
	nfile->lineno = 1;
	TAILQ_INSERT_TAIL(&files, nfile, entry);
	return (nfile);
}

int
popfile(void)
{
	struct file	*prev;

	if ((prev = TAILQ_PREV(file, files, entry)) != NULL)
		prev->errors += file->errors;

	TAILQ_REMOVE(&files, file, entry);
	fclose(file->stream);
	free(file->name);
	free(file);
	file = prev;
	return (file ? 0 : EOF);
}

int
parse_config(char *filename, struct bgpd_config *xconf, struct peer **xpeers)
{
	struct sym		*sym, *next;
	struct peer		*p, *pnext;
	struct rde_rib		*rr;
	int			 errors = 0;

	conf = new_config();

	if ((filter_l = calloc(1, sizeof(struct filter_head))) == NULL)
		fatal(NULL);
	if ((peerfilter_l = calloc(1, sizeof(struct filter_head))) == NULL)
		fatal(NULL);
	if ((groupfilter_l = calloc(1, sizeof(struct filter_head))) == NULL)
		fatal(NULL);
	TAILQ_INIT(filter_l);
	TAILQ_INIT(peerfilter_l);
	TAILQ_INIT(groupfilter_l);

	peer_l = NULL;
	peer_l_old = *xpeers;
	curpeer = NULL;
	curgroup = NULL;
	id = 1;

	netconf = &conf->networks;

	add_rib("Adj-RIB-In", 0, F_RIB_NOFIB | F_RIB_NOEVALUATE);
	add_rib("Loc-RIB", 0, F_RIB_LOCAL);

	if ((file = pushfile(filename, 1)) == NULL) {
		free(conf);
		return (-1);
	}
	topfile = file;

	yyparse();
	errors = file->errors;
	popfile();

	/* Free macros and check which have not been used. */
	TAILQ_FOREACH_SAFE(sym, &symhead, entry, next) {
		if ((cmd_opts & BGPD_OPT_VERBOSE2) && !sym->used)
			fprintf(stderr, "warning: macro \"%s\" not "
			    "used\n", sym->nam);
		if (!sym->persist) {
			free(sym->nam);
			free(sym->val);
			TAILQ_REMOVE(&symhead, sym, entry);
			free(sym);
		}
	}

	if (errors) {
		for (p = peer_l; p != NULL; p = pnext) {
			pnext = p->next;
			free(p);
		}

		while ((rr = SIMPLEQ_FIRST(&ribnames)) != NULL) {
			SIMPLEQ_REMOVE_HEAD(&ribnames, entry);
			free(rr);
		}

		filterlist_free(filter_l);
		filterlist_free(peerfilter_l);
		filterlist_free(groupfilter_l);

		free_config(conf);
	} else {
		/*
		 * Move filter list and static group and peer filtersets
		 * together. Static group sets come first then peer sets
		 * last normal filter rules.
		 */
		merge_filter_lists(conf->filters, groupfilter_l);
		merge_filter_lists(conf->filters, peerfilter_l);
		merge_filter_lists(conf->filters, filter_l);

		errors += mrt_mergeconfig(xconf->mrt, conf->mrt);
		errors += merge_config(xconf, conf, peer_l);
		*xpeers = peer_l;

		for (p = peer_l_old; p != NULL; p = pnext) {
			pnext = p->next;
			free(p);
		}

		free(filter_l);
		free(peerfilter_l);
		free(groupfilter_l);
	}

	return (errors ? -1 : 0);
}

int
symset(const char *nam, const char *val, int persist)
{
	struct sym	*sym;

	TAILQ_FOREACH(sym, &symhead, entry) {
		if (strcmp(nam, sym->nam) == 0)
			break;
	}

	if (sym != NULL) {
		if (sym->persist == 1)
			return (0);
		else {
			free(sym->nam);
			free(sym->val);
			TAILQ_REMOVE(&symhead, sym, entry);
			free(sym);
		}
	}
	if ((sym = calloc(1, sizeof(*sym))) == NULL)
		return (-1);

	sym->nam = strdup(nam);
	if (sym->nam == NULL) {
		free(sym);
		return (-1);
	}
	sym->val = strdup(val);
	if (sym->val == NULL) {
		free(sym->nam);
		free(sym);
		return (-1);
	}
	sym->used = 0;
	sym->persist = persist;
	TAILQ_INSERT_TAIL(&symhead, sym, entry);
	return (0);
}

int
cmdline_symset(char *s)
{
	char	*sym, *val;
	int	ret;
	size_t	len;

	if ((val = strrchr(s, '=')) == NULL)
		return (-1);

	len = strlen(s) - strlen(val) + 1;
	if ((sym = malloc(len)) == NULL)
		fatal("cmdline_symset: malloc");

	strlcpy(sym, s, len);

	ret = symset(sym, val + 1, 1);
	free(sym);

	return (ret);
}

char *
symget(const char *nam)
{
	struct sym	*sym;

	TAILQ_FOREACH(sym, &symhead, entry) {
		if (strcmp(nam, sym->nam) == 0) {
			sym->used = 1;
			return (sym->val);
		}
	}
	return (NULL);
}

int
getcommunity(char *s)
{
	int		 val;
	const char	*errstr;

	if (strcmp(s, "*") == 0)
		return (COMMUNITY_ANY);
	if (strcmp(s, "neighbor-as") == 0)
		return (COMMUNITY_NEIGHBOR_AS);
	val = strtonum(s, 0, USHRT_MAX, &errstr);
	if (errstr) {
		yyerror("Community %s is %s (max: %u)", s, errstr, USHRT_MAX);
		return (COMMUNITY_ERROR);
	}
	return (val);
}

int
parsecommunity(struct filter_community *c, char *s)
{
	char *p;
	int i, as;

	/* Well-known communities */
	if (strcasecmp(s, "NO_EXPORT") == 0) {
		c->as = COMMUNITY_WELLKNOWN;
		c->type = COMMUNITY_NO_EXPORT;
		return (0);
	} else if (strcasecmp(s, "NO_ADVERTISE") == 0) {
		c->as = COMMUNITY_WELLKNOWN;
		c->type = COMMUNITY_NO_ADVERTISE;
		return (0);
	} else if (strcasecmp(s, "NO_EXPORT_SUBCONFED") == 0) {
		c->as = COMMUNITY_WELLKNOWN;
		c->type = COMMUNITY_NO_EXPSUBCONFED;
		return (0);
	} else if (strcasecmp(s, "NO_PEER") == 0) {
		c->as = COMMUNITY_WELLKNOWN;
		c->type = COMMUNITY_NO_PEER;
		return (0);
	} else if (strcasecmp(s, "BLACKHOLE") == 0) {
		c->as = COMMUNITY_WELLKNOWN;
		c->type = COMMUNITY_BLACKHOLE;
		return (0);
	}

	if ((p = strchr(s, ':')) == NULL) {
		yyerror("Bad community syntax");
		return (-1);
	}
	*p++ = 0;

	if ((i = getcommunity(s)) == COMMUNITY_ERROR)
		return (-1);
	if (i == COMMUNITY_WELLKNOWN) {
		yyerror("Bad community AS number");
		return (-1);
	}
	as = i;

	if ((i = getcommunity(p)) == COMMUNITY_ERROR)
		return (-1);
	c->as = as;
	c->type = i;

	return (0);
}

int64_t
getlargecommunity(char *s)
{
	u_int		 val;
	const char	*errstr;

	if (strcmp(s, "*") == 0)
		return (COMMUNITY_ANY);
	if (strcmp(s, "neighbor-as") == 0)
		return (COMMUNITY_NEIGHBOR_AS);
	val = strtonum(s, 0, UINT_MAX, &errstr);
	if (errstr) {
		yyerror("Large Community %s is %s (max: %u)",
		    s, errstr, UINT_MAX);
		return (COMMUNITY_ERROR);
	}
	return (val);
}

int
parselargecommunity(struct filter_largecommunity *c, char *s)
{
	char *p, *q;
	int64_t as, ld1, ld2;

	if ((p = strchr(s, ':')) == NULL) {
		yyerror("Bad community syntax");
		return (-1);
	}
	*p++ = 0;

	if ((q = strchr(p, ':')) == NULL) {
		yyerror("Bad community syntax");
		return (-1);
	}
	*q++ = 0;

	if ((as = getlargecommunity(s)) == COMMUNITY_ERROR)
		return (-1);

	if ((ld1 = getlargecommunity(p)) == COMMUNITY_ERROR)
		return (-1);

	if ((ld2 = getlargecommunity(q)) == COMMUNITY_ERROR)
		return (-1);

	c->as = as;
	c->ld1 = ld1;
	c->ld2 = ld2;

	return (0);
}

int
parsesubtype(char *type)
{
	/* this has to be sorted always */
	static const struct keywords keywords[] = {
		{ "bdc",	EXT_COMMUNITY_BGP_COLLECT },
		{ "odi",	EXT_COMMUNITY_OSPF_DOM_ID },
		{ "ori",	EXT_COMMUNITY_OSPF_RTR_ID },
		{ "ort",	EXT_COMMUNITY_OSPF_RTR_TYPE },
		{ "rt",		EXT_COMMUNITY_ROUTE_TGT },
		{ "soo",	EXT_COMMUNITY_ROUTE_ORIG }
	};
	const struct keywords	*p;

	p = bsearch(type, keywords, sizeof(keywords)/sizeof(keywords[0]),
	    sizeof(keywords[0]), kw_cmp);

	if (p)
		return (p->k_val);
	else
		return (-1);
}

int
parseextvalue(char *s, u_int32_t *v)
{
	const char 	*errstr;
	char		*p;
	struct in_addr	 ip;
	u_int32_t	 uvalh = 0, uval;

	if ((p = strchr(s, '.')) == NULL) {
		/* AS_PLAIN number (4 or 2 byte) */
		uval = strtonum(s, 0, UINT_MAX, &errstr);
		if (errstr) {
			yyerror("Bad ext-community %s is %s", s, errstr);
			return (-1);
		}
		*v = uval;
		if (uval > USHRT_MAX)
			return (EXT_COMMUNITY_FOUR_AS);
		else
			return (EXT_COMMUNITY_TWO_AS);
	} else if (strchr(p + 1, '.') == NULL) {
		/* AS_DOT number (4-byte) */
		*p++ = '\0';
		uvalh = strtonum(s, 0, USHRT_MAX, &errstr);
		if (errstr) {
			yyerror("Bad ext-community %s is %s", s, errstr);
			return (-1);
		}
		uval = strtonum(p, 0, USHRT_MAX, &errstr);
		if (errstr) {
			yyerror("Bad ext-community %s is %s", p, errstr);
			return (-1);
		}
		*v = uval | (uvalh << 16);
		return (EXT_COMMUNITY_FOUR_AS);
	} else {
		/* more than one dot -> IP address */
		if (inet_aton(s, &ip) == 0) {
			yyerror("Bad ext-community %s not parseable", s);
			return (-1);
		}
		*v = ip.s_addr;
		return (EXT_COMMUNITY_IPV4);
	}
	return (-1);
}

int
parseextcommunity(struct filter_extcommunity *c, char *t, char *s)
{
	const struct ext_comm_pairs	 iana[] = IANA_EXT_COMMUNITIES;
	const char 	*errstr;
	u_int64_t	 ullval;
	u_int32_t	 uval;
	char		*p, *ep;
	unsigned int	 i;
	int		 type, subtype;

	if ((subtype = parsesubtype(t)) == -1) {
		yyerror("Bad ext-community unknown type");
		return (-1);
	}

	if ((p = strchr(s, ':')) == NULL) {
		type = EXT_COMMUNITY_OPAQUE,
		errno = 0;
		ullval = strtoull(s, &ep, 0);
		if (s[0] == '\0' || *ep != '\0') {
			yyerror("Bad ext-community bad value");
			return (-1);
		}
		if (errno == ERANGE && ullval > EXT_COMMUNITY_OPAQUE_MAX) {
			yyerror("Bad ext-community value to big");
			return (-1);
		}
		c->data.ext_opaq = ullval;
	} else {
		*p++ = '\0';
		if ((type = parseextvalue(s, &uval)) == -1)
			return (-1);
		switch (type) {
		case EXT_COMMUNITY_TWO_AS:
			ullval = strtonum(p, 0, UINT_MAX, &errstr);
			break;
		case EXT_COMMUNITY_IPV4:
		case EXT_COMMUNITY_FOUR_AS:
			ullval = strtonum(p, 0, USHRT_MAX, &errstr);
			break;
		default:
			fatalx("parseextcommunity: unexpected result");
		}
		if (errstr) {
			yyerror("Bad ext-community %s is %s", p,
			    errstr);
			return (-1);
		}
		switch (type) {
		case EXT_COMMUNITY_TWO_AS:
			c->data.ext_as.as = uval;
			c->data.ext_as.val = ullval;
			break;
		case EXT_COMMUNITY_IPV4:
			c->data.ext_ip.addr.s_addr = uval;
			c->data.ext_ip.val = ullval;
			break;
		case EXT_COMMUNITY_FOUR_AS:
			c->data.ext_as4.as4 = uval;
			c->data.ext_as4.val = ullval;
			break;
		}
	}
	c->type = type;
	c->subtype = subtype;

	/* verify type/subtype combo */
	for (i = 0; i < sizeof(iana)/sizeof(iana[0]); i++) {
		if (iana[i].type == type && iana[i].subtype == subtype) {
			if (iana[i].transitive)
				c->type |= EXT_COMMUNITY_TRANSITIVE;
			c->flags |= EXT_COMMUNITY_FLAG_VALID;
			return (0);
		}
	}

	yyerror("Bad ext-community bad format for type");
	return (-1);
}

struct peer *
alloc_peer(void)
{
	struct peer	*p;
	u_int8_t	 i;

	if ((p = calloc(1, sizeof(struct peer))) == NULL)
		fatal("new_peer");

	/* some sane defaults */
	p->state = STATE_NONE;
	p->next = NULL;
	p->conf.distance = 1;
	p->conf.announce_type = ANNOUNCE_UNDEF;
	p->conf.announce_capa = 1;
	for (i = 0; i < AID_MAX; i++)
		p->conf.capabilities.mp[i] = -1;
	p->conf.capabilities.refresh = 1;
	p->conf.capabilities.grestart.restart = 1;
	p->conf.capabilities.as4byte = 1;
	p->conf.local_as = conf->as;
	p->conf.local_short_as = conf->short_as;
	p->conf.softreconfig_in = 1;
	p->conf.softreconfig_out = 1;

	return (p);
}

struct peer *
new_peer(void)
{
	struct peer		*p;

	p = alloc_peer();

	if (curgroup != NULL) {
		memcpy(p, curgroup, sizeof(struct peer));
		if (strlcpy(p->conf.group, curgroup->conf.group,
		    sizeof(p->conf.group)) >= sizeof(p->conf.group))
			fatalx("new_peer group strlcpy");
		if (strlcpy(p->conf.descr, curgroup->conf.descr,
		    sizeof(p->conf.descr)) >= sizeof(p->conf.descr))
			fatalx("new_peer descr strlcpy");
		p->conf.groupid = curgroup->conf.id;
		p->conf.local_as = curgroup->conf.local_as;
		p->conf.local_short_as = curgroup->conf.local_short_as;
	}
	p->next = NULL;
	if (conf->flags & BGPD_FLAG_DECISION_TRANS_AS)
		p->conf.flags |= PEERFLAG_TRANS_AS;
	return (p);
}

struct peer *
new_group(void)
{
	return (alloc_peer());
}

int
add_mrtconfig(enum mrt_type type, char *name, int timeout, struct peer *p,
    char *rib)
{
	struct mrt	*m, *n;

	LIST_FOREACH(m, conf->mrt, entry) {
		if ((rib && strcmp(rib, m->rib)) ||
		    (!rib && *m->rib))
			continue;
		if (p == NULL) {
			if (m->peer_id != 0 || m->group_id != 0)
				continue;
		} else {
			if (m->peer_id != p->conf.id ||
			    m->group_id != p->conf.groupid)
				continue;
		}
		if (m->type == type) {
			yyerror("only one mrtdump per type allowed.");
			return (-1);
		}
	}

	if ((n = calloc(1, sizeof(struct mrt_config))) == NULL)
		fatal("add_mrtconfig");

	n->type = type;
	if (strlcpy(MRT2MC(n)->name, name, sizeof(MRT2MC(n)->name)) >=
	    sizeof(MRT2MC(n)->name)) {
		yyerror("filename \"%s\" too long: max %zu",
		    name, sizeof(MRT2MC(n)->name) - 1);
		free(n);
		return (-1);
	}
	MRT2MC(n)->ReopenTimerInterval = timeout;
	if (p != NULL) {
		if (curgroup == p) {
			n->peer_id = 0;
			n->group_id = p->conf.id;
		} else {
			n->peer_id = p->conf.id;
			n->group_id = 0;
		}
	}
	if (rib) {
		if (!find_rib(rib)) {
			yyerror("rib \"%s\" does not exist.", rib);
			free(n);
			return (-1);
		}
		if (strlcpy(n->rib, rib, sizeof(n->rib)) >=
		    sizeof(n->rib)) {
			yyerror("rib name \"%s\" too long: max %zu",
			    name, sizeof(n->rib) - 1);
			free(n);
			return (-1);
		}
	}

	LIST_INSERT_HEAD(conf->mrt, n, entry);

	return (0);
}

int
add_rib(char *name, u_int rtableid, u_int16_t flags)
{
	struct rde_rib	*rr;
	u_int		 rdom;

	if ((rr = find_rib(name)) == NULL) {
		if ((rr = calloc(1, sizeof(*rr))) == NULL) {
			log_warn("add_rib");
			return (-1);
		}
	}
	if (strlcpy(rr->name, name, sizeof(rr->name)) >= sizeof(rr->name)) {
		yyerror("rib name \"%s\" too long: max %zu",
		   name, sizeof(rr->name) - 1);
		free(rr);
		return (-1);
	}
	rr->flags |= flags;
	if ((rr->flags & F_RIB_HASNOFIB) == 0) {
		if (ktable_exists(rtableid, &rdom) != 1) {
			yyerror("rtable id %u does not exist", rtableid);
			free(rr);
			return (-1);
		}
		if (rdom != 0) {
			yyerror("rtable %u does not belong to rdomain 0",
			    rtableid);
			free(rr);
			return (-1);
		}
		rr->rtableid = rtableid;
	}
	SIMPLEQ_INSERT_TAIL(&ribnames, rr, entry);
	return (0);
}

struct rde_rib *
find_rib(char *name)
{
	struct rde_rib	*rr;

	SIMPLEQ_FOREACH(rr, &ribnames, entry) {
		if (!strcmp(rr->name, name))
			return (rr);
	}
	return (NULL);
}

int
get_id(struct peer *newpeer)
{
	struct peer	*p;

	for (p = peer_l_old; p != NULL; p = p->next)
		if (newpeer->conf.remote_addr.aid) {
			if (!memcmp(&p->conf.remote_addr,
			    &newpeer->conf.remote_addr,
			    sizeof(p->conf.remote_addr))) {
				newpeer->conf.id = p->conf.id;
				return (0);
			}
		} else {	/* newpeer is a group */
			if (strcmp(newpeer->conf.group, p->conf.group) == 0) {
				newpeer->conf.id = p->conf.groupid;
				return (0);
			}
		}

	/* new one */
	for (; id < UINT_MAX / 2; id++) {
		for (p = peer_l_old; p != NULL &&
		    p->conf.id != id && p->conf.groupid != id; p = p->next)
			;	/* nothing */
		if (p == NULL) {	/* we found a free id */
			newpeer->conf.id = id++;
			return (0);
		}
	}

	return (-1);
}

int
merge_prefixspec(struct filter_prefix_l *p, struct filter_prefixlen *pl)
{
	u_int8_t max_len = 0;

	switch (p->p.addr.aid) {
	case AID_INET:
	case AID_VPN_IPv4:
		max_len = 32;
		break;
	case AID_INET6:
		max_len = 128;
		break;
	}

	switch (pl->op) {
	case OP_NONE:
		return (0);
	case OP_RANGE:
	case OP_XRANGE:
		if (pl->len_min > max_len || pl->len_max > max_len) {
			yyerror("prefixlen %d too big for AF, limit %d",
			    pl->len_min > max_len ? pl->len_min : pl->len_max,
			    max_len);
			return (-1);
		}
		if (pl->len_min < p->p.len) {
			yyerror("prefixlen %d smaller than prefix, limit %d",
			    pl->len_min, p->p.len);
			return (-1);
		}
		p->p.len_max = pl->len_max;
		break;
	case OP_GE:
		/* fix up the "or-longer" case */
		if (pl->len_min == -1)
			pl->len_min = p->p.len;
		/* FALLTHROUGH */
	case OP_EQ:
	case OP_NE:
	case OP_LE:
	case OP_GT:
		if (pl->len_min > max_len) {
			yyerror("prefixlen %d to big for AF, limit %d",
			    pl->len_min, max_len);
			return (-1);
		}
		if (pl->len_min < p->p.len) {
			yyerror("prefixlen %d smaller than prefix, limit %d",
			    pl->len_min, p->p.len);
			return (-1);
		}
		break;
	case OP_LT:
		if (pl->len_min > max_len - 1) {
			yyerror("prefixlen %d to big for AF, limit %d",
			    pl->len_min, max_len - 1);
			return (-1);
		}
		if (pl->len_min < p->p.len + 1) {
			yyerror("prefixlen %d too small for prefix, limit %d",
			    pl->len_min, p->p.len + 1);
			return (-1);
		}
		break;
	}

	p->p.op = pl->op;
	p->p.len_min = pl->len_min;
	return (0);
}

int
expand_rule(struct filter_rule *rule, struct filter_peers_l *peer,
    struct filter_match_l *match, struct filter_set_head *set)
{
	struct filter_rule	*r;
	struct filter_peers_l	*p, *pnext;
	struct filter_prefix_l	*prefix, *prefix_next;
	struct filter_as_l	*a, *anext;
	struct filter_set	*s;

	p = peer;
	do {
		a = match->as_l;
		do {
			prefix = match->prefix_l;
			do {
				if ((r = calloc(1,
				    sizeof(struct filter_rule))) == NULL) {
					log_warn("expand_rule");
					return (-1);
				}

				memcpy(r, rule, sizeof(struct filter_rule));
				memcpy(&r->match, match,
				    sizeof(struct filter_match));
				TAILQ_INIT(&r->set);
				copy_filterset(set, &r->set);

				if (p != NULL)
					memcpy(&r->peer, &p->p,
					    sizeof(struct filter_peers));

				if (prefix != NULL)
					memcpy(&r->match.prefix, &prefix->p,
					    sizeof(r->match.prefix));

				if (a != NULL)
					memcpy(&r->match.as, &a->a,
					    sizeof(struct filter_as));

				TAILQ_INSERT_TAIL(filter_l, r, entry);

				if (prefix != NULL)
					prefix = prefix->next;
			} while (prefix != NULL);

			if (a != NULL)
				a = a->next;
		} while (a != NULL);

		if (p != NULL)
			p = p->next;
	} while (p != NULL);

	for (p = peer; p != NULL; p = pnext) {
		pnext = p->next;
		free(p);
	}

	for (a = match->as_l; a != NULL; a = anext) {
		anext = a->next;
		free(a);
	}

	for (prefix = match->prefix_l; prefix != NULL; prefix = prefix_next) {
		prefix_next = prefix->next;
		free(prefix);
	}

	if (set != NULL) {
		while ((s = TAILQ_FIRST(set)) != NULL) {
			TAILQ_REMOVE(set, s, entry);
			free(s);
		}
		free(set);
	}

	return (0);
}

int
str2key(char *s, char *dest, size_t max_len)
{
	unsigned	i;
	char		t[3];

	if (strlen(s) / 2 > max_len) {
		yyerror("key too long");
		return (-1);
	}

	if (strlen(s) % 2) {
		yyerror("key must be of even length");
		return (-1);
	}

	for (i = 0; i < strlen(s) / 2; i++) {
		t[0] = s[2*i];
		t[1] = s[2*i + 1];
		t[2] = 0;
		if (!isxdigit(t[0]) || !isxdigit(t[1])) {
			yyerror("key must be specified in hex");
			return (-1);
		}
		dest[i] = strtoul(t, NULL, 16);
	}

	return (0);
}

int
neighbor_consistent(struct peer *p)
{
	u_int8_t	i;

	/* local-address and peer's address: same address family */
	if (p->conf.local_addr.aid &&
	    p->conf.local_addr.aid != p->conf.remote_addr.aid) {
		yyerror("local-address and neighbor address "
		    "must be of the same address family");
		return (-1);
	}

	/* with any form of ipsec local-address is required */
	if ((p->conf.auth.method == AUTH_IPSEC_IKE_ESP ||
	    p->conf.auth.method == AUTH_IPSEC_IKE_AH ||
	    p->conf.auth.method == AUTH_IPSEC_MANUAL_ESP ||
	    p->conf.auth.method == AUTH_IPSEC_MANUAL_AH) &&
	    !p->conf.local_addr.aid) {
		yyerror("neighbors with any form of IPsec configured "
		    "need local-address to be specified");
		return (-1);
	}

	/* with static keying we need both directions */
	if ((p->conf.auth.method == AUTH_IPSEC_MANUAL_ESP ||
	    p->conf.auth.method == AUTH_IPSEC_MANUAL_AH) &&
	    (!p->conf.auth.spi_in || !p->conf.auth.spi_out)) {
		yyerror("with manual keyed IPsec, SPIs and keys "
		    "for both directions are required");
		return (-1);
	}

	if (!conf->as) {
		yyerror("AS needs to be given before neighbor definitions");
		return (-1);
	}

	/* set default values if they where undefined */
	p->conf.ebgp = (p->conf.remote_as != conf->as);
	if (p->conf.announce_type == ANNOUNCE_UNDEF)
		p->conf.announce_type = p->conf.ebgp ?
		    ANNOUNCE_SELF : ANNOUNCE_ALL;
	if (p->conf.enforce_as == ENFORCE_AS_UNDEF)
		p->conf.enforce_as = p->conf.ebgp ?
		    ENFORCE_AS_ON : ENFORCE_AS_OFF;

	/* EBGP neighbors are not allowed in route reflector clusters */
	if (p->conf.reflector_client && p->conf.ebgp) {
		yyerror("EBGP neighbors are not allowed in route "
		    "reflector clusters");
		return (-1);
	}

	/* the default MP capability is NONE */
	for (i = 0; i < AID_MAX; i++)
		if (p->conf.capabilities.mp[i] == -1)
			p->conf.capabilities.mp[i] = 0;

	return (0);
}

int
merge_filterset(struct filter_set_head *sh, struct filter_set *s)
{
	struct filter_set	*t;

	TAILQ_FOREACH(t, sh, entry) {
		/*
		 * need to cycle across the full list because even
		 * if types are not equal filterset_cmp() may return 0.
		 */
		if (filterset_cmp(s, t) == 0) {
			if (s->type == ACTION_SET_COMMUNITY)
				yyerror("community is already set");
			else if (s->type == ACTION_DEL_COMMUNITY)
				yyerror("community will already be deleted");
			else if (s->type == ACTION_SET_LARGE_COMMUNITY)
				yyerror("large-community is already set");
			else if (s->type == ACTION_DEL_LARGE_COMMUNITY)
				yyerror("large-community will already be deleted");
			else if (s->type == ACTION_SET_EXT_COMMUNITY)
				yyerror("ext-community is already set");
			else if (s->type == ACTION_DEL_EXT_COMMUNITY)
				yyerror(
				    "ext-community will already be deleted");
			else
				yyerror("redefining set parameter %s",
				    filterset_name(s->type));
			return (-1);
		}
	}

	TAILQ_FOREACH(t, sh, entry) {
		if (s->type < t->type) {
			TAILQ_INSERT_BEFORE(t, s, entry);
			return (0);
		}
		if (s->type == t->type)
			switch (s->type) {
			case ACTION_SET_COMMUNITY:
			case ACTION_DEL_COMMUNITY:
				if (s->action.community.as <
				    t->action.community.as ||
				    (s->action.community.as ==
				    t->action.community.as &&
				    s->action.community.type <
				    t->action.community.type)) {
					TAILQ_INSERT_BEFORE(t, s, entry);
					return (0);
				}
				break;
			case ACTION_SET_LARGE_COMMUNITY:
			case ACTION_DEL_LARGE_COMMUNITY:
				if (s->action.large_community.as <
				    t->action.large_community.as ||
				    (s->action.large_community.as ==
				    t->action.large_community.as &&
				    s->action.large_community.ld1 <
				    t->action.large_community.ld2 )) {
					TAILQ_INSERT_BEFORE(t, s, entry);
					return (0);
				}
				break;
			case ACTION_SET_EXT_COMMUNITY:
			case ACTION_DEL_EXT_COMMUNITY:
				if (memcmp(&s->action.ext_community,
				    &t->action.ext_community,
				    sizeof(s->action.ext_community)) < 0) {
					TAILQ_INSERT_BEFORE(t, s, entry);
					return (0);
				}
				break;
			case ACTION_SET_NEXTHOP:
				if (s->action.nexthop.aid <
				    t->action.nexthop.aid) {
					TAILQ_INSERT_BEFORE(t, s, entry);
					return (0);
				}
				break;
			default:
				break;
			}
	}

	TAILQ_INSERT_TAIL(sh, s, entry);
	return (0);
}

void
copy_filterset(struct filter_set_head *source, struct filter_set_head *dest)
{
	struct filter_set	*s, *t;

	if (source == NULL)
		return;

	TAILQ_FOREACH(s, source, entry) {
		if ((t = malloc(sizeof(struct filter_set))) == NULL)
			fatal(NULL);
		memcpy(t, s, sizeof(struct filter_set));
		TAILQ_INSERT_TAIL(dest, t, entry);
	}
}

void
merge_filter_lists(struct filter_head *dst, struct filter_head *src)
{
	struct filter_rule *r;

	while ((r = TAILQ_FIRST(src)) != NULL) {
		TAILQ_REMOVE(src, r, entry);
		TAILQ_INSERT_TAIL(dst, r, entry);
	}
}

struct filter_rule *
get_rule(enum action_types type)
{
	struct filter_rule	*r;
	int			 out;

	switch (type) {
	case ACTION_SET_PREPEND_SELF:
	case ACTION_SET_NEXTHOP_NOMODIFY:
	case ACTION_SET_NEXTHOP_SELF:
		out = 1;
		break;
	default:
		out = 0;
		break;
	}
	r = (curpeer == curgroup) ? curgroup_filter[out] : curpeer_filter[out];
	if (r == NULL) {
		if ((r = calloc(1, sizeof(struct filter_rule))) == NULL)
			fatal(NULL);
		r->quick = 0;
		r->dir = out ? DIR_OUT : DIR_IN;
		r->action = ACTION_NONE;
		r->match.community.as = COMMUNITY_UNSET;
		r->match.large_community.as = COMMUNITY_UNSET;
		TAILQ_INIT(&r->set);
		if (curpeer == curgroup) {
			/* group */
			r->peer.groupid = curgroup->conf.id;
			curgroup_filter[out] = r;
		} else {
			/* peer */
			r->peer.peerid = curpeer->conf.id;
			curpeer_filter[out] = r;
		}
	}
	return (r);
}
#line 2569 "parse.c"
/* allocate initial stack or double stack size, up to YYMAXDEPTH */
static int yygrowstack(YYSTACKDATA *data)
{
    int i;
    unsigned newsize;
    short *newss;
    YYSTYPE *newvs;

    if ((newsize = data->stacksize) == 0)
        newsize = YYINITSTACKSIZE;
    else if (newsize >= YYMAXDEPTH)
        return -1;
    else if ((newsize *= 2) > YYMAXDEPTH)
        newsize = YYMAXDEPTH;

    i = data->s_mark - data->s_base;
    newss = (data->s_base != 0)
          ? (short *)realloc(data->s_base, newsize * sizeof(*newss))
          : (short *)malloc(newsize * sizeof(*newss));
    if (newss == 0)
        return -1;

    data->s_base  = newss;
    data->s_mark = newss + i;

    newvs = (data->l_base != 0)
          ? (YYSTYPE *)realloc(data->l_base, newsize * sizeof(*newvs))
          : (YYSTYPE *)malloc(newsize * sizeof(*newvs));
    if (newvs == 0)
        return -1;

    data->l_base = newvs;
    data->l_mark = newvs + i;

    data->stacksize = newsize;
    data->s_last = data->s_base + newsize - 1;
    return 0;
}

#if YYPURE || defined(YY_NO_LEAKS)
static void yyfreestack(YYSTACKDATA *data)
{
    free(data->s_base);
    free(data->l_base);
    memset(data, 0, sizeof(*data));
}
#else
#define yyfreestack(data) /* nothing */
#endif

#define YYABORT  goto yyabort
#define YYREJECT goto yyabort
#define YYACCEPT goto yyaccept
#define YYERROR  goto yyerrlab

int
YYPARSE_DECL()
{
    int yym, yyn, yystate;
#if YYDEBUG
    const char *yys;

    if ((yys = getenv("YYDEBUG")) != 0)
    {
        yyn = *yys;
        if (yyn >= '0' && yyn <= '9')
            yydebug = yyn - '0';
    }
#endif

    yynerrs = 0;
    yyerrflag = 0;
    yychar = YYEMPTY;
    yystate = 0;

#if YYPURE
    memset(&yystack, 0, sizeof(yystack));
#endif

    if (yystack.s_base == NULL && yygrowstack(&yystack)) goto yyoverflow;
    yystack.s_mark = yystack.s_base;
    yystack.l_mark = yystack.l_base;
    yystate = 0;
    *yystack.s_mark = 0;

yyloop:
    if ((yyn = yydefred[yystate]) != 0) goto yyreduce;
    if (yychar < 0)
    {
        if ((yychar = yylex()) < 0) yychar = 0;
#if YYDEBUG
        if (yydebug)
        {
            yys = 0;
            if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
            if (!yys) yys = "illegal-symbol";
            printf("%sdebug: state %d, reading %d (%s)\n",
                    YYPREFIX, yystate, yychar, yys);
        }
#endif
    }
    if ((yyn = yysindex[yystate]) && (yyn += yychar) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yychar)
    {
#if YYDEBUG
        if (yydebug)
            printf("%sdebug: state %d, shifting to state %d\n",
                    YYPREFIX, yystate, yytable[yyn]);
#endif
        if (yystack.s_mark >= yystack.s_last && yygrowstack(&yystack))
        {
            goto yyoverflow;
        }
        yystate = yytable[yyn];
        *++yystack.s_mark = yytable[yyn];
        *++yystack.l_mark = yylval;
        yychar = YYEMPTY;
        if (yyerrflag > 0)  --yyerrflag;
        goto yyloop;
    }
    if ((yyn = yyrindex[yystate]) && (yyn += yychar) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yychar)
    {
        yyn = yytable[yyn];
        goto yyreduce;
    }
    if (yyerrflag) goto yyinrecovery;

    yyerror("syntax error");

    goto yyerrlab;

yyerrlab:
    ++yynerrs;

yyinrecovery:
    if (yyerrflag < 3)
    {
        yyerrflag = 3;
        for (;;)
        {
            if ((yyn = yysindex[*yystack.s_mark]) && (yyn += YYERRCODE) >= 0 &&
                    yyn <= YYTABLESIZE && yycheck[yyn] == YYERRCODE)
            {
#if YYDEBUG
                if (yydebug)
                    printf("%sdebug: state %d, error recovery shifting\
 to state %d\n", YYPREFIX, *yystack.s_mark, yytable[yyn]);
#endif
                if (yystack.s_mark >= yystack.s_last && yygrowstack(&yystack))
                {
                    goto yyoverflow;
                }
                yystate = yytable[yyn];
                *++yystack.s_mark = yytable[yyn];
                *++yystack.l_mark = yylval;
                goto yyloop;
            }
            else
            {
#if YYDEBUG
                if (yydebug)
                    printf("%sdebug: error recovery discarding state %d\n",
                            YYPREFIX, *yystack.s_mark);
#endif
                if (yystack.s_mark <= yystack.s_base) goto yyabort;
                --yystack.s_mark;
                --yystack.l_mark;
            }
        }
    }
    else
    {
        if (yychar == 0) goto yyabort;
#if YYDEBUG
        if (yydebug)
        {
            yys = 0;
            if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
            if (!yys) yys = "illegal-symbol";
            printf("%sdebug: state %d, error recovery discards token %d (%s)\n",
                    YYPREFIX, yystate, yychar, yys);
        }
#endif
        yychar = YYEMPTY;
        goto yyloop;
    }

yyreduce:
#if YYDEBUG
    if (yydebug)
        printf("%sdebug: state %d, reducing by rule %d (%s)\n",
                YYPREFIX, yystate, yyn, yyrule[yyn]);
#endif
    yym = yylen[yyn];
    if (yym)
        yyval = yystack.l_mark[1-yym];
    else
        memset(&yyval, 0, sizeof yyval);
    switch (yyn)
    {
case 10:
#line 239 "parse.y"
	{ file->errors++; }
break;
case 11:
#line 242 "parse.y"
	{
			/*
			 * According to iana 65535 and 4294967295 are reserved
			 * but enforcing this is not duty of the parser.
			 */
			if (yystack.l_mark[0].v.number < 0 || yystack.l_mark[0].v.number > UINT_MAX) {
				yyerror("AS too big: max %u", UINT_MAX);
				YYERROR;
			}
		}
break;
case 12:
#line 253 "parse.y"
	{
			const char	*errstr;
			char		*dot;
			u_int32_t	 uvalh = 0, uval;

			if ((dot = strchr(yystack.l_mark[0].v.string,'.')) != NULL) {
				*dot++ = '\0';
				uvalh = strtonum(yystack.l_mark[0].v.string, 0, USHRT_MAX, &errstr);
				if (errstr) {
					yyerror("number %s is %s", yystack.l_mark[0].v.string, errstr);
					free(yystack.l_mark[0].v.string);
					YYERROR;
				}
				uval = strtonum(dot, 0, USHRT_MAX, &errstr);
				if (errstr) {
					yyerror("number %s is %s", dot, errstr);
					free(yystack.l_mark[0].v.string);
					YYERROR;
				}
				free(yystack.l_mark[0].v.string);
			} else {
				yyerror("AS %s is bad", yystack.l_mark[0].v.string);
				free(yystack.l_mark[0].v.string);
				YYERROR;
			}
			if (uvalh == 0 && uval == AS_TRANS) {
				yyerror("AS %u is reserved and may not be used",
				    AS_TRANS);
				YYERROR;
			}
			yyval.v.number = uval | (uvalh << 16);
		}
break;
case 13:
#line 285 "parse.y"
	{
			if (yystack.l_mark[0].v.number == AS_TRANS) {
				yyerror("AS %u is reserved and may not be used",
				    AS_TRANS);
				YYERROR;
			}
			yyval.v.number = yystack.l_mark[0].v.number;
		}
break;
case 14:
#line 295 "parse.y"
	{
			const char	*errstr;
			char		*dot;
			u_int32_t	 uvalh = 0, uval;

			if ((dot = strchr(yystack.l_mark[0].v.string,'.')) != NULL) {
				*dot++ = '\0';
				uvalh = strtonum(yystack.l_mark[0].v.string, 0, USHRT_MAX, &errstr);
				if (errstr) {
					yyerror("number %s is %s", yystack.l_mark[0].v.string, errstr);
					free(yystack.l_mark[0].v.string);
					YYERROR;
				}
				uval = strtonum(dot, 0, USHRT_MAX, &errstr);
				if (errstr) {
					yyerror("number %s is %s", dot, errstr);
					free(yystack.l_mark[0].v.string);
					YYERROR;
				}
				free(yystack.l_mark[0].v.string);
			} else {
				yyerror("AS %s is bad", yystack.l_mark[0].v.string);
				free(yystack.l_mark[0].v.string);
				YYERROR;
			}
			yyval.v.number = uval | (uvalh << 16);
		}
break;
case 15:
#line 322 "parse.y"
	{
			yyval.v.number = yystack.l_mark[0].v.number;
		}
break;
case 16:
#line 327 "parse.y"
	{
			if (asprintf(&yyval.v.string, "%s %s", yystack.l_mark[-1].v.string, yystack.l_mark[0].v.string) == -1)
				fatal("string: asprintf");
			free(yystack.l_mark[-1].v.string);
			free(yystack.l_mark[0].v.string);
		}
break;
case 18:
#line 336 "parse.y"
	{
			if (!strcmp(yystack.l_mark[0].v.string, "yes"))
				yyval.v.number = 1;
			else if (!strcmp(yystack.l_mark[0].v.string, "no"))
				yyval.v.number = 0;
			else {
				yyerror("syntax error, "
				    "either yes or no expected");
				free(yystack.l_mark[0].v.string);
				YYERROR;
			}
			free(yystack.l_mark[0].v.string);
		}
break;
case 19:
#line 351 "parse.y"
	{
			char *s = yystack.l_mark[-2].v.string;
			if (cmd_opts & BGPD_OPT_VERBOSE)
				printf("%s = \"%s\"\n", yystack.l_mark[-2].v.string, yystack.l_mark[0].v.string);
			while (*s++) {
				if (isspace((unsigned char)*s)) {
					yyerror("macro name cannot contain "
					    "whitespace");
					YYERROR;
				}
			}
			if (symset(yystack.l_mark[-2].v.string, yystack.l_mark[0].v.string, 0) == -1)
				fatal("cannot store variable");
			free(yystack.l_mark[-2].v.string);
			free(yystack.l_mark[0].v.string);
		}
break;
case 20:
#line 369 "parse.y"
	{
			struct file	*nfile;

			if ((nfile = pushfile(yystack.l_mark[0].v.string, 1)) == NULL) {
				yyerror("failed to include file %s", yystack.l_mark[0].v.string);
				free(yystack.l_mark[0].v.string);
				YYERROR;
			}
			free(yystack.l_mark[0].v.string);

			file = nfile;
			lungetc('\n');
		}
break;
case 21:
#line 384 "parse.y"
	{
			conf->as = yystack.l_mark[0].v.number;
			if (yystack.l_mark[0].v.number > USHRT_MAX)
				conf->short_as = AS_TRANS;
			else
				conf->short_as = yystack.l_mark[0].v.number;
		}
break;
case 22:
#line 391 "parse.y"
	{
			conf->as = yystack.l_mark[-1].v.number;
			conf->short_as = yystack.l_mark[0].v.number;
		}
break;
case 23:
#line 395 "parse.y"
	{
			if (yystack.l_mark[0].v.addr.aid != AID_INET) {
				yyerror("router-id must be an IPv4 address");
				YYERROR;
			}
			conf->bgpid = yystack.l_mark[0].v.addr.v4.s_addr;
		}
break;
case 24:
#line 402 "parse.y"
	{
			if (yystack.l_mark[0].v.number < MIN_HOLDTIME || yystack.l_mark[0].v.number > USHRT_MAX) {
				yyerror("holdtime must be between %u and %u",
				    MIN_HOLDTIME, USHRT_MAX);
				YYERROR;
			}
			conf->holdtime = yystack.l_mark[0].v.number;
		}
break;
case 25:
#line 410 "parse.y"
	{
			if (yystack.l_mark[0].v.number < MIN_HOLDTIME || yystack.l_mark[0].v.number > USHRT_MAX) {
				yyerror("holdtime must be between %u and %u",
				    MIN_HOLDTIME, USHRT_MAX);
				YYERROR;
			}
			conf->min_holdtime = yystack.l_mark[0].v.number;
		}
break;
case 26:
#line 418 "parse.y"
	{
			struct listen_addr	*la;

			if ((la = calloc(1, sizeof(struct listen_addr))) ==
			    NULL)
				fatal("parse conf_main listen on calloc");

			la->fd = -1;
			memcpy(&la->sa, addr2sa(&yystack.l_mark[0].v.addr, BGP_PORT), sizeof(la->sa));
			TAILQ_INSERT_TAIL(conf->listen_addrs, la, entry);
		}
break;
case 27:
#line 429 "parse.y"
	{
			if (yystack.l_mark[0].v.number <= RTP_NONE || yystack.l_mark[0].v.number > RTP_MAX) {
				yyerror("invalid fib-priority");
				YYERROR;
			}
			conf->fib_priority = yystack.l_mark[0].v.number;
		}
break;
case 28:
#line 436 "parse.y"
	{
			struct rde_rib *rr;
			rr = find_rib("Loc-RIB");
			if (rr == NULL)
				fatalx("RTABLE can not find the main RIB!");

			if (yystack.l_mark[0].v.number == 0)
				rr->flags |= F_RIB_NOFIBSYNC;
			else
				rr->flags &= ~F_RIB_NOFIBSYNC;
		}
break;
case 29:
#line 447 "parse.y"
	{
			if (yystack.l_mark[0].v.number == 1)
				conf->flags |= BGPD_FLAG_NO_EVALUATE;
			else
				conf->flags &= ~BGPD_FLAG_NO_EVALUATE;
		}
break;
case 30:
#line 453 "parse.y"
	{
			if (add_rib(yystack.l_mark[0].v.string, 0, F_RIB_NOFIB)) {
				free(yystack.l_mark[0].v.string);
				YYERROR;
			}
			free(yystack.l_mark[0].v.string);
		}
break;
case 31:
#line 460 "parse.y"
	{
			if (yystack.l_mark[-1].v.number) {
				free(yystack.l_mark[-2].v.string);
				yyerror("bad rde rib definition");
				YYERROR;
			}
			if (add_rib(yystack.l_mark[-2].v.string, 0, F_RIB_NOFIB | F_RIB_NOEVALUATE)) {
				free(yystack.l_mark[-2].v.string);
				YYERROR;
			}
			free(yystack.l_mark[-2].v.string);
		}
break;
case 32:
#line 472 "parse.y"
	{
			if (add_rib(yystack.l_mark[-2].v.string, yystack.l_mark[0].v.number, 0)) {
				free(yystack.l_mark[-2].v.string);
				YYERROR;
			}
			free(yystack.l_mark[-2].v.string);
		}
break;
case 33:
#line 479 "parse.y"
	{
			int	flags = 0;
			if (yystack.l_mark[0].v.number == 0)
				flags = F_RIB_NOFIBSYNC;
			if (add_rib(yystack.l_mark[-4].v.string, yystack.l_mark[-2].v.number, flags)) {
				free(yystack.l_mark[-4].v.string);
				YYERROR;
			}
			free(yystack.l_mark[-4].v.string);
		}
break;
case 34:
#line 489 "parse.y"
	{
			if (yystack.l_mark[0].v.number == 1)
				conf->flags |= BGPD_FLAG_DECISION_TRANS_AS;
			else
				conf->flags &= ~BGPD_FLAG_DECISION_TRANS_AS;
		}
break;
case 35:
#line 495 "parse.y"
	{
			if (!strcmp(yystack.l_mark[0].v.string, "updates"))
				conf->log |= BGPD_LOG_UPDATES;
			else {
				free(yystack.l_mark[0].v.string);
				YYERROR;
			}
			free(yystack.l_mark[0].v.string);
		}
break;
case 37:
#line 505 "parse.y"
	{
			int action;

			if (yystack.l_mark[0].v.number < 0 || yystack.l_mark[0].v.number > INT_MAX) {
				yyerror("bad timeout");
				free(yystack.l_mark[-2].v.string);
				free(yystack.l_mark[-1].v.string);
				YYERROR;
			}
			if (!strcmp(yystack.l_mark[-2].v.string, "table"))
				action = MRT_TABLE_DUMP;
			else if (!strcmp(yystack.l_mark[-2].v.string, "table-mp"))
				action = MRT_TABLE_DUMP_MP;
			else if (!strcmp(yystack.l_mark[-2].v.string, "table-v2"))
				action = MRT_TABLE_DUMP_V2;
			else {
				yyerror("unknown mrt dump type");
				free(yystack.l_mark[-2].v.string);
				free(yystack.l_mark[-1].v.string);
				YYERROR;
			}
			free(yystack.l_mark[-2].v.string);
			if (add_mrtconfig(action, yystack.l_mark[-1].v.string, yystack.l_mark[0].v.number, NULL, NULL) == -1) {
				free(yystack.l_mark[-1].v.string);
				YYERROR;
			}
			free(yystack.l_mark[-1].v.string);
		}
break;
case 38:
#line 533 "parse.y"
	{
			int action;

			if (yystack.l_mark[0].v.number < 0 || yystack.l_mark[0].v.number > INT_MAX) {
				yyerror("bad timeout");
				free(yystack.l_mark[-3].v.string);
				free(yystack.l_mark[-2].v.string);
				free(yystack.l_mark[-1].v.string);
				YYERROR;
			}
			if (!strcmp(yystack.l_mark[-2].v.string, "table"))
				action = MRT_TABLE_DUMP;
			else if (!strcmp(yystack.l_mark[-2].v.string, "table-mp"))
				action = MRT_TABLE_DUMP_MP;
			else if (!strcmp(yystack.l_mark[-2].v.string, "table-v2"))
				action = MRT_TABLE_DUMP_V2;
			else {
				yyerror("unknown mrt dump type");
				free(yystack.l_mark[-3].v.string);
				free(yystack.l_mark[-2].v.string);
				free(yystack.l_mark[-1].v.string);
				YYERROR;
			}
			free(yystack.l_mark[-2].v.string);
			if (add_mrtconfig(action, yystack.l_mark[-1].v.string, yystack.l_mark[0].v.number, NULL, yystack.l_mark[-3].v.string) == -1) {
				free(yystack.l_mark[-3].v.string);
				free(yystack.l_mark[-1].v.string);
				YYERROR;
			}
			free(yystack.l_mark[-3].v.string);
			free(yystack.l_mark[-1].v.string);
		}
break;
case 40:
#line 566 "parse.y"
	{
			if (!strcmp(yystack.l_mark[-1].v.string, "route-age"))
				conf->flags |= BGPD_FLAG_DECISION_ROUTEAGE;
			else {
				yyerror("unknown route decision type");
				free(yystack.l_mark[-1].v.string);
				YYERROR;
			}
			free(yystack.l_mark[-1].v.string);
		}
break;
case 41:
#line 576 "parse.y"
	{
			if (!strcmp(yystack.l_mark[-1].v.string, "route-age"))
				conf->flags &= ~BGPD_FLAG_DECISION_ROUTEAGE;
			else {
				yyerror("unknown route decision type");
				free(yystack.l_mark[-1].v.string);
				YYERROR;
			}
			free(yystack.l_mark[-1].v.string);
		}
break;
case 42:
#line 586 "parse.y"
	{
			if (!strcmp(yystack.l_mark[0].v.string, "always"))
				conf->flags |= BGPD_FLAG_DECISION_MED_ALWAYS;
			else if (!strcmp(yystack.l_mark[0].v.string, "strict"))
				conf->flags &= ~BGPD_FLAG_DECISION_MED_ALWAYS;
			else {
				yyerror("rde med compare: "
				    "unknown setting \"%s\"", yystack.l_mark[0].v.string);
				free(yystack.l_mark[0].v.string);
				YYERROR;
			}
			free(yystack.l_mark[0].v.string);
		}
break;
case 43:
#line 599 "parse.y"
	{
			if (!strcmp(yystack.l_mark[0].v.string, "bgp"))
				conf->flags |= BGPD_FLAG_NEXTHOP_BGP;
			else if (!strcmp(yystack.l_mark[0].v.string, "default"))
				conf->flags |= BGPD_FLAG_NEXTHOP_DEFAULT;
			else {
				yyerror("nexthop depend on: "
				    "unknown setting \"%s\"", yystack.l_mark[0].v.string);
				free(yystack.l_mark[0].v.string);
				YYERROR;
			}
			free(yystack.l_mark[0].v.string);
		}
break;
case 44:
#line 612 "parse.y"
	{
			struct rde_rib *rr;
			if (ktable_exists(yystack.l_mark[0].v.number, NULL) != 1) {
				yyerror("rtable id %lld does not exist", yystack.l_mark[0].v.number);
				YYERROR;
			}
			rr = find_rib("Loc-RIB");
			if (rr == NULL)
				fatalx("RTABLE can not find the main RIB!");
			rr->rtableid = yystack.l_mark[0].v.number;
		}
break;
case 45:
#line 623 "parse.y"
	{
			if (yystack.l_mark[0].v.number > USHRT_MAX || yystack.l_mark[0].v.number < 1) {
				yyerror("invalid connect-retry");
				YYERROR;
			}
			conf->connectretry = yystack.l_mark[0].v.number;
		}
break;
case 46:
#line 630 "parse.y"
	{
			if (strlen(yystack.l_mark[-1].v.string) >=
			    sizeof(((struct sockaddr_un *)0)->sun_path)) {
				yyerror("socket path too long");
				YYERROR;
			}
			if (yystack.l_mark[0].v.number) {
				free(conf->rcsock);
				conf->rcsock = yystack.l_mark[-1].v.string;
			} else {
				free(conf->csock);
				conf->csock = yystack.l_mark[-1].v.string;
			}
		}
break;
case 47:
#line 646 "parse.y"
	{
			int action;

			if (yystack.l_mark[0].v.number < 0 || yystack.l_mark[0].v.number > INT_MAX) {
				yyerror("bad timeout");
				free(yystack.l_mark[-3].v.string);
				free(yystack.l_mark[-1].v.string);
				YYERROR;
			}
			if (!strcmp(yystack.l_mark[-3].v.string, "all"))
				action = yystack.l_mark[-2].v.number ? MRT_ALL_IN : MRT_ALL_OUT;
			else if (!strcmp(yystack.l_mark[-3].v.string, "updates"))
				action = yystack.l_mark[-2].v.number ? MRT_UPDATE_IN : MRT_UPDATE_OUT;
			else {
				yyerror("unknown mrt msg dump type");
				free(yystack.l_mark[-3].v.string);
				free(yystack.l_mark[-1].v.string);
				YYERROR;
			}
			if (add_mrtconfig(action, yystack.l_mark[-1].v.string, yystack.l_mark[0].v.number, curpeer, NULL) ==
			    -1) {
				free(yystack.l_mark[-3].v.string);
				free(yystack.l_mark[-1].v.string);
				YYERROR;
			}
			free(yystack.l_mark[-3].v.string);
			free(yystack.l_mark[-1].v.string);
		}
break;
case 48:
#line 676 "parse.y"
	{
			struct network	*n;

			if ((n = calloc(1, sizeof(struct network))) == NULL)
				fatal("new_network");
			memcpy(&n->net.prefix, &yystack.l_mark[-1].v.prefix.prefix,
			    sizeof(n->net.prefix));
			n->net.prefixlen = yystack.l_mark[-1].v.prefix.len;
			filterset_move(yystack.l_mark[0].v.filter_set_head, &n->net.attrset);
			free(yystack.l_mark[0].v.filter_set_head);

			TAILQ_INSERT_TAIL(netconf, n, entry);
		}
break;
case 49:
#line 689 "parse.y"
	{
			struct network	*n;

			if ((n = calloc(1, sizeof(struct network))) == NULL)
				fatal("new_network");
			if (afi2aid(yystack.l_mark[-3].v.number, SAFI_UNICAST, &n->net.prefix.aid) ==
			    -1) {
				yyerror("unknown family");
				filterset_free(yystack.l_mark[0].v.filter_set_head);
				free(yystack.l_mark[0].v.filter_set_head);
				YYERROR;
			}
			n->net.type = NETWORK_RTLABEL;
			n->net.rtlabel = rtlabel_name2id(yystack.l_mark[-1].v.string);
			filterset_move(yystack.l_mark[0].v.filter_set_head, &n->net.attrset);
			free(yystack.l_mark[0].v.filter_set_head);

			TAILQ_INSERT_TAIL(netconf, n, entry);
		}
break;
case 50:
#line 708 "parse.y"
	{
			struct network	*n;

			if ((n = calloc(1, sizeof(struct network))) == NULL)
				fatal("new_network");
			if (afi2aid(yystack.l_mark[-2].v.number, SAFI_UNICAST, &n->net.prefix.aid) ==
			    -1) {
				yyerror("unknown family");
				filterset_free(yystack.l_mark[0].v.filter_set_head);
				free(yystack.l_mark[0].v.filter_set_head);
				YYERROR;
			}
			n->net.type = yystack.l_mark[-1].v.number ? NETWORK_STATIC : NETWORK_CONNECTED;
			filterset_move(yystack.l_mark[0].v.filter_set_head, &n->net.attrset);
			free(yystack.l_mark[0].v.filter_set_head);

			TAILQ_INSERT_TAIL(netconf, n, entry);
		}
break;
case 51:
#line 728 "parse.y"
	{ yyval.v.number = 1; }
break;
case 52:
#line 729 "parse.y"
	{ yyval.v.number = 0; }
break;
case 53:
#line 732 "parse.y"
	{ yyval.v.number = 1; }
break;
case 54:
#line 733 "parse.y"
	{ yyval.v.number = 0; }
break;
case 55:
#line 736 "parse.y"
	{
			u_int8_t	len;

			if (!host(yystack.l_mark[0].v.string, &yyval.v.addr, &len)) {
				yyerror("could not parse address spec \"%s\"",
				    yystack.l_mark[0].v.string);
				free(yystack.l_mark[0].v.string);
				YYERROR;
			}
			free(yystack.l_mark[0].v.string);

			if ((yyval.v.addr.aid == AID_INET && len != 32) ||
			    (yyval.v.addr.aid == AID_INET6 && len != 128)) {
				/* unreachable */
				yyerror("got prefixlen %u, expected %u",
				    len, yyval.v.addr.aid == AID_INET ? 32 : 128);
				YYERROR;
			}
		}
break;
case 56:
#line 757 "parse.y"
	{
			char	*s;

			if (yystack.l_mark[0].v.number < 0 || yystack.l_mark[0].v.number > 128) {
				yyerror("bad prefixlen %lld", yystack.l_mark[0].v.number);
				free(yystack.l_mark[-2].v.string);
				YYERROR;
			}
			if (asprintf(&s, "%s/%lld", yystack.l_mark[-2].v.string, yystack.l_mark[0].v.number) == -1)
				fatal(NULL);
			free(yystack.l_mark[-2].v.string);

			if (!host(s, &yyval.v.prefix.prefix, &yyval.v.prefix.len)) {
				yyerror("could not parse address \"%s\"", s);
				free(s);
				YYERROR;
			}
			free(s);
		}
break;
case 57:
#line 776 "parse.y"
	{
			char	*s;

			/* does not match IPv6 */
			if (yystack.l_mark[-2].v.number < 0 || yystack.l_mark[-2].v.number > 255 || yystack.l_mark[0].v.number < 0 || yystack.l_mark[0].v.number > 32) {
				yyerror("bad prefix %lld/%lld", yystack.l_mark[-2].v.number, yystack.l_mark[0].v.number);
				YYERROR;
			}
			if (asprintf(&s, "%lld/%lld", yystack.l_mark[-2].v.number, yystack.l_mark[0].v.number) == -1)
				fatal(NULL);

			if (!host(s, &yyval.v.prefix.prefix, &yyval.v.prefix.len)) {
				yyerror("could not parse address \"%s\"", s);
				free(s);
				YYERROR;
			}
			free(s);
		}
break;
case 58:
#line 796 "parse.y"
	{
			memcpy(&yyval.v.prefix.prefix, &yystack.l_mark[0].v.addr, sizeof(struct bgpd_addr));
			if (yyval.v.prefix.prefix.aid == AID_INET)
				yyval.v.prefix.len = 32;
			else
				yyval.v.prefix.len = 128;
		}
break;
case 63:
#line 813 "parse.y"
	{ yyval.v.number = 0; }
break;
case 65:
#line 817 "parse.y"
	{
			if (ktable_exists(yystack.l_mark[-3].v.number, NULL) != 1) {
				yyerror("rdomain %lld does not exist", yystack.l_mark[-3].v.number);
				YYERROR;
			}
			if (!(currdom = calloc(1, sizeof(struct rdomain))))
				fatal(NULL);
			currdom->rtableid = yystack.l_mark[-3].v.number;
			TAILQ_INIT(&currdom->import);
			TAILQ_INIT(&currdom->export);
			TAILQ_INIT(&currdom->net_l);
			netconf = &currdom->net_l;
		}
break;
case 66:
#line 830 "parse.y"
	{
			/* insert into list */
			SIMPLEQ_INSERT_TAIL(&conf->rdomains, currdom, entry);
			currdom = NULL;
			netconf = &conf->networks;
		}
break;
case 70:
#line 844 "parse.y"
	{
			struct filter_extcommunity	ext;
			u_int64_t			rd;

			if (parseextcommunity(&ext, "rt", yystack.l_mark[0].v.string) == -1) {
				free(yystack.l_mark[0].v.string);
				YYERROR;
			}
			free(yystack.l_mark[0].v.string);
			/*
			 * RD is almost encode like an ext-community,
			 * but only almost so convert here.
			 */
			if (community_ext_conv(&ext, 0, &rd)) {
				yyerror("bad encoding of rd");
				YYERROR;
			}
			rd = betoh64(rd) & 0xffffffffffffULL;
			switch (ext.type) {
			case EXT_COMMUNITY_TWO_AS:
				rd |= (0ULL << 48);
				break;
			case EXT_COMMUNITY_IPV4:
				rd |= (1ULL << 48);
				break;
			case EXT_COMMUNITY_FOUR_AS:
				rd |= (2ULL << 48);
				break;
			default:
				yyerror("bad encoding of rd");
				YYERROR;
			}
			currdom->rd = htobe64(rd);
		}
break;
case 71:
#line 878 "parse.y"
	{
			struct filter_set	*set;

			if ((set = calloc(1, sizeof(struct filter_set))) ==
			    NULL)
				fatal(NULL);
			set->type = ACTION_SET_EXT_COMMUNITY;
			if (parseextcommunity(&set->action.ext_community,
			    yystack.l_mark[-1].v.string, yystack.l_mark[0].v.string) == -1) {
				free(yystack.l_mark[0].v.string);
				free(yystack.l_mark[-1].v.string);
				free(set);
				YYERROR;
			}
			free(yystack.l_mark[0].v.string);
			free(yystack.l_mark[-1].v.string);
			TAILQ_INSERT_TAIL(&currdom->export, set, entry);
		}
break;
case 72:
#line 896 "parse.y"
	{
			struct filter_set	*set;

			if ((set = calloc(1, sizeof(struct filter_set))) ==
			    NULL)
				fatal(NULL);
			set->type = ACTION_SET_EXT_COMMUNITY;
			if (parseextcommunity(&set->action.ext_community,
			    yystack.l_mark[-1].v.string, yystack.l_mark[0].v.string) == -1) {
				free(yystack.l_mark[0].v.string);
				free(yystack.l_mark[-1].v.string);
				free(set);
				YYERROR;
			}
			free(yystack.l_mark[0].v.string);
			free(yystack.l_mark[-1].v.string);
			TAILQ_INSERT_TAIL(&currdom->import, set, entry);
		}
break;
case 73:
#line 914 "parse.y"
	{
			if (strlcpy(currdom->descr, yystack.l_mark[0].v.string,
			    sizeof(currdom->descr)) >=
			    sizeof(currdom->descr)) {
				yyerror("descr \"%s\" too long: max %zu",
				    yystack.l_mark[0].v.string, sizeof(currdom->descr) - 1);
				free(yystack.l_mark[0].v.string);
				YYERROR;
			}
			free(yystack.l_mark[0].v.string);
		}
break;
case 74:
#line 925 "parse.y"
	{
			if (yystack.l_mark[0].v.number == 0)
				currdom->flags |= F_RIB_NOFIBSYNC;
			else
				currdom->flags &= ~F_RIB_NOFIBSYNC;
		}
break;
case 76:
#line 932 "parse.y"
	{
			/* XXX this is a hack */
			if (if_nametoindex(yystack.l_mark[0].v.string) == 0) {
				yyerror("interface %s does not exist", yystack.l_mark[0].v.string);
				free(yystack.l_mark[0].v.string);
				YYERROR;
			}
			strlcpy(currdom->ifmpe, yystack.l_mark[0].v.string, IFNAMSIZ);
			free(yystack.l_mark[0].v.string);
			if (get_mpe_label(currdom)) {
				yyerror("failed to get mpls label from %s",
				    currdom->ifmpe);
				YYERROR;
			}
		}
break;
case 77:
#line 949 "parse.y"
	{	curpeer = new_peer(); }
break;
case 78:
#line 950 "parse.y"
	{
			memcpy(&curpeer->conf.remote_addr, &yystack.l_mark[0].v.prefix.prefix,
			    sizeof(curpeer->conf.remote_addr));
			curpeer->conf.remote_masklen = yystack.l_mark[0].v.prefix.len;
			if ((yystack.l_mark[0].v.prefix.prefix.aid == AID_INET && yystack.l_mark[0].v.prefix.len != 32) ||
			    (yystack.l_mark[0].v.prefix.prefix.aid == AID_INET6 && yystack.l_mark[0].v.prefix.len != 128))
				curpeer->conf.template = 1;
			if (curpeer->conf.capabilities.mp[
			    curpeer->conf.remote_addr.aid] == -1)
				curpeer->conf.capabilities.mp[
				    curpeer->conf.remote_addr.aid] = 1;
			if (get_id(curpeer)) {
				yyerror("get_id failed");
				YYERROR;
			}
		}
break;
case 79:
#line 966 "parse.y"
	{
			if (curpeer_filter[0] != NULL)
				TAILQ_INSERT_TAIL(peerfilter_l,
				    curpeer_filter[0], entry);
			if (curpeer_filter[1] != NULL)
				TAILQ_INSERT_TAIL(peerfilter_l,
				    curpeer_filter[1], entry);
			curpeer_filter[0] = NULL;
			curpeer_filter[1] = NULL;

			if (neighbor_consistent(curpeer) == -1)
				YYERROR;
			curpeer->next = peer_l;
			peer_l = curpeer;
			curpeer = curgroup;
		}
break;
case 80:
#line 984 "parse.y"
	{
			curgroup = curpeer = new_group();
			if (strlcpy(curgroup->conf.group, yystack.l_mark[-3].v.string,
			    sizeof(curgroup->conf.group)) >=
			    sizeof(curgroup->conf.group)) {
				yyerror("group name \"%s\" too long: max %zu",
				    yystack.l_mark[-3].v.string, sizeof(curgroup->conf.group) - 1);
				free(yystack.l_mark[-3].v.string);
				YYERROR;
			}
			free(yystack.l_mark[-3].v.string);
			if (get_id(curgroup)) {
				yyerror("get_id failed");
				YYERROR;
			}
		}
break;
case 81:
#line 1000 "parse.y"
	{
			if (curgroup_filter[0] != NULL)
				TAILQ_INSERT_TAIL(groupfilter_l,
				    curgroup_filter[0], entry);
			if (curgroup_filter[1] != NULL)
				TAILQ_INSERT_TAIL(groupfilter_l,
				    curgroup_filter[1], entry);
			curgroup_filter[0] = NULL;
			curgroup_filter[1] = NULL;

			free(curgroup);
			curgroup = NULL;
		}
break;
case 92:
#line 1035 "parse.y"
	{
			curpeer->conf.remote_as = yystack.l_mark[0].v.number;
		}
break;
case 93:
#line 1038 "parse.y"
	{
			if (strlcpy(curpeer->conf.descr, yystack.l_mark[0].v.string,
			    sizeof(curpeer->conf.descr)) >=
			    sizeof(curpeer->conf.descr)) {
				yyerror("descr \"%s\" too long: max %zu",
				    yystack.l_mark[0].v.string, sizeof(curpeer->conf.descr) - 1);
				free(yystack.l_mark[0].v.string);
				YYERROR;
			}
			free(yystack.l_mark[0].v.string);
		}
break;
case 94:
#line 1049 "parse.y"
	{
			memcpy(&curpeer->conf.local_addr, &yystack.l_mark[0].v.addr,
			    sizeof(curpeer->conf.local_addr));
		}
break;
case 95:
#line 1053 "parse.y"
	{
			if (yystack.l_mark[0].v.number < 2 || yystack.l_mark[0].v.number > 255) {
				yyerror("invalid multihop distance %lld", yystack.l_mark[0].v.number);
				YYERROR;
			}
			curpeer->conf.distance = yystack.l_mark[0].v.number;
		}
break;
case 96:
#line 1060 "parse.y"
	{
			curpeer->conf.passive = 1;
		}
break;
case 97:
#line 1063 "parse.y"
	{
			curpeer->conf.down = 1;
		}
break;
case 98:
#line 1066 "parse.y"
	{
			curpeer->conf.down = 1;
			if (strlcpy(curpeer->conf.shutcomm, yystack.l_mark[0].v.string,
				sizeof(curpeer->conf.shutcomm)) >=
				sizeof(curpeer->conf.shutcomm)) {
				    yyerror("shutdown reason too long");
				    free(yystack.l_mark[0].v.string);
				    YYERROR;
			}
			free(yystack.l_mark[0].v.string);
		}
break;
case 99:
#line 1077 "parse.y"
	{
			if (!find_rib(yystack.l_mark[0].v.string)) {
				yyerror("rib \"%s\" does not exist.", yystack.l_mark[0].v.string);
				free(yystack.l_mark[0].v.string);
				YYERROR;
			}
			if (strlcpy(curpeer->conf.rib, yystack.l_mark[0].v.string,
			    sizeof(curpeer->conf.rib)) >=
			    sizeof(curpeer->conf.rib)) {
				yyerror("rib name \"%s\" too long: max %zu",
				   yystack.l_mark[0].v.string, sizeof(curpeer->conf.rib) - 1);
				free(yystack.l_mark[0].v.string);
				YYERROR;
			}
			free(yystack.l_mark[0].v.string);
		}
break;
case 100:
#line 1093 "parse.y"
	{
			if (yystack.l_mark[0].v.number < MIN_HOLDTIME || yystack.l_mark[0].v.number > USHRT_MAX) {
				yyerror("holdtime must be between %u and %u",
				    MIN_HOLDTIME, USHRT_MAX);
				YYERROR;
			}
			curpeer->conf.holdtime = yystack.l_mark[0].v.number;
		}
break;
case 101:
#line 1101 "parse.y"
	{
			if (yystack.l_mark[0].v.number < MIN_HOLDTIME || yystack.l_mark[0].v.number > USHRT_MAX) {
				yyerror("holdtime must be between %u and %u",
				    MIN_HOLDTIME, USHRT_MAX);
				YYERROR;
			}
			curpeer->conf.min_holdtime = yystack.l_mark[0].v.number;
		}
break;
case 102:
#line 1109 "parse.y"
	{
			u_int8_t	aid, safi;
			int8_t		val = 1;

			if (!strcmp(yystack.l_mark[0].v.string, "none")) {
				safi = SAFI_UNICAST;
				val = 0;
			} else if (!strcmp(yystack.l_mark[0].v.string, "unicast")) {
				safi = SAFI_UNICAST;
			} else if (!strcmp(yystack.l_mark[0].v.string, "vpn")) {
				safi = SAFI_MPLSVPN;
			} else {
				yyerror("unknown/unsupported SAFI \"%s\"",
				    yystack.l_mark[0].v.string);
				free(yystack.l_mark[0].v.string);
				YYERROR;
			}
			free(yystack.l_mark[0].v.string);

			if (afi2aid(yystack.l_mark[-1].v.number, safi, &aid) == -1) {
				yyerror("unknown AFI/SAFI pair");
				YYERROR;
			}
			curpeer->conf.capabilities.mp[aid] = val;
		}
break;
case 103:
#line 1134 "parse.y"
	{
			curpeer->conf.announce_capa = yystack.l_mark[0].v.number;
		}
break;
case 104:
#line 1137 "parse.y"
	{
			curpeer->conf.capabilities.refresh = yystack.l_mark[0].v.number;
		}
break;
case 105:
#line 1140 "parse.y"
	{
			curpeer->conf.capabilities.grestart.restart = yystack.l_mark[0].v.number;
		}
break;
case 106:
#line 1143 "parse.y"
	{
			curpeer->conf.capabilities.as4byte = yystack.l_mark[0].v.number;
		}
break;
case 107:
#line 1146 "parse.y"
	{
			curpeer->conf.announce_type = ANNOUNCE_SELF;
		}
break;
case 108:
#line 1149 "parse.y"
	{
			if (!strcmp(yystack.l_mark[0].v.string, "self"))
				curpeer->conf.announce_type = ANNOUNCE_SELF;
			else if (!strcmp(yystack.l_mark[0].v.string, "none"))
				curpeer->conf.announce_type = ANNOUNCE_NONE;
			else if (!strcmp(yystack.l_mark[0].v.string, "all"))
				curpeer->conf.announce_type = ANNOUNCE_ALL;
			else if (!strcmp(yystack.l_mark[0].v.string, "default-route"))
				curpeer->conf.announce_type =
				    ANNOUNCE_DEFAULT_ROUTE;
			else {
				yyerror("invalid announce type");
				free(yystack.l_mark[0].v.string);
				YYERROR;
			}
			free(yystack.l_mark[0].v.string);
		}
break;
case 109:
#line 1166 "parse.y"
	{
			if (yystack.l_mark[0].v.number)
				curpeer->conf.enforce_as = ENFORCE_AS_ON;
			else
				curpeer->conf.enforce_as = ENFORCE_AS_OFF;
		}
break;
case 110:
#line 1172 "parse.y"
	{
			if (yystack.l_mark[-1].v.number < 0 || yystack.l_mark[-1].v.number > UINT_MAX) {
				yyerror("bad maximum number of prefixes");
				YYERROR;
			}
			curpeer->conf.max_prefix = yystack.l_mark[-1].v.number;
			curpeer->conf.max_prefix_restart = yystack.l_mark[0].v.number;
		}
break;
case 111:
#line 1180 "parse.y"
	{
			if (curpeer->conf.auth.method) {
				yyerror("auth method cannot be redefined");
				free(yystack.l_mark[0].v.string);
				YYERROR;
			}
			if (strlcpy(curpeer->conf.auth.md5key, yystack.l_mark[0].v.string,
			    sizeof(curpeer->conf.auth.md5key)) >=
			    sizeof(curpeer->conf.auth.md5key)) {
				yyerror("tcp md5sig password too long: max %zu",
				    sizeof(curpeer->conf.auth.md5key) - 1);
				free(yystack.l_mark[0].v.string);
				YYERROR;
			}
			curpeer->conf.auth.method = AUTH_MD5SIG;
			curpeer->conf.auth.md5key_len = strlen(yystack.l_mark[0].v.string);
			free(yystack.l_mark[0].v.string);
		}
break;
case 112:
#line 1198 "parse.y"
	{
			if (curpeer->conf.auth.method) {
				yyerror("auth method cannot be redefined");
				free(yystack.l_mark[0].v.string);
				YYERROR;
			}

			if (str2key(yystack.l_mark[0].v.string, curpeer->conf.auth.md5key,
			    sizeof(curpeer->conf.auth.md5key)) == -1) {
				free(yystack.l_mark[0].v.string);
				YYERROR;
			}
			curpeer->conf.auth.method = AUTH_MD5SIG;
			curpeer->conf.auth.md5key_len = strlen(yystack.l_mark[0].v.string) / 2;
			free(yystack.l_mark[0].v.string);
		}
break;
case 113:
#line 1214 "parse.y"
	{
			if (curpeer->conf.auth.method) {
				yyerror("auth method cannot be redefined");
				YYERROR;
			}
			if (yystack.l_mark[-1].v.number)
				curpeer->conf.auth.method = AUTH_IPSEC_IKE_ESP;
			else
				curpeer->conf.auth.method = AUTH_IPSEC_IKE_AH;
		}
break;
case 114:
#line 1224 "parse.y"
	{
			u_int32_t	auth_alg;
			u_int8_t	keylen;

			if (curpeer->conf.auth.method &&
			    (((curpeer->conf.auth.spi_in && yystack.l_mark[-5].v.number == 1) ||
			    (curpeer->conf.auth.spi_out && yystack.l_mark[-5].v.number == 0)) ||
			    (yystack.l_mark[-6].v.number == 1 && curpeer->conf.auth.method !=
			    AUTH_IPSEC_MANUAL_ESP) ||
			    (yystack.l_mark[-6].v.number == 0 && curpeer->conf.auth.method !=
			    AUTH_IPSEC_MANUAL_AH))) {
				yyerror("auth method cannot be redefined");
				free(yystack.l_mark[-2].v.string);
				free(yystack.l_mark[-1].v.string);
				YYERROR;
			}

			if (!strcmp(yystack.l_mark[-2].v.string, "sha1")) {
				auth_alg = SADB_AALG_SHA1HMAC;
				keylen = 20;
			} else if (!strcmp(yystack.l_mark[-2].v.string, "md5")) {
				auth_alg = SADB_AALG_MD5HMAC;
				keylen = 16;
			} else {
				yyerror("unknown auth algorithm \"%s\"", yystack.l_mark[-2].v.string);
				free(yystack.l_mark[-2].v.string);
				free(yystack.l_mark[-1].v.string);
				YYERROR;
			}
			free(yystack.l_mark[-2].v.string);

			if (strlen(yystack.l_mark[-1].v.string) / 2 != keylen) {
				yyerror("auth key len: must be %u bytes, "
				    "is %zu bytes", keylen, strlen(yystack.l_mark[-1].v.string) / 2);
				free(yystack.l_mark[-1].v.string);
				YYERROR;
			}

			if (yystack.l_mark[-6].v.number)
				curpeer->conf.auth.method =
				    AUTH_IPSEC_MANUAL_ESP;
			else {
				if (yystack.l_mark[0].v.encspec.enc_alg) {
					yyerror("\"ipsec ah\" doesn't take "
					    "encryption keys");
					free(yystack.l_mark[-1].v.string);
					YYERROR;
				}
				curpeer->conf.auth.method =
				    AUTH_IPSEC_MANUAL_AH;
			}

			if (yystack.l_mark[-3].v.number <= SPI_RESERVED_MAX || yystack.l_mark[-3].v.number > UINT_MAX) {
				yyerror("bad spi number %lld", yystack.l_mark[-3].v.number);
				free(yystack.l_mark[-1].v.string);
				YYERROR;
			}

			if (yystack.l_mark[-5].v.number == 1) {
				if (str2key(yystack.l_mark[-1].v.string, curpeer->conf.auth.auth_key_in,
				    sizeof(curpeer->conf.auth.auth_key_in)) ==
				    -1) {
					free(yystack.l_mark[-1].v.string);
					YYERROR;
				}
				curpeer->conf.auth.spi_in = yystack.l_mark[-3].v.number;
				curpeer->conf.auth.auth_alg_in = auth_alg;
				curpeer->conf.auth.enc_alg_in = yystack.l_mark[0].v.encspec.enc_alg;
				memcpy(&curpeer->conf.auth.enc_key_in,
				    &yystack.l_mark[0].v.encspec.enc_key,
				    sizeof(curpeer->conf.auth.enc_key_in));
				curpeer->conf.auth.enc_keylen_in =
				    yystack.l_mark[0].v.encspec.enc_key_len;
				curpeer->conf.auth.auth_keylen_in = keylen;
			} else {
				if (str2key(yystack.l_mark[-1].v.string, curpeer->conf.auth.auth_key_out,
				    sizeof(curpeer->conf.auth.auth_key_out)) ==
				    -1) {
					free(yystack.l_mark[-1].v.string);
					YYERROR;
				}
				curpeer->conf.auth.spi_out = yystack.l_mark[-3].v.number;
				curpeer->conf.auth.auth_alg_out = auth_alg;
				curpeer->conf.auth.enc_alg_out = yystack.l_mark[0].v.encspec.enc_alg;
				memcpy(&curpeer->conf.auth.enc_key_out,
				    &yystack.l_mark[0].v.encspec.enc_key,
				    sizeof(curpeer->conf.auth.enc_key_out));
				curpeer->conf.auth.enc_keylen_out =
				    yystack.l_mark[0].v.encspec.enc_key_len;
				curpeer->conf.auth.auth_keylen_out = keylen;
			}
			free(yystack.l_mark[-1].v.string);
		}
break;
case 115:
#line 1317 "parse.y"
	{
			curpeer->conf.ttlsec = yystack.l_mark[0].v.number;
		}
break;
case 116:
#line 1320 "parse.y"
	{
			struct filter_rule	*r;

			r = get_rule(yystack.l_mark[0].v.filter_set->type);
			if (merge_filterset(&r->set, yystack.l_mark[0].v.filter_set) == -1)
				YYERROR;
		}
break;
case 117:
#line 1327 "parse.y"
	{
			struct filter_rule	*r;
			struct filter_set	*s;

			while ((s = TAILQ_FIRST(yystack.l_mark[-2].v.filter_set_head)) != NULL) {
				TAILQ_REMOVE(yystack.l_mark[-2].v.filter_set_head, s, entry);
				r = get_rule(s->type);
				if (merge_filterset(&r->set, s) == -1)
					YYERROR;
			}
			free(yystack.l_mark[-2].v.filter_set_head);
		}
break;
case 119:
#line 1340 "parse.y"
	{
			if ((conf->flags & BGPD_FLAG_REFLECTOR) &&
			    conf->clusterid != 0) {
				yyerror("only one route reflector "
				    "cluster allowed");
				YYERROR;
			}
			conf->flags |= BGPD_FLAG_REFLECTOR;
			curpeer->conf.reflector_client = 1;
		}
break;
case 120:
#line 1350 "parse.y"
	{
			if (yystack.l_mark[0].v.addr.aid != AID_INET) {
				yyerror("route reflector cluster-id must be "
				    "an IPv4 address");
				YYERROR;
			}
			if ((conf->flags & BGPD_FLAG_REFLECTOR) &&
			    conf->clusterid != yystack.l_mark[0].v.addr.v4.s_addr) {
				yyerror("only one route reflector "
				    "cluster allowed");
				YYERROR;
			}
			conf->flags |= BGPD_FLAG_REFLECTOR;
			curpeer->conf.reflector_client = 1;
			conf->clusterid = yystack.l_mark[0].v.addr.v4.s_addr;
		}
break;
case 121:
#line 1366 "parse.y"
	{
			if (strlcpy(curpeer->conf.if_depend, yystack.l_mark[0].v.string,
			    sizeof(curpeer->conf.if_depend)) >=
			    sizeof(curpeer->conf.if_depend)) {
				yyerror("interface name \"%s\" too long: "
				    "max %zu", yystack.l_mark[0].v.string,
				    sizeof(curpeer->conf.if_depend) - 1);
				free(yystack.l_mark[0].v.string);
				YYERROR;
			}
			free(yystack.l_mark[0].v.string);
		}
break;
case 122:
#line 1378 "parse.y"
	{
			if (strlcpy(curpeer->conf.demote_group, yystack.l_mark[0].v.string,
			    sizeof(curpeer->conf.demote_group)) >=
			    sizeof(curpeer->conf.demote_group)) {
				yyerror("demote group name \"%s\" too long: "
				    "max %zu", yystack.l_mark[0].v.string,
				    sizeof(curpeer->conf.demote_group) - 1);
				free(yystack.l_mark[0].v.string);
				YYERROR;
			}
			free(yystack.l_mark[0].v.string);
			if (carp_demote_init(curpeer->conf.demote_group,
			    cmd_opts & BGPD_OPT_FORCE_DEMOTE) == -1) {
				yyerror("error initializing group \"%s\"",
				    curpeer->conf.demote_group);
				YYERROR;
			}
		}
break;
case 123:
#line 1396 "parse.y"
	{
			if (yystack.l_mark[-1].v.number)
				curpeer->conf.softreconfig_in = yystack.l_mark[0].v.number;
			else
				curpeer->conf.softreconfig_out = yystack.l_mark[0].v.number;
		}
break;
case 124:
#line 1402 "parse.y"
	{
			if (yystack.l_mark[0].v.number == 1)
				curpeer->conf.flags |= PEERFLAG_TRANS_AS;
			else
				curpeer->conf.flags &= ~PEERFLAG_TRANS_AS;
		}
break;
case 125:
#line 1408 "parse.y"
	{
			if (!strcmp(yystack.l_mark[0].v.string, "updates"))
				curpeer->conf.flags |= PEERFLAG_LOG_UPDATES;
			else if (!strcmp(yystack.l_mark[0].v.string, "no"))
				curpeer->conf.flags &= ~PEERFLAG_LOG_UPDATES;
			else {
				free(yystack.l_mark[0].v.string);
				YYERROR;
			}
			free(yystack.l_mark[0].v.string);
		}
break;
case 126:
#line 1421 "parse.y"
	{ yyval.v.number = 0; }
break;
case 127:
#line 1422 "parse.y"
	{
			if (yystack.l_mark[0].v.number < 1 || yystack.l_mark[0].v.number > USHRT_MAX) {
				yyerror("restart out of range. 1 to %u minutes",
				    USHRT_MAX);
				YYERROR;
			}
			yyval.v.number = yystack.l_mark[0].v.number;
		}
break;
case 128:
#line 1432 "parse.y"
	{ yyval.v.number = AFI_IPv4; }
break;
case 129:
#line 1433 "parse.y"
	{ yyval.v.number = AFI_IPv6; }
break;
case 130:
#line 1436 "parse.y"
	{ yyval.v.number = 1; }
break;
case 131:
#line 1437 "parse.y"
	{ yyval.v.number = 0; }
break;
case 132:
#line 1440 "parse.y"
	{ yyval.v.number = 1; }
break;
case 133:
#line 1441 "parse.y"
	{ yyval.v.number = 0; }
break;
case 134:
#line 1444 "parse.y"
	{
			bzero(&yyval.v.encspec, sizeof(yyval.v.encspec));
		}
break;
case 135:
#line 1447 "parse.y"
	{
			bzero(&yyval.v.encspec, sizeof(yyval.v.encspec));
			if (!strcmp(yystack.l_mark[-1].v.string, "3des") || !strcmp(yystack.l_mark[-1].v.string, "3des-cbc")) {
				yyval.v.encspec.enc_alg = SADB_EALG_3DESCBC;
				yyval.v.encspec.enc_key_len = 21; /* XXX verify */
			} else if (!strcmp(yystack.l_mark[-1].v.string, "aes") ||
			    !strcmp(yystack.l_mark[-1].v.string, "aes-128-cbc")) {
				yyval.v.encspec.enc_alg = SADB_X_EALG_AES;
				yyval.v.encspec.enc_key_len = 16;
			} else {
				yyerror("unknown enc algorithm \"%s\"", yystack.l_mark[-1].v.string);
				free(yystack.l_mark[-1].v.string);
				free(yystack.l_mark[0].v.string);
				YYERROR;
			}
			free(yystack.l_mark[-1].v.string);

			if (strlen(yystack.l_mark[0].v.string) / 2 != yyval.v.encspec.enc_key_len) {
				yyerror("enc key length wrong: should be %u "
				    "bytes, is %zu bytes",
				    yyval.v.encspec.enc_key_len * 2, strlen(yystack.l_mark[0].v.string));
				free(yystack.l_mark[0].v.string);
				YYERROR;
			}

			if (str2key(yystack.l_mark[0].v.string, yyval.v.encspec.enc_key, sizeof(yyval.v.encspec.enc_key)) == -1) {
				free(yystack.l_mark[0].v.string);
				YYERROR;
			}
			free(yystack.l_mark[0].v.string);
		}
break;
case 136:
#line 1481 "parse.y"
	{
			struct filter_rule	 r;

			bzero(&r, sizeof(r));
			r.action = yystack.l_mark[-6].v.u8;
			r.quick = yystack.l_mark[-5].v.u8;
			r.dir = yystack.l_mark[-3].v.u8;
			if (yystack.l_mark[-4].v.string) {
				if (r.dir != DIR_IN) {
					yyerror("rib only allowed on \"from\" "
					    "rules.");
					free(yystack.l_mark[-4].v.string);
					YYERROR;
				}
				if (!find_rib(yystack.l_mark[-4].v.string)) {
					yyerror("rib \"%s\" does not exist.",
					    yystack.l_mark[-4].v.string);
					free(yystack.l_mark[-4].v.string);
					YYERROR;
				}
				if (strlcpy(r.rib, yystack.l_mark[-4].v.string, sizeof(r.rib)) >=
				    sizeof(r.rib)) {
					yyerror("rib name \"%s\" too long: "
					    "max %zu", yystack.l_mark[-4].v.string, sizeof(r.rib) - 1);
					free(yystack.l_mark[-4].v.string);
					YYERROR;
				}
				free(yystack.l_mark[-4].v.string);
			}
			if (expand_rule(&r, yystack.l_mark[-2].v.filter_peers, &yystack.l_mark[-1].v.filter_match, yystack.l_mark[0].v.filter_set_head) == -1)
				YYERROR;
		}
break;
case 137:
#line 1515 "parse.y"
	{ yyval.v.u8 = ACTION_ALLOW; }
break;
case 138:
#line 1516 "parse.y"
	{ yyval.v.u8 = ACTION_DENY; }
break;
case 139:
#line 1517 "parse.y"
	{ yyval.v.u8 = ACTION_NONE; }
break;
case 140:
#line 1520 "parse.y"
	{ yyval.v.u8 = 0; }
break;
case 141:
#line 1521 "parse.y"
	{ yyval.v.u8 = 1; }
break;
case 142:
#line 1524 "parse.y"
	{ yyval.v.u8 = DIR_IN; }
break;
case 143:
#line 1525 "parse.y"
	{ yyval.v.u8 = DIR_OUT; }
break;
case 144:
#line 1528 "parse.y"
	{ yyval.v.string = NULL; }
break;
case 145:
#line 1529 "parse.y"
	{ yyval.v.string = yystack.l_mark[0].v.string; }
break;
case 147:
#line 1532 "parse.y"
	{ yyval.v.filter_peers = yystack.l_mark[-1].v.filter_peers; }
break;
case 148:
#line 1535 "parse.y"
	{ yyval.v.filter_peers = yystack.l_mark[0].v.filter_peers; }
break;
case 149:
#line 1536 "parse.y"
	{
			yystack.l_mark[0].v.filter_peers->next = yystack.l_mark[-2].v.filter_peers;
			yyval.v.filter_peers = yystack.l_mark[0].v.filter_peers;
		}
break;
case 150:
#line 1542 "parse.y"
	{
			if ((yyval.v.filter_peers = calloc(1, sizeof(struct filter_peers_l))) ==
			    NULL)
				fatal(NULL);
			yyval.v.filter_peers->p.peerid = yyval.v.filter_peers->p.groupid = 0;
			yyval.v.filter_peers->next = NULL;
		}
break;
case 151:
#line 1549 "parse.y"
	{
			struct peer *p;

			if ((yyval.v.filter_peers = calloc(1, sizeof(struct filter_peers_l))) ==
			    NULL)
				fatal(NULL);
			yyval.v.filter_peers->p.remote_as = yyval.v.filter_peers->p.groupid = yyval.v.filter_peers->p.peerid = 0;
			yyval.v.filter_peers->next = NULL;
			for (p = peer_l; p != NULL; p = p->next)
				if (!memcmp(&p->conf.remote_addr,
				    &yystack.l_mark[0].v.addr, sizeof(p->conf.remote_addr))) {
					yyval.v.filter_peers->p.peerid = p->conf.id;
					break;
				}
			if (yyval.v.filter_peers->p.peerid == 0) {
				yyerror("no such peer: %s", log_addr(&yystack.l_mark[0].v.addr));
				free(yyval.v.filter_peers);
				YYERROR;
			}
		}
break;
case 152:
#line 1569 "parse.y"
	{
			if ((yyval.v.filter_peers = calloc(1, sizeof(struct filter_peers_l))) ==
			    NULL)
				fatal(NULL);
			yyval.v.filter_peers->p.groupid = yyval.v.filter_peers->p.peerid = 0;
			yyval.v.filter_peers->p.remote_as = yystack.l_mark[0].v.number;
		}
break;
case 153:
#line 1576 "parse.y"
	{
			struct peer *p;

			if ((yyval.v.filter_peers = calloc(1, sizeof(struct filter_peers_l))) ==
			    NULL)
				fatal(NULL);
			yyval.v.filter_peers->p.remote_as = yyval.v.filter_peers->p.peerid = 0;
			yyval.v.filter_peers->next = NULL;
			for (p = peer_l; p != NULL; p = p->next)
				if (!strcmp(p->conf.group, yystack.l_mark[0].v.string)) {
					yyval.v.filter_peers->p.groupid = p->conf.groupid;
					break;
				}
			if (yyval.v.filter_peers->p.groupid == 0) {
				yyerror("no such group: \"%s\"", yystack.l_mark[0].v.string);
				free(yystack.l_mark[0].v.string);
				free(yyval.v.filter_peers);
				YYERROR;
			}
			free(yystack.l_mark[0].v.string);
		}
break;
case 154:
#line 1599 "parse.y"
	{
			if (yystack.l_mark[0].v.prefixlen.op == OP_NONE)
				yystack.l_mark[0].v.prefixlen.op = OP_GE;
			if ((yyval.v.filter_prefix = calloc(1, sizeof(struct filter_prefix_l))) ==
			    NULL)
				fatal(NULL);
			yyval.v.filter_prefix->p.addr.aid = AID_INET;
			if (merge_prefixspec(yyval.v.filter_prefix, &yystack.l_mark[0].v.prefixlen) == -1) {
				free(yyval.v.filter_prefix);
				YYERROR;
			}
		}
break;
case 155:
#line 1611 "parse.y"
	{
			if (yystack.l_mark[0].v.prefixlen.op == OP_NONE)
				yystack.l_mark[0].v.prefixlen.op = OP_GE;
			if ((yyval.v.filter_prefix = calloc(1, sizeof(struct filter_prefix_l))) ==
			    NULL)
				fatal(NULL);
			yyval.v.filter_prefix->p.addr.aid = AID_INET6;
			if (merge_prefixspec(yyval.v.filter_prefix, &yystack.l_mark[0].v.prefixlen) == -1) {
				free(yyval.v.filter_prefix);
				YYERROR;
			}
		}
break;
case 156:
#line 1623 "parse.y"
	{ yyval.v.filter_prefix = yystack.l_mark[0].v.filter_prefix; }
break;
case 157:
#line 1624 "parse.y"
	{ yyval.v.filter_prefix = yystack.l_mark[-1].v.filter_prefix; }
break;
case 158:
#line 1627 "parse.y"
	{ yyval.v.filter_prefix = yystack.l_mark[0].v.filter_prefix; }
break;
case 159:
#line 1628 "parse.y"
	{
			yystack.l_mark[0].v.filter_prefix->next = yystack.l_mark[-2].v.filter_prefix;
			yyval.v.filter_prefix = yystack.l_mark[0].v.filter_prefix;
		}
break;
case 160:
#line 1634 "parse.y"
	{
			if ((yyval.v.filter_prefix = calloc(1, sizeof(struct filter_prefix_l))) ==
			    NULL)
				fatal(NULL);
			memcpy(&yyval.v.filter_prefix->p.addr, &yystack.l_mark[-1].v.prefix.prefix,
			    sizeof(yyval.v.filter_prefix->p.addr));
			yyval.v.filter_prefix->p.len = yystack.l_mark[-1].v.prefix.len;

			if (merge_prefixspec(yyval.v.filter_prefix, &yystack.l_mark[0].v.prefixlen) == -1) {
				free(yyval.v.filter_prefix);
				YYERROR;
			}
		}
break;
case 162:
#line 1650 "parse.y"
	{ yyval.v.filter_as = yystack.l_mark[-1].v.filter_as; }
break;
case 164:
#line 1654 "parse.y"
	{
			struct filter_as_l	*a;

			/* merge, both can be lists */
			for (a = yystack.l_mark[-2].v.filter_as; a != NULL && a->next != NULL; a = a->next)
				;	/* nothing */
			if (a != NULL)
				a->next = yystack.l_mark[0].v.filter_as;
			yyval.v.filter_as = yystack.l_mark[-2].v.filter_as;
		}
break;
case 165:
#line 1666 "parse.y"
	{
			yyval.v.filter_as = yystack.l_mark[0].v.filter_as;
			yyval.v.filter_as->a.type = yystack.l_mark[-1].v.u8;
		}
break;
case 166:
#line 1670 "parse.y"
	{
			struct filter_as_l	*a;

			yyval.v.filter_as = yystack.l_mark[-1].v.filter_as;
			for (a = yyval.v.filter_as; a != NULL; a = a->next)
				a->a.type = yystack.l_mark[-3].v.u8;
		}
break;
case 168:
#line 1680 "parse.y"
	{ yyval.v.filter_as = yystack.l_mark[-1].v.filter_as; }
break;
case 169:
#line 1682 "parse.y"
	{
			struct filter_as_l	*a;

			/* merge, both can be lists */
			for (a = yystack.l_mark[-2].v.filter_as; a != NULL && a->next != NULL; a = a->next)
				;	/* nothing */
			if (a != NULL)
				a->next = yystack.l_mark[0].v.filter_as;
			yyval.v.filter_as = yystack.l_mark[-2].v.filter_as;
		}
break;
case 171:
#line 1695 "parse.y"
	{
			yystack.l_mark[0].v.filter_as->next = yystack.l_mark[-2].v.filter_as;
			yyval.v.filter_as = yystack.l_mark[0].v.filter_as;
		}
break;
case 172:
#line 1701 "parse.y"
	{
			if ((yyval.v.filter_as = calloc(1, sizeof(struct filter_as_l))) ==
			    NULL)
				fatal(NULL);
			yyval.v.filter_as->a.as = yystack.l_mark[0].v.number;
			yyval.v.filter_as->a.op = OP_EQ;
		}
break;
case 173:
#line 1708 "parse.y"
	{
			if ((yyval.v.filter_as = calloc(1, sizeof(struct filter_as_l))) ==
			    NULL)
				fatal(NULL);
			yyval.v.filter_as->a.flags = AS_FLAG_NEIGHBORAS;
		}
break;
case 174:
#line 1714 "parse.y"
	{
			if ((yyval.v.filter_as = calloc(1, sizeof(struct filter_as_l))) ==
			    NULL)
				fatal(NULL);
			yyval.v.filter_as->a.op = yystack.l_mark[-1].v.u8;
			yyval.v.filter_as->a.as = yystack.l_mark[0].v.number;
		}
break;
case 175:
#line 1721 "parse.y"
	{
			if ((yyval.v.filter_as = calloc(1, sizeof(struct filter_as_l))) ==
			    NULL)
				fatal(NULL);
			if (yystack.l_mark[-2].v.number >= yystack.l_mark[0].v.number) {
				yyerror("start AS is bigger than end");
				YYERROR;
			}
			yyval.v.filter_as->a.op = yystack.l_mark[-1].v.u8;
			yyval.v.filter_as->a.as_min = yystack.l_mark[-2].v.number;
			yyval.v.filter_as->a.as_max = yystack.l_mark[0].v.number;
		}
break;
case 176:
#line 1735 "parse.y"
	{
			bzero(&yyval.v.filter_match, sizeof(yyval.v.filter_match));
			yyval.v.filter_match.m.community.as = COMMUNITY_UNSET;
			yyval.v.filter_match.m.large_community.as = COMMUNITY_UNSET;
		}
break;
case 177:
#line 1740 "parse.y"
	{
			bzero(&fmopts, sizeof(fmopts));
			fmopts.m.community.as = COMMUNITY_UNSET;
			fmopts.m.large_community.as = COMMUNITY_UNSET;
		}
break;
case 178:
#line 1745 "parse.y"
	{
			memcpy(&yyval.v.filter_match, &fmopts, sizeof(yyval.v.filter_match));
		}
break;
case 181:
#line 1754 "parse.y"
	{
			if (fmopts.prefix_l != NULL) {
				yyerror("\"prefix\" already specified");
				YYERROR;
			}
			fmopts.prefix_l = yystack.l_mark[0].v.filter_prefix;
		}
break;
case 182:
#line 1761 "parse.y"
	{
			if (fmopts.as_l != NULL) {
				yyerror("AS filters already specified");
				YYERROR;
			}
			fmopts.as_l = yystack.l_mark[0].v.filter_as;
		}
break;
case 183:
#line 1768 "parse.y"
	{
			if (fmopts.m.aslen.type != ASLEN_NONE) {
				yyerror("AS length filters already specified");
				YYERROR;
			}
			if (yystack.l_mark[0].v.number < 0 || yystack.l_mark[0].v.number > UINT_MAX) {
				yyerror("bad max-as-len %lld", yystack.l_mark[0].v.number);
				YYERROR;
			}
			fmopts.m.aslen.type = ASLEN_MAX;
			fmopts.m.aslen.aslen = yystack.l_mark[0].v.number;
		}
break;
case 184:
#line 1780 "parse.y"
	{
			if (fmopts.m.aslen.type != ASLEN_NONE) {
				yyerror("AS length filters already specified");
				YYERROR;
			}
			if (yystack.l_mark[0].v.number < 0 || yystack.l_mark[0].v.number > UINT_MAX) {
				yyerror("bad max-as-seq %lld", yystack.l_mark[0].v.number);
				YYERROR;
			}
			fmopts.m.aslen.type = ASLEN_SEQ;
			fmopts.m.aslen.aslen = yystack.l_mark[0].v.number;
		}
break;
case 185:
#line 1792 "parse.y"
	{
			if (fmopts.m.community.as != COMMUNITY_UNSET) {
				yyerror("\"community\" already specified");
				free(yystack.l_mark[0].v.string);
				YYERROR;
			}
			if (parsecommunity(&fmopts.m.community, yystack.l_mark[0].v.string) == -1) {
				free(yystack.l_mark[0].v.string);
				YYERROR;
			}
			free(yystack.l_mark[0].v.string);
		}
break;
case 186:
#line 1804 "parse.y"
	{
			if (fmopts.m.large_community.as != COMMUNITY_UNSET) {
				yyerror("\"large-community\" already specified");
				free(yystack.l_mark[0].v.string);
				YYERROR;
			}
			if (parselargecommunity(&fmopts.m.large_community, yystack.l_mark[0].v.string) == -1) {
				free(yystack.l_mark[0].v.string);
				YYERROR;
			}
			free(yystack.l_mark[0].v.string);
		}
break;
case 187:
#line 1816 "parse.y"
	{
			if (fmopts.m.ext_community.flags &
			    EXT_COMMUNITY_FLAG_VALID) {
				yyerror("\"ext-community\" already specified");
				free(yystack.l_mark[-1].v.string);
				free(yystack.l_mark[0].v.string);
				YYERROR;
			}

			if (parseextcommunity(&fmopts.m.ext_community,
			    yystack.l_mark[-1].v.string, yystack.l_mark[0].v.string) == -1) {
				free(yystack.l_mark[-1].v.string);
				free(yystack.l_mark[0].v.string);
				YYERROR;
			}
			free(yystack.l_mark[-1].v.string);
			free(yystack.l_mark[0].v.string);
		}
break;
case 188:
#line 1834 "parse.y"
	{
			if (fmopts.m.nexthop.flags) {
				yyerror("nexthop already specified");
				YYERROR;
			}
			fmopts.m.nexthop.addr = yystack.l_mark[0].v.addr;
			fmopts.m.nexthop.flags = FILTER_NEXTHOP_ADDR;
		}
break;
case 189:
#line 1842 "parse.y"
	{
			if (fmopts.m.nexthop.flags) {
				yyerror("nexthop already specified");
				YYERROR;
			}
			fmopts.m.nexthop.flags = FILTER_NEXTHOP_NEIGHBOR;
		}
break;
case 190:
#line 1851 "parse.y"
	{ bzero(&yyval.v.prefixlen, sizeof(yyval.v.prefixlen)); }
break;
case 191:
#line 1852 "parse.y"
	{
			bzero(&yyval.v.prefixlen, sizeof(yyval.v.prefixlen));
			yyval.v.prefixlen.op = OP_GE;
			yyval.v.prefixlen.len_min = -1;
		}
break;
case 192:
#line 1857 "parse.y"
	{
			bzero(&yyval.v.prefixlen, sizeof(yyval.v.prefixlen));
			if (yystack.l_mark[0].v.number < 0 || yystack.l_mark[0].v.number > 128) {
				yyerror("prefixlen must be >= 0 and <= 128");
				YYERROR;
			}
			if (yystack.l_mark[-1].v.u8 == OP_GT && yystack.l_mark[0].v.number == 0) {
				yyerror("prefixlen must be > 0");
				YYERROR;
			}
			yyval.v.prefixlen.op = yystack.l_mark[-1].v.u8;
			yyval.v.prefixlen.len_min = yystack.l_mark[0].v.number;
		}
break;
case 193:
#line 1870 "parse.y"
	{
			bzero(&yyval.v.prefixlen, sizeof(yyval.v.prefixlen));
			if (yystack.l_mark[-2].v.number < 0 || yystack.l_mark[-2].v.number > 128 || yystack.l_mark[0].v.number < 0 || yystack.l_mark[0].v.number > 128) {
				yyerror("prefixlen must be < 128");
				YYERROR;
			}
			if (yystack.l_mark[-2].v.number >= yystack.l_mark[0].v.number) {
				yyerror("start prefixlen is bigger than end");
				YYERROR;
			}
			yyval.v.prefixlen.op = yystack.l_mark[-1].v.u8;
			yyval.v.prefixlen.len_min = yystack.l_mark[-2].v.number;
			yyval.v.prefixlen.len_max = yystack.l_mark[0].v.number;
		}
break;
case 194:
#line 1886 "parse.y"
	{ yyval.v.u8 = AS_ALL; }
break;
case 195:
#line 1887 "parse.y"
	{ yyval.v.u8 = AS_SOURCE; }
break;
case 196:
#line 1888 "parse.y"
	{ yyval.v.u8 = AS_TRANSIT; }
break;
case 197:
#line 1889 "parse.y"
	{ yyval.v.u8 = AS_PEER; }
break;
case 198:
#line 1892 "parse.y"
	{ yyval.v.filter_set_head = NULL; }
break;
case 199:
#line 1893 "parse.y"
	{
			if ((yyval.v.filter_set_head = calloc(1, sizeof(struct filter_set_head))) ==
			    NULL)
				fatal(NULL);
			TAILQ_INIT(yyval.v.filter_set_head);
			TAILQ_INSERT_TAIL(yyval.v.filter_set_head, yystack.l_mark[0].v.filter_set, entry);
		}
break;
case 200:
#line 1900 "parse.y"
	{ yyval.v.filter_set_head = yystack.l_mark[-2].v.filter_set_head; }
break;
case 201:
#line 1903 "parse.y"
	{
			yyval.v.filter_set_head = yystack.l_mark[-2].v.filter_set_head;
			if (merge_filterset(yyval.v.filter_set_head, yystack.l_mark[0].v.filter_set) == 1)
				YYERROR;
		}
break;
case 202:
#line 1908 "parse.y"
	{
			if ((yyval.v.filter_set_head = calloc(1, sizeof(struct filter_set_head))) ==
			    NULL)
				fatal(NULL);
			TAILQ_INIT(yyval.v.filter_set_head);
			TAILQ_INSERT_TAIL(yyval.v.filter_set_head, yystack.l_mark[0].v.filter_set, entry);
		}
break;
case 203:
#line 1917 "parse.y"
	{ yyval.v.u8 = 0; }
break;
case 204:
#line 1918 "parse.y"
	{ yyval.v.u8 = 1; }
break;
case 205:
#line 1921 "parse.y"
	{
			if (yystack.l_mark[0].v.number < -INT_MAX || yystack.l_mark[0].v.number > UINT_MAX) {
				yyerror("bad localpref %lld", yystack.l_mark[0].v.number);
				YYERROR;
			}
			if ((yyval.v.filter_set = calloc(1, sizeof(struct filter_set))) == NULL)
				fatal(NULL);
			if (yystack.l_mark[0].v.number > 0) {
				yyval.v.filter_set->type = ACTION_SET_LOCALPREF;
				yyval.v.filter_set->action.metric = yystack.l_mark[0].v.number;
			} else {
				yyval.v.filter_set->type = ACTION_SET_RELATIVE_LOCALPREF;
				yyval.v.filter_set->action.relative = yystack.l_mark[0].v.number;
			}
		}
break;
case 206:
#line 1936 "parse.y"
	{
			if (yystack.l_mark[0].v.number < 0 || yystack.l_mark[0].v.number > INT_MAX) {
				yyerror("bad localpref +%lld", yystack.l_mark[0].v.number);
				YYERROR;
			}
			if ((yyval.v.filter_set = calloc(1, sizeof(struct filter_set))) == NULL)
				fatal(NULL);
			yyval.v.filter_set->type = ACTION_SET_RELATIVE_LOCALPREF;
			yyval.v.filter_set->action.relative = yystack.l_mark[0].v.number;
		}
break;
case 207:
#line 1946 "parse.y"
	{
			if (yystack.l_mark[0].v.number < 0 || yystack.l_mark[0].v.number > INT_MAX) {
				yyerror("bad localpref -%lld", yystack.l_mark[0].v.number);
				YYERROR;
			}
			if ((yyval.v.filter_set = calloc(1, sizeof(struct filter_set))) == NULL)
				fatal(NULL);
			yyval.v.filter_set->type = ACTION_SET_RELATIVE_LOCALPREF;
			yyval.v.filter_set->action.relative = -yystack.l_mark[0].v.number;
		}
break;
case 208:
#line 1956 "parse.y"
	{
			if (yystack.l_mark[0].v.number < -INT_MAX || yystack.l_mark[0].v.number > UINT_MAX) {
				yyerror("bad metric %lld", yystack.l_mark[0].v.number);
				YYERROR;
			}
			if ((yyval.v.filter_set = calloc(1, sizeof(struct filter_set))) == NULL)
				fatal(NULL);
			if (yystack.l_mark[0].v.number >= 0) {
				yyval.v.filter_set->type = ACTION_SET_MED;
				yyval.v.filter_set->action.metric = yystack.l_mark[0].v.number;
			} else {
				yyval.v.filter_set->type = ACTION_SET_RELATIVE_MED;
				yyval.v.filter_set->action.relative = yystack.l_mark[0].v.number;
			}
		}
break;
case 209:
#line 1971 "parse.y"
	{
			if (yystack.l_mark[0].v.number < 0 || yystack.l_mark[0].v.number > INT_MAX) {
				yyerror("bad metric +%lld", yystack.l_mark[0].v.number);
				YYERROR;
			}
			if ((yyval.v.filter_set = calloc(1, sizeof(struct filter_set))) == NULL)
				fatal(NULL);
			yyval.v.filter_set->type = ACTION_SET_RELATIVE_MED;
			yyval.v.filter_set->action.relative = yystack.l_mark[0].v.number;
		}
break;
case 210:
#line 1981 "parse.y"
	{
			if (yystack.l_mark[0].v.number < 0 || yystack.l_mark[0].v.number > INT_MAX) {
				yyerror("bad metric -%lld", yystack.l_mark[0].v.number);
				YYERROR;
			}
			if ((yyval.v.filter_set = calloc(1, sizeof(struct filter_set))) == NULL)
				fatal(NULL);
			yyval.v.filter_set->type = ACTION_SET_RELATIVE_MED;
			yyval.v.filter_set->action.relative = -yystack.l_mark[0].v.number;
		}
break;
case 211:
#line 1991 "parse.y"
	{	/* alias for MED */
			if (yystack.l_mark[0].v.number < -INT_MAX || yystack.l_mark[0].v.number > UINT_MAX) {
				yyerror("bad metric %lld", yystack.l_mark[0].v.number);
				YYERROR;
			}
			if ((yyval.v.filter_set = calloc(1, sizeof(struct filter_set))) == NULL)
				fatal(NULL);
			if (yystack.l_mark[0].v.number >= 0) {
				yyval.v.filter_set->type = ACTION_SET_MED;
				yyval.v.filter_set->action.metric = yystack.l_mark[0].v.number;
			} else {
				yyval.v.filter_set->type = ACTION_SET_RELATIVE_MED;
				yyval.v.filter_set->action.relative = yystack.l_mark[0].v.number;
			}
		}
break;
case 212:
#line 2006 "parse.y"
	{
			if (yystack.l_mark[0].v.number < 0 || yystack.l_mark[0].v.number > INT_MAX) {
				yyerror("bad metric +%lld", yystack.l_mark[0].v.number);
				YYERROR;
			}
			if ((yyval.v.filter_set = calloc(1, sizeof(struct filter_set))) == NULL)
				fatal(NULL);
			yyval.v.filter_set->type = ACTION_SET_RELATIVE_MED;
			yyval.v.filter_set->action.metric = yystack.l_mark[0].v.number;
		}
break;
case 213:
#line 2016 "parse.y"
	{
			if (yystack.l_mark[0].v.number < 0 || yystack.l_mark[0].v.number > INT_MAX) {
				yyerror("bad metric -%lld", yystack.l_mark[0].v.number);
				YYERROR;
			}
			if ((yyval.v.filter_set = calloc(1, sizeof(struct filter_set))) == NULL)
				fatal(NULL);
			yyval.v.filter_set->type = ACTION_SET_RELATIVE_MED;
			yyval.v.filter_set->action.relative = -yystack.l_mark[0].v.number;
		}
break;
case 214:
#line 2026 "parse.y"
	{
			if (yystack.l_mark[0].v.number < -INT_MAX || yystack.l_mark[0].v.number > UINT_MAX) {
				yyerror("bad weight %lld", yystack.l_mark[0].v.number);
				YYERROR;
			}
			if ((yyval.v.filter_set = calloc(1, sizeof(struct filter_set))) == NULL)
				fatal(NULL);
			if (yystack.l_mark[0].v.number > 0) {
				yyval.v.filter_set->type = ACTION_SET_WEIGHT;
				yyval.v.filter_set->action.metric = yystack.l_mark[0].v.number;
			} else {
				yyval.v.filter_set->type = ACTION_SET_RELATIVE_WEIGHT;
				yyval.v.filter_set->action.relative = yystack.l_mark[0].v.number;
			}
		}
break;
case 215:
#line 2041 "parse.y"
	{
			if (yystack.l_mark[0].v.number < 0 || yystack.l_mark[0].v.number > INT_MAX) {
				yyerror("bad weight +%lld", yystack.l_mark[0].v.number);
				YYERROR;
			}
			if ((yyval.v.filter_set = calloc(1, sizeof(struct filter_set))) == NULL)
				fatal(NULL);
			yyval.v.filter_set->type = ACTION_SET_RELATIVE_WEIGHT;
			yyval.v.filter_set->action.relative = yystack.l_mark[0].v.number;
		}
break;
case 216:
#line 2051 "parse.y"
	{
			if (yystack.l_mark[0].v.number < 0 || yystack.l_mark[0].v.number > INT_MAX) {
				yyerror("bad weight -%lld", yystack.l_mark[0].v.number);
				YYERROR;
			}
			if ((yyval.v.filter_set = calloc(1, sizeof(struct filter_set))) == NULL)
				fatal(NULL);
			yyval.v.filter_set->type = ACTION_SET_RELATIVE_WEIGHT;
			yyval.v.filter_set->action.relative = -yystack.l_mark[0].v.number;
		}
break;
case 217:
#line 2061 "parse.y"
	{
			if ((yyval.v.filter_set = calloc(1, sizeof(struct filter_set))) == NULL)
				fatal(NULL);
			yyval.v.filter_set->type = ACTION_SET_NEXTHOP;
			memcpy(&yyval.v.filter_set->action.nexthop, &yystack.l_mark[0].v.addr,
			    sizeof(yyval.v.filter_set->action.nexthop));
		}
break;
case 218:
#line 2068 "parse.y"
	{
			if ((yyval.v.filter_set = calloc(1, sizeof(struct filter_set))) == NULL)
				fatal(NULL);
			yyval.v.filter_set->type = ACTION_SET_NEXTHOP_BLACKHOLE;
		}
break;
case 219:
#line 2073 "parse.y"
	{
			if ((yyval.v.filter_set = calloc(1, sizeof(struct filter_set))) == NULL)
				fatal(NULL);
			yyval.v.filter_set->type = ACTION_SET_NEXTHOP_REJECT;
		}
break;
case 220:
#line 2078 "parse.y"
	{
			if ((yyval.v.filter_set = calloc(1, sizeof(struct filter_set))) == NULL)
				fatal(NULL);
			yyval.v.filter_set->type = ACTION_SET_NEXTHOP_NOMODIFY;
		}
break;
case 221:
#line 2083 "parse.y"
	{
			if ((yyval.v.filter_set = calloc(1, sizeof(struct filter_set))) == NULL)
				fatal(NULL);
			yyval.v.filter_set->type = ACTION_SET_NEXTHOP_SELF;
		}
break;
case 222:
#line 2088 "parse.y"
	{
			if (yystack.l_mark[0].v.number < 0 || yystack.l_mark[0].v.number > 128) {
				yyerror("bad number of prepends");
				YYERROR;
			}
			if ((yyval.v.filter_set = calloc(1, sizeof(struct filter_set))) == NULL)
				fatal(NULL);
			yyval.v.filter_set->type = ACTION_SET_PREPEND_SELF;
			yyval.v.filter_set->action.prepend = yystack.l_mark[0].v.number;
		}
break;
case 223:
#line 2098 "parse.y"
	{
			if (yystack.l_mark[0].v.number < 0 || yystack.l_mark[0].v.number > 128) {
				yyerror("bad number of prepends");
				YYERROR;
			}
			if ((yyval.v.filter_set = calloc(1, sizeof(struct filter_set))) == NULL)
				fatal(NULL);
			yyval.v.filter_set->type = ACTION_SET_PREPEND_PEER;
			yyval.v.filter_set->action.prepend = yystack.l_mark[0].v.number;
		}
break;
case 224:
#line 2108 "parse.y"
	{
			if ((yyval.v.filter_set = calloc(1, sizeof(struct filter_set))) == NULL)
				fatal(NULL);
			yyval.v.filter_set->type = ACTION_PFTABLE;
			if (!(cmd_opts & BGPD_OPT_NOACTION) &&
			    pftable_exists(yystack.l_mark[0].v.string) != 0) {
				yyerror("pftable name does not exist");
				free(yystack.l_mark[0].v.string);
				free(yyval.v.filter_set);
				YYERROR;
			}
			if (strlcpy(yyval.v.filter_set->action.pftable, yystack.l_mark[0].v.string,
			    sizeof(yyval.v.filter_set->action.pftable)) >=
			    sizeof(yyval.v.filter_set->action.pftable)) {
				yyerror("pftable name too long");
				free(yystack.l_mark[0].v.string);
				free(yyval.v.filter_set);
				YYERROR;
			}
			if (pftable_add(yystack.l_mark[0].v.string) != 0) {
				yyerror("Couldn't register table");
				free(yystack.l_mark[0].v.string);
				free(yyval.v.filter_set);
				YYERROR;
			}
			free(yystack.l_mark[0].v.string);
		}
break;
case 225:
#line 2135 "parse.y"
	{
			if ((yyval.v.filter_set = calloc(1, sizeof(struct filter_set))) == NULL)
				fatal(NULL);
			yyval.v.filter_set->type = ACTION_RTLABEL;
			if (strlcpy(yyval.v.filter_set->action.rtlabel, yystack.l_mark[0].v.string,
			    sizeof(yyval.v.filter_set->action.rtlabel)) >=
			    sizeof(yyval.v.filter_set->action.rtlabel)) {
				yyerror("rtlabel name too long");
				free(yystack.l_mark[0].v.string);
				free(yyval.v.filter_set);
				YYERROR;
			}
			free(yystack.l_mark[0].v.string);
		}
break;
case 226:
#line 2149 "parse.y"
	{
			if ((yyval.v.filter_set = calloc(1, sizeof(struct filter_set))) == NULL)
				fatal(NULL);
			if (yystack.l_mark[-1].v.u8)
				yyval.v.filter_set->type = ACTION_DEL_COMMUNITY;
			else
				yyval.v.filter_set->type = ACTION_SET_COMMUNITY;

			if (parsecommunity(&yyval.v.filter_set->action.community, yystack.l_mark[0].v.string) == -1) {
				free(yystack.l_mark[0].v.string);
				free(yyval.v.filter_set);
				YYERROR;
			}
			free(yystack.l_mark[0].v.string);
			/* Don't allow setting of any match */
			if (!yystack.l_mark[-1].v.u8 && (yyval.v.filter_set->action.community.as == COMMUNITY_ANY ||
			    yyval.v.filter_set->action.community.type == COMMUNITY_ANY)) {
				yyerror("'*' is not allowed in set community");
				free(yyval.v.filter_set);
				YYERROR;
			}
		}
break;
case 227:
#line 2171 "parse.y"
	{
			if ((yyval.v.filter_set = calloc(1, sizeof(struct filter_set))) == NULL)
				fatal(NULL);
			if (yystack.l_mark[-1].v.u8)
				yyval.v.filter_set->type = ACTION_DEL_LARGE_COMMUNITY;
			else
				yyval.v.filter_set->type = ACTION_SET_LARGE_COMMUNITY;

			if (parselargecommunity(&yyval.v.filter_set->action.large_community,
			    yystack.l_mark[0].v.string) == -1) {
				free(yystack.l_mark[0].v.string);
				free(yyval.v.filter_set);
				YYERROR;
			}
			free(yystack.l_mark[0].v.string);
			/* Don't allow setting of any match */
			if (!yystack.l_mark[-1].v.u8 &&
			    (yyval.v.filter_set->action.large_community.as == COMMUNITY_ANY ||
			    yyval.v.filter_set->action.large_community.ld1 == COMMUNITY_ANY ||
			    yyval.v.filter_set->action.large_community.ld2 == COMMUNITY_ANY)) {
				yyerror("'*' is not allowed in set community");
				free(yyval.v.filter_set);
				YYERROR;
			}
		}
break;
case 228:
#line 2196 "parse.y"
	{
			if ((yyval.v.filter_set = calloc(1, sizeof(struct filter_set))) == NULL)
				fatal(NULL);
			if (yystack.l_mark[-2].v.u8)
				yyval.v.filter_set->type = ACTION_DEL_EXT_COMMUNITY;
			else
				yyval.v.filter_set->type = ACTION_SET_EXT_COMMUNITY;

			if (parseextcommunity(&yyval.v.filter_set->action.ext_community,
			    yystack.l_mark[-1].v.string, yystack.l_mark[0].v.string) == -1) {
				free(yystack.l_mark[-1].v.string);
				free(yystack.l_mark[0].v.string);
				free(yyval.v.filter_set);
				YYERROR;
			}
			free(yystack.l_mark[-1].v.string);
			free(yystack.l_mark[0].v.string);
		}
break;
case 229:
#line 2214 "parse.y"
	{
			if ((yyval.v.filter_set = calloc(1, sizeof(struct filter_set))) == NULL)
				fatal(NULL);
			yyval.v.filter_set->type = ACTION_SET_ORIGIN;
			yyval.v.filter_set->action.origin = yystack.l_mark[0].v.number;
		}
break;
case 230:
#line 2222 "parse.y"
	{
			if (!strcmp(yystack.l_mark[0].v.string, "egp"))
				yyval.v.number = ORIGIN_EGP;
			else if (!strcmp(yystack.l_mark[0].v.string, "igp"))
				yyval.v.number = ORIGIN_IGP;
			else if (!strcmp(yystack.l_mark[0].v.string, "incomplete"))
				yyval.v.number = ORIGIN_INCOMPLETE;
			else {
				yyerror("unknown origin \"%s\"", yystack.l_mark[0].v.string);
				free(yystack.l_mark[0].v.string);
				YYERROR;
			}
			free(yystack.l_mark[0].v.string);
		}
break;
case 233:
#line 2241 "parse.y"
	{ yyval.v.u8 = OP_EQ; }
break;
case 234:
#line 2242 "parse.y"
	{ yyval.v.u8 = OP_NE; }
break;
case 235:
#line 2243 "parse.y"
	{ yyval.v.u8 = OP_LE; }
break;
case 236:
#line 2244 "parse.y"
	{ yyval.v.u8 = OP_LT; }
break;
case 237:
#line 2245 "parse.y"
	{ yyval.v.u8 = OP_GE; }
break;
case 238:
#line 2246 "parse.y"
	{ yyval.v.u8 = OP_GT; }
break;
case 239:
#line 2249 "parse.y"
	{ yyval.v.u8 = OP_EQ; }
break;
case 240:
#line 2250 "parse.y"
	{ yyval.v.u8 = OP_NE; }
break;
case 241:
#line 2253 "parse.y"
	{ yyval.v.u8 = OP_RANGE; }
break;
case 242:
#line 2254 "parse.y"
	{ yyval.v.u8 = OP_XRANGE; }
break;
#line 5228 "parse.c"
    }
    yystack.s_mark -= yym;
    yystate = *yystack.s_mark;
    yystack.l_mark -= yym;
    yym = yylhs[yyn];
    if (yystate == 0 && yym == 0)
    {
#if YYDEBUG
        if (yydebug)
            printf("%sdebug: after reduction, shifting from state 0 to\
 state %d\n", YYPREFIX, YYFINAL);
#endif
        yystate = YYFINAL;
        *++yystack.s_mark = YYFINAL;
        *++yystack.l_mark = yyval;
        if (yychar < 0)
        {
            if ((yychar = yylex()) < 0) yychar = 0;
#if YYDEBUG
            if (yydebug)
            {
                yys = 0;
                if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
                if (!yys) yys = "illegal-symbol";
                printf("%sdebug: state %d, reading %d (%s)\n",
                        YYPREFIX, YYFINAL, yychar, yys);
            }
#endif
        }
        if (yychar == 0) goto yyaccept;
        goto yyloop;
    }
    if ((yyn = yygindex[yym]) && (yyn += yystate) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yystate)
        yystate = yytable[yyn];
    else
        yystate = yydgoto[yym];
#if YYDEBUG
    if (yydebug)
        printf("%sdebug: after reduction, shifting from state %d \
to state %d\n", YYPREFIX, *yystack.s_mark, yystate);
#endif
    if (yystack.s_mark >= yystack.s_last && yygrowstack(&yystack))
    {
        goto yyoverflow;
    }
    *++yystack.s_mark = (short) yystate;
    *++yystack.l_mark = yyval;
    goto yyloop;

yyoverflow:
    yyerror("yacc stack overflow");

yyabort:
    yyfreestack(&yystack);
    return (1);

yyaccept:
    yyfreestack(&yystack);
    return (0);
}
