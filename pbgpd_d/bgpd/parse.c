#include <stdlib.h>
#include <string.h>
#define YYBYACC 1
#define YYMAJOR 1
#define YYMINOR 9
#define YYLEX yylex()
#define YYEMPTY -1
#define yyclearin (yychar=(YYEMPTY))
#define yyerrok (yyerrflag=0)
#define YYRECOVERING() (yyerrflag!=0)
#define YYPREFIX "yy"
#line 23 "parse.y"
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>

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
int		 yyerror(const char *, ...);
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
static struct mrt_head		*mrtconf;
static struct network_head	*netconf;
static struct peer		*peer_l, *peer_l_old;
static struct peer		*curpeer;
static struct peer		*curgroup;
static struct filter_head	*filter_l;
static struct filter_head	*peerfilter_l;
static struct filter_head	*groupfilter_l;
static struct filter_rule	*curpeer_filter[2];
static struct filter_rule	*curgroup_filter[2];
static struct listen_addrs	*listen_addrs;
static u_int32_t		 id;

struct filter_peers_l {
	struct filter_peers_l	*next;
	struct filter_peers	 p;
};

struct filter_prefix_l {
	struct filter_prefix_l	*next;
	struct filter_prefix	 p;
};

struct filter_as_l {
	struct filter_as_l	*next;
	struct filter_as	 a;
};

struct filter_match_l {
	struct filter_match	 m;
	struct filter_prefix_l	*prefix_l;
	struct filter_as_l	*as_l;
	sa_family_t		 af;
} fmopts;

struct peer	*alloc_peer(void);
struct peer	*new_peer(void);
struct peer	*new_group(void);
int		 add_mrtconfig(enum mrt_type, char *, time_t, struct peer *,
		    char *);
int		 add_rib(char *, u_int16_t);
int		 find_rib(char *);
int		 get_id(struct peer *);
int		 expand_rule(struct filter_rule *, struct filter_peers_l *,
		    struct filter_match_l *, struct filter_set_head *);
int		 str2key(char *, char *, size_t);
int		 neighbor_consistent(struct peer *);
int		 merge_filterset(struct filter_set_head *, struct filter_set *);
void		 copy_filterset(struct filter_set_head *,
		    struct filter_set_head *);
void		 move_filterset(struct filter_set_head *,
		    struct filter_set_head *);
struct filter_rule	*get_rule(enum action_types);

int		 getcommunity(char *);
int		 parsecommunity(char *, int *, int *);

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
		struct filter_prefixlen	 prefixlen;
		struct filter_set	*filter_set;
		struct filter_set_head	*filter_set_head;
		struct {
			struct bgpd_addr	prefix;
			u_int8_t		len;
		}			prefix;
		struct {
			u_int8_t		enc_alg;
			char			enc_key[IPSEC_ENC_KEY_LEN];
			u_int8_t		enc_key_len;
		}			encspec;
	} v;
	int lineno;
} YYSTYPE;

#line 150 "y.tab.c"
#define AS 257
#define ROUTERID 258
#define HOLDTIME 259
#define YMIN 260
#define LISTEN 261
#define ON 262
#define FIBUPDATE 263
#define RTABLE 264
#define RDE 265
#define RIB 266
#define EVALUATE 267
#define IGNORE 268
#define COMPARE 269
#define GROUP 270
#define NEIGHBOR 271
#define NETWORK 272
#define REMOTEAS 273
#define DESCR 274
#define LOCALADDR 275
#define MULTIHOP 276
#define PASSIVE 277
#define MAXPREFIX 278
#define RESTART 279
#define ANNOUNCE 280
#define DEMOTE 281
#define CONNECTRETRY 282
#define ENFORCE 283
#define NEIGHBORAS 284
#define CAPABILITIES 285
#define REFLECTOR 286
#define DEPEND 287
#define DOWN 288
#define SOFTRECONFIG 289
#define DUMP 290
#define IN 291
#define OUT 292
#define LOG 293
#define ROUTECOLL 294
#define TRANSPARENT 295
#define TCP 296
#define MD5SIG 297
#define PASSWORD 298
#define KEY 299
#define TTLSECURITY 300
#define ALLOW 301
#define DENY 302
#define MATCH 303
#define QUICK 304
#define FROM 305
#define TO 306
#define ANY 307
#define CONNECTED 308
#define STATIC 309
#define PREFIX 310
#define PREFIXLEN 311
#define SOURCEAS 312
#define TRANSITAS 313
#define PEERAS 314
#define COMMUNITY 315
#define DELETE 316
#define SET 317
#define LOCALPREF 318
#define MED 319
#define METRIC 320
#define NEXTHOP 321
#define REJECT 322
#define BLACKHOLE 323
#define NOMODIFY 324
#define SELF 325
#define PREPEND_SELF 326
#define PREPEND_PEER 327
#define PFTABLE 328
#define WEIGHT 329
#define RTLABEL 330
#define ERROR 331
#define INCLUDE 332
#define IPSEC 333
#define ESP 334
#define AH 335
#define SPI 336
#define IKE 337
#define IPV4 338
#define IPV6 339
#define QUALIFY 340
#define VIA 341
#define STRING 342
#define NUMBER 343
#define YYERRCODE 256
#if defined(__cplusplus) || defined(__STDC__)
const short yylhs[] =
#else
short yylhs[] =
#endif
	{                                        -1,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    1,
    2,    2,    9,    9,    4,   44,   42,   43,   43,   43,
   43,   43,   43,   43,   43,   43,   43,   43,   43,   43,
   43,   43,   43,   43,   43,   43,   43,   43,   43,   43,
   43,   43,   43,   48,    5,    5,   11,   12,   12,   13,
   13,   49,   49,   50,    3,    3,   51,   53,   45,   55,
   46,   54,   54,   56,   56,   56,   52,   52,   58,   58,
   59,   59,   57,   57,   57,   57,   57,   57,   57,   57,
   57,   57,   57,   57,   57,   57,   57,   57,   57,   57,
   57,   57,   57,   57,   57,   57,   57,   57,   57,   57,
   57,    8,    8,    7,    7,    6,    6,   41,   41,   47,
   14,   14,   14,   15,   15,   16,   16,   10,   10,   20,
   20,   19,   19,   18,   18,   18,   36,   36,   37,   37,
   37,   35,   35,   34,   26,   26,   28,   28,   27,   27,
   29,   29,   29,   25,   25,   24,   23,   61,   23,   21,
   21,   22,   22,   22,   22,   22,   22,   30,   30,   40,
   40,   40,   40,   32,   32,   32,   33,   33,   17,   17,
   31,   31,   31,   31,   31,   31,   31,   31,   31,   31,
   31,   31,   31,   31,   31,   31,   31,   31,   31,   31,
   31,   31,   60,   60,   38,   38,   38,   38,   38,   38,
   39,   39,
};
#if defined(__cplusplus) || defined(__STDC__)
const short yylen[] =
#else
short yylen[] =
#endif
	{                                         2,
    0,    2,    3,    3,    3,    3,    3,    3,    3,    1,
    1,    1,    2,    1,    1,    3,    2,    2,    3,    2,
    2,    3,    3,    2,    2,    3,    5,    2,    2,    3,
    4,    4,    3,    3,    4,    6,    1,    3,    3,    4,
    4,    2,    2,    5,    1,    1,    1,    3,    3,    1,
    1,    2,    0,    2,    0,    1,    0,    0,    5,    0,
    8,    2,    1,    2,    2,    2,    4,    0,    2,    1,
    2,    2,    2,    2,    2,    2,    1,    1,    2,    2,
    3,    3,    3,    2,    2,    3,    3,    4,    4,    3,
    8,    2,    2,    7,    1,    1,    2,    3,    2,    3,
    2,    0,    2,    1,    1,    1,    1,    0,    2,    7,
    1,    1,    1,    0,    1,    1,    1,    0,    2,    1,
    3,    1,    3,    1,    1,    2,    2,    4,    1,    3,
    4,    1,    3,    1,    1,    3,    1,    3,    2,    4,
    1,    3,    4,    1,    3,    1,    0,    0,    2,    1,
    2,    1,    2,    1,    2,    1,    1,    2,    3,    1,
    1,    1,    1,    0,    2,    7,    3,    1,    0,    1,
    2,    3,    3,    2,    3,    3,    2,    3,    3,    2,
    3,    3,    2,    2,    2,    2,    2,    2,    2,    2,
    2,    3,    1,    0,    1,    2,    2,    1,    2,    1,
    1,    2,
};
#if defined(__cplusplus) || defined(__STDC__)
const short yydefred[] =
#else
short yydefred[] =
#endif
	{                                      1,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,  111,  112,  113,    0,
    0,    0,    2,    0,    0,    0,    0,    0,    0,    0,
   37,    0,    9,   11,   10,   12,    0,   47,   20,    0,
   21,    0,   15,   24,   42,    0,    0,    0,   14,    0,
    0,    0,  104,  105,    0,    0,    0,    0,   43,    0,
    0,   29,   25,   28,    0,   17,    0,  115,    0,    3,
    4,    5,    6,    7,    8,    0,   19,   22,   23,    0,
    0,   38,   39,   13,    0,    0,    0,   34,   33,    0,
    0,    0,    0,   30,    0,   45,   46,    0,    0,    0,
    0,    0,    0,    0,   50,   51,   58,    0,   40,   52,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  165,    0,   48,   49,   32,   31,    0,   56,   35,
    0,   41,  119,  116,  117,    0,    0,   27,   60,  170,
    0,  171,    0,    0,  174,    0,    0,  177,    0,    0,
  185,  184,  186,  187,  183,  188,  189,  190,  180,    0,
    0,  191,    0,    0,   44,    0,  124,    0,  125,  120,
    0,    0,   59,    0,  192,  172,  173,  175,  176,  178,
  179,  181,  182,    0,   36,  126,  122,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,   77,    0,
    0,    0,    0,    0,    0,   78,    0,    0,    0,    0,
    0,    0,    0,    0,   95,    0,   63,    0,  168,    0,
  121,  193,    0,  110,  160,    0,    0,  161,  162,  163,
    0,  156,  157,    0,    0,  150,  154,  135,  152,    0,
    0,    0,    0,   70,    0,   66,    0,   80,   79,   73,
    0,   75,   76,    0,    0,   84,   85,    0,   99,    0,
   97,    0,    0,    0,  101,    0,   92,   93,    0,  106,
  107,    0,   65,   61,   62,   64,    0,    0,  123,    0,
  134,  127,    0,  195,    0,    0,    0,  153,    0,  155,
  137,    0,  151,    0,  146,  139,   72,   71,   67,   69,
   54,   81,    0,   87,   83,   82,   86,   98,  100,    0,
    0,    0,   90,    0,  166,  167,    0,  132,    0,    0,
  201,    0,    0,  196,  197,  199,  158,  136,    0,    0,
  144,    0,    0,  103,    0,    0,    0,    0,    0,    0,
  128,  202,  159,  138,    0,    0,  140,    0,    0,    0,
  133,    0,  145,    0,    0,  131,  143,   94,    0,    0,
   91,  109,
};
#if defined(__cplusplus) || defined(__STDC__)
const short yydgoto[] =
#else
short yydgoto[] =
#endif
	{                                       1,
   36,  295,  130,   44,   99,  272,   57,  304,   50,  103,
  169,  281,  107,   24,   69,  136,  141,  170,  188,  171,
  235,  236,  189,  331,  332,  237,  238,  292,  333,  288,
  219,   88,  220,  318,  319,  239,  320,  289,  323,  240,
  361,   25,   26,   27,  214,   29,   30,  215,   86,  246,
   32,  173,  137,  216,  174,  217,  218,  243,  244,  278,
  190,
};
#if defined(__cplusplus) || defined(__STDC__)
const short yysindex[] =
#else
short yysindex[] =
#endif
	{                                      0,
  -10,   45, -240, -282, -226, -192, -250, -246, -224, -243,
 -146, -237, -215, -233, -250, -250,    0,    0,    0, -228,
 -216,   70,    0, -166,  134,  136,  142,  158,  174,  176,
    0,  -82,    0,    0,    0,    0, -173,    0,    0, -136,
    0, -282,    0,    0,    0, -152,  -60, -153,    0,   -9,
 -106, -106,    0,    0,  166,  173, -143, -106,    0, -120,
 -205,    0,    0,    0, -118,    0, -243,    0,  -42,    0,
    0,    0,    0,    0,    0, -193,    0,    0,    0, -250,
 -117,    0,    0,    0,  221,  105,    8,    0,    0, -107,
 -102, -106, -106,    0, -105,    0,    0,  -80,  -73,  -71,
  -69,  -67, -131,  166,    0,    0,    0,    3,    0,    0,
  221,  -38,  -40,  -39,  -36,  -90,  -66,  -64,  -56,  -23,
  -55,    0,  159,    0,    0,    0,    0,  -54,    0,    0,
  -80,    0,    0,    0,    0,  -92,  167,    0,    0,    0,
  -48,    0,  -62,  -46,    0,  -45,  -44,    0,  -43,  -41,
    0,    0,    0,    0,    0,    0,    0,    0,    0,  -37,
  -35,    0,  221,  -80,    0,  -32,    0, -213,    0,    0,
    0,  221,    0, -212,    0,    0,    0,    0,    0,    0,
    0,    0,    0,  132,    0,    0,    0,   -3, -106, -112,
  336,  279, -220,  -21, -240, -243, -282,  -19,    0,  -18,
 -178,  -12,   11, -282,   39,    0, -115,  -11, -250,   47,
 -250,    8, -154,  279,    0,  218,    0,  279,    0,   72,
    0,    0, -213,    0,    0, -113,  -25,    0,    0,    0,
    4,    0,    0, -159, -112,    0,    0,    0,    0, -104,
  279,  279,  266,    0,  221,    0,    7,    0,    0,    0,
  -69,    0,    0,   26, -250,    0,    0,    6,    0, -250,
    0,   10, -250, -115,    0, -116,    0,    0,  222,    0,
    0, -202,    0,    0,    0,    0,  171,  132,    0, -100,
    0,    0,   34,    0,  286,  290,  292,    0,   12,    0,
    0,   -1,    0,  -98,    0,    0,    0,    0,    0,    0,
    0,    0,   22,    0,    0,    0,    0,    0,    0, -243,
 -243,  221,    0,   31,    0,    0, -155,    0,  318,  243,
    0,  314,   32,    0,    0,    0,    0,    0, -159, -240,
    0,  318,  251,    0,  -69,  -69,  132,   37,    5, -155,
    0,    0,    0,    0,    9, -240,    0,   72,   40, -100,
    0,  -98,    0,  252,   46,    0,    0,    0,   48,   55,
    0,    0,};
#if defined(__cplusplus) || defined(__STDC__)
const short yyrindex[] =
#else
short yyrindex[] =
#endif
	{                                      0,
  118,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0, -186,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,  389,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,  283,
  397,  397,    0,    0,    0,    0,    0,  397,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0, -101,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,  404,
    0,    0,    0,    0,   83,    0,  283,    0,    0,    0,
    0,  397,  397,    0,    0,    0,    0,  407,    0,    0,
  408,    0,    0,   19,    0,    0,    0,    0,    0,    0,
  301,   77,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
  407,    0,    0,    0,    0,    0,  411,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,  160,  407,    0,    0,    0,    0,    0,    0,
    2,  371,    0,  118,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0, -203,  397,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,  418,    0,    0,    0,    0,    0,    0,
    0,  283,    0,    0,    0,  118,    0,    0,    0,   66,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,   -8,    0,    0,    0,    0,    0,
    0,    0,    0,    0,  149,    0,    0,    0,    0,    0,
  174,    0,    0,  421,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,   90,   91,    0,    0,    0,
    0, -156,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  160,    0,    0,    0,    0,    0,    0,  -77,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  -75,    0,    0,  430,  431,    0,    0, -124,    0,
    0,    0,    0,    0, -124,    0,    0,   66,    0,  317,
    0,  321,    0,    0,    0,    0,    0,    0,  433,    0,
    0,    0,};
#if defined(__cplusplus) || defined(__STDC__)
const short yygindex[] =
#else
short yygindex[] =
#endif
	{                                      0,
  417,   21,  -79,    1, -162,    0,  247,    0,  -53,    0,
   17,   35,    0,    0,    0,    0,    0, -110,    0,    0,
    0,  220,    0, -210,  126,    0, -201,    0,  111,    0,
  -61,  -20,  120, -199,  147,    0,  115,    0,    0,    0,
    0,    0,    0,    0,  466,    0,    0,  467,  -72,  -47,
    0,    0,    0,    0,    0,  253, -135,    0,  227, -160,
    0,
};
#define YYTABLESIZE 704
#if defined(__cplusplus) || defined(__STDC__)
const short yytable[] =
#else
short yytable[] =
#endif
	{                                      23,
   85,  149,  143,  146,  144,  147,  149,  285,  150,  280,
  234,  147,  110,  101,  123,   63,   64,   85,  294,  160,
   39,  161,  317,   37,  330,  122,  282,  223,   47,  296,
  168,   89,  291,   40,  286,  284,  287,   94,  139,  247,
  222,   46,  222,  192,  263,   58,  193,  129,  222,  141,
   60,  165,  222,  194,   33,  242,  166,  187,   79,   38,
  195,  196,  197,  198,  199,  200,  194,  201,  202,   42,
  203,  126,  127,  204,  205,  206,  207,  208,  321,  114,
  108,   85,  209,  210,  185,   96,   97,  211,   96,   97,
  184,   43,  105,  167,   47,  322,   45,  225,   49,  191,
  194,   34,   35,  194,  212,   59,  255,  242,   62,  314,
  106,   65,  279,   82,   83,  222,   41,   48,  114,  114,
  213,  221,  248,  328,  148,   66,   61,  344,   38,  350,
   67,  329,  155,  352,  313,  353,   98,   68,  194,  269,
  351,   47,  251,   70,  225,   71,  256,  277,  104,   56,
  268,   72,  228,  229,  230,  194,  194,  194,  340,   53,
   54,   51,   52,  257,   92,   93,  273,   73,  224,   35,
  276,  346,  301,  134,  135,   96,   97,  166,  340,  270,
  271,  310,  311,   74,  346,   75,   55,   56,   76,   80,
   53,   53,   54,  297,  298,   55,   56,  226,  227,  228,
  229,  230,  231,  118,  118,   53,   78,   53,   81,  265,
   87,  267,   90,  252,  167,  250,  316,  194,  194,   91,
  261,   95,  100,  102,  109,  232,  233,  111,   55,   56,
   85,  151,  152,  153,  154,  124,  128,   34,   35,  337,
  125,   55,   56,   34,   35,    2,    3,    4,    5,   38,
    6,   38,    7,    8,    9,  305,  335,  336,  148,   10,
  307,   11,  129,  309,  194,  194,  194,  194,  131,  138,
  132,   12,   84,   53,  133,  354,  156,  140,  157,   13,
  176,  163,   14,   15,   16,  158,  162,  164,  245,  172,
   17,   18,   19,  175,  260,  315,  177,  178,  179,  180,
  262,  181,  142,  145,  303,  182,  148,  183,  149,  186,
   20,  148,  148,  148,  148,  148,  148,  283,  147,  159,
  249,   21,  112,  253,  254,  113,  114,  115,  116,  259,
  264,   22,   84,  117,  118,  119,  120,  121,   53,  148,
  148,   53,  274,  266,  312,  290,  324,  306,   53,  302,
  325,  308,  326,   53,  327,   53,   53,   53,   53,   53,
   53,  222,   53,   53,  334,   53,  338,  341,   53,   53,
   53,   53,   53,  342,  343,  347,  358,   53,   53,  349,
  194,  355,   53,  194,  194,  194,  194,  359,   57,  360,
  299,  194,  194,  194,  194,  194,  362,   53,   18,   53,
   53,   53,   53,   53,   53,   53,  164,   53,   53,   53,
   53,   53,   53,   26,   53,   53,   55,   16,  169,   53,
   68,   53,   53,   53,   53,   53,   53,   96,   53,   53,
  102,   53,  198,  200,   53,   53,   53,   53,   53,   88,
   89,  130,  108,   53,   53,  142,  112,  258,   53,  113,
  114,  115,  116,   77,  293,  345,  348,  117,  118,  119,
  120,  121,  357,  339,  356,   53,   28,   31,  275,  300,
    0,    0,    0,  192,   53,    0,  193,   53,   53,   53,
   53,   53,    0,  194,    0,   53,   53,   53,   53,   53,
  195,  196,  197,  198,  199,  200,    0,  201,  202,    0,
  203,    0,    0,  204,  205,  206,  207,  208,    0,    0,
    0,    0,  209,  210,    0,    0,    0,  211,    0,    0,
    0,  241,    0,    0,  193,    0,    0,    0,    0,    0,
    0,  194,    0,    0,  212,    0,    0,    0,  195,  196,
  197,  198,  199,  200,    0,  201,  202,    0,  203,    0,
  213,  204,  205,  206,  207,  208,   53,    0,    0,   53,
  209,  210,    0,    0,    0,  211,   53,    0,    0,    0,
    0,   53,    0,   53,   53,   53,   53,   53,   53,    0,
   53,   53,  212,   53,    0,    0,   53,   53,   53,   53,
   53,  241,    0,    0,  193,   53,   53,    0,  213,    0,
   53,  194,    0,    0,    0,    0,    0,    0,  195,  196,
  197,  198,  199,  200,    0,  201,  202,   53,  203,    0,
    0,  204,  205,  206,  207,  208,   53,    0,    0,   53,
  209,  210,    0,   53,    0,  211,   53,    0,    0,    0,
    0,    0,    0,   53,   53,   53,   53,   53,   53,    0,
   53,   53,  212,   53,    0,    0,   53,   53,   53,   53,
   53,    0,    0,    0,    0,   53,   53,    0,  213,    0,
   53,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,   53,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,   53,
};
#if defined(__cplusplus) || defined(__STDC__)
const short yycheck[] =
#else
short yycheck[] =
#endif
	{                                      10,
   10,   10,   43,   43,   45,   45,   43,   33,   45,  123,
  123,   10,   85,   67,   87,   15,   16,   10,  123,   43,
    4,   45,  123,    3,  123,   87,  226,  188,   10,  240,
  123,   52,  234,  260,   60,   61,   62,   58,  111,  260,
   44,  266,   44,  256,  207,   11,  259,  125,   44,  125,
  266,  131,   44,  266,   10,  191,  270,  168,   42,  342,
  273,  274,  275,  276,  277,  278,  270,  280,  281,  262,
  283,   92,   93,  286,  287,  288,  289,  290,   45,  266,
   80,   10,  295,  296,  164,  291,  292,  300,  291,  292,
  163,  342,   76,  307,  319,   62,  343,  257,  342,  172,
  257,  342,  343,  307,  317,  343,  285,  243,  342,  272,
   76,  340,  223,  267,  268,   44,  343,  342,  305,  306,
  333,  125,  343,  125,  123,  342,  342,  329,  342,  125,
   61,  292,  116,  125,  337,  346,  342,  304,  342,  212,
  340,  123,  196,   10,  257,   10,  325,  220,  342,  343,
  212,   10,  312,  313,  314,  312,  313,  314,  319,  338,
  339,  308,  309,  342,  308,  309,  214,   10,  189,  343,
  218,  332,  245,  305,  306,  291,  292,  270,  339,  334,
  335,  298,  299,   10,  345,   10,  342,  343,  271,  342,
  125,  338,  339,  241,  242,  342,  343,  310,  311,  312,
  313,  314,  315,  305,  306,  123,  343,  125,  269,  209,
  317,  211,   47,  197,  307,  195,  278,  342,  343,   47,
  204,  342,  341,  266,  342,  338,  339,  123,  342,  343,
   10,  322,  323,  324,  325,  343,  342,  342,  343,  312,
  343,  342,  343,  342,  343,  256,  257,  258,  259,  342,
  261,  342,  263,  264,  265,  255,  310,  311,  257,  270,
  260,  272,  343,  263,  342,  343,  342,  343,  342,  267,
  342,  282,  342,  125,  342,  348,  343,  316,  343,  290,
  343,  123,  293,  294,  295,  342,  342,  342,   10,  123,
  301,  302,  303,  342,  284,  125,  343,  343,  343,  343,
  262,  343,  343,  343,  279,  343,  343,  343,  317,  342,
  321,  310,  311,  312,  313,  314,  315,  343,  317,  343,
  342,  332,  315,  343,  343,  318,  319,  320,  321,  342,
  342,  342,  342,  326,  327,  328,  329,  330,  256,  338,
  339,  259,  125,  297,  123,  342,   61,  342,  266,  343,
   61,  342,   61,  271,  343,  273,  274,  275,  276,  277,
  278,   44,  280,  281,  343,  283,  336,  125,  286,  287,
  288,  289,  290,   60,  343,  125,  125,  295,  296,  343,
  315,  342,  300,  318,  319,  320,  321,  342,  271,  342,
  125,  326,  327,  328,  329,  330,  342,  315,   10,  317,
  318,  319,  320,  321,  256,  123,   10,  259,  326,  327,
  328,  329,  330,   10,  266,  333,   10,   10,  342,  271,
   10,  273,  274,  275,  276,  277,  278,   10,  280,  281,
   10,  283,  343,  343,  286,  287,  288,  289,  290,   10,
   10,  125,   10,  295,  296,  125,  315,  201,  300,  318,
  319,  320,  321,   37,  235,  330,  337,  326,  327,  328,
  329,  330,  352,  317,  350,  317,    1,    1,  216,  243,
   -1,   -1,   -1,  256,  315,   -1,  259,  318,  319,  320,
  321,  333,   -1,  266,   -1,  326,  327,  328,  329,  330,
  273,  274,  275,  276,  277,  278,   -1,  280,  281,   -1,
  283,   -1,   -1,  286,  287,  288,  289,  290,   -1,   -1,
   -1,   -1,  295,  296,   -1,   -1,   -1,  300,   -1,   -1,
   -1,  256,   -1,   -1,  259,   -1,   -1,   -1,   -1,   -1,
   -1,  266,   -1,   -1,  317,   -1,   -1,   -1,  273,  274,
  275,  276,  277,  278,   -1,  280,  281,   -1,  283,   -1,
  333,  286,  287,  288,  289,  290,  256,   -1,   -1,  259,
  295,  296,   -1,   -1,   -1,  300,  266,   -1,   -1,   -1,
   -1,  271,   -1,  273,  274,  275,  276,  277,  278,   -1,
  280,  281,  317,  283,   -1,   -1,  286,  287,  288,  289,
  290,  256,   -1,   -1,  259,  295,  296,   -1,  333,   -1,
  300,  266,   -1,   -1,   -1,   -1,   -1,   -1,  273,  274,
  275,  276,  277,  278,   -1,  280,  281,  317,  283,   -1,
   -1,  286,  287,  288,  289,  290,  256,   -1,   -1,  259,
  295,  296,   -1,  333,   -1,  300,  266,   -1,   -1,   -1,
   -1,   -1,   -1,  273,  274,  275,  276,  277,  278,   -1,
  280,  281,  317,  283,   -1,   -1,  286,  287,  288,  289,
  290,   -1,   -1,   -1,   -1,  295,  296,   -1,  333,   -1,
  300,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,  317,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  333,
};
#define YYFINAL 1
#ifndef YYDEBUG
#define YYDEBUG 0
#endif
#define YYMAXTOKEN 343
#if YYDEBUG
#if defined(__cplusplus) || defined(__STDC__)
const char * const yyname[] =
#else
char *yyname[] =
#endif
	{
"end-of-file",0,0,0,0,0,0,0,0,0,"'\\n'",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,"'!'",0,0,0,0,0,0,0,0,0,"'+'","','","'-'",0,"'/'",0,0,0,0,0,0,0,0,0,0,0,0,
"'<'","'='","'>'",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"'{'",0,"'}'",0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,"AS","ROUTERID","HOLDTIME","YMIN","LISTEN","ON","FIBUPDATE",
"RTABLE","RDE","RIB","EVALUATE","IGNORE","COMPARE","GROUP","NEIGHBOR","NETWORK",
"REMOTEAS","DESCR","LOCALADDR","MULTIHOP","PASSIVE","MAXPREFIX","RESTART",
"ANNOUNCE","DEMOTE","CONNECTRETRY","ENFORCE","NEIGHBORAS","CAPABILITIES",
"REFLECTOR","DEPEND","DOWN","SOFTRECONFIG","DUMP","IN","OUT","LOG","ROUTECOLL",
"TRANSPARENT","TCP","MD5SIG","PASSWORD","KEY","TTLSECURITY","ALLOW","DENY",
"MATCH","QUICK","FROM","TO","ANY","CONNECTED","STATIC","PREFIX","PREFIXLEN",
"SOURCEAS","TRANSITAS","PEERAS","COMMUNITY","DELETE","SET","LOCALPREF","MED",
"METRIC","NEXTHOP","REJECT","BLACKHOLE","NOMODIFY","SELF","PREPEND_SELF",
"PREPEND_PEER","PFTABLE","WEIGHT","RTLABEL","ERROR","INCLUDE","IPSEC","ESP",
"AH","SPI","IKE","IPV4","IPV6","QUALIFY","VIA","STRING","NUMBER",
};
#if defined(__cplusplus) || defined(__STDC__)
const char * const yyrule[] =
#else
char *yyrule[] =
#endif
	{"$accept : grammar",
"grammar :",
"grammar : grammar '\\n'",
"grammar : grammar include '\\n'",
"grammar : grammar conf_main '\\n'",
"grammar : grammar varset '\\n'",
"grammar : grammar neighbor '\\n'",
"grammar : grammar group '\\n'",
"grammar : grammar filterrule '\\n'",
"grammar : grammar error '\\n'",
"asnumber : NUMBER",
"as4number : STRING",
"as4number : asnumber",
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
"conf_main : FIBUPDATE yesno",
"conf_main : ROUTECOLL yesno",
"conf_main : RDE RIB STRING",
"conf_main : RDE RIB STRING yesno EVALUATE",
"conf_main : TRANSPARENT yesno",
"conf_main : LOG STRING",
"conf_main : NETWORK prefix filter_set",
"conf_main : NETWORK family STATIC filter_set",
"conf_main : NETWORK family CONNECTED filter_set",
"conf_main : NETWORK STATIC filter_set",
"conf_main : NETWORK CONNECTED filter_set",
"conf_main : DUMP STRING STRING optnumber",
"conf_main : DUMP RIB STRING STRING STRING optnumber",
"conf_main : mrtdump",
"conf_main : RDE STRING EVALUATE",
"conf_main : RDE STRING IGNORE",
"conf_main : RDE MED COMPARE STRING",
"conf_main : NEXTHOP QUALIFY VIA STRING",
"conf_main : RTABLE NUMBER",
"conf_main : CONNECTRETRY NUMBER",
"mrtdump : DUMP STRING inout STRING optnumber",
"inout : IN",
"inout : OUT",
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
"$$2 :",
"neighbor : $$1 NEIGHBOR addrspec $$2 peeropts_h",
"$$3 :",
"group : GROUP string optnl '{' optnl $$3 groupopts_l '}'",
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
"peeroptsl : error nl",
"peeropts : REMOTEAS as4number",
"peeropts : DESCR string",
"peeropts : LOCALADDR address",
"peeropts : MULTIHOP NUMBER",
"peeropts : PASSIVE",
"peeropts : DOWN",
"peeropts : RIB STRING",
"peeropts : HOLDTIME NUMBER",
"peeropts : HOLDTIME YMIN NUMBER",
"peeropts : ANNOUNCE family STRING",
"peeropts : ANNOUNCE CAPABILITIES yesno",
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
"restart :",
"restart : RESTART NUMBER",
"family : IPV4",
"family : IPV6",
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
"filter_peer : GROUP STRING",
"filter_prefix_h : PREFIX filter_prefix",
"filter_prefix_h : PREFIX '{' filter_prefix_m '}'",
"filter_prefix_m : filter_prefix_l",
"filter_prefix_m : '{' filter_prefix_l '}'",
"filter_prefix_m : '{' filter_prefix_l '}' filter_prefix_m",
"filter_prefix_l : filter_prefix",
"filter_prefix_l : filter_prefix_l comma filter_prefix",
"filter_prefix : prefix",
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
"filter_as : as4number",
"filter_match_h :",
"$$4 :",
"filter_match_h : $$4 filter_match",
"filter_match : filter_elm",
"filter_match : filter_match filter_elm",
"filter_elm : filter_prefix_h",
"filter_elm : PREFIXLEN prefixlenop",
"filter_elm : filter_as_h",
"filter_elm : COMMUNITY STRING",
"filter_elm : IPV4",
"filter_elm : IPV6",
"prefixlenop : unaryop NUMBER",
"prefixlenop : NUMBER binaryop NUMBER",
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
"comma : ','",
"comma :",
"unaryop : '='",
"unaryop : '!' '='",
"unaryop : '<' '='",
"unaryop : '<'",
"unaryop : '>' '='",
"unaryop : '>'",
"binaryop : '-'",
"binaryop : '>' '<'",
};
#endif
#ifdef YYSTACKSIZE
#undef YYMAXDEPTH
#define YYMAXDEPTH YYSTACKSIZE
#else
#ifdef YYMAXDEPTH
#define YYSTACKSIZE YYMAXDEPTH
#else
#define YYSTACKSIZE 10000
#define YYMAXDEPTH 10000
#endif
#endif
#define YYINITSTACKSIZE 200
/* LINTUSED */
int yydebug;
int yynerrs;
int yyerrflag;
int yychar;
short *yyssp;
YYSTYPE *yyvsp;
YYSTYPE yyval;
YYSTYPE yylval;
short *yyss;
short *yysslim;
YYSTYPE *yyvs;
int yystacksize;
#line 1836 "parse.y"

struct keywords {
	const char	*k_name;
	int		 k_val;
};

int
yyerror(const char *fmt, ...)
{
	va_list		 ap;
	char		*nfmt;

	file->errors++;
	va_start(ap, fmt);
	if (asprintf(&nfmt, "%s:%d: %s", file->name, yylval.lineno, fmt) == -1)
		fatalx("yyerror asprintf");
	vlog(LOG_CRIT, nfmt, ap);
	va_end(ap);
	free(nfmt);
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
		{ "fib-update",		FIBUPDATE},
		{ "from",		FROM},
		{ "group",		GROUP},
		{ "holdtime",		HOLDTIME},
		{ "ignore",		IGNORE},
		{ "ike",		IKE},
		{ "in",			IN},
		{ "include",		INCLUDE},
		{ "inet",		IPV4},
		{ "inet6",		IPV6},
		{ "ipsec",		IPSEC},
		{ "key",		KEY},
		{ "listen",		LISTEN},
		{ "local-address",	LOCALADDR},
		{ "localpref",		LOCALPREF},
		{ "log",		LOG},
		{ "match",		MATCH},
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
		{ "rde",		RDE},
		{ "reject",		REJECT},
		{ "remote-as",		REMOTEAS},
		{ "restart",		RESTART},
		{ "rib",		RIB},
		{ "route-collector",	ROUTECOLL},
		{ "route-reflector",	REFLECTOR},
		{ "router-id",		ROUTERID},
		{ "rtable",		RTABLE},
		{ "rtlabel",		RTLABEL},
		{ "self",		SELF},
		{ "set",		SET},
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

char	*parsebuf;
int	 parseindex;
char	 pushback_buffer[MAXPUSHBACK];
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
	char	 buf[8096];
	char	*p, *val;
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
				*p++ = (char)c;
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
				else if (next == '\n')
					continue;
				else
					lungetc(next);
			} else if (c == quotec) {
				*p = '\0';
				break;
			}
			if (p + 1 >= buf + sizeof(buf) - 1) {
				yyerror("string too long");
				return (findeol());
			}
			*p++ = (char)c;
		}
		yylval.v.string = strdup(buf);
		if (yylval.v.string == NULL)
			fatal("yylex: strdup");
		return (STRING);
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
	if (st.st_mode & (S_IRWXG | S_IRWXO)) {
		log_warnx("%s: group/world readable/writeable", fname);
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
parse_config(char *filename, struct bgpd_config *xconf,
    struct mrt_head *xmconf, struct peer **xpeers, struct network_head *nc,
    struct filter_head *xfilter_l)
{
	struct sym		*sym, *next;
	struct peer		*p, *pnext;
	struct listen_addr	*la;
	struct network		*n;
	struct filter_rule	*r;
	int			 errors = 0;

	if ((conf = calloc(1, sizeof(struct bgpd_config))) == NULL)
		fatal(NULL);
	conf->opts = xconf->opts;

	if ((file = pushfile(filename, 1)) == NULL) {
		free(conf);
		return (-1);
	}
	topfile = file;

	if ((mrtconf = calloc(1, sizeof(struct mrt_head))) == NULL)
		fatal(NULL);
	if ((listen_addrs = calloc(1, sizeof(struct listen_addrs))) == NULL)
		fatal(NULL);
	if ((filter_l = calloc(1, sizeof(struct filter_head))) == NULL)
		fatal(NULL);
	if ((peerfilter_l = calloc(1, sizeof(struct filter_head))) == NULL)
		fatal(NULL);
	if ((groupfilter_l = calloc(1, sizeof(struct filter_head))) == NULL)
		fatal(NULL);
	LIST_INIT(mrtconf);
	TAILQ_INIT(listen_addrs);
	TAILQ_INIT(filter_l);
	TAILQ_INIT(peerfilter_l);
	TAILQ_INIT(groupfilter_l);

	peer_l = NULL;
	peer_l_old = *xpeers;
	curpeer = NULL;
	curgroup = NULL;
	id = 1;

	/* network list is always empty in the parent */
	netconf = nc;
	TAILQ_INIT(netconf);
	/* init the empty filter list for later */
	TAILQ_INIT(xfilter_l);

	add_rib("Adj-RIB-In", F_RIB_NOEVALUATE);
	add_rib("Loc-RIB", 0);

	yyparse();
	errors = file->errors;
	popfile();

	/* Free macros and check which have not been used. */
	for (sym = TAILQ_FIRST(&symhead); sym != NULL; sym = next) {
		next = TAILQ_NEXT(sym, entry);
		if ((conf->opts & BGPD_OPT_VERBOSE2) && !sym->used)
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
		/* XXX more leaks in this case */
		while ((la = TAILQ_FIRST(listen_addrs)) != NULL) {
			TAILQ_REMOVE(listen_addrs, la, entry);
			free(la);
		}
		free(listen_addrs);

		for (p = peer_l; p != NULL; p = pnext) {
			pnext = p->next;
			free(p);
		}

		while ((n = TAILQ_FIRST(netconf)) != NULL) {
			TAILQ_REMOVE(netconf, n, entry);
			free(n);
		}

		while ((r = TAILQ_FIRST(filter_l)) != NULL) {
			TAILQ_REMOVE(filter_l, r, entry);
			free(r);
		}

		while ((r = TAILQ_FIRST(peerfilter_l)) != NULL) {
			TAILQ_REMOVE(peerfilter_l, r, entry);
			free(r);
		}

		while ((r = TAILQ_FIRST(groupfilter_l)) != NULL) {
			TAILQ_REMOVE(groupfilter_l, r, entry);
			free(r);
		}
	} else {
		errors += merge_config(xconf, conf, peer_l, listen_addrs);
		errors += mrt_mergeconfig(xmconf, mrtconf);
		*xpeers = peer_l;

		for (p = peer_l_old; p != NULL; p = pnext) {
			pnext = p->next;
			free(p);
		}

		/*
		 * Move filter list and static group and peer filtersets
		 * together. Static group sets come first then peer sets
		 * last normal filter rules.
		 */
		while ((r = TAILQ_FIRST(groupfilter_l)) != NULL) {
			TAILQ_REMOVE(groupfilter_l, r, entry);
			TAILQ_INSERT_TAIL(xfilter_l, r, entry);
		}
		while ((r = TAILQ_FIRST(peerfilter_l)) != NULL) {
			TAILQ_REMOVE(peerfilter_l, r, entry);
			TAILQ_INSERT_TAIL(xfilter_l, r, entry);
		}
		while ((r = TAILQ_FIRST(filter_l)) != NULL) {
			TAILQ_REMOVE(filter_l, r, entry);
			TAILQ_INSERT_TAIL(xfilter_l, r, entry);
		}
	}

	free(conf);
	free(mrtconf);
	free(filter_l);
	free(peerfilter_l);
	free(groupfilter_l);

	return (errors ? -1 : 0);
}

int
symset(const char *nam, const char *val, int persist)
{
	struct sym	*sym;

	for (sym = TAILQ_FIRST(&symhead); sym && strcmp(nam, sym->nam);
	    sym = TAILQ_NEXT(sym, entry))
		;	/* nothing */

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

	TAILQ_FOREACH(sym, &symhead, entry)
		if (strcmp(nam, sym->nam) == 0) {
			sym->used = 1;
			return (sym->val);
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
parsecommunity(char *s, int *as, int *type)
{
	char *p;
	int i;

	/* Well-known communities */
	if (strcasecmp(s, "NO_EXPORT") == 0) {
		*as = COMMUNITY_WELLKNOWN;
		*type = COMMUNITY_NO_EXPORT;
		return (0);
	} else if (strcasecmp(s, "NO_ADVERTISE") == 0) {
		*as = COMMUNITY_WELLKNOWN;
		*type = COMMUNITY_NO_ADVERTISE;
		return (0);
	} else if (strcasecmp(s, "NO_EXPORT_SUBCONFED") == 0) {
		*as = COMMUNITY_WELLKNOWN;
		*type = COMMUNITY_NO_EXPSUBCONFED;
		return (0);
	} else if (strcasecmp(s, "NO_PEER") == 0) {
		*as = COMMUNITY_WELLKNOWN;
		*type = COMMUNITY_NO_PEER;
		return (0);
	}

	if ((p = strchr(s, ':')) == NULL) {
		yyerror("Bad community syntax");
		return (-1);
	}
	*p++ = 0;

	if ((i = getcommunity(s)) == COMMUNITY_ERROR)
		return (-1);
	if (i == USHRT_MAX) {
		yyerror("Bad community AS number");
		return (-1);
	}
	*as = i;

	if ((i = getcommunity(p)) == COMMUNITY_ERROR)
		return (-1);
	*type = i;

	return (0);
}

struct peer *
alloc_peer(void)
{
	struct peer	*p;

	if ((p = calloc(1, sizeof(struct peer))) == NULL)
		fatal("new_peer");

	/* some sane defaults */
	p->state = STATE_NONE;
	p->next = NULL;
	p->conf.distance = 1;
	p->conf.announce_type = ANNOUNCE_UNDEF;
	p->conf.announce_capa = 1;
	p->conf.capabilities.mp_v4 = SAFI_UNICAST;
	p->conf.capabilities.mp_v6 = SAFI_NONE;
	p->conf.capabilities.refresh = 1;
	p->conf.capabilities.restart = 0;
	p->conf.capabilities.as4byte = 0;
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
add_mrtconfig(enum mrt_type type, char *name, time_t timeout, struct peer *p,
    char *rib)
{
	struct mrt	*m, *n;

	LIST_FOREACH(m, mrtconf, entry) {
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
		yyerror("filename \"%s\" too long: max %u",
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
			yyerror("rib name \"%s\" too long: max %u",
			    name, sizeof(n->rib) - 1);
			free(n);
			return (-1);
		}
	}

	LIST_INSERT_HEAD(mrtconf, n, entry);

	return (0);
}

int
add_rib(char *name, u_int16_t flags)
{
	struct rde_rib	*rr;

	if (find_rib(name)) {
		yyerror("rib \"%s\" allready exists.", name);
		return (-1);
	}

	if ((rr = calloc(1, sizeof(*rr))) == NULL) {
		log_warn("add_rib");
		return (-1);
	}
	if (strlcpy(rr->name, name, sizeof(rr->name)) >= sizeof(rr->name)) {
		yyerror("rib name \"%s\" too long: max %u",
		   name, sizeof(rr->name) - 1);
		return (-1);
	}
	rr->flags |= flags;
	SIMPLEQ_INSERT_TAIL(&ribnames, rr, entry);
	return (0);
}

int
find_rib(char *name)
{
	struct rde_rib	*rr;

	SIMPLEQ_FOREACH(rr, &ribnames, entry) {
		if (!strcmp(rr->name, name))
			return (1);
	}
	return (0);
}

int
get_id(struct peer *newpeer)
{
	struct peer	*p;

	for (p = peer_l_old; p != NULL; p = p->next)
		if (newpeer->conf.remote_addr.af) {
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
		prefix = match->prefix_l;
		do {
			a = match->as_l;
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

				if (a != NULL)
					a = a->next;
			} while (a != NULL);

			if (prefix != NULL)
				prefix = prefix->next;
		} while (prefix != NULL);

		if (p != NULL)
			p = p->next;
	} while (p != NULL);

	for (p = peer; p != NULL; p = pnext) {
		pnext = p->next;
		free(p);
	}

	for (prefix = match->prefix_l; prefix != NULL; prefix = prefix_next) {
		prefix_next = prefix->next;
		free(prefix);
	}

	for (a = match->as_l; a != NULL; a = anext) {
		anext = a->next;
		free(a);
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
	/* local-address and peer's address: same address family */
	if (p->conf.local_addr.af &&
	    p->conf.local_addr.af != p->conf.remote_addr.af) {
		yyerror("local-address and neighbor address "
		    "must be of the same address family");
		return (-1);
	}

	/* with any form of ipsec local-address is required */
	if ((p->conf.auth.method == AUTH_IPSEC_IKE_ESP ||
	    p->conf.auth.method == AUTH_IPSEC_IKE_AH ||
	    p->conf.auth.method == AUTH_IPSEC_MANUAL_ESP ||
	    p->conf.auth.method == AUTH_IPSEC_MANUAL_AH) &&
	    !p->conf.local_addr.af) {
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

	/* for testing: enable 4-byte AS number capability if necessary */
	if (conf->as > USHRT_MAX || p->conf.remote_as > USHRT_MAX)
		p->conf.capabilities.as4byte = 1;

	/* set default values if they where undefined */
	p->conf.ebgp = (p->conf.remote_as != conf->as);
	if (p->conf.announce_type == ANNOUNCE_UNDEF)
		p->conf.announce_type = p->conf.ebgp == 0 ?
		    ANNOUNCE_ALL : ANNOUNCE_SELF;
	if (p->conf.enforce_as == ENFORCE_AS_UNDEF)
		p->conf.enforce_as = p->conf.ebgp == 0 ?
		    ENFORCE_AS_OFF : ENFORCE_AS_ON;

	/* EBGP neighbors are not allowed in route reflector clusters */
	if (p->conf.reflector_client && p->conf.ebgp) {
		yyerror("EBGP neighbors are not allowed in route "
		    "reflector clusters");
		return (-1);
	}

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
			case ACTION_SET_NEXTHOP:
				if (s->action.nexthop.af <
				    t->action.nexthop.af) {
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
		if ((t = calloc(1, sizeof(struct filter_set))) == NULL)
			fatal(NULL);
		memcpy(t, s, sizeof(struct filter_set));
		TAILQ_INSERT_TAIL(dest, t, entry);
	}
}

void
move_filterset(struct filter_set_head *source, struct filter_set_head *dest)
{
	struct filter_set	*s;

	TAILQ_INIT(dest);

	if (source == NULL)
		return;

	while ((s = TAILQ_FIRST(source)) != NULL) {
		TAILQ_REMOVE(source, s, entry);
		TAILQ_INSERT_TAIL(dest, s, entry);
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
#line 2030 "y.tab.c"
/* allocate initial stack or double stack size, up to YYMAXDEPTH */
#if defined(__cplusplus) || defined(__STDC__)
static int yygrowstack(void)
#else
static int yygrowstack()
#endif
{
    int newsize, i;
    short *newss;
    YYSTYPE *newvs;

    if ((newsize = yystacksize) == 0)
        newsize = YYINITSTACKSIZE;
    else if (newsize >= YYMAXDEPTH)
        return -1;
    else if ((newsize *= 2) > YYMAXDEPTH)
        newsize = YYMAXDEPTH;
    i = yyssp - yyss;
#ifdef SIZE_MAX
#define YY_SIZE_MAX SIZE_MAX
#else
#define YY_SIZE_MAX 0xffffffffU
#endif
    if (newsize && YY_SIZE_MAX / newsize < sizeof *newss)
        goto bail;
    newss = yyss ? (short *)realloc(yyss, newsize * sizeof *newss) :
      (short *)malloc(newsize * sizeof *newss); /* overflow check above */
    if (newss == NULL)
        goto bail;
    yyss = newss;
    yyssp = newss + i;
    if (newsize && YY_SIZE_MAX / newsize < sizeof *newvs)
        goto bail;
    newvs = yyvs ? (YYSTYPE *)realloc(yyvs, newsize * sizeof *newvs) :
      (YYSTYPE *)malloc(newsize * sizeof *newvs); /* overflow check above */
    if (newvs == NULL)
        goto bail;
    yyvs = newvs;
    yyvsp = newvs + i;
    yystacksize = newsize;
    yysslim = yyss + newsize - 1;
    return 0;
bail:
    if (yyss)
            free(yyss);
    if (yyvs)
            free(yyvs);
    yyss = yyssp = NULL;
    yyvs = yyvsp = NULL;
    yystacksize = 0;
    return -1;
}

#define YYABORT goto yyabort
#define YYREJECT goto yyabort
#define YYACCEPT goto yyaccept
#define YYERROR goto yyerrlab
int
#if defined(__cplusplus) || defined(__STDC__)
yyparse(void)
#else
yyparse()
#endif
{
    int yym, yyn, yystate;
#if YYDEBUG
#if defined(__cplusplus) || defined(__STDC__)
    const char *yys;
#else /* !(defined(__cplusplus) || defined(__STDC__)) */
    char *yys;
#endif /* !(defined(__cplusplus) || defined(__STDC__)) */

    if ((yys = getenv("YYDEBUG")))
    {
        yyn = *yys;
        if (yyn >= '0' && yyn <= '9')
            yydebug = yyn - '0';
    }
#endif /* YYDEBUG */

    yynerrs = 0;
    yyerrflag = 0;
    yychar = (-1);

    if (yyss == NULL && yygrowstack()) goto yyoverflow;
    yyssp = yyss;
    yyvsp = yyvs;
    *yyssp = yystate = 0;

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
        if (yyssp >= yysslim && yygrowstack())
        {
            goto yyoverflow;
        }
        *++yyssp = yystate = yytable[yyn];
        *++yyvsp = yylval;
        yychar = (-1);
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
#if defined(lint) || defined(__GNUC__)
    goto yynewerror;
#endif
yynewerror:
    yyerror("syntax error");
#if defined(lint) || defined(__GNUC__)
    goto yyerrlab;
#endif
yyerrlab:
    ++yynerrs;
yyinrecovery:
    if (yyerrflag < 3)
    {
        yyerrflag = 3;
        for (;;)
        {
            if ((yyn = yysindex[*yyssp]) && (yyn += YYERRCODE) >= 0 &&
                    yyn <= YYTABLESIZE && yycheck[yyn] == YYERRCODE)
            {
#if YYDEBUG
                if (yydebug)
                    printf("%sdebug: state %d, error recovery shifting\
 to state %d\n", YYPREFIX, *yyssp, yytable[yyn]);
#endif
                if (yyssp >= yysslim && yygrowstack())
                {
                    goto yyoverflow;
                }
                *++yyssp = yystate = yytable[yyn];
                *++yyvsp = yylval;
                goto yyloop;
            }
            else
            {
#if YYDEBUG
                if (yydebug)
                    printf("%sdebug: error recovery discarding state %d\n",
                            YYPREFIX, *yyssp);
#endif
                if (yyssp <= yyss) goto yyabort;
                --yyssp;
                --yyvsp;
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
        yychar = (-1);
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
        yyval = yyvsp[1-yym];
    else
        memset(&yyval, 0, sizeof yyval);
    switch (yyn)
    {
case 9:
#line 210 "parse.y"
{ file->errors++; }
break;
case 10:
#line 213 "parse.y"
{
			if (yyvsp[0].v.number < 0 || yyvsp[0].v.number >= ASNUM_MAX) {
				yyerror("AS too big: max %u", ASNUM_MAX - 1);
				YYERROR;
			}
		}
break;
case 11:
#line 220 "parse.y"
{
			const char	*errstr;
			char		*dot;
			u_int32_t	 uvalh = 0, uval;

			if ((dot = strchr(yyvsp[0].v.string,'.')) != NULL) {
				*dot++ = '\0';
				uvalh = strtonum(yyvsp[0].v.string, 0, USHRT_MAX, &errstr);
				if (errstr) {
					yyerror("number %s is %s", yyvsp[0].v.string, errstr);
					free(yyvsp[0].v.string);
					YYERROR;
				}
				uval = strtonum(dot, 0, USHRT_MAX, &errstr);
				if (errstr) {
					yyerror("number %s is %s", dot, errstr);
					free(yyvsp[0].v.string);
					YYERROR;
				}
				free(yyvsp[0].v.string);
			} else {
				yyerror("AS %s is bad", yyvsp[0].v.string);
				free(yyvsp[0].v.string);
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
case 12:
#line 252 "parse.y"
{
			if (yyvsp[0].v.number == AS_TRANS) {
				yyerror("AS %u is reserved and may not be used",
				    AS_TRANS);
				YYERROR;
			}
			yyval.v.number = yyvsp[0].v.number;
		}
break;
case 13:
#line 262 "parse.y"
{
			if (asprintf(&yyval.v.string, "%s %s", yyvsp[-1].v.string, yyvsp[0].v.string) == -1)
				fatal("string: asprintf");
			free(yyvsp[-1].v.string);
			free(yyvsp[0].v.string);
		}
break;
case 15:
#line 271 "parse.y"
{
			if (!strcmp(yyvsp[0].v.string, "yes"))
				yyval.v.number = 1;
			else if (!strcmp(yyvsp[0].v.string, "no"))
				yyval.v.number = 0;
			else {
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[0].v.string);
		}
break;
case 16:
#line 284 "parse.y"
{
			if (conf->opts & BGPD_OPT_VERBOSE)
				printf("%s = \"%s\"\n", yyvsp[-2].v.string, yyvsp[0].v.string);
			if (symset(yyvsp[-2].v.string, yyvsp[0].v.string, 0) == -1)
				fatal("cannot store variable");
			free(yyvsp[-2].v.string);
			free(yyvsp[0].v.string);
		}
break;
case 17:
#line 294 "parse.y"
{
			struct file	*nfile;

			if ((nfile = pushfile(yyvsp[0].v.string, 1)) == NULL) {
				yyerror("failed to include file %s", yyvsp[0].v.string);
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[0].v.string);

			file = nfile;
			lungetc('\n');
		}
break;
case 18:
#line 309 "parse.y"
{
			conf->as = yyvsp[0].v.number;
			if (yyvsp[0].v.number > USHRT_MAX)
				conf->short_as = AS_TRANS;
			else
				conf->short_as = yyvsp[0].v.number;
		}
break;
case 19:
#line 316 "parse.y"
{
			conf->as = yyvsp[-1].v.number;
			conf->short_as = yyvsp[0].v.number;
		}
break;
case 20:
#line 320 "parse.y"
{
			if (yyvsp[0].v.addr.af != AF_INET) {
				yyerror("router-id must be an IPv4 address");
				YYERROR;
			}
			conf->bgpid = yyvsp[0].v.addr.v4.s_addr;
		}
break;
case 21:
#line 327 "parse.y"
{
			if (yyvsp[0].v.number < MIN_HOLDTIME || yyvsp[0].v.number > USHRT_MAX) {
				yyerror("holdtime must be between %u and %u",
				    MIN_HOLDTIME, USHRT_MAX);
				YYERROR;
			}
			conf->holdtime = yyvsp[0].v.number;
		}
break;
case 22:
#line 335 "parse.y"
{
			if (yyvsp[0].v.number < MIN_HOLDTIME || yyvsp[0].v.number > USHRT_MAX) {
				yyerror("holdtime must be between %u and %u",
				    MIN_HOLDTIME, USHRT_MAX);
				YYERROR;
			}
			conf->min_holdtime = yyvsp[0].v.number;
		}
break;
case 23:
#line 343 "parse.y"
{
			struct listen_addr	*la;
			struct sockaddr_in	*in;
			struct sockaddr_in6	*in6;

			if ((la = calloc(1, sizeof(struct listen_addr))) ==
			    NULL)
				fatal("parse conf_main listen on calloc");

			la->fd = -1;
			la->sa.ss_family = yyvsp[0].v.addr.af;
			switch (yyvsp[0].v.addr.af) {
			case AF_INET:
				la->sa.ss_len = sizeof(struct sockaddr_in);
				in = (struct sockaddr_in *)&la->sa;
				in->sin_addr.s_addr = yyvsp[0].v.addr.v4.s_addr;
				in->sin_port = htons(BGP_PORT);
				break;
			case AF_INET6:
				la->sa.ss_len = sizeof(struct sockaddr_in6);
				in6 = (struct sockaddr_in6 *)&la->sa;
				memcpy(&in6->sin6_addr, &yyvsp[0].v.addr.v6,
				    sizeof(in6->sin6_addr));
				in6->sin6_port = htons(BGP_PORT);
				break;
			default:
				yyerror("king bula does not like family %u",
				    yyvsp[0].v.addr.af);
				YYERROR;
			}

			TAILQ_INSERT_TAIL(listen_addrs, la, entry);
		}
break;
case 24:
#line 376 "parse.y"
{
			if (yyvsp[0].v.number == 0)
				conf->flags |= BGPD_FLAG_NO_FIB_UPDATE;
			else
				conf->flags &= ~BGPD_FLAG_NO_FIB_UPDATE;
		}
break;
case 25:
#line 382 "parse.y"
{
			if (yyvsp[0].v.number == 1)
				conf->flags |= BGPD_FLAG_NO_EVALUATE;
			else
				conf->flags &= ~BGPD_FLAG_NO_EVALUATE;
		}
break;
case 26:
#line 388 "parse.y"
{
			if (add_rib(yyvsp[0].v.string, F_RIB_NOFIB)) {
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[0].v.string);
		}
break;
case 27:
#line 395 "parse.y"
{
			if (yyvsp[-1].v.number) {
				free(yyvsp[-2].v.string);
				YYERROR;
			}
			if (!add_rib(yyvsp[-2].v.string, F_RIB_NOEVALUATE)) {
				free(yyvsp[-2].v.string);
				YYERROR;
			}
			free(yyvsp[-2].v.string);
		}
break;
case 28:
#line 406 "parse.y"
{
			if (yyvsp[0].v.number == 1)
				conf->flags |= BGPD_FLAG_DECISION_TRANS_AS;
			else
				conf->flags &= ~BGPD_FLAG_DECISION_TRANS_AS;
		}
break;
case 29:
#line 412 "parse.y"
{
			if (!strcmp(yyvsp[0].v.string, "updates"))
				conf->log |= BGPD_LOG_UPDATES;
			else {
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[0].v.string);
		}
break;
case 30:
#line 421 "parse.y"
{
			struct network	*n;

			if ((n = calloc(1, sizeof(struct network))) == NULL)
				fatal("new_network");
			memcpy(&n->net.prefix, &yyvsp[-1].v.prefix.prefix,
			    sizeof(n->net.prefix));
			n->net.prefixlen = yyvsp[-1].v.prefix.len;
			move_filterset(yyvsp[0].v.filter_set_head, &n->net.attrset);
			free(yyvsp[0].v.filter_set_head);

			TAILQ_INSERT_TAIL(netconf, n, entry);
		}
break;
case 31:
#line 434 "parse.y"
{
			if (yyvsp[-2].v.number == AFI_IPv4) {
				conf->flags |= BGPD_FLAG_REDIST_STATIC;
				move_filterset(yyvsp[0].v.filter_set_head, &conf->staticset);
			} else if (yyvsp[-2].v.number == AFI_IPv6) {
				conf->flags |= BGPD_FLAG_REDIST6_STATIC;
				move_filterset(yyvsp[0].v.filter_set_head, &conf->staticset6);
			} else {
				yyerror("unknown family");
				free(yyvsp[0].v.filter_set_head);
				YYERROR;
			}
			free(yyvsp[0].v.filter_set_head);
		}
break;
case 32:
#line 448 "parse.y"
{
			if (yyvsp[-2].v.number == AFI_IPv4) {
				conf->flags |= BGPD_FLAG_REDIST_CONNECTED;
				move_filterset(yyvsp[0].v.filter_set_head, &conf->connectset);
			} else if (yyvsp[-2].v.number == AFI_IPv6) {
				conf->flags |= BGPD_FLAG_REDIST6_CONNECTED;
				move_filterset(yyvsp[0].v.filter_set_head, &conf->connectset6);
			} else {
				yyerror("unknown family");
				free(yyvsp[0].v.filter_set_head);
				YYERROR;
			}
			free(yyvsp[0].v.filter_set_head);
		}
break;
case 33:
#line 462 "parse.y"
{
			/* keep for compatibility till after next release */
			conf->flags |= BGPD_FLAG_REDIST_STATIC;
			move_filterset(yyvsp[0].v.filter_set_head, &conf->staticset);
			free(yyvsp[0].v.filter_set_head);
		}
break;
case 34:
#line 468 "parse.y"
{
			/* keep for compatibility till after next release */
			conf->flags |= BGPD_FLAG_REDIST_CONNECTED;
			move_filterset(yyvsp[0].v.filter_set_head, &conf->connectset);
			free(yyvsp[0].v.filter_set_head);
		}
break;
case 35:
#line 474 "parse.y"
{
			int action;

			if (yyvsp[0].v.number < 0 || yyvsp[0].v.number > UINT_MAX) {
				yyerror("bad timeout");
				free(yyvsp[-2].v.string);
				free(yyvsp[-1].v.string);
				YYERROR;
			}
			if (!strcmp(yyvsp[-2].v.string, "table"))
				action = MRT_TABLE_DUMP;
			else if (!strcmp(yyvsp[-2].v.string, "table-mp"))
				action = MRT_TABLE_DUMP_MP;
			else {
				yyerror("unknown mrt dump type");
				free(yyvsp[-2].v.string);
				free(yyvsp[-1].v.string);
				YYERROR;
			}
			free(yyvsp[-2].v.string);
			if (add_mrtconfig(action, yyvsp[-1].v.string, yyvsp[0].v.number, NULL, NULL) == -1) {
				free(yyvsp[-1].v.string);
				YYERROR;
			}
			free(yyvsp[-1].v.string);
		}
break;
case 36:
#line 500 "parse.y"
{
			int action;

			if (yyvsp[0].v.number < 0 || yyvsp[0].v.number > UINT_MAX) {
				yyerror("bad timeout");
				free(yyvsp[-3].v.string);
				free(yyvsp[-2].v.string);
				free(yyvsp[-1].v.string);
				YYERROR;
			}
			if (!strcmp(yyvsp[-2].v.string, "table"))
				action = MRT_TABLE_DUMP;
			else if (!strcmp(yyvsp[-2].v.string, "table-mp"))
				action = MRT_TABLE_DUMP_MP;
			else {
				yyerror("unknown mrt dump type");
				free(yyvsp[-3].v.string);
				free(yyvsp[-2].v.string);
				free(yyvsp[-1].v.string);
				YYERROR;
			}
			free(yyvsp[-2].v.string);
			if (add_mrtconfig(action, yyvsp[-1].v.string, yyvsp[0].v.number, NULL, yyvsp[-3].v.string) == -1) {
				free(yyvsp[-3].v.string);
				free(yyvsp[-1].v.string);
				YYERROR;
			}
			free(yyvsp[-3].v.string);
			free(yyvsp[-1].v.string);
		}
break;
case 38:
#line 531 "parse.y"
{
			if (!strcmp(yyvsp[-1].v.string, "route-age"))
				conf->flags |= BGPD_FLAG_DECISION_ROUTEAGE;
			else {
				yyerror("unknown route decision type");
				free(yyvsp[-1].v.string);
				YYERROR;
			}
			free(yyvsp[-1].v.string);
		}
break;
case 39:
#line 541 "parse.y"
{
			if (!strcmp(yyvsp[-1].v.string, "route-age"))
				conf->flags &= ~BGPD_FLAG_DECISION_ROUTEAGE;
			else {
				yyerror("unknown route decision type");
				free(yyvsp[-1].v.string);
				YYERROR;
			}
			free(yyvsp[-1].v.string);
		}
break;
case 40:
#line 551 "parse.y"
{
			if (!strcmp(yyvsp[0].v.string, "always"))
				conf->flags |= BGPD_FLAG_DECISION_MED_ALWAYS;
			else if (!strcmp(yyvsp[0].v.string, "strict"))
				conf->flags &= ~BGPD_FLAG_DECISION_MED_ALWAYS;
			else {
				yyerror("rde med compare: "
				    "unknown setting \"%s\"", yyvsp[0].v.string);
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[0].v.string);
		}
break;
case 41:
#line 564 "parse.y"
{
			if (!strcmp(yyvsp[0].v.string, "bgp"))
				conf->flags |= BGPD_FLAG_NEXTHOP_BGP;
			else if (!strcmp(yyvsp[0].v.string, "default"))
				conf->flags |= BGPD_FLAG_NEXTHOP_DEFAULT;
			else {
				yyerror("nexthop depend on: "
				    "unknown setting \"%s\"", yyvsp[0].v.string);
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[0].v.string);
		}
break;
case 42:
#line 577 "parse.y"
{
			if (yyvsp[0].v.number > RT_TABLEID_MAX || yyvsp[0].v.number < 0) {
				yyerror("invalid rtable id");
				YYERROR;
			}
			conf->rtableid = yyvsp[0].v.number;
		}
break;
case 43:
#line 584 "parse.y"
{
			if (yyvsp[0].v.number > USHRT_MAX || yyvsp[0].v.number < 1) {
				yyerror("invalid connect-retry");
				YYERROR;
			}
			conf->connectretry = yyvsp[0].v.number;
		}
break;
case 44:
#line 593 "parse.y"
{
			int action;

			if (yyvsp[0].v.number < 0 || yyvsp[0].v.number > UINT_MAX) {
				yyerror("bad timeout");
				free(yyvsp[-3].v.string);
				free(yyvsp[-1].v.string);
				YYERROR;
			}
			if (!strcmp(yyvsp[-3].v.string, "all"))
				action = yyvsp[-2].v.number ? MRT_ALL_IN : MRT_ALL_OUT;
			else if (!strcmp(yyvsp[-3].v.string, "updates"))
				action = yyvsp[-2].v.number ? MRT_UPDATE_IN : MRT_UPDATE_OUT;
			else {
				yyerror("unknown mrt msg dump type");
				free(yyvsp[-3].v.string);
				free(yyvsp[-1].v.string);
				YYERROR;
			}
			if (add_mrtconfig(action, yyvsp[-1].v.string, yyvsp[0].v.number, curpeer, NULL) ==
			    -1) {
				free(yyvsp[-3].v.string);
				free(yyvsp[-1].v.string);
				YYERROR;
			}
			free(yyvsp[-3].v.string);
			free(yyvsp[-1].v.string);
		}
break;
case 45:
#line 623 "parse.y"
{ yyval.v.number = 1; }
break;
case 46:
#line 624 "parse.y"
{ yyval.v.number = 0; }
break;
case 47:
#line 627 "parse.y"
{
			u_int8_t	len;

			if (!host(yyvsp[0].v.string, &yyval.v.addr, &len)) {
				yyerror("could not parse address spec \"%s\"",
				    yyvsp[0].v.string);
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[0].v.string);

			if ((yyval.v.addr.af == AF_INET && len != 32) ||
			    (yyval.v.addr.af == AF_INET6 && len != 128)) {
				/* unreachable */
				yyerror("got prefixlen %u, expected %u",
				    len, yyval.v.addr.af == AF_INET ? 32 : 128);
				YYERROR;
			}
		}
break;
case 48:
#line 648 "parse.y"
{
			char	*s;

			if (yyvsp[0].v.number < 0 || yyvsp[0].v.number > 128) {
				yyerror("bad prefixlen %lld", yyvsp[0].v.number);
				free(yyvsp[-2].v.string);
				YYERROR;
			}
			if (asprintf(&s, "%s/%lld", yyvsp[-2].v.string, yyvsp[0].v.number) == -1)
				fatal(NULL);
			free(yyvsp[-2].v.string);

			if (!host(s, &yyval.v.prefix.prefix, &yyval.v.prefix.len)) {
				yyerror("could not parse address \"%s\"", s);
				free(s);
				YYERROR;
			}
			free(s);
		}
break;
case 49:
#line 667 "parse.y"
{
			char	*s;

			/* does not match IPv6 */
			if (yyvsp[-2].v.number < 0 || yyvsp[-2].v.number > 255 || yyvsp[0].v.number < 0 || yyvsp[0].v.number > 32) {
				yyerror("bad prefix %lld/%lld", yyvsp[-2].v.number, yyvsp[0].v.number);
				YYERROR;
			}
			if (asprintf(&s, "%lld/%lld", yyvsp[-2].v.number, yyvsp[0].v.number) == -1)
				fatal(NULL);

			if (!host(s, &yyval.v.prefix.prefix, &yyval.v.prefix.len)) {
				yyerror("could not parse address \"%s\"", s);
				free(s);
				YYERROR;
			}
			free(s);
		}
break;
case 50:
#line 687 "parse.y"
{
			memcpy(&yyval.v.prefix.prefix, &yyvsp[0].v.addr, sizeof(struct bgpd_addr));
			if (yyval.v.prefix.prefix.af == AF_INET)
				yyval.v.prefix.len = 32;
			else
				yyval.v.prefix.len = 128;
		}
break;
case 55:
#line 704 "parse.y"
{ yyval.v.number = 0; }
break;
case 57:
#line 708 "parse.y"
{	curpeer = new_peer(); }
break;
case 58:
#line 709 "parse.y"
{
			memcpy(&curpeer->conf.remote_addr, &yyvsp[0].v.prefix.prefix,
			    sizeof(curpeer->conf.remote_addr));
			curpeer->conf.remote_masklen = yyvsp[0].v.prefix.len;
			if ((yyvsp[0].v.prefix.prefix.af == AF_INET && yyvsp[0].v.prefix.len != 32) ||
			    (yyvsp[0].v.prefix.prefix.af == AF_INET6 && yyvsp[0].v.prefix.len != 128))
				curpeer->conf.template = 1;
			if (get_id(curpeer)) {
				yyerror("get_id failed");
				YYERROR;
			}
		}
break;
case 59:
#line 721 "parse.y"
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
case 60:
#line 739 "parse.y"
{
			curgroup = curpeer = new_group();
			if (strlcpy(curgroup->conf.group, yyvsp[-3].v.string,
			    sizeof(curgroup->conf.group)) >=
			    sizeof(curgroup->conf.group)) {
				yyerror("group name \"%s\" too long: max %u",
				    yyvsp[-3].v.string, sizeof(curgroup->conf.group) - 1);
				free(yyvsp[-3].v.string);
				YYERROR;
			}
			free(yyvsp[-3].v.string);
			if (get_id(curgroup)) {
				yyerror("get_id failed");
				YYERROR;
			}
		}
break;
case 61:
#line 755 "parse.y"
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
case 73:
#line 791 "parse.y"
{
			curpeer->conf.remote_as = yyvsp[0].v.number;
		}
break;
case 74:
#line 794 "parse.y"
{
			if (strlcpy(curpeer->conf.descr, yyvsp[0].v.string,
			    sizeof(curpeer->conf.descr)) >=
			    sizeof(curpeer->conf.descr)) {
				yyerror("descr \"%s\" too long: max %u",
				    yyvsp[0].v.string, sizeof(curpeer->conf.descr) - 1);
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[0].v.string);
		}
break;
case 75:
#line 805 "parse.y"
{
			memcpy(&curpeer->conf.local_addr, &yyvsp[0].v.addr,
			    sizeof(curpeer->conf.local_addr));
		}
break;
case 76:
#line 809 "parse.y"
{
			if (yyvsp[0].v.number < 2 || yyvsp[0].v.number > 255) {
				yyerror("invalid multihop distance %d", yyvsp[0].v.number);
				YYERROR;
			}
			curpeer->conf.distance = yyvsp[0].v.number;
		}
break;
case 77:
#line 816 "parse.y"
{
			curpeer->conf.passive = 1;
		}
break;
case 78:
#line 819 "parse.y"
{
			curpeer->conf.down = 1;
		}
break;
case 79:
#line 822 "parse.y"
{
			if (!find_rib(yyvsp[0].v.string)) {
				yyerror("rib \"%s\" does not exist.", yyvsp[0].v.string);
				free(yyvsp[0].v.string);
				YYERROR;
			}
			if (strlcpy(curpeer->conf.rib, yyvsp[0].v.string,
			    sizeof(curpeer->conf.rib)) >=
			    sizeof(curpeer->conf.rib)) {
				yyerror("rib name \"%s\" too long: max %u",
				   yyvsp[0].v.string, sizeof(curpeer->conf.rib) - 1);
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[0].v.string);
		}
break;
case 80:
#line 838 "parse.y"
{
			if (yyvsp[0].v.number < MIN_HOLDTIME || yyvsp[0].v.number > USHRT_MAX) {
				yyerror("holdtime must be between %u and %u",
				    MIN_HOLDTIME, USHRT_MAX);
				YYERROR;
			}
			curpeer->conf.holdtime = yyvsp[0].v.number;
		}
break;
case 81:
#line 846 "parse.y"
{
			if (yyvsp[0].v.number < MIN_HOLDTIME || yyvsp[0].v.number > USHRT_MAX) {
				yyerror("holdtime must be between %u and %u",
				    MIN_HOLDTIME, USHRT_MAX);
				YYERROR;
			}
			curpeer->conf.min_holdtime = yyvsp[0].v.number;
		}
break;
case 82:
#line 854 "parse.y"
{
			u_int8_t	safi;

			if (!strcmp(yyvsp[0].v.string, "none"))
				safi = SAFI_NONE;
			else if (!strcmp(yyvsp[0].v.string, "unicast"))
				safi = SAFI_UNICAST;
			else {
				yyerror("unknown/unsupported SAFI \"%s\"",
				    yyvsp[0].v.string);
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[0].v.string);

			switch (yyvsp[-1].v.number) {
			case AFI_IPv4:
				curpeer->conf.capabilities.mp_v4 = safi;
				break;
			case AFI_IPv6:
				curpeer->conf.capabilities.mp_v6 = safi;
				break;
			default:
				fatal("king bula sees borked AFI");
			}
		}
break;
case 83:
#line 880 "parse.y"
{
			curpeer->conf.announce_capa = yyvsp[0].v.number;
		}
break;
case 84:
#line 883 "parse.y"
{
			curpeer->conf.announce_type = ANNOUNCE_SELF;
		}
break;
case 85:
#line 886 "parse.y"
{
			if (!strcmp(yyvsp[0].v.string, "none"))
				curpeer->conf.announce_type = ANNOUNCE_NONE;
			else if (!strcmp(yyvsp[0].v.string, "all"))
				curpeer->conf.announce_type = ANNOUNCE_ALL;
			else if (!strcmp(yyvsp[0].v.string, "default-route"))
				curpeer->conf.announce_type =
				    ANNOUNCE_DEFAULT_ROUTE;
			else {
				yyerror("invalid announce type");
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[0].v.string);
		}
break;
case 86:
#line 901 "parse.y"
{
			if (yyvsp[0].v.number)
				curpeer->conf.enforce_as = ENFORCE_AS_ON;
			else
				curpeer->conf.enforce_as = ENFORCE_AS_OFF;
		}
break;
case 87:
#line 907 "parse.y"
{
			if (yyvsp[-1].v.number < 0 || yyvsp[-1].v.number > UINT_MAX) {
				yyerror("bad maximum number of prefixes");
				YYERROR;
			}
			curpeer->conf.max_prefix = yyvsp[-1].v.number;
			curpeer->conf.max_prefix_restart = yyvsp[0].v.number;
		}
break;
case 88:
#line 915 "parse.y"
{
			if (curpeer->conf.auth.method) {
				yyerror("auth method cannot be redefined");
				free(yyvsp[0].v.string);
				YYERROR;
			}
			if (strlcpy(curpeer->conf.auth.md5key, yyvsp[0].v.string,
			    sizeof(curpeer->conf.auth.md5key)) >=
			    sizeof(curpeer->conf.auth.md5key)) {
				yyerror("tcp md5sig password too long: max %u",
				    sizeof(curpeer->conf.auth.md5key) - 1);
				free(yyvsp[0].v.string);
				YYERROR;
			}
			curpeer->conf.auth.method = AUTH_MD5SIG;
			curpeer->conf.auth.md5key_len = strlen(yyvsp[0].v.string);
			free(yyvsp[0].v.string);
		}
break;
case 89:
#line 933 "parse.y"
{
			if (curpeer->conf.auth.method) {
				yyerror("auth method cannot be redefined");
				free(yyvsp[0].v.string);
				YYERROR;
			}

			if (str2key(yyvsp[0].v.string, curpeer->conf.auth.md5key,
			    sizeof(curpeer->conf.auth.md5key)) == -1) {
				free(yyvsp[0].v.string);
				YYERROR;
			}
			curpeer->conf.auth.method = AUTH_MD5SIG;
			curpeer->conf.auth.md5key_len = strlen(yyvsp[0].v.string) / 2;
			free(yyvsp[0].v.string);
		}
break;
case 90:
#line 949 "parse.y"
{
			if (curpeer->conf.auth.method) {
				yyerror("auth method cannot be redefined");
				YYERROR;
			}
			if (yyvsp[-1].v.number)
				curpeer->conf.auth.method = AUTH_IPSEC_IKE_ESP;
			else
				curpeer->conf.auth.method = AUTH_IPSEC_IKE_AH;
		}
break;
case 91:
#line 959 "parse.y"
{
			u_int32_t	auth_alg;
			u_int8_t	keylen;

			if (curpeer->conf.auth.method &&
			    (((curpeer->conf.auth.spi_in && yyvsp[-5].v.number == 1) ||
			    (curpeer->conf.auth.spi_out && yyvsp[-5].v.number == 0)) ||
			    (yyvsp[-6].v.number == 1 && curpeer->conf.auth.method !=
			    AUTH_IPSEC_MANUAL_ESP) ||
			    (yyvsp[-6].v.number == 0 && curpeer->conf.auth.method !=
			    AUTH_IPSEC_MANUAL_AH))) {
				yyerror("auth method cannot be redefined");
				free(yyvsp[-2].v.string);
				free(yyvsp[-1].v.string);
				YYERROR;
			}

			if (!strcmp(yyvsp[-2].v.string, "sha1")) {
				auth_alg = SADB_AALG_SHA1HMAC;
				keylen = 20;
			} else if (!strcmp(yyvsp[-2].v.string, "md5")) {
				auth_alg = SADB_AALG_MD5HMAC;
				keylen = 16;
			} else {
				yyerror("unknown auth algorithm \"%s\"", yyvsp[-2].v.string);
				free(yyvsp[-2].v.string);
				free(yyvsp[-1].v.string);
				YYERROR;
			}
			free(yyvsp[-2].v.string);

			if (strlen(yyvsp[-1].v.string) / 2 != keylen) {
				yyerror("auth key len: must be %u bytes, "
				    "is %u bytes", keylen, strlen(yyvsp[-1].v.string) / 2);
				free(yyvsp[-1].v.string);
				YYERROR;
			}

			if (yyvsp[-6].v.number)
				curpeer->conf.auth.method =
				    AUTH_IPSEC_MANUAL_ESP;
			else {
				if (yyvsp[0].v.encspec.enc_alg) {
					yyerror("\"ipsec ah\" doesn't take "
					    "encryption keys");
					free(yyvsp[-1].v.string);
					YYERROR;
				}
				curpeer->conf.auth.method =
				    AUTH_IPSEC_MANUAL_AH;
			}

			if (yyvsp[-3].v.number < 0 || yyvsp[-3].v.number > UINT_MAX) {
				yyerror("bad spi number %lld", yyvsp[-3].v.number);
				free(yyvsp[-1].v.string);
				YYERROR;
			}

			if (yyvsp[-5].v.number == 1) {
				if (str2key(yyvsp[-1].v.string, curpeer->conf.auth.auth_key_in,
				    sizeof(curpeer->conf.auth.auth_key_in)) ==
				    -1) {
					free(yyvsp[-1].v.string);
					YYERROR;
				}
				curpeer->conf.auth.spi_in = yyvsp[-3].v.number;
				curpeer->conf.auth.auth_alg_in = auth_alg;
				curpeer->conf.auth.enc_alg_in = yyvsp[0].v.encspec.enc_alg;
				memcpy(&curpeer->conf.auth.enc_key_in,
				    &yyvsp[0].v.encspec.enc_key,
				    sizeof(curpeer->conf.auth.enc_key_in));
				curpeer->conf.auth.enc_keylen_in =
				    yyvsp[0].v.encspec.enc_key_len;
				curpeer->conf.auth.auth_keylen_in = keylen;
			} else {
				if (str2key(yyvsp[-1].v.string, curpeer->conf.auth.auth_key_out,
				    sizeof(curpeer->conf.auth.auth_key_out)) ==
				    -1) {
					free(yyvsp[-1].v.string);
					YYERROR;
				}
				curpeer->conf.auth.spi_out = yyvsp[-3].v.number;
				curpeer->conf.auth.auth_alg_out = auth_alg;
				curpeer->conf.auth.enc_alg_out = yyvsp[0].v.encspec.enc_alg;
				memcpy(&curpeer->conf.auth.enc_key_out,
				    &yyvsp[0].v.encspec.enc_key,
				    sizeof(curpeer->conf.auth.enc_key_out));
				curpeer->conf.auth.enc_keylen_out =
				    yyvsp[0].v.encspec.enc_key_len;
				curpeer->conf.auth.auth_keylen_out = keylen;
			}
			free(yyvsp[-1].v.string);
		}
break;
case 92:
#line 1052 "parse.y"
{
			curpeer->conf.ttlsec = yyvsp[0].v.number;
		}
break;
case 93:
#line 1055 "parse.y"
{
			struct filter_rule	*r;

			r = get_rule(yyvsp[0].v.filter_set->type);
			if (merge_filterset(&r->set, yyvsp[0].v.filter_set) == -1)
				YYERROR;
		}
break;
case 94:
#line 1062 "parse.y"
{
			struct filter_rule	*r;
			struct filter_set	*s;

			while ((s = TAILQ_FIRST(yyvsp[-2].v.filter_set_head)) != NULL) {
				TAILQ_REMOVE(yyvsp[-2].v.filter_set_head, s, entry);
				r = get_rule(s->type);
				if (merge_filterset(&r->set, s) == -1)
					YYERROR;
			}
			free(yyvsp[-2].v.filter_set_head);
		}
break;
case 96:
#line 1075 "parse.y"
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
case 97:
#line 1085 "parse.y"
{
			if (yyvsp[0].v.addr.af != AF_INET) {
				yyerror("route reflector cluster-id must be "
				    "an IPv4 address");
				YYERROR;
			}
			if ((conf->flags & BGPD_FLAG_REFLECTOR) &&
			    conf->clusterid != yyvsp[0].v.addr.v4.s_addr) {
				yyerror("only one route reflector "
				    "cluster allowed");
				YYERROR;
			}
			conf->flags |= BGPD_FLAG_REFLECTOR;
			curpeer->conf.reflector_client = 1;
			conf->clusterid = yyvsp[0].v.addr.v4.s_addr;
		}
break;
case 98:
#line 1101 "parse.y"
{
			if (strlcpy(curpeer->conf.if_depend, yyvsp[0].v.string,
			    sizeof(curpeer->conf.if_depend)) >=
			    sizeof(curpeer->conf.if_depend)) {
				yyerror("interface name \"%s\" too long: "
				    "max %u", yyvsp[0].v.string,
				    sizeof(curpeer->conf.if_depend) - 1);
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[0].v.string);
		}
break;
case 99:
#line 1113 "parse.y"
{
			if (strlcpy(curpeer->conf.demote_group, yyvsp[0].v.string,
			    sizeof(curpeer->conf.demote_group)) >=
			    sizeof(curpeer->conf.demote_group)) {
				yyerror("demote group name \"%s\" too long: "
				    "max %u", yyvsp[0].v.string,
				    sizeof(curpeer->conf.demote_group) - 1);
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[0].v.string);
			if (carp_demote_init(curpeer->conf.demote_group,
			    conf->opts & BGPD_OPT_FORCE_DEMOTE) == -1) {
				yyerror("error initializing group \"%s\"",
				    curpeer->conf.demote_group);
				YYERROR;
			}
		}
break;
case 100:
#line 1131 "parse.y"
{
			if (yyvsp[-1].v.number)
				curpeer->conf.softreconfig_in = yyvsp[0].v.number;
			else
				curpeer->conf.softreconfig_out = yyvsp[0].v.number;
		}
break;
case 101:
#line 1137 "parse.y"
{
			if (yyvsp[0].v.number == 1)
				curpeer->conf.flags |= PEERFLAG_TRANS_AS;
			else
				curpeer->conf.flags &= ~PEERFLAG_TRANS_AS;
		}
break;
case 102:
#line 1145 "parse.y"
{ yyval.v.number = 0; }
break;
case 103:
#line 1146 "parse.y"
{
			if (yyvsp[0].v.number < 1 || yyvsp[0].v.number > USHRT_MAX) {
				yyerror("restart out of range. 1 to %u minutes",
				    USHRT_MAX);
				YYERROR;
			}
			yyval.v.number = yyvsp[0].v.number;
		}
break;
case 104:
#line 1156 "parse.y"
{ yyval.v.number = AFI_IPv4; }
break;
case 105:
#line 1157 "parse.y"
{ yyval.v.number = AFI_IPv6; }
break;
case 106:
#line 1160 "parse.y"
{ yyval.v.number = 1; }
break;
case 107:
#line 1161 "parse.y"
{ yyval.v.number = 0; }
break;
case 108:
#line 1164 "parse.y"
{
			bzero(&yyval.v.encspec, sizeof(yyval.v.encspec));
		}
break;
case 109:
#line 1167 "parse.y"
{
			bzero(&yyval.v.encspec, sizeof(yyval.v.encspec));
			if (!strcmp(yyvsp[-1].v.string, "3des") || !strcmp(yyvsp[-1].v.string, "3des-cbc")) {
				yyval.v.encspec.enc_alg = SADB_EALG_3DESCBC;
				yyval.v.encspec.enc_key_len = 21; /* XXX verify */
			} else if (!strcmp(yyvsp[-1].v.string, "aes") ||
			    !strcmp(yyvsp[-1].v.string, "aes-128-cbc")) {
				yyval.v.encspec.enc_alg = SADB_X_EALG_AES;
				yyval.v.encspec.enc_key_len = 16;
			} else {
				yyerror("unknown enc algorithm \"%s\"", yyvsp[-1].v.string);
				free(yyvsp[-1].v.string);
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[-1].v.string);

			if (strlen(yyvsp[0].v.string) / 2 != yyval.v.encspec.enc_key_len) {
				yyerror("enc key length wrong: should be %u "
				    "bytes, is %u bytes",
				    yyval.v.encspec.enc_key_len * 2, strlen(yyvsp[0].v.string));
				free(yyvsp[0].v.string);
				YYERROR;
			}

			if (str2key(yyvsp[0].v.string, yyval.v.encspec.enc_key, sizeof(yyval.v.encspec.enc_key)) == -1) {
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[0].v.string);
		}
break;
case 110:
#line 1201 "parse.y"
{
			struct filter_rule	 r;

			bzero(&r, sizeof(r));
			r.action = yyvsp[-6].v.u8;
			r.quick = yyvsp[-5].v.u8;
			r.dir = yyvsp[-3].v.u8;
			if (yyvsp[-4].v.string) {
				if (r.dir != DIR_IN) {
					yyerror("rib only allowed on \"from\" "
					    "rules.");
					free(yyvsp[-4].v.string);
					YYERROR;
				}
				if (!find_rib(yyvsp[-4].v.string)) {
					yyerror("rib \"%s\" does not exist.",
					    yyvsp[-4].v.string);
					free(yyvsp[-4].v.string);
					YYERROR;
				}
				if (strlcpy(r.rib, yyvsp[-4].v.string, sizeof(r.rib)) >=
				    sizeof(r.rib)) {
					yyerror("rib name \"%s\" too long: "
					    "max %u", yyvsp[-4].v.string, sizeof(r.rib) - 1);
					free(yyvsp[-4].v.string);
					YYERROR;
				}
				free(yyvsp[-4].v.string);
			}
			if (expand_rule(&r, yyvsp[-2].v.filter_peers, &yyvsp[-1].v.filter_match, yyvsp[0].v.filter_set_head) == -1)
				YYERROR;
		}
break;
case 111:
#line 1235 "parse.y"
{ yyval.v.u8 = ACTION_ALLOW; }
break;
case 112:
#line 1236 "parse.y"
{ yyval.v.u8 = ACTION_DENY; }
break;
case 113:
#line 1237 "parse.y"
{ yyval.v.u8 = ACTION_NONE; }
break;
case 114:
#line 1240 "parse.y"
{ yyval.v.u8 = 0; }
break;
case 115:
#line 1241 "parse.y"
{ yyval.v.u8 = 1; }
break;
case 116:
#line 1244 "parse.y"
{ yyval.v.u8 = DIR_IN; }
break;
case 117:
#line 1245 "parse.y"
{ yyval.v.u8 = DIR_OUT; }
break;
case 118:
#line 1248 "parse.y"
{ yyval.v.string = NULL; }
break;
case 119:
#line 1249 "parse.y"
{ yyval.v.string = yyvsp[0].v.string; }
break;
case 121:
#line 1252 "parse.y"
{ yyval.v.filter_peers = yyvsp[-1].v.filter_peers; }
break;
case 122:
#line 1255 "parse.y"
{ yyval.v.filter_peers = yyvsp[0].v.filter_peers; }
break;
case 123:
#line 1256 "parse.y"
{
			yyvsp[0].v.filter_peers->next = yyvsp[-2].v.filter_peers;
			yyval.v.filter_peers = yyvsp[0].v.filter_peers;
		}
break;
case 124:
#line 1262 "parse.y"
{
			if ((yyval.v.filter_peers = calloc(1, sizeof(struct filter_peers_l))) ==
			    NULL)
				fatal(NULL);
			yyval.v.filter_peers->p.peerid = yyval.v.filter_peers->p.groupid = 0;
			yyval.v.filter_peers->next = NULL;
		}
break;
case 125:
#line 1269 "parse.y"
{
			struct peer *p;

			if ((yyval.v.filter_peers = calloc(1, sizeof(struct filter_peers_l))) ==
			    NULL)
				fatal(NULL);
			yyval.v.filter_peers->p.groupid = yyval.v.filter_peers->p.peerid = 0;
			yyval.v.filter_peers->next = NULL;
			for (p = peer_l; p != NULL; p = p->next)
				if (!memcmp(&p->conf.remote_addr,
				    &yyvsp[0].v.addr, sizeof(p->conf.remote_addr))) {
					yyval.v.filter_peers->p.peerid = p->conf.id;
					break;
				}
			if (yyval.v.filter_peers->p.peerid == 0) {
				yyerror("no such peer: %s", log_addr(&yyvsp[0].v.addr));
				free(yyval.v.filter_peers);
				YYERROR;
			}
		}
break;
case 126:
#line 1289 "parse.y"
{
			struct peer *p;

			if ((yyval.v.filter_peers = calloc(1, sizeof(struct filter_peers_l))) ==
			    NULL)
				fatal(NULL);
			yyval.v.filter_peers->p.peerid = 0;
			yyval.v.filter_peers->next = NULL;
			for (p = peer_l; p != NULL; p = p->next)
				if (!strcmp(p->conf.group, yyvsp[0].v.string)) {
					yyval.v.filter_peers->p.groupid = p->conf.groupid;
					break;
				}
			if (yyval.v.filter_peers->p.groupid == 0) {
				yyerror("no such group: \"%s\"", yyvsp[0].v.string);
				free(yyvsp[0].v.string);
				free(yyval.v.filter_peers);
				YYERROR;
			}
			free(yyvsp[0].v.string);
		}
break;
case 127:
#line 1312 "parse.y"
{ yyval.v.filter_prefix = yyvsp[0].v.filter_prefix; }
break;
case 128:
#line 1313 "parse.y"
{ yyval.v.filter_prefix = yyvsp[-1].v.filter_prefix; }
break;
case 130:
#line 1317 "parse.y"
{ yyval.v.filter_prefix = yyvsp[-1].v.filter_prefix; }
break;
case 131:
#line 1319 "parse.y"
{
			struct filter_prefix_l	*p;

			/* merge, both can be lists */
			for (p = yyvsp[-2].v.filter_prefix; p != NULL && p->next != NULL; p = p->next)
				;	/* nothing */
			if (p != NULL)
				p->next = yyvsp[0].v.filter_prefix;
			yyval.v.filter_prefix = yyvsp[-2].v.filter_prefix;
		}
break;
case 132:
#line 1331 "parse.y"
{ yyval.v.filter_prefix = yyvsp[0].v.filter_prefix; }
break;
case 133:
#line 1332 "parse.y"
{
			yyvsp[0].v.filter_prefix->next = yyvsp[-2].v.filter_prefix;
			yyval.v.filter_prefix = yyvsp[0].v.filter_prefix;
		}
break;
case 134:
#line 1338 "parse.y"
{
			if (fmopts.af && fmopts.af != yyvsp[0].v.prefix.prefix.af) {
				yyerror("rules with mixed address families "
				    "are not allowed");
				YYERROR;
			} else
				fmopts.af = yyvsp[0].v.prefix.prefix.af;
			if ((yyval.v.filter_prefix = calloc(1, sizeof(struct filter_prefix_l))) ==
			    NULL)
				fatal(NULL);
			memcpy(&yyval.v.filter_prefix->p.addr, &yyvsp[0].v.prefix.prefix,
			    sizeof(yyval.v.filter_prefix->p.addr));
			yyval.v.filter_prefix->p.len = yyvsp[0].v.prefix.len;
			yyval.v.filter_prefix->next = NULL;
		}
break;
case 136:
#line 1356 "parse.y"
{ yyval.v.filter_as = yyvsp[-1].v.filter_as; }
break;
case 138:
#line 1360 "parse.y"
{
			struct filter_as_l	*a;

			/* merge, both can be lists */
			for (a = yyvsp[-2].v.filter_as; a != NULL && a->next != NULL; a = a->next)
				;	/* nothing */
			if (a != NULL)
				a->next = yyvsp[0].v.filter_as;
			yyval.v.filter_as = yyvsp[-2].v.filter_as;
		}
break;
case 139:
#line 1372 "parse.y"
{
			yyval.v.filter_as = yyvsp[0].v.filter_as;
			yyval.v.filter_as->a.type = yyvsp[-1].v.u8;
		}
break;
case 140:
#line 1376 "parse.y"
{
			struct filter_as_l	*a;

			yyval.v.filter_as = yyvsp[-1].v.filter_as;
			for (a = yyval.v.filter_as; a != NULL; a = a->next)
				a->a.type = yyvsp[-3].v.u8;
		}
break;
case 142:
#line 1386 "parse.y"
{ yyval.v.filter_as = yyvsp[-1].v.filter_as; }
break;
case 143:
#line 1388 "parse.y"
{
			struct filter_as_l	*a;

			/* merge, both can be lists */
			for (a = yyvsp[-2].v.filter_as; a != NULL && a->next != NULL; a = a->next)
				;	/* nothing */
			if (a != NULL)
				a->next = yyvsp[0].v.filter_as;
			yyval.v.filter_as = yyvsp[-2].v.filter_as;
		}
break;
case 145:
#line 1401 "parse.y"
{
			yyvsp[0].v.filter_as->next = yyvsp[-2].v.filter_as;
			yyval.v.filter_as = yyvsp[0].v.filter_as;
		}
break;
case 146:
#line 1407 "parse.y"
{
			if ((yyval.v.filter_as = calloc(1, sizeof(struct filter_as_l))) ==
			    NULL)
				fatal(NULL);
			yyval.v.filter_as->a.as = yyvsp[0].v.number;
		}
break;
case 147:
#line 1415 "parse.y"
{
			bzero(&yyval.v.filter_match, sizeof(yyval.v.filter_match));
			yyval.v.filter_match.m.community.as = COMMUNITY_UNSET;
		}
break;
case 148:
#line 1419 "parse.y"
{
			bzero(&fmopts, sizeof(fmopts));
			fmopts.m.community.as = COMMUNITY_UNSET;
		}
break;
case 149:
#line 1423 "parse.y"
{
			memcpy(&yyval.v.filter_match, &fmopts, sizeof(yyval.v.filter_match));
		}
break;
case 152:
#line 1432 "parse.y"
{
			if (fmopts.prefix_l != NULL) {
				yyerror("\"prefix\" already specified");
				YYERROR;
			}
			fmopts.prefix_l = yyvsp[0].v.filter_prefix;
		}
break;
case 153:
#line 1439 "parse.y"
{
			if (fmopts.af == 0) {
				yyerror("address family needs to be specified "
				    "before \"prefixlen\"");
				YYERROR;
			}
			if (fmopts.m.prefixlen.af) {
				yyerror("\"prefixlen\" already specified");
				YYERROR;
			}
			memcpy(&fmopts.m.prefixlen, &yyvsp[0].v.prefixlen,
			    sizeof(fmopts.m.prefixlen));
			fmopts.m.prefixlen.af = fmopts.af;
		}
break;
case 154:
#line 1453 "parse.y"
{
			if (fmopts.as_l != NULL) {
				yyerror("AS filters already specified");
				YYERROR;
			}
			fmopts.as_l = yyvsp[0].v.filter_as;
		}
break;
case 155:
#line 1460 "parse.y"
{
			if (fmopts.m.community.as != COMMUNITY_UNSET) {
				yyerror("\"community\" already specified");
				free(yyvsp[0].v.string);
				YYERROR;
			}
			if (parsecommunity(yyvsp[0].v.string, &fmopts.m.community.as,
			    &fmopts.m.community.type) == -1) {
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[0].v.string);
		}
break;
case 156:
#line 1473 "parse.y"
{
			if (fmopts.af) {
				yyerror("address family already specified");
				YYERROR;
			}
			fmopts.af = AF_INET;
		}
break;
case 157:
#line 1480 "parse.y"
{
			if (fmopts.af) {
				yyerror("address family already specified");
				YYERROR;
			}
			fmopts.af = AF_INET6;
		}
break;
case 158:
#line 1489 "parse.y"
{
			bzero(&yyval.v.prefixlen, sizeof(yyval.v.prefixlen));
			if (yyvsp[0].v.number < 0 || yyvsp[0].v.number > 128) {
				yyerror("prefixlen must be < 128");
				YYERROR;
			}
			yyval.v.prefixlen.op = yyvsp[-1].v.u8;
			yyval.v.prefixlen.len_min = yyvsp[0].v.number;
		}
break;
case 159:
#line 1498 "parse.y"
{
			bzero(&yyval.v.prefixlen, sizeof(yyval.v.prefixlen));
			if (yyvsp[-2].v.number < 0 || yyvsp[-2].v.number > 128 || yyvsp[0].v.number < 0 || yyvsp[0].v.number > 128) {
				yyerror("prefixlen must be < 128");
				YYERROR;
			}
			if (yyvsp[-2].v.number >= yyvsp[0].v.number) {
				yyerror("start prefixlen is bigger than end");
				YYERROR;
			}
			yyval.v.prefixlen.op = yyvsp[-1].v.u8;
			yyval.v.prefixlen.len_min = yyvsp[-2].v.number;
			yyval.v.prefixlen.len_max = yyvsp[0].v.number;
		}
break;
case 160:
#line 1514 "parse.y"
{ yyval.v.u8 = AS_ALL; }
break;
case 161:
#line 1515 "parse.y"
{ yyval.v.u8 = AS_SOURCE; }
break;
case 162:
#line 1516 "parse.y"
{ yyval.v.u8 = AS_TRANSIT; }
break;
case 163:
#line 1517 "parse.y"
{ yyval.v.u8 = AS_PEER; }
break;
case 164:
#line 1520 "parse.y"
{ yyval.v.filter_set_head = NULL; }
break;
case 165:
#line 1521 "parse.y"
{
			if ((yyval.v.filter_set_head = calloc(1, sizeof(struct filter_set_head))) ==
			    NULL)
				fatal(NULL);
			TAILQ_INIT(yyval.v.filter_set_head);
			TAILQ_INSERT_TAIL(yyval.v.filter_set_head, yyvsp[0].v.filter_set, entry);
		}
break;
case 166:
#line 1528 "parse.y"
{ yyval.v.filter_set_head = yyvsp[-2].v.filter_set_head; }
break;
case 167:
#line 1531 "parse.y"
{
			yyval.v.filter_set_head = yyvsp[-2].v.filter_set_head;
			if (merge_filterset(yyval.v.filter_set_head, yyvsp[0].v.filter_set) == 1)
				YYERROR;
		}
break;
case 168:
#line 1536 "parse.y"
{
			if ((yyval.v.filter_set_head = calloc(1, sizeof(struct filter_set_head))) ==
			    NULL)
				fatal(NULL);
			TAILQ_INIT(yyval.v.filter_set_head);
			TAILQ_INSERT_TAIL(yyval.v.filter_set_head, yyvsp[0].v.filter_set, entry);
		}
break;
case 169:
#line 1545 "parse.y"
{ yyval.v.u8 = 0; }
break;
case 170:
#line 1546 "parse.y"
{ yyval.v.u8 = 1; }
break;
case 171:
#line 1549 "parse.y"
{
			if (yyvsp[0].v.number < -INT_MAX || yyvsp[0].v.number > UINT_MAX) {
				yyerror("bad localpref %lld", yyvsp[0].v.number);
				YYERROR;
			}
			if ((yyval.v.filter_set = calloc(1, sizeof(struct filter_set))) == NULL)
				fatal(NULL);
			if (yyvsp[0].v.number > 0) {
				yyval.v.filter_set->type = ACTION_SET_LOCALPREF;
				yyval.v.filter_set->action.metric = yyvsp[0].v.number;
			} else {
				yyval.v.filter_set->type = ACTION_SET_RELATIVE_LOCALPREF;
				yyval.v.filter_set->action.relative = yyvsp[0].v.number;
			}
		}
break;
case 172:
#line 1564 "parse.y"
{
			if (yyvsp[0].v.number < 0 || yyvsp[0].v.number > INT_MAX) {
				yyerror("bad localpref +%lld", yyvsp[0].v.number);
				YYERROR;
			}
			if ((yyval.v.filter_set = calloc(1, sizeof(struct filter_set))) == NULL)
				fatal(NULL);
			yyval.v.filter_set->type = ACTION_SET_RELATIVE_LOCALPREF;
			yyval.v.filter_set->action.relative = yyvsp[0].v.number;
		}
break;
case 173:
#line 1574 "parse.y"
{
			if (yyvsp[0].v.number < 0 || yyvsp[0].v.number > INT_MAX) {
				yyerror("bad localpref -%lld", yyvsp[0].v.number);
				YYERROR;
			}
			if ((yyval.v.filter_set = calloc(1, sizeof(struct filter_set))) == NULL)
				fatal(NULL);
			yyval.v.filter_set->type = ACTION_SET_RELATIVE_LOCALPREF;
			yyval.v.filter_set->action.relative = -yyvsp[0].v.number;
		}
break;
case 174:
#line 1584 "parse.y"
{
			if (yyvsp[0].v.number < -INT_MAX || yyvsp[0].v.number > UINT_MAX) {
				yyerror("bad metric %lld", yyvsp[0].v.number);
				YYERROR;
			}
			if ((yyval.v.filter_set = calloc(1, sizeof(struct filter_set))) == NULL)
				fatal(NULL);
			if (yyvsp[0].v.number > 0) {
				yyval.v.filter_set->type = ACTION_SET_MED;
				yyval.v.filter_set->action.metric = yyvsp[0].v.number;
			} else {
				yyval.v.filter_set->type = ACTION_SET_RELATIVE_MED;
				yyval.v.filter_set->action.relative = yyvsp[0].v.number;
			}
		}
break;
case 175:
#line 1599 "parse.y"
{
			if (yyvsp[0].v.number < 0 || yyvsp[0].v.number > INT_MAX) {
				yyerror("bad metric +%lld", yyvsp[0].v.number);
				YYERROR;
			}
			if ((yyval.v.filter_set = calloc(1, sizeof(struct filter_set))) == NULL)
				fatal(NULL);
			yyval.v.filter_set->type = ACTION_SET_RELATIVE_MED;
			yyval.v.filter_set->action.relative = yyvsp[0].v.number;
		}
break;
case 176:
#line 1609 "parse.y"
{
			if (yyvsp[0].v.number < 0 || yyvsp[0].v.number > INT_MAX) {
				yyerror("bad metric -%lld", yyvsp[0].v.number);
				YYERROR;
			}
			if ((yyval.v.filter_set = calloc(1, sizeof(struct filter_set))) == NULL)
				fatal(NULL);
			yyval.v.filter_set->type = ACTION_SET_RELATIVE_MED;
			yyval.v.filter_set->action.relative = -yyvsp[0].v.number;
		}
break;
case 177:
#line 1619 "parse.y"
{	/* alias for MED */
			if (yyvsp[0].v.number < -INT_MAX || yyvsp[0].v.number > UINT_MAX) {
				yyerror("bad metric %lld", yyvsp[0].v.number);
				YYERROR;
			}
			if ((yyval.v.filter_set = calloc(1, sizeof(struct filter_set))) == NULL)
				fatal(NULL);
			if (yyvsp[0].v.number > 0) {
				yyval.v.filter_set->type = ACTION_SET_MED;
				yyval.v.filter_set->action.metric = yyvsp[0].v.number;
			} else {
				yyval.v.filter_set->type = ACTION_SET_RELATIVE_MED;
				yyval.v.filter_set->action.relative = yyvsp[0].v.number;
			}
		}
break;
case 178:
#line 1634 "parse.y"
{
			if (yyvsp[0].v.number < 0 || yyvsp[0].v.number > INT_MAX) {
				yyerror("bad metric +%lld", yyvsp[0].v.number);
				YYERROR;
			}
			if ((yyval.v.filter_set = calloc(1, sizeof(struct filter_set))) == NULL)
				fatal(NULL);
			yyval.v.filter_set->type = ACTION_SET_RELATIVE_MED;
			yyval.v.filter_set->action.metric = yyvsp[0].v.number;
		}
break;
case 179:
#line 1644 "parse.y"
{
			if (yyvsp[0].v.number < 0 || yyvsp[0].v.number > INT_MAX) {
				yyerror("bad metric -%lld", yyvsp[0].v.number);
				YYERROR;
			}
			if ((yyval.v.filter_set = calloc(1, sizeof(struct filter_set))) == NULL)
				fatal(NULL);
			yyval.v.filter_set->type = ACTION_SET_RELATIVE_MED;
			yyval.v.filter_set->action.relative = -yyvsp[0].v.number;
		}
break;
case 180:
#line 1654 "parse.y"
{
			if (yyvsp[0].v.number < -INT_MAX || yyvsp[0].v.number > UINT_MAX) {
				yyerror("bad weight %lld", yyvsp[0].v.number);
				YYERROR;
			}
			if ((yyval.v.filter_set = calloc(1, sizeof(struct filter_set))) == NULL)
				fatal(NULL);
			if (yyvsp[0].v.number > 0) {
				yyval.v.filter_set->type = ACTION_SET_WEIGHT;
				yyval.v.filter_set->action.metric = yyvsp[0].v.number;
			} else {
				yyval.v.filter_set->type = ACTION_SET_RELATIVE_WEIGHT;
				yyval.v.filter_set->action.relative = yyvsp[0].v.number;
			}
		}
break;
case 181:
#line 1669 "parse.y"
{
			if (yyvsp[0].v.number < 0 || yyvsp[0].v.number > INT_MAX) {
				yyerror("bad weight +%lld", yyvsp[0].v.number);
				YYERROR;
			}
			if ((yyval.v.filter_set = calloc(1, sizeof(struct filter_set))) == NULL)
				fatal(NULL);
			yyval.v.filter_set->type = ACTION_SET_RELATIVE_WEIGHT;
			yyval.v.filter_set->action.relative = yyvsp[0].v.number;
		}
break;
case 182:
#line 1679 "parse.y"
{
			if (yyvsp[0].v.number < 0 || yyvsp[0].v.number > INT_MAX) {
				yyerror("bad weight -%lld", yyvsp[0].v.number);
				YYERROR;
			}
			if ((yyval.v.filter_set = calloc(1, sizeof(struct filter_set))) == NULL)
				fatal(NULL);
			yyval.v.filter_set->type = ACTION_SET_RELATIVE_WEIGHT;
			yyval.v.filter_set->action.relative = -yyvsp[0].v.number;
		}
break;
case 183:
#line 1689 "parse.y"
{
			if ((yyval.v.filter_set = calloc(1, sizeof(struct filter_set))) == NULL)
				fatal(NULL);
			yyval.v.filter_set->type = ACTION_SET_NEXTHOP;
			memcpy(&yyval.v.filter_set->action.nexthop, &yyvsp[0].v.addr,
			    sizeof(yyval.v.filter_set->action.nexthop));
		}
break;
case 184:
#line 1696 "parse.y"
{
			if ((yyval.v.filter_set = calloc(1, sizeof(struct filter_set))) == NULL)
				fatal(NULL);
			yyval.v.filter_set->type = ACTION_SET_NEXTHOP_BLACKHOLE;
		}
break;
case 185:
#line 1701 "parse.y"
{
			if ((yyval.v.filter_set = calloc(1, sizeof(struct filter_set))) == NULL)
				fatal(NULL);
			yyval.v.filter_set->type = ACTION_SET_NEXTHOP_REJECT;
		}
break;
case 186:
#line 1706 "parse.y"
{
			if ((yyval.v.filter_set = calloc(1, sizeof(struct filter_set))) == NULL)
				fatal(NULL);
			yyval.v.filter_set->type = ACTION_SET_NEXTHOP_NOMODIFY;
		}
break;
case 187:
#line 1711 "parse.y"
{
			if ((yyval.v.filter_set = calloc(1, sizeof(struct filter_set))) == NULL)
				fatal(NULL);
			yyval.v.filter_set->type = ACTION_SET_NEXTHOP_SELF;
		}
break;
case 188:
#line 1716 "parse.y"
{
			if (yyvsp[0].v.number < 0 || yyvsp[0].v.number > 128) {
				yyerror("bad number of prepends");
				YYERROR;
			}
			if ((yyval.v.filter_set = calloc(1, sizeof(struct filter_set))) == NULL)
				fatal(NULL);
			yyval.v.filter_set->type = ACTION_SET_PREPEND_SELF;
			yyval.v.filter_set->action.prepend = yyvsp[0].v.number;
		}
break;
case 189:
#line 1726 "parse.y"
{
			if (yyvsp[0].v.number < 0 || yyvsp[0].v.number > 128) {
				yyerror("bad number of prepends");
				YYERROR;
			}
			if ((yyval.v.filter_set = calloc(1, sizeof(struct filter_set))) == NULL)
				fatal(NULL);
			yyval.v.filter_set->type = ACTION_SET_PREPEND_PEER;
			yyval.v.filter_set->action.prepend = yyvsp[0].v.number;
		}
break;
case 190:
#line 1736 "parse.y"
{
			if ((yyval.v.filter_set = calloc(1, sizeof(struct filter_set))) == NULL)
				fatal(NULL);
			yyval.v.filter_set->type = ACTION_PFTABLE;
			if (!(conf->opts & BGPD_OPT_NOACTION) &&
			    pftable_exists(yyvsp[0].v.string) != 0) {
				yyerror("pftable name does not exist");
				free(yyvsp[0].v.string);
				free(yyval.v.filter_set);
				YYERROR;
			}
			if (strlcpy(yyval.v.filter_set->action.pftable, yyvsp[0].v.string,
			    sizeof(yyval.v.filter_set->action.pftable)) >=
			    sizeof(yyval.v.filter_set->action.pftable)) {
				yyerror("pftable name too long");
				free(yyvsp[0].v.string);
				free(yyval.v.filter_set);
				YYERROR;
			}
			if (pftable_add(yyvsp[0].v.string) != 0) {
				yyerror("Couldn't register table");
				free(yyvsp[0].v.string);
				free(yyval.v.filter_set);
				YYERROR;
			}
			free(yyvsp[0].v.string);
		}
break;
case 191:
#line 1763 "parse.y"
{
			if ((yyval.v.filter_set = calloc(1, sizeof(struct filter_set))) == NULL)
				fatal(NULL);
			yyval.v.filter_set->type = ACTION_RTLABEL;
			if (strlcpy(yyval.v.filter_set->action.rtlabel, yyvsp[0].v.string,
			    sizeof(yyval.v.filter_set->action.rtlabel)) >=
			    sizeof(yyval.v.filter_set->action.rtlabel)) {
				yyerror("rtlabel name too long");
				free(yyvsp[0].v.string);
				free(yyval.v.filter_set);
				YYERROR;
			}
			free(yyvsp[0].v.string);
		}
break;
case 192:
#line 1777 "parse.y"
{
			if ((yyval.v.filter_set = calloc(1, sizeof(struct filter_set))) == NULL)
				fatal(NULL);
			if (yyvsp[-1].v.u8)
				yyval.v.filter_set->type = ACTION_DEL_COMMUNITY;
			else
				yyval.v.filter_set->type = ACTION_SET_COMMUNITY;

			if (parsecommunity(yyvsp[0].v.string, &yyval.v.filter_set->action.community.as,
			    &yyval.v.filter_set->action.community.type) == -1) {
				free(yyvsp[0].v.string);
				free(yyval.v.filter_set);
				YYERROR;
			}
			free(yyvsp[0].v.string);
			/* Don't allow setting of any match */
			if (!yyvsp[-1].v.u8 && (yyval.v.filter_set->action.community.as == COMMUNITY_ANY ||
			    yyval.v.filter_set->action.community.type == COMMUNITY_ANY)) {
				yyerror("'*' is not allowed in set community");
				free(yyval.v.filter_set);
				YYERROR;
			}
			/* Don't allow setting of unknown well-known types */
			if (yyval.v.filter_set->action.community.as == COMMUNITY_WELLKNOWN) {
				switch (yyval.v.filter_set->action.community.type) {
				case COMMUNITY_NO_EXPORT:
				case COMMUNITY_NO_ADVERTISE:
				case COMMUNITY_NO_EXPSUBCONFED:
				case COMMUNITY_NO_PEER:
					/* valid */
					break;
				default:
					/* unknown */
					yyerror("Invalid well-known community");
					free(yyval.v.filter_set);
					YYERROR;
					break;
				}
			}
		}
break;
case 195:
#line 1823 "parse.y"
{ yyval.v.u8 = OP_EQ; }
break;
case 196:
#line 1824 "parse.y"
{ yyval.v.u8 = OP_NE; }
break;
case 197:
#line 1825 "parse.y"
{ yyval.v.u8 = OP_LE; }
break;
case 198:
#line 1826 "parse.y"
{ yyval.v.u8 = OP_LT; }
break;
case 199:
#line 1827 "parse.y"
{ yyval.v.u8 = OP_GE; }
break;
case 200:
#line 1828 "parse.y"
{ yyval.v.u8 = OP_GT; }
break;
case 201:
#line 1831 "parse.y"
{ yyval.v.u8 = OP_RANGE; }
break;
case 202:
#line 1832 "parse.y"
{ yyval.v.u8 = OP_XRANGE; }
break;
#line 4209 "y.tab.c"
    }
    yyssp -= yym;
    yystate = *yyssp;
    yyvsp -= yym;
    yym = yylhs[yyn];
    if (yystate == 0 && yym == 0)
    {
#if YYDEBUG
        if (yydebug)
            printf("%sdebug: after reduction, shifting from state 0 to\
 state %d\n", YYPREFIX, YYFINAL);
#endif
        yystate = YYFINAL;
        *++yyssp = YYFINAL;
        *++yyvsp = yyval;
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
to state %d\n", YYPREFIX, *yyssp, yystate);
#endif
    if (yyssp >= yysslim && yygrowstack())
    {
        goto yyoverflow;
    }
    *++yyssp = yystate;
    *++yyvsp = yyval;
    goto yyloop;
yyoverflow:
    yyerror("yacc stack overflow");
yyabort:
    if (yyss)
            free(yyss);
    if (yyvs)
            free(yyvs);
    yyss = yyssp = NULL;
    yyvs = yyvsp = NULL;
    yystacksize = 0;
    return (1);
yyaccept:
    if (yyss)
            free(yyss);
    if (yyvs)
            free(yyvs);
    yyss = yyssp = NULL;
    yyvs = yyvsp = NULL;
    yystacksize = 0;
    return (0);
}
