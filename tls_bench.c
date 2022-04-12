/* tls_bench.c
 *
 * Copyright (C) 2006-2021 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */


/*
Example gcc build statement

  gcc -lwolfssl -lpthread -o tls_bench tls_bench.c
  ./tls_bench

Or

  #include <examples/benchmark/tls_bench.h>
  bench_tls(args);
*/

#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/tfm.h>
//#include <wolfcrypt/src/tfm.c>

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif
#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/hash.h> /* WC_MAX_DIGEST_SIZE */
#include <wolfssl/test.h>
#include <wolfssl/wolfio.h>
#include <examples/benchmark/tls_bench.h>



/* force certificate test buffers to be included via headers */
#undef  USE_CERT_BUFFERS_2048
#define USE_CERT_BUFFERS_2048
#undef  USE_CERT_BUFFERS_256
#define USE_CERT_BUFFERS_256
#include <wolfssl/certs_test.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <errno.h>

/* For testing no pthread support */
#if 0
    #undef HAVE_PTHREAD
#endif

/* PTHREAD requires server and client enabled */
#if defined(HAVE_PTHREAD) && (defined(NO_WOLFSSL_CLIENT) || defined(NO_WOLFSSL_SERVER))
    #undef HAVE_PTHREAD
#endif

#ifdef HAVE_PTHREAD
    #include <pthread.h>
#endif

#if 0
#define BENCH_USE_NONBLOCK
#endif

/* Defaults for configuration parameters */
#define BENCH_DEFAULT_HOST  "localhost"
#define BENCH_DEFAULT_PORT  11112
#define NUM_THREAD_PAIRS    1 /* Thread pairs of server/client */
#ifndef BENCH_RUNTIME_SEC
    #ifdef BENCH_EMBEDDED
        #define BENCH_RUNTIME_SEC   15
    #else
        #define BENCH_RUNTIME_SEC   1
    #endif
#endif
/* TLS packet size */
#ifndef TEST_PACKET_SIZE
    #ifdef BENCH_EMBEDDED
        #define TEST_PACKET_SIZE    (2 * 1024)
    #else
        #define TEST_PACKET_SIZE    (16 * 1024)
    #endif
#endif
/* Total bytes to benchmark per connection */
#ifndef TEST_MAX_SIZE
    #ifdef BENCH_EMBEDDED
        #define TEST_MAX_SIZE       (16 * 1024)
    #else
        #define TEST_MAX_SIZE       (128 * 1024)
    #endif
#endif

#ifdef WOLFSSL_DTLS
    #ifdef BENCH_EMBEDDED
        /* WOLFSSL_MAX_MTU in internal.h */
        #define TEST_DTLS_PACKET_SIZE   (1500)
    #else
        /* MAX_UDP_SIZE in interna.h */
        #define TEST_DTLS_PACKET_SIZE   (8092)
    #endif
#endif

/* In memory transfer buffer maximum size */
/* Must be large enough to handle max TLS packet size plus max TLS header MAX_MSG_EXTRA */
#define MEM_BUFFER_SZ       (TEST_PACKET_SIZE + 38 + WC_MAX_DIGEST_SIZE)
#define SHOW_VERBOSE        0 /* Default output is tab delimited format */

#if (!defined(NO_WOLFSSL_CLIENT) || !defined(NO_WOLFSSL_SERVER)) && \
    !defined(WOLFCRYPT_ONLY) && defined(USE_WOLFSSL_IO)

/* shutdown message - nice signal to server, we are done */
static const char* kShutdown = "shutdown";

#ifndef NO_WOLFSSL_CLIENT
PEDANTIC_EXTENSION static const char* kTestStr =
"Biodiesel cupidatat marfa, cliche aute put a bird on it incididunt elit\n"
"polaroid. Sunt tattooed bespoke reprehenderit. Sint twee organic id\n"
"marfa. Commodo veniam ad esse gastropub. 3 wolf moon sartorial vero,\n"
"plaid delectus biodiesel squid +1 vice. Post-ironic keffiyeh leggings\n"
"selfies cray fap hoodie, forage anim. Carles cupidatat shoreditch, VHS\n"
"small batch meggings kogi dolore food truck bespoke gastropub.\n"
"\n"
"Terry richardson adipisicing actually typewriter tumblr, twee whatever\n"
"four loko you probably haven't heard of them high life. Messenger bag\n"
"whatever tattooed deep v mlkshk. Brooklyn pinterest assumenda chillwave\n"
"et, banksy ullamco messenger bag umami pariatur direct trade forage.\n"
"Typewriter culpa try-hard, pariatur sint brooklyn meggings. Gentrify\n"
"food truck next level, tousled irony non semiotics PBR ethical anim cred\n"
"readymade. Mumblecore brunch lomo odd future, portland organic terry\n"
"richardson elit leggings adipisicing ennui raw denim banjo hella. Godard\n"
"mixtape polaroid, pork belly readymade organic cray typewriter helvetica\n"
"four loko whatever street art yr farm-to-table.\n"
"\n"
"Vinyl keytar vice tofu. Locavore you probably haven't heard of them pug\n"
"pickled, hella tonx labore truffaut DIY mlkshk elit cosby sweater sint\n"
"et mumblecore. Elit swag semiotics, reprehenderit DIY sartorial nisi ugh\n"
"nesciunt pug pork belly wayfarers selfies delectus. Ethical hoodie\n"
"seitan fingerstache kale chips. Terry richardson artisan williamsburg,\n"
"eiusmod fanny pack irony tonx ennui lo-fi incididunt tofu YOLO\n"
"readymade. 8-bit sed ethnic beard officia. Pour-over iphone DIY butcher,\n"
"ethnic art party qui letterpress nisi proident jean shorts mlkshk\n"
"locavore.\n"
"\n"
"Narwhal flexitarian letterpress, do gluten-free voluptate next level\n"
"banh mi tonx incididunt carles DIY. Odd future nulla 8-bit beard ut\n"
"cillum pickled velit, YOLO officia you probably haven't heard of them\n"
"trust fund gastropub. Nisi adipisicing tattooed, Austin mlkshk 90's\n"
"small batch american apparel. Put a bird on it cosby sweater before they\n"
"sold out pork belly kogi hella. Street art mollit sustainable polaroid,\n"
"DIY ethnic ea pug beard dreamcatcher cosby sweater magna scenester nisi.\n"
"Sed pork belly skateboard mollit, labore proident eiusmod. Sriracha\n"
"excepteur cosby sweater, anim deserunt laborum eu aliquip ethical et\n"
"neutra PBR selvage.\n"
"\n"
"Raw denim pork belly truffaut, irony plaid sustainable put a bird on it\n"
"next level jean shorts exercitation. Hashtag keytar whatever, nihil\n"
"authentic aliquip disrupt laborum. Tattooed selfies deserunt trust fund\n"
"wayfarers. 3 wolf moon synth church-key sartorial, gastropub leggings\n"
"tattooed. Labore high life commodo, meggings raw denim fingerstache pug\n"
"trust fund leggings seitan forage. Nostrud ullamco duis, reprehenderit\n"
"incididunt flannel sustainable helvetica pork belly pug banksy you\n"
"probably haven't heard of them nesciunt farm-to-table. Disrupt nostrud\n"
"mollit magna, sriracha sartorial helvetica.\n"
"\n"
"Nulla kogi reprehenderit, skateboard sustainable duis adipisicing viral\n"
"ad fanny pack salvia. Fanny pack trust fund you probably haven't heard\n"
"of them YOLO vice nihil. Keffiyeh cray lo-fi pinterest cardigan aliqua,\n"
"reprehenderit aute. Culpa tousled williamsburg, marfa lomo actually anim\n"
"skateboard. Iphone aliqua ugh, semiotics pariatur vero readymade\n"
"organic. Marfa squid nulla, in laborum disrupt laboris irure gastropub.\n"
"Veniam sunt food truck leggings, sint vinyl fap.\n"
"\n"
"Hella dolore pork belly, truffaut carles you probably haven't heard of\n"
"them PBR helvetica in sapiente. Fashion axe ugh bushwick american\n"
"apparel. Fingerstache sed iphone, jean shorts blue bottle nisi bushwick\n"
"flexitarian officia veniam plaid bespoke fap YOLO lo-fi. Blog\n"
"letterpress mumblecore, food truck id cray brooklyn cillum ad sed.\n"
"Assumenda chambray wayfarers vinyl mixtape sustainable. VHS vinyl\n"
"delectus, culpa williamsburg polaroid cliche swag church-key synth kogi\n"
"magna pop-up literally. Swag thundercats ennui shoreditch vegan\n"
"pitchfork neutra truffaut etsy, sed single-origin coffee craft beer.\n"
"\n"
"Odio letterpress brooklyn elit. Nulla single-origin coffee in occaecat\n"
"meggings. Irony meggings 8-bit, chillwave lo-fi adipisicing cred\n"
"dreamcatcher veniam. Put a bird on it irony umami, trust fund bushwick\n"
"locavore kale chips. Sriracha swag thundercats, chillwave disrupt\n"
"tousled beard mollit mustache leggings portland next level. Nihil esse\n"
"est, skateboard art party etsy thundercats sed dreamcatcher ut iphone\n"
"swag consectetur et. Irure skateboard banjo, nulla deserunt messenger\n"
"bag dolor terry richardson sapiente.\n";
#endif

#if !defined(NO_DH)

#define MIN_DHKEY_BITS      1024

#if !defined(NO_WOLFSSL_SERVER)
/* dh2048 p */
static const unsigned char dhp[] =
{
    0xb0, 0xa1, 0x08, 0x06, 0x9c, 0x08, 0x13, 0xba, 0x59, 0x06, 0x3c, 0xbc, 0x30,
    0xd5, 0xf5, 0x00, 0xc1, 0x4f, 0x44, 0xa7, 0xd6, 0xef, 0x4a, 0xc6, 0x25, 0x27,
    0x1c, 0xe8, 0xd2, 0x96, 0x53, 0x0a, 0x5c, 0x91, 0xdd, 0xa2, 0xc2, 0x94, 0x84,
    0xbf, 0x7d, 0xb2, 0x44, 0x9f, 0x9b, 0xd2, 0xc1, 0x8a, 0xc5, 0xbe, 0x72, 0x5c,
    0xa7, 0xe7, 0x91, 0xe6, 0xd4, 0x9f, 0x73, 0x07, 0x85, 0x5b, 0x66, 0x48, 0xc7,
    0x70, 0xfa, 0xb4, 0xee, 0x02, 0xc9, 0x3d, 0x9a, 0x4a, 0xda, 0x3d, 0xc1, 0x46,
    0x3e, 0x19, 0x69, 0xd1, 0x17, 0x46, 0x07, 0xa3, 0x4d, 0x9f, 0x2b, 0x96, 0x17,
    0x39, 0x6d, 0x30, 0x8d, 0x2a, 0xf3, 0x94, 0xd3, 0x75, 0xcf, 0xa0, 0x75, 0xe6,
    0xf2, 0x92, 0x1f, 0x1a, 0x70, 0x05, 0xaa, 0x04, 0x83, 0x57, 0x30, 0xfb, 0xda,
    0x76, 0x93, 0x38, 0x50, 0xe8, 0x27, 0xfd, 0x63, 0xee, 0x3c, 0xe5, 0xb7, 0xc8,
    0x09, 0xae, 0x6f, 0x50, 0x35, 0x8e, 0x84, 0xce, 0x4a, 0x00, 0xe9, 0x12, 0x7e,
    0x5a, 0x31, 0xd7, 0x33, 0xfc, 0x21, 0x13, 0x76, 0xcc, 0x16, 0x30, 0xdb, 0x0c,
    0xfc, 0xc5, 0x62, 0xa7, 0x35, 0xb8, 0xef, 0xb7, 0xb0, 0xac, 0xc0, 0x36, 0xf6,
    0xd9, 0xc9, 0x46, 0x48, 0xf9, 0x40, 0x90, 0x00, 0x2b, 0x1b, 0xaa, 0x6c, 0xe3,
    0x1a, 0xc3, 0x0b, 0x03, 0x9e, 0x1b, 0xc2, 0x46, 0xe4, 0x48, 0x4e, 0x22, 0x73,
    0x6f, 0xc3, 0x5f, 0xd4, 0x9a, 0xd6, 0x30, 0x07, 0x48, 0xd6, 0x8c, 0x90, 0xab,
    0xd4, 0xf6, 0xf1, 0xe3, 0x48, 0xd3, 0x58, 0x4b, 0xa6, 0xb9, 0xcd, 0x29, 0xbf,
    0x68, 0x1f, 0x08, 0x4b, 0x63, 0x86, 0x2f, 0x5c, 0x6b, 0xd6, 0xb6, 0x06, 0x65,
    0xf7, 0xa6, 0xdc, 0x00, 0x67, 0x6b, 0xbb, 0xc3, 0xa9, 0x41, 0x83, 0xfb, 0xc7,
    0xfa, 0xc8, 0xe2, 0x1e, 0x7e, 0xaf, 0x00, 0x3f, 0x93
};

/* dh2048 g */
static const unsigned char dhg[] =
{
    0x02,
};
#endif /* !NO_WOLFSSL_SERVER */
#endif /* !NO_DH */

#if defined(WOLFSSL_TLS13) && defined(HAVE_SUPPORTED_CURVES)
struct group_info {
    word16 group;
    const char *name;
};

static struct group_info groups[] = {
    { WOLFSSL_ECC_SECP160K1, "ECC_SECP160K1" },
    { WOLFSSL_ECC_SECP160R1, "ECC_SECP160R1" },
    { WOLFSSL_ECC_SECP160R2, "ECC_SECP160R2" },
    { WOLFSSL_ECC_SECP192K1, "ECC_SECP192K1" },
    { WOLFSSL_ECC_SECP192R1, "ECC_SECP192R1" },
    { WOLFSSL_ECC_SECP224K1, "ECC_SECP224K1" },
    { WOLFSSL_ECC_SECP224R1, "ECC_SECP224R1" },
    { WOLFSSL_ECC_SECP256K1, "ECC_SECP256K1" },
    { WOLFSSL_ECC_SECP256R1, "ECC_SECP256R1" },
    { WOLFSSL_ECC_SECP384R1, "ECC_SECP384R1" },
    { WOLFSSL_ECC_SECP521R1, "ECC_SECP521R1" },
    { WOLFSSL_ECC_BRAINPOOLP256R1, "ECC_BRAINPOOLP256R1" },
    { WOLFSSL_ECC_BRAINPOOLP384R1, "ECC_BRAINPOOLP384R1" },
    { WOLFSSL_ECC_BRAINPOOLP512R1, "ECC_BRAINPOOLP512R1" },
    { WOLFSSL_ECC_X25519, "ECC_X25519" },
    { WOLFSSL_ECC_X448, "ECC_X448" },
    { WOLFSSL_FFDHE_2048, "FFDHE_2048" },
    { WOLFSSL_FFDHE_3072, "FFDHE_3072" },
    { WOLFSSL_FFDHE_4096, "FFDHE_4096" },
    { WOLFSSL_FFDHE_6144, "FFDHE_6144" },
    { WOLFSSL_FFDHE_8192, "FFDHE_8192" },
#ifdef HAVE_PQC
    { WOLFSSL_NTRU_HPS_LEVEL1, "NTRU_HPS_LEVEL1" },
    { WOLFSSL_NTRU_HPS_LEVEL3, "NTRU_HPS_LEVEL3" },
    { WOLFSSL_NTRU_HPS_LEVEL5, "NTRU_HPS_LEVEL5" },
    { WOLFSSL_NTRU_HRSS_LEVEL3, "NTRU_HRSS_LEVEL3" },
    { WOLFSSL_SABER_LEVEL1, "SABER_LEVEL1" },
    { WOLFSSL_SABER_LEVEL3, "SABER_LEVEL3" },
    { WOLFSSL_SABER_LEVEL5, "SABER_LEVEL5" },
    { WOLFSSL_KYBER_LEVEL1, "KYBER_LEVEL1" },
    { WOLFSSL_KYBER_LEVEL3, "KYBER_LEVEL3" },
    { WOLFSSL_KYBER_LEVEL5, "KYBER_LEVEL5" },
    { WOLFSSL_KYBER_90S_LEVEL1, "KYBER_90S_LEVEL1" },
    { WOLFSSL_KYBER_90S_LEVEL3, "KYBER_90S_LEVEL3" },
    { WOLFSSL_KYBER_90S_LEVEL5, "KYBER_90S_LEVEL5" },
    { WOLFSSL_P256_NTRU_HPS_LEVEL1, "P256_NTRU_HPS_LEVEL1" },
    { WOLFSSL_P384_NTRU_HPS_LEVEL3, "P384_NTRU_HPS_LEVEL3" },
    { WOLFSSL_P521_NTRU_HPS_LEVEL5, "P521_NTRU_HPS_LEVEL5" },
    { WOLFSSL_P384_NTRU_HRSS_LEVEL3, "P384_NTRU_HRSS_LEVEL3" },
    { WOLFSSL_P256_SABER_LEVEL1, "P256_SABER_LEVEL1" },
    { WOLFSSL_P384_SABER_LEVEL3, "P384_SABER_LEVEL3" },
    { WOLFSSL_P521_SABER_LEVEL5, "P521_SABER_LEVEL5" },
    { WOLFSSL_P256_KYBER_LEVEL1, "P256_KYBER_LEVEL1" },
    { WOLFSSL_P384_KYBER_LEVEL3, "P384_KYBER_LEVEL3" },
    { WOLFSSL_P521_KYBER_LEVEL5, "P521_KYBER_LEVEL5" },
    { WOLFSSL_P256_KYBER_90S_LEVEL1, "P256_KYBER_90S_LEVEL1" },
    { WOLFSSL_P384_KYBER_90S_LEVEL3, "P384_KYBER_90S_LEVEL3" },
    { WOLFSSL_P521_KYBER_90S_LEVEL5, "P521_KYBER_90S_LEVEL5" },
#endif
    { 0, NULL }
};
#endif /* WOLFSSL_TLS13 && HAVE_SUPPORTED_CURVES */

#ifdef HAVE_PTHREAD
typedef struct {
    unsigned char buf[MEM_BUFFER_SZ];
    int write_bytes;
    int write_idx;
    int read_bytes;
    int read_idx;

    pthread_t tid;
    pthread_mutex_t mutex;
    pthread_cond_t cond;

    int done;
} memBuf_t;
#endif

typedef struct {
    double connTime;
    double rxTime;
    double txTime;
    int connCount;
    int rxTotal;
    int txTotal;
} stats_t;

typedef struct {
    int shutdown;
    int sockFd;
    int ret;
} side_t;

typedef struct {
    const char* cipher;
    word16 group;
    const char* host;
    word32 port;
    int packetSize; /* The data payload size in the packet */
    int maxSize;
    int runTimeSec;
    int showPeerInfo;
    int showVerbose;
#ifndef NO_WOLFSSL_SERVER
    int listenFd;
#endif
#ifdef WOLFSSL_DTLS
    int doDTLS;
    struct sockaddr_in serverAddr;
    struct sockaddr_in clientAddr;
#ifdef HAVE_PTHREAD
    int serverReady;
    int clientOrserverOnly;
    pthread_mutex_t dtls_mutex;
    pthread_cond_t dtls_cond;
#endif
#endif
    side_t client;
    side_t server;

#ifdef HAVE_PTHREAD
    int useLocalMem;

    /* client messages to server in memory */
    memBuf_t to_server;

    /* server messages to client in memory */
    memBuf_t to_client;

    /* Indicates that the server is ready for connection */
    int serverListening;
#endif

    /* server */
    stats_t server_stats;

    /* client */
    stats_t client_stats;
} info_t;

/* Global vars for argument parsing */
int myoptind = 0;
char* myoptarg = NULL;

#ifdef WOLFSSL_DTLS
int DoneHandShake = 0;
#endif

static double gettime_secs(int reset)
{
    struct timeval tv;
    gettimeofday(&tv, 0);
    (void)reset;

    return (double)tv.tv_sec + (double)tv.tv_usec / 1000000;
}


#ifdef HAVE_PTHREAD
/* server send callback */
static int ServerMemSend(info_t* info, char* buf, int sz)
{
    pthread_mutex_lock(&info->to_client.mutex);

#ifndef BENCH_USE_NONBLOCK
    /* check for overflow */
    if (info->to_client.write_idx + sz > MEM_BUFFER_SZ) {
        pthread_mutex_unlock(&info->to_client.mutex);
        fprintf(stderr, "ServerMemSend overflow\n");
        return -1;
    }
#else
    if (info->to_client.write_idx + sz > MEM_BUFFER_SZ)
        sz = MEM_BUFFER_SZ - info->to_client.write_idx;
#endif

    XMEMCPY(&info->to_client.buf[info->to_client.write_idx], buf, sz);
    info->to_client.write_idx += sz;
    info->to_client.write_bytes += sz;

    pthread_cond_signal(&info->to_client.cond);
    pthread_mutex_unlock(&info->to_client.mutex);

#ifdef BENCH_USE_NONBLOCK
    if (sz == 0)
        return WOLFSSL_CBIO_ERR_WANT_WRITE;
#endif
    return sz;
}

/* server recv callback */
static int ServerMemRecv(info_t* info, char* buf, int sz)
{
    pthread_mutex_lock(&info->to_server.mutex);

#ifndef BENCH_USE_NONBLOCK
    while (info->to_server.write_idx - info->to_server.read_idx < sz && !info->to_client.done)
        pthread_cond_wait(&info->to_server.cond, &info->to_server.mutex);
#else
    if (info->to_server.write_idx - info->to_server.read_idx < sz)
        sz = info->to_server.write_idx - info->to_server.read_idx;
#endif

    XMEMCPY(buf, &info->to_server.buf[info->to_server.read_idx], sz);
    info->to_server.read_idx += sz;
    info->to_server.read_bytes += sz;

    /* if the rx has caught up with pending then reset buffer positions */
    if (info->to_server.read_bytes == info->to_server.write_bytes) {
        info->to_server.read_bytes = info->to_server.read_idx = 0;
        info->to_server.write_bytes = info->to_server.write_idx = 0;
    }

    pthread_mutex_unlock(&info->to_server.mutex);

    if (info->to_client.done != 0)
        return -1;

#ifdef BENCH_USE_NONBLOCK
    if (sz == 0)
        return WOLFSSL_CBIO_ERR_WANT_READ;
#endif
    return sz;
}

/* client send callback */
static int ClientMemSend(info_t* info, char* buf, int sz)
{
    pthread_mutex_lock(&info->to_server.mutex);

#ifndef BENCH_USE_NONBLOCK
    /* check for overflow */
    if (info->to_server.write_idx + sz > MEM_BUFFER_SZ) {
        fprintf(stderr, "ClientMemSend overflow %d %d %d\n", info->to_server.write_idx, sz, MEM_BUFFER_SZ);
        pthread_mutex_unlock(&info->to_server.mutex);
        return -1;
    }
#else
    if (info->to_server.write_idx + sz > MEM_BUFFER_SZ)
        sz = MEM_BUFFER_SZ - info->to_server.write_idx;
#endif

    XMEMCPY(&info->to_server.buf[info->to_server.write_idx], buf, sz);
    info->to_server.write_idx += sz;
    info->to_server.write_bytes += sz;

    pthread_cond_signal(&info->to_server.cond);
    pthread_mutex_unlock(&info->to_server.mutex);

#ifdef BENCH_USE_NONBLOCK
    if (sz == 0)
        return WOLFSSL_CBIO_ERR_WANT_WRITE;
#endif
    return sz;
}

/* client recv callback */
static int ClientMemRecv(info_t* info, char* buf, int sz)
{
    pthread_mutex_lock(&info->to_client.mutex);

#ifndef BENCH_USE_NONBLOCK
    while (info->to_client.write_idx - info->to_client.read_idx < sz)
        pthread_cond_wait(&info->to_client.cond, &info->to_client.mutex);
#else
    if (info->to_client.write_idx - info->to_client.read_idx < sz)
        sz = info->to_client.write_idx - info->to_client.read_idx;
#endif

    XMEMCPY(buf, &info->to_client.buf[info->to_client.read_idx], sz);
    info->to_client.read_idx += sz;
    info->to_client.read_bytes += sz;

    /* if the rx has caught up with pending then reset buffer positions */
    if (info->to_client.read_bytes == info->to_client.write_bytes) {
        info->to_client.read_bytes = info->to_client.read_idx = 0;
        info->to_client.write_bytes = info->to_client.write_idx = 0;
    }

    pthread_mutex_unlock(&info->to_client.mutex);

#ifdef BENCH_USE_NONBLOCK
    if (sz == 0)
        return WOLFSSL_CBIO_ERR_WANT_READ;
#endif
    return sz;
}
#endif /* HAVE_PTHREAD */

static int SocketRecv(int sockFd, char* buf, int sz)
{
    int recvd = (int)recv(sockFd, buf, sz, 0);
    if (recvd == -1) {
        switch (errno) {
    #if EAGAIN != SOCKET_EWOULDBLOCK
        case EAGAIN: /* EAGAIN == EWOULDBLOCK on some systems, but not others */
    #endif
        case SOCKET_EWOULDBLOCK:
            return WOLFSSL_CBIO_ERR_WANT_READ;
        case SOCKET_ECONNRESET:
            return WOLFSSL_CBIO_ERR_CONN_RST;
        case SOCKET_EINTR:
            return WOLFSSL_CBIO_ERR_ISR;
        case SOCKET_ECONNREFUSED: /* DTLS case */
            return WOLFSSL_CBIO_ERR_WANT_READ;
        case SOCKET_ECONNABORTED:
            return WOLFSSL_CBIO_ERR_CONN_CLOSE;
        default:
            return WOLFSSL_CBIO_ERR_GENERAL;
        }
    }
    else if (recvd == 0) {
        return WOLFSSL_CBIO_ERR_CONN_CLOSE;
    }
    return recvd;
}

static int SocketSend(int sockFd, char* buf, int sz)
{
    int sent = (int)send(sockFd, buf, sz, 0);
    if (sent == -1) {
        switch (errno) {
    #if EAGAIN != SOCKET_EWOULDBLOCK
        case EAGAIN: /* EAGAIN == EWOULDBLOCK on some systems, but not others */
    #endif
        case SOCKET_EWOULDBLOCK:
            return WOLFSSL_CBIO_ERR_WANT_READ;
        case SOCKET_ECONNRESET:
            return WOLFSSL_CBIO_ERR_CONN_RST;
        case SOCKET_EINTR:
            return WOLFSSL_CBIO_ERR_ISR;
        case SOCKET_EPIPE:
            return WOLFSSL_CBIO_ERR_CONN_CLOSE;
        default:
            return WOLFSSL_CBIO_ERR_GENERAL;
        }
    }
    else if (sent == 0) {
        return 0;
    }
    return sent;
}
#if defined(WOLFSSL_DTLS) && !defined(NO_WOLFSSL_SERVER)
static int ReceiveFrom(WOLFSSL *ssl, int sd, char *buf, int sz)
{
    int recvd;
    int dtls_timeout = wolfSSL_dtls_get_current_timeout(ssl);
    struct sockaddr peer;
    socklen_t peerSz = 0;

    if (DoneHandShake) dtls_timeout = 0;

    if (!wolfSSL_get_using_nonblock(ssl)) {
        struct timeval timeout;
        XMEMSET(&timeout, 0, sizeof(timeout));
        timeout.tv_sec = dtls_timeout;

        if (setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout,
                       sizeof(timeout)) != 0) {
                fprintf(stderr, "setsockopt rcvtimeo failed\n");
        }
    }

    recvd = (int)recvfrom(sd, buf, sz, 0, (SOCKADDR*)&peer, &peerSz);

    if (recvd < 0) {

        if (errno == SOCKET_EWOULDBLOCK || errno == SOCKET_EAGAIN) {
            if (wolfSSL_dtls_get_using_nonblock(ssl)) {
                return WOLFSSL_CBIO_ERR_WANT_READ;
            }
            else {
                return WOLFSSL_CBIO_ERR_TIMEOUT;
            }
        }
        else if (errno == SOCKET_ECONNRESET) {
            return WOLFSSL_CBIO_ERR_CONN_RST;
        }
        else if (errno == SOCKET_EINTR) {
            return WOLFSSL_CBIO_ERR_ISR;
        }
        else if (errno == SOCKET_ECONNREFUSED) {
            return WOLFSSL_CBIO_ERR_WANT_READ;
        }
        else {
            return WOLFSSL_CBIO_ERR_GENERAL;
        }
    }
    else {
        if (recvd == 0) {
            return WOLFSSL_CBIO_ERR_CONN_CLOSE;
        }
    }

    return recvd;
}
#endif /* WOLFSSL_DTLS && !NO_WOLFSSL_SERVER */

#if defined(WOLFSSL_DTLS) && !defined(NO_WOLFSSL_CLIENT)
static int SendTo(int sd, char *buf, int sz, const struct sockaddr *peer,
                  socklen_t peerSz)
{
    int sent;

    sent = (int)sendto(sd, buf, sz, 0, peer, peerSz);

    if (sent < 0) {
        if (errno == SOCKET_EWOULDBLOCK || errno == SOCKET_EAGAIN) {
            return WOLFSSL_CBIO_ERR_WANT_WRITE;
        }
        else if (errno == SOCKET_ECONNRESET) {
            return WOLFSSL_CBIO_ERR_CONN_RST;
        }
        else if (errno == SOCKET_EINTR) {
            return WOLFSSL_CBIO_ERR_ISR;
        }
        else if (errno == SOCKET_EPIPE) {
            return WOLFSSL_CBIO_ERR_CONN_CLOSE;
        }
        else {
            return WOLFSSL_CBIO_ERR_GENERAL;
        }
    }

    return sent;
}

static int myDoneHsCb(WOLFSSL* ssl, void* user_ctx)
{
    (void) ssl;
    (void) user_ctx;

    DoneHandShake = 1;
    return 1;
}
#endif /* WOLFSSL_DTLS && !NO_WOLFSSL_CLIENT */

#ifndef NO_WOLFSSL_SERVER
static int ServerSend(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    info_t* info = (info_t*)ctx;
    (void)ssl;
#ifdef HAVE_PTHREAD
    if (info->useLocalMem)
        return ServerMemSend(info, buf, sz);
#endif
#if defined(WOLFSSL_DTLS) && !defined(NO_WOLFSSL_CLIENT)
    if (info->doDTLS) {
        return SendTo(info->server.sockFd, buf, sz,
            (const struct sockaddr*)&info->clientAddr, sizeof(info->clientAddr));
    } else
#endif
        return SocketSend(info->server.sockFd, buf, sz);
}
static int ServerRecv(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    info_t* info = (info_t*)ctx;
    (void)ssl;
#ifdef HAVE_PTHREAD
    if (info->useLocalMem)
        return ServerMemRecv(info, buf, sz);
#endif
#ifdef WOLFSSL_DTLS
    if (info->doDTLS) {
        return ReceiveFrom(ssl, info->server.sockFd, buf, sz);
    } else
#endif
        return SocketRecv(info->server.sockFd, buf, sz);
}
#endif /* !NO_WOLFSSL_SERVER */

#ifndef NO_WOLFSSL_CLIENT
static int ClientSend(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    info_t* info = (info_t*)ctx;
    (void)ssl;
#ifdef HAVE_PTHREAD
    if (info->useLocalMem)
        return ClientMemSend(info, buf, sz);
#endif
#ifdef WOLFSSL_DTLS
    if (info->doDTLS) {
        return SendTo(info->client.sockFd, buf, sz,
            (const struct sockaddr*)&info->serverAddr, sizeof(info->serverAddr));
    } else
#endif
        return SocketSend(info->client.sockFd, buf, sz);
}
static int ClientRecv(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    info_t* info = (info_t*)ctx;
    (void)ssl;
#ifdef HAVE_PTHREAD
    if (info->useLocalMem)
        return ClientMemRecv(info, buf, sz);
#endif
#if defined(WOLFSSL_DTLS) && !defined(NO_WOLFSSL_SERVER)
    if (info->doDTLS) {
        return ReceiveFrom(ssl, info->client.sockFd, buf, sz);
    } else
#endif
        return SocketRecv(info->client.sockFd, buf, sz);
}
#endif /* !NO_WOLFSSL_CLIENT */

static void CloseAndCleanupSocket(int* sockFd)
{
    if (*sockFd != -1) {
        close(*sockFd);
        *sockFd = -1;
    }
#ifdef WOLFSSL_DTLS
    DoneHandShake = 0;
#endif
}

#ifdef BENCH_USE_NONBLOCK
static int SetSocketNonBlocking(int sockFd)
{
    int flags = fcntl(sockFd, F_GETFL, 0);
    if (flags < 0) {
        fprintf(stderr, "fcntl get failed\n");
        return -1;
    }
    flags = fcntl(sockFd, F_SETFL, flags | O_NONBLOCK);
    if (flags < 0) {
        fprintf(stderr, "fcntl set failed\n");
        return -1;
    }
    return 0;
}
#endif

#ifndef NO_WOLFSSL_CLIENT
static int SetupSocketAndConnect(info_t* info, const char* host,
    word32 port)
{
    struct sockaddr_in servAddr;
    struct hostent* entry;

    /* Setup server address */
    XMEMSET(&servAddr, 0, sizeof(servAddr));
    servAddr.sin_family = AF_INET;
    servAddr.sin_port = htons(port);

    /* Resolve host */
    entry = gethostbyname(host);
    if (entry) {
        XMEMCPY(&servAddr.sin_addr.s_addr, entry->h_addr_list[0],
            entry->h_length);
    }
    else {
        servAddr.sin_addr.s_addr = inet_addr(host);
    }

#ifdef WOLFSSL_DTLS
    if (info->doDTLS) {
        /* Create the SOCK_DGRAM socket type is implemented on the User
        *  Datagram Protocol/Internet Protocol(UDP/IP protocol).*/
        if ((info->client.sockFd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
            fprintf(stderr, "ERROR: failed to create the SOCK_DGRAM socket\n");
            return -1;
        }
        XMEMCPY(&info->serverAddr, &servAddr, sizeof(servAddr));
    } else {
#endif
    /* Create a socket that uses an Internet IPv4 address,
     * Sets the socket to be stream based (TCP),
     * 0 means choose the default protocol. */
    if ((info->client.sockFd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        fprintf(stderr, "ERROR: failed to create the socket\n");
        return -1;
    }

    /* Connect to the server */
#ifdef HAVE_PTHREAD
    while ((info->serverListening == 0) && (info->server.shutdown == 0)) {
        if (info->showVerbose) {
            fprintf(stderr, "Waiting for server to listen...\n");
        }
        XSLEEP_MS(1);
    }
#endif

    if (info->server.shutdown == 1) {
        fprintf(stderr, "ERROR: server side has shutdown\n");
        return -1;
    }

    if (connect(info->client.sockFd, (struct sockaddr*)&servAddr,
                                                    sizeof(servAddr)) == -1) {
        fprintf(stderr, "ERROR: failed to connect\n");
        return -1;
    }
#ifdef WOLFSSL_DTLS
    }
#endif

#ifdef BENCH_USE_NONBLOCK
    if (SetSocketNonBlocking(info->client.sockFd) != 0) {
        return -1;
    }
#endif

    if (info->showVerbose) {
        fprintf(stderr, "Connected to %s on port %d\n", host, port);
    }

    return 0;
}

static int bench_tls_client(info_t* info)
{
    byte *writeBuf = NULL, *readBuf = NULL;
    double start, total = 0;
    int ret, readBufSz;
    WOLFSSL_CTX* cli_ctx = NULL;
    WOLFSSL* cli_ssl = NULL;
    int haveShownPeerInfo = 0;
    int tls13 = XSTRNCMP(info->cipher, "TLS13", 5) == 0;
    int total_sz;

    total = gettime_secs(0);

    /* set up client */
#ifdef WOLFSSL_DTLS
    if(info->doDTLS) {
        if (tls13) return WOLFSSL_SUCCESS;
        cli_ctx = wolfSSL_CTX_new(wolfDTLSv1_2_client_method());
    } else
#endif
#ifdef WOLFSSL_TLS13
    if (tls13)
        cli_ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
#endif
    if (!tls13)
#ifdef WOLFSSL_DTLS
        if(!info->doDTLS)
#endif
#if !defined(WOLFSSL_TLS13)
        cli_ctx = wolfSSL_CTX_new(wolfSSLv23_client_method());
#elif !defined(WOLFSSL_NO_TLS12)
        cli_ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
#endif

    if (cli_ctx == NULL) {
        fprintf(stderr, "error creating ctx\n");
        ret = MEMORY_E; goto exit;
    }

#ifndef NO_CERTS
#ifdef HAVE_ECC
    if (XSTRSTR(info->cipher, "ECDSA")) {
        ret = wolfSSL_CTX_load_verify_buffer(cli_ctx, ca_ecc_cert_der_256,
            sizeof_ca_ecc_cert_der_256, WOLFSSL_FILETYPE_ASN1);
    }
    else
#endif
    {
        ret = wolfSSL_CTX_load_verify_buffer(cli_ctx, ca_cert_der_2048,
            sizeof_ca_cert_der_2048, WOLFSSL_FILETYPE_ASN1);
    }
    if (ret != WOLFSSL_SUCCESS) {
        fprintf(stderr, "error loading CA\n");
        goto exit;
    }
#endif

    wolfSSL_CTX_SetIOSend(cli_ctx, ClientSend);
    wolfSSL_CTX_SetIORecv(cli_ctx, ClientRecv);

    /* set cipher suite */
    ret = wolfSSL_CTX_set_cipher_list(cli_ctx, info->cipher);
    if (ret != WOLFSSL_SUCCESS) {
        fprintf(stderr, "error setting cipher suite\n");
        goto exit;
    }

#ifndef NO_DH
    ret = wolfSSL_CTX_SetMinDhKey_Sz(cli_ctx, MIN_DHKEY_BITS);
    if (ret != WOLFSSL_SUCCESS) {
        fprintf(stderr, "Error setting minimum DH key size\n");
        goto exit;
    }
#endif

    /* Allocate and initialize a packet sized buffer */
    writeBuf = (unsigned char*)XMALLOC(info->packetSize, NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    if (writeBuf == NULL) {
        fprintf(stderr, "failed to allocate write memory\n");
        ret = MEMORY_E; goto exit;
    }

    /* Allocate read buffer */
    readBufSz = info->packetSize;
    readBuf = (unsigned char*)XMALLOC(readBufSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (readBuf == NULL) {
        fprintf(stderr, "failed to allocate read memory\n");
        ret = MEMORY_E; goto exit;
    }

    /* BENCHMARK CONNECTIONS LOOP */
    while (!info->client.shutdown) {
        int writeSz = info->packetSize;
    #ifdef BENCH_USE_NONBLOCK
        int err;
    #endif

    #ifdef HAVE_PTHREAD
        if (!info->useLocalMem)
    #endif
        {
            /* Setup socket and connection */
            ret = SetupSocketAndConnect(info, info->host, info->port);
            if (ret != 0) goto exit;
        }

        cli_ssl = wolfSSL_new(cli_ctx);
        if (cli_ssl == NULL) {
            fprintf(stderr, "error creating client object\n");
            goto exit;
        }

#if defined(WOLFSSL_TLS13) && defined(HAVE_SUPPORTED_CURVES)
        if (info->group != 0) {
            ret = wolfSSL_UseKeyShare(cli_ssl, info->group);
            if (ret != WOLFSSL_SUCCESS) {
                fprintf(stderr, "error setting client key share.\n");
                goto exit;
            }
        }
#endif

#ifdef WOLFSSL_DTLS
        if (info->doDTLS) {
            ret = wolfSSL_dtls_set_peer(cli_ssl, &info->serverAddr,
                                                    sizeof(info->serverAddr));
            if (ret != WOLFSSL_SUCCESS) {
                fprintf(stderr, "error setting dtls peer\n");
                goto exit;
            }
            ret = wolfSSL_SetHsDoneCb(cli_ssl, myDoneHsCb, NULL);
            if (ret != WOLFSSL_SUCCESS) {
                fprintf(stderr, "error handshake done callback\n");
                goto exit;
            }
        }
#endif
        wolfSSL_SetIOReadCtx(cli_ssl, info);
        wolfSSL_SetIOWriteCtx(cli_ssl, info);

#if defined(HAVE_PTHREAD) && defined(WOLFSSL_DTLS)
        /* synchronize with server */
        if (info->doDTLS && !info->clientOrserverOnly) {
            pthread_mutex_lock(&info->dtls_mutex);
            if (info->serverReady != 1) {
                pthread_cond_wait(&info->dtls_cond, &info->dtls_mutex);
            }
            /* for next loop */
            info->serverReady = 0;
            pthread_mutex_unlock(&info->dtls_mutex);
        }
#endif
        /* perform connect */
        start = gettime_secs(1);
    #ifndef BENCH_USE_NONBLOCK
        ret = wolfSSL_connect(cli_ssl);
    #else
        do
        {
            ret = wolfSSL_connect(cli_ssl);
            err = wolfSSL_get_error(cli_ssl, ret);
        }
        while (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE);
    #endif
        start = gettime_secs(0) - start;
        if (ret != WOLFSSL_SUCCESS) {
            fprintf(stderr, "error connecting client\n");
            ret = wolfSSL_get_error(cli_ssl, ret);
            goto exit;
        }
        info->client_stats.connTime += start;
        info->client_stats.connCount++;

        if ((info->showPeerInfo) && (!haveShownPeerInfo)) {
            haveShownPeerInfo = 1;
            showPeer(cli_ssl);
        }

        /* check for run time completion and issue shutdown */
        if (gettime_secs(0) - total >= info->runTimeSec) {
            info->client.shutdown = 1;

            writeSz = (int)XSTRLEN(kShutdown) + 1;
            XMEMCPY(writeBuf, kShutdown, writeSz); /* include null term */
            if (info->showVerbose) {
                fprintf(stderr, "Sending shutdown\n");
            }

            ret = wolfSSL_write(cli_ssl, writeBuf, writeSz);
            if (ret < 0) {
                fprintf(stderr, "error on client write\n");
                ret = wolfSSL_get_error(cli_ssl, ret);
                goto exit;
            }
        }
        else {
            XMEMSET(writeBuf, 0, info->packetSize);
            XSTRNCPY((char*)writeBuf, kTestStr, info->packetSize);
        }

        /* write / read echo loop */
        ret = 0;
        total_sz = 0;
        while (ret == 0 && total_sz < info->maxSize && !info->client.shutdown) {
            /* write test message to server */
            start = gettime_secs(1);
        #ifndef BENCH_USE_NONBLOCK
            ret = wolfSSL_write(cli_ssl, writeBuf, writeSz);
        #else
            do {
                ret = wolfSSL_write(cli_ssl, writeBuf, writeSz);
                err = wolfSSL_get_error(cli_ssl, ret);
            }
            while (err == WOLFSSL_ERROR_WANT_WRITE);
        #endif
            info->client_stats.txTime += gettime_secs(0) - start;
            if (ret < 0) {
                fprintf(stderr, "error on client write\n");
                ret = wolfSSL_get_error(cli_ssl, ret);
                goto exit;
            }
            info->client_stats.txTotal += ret;
            total_sz += ret;

            /* read echo of message from server */
            XMEMSET(readBuf, 0, readBufSz);
            start = gettime_secs(1);
        #ifndef BENCH_USE_NONBLOCK
            ret = wolfSSL_read(cli_ssl, readBuf, readBufSz);
        #else
            do {
                ret = wolfSSL_read(cli_ssl, readBuf, readBufSz);
                err = wolfSSL_get_error(cli_ssl, ret);
            }
            while (err == WOLFSSL_ERROR_WANT_READ);
        #endif
            info->client_stats.rxTime += gettime_secs(0) - start;
            if (ret < 0) {
                fprintf(stderr, "error on client read\n");
                ret = wolfSSL_get_error(cli_ssl, ret);
                goto exit;
            }
            info->client_stats.rxTotal += ret;
            ret = 0; /* reset return code */

            /* validate echo */
            if (XMEMCMP((char*)writeBuf, (char*)readBuf, writeSz) != 0) {
                fprintf(stderr, "echo check failed!\n");
                ret = wolfSSL_get_error(cli_ssl, ret);
                goto exit;
            }
        }

        CloseAndCleanupSocket(&info->client.sockFd);

        wolfSSL_free(cli_ssl);
        cli_ssl = NULL;
    }

exit:

    if (ret != 0 && ret != WOLFSSL_SUCCESS) {
        fprintf(stderr, "Client Error: %d (%s)\n", ret,
            wolfSSL_ERR_reason_error_string(ret));
    }

    /* clean up */
    CloseAndCleanupSocket(&info->client.sockFd);
    if (cli_ssl != NULL)
        wolfSSL_free(cli_ssl);
    if (cli_ctx != NULL)
        wolfSSL_CTX_free(cli_ctx);
    XFREE(readBuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(writeBuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    info->client.ret = ret;

    return ret;
}

#ifdef HAVE_PTHREAD
static void* client_thread(void* args)
{
    int ret;
    info_t* info = (info_t*)args;

    ret = bench_tls_client(info);

    pthread_cond_signal(&info->to_server.cond);
    info->to_client.done = 1;
    info->client.ret = ret;

    return NULL;
}
#endif /* HAVE_PTHREAD */
#endif /* !NO_WOLFSSL_CLIENT */


#ifndef NO_WOLFSSL_SERVER
static int SetupSocketAndListen(int* listenFd, word32 port, int doDTLS)
{
    struct sockaddr_in servAddr;
#if defined(_MSC_VER) || defined(__MINGW32__)
    char optval = 1;
#else
    int optval = 1;
#endif
#ifndef WOLFSSL_DTLS
    (void) doDTLS;
#endif
    /* Setup server address */
    XMEMSET(&servAddr, 0, sizeof(servAddr));
    servAddr.sin_family = AF_INET;
    servAddr.sin_port = htons(port);
    servAddr.sin_addr.s_addr = INADDR_ANY;

#ifdef WOLFSSL_DTLS
    if (doDTLS) {
        /* Create a socket that is implemented on the User Datagram Protocol/
        * Interet Protocol(UDP/IP protocol). */
        if((*listenFd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
            fprintf(stderr, "ERROR: failed to create the socket\n");
            return -1;
        }
    } else
#endif
    /* Create a socket that uses an Internet IPv4 address,
     * Sets the socket to be stream based (TCP),
     * 0 means choose the default protocol. */
    if ((*listenFd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        fprintf(stderr, "ERROR: failed to create the socket\n");
        return -1;
    }

    /* allow reuse */
    if (setsockopt(*listenFd, SOL_SOCKET, SO_REUSEADDR,
                &optval, sizeof(optval)) == -1) {
        fprintf(stderr, "setsockopt SO_REUSEADDR failed\n");
        return -1;
    }

    /* Listen for the client. */
    if (bind(*listenFd, (struct sockaddr*)&servAddr,
                                                    sizeof(servAddr)) == -1) {
        fprintf(stderr, "ERROR: failed to bind\n");
        return -1;
    }
#ifdef WOLFSSL_DTLS
    if (!doDTLS)
#endif
    if (listen(*listenFd, 5) != 0) {
        fprintf(stderr, "ERROR: failed to listen\n");
        return -1;
    }

#ifdef BENCH_USE_NONBLOCK
    if (SetSocketNonBlocking(*listenFd) != 0) {
        return -1;
    }
#endif

    return 0;
}

static int SocketWaitClient(info_t* info)
{
    int connd;
    struct sockaddr_in clientAddr;
    socklen_t size = sizeof(clientAddr);
#ifdef WOLFSSL_DTLS
    char msg[64];

    if (info->doDTLS) {
#ifdef HAVE_PTHREAD
        if (!info->clientOrserverOnly) {
            pthread_mutex_lock(&info->dtls_mutex);
            info->serverReady = 1;
            pthread_cond_signal(&info->dtls_cond);
            pthread_mutex_unlock(&info->dtls_mutex);
        }
#endif
        connd = (int)recvfrom(info->listenFd, (char *)msg, sizeof(msg),
            MSG_PEEK, (struct sockaddr*)&clientAddr, &size);
        if (connd < -1) {
            fprintf(stderr, "ERROR: failed to accept the connection\n");
            return -1;
        }
        XMEMCPY(&info->clientAddr, &clientAddr, sizeof(clientAddr));
        info->server.sockFd = info->listenFd;
    } else {
#endif
#ifdef HAVE_PTHREAD
    info->serverListening = 1;
#endif
    if ((connd = accept(info->listenFd, (struct sockaddr*)&clientAddr, &size)) == -1) {
        if (errno == SOCKET_EWOULDBLOCK)
            return -2;
        fprintf(stderr, "ERROR: failed to accept the connection\n");
        return -1;
    }
    info->server.sockFd = connd;
#ifdef WOLFSSL_DTLS
    }
#endif

    if (info->showVerbose) {
        fprintf(stderr, "Got client %d\n", connd);
    }

    return 0;
}
static void CloseAndCleanupListenSocket(int* listenFd)
{
    if (*listenFd != -1) {
        close(*listenFd);
        *listenFd = -1;
    }
}

static int bench_tls_server(info_t* info)
{
    byte *readBuf = NULL;
    double start;
    int ret, len = 0, readBufSz;
    WOLFSSL_CTX* srv_ctx = NULL;
    WOLFSSL* srv_ssl = NULL;
    int tls13 = XSTRNCMP(info->cipher, "TLS13", 5) == 0;
    int total_sz;

    /* set up server */
#ifdef WOLFSSL_DTLS
    if(info->doDTLS) {
        if(tls13) return WOLFSSL_SUCCESS;
        srv_ctx = wolfSSL_CTX_new(wolfDTLSv1_2_server_method());
    } else {
#endif
#ifdef WOLFSSL_TLS13
    if (tls13)
        srv_ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
#endif
    if (!tls13)
        srv_ctx = wolfSSL_CTX_new(wolfSSLv23_server_method());
#ifdef WOLFSSL_DTLS
    }
#endif
    if (srv_ctx == NULL) {
        fprintf(stderr, "error creating server ctx\n");
        ret = MEMORY_E; goto exit;
    }

#ifndef NO_CERTS
#ifdef HAVE_ECC
    if (XSTRSTR(info->cipher, "ECDSA")) {
        ret = wolfSSL_CTX_use_PrivateKey_buffer(srv_ctx, ecc_key_der_256,
            sizeof_ecc_key_der_256, WOLFSSL_FILETYPE_ASN1);
    }
    else
#endif
    {
        ret = wolfSSL_CTX_use_PrivateKey_buffer(srv_ctx, server_key_der_2048,
            sizeof_server_key_der_2048, WOLFSSL_FILETYPE_ASN1);
    }
    if (ret != WOLFSSL_SUCCESS) {
        fprintf(stderr, "error loading server key\n");
        goto exit;
    }

#ifdef HAVE_ECC
    if (XSTRSTR(info->cipher, "ECDSA")) {
        ret = wolfSSL_CTX_use_certificate_buffer(srv_ctx, serv_ecc_der_256,
            sizeof_serv_ecc_der_256, WOLFSSL_FILETYPE_ASN1);
    }
    else
#endif
    {
        ret = wolfSSL_CTX_use_certificate_buffer(srv_ctx, server_cert_der_2048,
            sizeof_server_cert_der_2048, WOLFSSL_FILETYPE_ASN1);
    }
    if (ret != WOLFSSL_SUCCESS) {
        fprintf(stderr, "error loading server cert\n");
        goto exit;
    }
#endif /* !NO_CERTS */

    wolfSSL_CTX_SetIOSend(srv_ctx, ServerSend);
    wolfSSL_CTX_SetIORecv(srv_ctx, ServerRecv);

    /* set cipher suite */
    ret = wolfSSL_CTX_set_cipher_list(srv_ctx, info->cipher);
    if (ret != WOLFSSL_SUCCESS) {
        fprintf(stderr, "error setting cipher suite\n");
        goto exit;
    }

#ifndef NO_DH
    ret = wolfSSL_CTX_SetMinDhKey_Sz(srv_ctx, MIN_DHKEY_BITS);
    if (ret != WOLFSSL_SUCCESS) {
        fprintf(stderr, "Error setting minimum DH key size\n");
        goto exit;
    }
#endif

    /* Allocate read buffer */
    readBufSz = info->packetSize;
    readBuf = (unsigned char*)XMALLOC(readBufSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (readBuf == NULL) {
        fprintf(stderr, "failed to allocate read memory\n");
        ret = MEMORY_E; goto exit;
    }

    /* BENCHMARK CONNECTIONS LOOP */
    while (!info->server.shutdown) {
    #ifdef BENCH_USE_NONBLOCK
        int err;
    #endif

    #ifdef HAVE_PTHREAD
        if (!info->useLocalMem)
    #endif
        {
            /* Accept client connections */
            ret = SocketWaitClient(info);
        #ifdef BENCH_USE_NONBLOCK
            if (ret == -2) {
                XSLEEP_MS(0);
                continue;
            }
        #endif
            if (ret != 0) {
                goto exit;
            }
        }

        srv_ssl = wolfSSL_new(srv_ctx);
        if (srv_ssl == NULL) {
            fprintf(stderr, "error creating server object\n");
            ret = MEMORY_E; goto exit;
        }

#if defined(WOLFSSL_TLS13) && defined(HAVE_SUPPORTED_CURVES)
        if (info->group != 0) {
            ret = wolfSSL_UseKeyShare(srv_ssl, info->group);
            if (ret != WOLFSSL_SUCCESS) {
                fprintf(stderr, "error setting server key share.\n");
                goto exit;
            }
        }
#endif

#ifdef WOLFSSL_DTLS
        if (info->doDTLS) {
            ret = wolfSSL_dtls_set_peer(srv_ssl, &info->clientAddr,
                        sizeof(info->clientAddr));
            if (ret != WOLFSSL_SUCCESS) {
                fprintf(stderr, "error setting dtls peer\n");
                goto exit;
            }
        }
#endif

        wolfSSL_SetIOReadCtx(srv_ssl, info);
        wolfSSL_SetIOWriteCtx(srv_ssl, info);
    #ifndef NO_DH
        wolfSSL_SetTmpDH(srv_ssl, dhp, sizeof(dhp), dhg, sizeof(dhg));
    #endif

        /* accept TLS connection */
        start = gettime_secs(1);
    #ifndef BENCH_USE_NONBLOCK
        ret = wolfSSL_accept(srv_ssl);
    #else
        do {
            ret = wolfSSL_accept(srv_ssl);
            err = wolfSSL_get_error(srv_ssl, ret);
        }
        while (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE);
    #endif
        start = gettime_secs(0) - start;
        if (ret != WOLFSSL_SUCCESS) {
            fprintf(stderr, "error on server accept\n");
            ret = wolfSSL_get_error(srv_ssl, ret);
            goto exit;
        }

        info->server_stats.connTime += start;
        info->server_stats.connCount++;

        /* echo loop */
        ret = 0;
        total_sz = 0;
        while (ret == 0 && total_sz < info->maxSize) {
            double rxTime;

            /* read message from client */
            XMEMSET(readBuf, 0, readBufSz);
            start = gettime_secs(1);
        #ifndef BENCH_USE_NONBLOCK
            ret = wolfSSL_read(srv_ssl, readBuf, readBufSz);
        #else
            do {
                ret = wolfSSL_read(srv_ssl, readBuf, readBufSz);
                err = wolfSSL_get_error(srv_ssl, ret);
            }
            while (err == WOLFSSL_ERROR_WANT_READ);
        #endif
            rxTime = gettime_secs(0) - start;

            /* shutdown signals, no more connections for this cipher */
            if (XSTRSTR((const char*)readBuf, kShutdown) != NULL) {
                info->server.shutdown = 1;
                if (info->showVerbose) {
                    fprintf(stderr, "Server shutdown done\n");
                }
                ret = 0; /* success */
                break;
            }

            info->server_stats.rxTime += rxTime;
            if (ret < 0) {
                fprintf(stderr, "error on server read\n");
                ret = wolfSSL_get_error(srv_ssl, ret);
                goto exit;
            }
            info->server_stats.rxTotal += ret;
            len = ret;
            total_sz += ret;

            /* write message back to client */
            start = gettime_secs(1);
        #ifndef BENCH_USE_NONBLOCK
            ret = wolfSSL_write(srv_ssl, readBuf, len);
        #else
            do {
                ret = wolfSSL_write(srv_ssl, readBuf, len);
                err = wolfSSL_get_error(srv_ssl, ret);
            }
            while (err == WOLFSSL_ERROR_WANT_WRITE);
        #endif
            info->server_stats.txTime += gettime_secs(0) - start;
            if (ret < 0) {
                fprintf(stderr, "error on server write\n");
                ret = wolfSSL_get_error(srv_ssl, ret);
                goto exit;
            }
            info->server_stats.txTotal += ret;
            ret = 0; /* reset return code */
        }

        CloseAndCleanupSocket(&info->server.sockFd);

        wolfSSL_free(srv_ssl);
        srv_ssl = NULL;
#ifdef WOLFSSL_DTLS
        if (info->doDTLS) {
            SetupSocketAndListen(&info->listenFd, info->port, info->doDTLS);
        }
#endif

    }

exit:

    if (ret != 0 && ret != WOLFSSL_SUCCESS) {
        fprintf(stderr, "Server Error: %d (%s)\n", ret,
                wolfSSL_ERR_reason_error_string(ret));
    }

    /* clean up */
    CloseAndCleanupSocket(&info->server.sockFd);
    if (srv_ssl != NULL)
        wolfSSL_free(srv_ssl);
    if (srv_ctx != NULL)
        wolfSSL_CTX_free(srv_ctx);
    XFREE(readBuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    info->server.ret = ret;

    return ret;
}

#ifdef HAVE_PTHREAD
static void* server_thread(void* args)
{
    int ret = 0;
    info_t* info = (info_t*)args;

    if (!info->useLocalMem) {
        /* Setup TLS server listener */
#ifdef WOLFSSL_DTLS
        ret = SetupSocketAndListen(&info->listenFd, info->port, info->doDTLS);
#else
        ret = SetupSocketAndListen(&info->listenFd, info->port, 0);
#endif
    }
    if (ret == 0) {
        ret = bench_tls_server(info);

        if (!info->useLocalMem) {
            CloseAndCleanupListenSocket(&info->listenFd);
        }
    }

    pthread_cond_signal(&info->to_client.cond);
    info->to_server.done = 1;
    info->server.ret = ret;

    return NULL;
}
#endif /* HAVE_PTHREAD */
#endif /* !NO_WOLFSSL_SERVER */


static void print_stats(stats_t* wcStat, const char* desc, const char* cipher, const char *group, int verbose)
{
    if (verbose) {
        fprintf(stderr,
                "wolfSSL %s Benchmark on %s with group %s:\n"
                "\tTotal       : %9d bytes\n"
                "\tNum Conns   : %9d\n"
                "\tRx Total    : %9.3f ms\n"
                "\tTx Total    : %9.3f ms\n"
                "\tRx          : %9.3f MB/s\n"
                "\tTx          : %9.3f MB/s\n"
                "\tConnect     : %9.3f ms\n"
                "\tConnect Avg : %9.3f ms\n",
                desc,
                cipher,
                group,
                wcStat->txTotal + wcStat->rxTotal,
                wcStat->connCount,
                wcStat->rxTime * 1000,
                wcStat->txTime * 1000,
                wcStat->rxTotal / wcStat->rxTime / 1024 / 1024,
                wcStat->txTotal / wcStat->txTime / 1024 / 1024,
                wcStat->connTime * 1000,
                wcStat->connTime * 1000 / wcStat->connCount);
    }
    else {
        fprintf(stderr,
                "%-6s  %-33s  %-25s  %11d  %9d  %9.3f  %9.3f  %9.3f  "
                "%9.3f  %17.3f  %15.3f\n",
                desc,
                cipher,
                group,
                wcStat->txTotal + wcStat->rxTotal,
                wcStat->connCount,
                wcStat->rxTime * 1000,
                wcStat->txTime * 1000,
                wcStat->rxTotal / wcStat->rxTime / 1024 / 1024,
                wcStat->txTotal / wcStat->txTime / 1024 / 1024,
                wcStat->connTime * 1000,
                wcStat->connTime * 1000 / wcStat->connCount);
    }
}

static void Usage(void)
{
    fprintf(stderr, "tls_bench "    LIBWOLFSSL_VERSION_STRING
            " NOTE: All files relative to wolfSSL home dir\n");
    fprintf(stderr, "-?          Help, print this usage\n");
    fprintf(stderr, "-c          Run as client only, no threading and uses sockets\n");
    fprintf(stderr, "-s          Run as server only, no threading and uses sockets\n");
    fprintf(stderr, "-h          Host (default %s)\n", BENCH_DEFAULT_HOST);
    fprintf(stderr, "-P          Port (default %d)\n", BENCH_DEFAULT_PORT);
    fprintf(stderr, "-e          List Every cipher suite available\n");
    fprintf(stderr, "-i          Show peer info\n");
#ifdef WOLFSSL_TLS13
    fprintf(stderr, "-g          Run through each of the TLS 1.3 groups that are available\n");
#endif
    fprintf(stderr, "-l <str>    Cipher suite list (: delimited)\n");
    fprintf(stderr, "-t <num>    Time <num> (seconds) to run each test (default %d)\n", BENCH_RUNTIME_SEC);
    fprintf(stderr, "-p <num>    The packet size <num> in bytes [1-16kB] (default %d)\n", TEST_PACKET_SIZE);
#ifdef WOLFSSL_DTLS
    fprintf(stderr, "            In the case of DTLS, [1-8kB] (default %d)\n", TEST_DTLS_PACKET_SIZE);
#endif
    fprintf(stderr, "-S <num>    The total size <num> in bytes (default %d)\n", TEST_MAX_SIZE);
    fprintf(stderr, "-v          Show verbose output\n");
#ifdef DEBUG_WOLFSSL
    fprintf(stderr, "-d          Enable debug messages\n");
#endif
#ifdef HAVE_PTHREAD
    fprintf(stderr, "-T <num>    Number of threaded server/client pairs (default %d)\n", NUM_THREAD_PAIRS);
    fprintf(stderr, "-m          Use local memory, not socket\n");
#endif
#ifdef WOLFSSL_DTLS
    fprintf(stderr, "-u          Use DTLS\n");
#endif
}

static void ShowCiphers(void)
{
    char ciphers[WOLFSSL_CIPHER_LIST_MAX_SIZE];

    int ret = wolfSSL_get_ciphers(ciphers, (int)sizeof(ciphers));

    if (ret == WOLFSSL_SUCCESS)
        fprintf(stderr, "%s\n", ciphers);
}

#if defined(WOLFSSL_TLS13) && defined(HAVE_SUPPORTED_CURVES)
static int SetupSupportedGroups(int verbose)
{
    int i;
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    int ret = 0;

    if (ret == 0) {
#ifdef NO_WOLFSSL_CLIENT
        ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
#else
        ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
#endif
        if (ctx == NULL) {
            ret = -1;
        }
    }

    if (ret == 0) {
        ssl = wolfSSL_new(ctx);
        if (ssl == NULL) {
            ret = -1;
        }
    }

    /* Determine which groups are actually supported. */
    for (i = 0; groups[i].name != NULL; i++) {
        if (ret == 0) {
            int uks_ret = wolfSSL_UseKeyShare(ssl, groups[i].group);
            if (uks_ret == WOLFSSL_SUCCESS) {
                if (verbose) {
                    printf("Will benchmark the following group: %s\n",
                       groups[i].name);
                }
            } else if (uks_ret == BAD_FUNC_ARG || uks_ret == NOT_COMPILED_IN) {
                groups[i].group = 0;
                if (verbose) {
                    printf("Will NOT benchmark the following group: %s\n",
                           groups[i].name);
                }
            } else {
                ret = -1;
            }
        }
    }

    if (ssl != NULL)
        wolfSSL_free(ssl);
    if (ctx != NULL)
        wolfSSL_CTX_free(ctx);
    return ret;
}
#endif


int bench_tls(void* args)
{
    int ret = 0;
    info_t *theadInfo = NULL, *info;
    stats_t cli_comb, srv_comb;
    int i;
    char *cipher, *next_cipher, *ciphers = NULL;
    int     argc = 0;
    char**  argv = NULL;
    int    ch;

    /* Vars configured by command line arguments */
    int argRuntimeSec = BENCH_RUNTIME_SEC;
    char *argCipherList = NULL;
    int argTestPacketSize = TEST_PACKET_SIZE;
    int argTestMaxSize = TEST_MAX_SIZE;
    int argThreadPairs = NUM_THREAD_PAIRS;
    int argShowVerbose = SHOW_VERBOSE;
    int argClientOnly = 0;
    int argServerOnly = 0;
    const char* argHost = BENCH_DEFAULT_HOST;
    int argPort = BENCH_DEFAULT_PORT;
    int argShowPeerInfo = 0;
#ifdef HAVE_PTHREAD
    int doShutdown;
#endif
#if !defined(NO_WOLFSSL_SERVER) || defined(HAVE_PTHREAD)
    int argLocalMem = 0;
    int listenFd = -1;
#endif
#if defined(WOLFSSL_DTLS) && !defined(NO_WOLFSSL_SERVER)
    int option_p = 0;
#endif
#ifdef WOLFSSL_DTLS
    int doDTLS = 0;
#endif
#if defined(WOLFSSL_TLS13) && defined(HAVE_SUPPORTED_CURVES)
    int group_index = 0;
    int argDoGroups = 0;
#endif

    if (args != NULL) {
        argc = ((func_args*)args)->argc;
        argv = ((func_args*)args)->argv;
        ((func_args*)args)->return_code = -1; /* error state */
    }

    /* Initialize wolfSSL */
    wolfSSL_Init();

    /* Parse command line arguments */
    while ((ch = mygetopt(argc, argv, "?" "udeil:p:t:vT:sch:P:mS:g")) != -1) {
        switch (ch) {
            case '?' :
                Usage();
                goto exit;

            case 's':
                argServerOnly = 1;
                break;

            case 'c':
                argClientOnly = 1;
                break;

            case 'h':
                argHost = myoptarg;
                break;

            case 'P':
                argPort = atoi(myoptarg);
                break;

            case 'd' :
            #ifdef DEBUG_WOLFSSL
                wolfSSL_Debugging_ON();
            #endif
                break;

            case 'e' :
                ShowCiphers();
                goto exit;

            case 'g' :
#if defined(WOLFSSL_TLS13) && defined(HAVE_SUPPORTED_CURVES)
                argDoGroups = 1;
                break;
#else
                fprintf(stderr, "There are only groups in TLS 1.3\n");
                Usage();
                ret = MY_EX_USAGE; goto exit;
#endif
            case 'i' :
                argShowPeerInfo = 1;
                break;

            case 'l' :
                argCipherList = myoptarg;
                break;

            case 'p' :
                argTestPacketSize = atoi(myoptarg);
                if (argTestPacketSize > (16 * 1024)) {
                    fprintf(stderr, "Invalid packet size %d\n", argTestPacketSize);
                    Usage();
                    ret = MY_EX_USAGE; goto exit;
                }
            #if defined(WOLFSSL_DTLS) && !defined(NO_WOLFSSL_SERVER)
                option_p = 1;
            #endif
                break;

            case 'S' :
                argTestMaxSize = atoi(myoptarg);
                break;

            case 't' :
                argRuntimeSec = atoi(myoptarg);
                break;

            case 'v' :
                argShowVerbose = 1;
                break;

            case 'T' :
            #ifdef HAVE_PTHREAD
                argThreadPairs = atoi(myoptarg);
            #endif
                break;

            case 'm':
            #ifdef HAVE_PTHREAD
                argLocalMem = 1;
            #endif
                break;
            case 'u':
            #ifdef WOLFSSL_DTLS
                doDTLS = 1;
                #ifdef BENCH_USE_NONBLOCK
                    fprintf(stderr, "tls_bench hasn't yet supported DTLS "
                       "non-blocking mode.\n");
                    Usage();
                    ret = MY_EX_USAGE; goto exit;
                #endif
            #endif
                break;
            default:
                Usage();
                ret = MY_EX_USAGE; goto exit;
        }
    }

    /* reset for test cases */
    myoptind = 0;

    if (argCipherList != NULL) {
        /* Use the list from CL argument */
        cipher = argCipherList;
    }
    else {
        /* Run for each cipher */
        ciphers = (char*)XMALLOC(WOLFSSL_CIPHER_LIST_MAX_SIZE, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (ciphers == NULL) {
            goto exit;
        }
        wolfSSL_get_ciphers(ciphers, WOLFSSL_CIPHER_LIST_MAX_SIZE);
        cipher = ciphers;
    }

#if defined(WOLFSSL_TLS13) && defined(HAVE_SUPPORTED_CURVES)
    if (argDoGroups) {
        if (SetupSupportedGroups(argShowVerbose) != 0) {
            goto exit;
        }
    }
#endif

    /* for server or client side only, only 1 thread is allowed */
    if (argServerOnly || argClientOnly) {
        argThreadPairs = 1;
    }
#ifndef HAVE_PTHREAD
    else {
        fprintf(stderr, "Threading is not enabled, so please use -s or -c to indicate side\n");
        Usage();
        ret = MY_EX_USAGE; goto exit;
    }
#endif

    /* Allocate test info array */
    theadInfo = (info_t*)XMALLOC(sizeof(info_t) * argThreadPairs, NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    if (theadInfo == NULL) {
        ret = MEMORY_E; goto exit;
    }
    XMEMSET(theadInfo, 0, sizeof(info_t) * argThreadPairs);

#ifndef NO_WOLFSSL_SERVER
    /* Use same listen socket to avoid timing issues between client and server */
    if (argServerOnly && !argLocalMem) {
        /* Setup TLS server listener */
#ifdef WOLFSSL_DTLS
        ret = SetupSocketAndListen(&listenFd, argPort, doDTLS);
#else
        ret = SetupSocketAndListen(&listenFd, argPort, 0);
#endif
        if (ret != 0) goto exit;
    }
#endif

#if defined(WOLFSSL_DTLS) && !defined(NO_WOLFSSL_SERVER)
    if (doDTLS) {
        if (argLocalMem) {
            fprintf(stderr, "tls_bench hasn't yet supported DTLS with local memory.\n");
            ret = MY_EX_USAGE; goto exit;
        }
        if (option_p && argTestPacketSize > TEST_DTLS_PACKET_SIZE){
            fprintf(stderr, "Invalid packet size %d\n", argTestPacketSize);
            Usage();
            ret = MY_EX_USAGE; goto exit;
        } else {
            /* argTestPacketSize would be default for tcp packet */
            if (argTestPacketSize >= TEST_PACKET_SIZE)
                argTestPacketSize = TEST_DTLS_PACKET_SIZE;
        }
    }
#endif
    fprintf(stderr, "Running TLS Benchmarks...\n");

    /* parse by : */
    while ((cipher != NULL) && (cipher[0] != '\0')) {
        const char *gname = "N/A";
        next_cipher = strchr(cipher, ':');
        if (next_cipher != NULL) {
            cipher[next_cipher - cipher] = '\0';
        }

        if (argShowVerbose) {
            fprintf(stderr, "Cipher: %s\n", cipher);
        }

#if defined(WOLFSSL_TLS13) && defined(HAVE_SUPPORTED_CURVES)
        for (group_index = 0; groups[group_index].name != NULL; group_index++) {
            gname = theadInfo[0].group == 0 ? "N/A" : groups[group_index].name;

            if (argDoGroups && groups[group_index].group == 0) {
                /* Skip unsupported group. */
                continue;
            }
#endif
            for (i=0; i<argThreadPairs; i++) {
                info = &theadInfo[i];
                XMEMSET(info, 0, sizeof(info_t));

                info->host = argHost;
                info->port = argPort + i; /* threads must have separate ports */
                info->cipher = cipher;

#if defined(WOLFSSL_TLS13) && defined(HAVE_SUPPORTED_CURVES)
                if (argDoGroups && XSTRNCMP(theadInfo[0].cipher, "TLS13", 5) == 0)
                    info->group = groups[group_index].group;
                else
#endif
                    info->group = 0;

                info->packetSize = argTestPacketSize;

                info->runTimeSec = argRuntimeSec;
                info->maxSize = argTestMaxSize;
                info->showPeerInfo = argShowPeerInfo;
                info->showVerbose = argShowVerbose;
        #ifndef NO_WOLFSSL_SERVER
                info->listenFd = listenFd;
        #endif
                info->client.sockFd = -1;
                info->server.sockFd = -1;

        #ifdef WOLFSSL_DTLS
                info->doDTLS = doDTLS;
        #ifdef HAVE_PTHREAD
                info->serverReady = 0;
                if (argServerOnly || argClientOnly) {
                    info->clientOrserverOnly = 1;
                }
        #endif
        #endif
                if (argClientOnly) {
            #if !defined(NO_WOLFSSL_SERVER) && !defined(NO_WOLFSSL_CLIENT)
                    /* to avoid to wait server forever */
                    info->serverListening = 1;
            #endif
            #ifndef NO_WOLFSSL_CLIENT
                    ret = bench_tls_client(info);
            #endif
                }
                else if (argServerOnly) {
            #ifndef NO_WOLFSSL_SERVER
                    ret = bench_tls_server(info);
            #endif
                }
                else {
            #ifdef HAVE_PTHREAD
                    info->useLocalMem = argLocalMem;
                    pthread_mutex_init(&info->to_server.mutex, NULL);
                    pthread_mutex_init(&info->to_client.mutex, NULL);
            #ifdef WOLFSSL_DTLS
                    pthread_mutex_init(&info->dtls_mutex, NULL);
                    pthread_cond_init(&info->dtls_cond, NULL);
            #endif
                    pthread_cond_init(&info->to_server.cond, NULL);
                    pthread_cond_init(&info->to_client.cond, NULL);

                    pthread_create(&info->to_server.tid, NULL, server_thread,
                                   info);
                    pthread_create(&info->to_client.tid, NULL, client_thread,
                                   info);

                    /* State that we won't be joining this thread */
                    pthread_detach(info->to_server.tid);
                    pthread_detach(info->to_client.tid);
            #endif
                }
            }

    #ifdef HAVE_PTHREAD
            /* For threading, wait for completion */
            if (!argClientOnly && !argServerOnly) {
                /* Wait until threads are marked done */
                do {
                     doShutdown = 1;

                    for (i = 0; i < argThreadPairs; ++i) {
                        info = &theadInfo[i];
                        if (!info->to_client.done || !info->to_server.done) {
                            doShutdown = 0;
                            XSLEEP_MS(1000); /* Allow other threads to run */
                        }

                    }
                } while (!doShutdown);
                if (argShowVerbose) {
                    fprintf(stderr, "Shutdown complete\n");
                }
            }
    #endif /* HAVE_PTHREAD */

            if (argShowVerbose) {
                /* print results */
                for (i = 0; i < argThreadPairs; ++i) {
                    info = &theadInfo[i];

                    fprintf(stderr, "\nThread %d\n", i);
            #ifndef NO_WOLFSSL_SERVER
                    if (!argClientOnly)
                        print_stats(&info->server_stats, "Server", info->cipher, gname, 1);
            #endif
            #ifndef NO_WOLFSSL_CLIENT
                    if (!argServerOnly)
                        print_stats(&info->client_stats, "Client", info->cipher, gname, 1);
            #endif
                }
            }

            /* print combined results for more than one thread */
            XMEMSET(&cli_comb, 0, sizeof(cli_comb));
            XMEMSET(&srv_comb, 0, sizeof(srv_comb));

            for (i = 0; i < argThreadPairs; ++i) {
                info = &theadInfo[i];

                cli_comb.connCount += info->client_stats.connCount;
                srv_comb.connCount += info->server_stats.connCount;

                cli_comb.connTime += info->client_stats.connTime;
                srv_comb.connTime += info->server_stats.connTime;

                cli_comb.rxTotal += info->client_stats.rxTotal;
                srv_comb.rxTotal += info->server_stats.rxTotal;

                cli_comb.rxTime += info->client_stats.rxTime;
                srv_comb.rxTime += info->server_stats.rxTime;

                cli_comb.txTotal += info->client_stats.txTotal;
                srv_comb.txTotal += info->server_stats.txTotal;

                cli_comb.txTime += info->client_stats.txTime;
                srv_comb.txTime += info->server_stats.txTime;
            }

            if (argShowVerbose) {
                fprintf(stderr, "Totals for %d Threads\n", argThreadPairs);
            }
            else {
                fprintf(stderr, "%-6s  %-33s  %-25s  %11s  %9s  %9s  %9s  %9s  %9s  %17s  %15s\n",
                        "Side", "Cipher", "Group", "Total Bytes", "Num Conns", "Rx ms", "Tx ms",
                        "Rx MB/s", "Tx MB/s", "Connect Total ms", "Connect Avg ms");
        #ifndef NO_WOLFSSL_SERVER
                if (!argClientOnly)
                    print_stats(&srv_comb, "Server", theadInfo[0].cipher, gname, 0);
        #endif
        #ifndef NO_WOLFSSL_CLIENT
                if (!argServerOnly)
                    print_stats(&cli_comb, "Client", theadInfo[0].cipher, gname, 0);
        #endif
            }

#if defined(WOLFSSL_TLS13) && defined(HAVE_SUPPORTED_CURVES)
            if (!argDoGroups || theadInfo[0].group == 0) {
                /* We only needed to do this once because they don't want to
                 * benchmarks groups or this isn't a TLS 1.3 cipher. */
                break;
            }
        }
#endif
        /* target next cipher */
        cipher = (next_cipher != NULL) ? (next_cipher + 1) : NULL;
    } /* while */

//printf("HERE 444 !!!!!!!!!!!!!!");
exit:

#ifndef NO_WOLFSSL_SERVER
    if (argServerOnly && !argLocalMem) {
        /* Close server listener */
        CloseAndCleanupListenSocket(&listenFd);
    }
#endif

    /* Cleanup the wolfSSL environment */
    wolfSSL_Cleanup();

    /* Free theadInfo array */
    XFREE(theadInfo, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    /* Free cipher list */
    XFREE(ciphers, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    /* Return reporting a success */
    if (args)
        ((func_args*)args)->return_code = ret;

    return ret;
}
#endif /* (!NO_WOLFSSL_CLIENT || !NO_WOLFSSL_SERVER) && !WOLFCRYPT_ONLY && USE_WOLFSSL_IO */

//GDCCCCCCCCCCCCCCCCCC
int s_fp_add(fp_int *a, fp_int *b, fp_int *c)
{
  int      x, y, oldused;
  fp_word  t;

  y       = MAX(a->used, b->used);
  oldused = MIN(c->used, FP_SIZE);   /* help static analysis w/ largest size */
  c->used = y;

  t = 0;
  for (x = 0; x < y; x++) {
      t         += ((fp_word)a->dp[x]) + ((fp_word)b->dp[x]);
      c->dp[x]   = (fp_digit)t;
      t        >>= DIGIT_BIT;
  }
  if (t != 0) {
     if (x == FP_SIZE)
         return FP_VAL;
     c->dp[c->used++] = (fp_digit)t;
     ++x;
  }

  c->used = x;

  /* zero any excess digits on the destination that we didn't write to */
  for (; x < oldused; x++) {
     c->dp[x] = 0;
  }
  fp_clamp(c);
  return FP_OKAY;
}

void fp_rshb(fp_int *c, int x)
{
    fp_digit *tmpc, mask, shift;
    fp_digit r, rr;
    fp_digit D = x;

    /* shifting by a negative number not supported, and shifting by
     * zero changes nothing.
     */
    if (x <= 0) return;

    /* shift digits first if needed */
    if (x >= DIGIT_BIT) {
        fp_rshd(c, x / DIGIT_BIT);
        /* recalculate number of bits to shift */
        D = x % DIGIT_BIT;
        /* check if any more shifting needed */
        if (D == 0) return;

    }

    /* zero shifted is always zero */
    if (fp_iszero(c)) return;

    /* mask */
    mask = (((fp_digit)1) << D) - 1;

    /* shift for lsb */
    shift = DIGIT_BIT - D;

    /* alias */
    tmpc = c->dp + (c->used - 1);

    /* carry */
    r = 0;
    for (x = c->used - 1; x >= 0; x--) {
      /* get the lower  bits of this word in a temp */
      rr = *tmpc & mask;

      /* shift the current word and mix in the carry bits from previous word */
      *tmpc = (*tmpc >> D) | (r << shift);
      --tmpc;

      /* set the carry to the carry bits of the current word found above */
      r = rr;
    }

    /* clamp digits */
    fp_clamp(c);
}

void fp_div_2d(fp_int *a, int b, fp_int *c, fp_int *d)
{
  int      D;

  /* if the shift count is <= 0 then we do no work */
  if (b <= 0) {
    fp_copy (a, c);
    if (d != NULL) {
      fp_zero (d);
    }
    return;
  }

  /* get the remainder before a is changed in calculating c */
  if (a == c && d != NULL) {
    fp_mod_2d (a, b, d);
  }

  /* copy */
  fp_copy(a, c);

  /* shift by as many digits in the bit count */
  if (b >= (int)DIGIT_BIT) {
    fp_rshd (c, b / DIGIT_BIT);
  }

  /* shift any bit count < DIGIT_BIT */
  D = (b % DIGIT_BIT);
  if (D != 0) {
    fp_rshb(c, D);
  }

  /* get the remainder if a is not changed in calculating c */
  if (a != c && d != NULL) {
    fp_mod_2d (a, b, d);
  }

  fp_clamp (c);
}

void fp_mod_2d(fp_int *a, int b, fp_int *c)
{
   int x;
   int bmax;

   /* zero if count less than or equal to zero */
   if (b <= 0) {
      fp_zero(c);
      return;
   }

   /* get copy of input */
   fp_copy(a, c);

   /* if 2**d is larger than we just return */
   if (c->sign == FP_ZPOS && b >= (DIGIT_BIT * a->used)) {
      return;
   }

  bmax = (b + DIGIT_BIT - 1) / DIGIT_BIT;
  /* zero digits above the last digit of the modulus */
  for (x = bmax; x < c->used; x++) {
    c->dp[x] = 0;
  }

  if (c->sign == FP_NEG) {
     fp_digit carry = 0;
     /* negate value */
     for (x = 0; x < c->used; x++) {
         fp_digit next = c->dp[x] > 0;
         c->dp[x] = (fp_digit)0 - c->dp[x] - carry;
         carry |= next;
     }
     for (; x < bmax; x++) {
         c->dp[x] = (fp_digit)0 - carry;
     }
     c->used = bmax;
     c->sign = FP_ZPOS;
  }

  /* clear the digit that is not completely outside/inside the modulus */
  x = DIGIT_BIT - (b % DIGIT_BIT);
  if (x != DIGIT_BIT) {
     c->dp[bmax - 1] &= ~((fp_digit)0) >> x;
  }

  fp_clamp (c);
}

int fp_add(fp_int *a, fp_int *b, fp_int *c)
{
  int sa, sb;
  int ret = FP_OKAY;

  /* get sign of both inputs */
  sa = a->sign;
  sb = b->sign;

  /* handle two cases, not four */
  if (sa == sb) {
    /* both positive or both negative */
    /* add their magnitudes, copy the sign */
    c->sign = sa;
    ret = s_fp_add (a, b, c);
  } else {
    /* one positive, the other negative */
    /* subtract the one with the greater magnitude from */
    /* the one of the lesser magnitude.  The result gets */
    /* the sign of the one with the greater magnitude. */
    if (fp_cmp_mag (a, b) == FP_LT) {
      c->sign = sb;
      s_fp_sub (b, a, c);
    } else {
      c->sign = sa;
      s_fp_sub (a, b, c);
    }
  }

  return ret;
}

int fp_mul_d(fp_int *a, fp_digit b, fp_int *c)
{
   fp_word  w;
   int      x, oldused;

   oldused = c->used;
   c->used = a->used;
   c->sign = a->sign;
   w       = 0;
   for (x = 0; x < a->used; x++) {
       w         = ((fp_word)a->dp[x]) * ((fp_word)b) + w;
       c->dp[x]  = (fp_digit)w;
       w         = w >> DIGIT_BIT;
   }
   if (w != 0) {
      if (a->used == FP_SIZE)
          return FP_VAL;
      c->dp[c->used++] = (fp_digit) w;
      ++x;
   }

   /* zero any excess digits on the destination that we didn't write to */
   /* also checking FP_SIZE here for static analysis */
   for (; x < oldused && x < FP_SIZE; x++) {
      c->dp[x] = 0;
   }

   fp_clamp(c);
   return FP_OKAY;
}

void fp_rshd(fp_int *a, int x)
{
  int y;

  /* too many digits just zero and return */
  if (x >= a->used) {
     fp_zero(a);
     return;
  }

   /* shift */
   for (y = 0; y < a->used - x; y++) {
      a->dp[y] = a->dp[y+x];
   }

   /* zero rest */
   for (; y < a->used; y++) {
      a->dp[y] = 0;
   }

   /* decrement count */
   a->used -= x;
   fp_clamp(a);
}

int fp_cmp(fp_int *a, fp_int *b)
{
   if (a->sign == FP_NEG && b->sign == FP_ZPOS) {
      return FP_LT;
   } else if (a->sign == FP_ZPOS && b->sign == FP_NEG) {
      return FP_GT;
   } else {
      /* compare digits */
      if (a->sign == FP_NEG) {
         /* if negative compare opposite direction */
         return fp_cmp_mag(b, a);
      } else {
         return fp_cmp_mag(a, b);
      }
   }
}

void s_fp_sub(fp_int *a, fp_int *b, fp_int *c)
{
  int      x, oldbused, oldused;
  fp_word  t;

  oldused  = c->used;
  oldbused = b->used;
  c->used  = a->used;
  t       = 0;
  for (x = 0; x < oldbused; x++) {
     t         = ((fp_word)a->dp[x]) - (((fp_word)b->dp[x]) + t);
     c->dp[x]  = (fp_digit)t;
     t         = (t >> DIGIT_BIT)&1;
  }
  for (; x < a->used; x++) {
     t         = ((fp_word)a->dp[x]) - t;
     c->dp[x]  = (fp_digit)t;
     t         = (t >> DIGIT_BIT)&1;
   }

  /* zero any excess digits on the destination that we didn't write to */
  for (; x < oldused; x++) {
     c->dp[x] = 0;
  }
  fp_clamp(c);
}

int fp_sub(fp_int *a, fp_int *b, fp_int *c)
{
  int sa, sb;
  int ret = FP_OKAY;

  sa = a->sign;
  sb = b->sign;

  if (sa != sb) {
    /* subtract a negative from a positive, OR */
    /* subtract a positive from a negative. */
    /* In either case, ADD their magnitudes, */
    /* and use the sign of the first number. */
    c->sign = sa;
    ret = s_fp_add (a, b, c);
  } else {
    /* subtract a positive from a positive, OR */
    /* subtract a negative from a negative. */
    /* First, take the difference between their */
    /* magnitudes, then... */
    if (fp_cmp_mag (a, b) != FP_LT) {
      /* Copy the sign from the first */
      c->sign = sa;
      /* The first has a larger or equal magnitude */
      s_fp_sub (a, b, c);
    } else {
      /* The result has the *opposite* sign from */
      /* the first number. */
      c->sign = (sa == FP_ZPOS) ? FP_NEG : FP_ZPOS;
      /* The second has a larger magnitude */
      s_fp_sub (b, a, c);
    }
  }
  return ret;
}

int fp_lshd(fp_int *a, int x)
{
    int y;

    if (a->used + x > FP_SIZE) return FP_VAL;

    y = a->used + x - 1;

    /* store new size */
    a->used = y + 1;

    /* move digits */
    for (; y >= x; y--) {
        a->dp[y] = a->dp[y-x];
    }

    /* zero lower digits */
    for (; y >= 0; y--) {
        a->dp[y] = 0;
    }

    /* clamp digits */
    fp_clamp(a);
    return FP_OKAY;
}

int fp_mul_2d(fp_int *a, int b, fp_int *c)
{
   fp_digit carry, carrytmp, shift;
   int x;

   /* copy it */
   fp_copy(a, c);

   /* handle whole digits */
   if (b >= DIGIT_BIT) {
      int ret = fp_lshd(c, b/DIGIT_BIT);
      if (ret != FP_OKAY)
         return ret;
   }
   b %= DIGIT_BIT;

   /* shift the digits */
   if (b != 0) {
      carry = 0;
      shift = DIGIT_BIT - b;
      for (x = 0; x < c->used; x++) {
          carrytmp = c->dp[x] >> shift;
          c->dp[x] = (c->dp[x] << b) + carry;
          carry = carrytmp;
      }
      /* store last carry if room */
      if (carry && x < FP_SIZE) {
         c->dp[c->used++] = carry;
      }
      if (x == FP_SIZE)
         return FP_VAL;
   }
   fp_clamp(c);
   return FP_OKAY;
}

int fp_count_bits (const fp_int * a)
{
  int     r;
  fp_digit q;

  /* shortcut */
  if (a->used == 0) {
    return 0;
  }

  /* get number of digits and add that */
  r = (a->used - 1) * DIGIT_BIT;

  /* take the last digit and count the bits in it */
  q = a->dp[a->used - 1];
  while (q > ((fp_digit) 0)) {
    ++r;
    q >>= ((fp_digit) 1);
  }

  return r;
}

int fp_div(fp_int *a, fp_int *b, fp_int *c, fp_int *d)
{
  int     n, t, i, norm, neg;
  int     ret;
#ifndef WOLFSSL_SMALL_STACK
  fp_int  q[1], x[1], y[1], t1[1], t2[1];
#else
  fp_int  *q, *x, *y, *t1, *t2;
#endif

  /* is divisor zero ? */
  if (fp_iszero (b) == FP_YES) {
    return FP_VAL;
  }

  /* if a < b then q=0, r = a */
  if (fp_cmp_mag (a, b) == FP_LT)
  {
    if (d != NULL) {
      fp_copy (a, d);
    }
    if (c != NULL) {
      fp_zero (c);
    }
    return FP_OKAY;
  }

#ifdef WOLFSSL_SMALL_STACK
  q = (fp_int*)XMALLOC(sizeof(fp_int) * 5, NULL, DYNAMIC_TYPE_BIGINT);
  if (q == NULL) {
      return FP_MEM;
  }
  x = &q[1]; y = &q[2]; t1 = &q[3]; t2 = &q[4];
#endif

  fp_init(q);
  /* qb + d = a, and b is an integer > 0, therefore q <= a */
  q->used = a->used;

  fp_init(t1);
  fp_init(t2);
  fp_init_copy(x, a);
  fp_init_copy(y, b);

  /* fix the sign */
  neg = (a->sign == b->sign) ? FP_ZPOS : FP_NEG;
  x->sign = y->sign = FP_ZPOS;

  /* normalize both x and y, ensure that y >= b/2, [b == 2**DIGIT_BIT] */
  norm = fp_count_bits(y) % DIGIT_BIT;
  if (norm < (int)(DIGIT_BIT-1)) {
    norm = (DIGIT_BIT-1) - norm;
    ret = fp_mul_2d (x, norm, x);
    if (ret != FP_OKAY) {
    #ifdef WOLFSSL_SMALL_STACK
      XFREE(q, NULL, DYNAMIC_TYPE_BIGINT);
    #endif
      return ret;
    }
    ret = fp_mul_2d (y, norm, y);
    if (ret != FP_OKAY) {
    #ifdef WOLFSSL_SMALL_STACK
      XFREE(q, NULL, DYNAMIC_TYPE_BIGINT);
    #endif
      return ret;
    }
  } else {
    norm = 0;
  }

  /* note hac does 0 based, so if used==5 then its 0,1,2,3,4, e.g. use 4 */
  n = x->used - 1;
  t = y->used - 1;

  /* while (x >= y*b**n-t) do { q[n-t] += 1; x -= y*b**{n-t} } */
  ret = fp_lshd (y, n - t); /* y = y*b**{n-t} */
  if (ret != FP_OKAY) {
  #ifdef WOLFSSL_SMALL_STACK
    XFREE(q, NULL, DYNAMIC_TYPE_BIGINT);
  #endif
    return ret;
  }

  while (fp_cmp (x, y) != FP_LT) {
    ++(q->dp[n - t]);
    ret = fp_sub (x, y, x);
    if (ret != FP_OKAY) {
    #ifdef WOLFSSL_SMALL_STACK
      XFREE(q, NULL, DYNAMIC_TYPE_BIGINT);
    #endif
      return ret;
    }
  }

  /* reset y by shifting it back down */
  fp_rshd (y, n - t);

  /* step 3. for i from n down to (t + 1) */
  for (i = n; i >= (t + 1); i--) {
    if (i > x->used) {
      continue;
    }

    /* step 3.1 if xi == yt then set q{i-t-1} to b-1,
     * otherwise set q{i-t-1} to (xi*b + x{i-1})/yt */
    if (x->dp[i] == y->dp[t]) {
      q->dp[i - t - 1] = (fp_digit) ((((fp_word)1) << DIGIT_BIT) - 1);
    } else {
      fp_word tmp;
      tmp = ((fp_word) x->dp[i]) << ((fp_word) DIGIT_BIT);
      tmp |= ((fp_word) x->dp[i - 1]);
#ifdef WOLFSSL_LINUXKM
      /* Linux kernel macro for in-place 64 bit integer division. */
      do_div(tmp, (fp_word)y->dp[t]);
#else
      tmp /= ((fp_word)y->dp[t]);
#endif
      q->dp[i - t - 1] = (fp_digit) (tmp);
    }

    /* while (q{i-t-1} * (yt * b + y{t-1})) >
             xi * b**2 + xi-1 * b + xi-2

       do q{i-t-1} -= 1;
    */
    q->dp[i - t - 1] = (q->dp[i - t - 1] + 1);
    do {
      q->dp[i - t - 1] = (q->dp[i - t - 1] - 1);

      /* find left hand */
      fp_zero (t1);
      t1->dp[0] = (t - 1 < 0) ? 0 : y->dp[t - 1];
      t1->dp[1] = y->dp[t];
      t1->used = 2;
      ret = fp_mul_d (t1, q->dp[i - t - 1], t1);
      if (ret != FP_OKAY) {
      #ifdef WOLFSSL_SMALL_STACK
        XFREE(q, NULL, DYNAMIC_TYPE_BIGINT);
      #endif
        return ret;
      }

      /* find right hand */
      t2->dp[0] = (i - 2 < 0) ? 0 : x->dp[i - 2];
      t2->dp[1] = (i - 1 < 0) ? 0 : x->dp[i - 1];
      t2->dp[2] = x->dp[i];
      t2->used = 3;
    } while (fp_cmp_mag(t1, t2) == FP_GT);

    /* step 3.3 x = x - q{i-t-1} * y * b**{i-t-1} */
    ret = fp_mul_d (y, q->dp[i - t - 1], t1);
    if (ret != FP_OKAY) {
    #ifdef WOLFSSL_SMALL_STACK
      XFREE(q, NULL, DYNAMIC_TYPE_BIGINT);
    #endif
      return ret;
    }
    ret = fp_lshd  (t1, i - t - 1);
    if (ret != FP_OKAY) {
    #ifdef WOLFSSL_SMALL_STACK
      XFREE(q, NULL, DYNAMIC_TYPE_BIGINT);
    #endif
      return ret;
    }
    ret = fp_sub   (x, t1, x);
    if (ret != FP_OKAY) {
    #ifdef WOLFSSL_SMALL_STACK
      XFREE(q, NULL, DYNAMIC_TYPE_BIGINT);
    #endif
      return ret;
    }

    /* if x < 0 then { x = x + y*b**{i-t-1}; q{i-t-1} -= 1; } */
    if (x->sign == FP_NEG) {
      fp_copy (y, t1);
      ret = fp_lshd (t1, i - t - 1);
      if (ret != FP_OKAY) {
      #ifdef WOLFSSL_SMALL_STACK
        XFREE(q, NULL, DYNAMIC_TYPE_BIGINT);
      #endif
        return ret;
      }
      ret = fp_add (x, t1, x);
      if (ret != FP_OKAY) {
      #ifdef WOLFSSL_SMALL_STACK
        XFREE(q, NULL, DYNAMIC_TYPE_BIGINT);
      #endif
        return ret;
      }
      q->dp[i - t - 1] = q->dp[i - t - 1] - 1;
    }
  }

  /* now q is the quotient and x is the remainder
   * [which we have to normalize]
   */

  /* get sign before writing to c */
  x->sign = x->used == 0 ? FP_ZPOS : a->sign;

  if (c != NULL) {
    fp_clamp (q);
    fp_copy (q, c);
    c->sign = neg;
  }

  if (d != NULL) {
    fp_div_2d (x, norm, x, NULL);

    /* zero any excess digits on the destination that we didn't write to */
    for (i = b->used; i < x->used; i++) {
        x->dp[i] = 0;
    }
    fp_clamp(x);
    fp_copy (x, d);
  }

#ifdef WOLFSSL_SMALL_STACK
  XFREE(q, NULL, DYNAMIC_TYPE_BIGINT);
#endif
  return FP_OKAY;
}

int fp_mod(fp_int *a, fp_int *b, fp_int *c)
{
#ifndef WOLFSSL_SMALL_STACK
   fp_int t[1];
#else
   fp_int *t;
#endif
   int    err;

#ifdef WOLFSSL_SMALL_STACK
   t = (fp_int*)XMALLOC(sizeof(fp_int), NULL, DYNAMIC_TYPE_BIGINT);
   if (t == NULL)
       return FP_MEM;
#endif

   fp_init(t);
   err = fp_div(a, b, NULL, t);
   if (err == FP_OKAY) {
      if (!fp_iszero(t) && (t->sign != b->sign)) {
         err = fp_add(t, b, c);
      } else {
         fp_copy(t, c);
     }
  }

#ifdef WOLFSSL_SMALL_STACK
  XFREE(t, NULL, DYNAMIC_TYPE_BIGINT);
#endif
  return err;
}

void fp_copy(const fp_int *a, fp_int *b)
{
    /* if source and destination are different */
    if (a != b) {
#if defined(ALT_ECC_SIZE) || defined(HAVE_WOLF_BIGINT)
        /* verify a will fit in b */
        if (b->size >= a->used) {
            int x, oldused;
            oldused = b->used;
            b->used = a->used;
            b->sign = a->sign;

            XMEMCPY(b->dp, a->dp, a->used * sizeof(fp_digit));

            /* zero any excess digits on the destination that we didn't write to */
            for (x = b->used; x >= 0 && x < oldused; x++) {
                b->dp[x] = 0;
            }
        }
        else {
            /* TODO: Handle error case */
        }
#else
        /* all dp's are same size, so do straight copy */
        b->used = a->used;
        b->sign = a->sign;
        XMEMCPY(b->dp, a->dp, FP_SIZE * sizeof(fp_digit));
#endif
    }
}

void fp_init(fp_int *a)
{
#if defined(ALT_ECC_SIZE) || defined(HAVE_WOLF_BIGINT)
    a->size = FP_SIZE;
#endif
#ifdef HAVE_WOLF_BIGINT
    wc_bigint_init(&a->raw);
#endif
    fp_zero(a);
}

void fp_zero(fp_int *a)
{
    int size;
    a->used = 0;
    a->sign = FP_ZPOS;
#if defined(ALT_ECC_SIZE) || defined(HAVE_WOLF_BIGINT)
    size = a->size;
#else
    size = FP_SIZE;
#endif
    XMEMSET(a->dp, 0, size * sizeof(fp_digit));
}

void fp_init_copy(fp_int *a, fp_int* b)
{
    if (a != b) {
        fp_init(a);
        fp_copy(b, a);
    }
}

int fp_cmp_mag(fp_int *a, fp_int *b)
{
   int x;

   if (a->used > b->used) {
      return FP_GT;
   } else if (a->used < b->used) {
      return FP_LT;
   } else {
      for (x = a->used - 1; x >= 0; x--) {
          if (a->dp[x] > b->dp[x]) {
             return FP_GT;
          } else if (a->dp[x] < b->dp[x]) {
             return FP_LT;
          }
      }
   }
   return FP_EQ;
}

int fp_gcd(fp_int *a, fp_int *b, fp_int *c);

int fp_gcd(fp_int *a, fp_int *b, fp_int *c)
{
#ifndef WOLFSSL_SMALL_STACK
   fp_int u[1], v[1], r[1];
#else
   fp_int *u, *v, *r;
#endif
(void) r[1];
   /* GCD of 0 and 0 is undefined as all integers divide 0. */
   if (fp_iszero(a) == FP_YES && fp_iszero(b) == FP_YES) {
       return FP_VAL;
   }

   /* either zero than gcd is the largest */
   if (fp_iszero (a) == FP_YES && fp_iszero (b) == FP_NO) {
     fp_abs (b, c);
     return FP_OKAY;
   }
   if (fp_iszero (a) == FP_NO && fp_iszero (b) == FP_YES) {
     fp_abs (a, c);
     return FP_OKAY;
   }

   /* optimized.  At this point if a == 0 then
    * b must equal zero too
    */
   if (fp_iszero (a) == FP_YES) {
     fp_zero(c);
     return FP_OKAY;
   }

#ifdef WOLFSSL_SMALL_STACK
   u = (fp_int*)XMALLOC(sizeof(fp_int) * 3, NULL, DYNAMIC_TYPE_BIGINT);
   if (u == NULL) {
       return FP_MEM;
   }
   v = &u[1]; r = &u[2];
#endif

   /* sort inputs */
   if (fp_cmp_mag(a, b) != FP_LT) {
      fp_init_copy(u, a);
      fp_init_copy(v, b);
   } else {
      fp_init_copy(u, b);
      fp_init_copy(v, a);
   }

   u->sign = FP_ZPOS;
   v->sign = FP_ZPOS;

   fp_init(r);
   while (fp_iszero(v) == FP_NO) {
      int err = fp_mod(u, v, r);
      if (err != MP_OKAY) {
#ifdef WOLFSSL_SMALL_STACK
          XFREE(u, NULL, DYNAMIC_TYPE_BIGINT);
#endif
        return err;
      }
      fp_copy(v, u);
      fp_copy(r, v);
   }
    fp_copy(u, c);

 #ifdef WOLFSSL_SMALL_STACK
    XFREE(u, NULL, DYNAMIC_TYPE_BIGINT);
 #endif
    return FP_OKAY;
}

//GDCCCCCCCCCCCCCCCCCCC
//GDCCCCCCCCCCCCCCCCCCC
//GDCCCCCCCCCCCCCCCCCCC
//GDCCCCCCCCCCCCCCCCCCC
//GDCCCCCCCCCCCCCCCCCCC
//GDCCCCCCCCCCCCCCCCCCC
//GDCCCCCCCCCCCCCCCCCCC
//GDCCCCCCCCCCCCCCCCCCC
//GDCCCCCCCCCCCCCCCCCCC
//GDCCCCCCCCCCCCCCCCCCC
//GDCCCCCCCCCCCCCCCCCCC
//GDCCCCCCCCCCCCCCCCCCC

#if defined(FREESCALE_LTC_TFM)
int wolfcrypt_mp_mod (mp_int * a, mp_int * b, mp_int * c)
#else
int mp_mod (mp_int * a, mp_int * b, mp_int * c)
#endif
{
  return fp_mod (a, b, c);
}

int fp_cmp_d(fp_int *a, fp_digit b)
{
  /* special case for zero*/
  if (a->used == 0 && b == 0)
    return FP_EQ;

  /* compare based on sign */
  if ((b && a->used == 0) || a->sign == FP_NEG) {
    return FP_LT;
  }

  /* compare based on magnitude */
  if (a->used > 1) {
    return FP_GT;
  }

  /* compare the only digit of a to b */
  if (a->dp[0] > b) {
    return FP_GT;
  } else if (a->dp[0] < b) {
    return FP_LT;
  } else {
    return FP_EQ;
  }

}

void fp_div_2(fp_int * a, fp_int * b)
{
  int     x, oldused;

  oldused = b->used;
  b->used = a->used;
  {
    fp_digit r, rr, *tmpa, *tmpb;

    /* source alias */
    tmpa = a->dp + b->used - 1;

    /* dest alias */
    tmpb = b->dp + b->used - 1;

    /* carry */
    r = 0;
    for (x = b->used - 1; x >= 0; x--) {
      /* get the carry for the next iteration */
      rr = *tmpa & 1;

      /* shift the current digit, add in carry and store */
      *tmpb-- = (*tmpa-- >> 1) | (r << (DIGIT_BIT - 1));

      /* forward carry to next iteration */
      r = rr;
    }

    /* zero any excess digits on the destination that we didn't write to */
    tmpb = b->dp + b->used;
    for (x = b->used; x < oldused; x++) {
      *tmpb++ = 0;
    }
  }
  b->sign = a->sign;
  fp_clamp (b);
}

void fp_set(fp_int *a, fp_digit b)
{
   fp_zero(a);
   a->dp[0] = b;
   a->used  = a->dp[0] ? 1 : 0;
}

static int fp_invmod_slow (fp_int * a, fp_int * b, fp_int * c)
{
#ifndef WOLFSSL_SMALL_STACK
  fp_int  x[1], y[1], u[1], v[1], A[1], B[1], C[1], D[1];
#else
  fp_int  *x, *y, *u, *v, *A, *B, *C, *D;
#endif
  int     err;

  /* b cannot be negative */
  if (b->sign == FP_NEG || fp_iszero(b) == FP_YES) {
    return FP_VAL;
  }
  if (fp_iszero(a) == FP_YES) {
    return FP_VAL;
  }

#ifdef WOLFSSL_SMALL_STACK
  x = (fp_int*)XMALLOC(sizeof(fp_int) * 8, NULL, DYNAMIC_TYPE_BIGINT);
  if (x == NULL) {
      return FP_MEM;
  }
  y = &x[1]; u = &x[2]; v = &x[3]; A = &x[4]; B = &x[5]; C = &x[6]; D = &x[7];
#endif

  /* init temps */
  fp_init(x);    fp_init(y);
  fp_init(u);    fp_init(v);
  fp_init(A);    fp_init(B);
  fp_init(C);    fp_init(D);

  /* x = a, y = b */
  if ((err = fp_mod(a, b, x)) != FP_OKAY) {
  #ifdef WOLFSSL_SMALL_STACK
    XFREE(x, NULL, DYNAMIC_TYPE_BIGINT);
  #endif
    return err;
  }
  fp_copy(b, y);

  /* 2. [modified] if x,y are both even then return an error! */
  if (fp_iseven(x) == FP_YES && fp_iseven(y) == FP_YES) {
  #ifdef WOLFSSL_SMALL_STACK
    XFREE(x, NULL, DYNAMIC_TYPE_BIGINT);
  #endif
    return FP_VAL;
  }

  /* 3. u=x, v=y, A=1, B=0, C=0,D=1 */
  fp_copy (x, u);
  fp_copy (y, v);
  fp_set (A, 1);
  fp_set (D, 1);

top:
  /* 4.  while u is even do */
  while (fp_iseven (u) == FP_YES) {
    /* 4.1 u = u/2 */
    fp_div_2 (u, u);

    /* 4.2 if A or B is odd then */
    if (fp_isodd (A) == FP_YES || fp_isodd (B) == FP_YES) {
      /* A = (A+y)/2, B = (B-x)/2 */
      err = fp_add (A, y, A);
      if (err != FP_OKAY) {
      #ifdef WOLFSSL_SMALL_STACK
        XFREE(x, NULL, DYNAMIC_TYPE_BIGINT);
      #endif
        return err;
      }
      err = fp_sub (B, x, B);
      if (err != FP_OKAY) {
      #ifdef WOLFSSL_SMALL_STACK
        XFREE(x, NULL, DYNAMIC_TYPE_BIGINT);
      #endif
        return err;
      }
    }
    /* A = A/2, B = B/2 */
    fp_div_2 (A, A);
    fp_div_2 (B, B);
  }

  /* 5.  while v is even do */
  while (fp_iseven (v) == FP_YES) {
    /* 5.1 v = v/2 */
    fp_div_2 (v, v);

    /* 5.2 if C or D is odd then */
    if (fp_isodd (C) == FP_YES || fp_isodd (D) == FP_YES) {
      /* C = (C+y)/2, D = (D-x)/2 */
      err = fp_add (C, y, C);
      if (err != FP_OKAY) {
      #ifdef WOLFSSL_SMALL_STACK
        XFREE(x, NULL, DYNAMIC_TYPE_BIGINT);
      #endif
        return err;
      }
      err = fp_sub (D, x, D);
      if (err != FP_OKAY) {
      #ifdef WOLFSSL_SMALL_STACK
        XFREE(x, NULL, DYNAMIC_TYPE_BIGINT);
      #endif
        return err;
      }
    }
    /* C = C/2, D = D/2 */
    fp_div_2 (C, C);
    fp_div_2 (D, D);
  }

  /* 6.  if u >= v then */
  if (fp_cmp (u, v) != FP_LT) {
    /* u = u - v, A = A - C, B = B - D */
    err = fp_sub (u, v, u);
    if (err != FP_OKAY) {
    #ifdef WOLFSSL_SMALL_STACK
      XFREE(x, NULL, DYNAMIC_TYPE_BIGINT);
    #endif
      return err;
    }
    err = fp_sub (A, C, A);
    if (err != FP_OKAY) {
    #ifdef WOLFSSL_SMALL_STACK
      XFREE(x, NULL, DYNAMIC_TYPE_BIGINT);
    #endif
      return err;
    }
    err = fp_sub (B, D, B);
    if (err != FP_OKAY) {
    #ifdef WOLFSSL_SMALL_STACK
      XFREE(x, NULL, DYNAMIC_TYPE_BIGINT);
    #endif
      return err;
    }
  } else {
    /* v - v - u, C = C - A, D = D - B */
    err = fp_sub (v, u, v);
    if (err != FP_OKAY) {
    #ifdef WOLFSSL_SMALL_STACK
      XFREE(x, NULL, DYNAMIC_TYPE_BIGINT);
    #endif
      return err;
    }
    err = fp_sub (C, A, C);
    if (err != FP_OKAY) {
    #ifdef WOLFSSL_SMALL_STACK
      XFREE(x, NULL, DYNAMIC_TYPE_BIGINT);
    #endif
      return err;
    }
    err = fp_sub (D, B, D);
    if (err != FP_OKAY) {
    #ifdef WOLFSSL_SMALL_STACK
      XFREE(x, NULL, DYNAMIC_TYPE_BIGINT);
    #endif
      return err;
    }
  }

  /* if not zero goto step 4 */
  if (fp_iszero (u) == FP_NO)
    goto top;

  /* now a = C, b = D, gcd == g*v */

  /* if v != 1 then there is no inverse */
  if (fp_cmp_d (v, 1) != FP_EQ) {
  #ifdef WOLFSSL_SMALL_STACK
    XFREE(x, NULL, DYNAMIC_TYPE_BIGINT);
  #endif
    return FP_VAL;
  }

  /* if its too low */
  while (fp_cmp_d(C, 0) == FP_LT) {
    err = fp_add(C, b, C);
    if (err != FP_OKAY) {
    #ifdef WOLFSSL_SMALL_STACK
      XFREE(x, NULL, DYNAMIC_TYPE_BIGINT);
    #endif
      return err;
    }
  }

  /* too big */
  while (fp_cmp_mag(C, b) != FP_LT) {
    err = fp_sub(C, b, C);
    if (err != FP_OKAY) {
    #ifdef WOLFSSL_SMALL_STACK
      XFREE(x, NULL, DYNAMIC_TYPE_BIGINT);
    #endif
      return err;
    }
  }

  /* C is now the inverse */
  fp_copy(C, c);
#ifdef WOLFSSL_SMALL_STACK
  XFREE(x, NULL, DYNAMIC_TYPE_BIGINT);
#endif
  return FP_OKAY;
}

int fp_invmod(fp_int *a, fp_int *b, fp_int *c)
{
 #ifndef WOLFSSL_SMALL_STACK
  fp_int  x[1], y[1], u[1], v[1], B[1], D[1];
#else
  fp_int  *x, *y, *u, *v, *B, *D;
#endif
  int     neg;
  (void) neg;
  int     err;

  if (b->sign == FP_NEG || fp_iszero(b) == FP_YES) {
    return FP_VAL;
  }

  /* [modified] sanity check on "a" */
  if (fp_iszero(a) == FP_YES) {
    return FP_VAL; /* can not divide by 0 here */
  }

  /* 2. [modified] b must be odd   */
  if (fp_iseven(b) == FP_YES) {
    return fp_invmod_slow(a,b,c);
  }

#ifdef WOLFSSL_SMALL_STACK
  x = (fp_int*)XMALLOC(sizeof(fp_int) * 6, NULL, DYNAMIC_TYPE_BIGINT);
  if (x == NULL) {
      return FP_MEM;
  }
  y = &x[1]; u = &x[2]; v = &x[3]; B = &x[4]; D = &x[5];
#endif

  /* init all our temps */
  fp_init(x);  fp_init(y);
  fp_init(u);  fp_init(v);
  fp_init(B);  fp_init(D);

  if (fp_cmp(a, b) != MP_LT) {
    err = mp_mod(a, b, y);
    if (err != FP_OKAY) {
    #ifdef WOLFSSL_SMALL_STACK
      XFREE(x, NULL, DYNAMIC_TYPE_BIGINT);
    #endif
      return err;
    }
    a = y;
  }

  if (fp_iszero(a) == FP_YES) {
  #ifdef WOLFSSL_SMALL_STACK
    XFREE(x, NULL, DYNAMIC_TYPE_BIGINT);
  #endif
    return FP_VAL;
  }

  /* x == modulus, y == value to invert */
  fp_copy(b, x);

  /* we need y = |a| */
  fp_abs(a, y);

  /* 3. u=x, v=y, A=1, B=0, C=0,D=1 */
  fp_copy(x, u);
  fp_copy(y, v);
  fp_set (D, 1);
 
top:
  /* 4.  while u is even do */
  while (fp_iseven (u) == FP_YES) {
    /* 4.1 u = u/2 */
    fp_div_2 (u, u);

    /* 4.2 if B is odd then */
    if (fp_isodd (B) == FP_YES) {
      err = fp_sub (B, x, B);
      if (err != FP_OKAY) {
      #ifdef WOLFSSL_SMALL_STACK
        XFREE(x, NULL, DYNAMIC_TYPE_BIGINT);
      #endif
        return err;
      }
    }
    /* B = B/2 */
    fp_div_2 (B, B);
  }

  /* 5.  while v is even do */
  while (fp_iseven (v) == FP_YES) {
    /* 5.1 v = v/2 */
    fp_div_2 (v, v);

    /* 5.2 if D is odd then */
    if (fp_isodd (D) == FP_YES) {
      /* D = (D-x)/2 */
      err = fp_sub (D, x, D);
      if (err != FP_OKAY) {
      #ifdef WOLFSSL_SMALL_STACK
        XFREE(x, NULL, DYNAMIC_TYPE_BIGINT);
      #endif
        return err;
      }
    }
    /* D = D/2 */
    fp_div_2 (D, D);
  }

  /* 6.  if u >= v then */
  if (fp_cmp (u, v) != FP_LT) {
    /* u = u - v, B = B - D */
    err = fp_sub (u, v, u);
    if (err != FP_OKAY) {
    #ifdef WOLFSSL_SMALL_STACK
      XFREE(x, NULL, DYNAMIC_TYPE_BIGINT);
    #endif
      return err;
    }
  } else {
    /* v - v - u, D = D - B */
    err = fp_sub (v, u, v);
    if (err != FP_OKAY) {
    #ifdef WOLFSSL_SMALL_STACK
      XFREE(x, NULL, DYNAMIC_TYPE_BIGINT);
    #endif
      return err;
    }
    err = fp_sub (D, B, D);
    if (err != FP_OKAY) {
    #ifdef WOLFSSL_SMALL_STACK
      XFREE(x, NULL, DYNAMIC_TYPE_BIGINT);
    #endif
      return err;
    }
  }

  /* if not zero goto step 4 */
  if (fp_iszero (u) == FP_NO) {
    goto top;
  }

  /* now a = C, b = D, gcd == g*v */

  /* if v != 1 then there is no inverse */
  if (fp_cmp_d (v, 1) != FP_EQ) {
  #ifdef WOLFSSL_SMALL_STACK
    XFREE(x, NULL, DYNAMIC_TYPE_BIGINT);
  #endif
    return FP_VAL;
  }

  /* b is now the inverse */
  neg = a->sign;
  while (D->sign == FP_NEG) {
    err = fp_add (D, b, D);
    if (err != FP_OKAY) {
    #ifdef WOLFSSL_SMALL_STACK
      XFREE(x, NULL, DYNAMIC_TYPE_BIGINT);
    #endif
      return FP_OKAY;
    }
  }
   /* too big */
  while (fp_cmp_mag(D, b) != FP_LT) {
    err = fp_sub(D, b, D);
    if (err != FP_OKAY) {
    #ifdef WOLFSSL_SMALL_STACK
      XFREE(x, NULL, DYNAMIC_TYPE_BIGINT);
    #endif
      return err;
    }
  }
  fp_copy (D, c);
  c->sign = neg;
#ifdef WOLFSSL_SMALL_STACK
  XFREE(x, NULL, DYNAMIC_TYPE_BIGINT);
#endif
  return FP_OKAY;
}

#ifndef NO_MAIN_DRIVER

int main(int argc, char** argv)
{
    func_args args;

    args.argc = argc;
    args.argv = argv;
    args.return_code = 0;

#if (!defined(NO_WOLFSSL_CLIENT) || !defined(NO_WOLFSSL_SERVER)) && \
    !defined(WOLFCRYPT_ONLY) && defined(USE_WOLFSSL_IO)
    //bench_tls(&args);
#endif
    //PART 1#########################
    // wolfSSL_Init();

    // ecc_key     key1, key2, key3;

    // wc_ecc_init(&key1);
    // wc_ecc_init(&key2);
    // wc_ecc_init(&key3);
    
    // int ret;
    // while(1) ret = wc_ecc_mulmod(&key1.k, &key2.pubkey, &key3.pubkey, &key2.k, &key3.k, 1);
    // (void)ret;

    //PART 2#########################
    // fp_int *a, *b, *c;

    // a = (fp_int*)XMALLOC(sizeof(fp_int), NULL, DYNAMIC_TYPE_BIGINT);
    // b = (fp_int*)XMALLOC(sizeof(fp_int), NULL, DYNAMIC_TYPE_BIGINT);
    // c = (fp_int*)XMALLOC(sizeof(fp_int), NULL, DYNAMIC_TYPE_BIGINT);

    //int ret2;
    //while(1) ret2 = fp_gcd(a, b, c);
    //(void) ret2;
    //PART 3#########################
    // fp_int *a, *b, *c;

    // a = (fp_int*)XMALLOC(sizeof(fp_int), NULL, DYNAMIC_TYPE_BIGINT);
    // b = (fp_int*)XMALLOC(sizeof(fp_int), NULL, DYNAMIC_TYPE_BIGINT);
    // c = (fp_int*)XMALLOC(sizeof(fp_int), NULL, DYNAMIC_TYPE_BIGINT);

    // int ret3;
    // ret3 = fp_invmod(a, b, c);
    // (void) ret3;

    return args.return_code;
}

#endif /* !NO_MAIN_DRIVER */
