/*
 *  Copyright 2006-2025 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  yafcap.c
 *  YAF libpcap input support
 *
 *  ------------------------------------------------------------------------
 *  Authors: Brian Trammell
 *  ------------------------------------------------------------------------
 *  @DISTRIBUTION_STATEMENT_BEGIN@
 *  YAF 2.16
 *
 *  Copyright 2024 Carnegie Mellon University.
 *
 *  NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
 *  INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
 *  UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
 *  AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR
 *  PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF
 *  THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF
 *  ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT
 *  INFRINGEMENT.
 *
 *  Licensed under a GNU GPL 2.0-style license, please see LICENSE.txt or
 *  contact permission@sei.cmu.edu for full terms.
 *
 *  [DISTRIBUTION STATEMENT A] This material has been approved for public
 *  release and unlimited distribution.  Please see Copyright notice for
 *  non-US Government use and distribution.
 *
 *  This Software includes and/or makes use of Third-Party Software each
 *  subject to its own license.
 *
 *  DM24-1063
 *  @DISTRIBUTION_STATEMENT_END@
 *  ------------------------------------------------------------------------
 */

#define _YAF_SOURCE_
#include <yaf/autoinc.h>
#include <yaf/yafcore.h>
#include <yaf/yaftab.h>
#include "yafout.h"

#include <airframe/airlock.h>
#include <airframe/airutil.h>
#include <pcap.h>
#if YAF_ENABLE_ZLIB
#include <zlib.h>
#endif

#ifdef YAF_ENABLE_BIVIO
#include <pcap-zcopy.h>
#endif

#include "yafcap.h"
#include "yaflush.h"
#include "yafstat.h"


/* mkstemp() template for temporary file when decompressing; the temp
 * directory will be prepended to this */
#define YF_TMPFILE_TEMPLATE "yf_def_tmp.XXXXXX"

#define YF_CHUNK 16384
/*RFC 1950 */
#define ZLIB_HEADER 0x9C78
/* RFC 1952 */
#define GZIP_HEADER 0x8B1F

struct yfCapSource_st {
    pcap_t     *pcap;
    /* file holding a list of pcap filenames */
    FILE       *lfp;
    /* handle for processing a PCAP-NG file */
    FILE       *pcapng;
    /* directory for temporary files */
    const char *tmpdir;
    char       *last_filename;
    /* TRUE if file's headers must be byteswapped */
    gboolean    swap;
    /* TRUE when reading from an interface; FALSE when reading a file */
    gboolean    is_live;
    /* TRUE if  timestamps are in nanoseconds; FALSE if microseconds */
    gboolean    is_nano;
    int         datalink;
};

static pcap_t    *yaf_pcap;
static int        yaf_promisc_mode = 1;
static GTimer    *timer_pcap_file = NULL;

/* Statistics */
static uint32_t   yaf_pcap_drop = 0;
static uint32_t   yaf_stats_out = 0;
static uint32_t   yaf_ifdrop = 0;

/* One second timeout for capture loop */
#define YAF_CAP_TIMEOUT 1000

/* Process at most 64 packets at once */
#define YAF_CAP_COUNT   64

#define PCAPNG_BLOCKTYPE 0x0A0D0D0A

#ifdef HAVE_PCAP_SET_TSTAMP_PRECISION
/* pcap_set_tstamp_precision() and pcap_open_offline_with_tstamp_precision()
 * were both added in libpcap-1.5.1 */

#define YF_PCAP_OPEN(ypo_path, ypo_errbuf)                      \
    pcap_open_offline_with_tstamp_precision(                    \
        (ypo_path), PCAP_TSTAMP_PRECISION_NANO, (ypo_errbuf))
#define YF_PCAP_FOPEN(yfo_handle, yfo_errbuf)                   \
    pcap_fopen_offline_with_tstamp_precision(                   \
        (yfo_handle), PCAP_TSTAMP_PRECISION_NANO, (yfo_errbuf))

#else   /* HAVE_PCAP_SET_TSTAMP_PRECISION */

#define YF_PCAP_OPEN(ypo_path, ypo_errbuf)      \
    pcap_open_offline((ypo_path), (ypo_errbuf))
#define YF_PCAP_FOPEN(yfo_handle, yfo_errbuf)           \
    pcap_fopen_offline((yfo_handle), (yfo_errbuf))

#endif  /* HAVE_PCAP_SET_TSTAMP_PRECISION */


static gboolean
yfCapCheckDatalink(
    pcap_t  *pcap,
    int     *datalink,
    GError **err)
{
    /* verify datalink */
    *datalink = pcap_datalink(pcap);

    switch (*datalink) {
#ifdef DLT_EN10MB
      case DLT_EN10MB:
#endif
#ifdef DLT_C_HDLC
      case DLT_C_HDLC:
#endif
#ifdef DLT_LINUX_SLL
      case DLT_LINUX_SLL:
#endif
#ifdef DLT_PPP
      case DLT_PPP:
#endif
#ifdef DLT_PPP_ETHER
      case DLT_PPP_ETHER:
#endif
#ifdef DLT_RAW
      case DLT_RAW:
#endif
#ifdef DLT_NULL
      case DLT_NULL:
#endif
#ifdef DLT_LOOP
      case DLT_LOOP:
#endif
#ifdef DLT_JUNIPER_ETHER
      case DLT_JUNIPER_ETHER:
#endif
        break;
      case -1:
        g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_IO,
                    "Unable to access pcap datalink, (superuser access?)");
        return FALSE;
      default:
        g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_IO,
                    "Unsupported pcap datalink type %u", *datalink);
        return FALSE;
    }

    return TRUE;
}


static void
yfSwapBytes(
    uint8_t   *a,
    uint32_t   len)
{
    uint32_t i;
    uint8_t  t;

    for (i = 0; i < len / 2; i++) {
        t = a[i];
        a[i] = a[(len - 1) - i];
        a[(len - 1) - i] = t;
    }
}


static uint32_t
yfCapPcapNGBlockLen(
    yfCapSource_t  *cs)
{
    uint8_t  pr[10];
    uint32_t block_len;

    if (!fread(pr, 8, 1, cs->pcapng)) {
        g_warning("Failed to read 8 octets from PCAP-NG File");
    }
    if (cs->swap) {
        yfSwapBytes(pr, 4);
        yfSwapBytes(pr + 4, 4);
    }
    block_len = ntohl(*(uint32_t *)(pr));
    if (block_len != 0x00000006) {
        g_warning("Potentially malformed PCAP-NG File.\n");
    }

    block_len = ntohl(*(uint32_t *)(pr + 4));
    if (block_len >= 8) {
        fseek(cs->pcapng, (block_len - 8), SEEK_CUR);
    }

    return block_len;
}


static void
yfCapPcapNGCheck(
    yfCapSource_t  *cs,
    const char     *path)
{
    uint8_t  pr[10];
    uint32_t ng_magic;
    uint32_t block_len;

    /* check if this is a pcapng file */
    cs->pcapng = fopen(path, "r");
    if (!cs->pcapng) {
        return;
    }

    if (!fread(pr, sizeof(uint32_t), 1, cs->pcapng)) {
        goto ERROR;
    }
    ng_magic = ntohl(*(uint32_t *)(pr));
    if (ng_magic != PCAPNG_BLOCKTYPE) {
        /* not pcapng */
        goto ERROR;
    }

    /* get block length and magic number */
    if (!fread(pr, 8, 1, cs->pcapng)) {
        goto ERROR;
    }

    /* check magic number */
    ng_magic = ntohl(*(uint32_t *)(pr + 4));
    if (ng_magic == 0x4D3C2B1A) {
        /* need to swap */
        cs->swap = TRUE;
        yfSwapBytes(pr, 4);
    } else if (ng_magic != 0x1A2B3C4D) {
        /* this is weird */
        goto ERROR;
    }
    block_len = ntohl(*(uint32_t *)(pr));

    fseek(cs->pcapng, block_len, SEEK_SET);

    /* read inf header */
    if (!fread(pr, 8, 1, cs->pcapng)) {
        goto ERROR;
    }
    if (cs->swap) {
        yfSwapBytes(pr, 4);
        yfSwapBytes((pr + 4), 4);
    }
    ng_magic = ntohl(*(uint32_t *)(pr));
    if (ng_magic != 0x00000001) {
        /* no mandatory inf header */
        goto ERROR;
    }

    block_len = ntohl(*(uint32_t *)(pr + 4));
    if (block_len < 8) {
        goto ERROR;
    }

    fseek(cs->pcapng, block_len - 8, SEEK_CUR);
    /* now should be at packet header */
    return;

  ERROR:
    fclose(cs->pcapng);
    cs->pcapng = NULL;
    return;
}


#if YAF_ENABLE_ZLIB
static FILE *
yfCapFileDecompress(
    FILE        *src,
    const char  *tmp_dir)
{
    int           ret;
    z_stream      strm;
    unsigned int  leftover;
    unsigned char in[YF_CHUNK];
    unsigned char out[YF_CHUNK];
    FILE         *dst = NULL;
    int           fd;
    char          tmpname[YF_CHUNK];

    /*allocate state */
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = 0;
    strm.next_in = Z_NULL;

    if (tmp_dir) {
        snprintf(tmpname, YF_CHUNK, "%s/" YF_TMPFILE_TEMPLATE, tmp_dir);
    } else if (getenv("TMPDIR")) {
        const char *env = getenv("TMPDIR");
        snprintf(tmpname, YF_CHUNK, "%s/" YF_TMPFILE_TEMPLATE, env);
    } else {
        snprintf(tmpname, YF_CHUNK, "/tmp/" YF_TMPFILE_TEMPLATE);
    }

    g_debug("Input file is compressed, attempting decompression");

    fd = mkstemp(tmpname);
    if (fd == -1) {
        g_warning("Unable to open decompression tmp file '%s': %s",
                  tmpname, strerror(errno));
        return NULL;
    }

    dst = fdopen(fd, "wb+");
    if (!dst) {
        g_warning("Unable to open decompression tmp file '%s': %s",
                  tmpname, strerror(errno));
        close(fd);
        return NULL;
    }

    ret = inflateInit2(&strm, 16 + MAX_WBITS);
    if (ret != Z_OK) {
        fclose(dst);
        unlink(tmpname);
        return NULL;
    }

    do {
        strm.avail_in = fread(in, 1, YF_CHUNK, src);
        if (ferror(src)) {
            (void)inflateEnd(&strm);
            return NULL;
        }

        if (strm.avail_in == 0) {
            break;
        }
        strm.next_in = in;

        do {
            strm.avail_out = YF_CHUNK;
            strm.next_out = out;

            ret = inflate(&strm, Z_NO_FLUSH);
            if (ret == Z_STREAM_ERROR) { return NULL; }
            leftover = YF_CHUNK - strm.avail_out;
            if (fwrite(out, 1, leftover, dst) != leftover || ferror(dst)) {
                (void)inflateEnd(&strm);
                return NULL;
            }
        } while (strm.avail_out == 0);
    } while (ret != Z_STREAM_END);

    (void)inflateEnd(&strm);

    rewind(dst);
    unlink(tmpname);

    return dst;
}
#endif /* if YAF_ENABLE_ZLIB */


static pcap_t *
yfCapOpenFileInner(
    const char  *path,
    int         *datalink,
    const char  *tmp_dir,
    GError     **err)
{
    pcap_t     *pcap;
    static char pcap_errbuf[PCAP_ERRBUF_SIZE];

    if ((strlen(path) == 1) && path[0] == '-') {
        /* Don't open stdin if it's a terminal */
        if (isatty(fileno(stdin))) {
            g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_IO,
                        "Refusing to read from terminal on stdin");
            return NULL;
        }
    }

    pcap = YF_PCAP_OPEN(path, pcap_errbuf);
#if YAF_ENABLE_ZLIB
    /* if open_offline failed, decompress the file if it appears to be
     * compressed */
    if (!pcap) {
        FILE *tmp = fopen(path, "rb");
        FILE *out = NULL;
        if (tmp) {
            uint16_t header = 0;
            if (fread(&header, 1, sizeof(header), tmp) == sizeof(header)
                && ((header == ZLIB_HEADER) || (header == GZIP_HEADER)))
            {
                rewind(tmp);
                out = yfCapFileDecompress(tmp, tmp_dir);
                if (NULL == out) {
                    fclose(tmp);
                    g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_IO,
                                "File could not be decompressed.");
                    return NULL;
                }
                pcap = YF_PCAP_FOPEN(out, pcap_errbuf);
                fclose(tmp);
            }
        }
    }
#endif /* if YAF_ENABLE_ZLIB */

    if (!pcap) {
        /* failed to open pcap file (or the uncompressed file) */
        g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_IO,
                    "%s", pcap_errbuf);
        return NULL;
    }

    if (!yfCapCheckDatalink(pcap, datalink, err)) {
        pcap_close(pcap);
        return NULL;
    }

    g_debug("Reading packets from %s", path);

    return pcap;
}


yfCapSource_t *
yfCapOpenFile(
    const char  *path,
    int         *datalink,
    const char  *tmp_dir,
    GError     **err)
{
    yfCapSource_t *cs;

    cs = g_new0(yfCapSource_t, 1);
    cs->pcap = yfCapOpenFileInner(path, datalink, tmp_dir, err);
    cs->is_live = FALSE;
    cs->lfp = NULL;
    cs->datalink = *datalink;
    cs->tmpdir = tmp_dir;
    cs->last_filename = g_strdup(path);
#ifdef HAVE_PCAP_SET_TSTAMP_PRECISION
    /* file is always read as nano if libpcap supports it */
    cs->is_nano = TRUE;
#else
    cs->is_nano = FALSE;
#endif

    if (!cs->pcap) {
        g_free(cs->last_filename);
        g_free(cs);
        cs = NULL;
    } else {
        yfCapPcapNGCheck(cs, path);
    }

    return cs;
}


static gboolean
yfCapFileListNext(
    yfCapSource_t  *cs,
    GError        **err)
{
    static char cappath[FILENAME_MAX + 1];
    size_t cappath_len;
    int this_datalink;

    /* close the present pcap if necessary */
    if (cs->pcap) {
        pcap_close(cs->pcap);
        cs->pcap = NULL;
    }

    /* keep going until we get an actual opened pcap file */
    while (1) {
        /* get the next line from the name list file */
        if (!fgets(cappath, FILENAME_MAX, cs->lfp)) {
            if (feof(cs->lfp)) {
                g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_EOF,
                            "End of pcap file list");
            } else {
                g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_IO,
                            "Couldn't read pcap file list: %s", strerror(
                                errno));
            }
            return FALSE;
        }

        /* ensure filename is null terminated */
        cappath[FILENAME_MAX] = (char)0;

        /* skip comments and blank lines */
        if (cappath[0] == '\n' || cappath[0] == '#') {
            continue;
        }

        /* remove trailing newline */
        cappath_len = strlen(cappath);
        if (cappath[cappath_len - 1] == '\n') {
            cappath[cappath_len - 1] = (char)0;
        }

        /* we have what we think is a filename. try opening it. */
        cs->pcap = yfCapOpenFileInner(cappath, &this_datalink, cs->tmpdir, err);
        if (!cs->pcap) {
            g_warning("skipping pcap file %s due to error: %s.",
                      cappath, (*err)->message);
            g_clear_error(err);
            continue;
        }
#ifdef HAVE_PCAP_SET_TSTAMP_PRECISION
        /* file is always read as nano if libpcap supports it */
        cs->is_nano = TRUE;
#else
        cs->is_nano = FALSE;
#endif

        yfCapPcapNGCheck(cs, cappath);

        if (cs->last_filename) {
            g_free(cs->last_filename);
        }
        cs->last_filename = g_strdup(cappath);

        /* make sure the datalink matches all the others */
        if (cs->datalink == -1) {
            cs->datalink = this_datalink;
        } else if (cs->datalink != this_datalink) {
            g_warning("skipping pcap file %s due to mismatched "
                      "datalink type %u (expecting %u).",
                      cappath, this_datalink, cs->datalink);
            pcap_close(cs->pcap);
            cs->pcap = NULL;
            continue;
        }

        /* We have a file. All is well. */
        return TRUE;
    }
}


yfCapSource_t *
yfCapOpenFileList(
    const char  *path,
    int         *datalink,
    const char  *tmp_dir,
    GError     **err)
{
    yfCapSource_t *cs;

    /* allocate a new capsource */
    cs = g_new0(yfCapSource_t, 1);

    /* handle file list from stdin */
    if ((strlen(path) == 1) && path[0] == '-') {
        /* Don't open stdin if it's a terminal */
        if (isatty(fileno(stdin))) {
            g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_IO,
                        "Refusing to read from terminal on stdin");
            g_free(cs);
            return NULL;
        }
        cs->lfp = stdin;
    } else {
        /* open file list file */
        cs->lfp = fopen(path, "r");
        if (!cs->lfp) {
            g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_IO,
                        "Couldn't open pcap file list: %s", strerror(errno));
            g_free(cs);
            return NULL;
        }
    }

    /* note we're not live */
    cs->is_live = FALSE;
    cs->is_nano = FALSE;

    /* note we have no datalink yet */
    cs->datalink = -1;

    cs->tmpdir = tmp_dir;

    /* open the first pcap file in the file list */
    if (!yfCapFileListNext(cs, err)) {
        fclose(cs->lfp);
        g_free(cs);
        return NULL;
    }

    /* copy datalink back out of capsource */
    *datalink = cs->datalink;

    /* all done */
    return cs;
}


static gboolean
yfSetPcapFilter(
    pcap_t      *pcap,
    const char  *bpf_expr,
    GError     **err)
{
    struct bpf_program bpf;

    /* attach filter */
    if (pcap_compile(pcap, &bpf, bpf_expr, 1, 0) < 0) {
        g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_ARGUMENT,
                    "Could not compile BPF expression %s: %s",
                    bpf_expr, pcap_geterr(pcap));
        return FALSE;
    }
    if (pcap_setfilter(pcap, &bpf)) {
        g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_ARGUMENT,
                    "Unable to set BPF expression %s: %s",
                    bpf_expr, pcap_geterr(pcap));
        pcap_freecode(&bpf);
        return FALSE;
    }
    pcap_freecode(&bpf);

    return TRUE;
}


void
yfSetPromiscMode(
    int   mode)
{
    yaf_promisc_mode = mode;
}


#if defined(YAF_ENABLE_BIVIO) || !defined(HAVE_PCAP_SET_TSTAMP_PRECISION)

/* open interface using pcap_open_live() */
static yfCapSource_t *
yfCapOpenLiveInner(
    const char  *ifname,
    int          snaplen,
    GError     **err)
{
    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    yfCapSource_t *cs;
    pcap_t *pcap;

    pcap = pcap_open_live(ifname, snaplen, yaf_promisc_mode,
                          YAF_CAP_TIMEOUT, pcap_errbuf);
    if (!pcap) {
        g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_IO,
                    "Unable to capture pcap from %s: %s",
                    ifname, pcap_errbuf);
        return NULL;
    }

#ifdef YAF_ENABLE_BIVIO
    if (!pcap_is_zcopy(pcap)) {
        g_warning("ZCOPY Not enabled on Bivio");
    }
#endif

    cs = g_new0(yfCapSource_t, 1);
    cs->pcap = pcap;
    cs->is_nano = FALSE;
    cs->datalink = -1;

    return cs;
}

#else  /* YAF_ENABLE_BIVIO || !HAVE_PCAP_SET_TSTAMP_PRECISION */

/* open interface using pcap_create(), pcap_activate() */
static yfCapSource_t *
yfCapOpenLiveInner(
    const char  *ifname,
    int          snaplen,
    GError     **err)
{
    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    yfCapSource_t *cs;
    int tstamp_prec;
    int rc;

    cs = g_new0(yfCapSource_t, 1);
    cs->is_nano = FALSE;
    cs->datalink = -1;

    cs->pcap = pcap_create(ifname, pcap_errbuf);
    if (!cs->pcap) {
        g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_IO,
                    "Unable to capture pcap from %s: %s",
                    ifname, pcap_errbuf);
        g_free(cs);
        return NULL;
    }

    /* apply settings that pcap_open_live() handles */
    if ((0 != (rc = pcap_set_snaplen(cs->pcap, snaplen)))
        || (0 != (rc = pcap_set_promisc(cs->pcap, yaf_promisc_mode)))
        || (0 != (rc = pcap_set_timeout(cs->pcap, YAF_CAP_TIMEOUT))))
    {
        g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_IO,
                    "Error configuring packet capture: %s",
                    pcap_statustostr(rc));
        goto ERROR;
    }

    /* attempt to use nanosecond precision */
    tstamp_prec = pcap_get_tstamp_precision(cs->pcap);
    if (PCAP_TSTAMP_PRECISION_NANO == tstamp_prec) {
        cs->is_nano = TRUE;
    } else {
        rc = pcap_set_tstamp_precision(cs->pcap, PCAP_TSTAMP_PRECISION_NANO);
        switch (rc) {
          case 0:
            cs->is_nano = TRUE;
            break;
          case PCAP_ERROR_TSTAMP_PRECISION_NOTSUP:
            if (0 != (rc = pcap_set_tstamp_precision(cs->pcap, tstamp_prec))) {
                g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_IO,
                            "Unable to set pcap precision back to default: %s",
                            pcap_statustostr(rc));
                goto ERROR;
            }
            break;
          default:
            g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_IO,
                        "Unable to set pcap precision to nanoseconds: %s",
                        pcap_statustostr(rc));
            goto ERROR;
        }
    }

    rc = pcap_activate(cs->pcap);
    switch (rc) {
      case 0:
        break;
      case PCAP_WARNING_PROMISC_NOTSUP:
      case PCAP_WARNING:
        g_warning("Packet captured enabled but also generated a warning: %s",
                  pcap_geterr(cs->pcap));
        break;
      case PCAP_ERROR_NO_SUCH_DEVICE:
      case PCAP_ERROR_PERM_DENIED:
      case PCAP_ERROR:
        g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_IO,
                    "Unable to activate pcap: %s", pcap_geterr(cs->pcap));
        goto ERROR;
      case PCAP_ERROR_IFACE_NOT_UP:
        g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_IO,
                    "Unable to activate pcap: interface %s is not up: %s",
                    ifname, pcap_statustostr(rc));
        goto ERROR;
      case PCAP_ERROR_PROMISC_PERM_DENIED:
      case PCAP_ERROR_RFMON_NOTSUP:
      default:
        if (rc < 0) {
            g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_IO,
                        "Unable to activate pcap %s", pcap_statustostr(rc));
            goto ERROR;
        }
        g_warning("Packet capture enabled but also generated a warning: %s",
                  pcap_statustostr(rc));
        break;
    }

    return cs;

  ERROR:
    pcap_close(cs->pcap);
    g_free(cs);
    return NULL;
}

#endif  /* #else of #if YAF_ENABLE_BIVIO || !HAVE_PCAP_SET_TSTAMP_PRECISION */


yfCapSource_t *
yfCapOpenLive(
    const char  *ifname,
    int          snaplen,
    int         *datalink,
    GError     **err)
{
    yfCapSource_t *cs;

    cs = yfCapOpenLiveInner(ifname, snaplen, err);
    if (NULL == cs) {
        return NULL;
    }

    if (!yfCapCheckDatalink(cs->pcap, datalink, err)) {
        pcap_close(cs->pcap);
        g_free(cs);
        return NULL;
    }

    cs->is_live = TRUE;
    cs->lfp = NULL;
    cs->datalink = *datalink;

    return cs;
}


void
yfCapClose(
    yfCapSource_t  *cs)
{
    if (cs->pcap) {
        pcap_close(cs->pcap);
    }
    if (cs->lfp) {
        fclose(cs->lfp);
    }
    g_free(cs->last_filename);
    g_free(cs);
}


static void
yfCapUpdateStats(
    pcap_t  *pcap)
{
    struct pcap_stat ps;

    if (pcap_stats(pcap, &ps) != 0) {
        g_warning("couldn't get statistics: %s", pcap_geterr(pcap));
        return;
    }

    yaf_pcap_drop = ps.ps_drop;
    yaf_ifdrop = ps.ps_ifdrop;
}


void
yfCapDumpStats(
    void)
{
    if (yaf_stats_out) {
        g_debug("yaf Exported %u stats records.", yaf_stats_out);
    }

    if (yaf_pcap_drop) {
        g_warning("Live capture device dropped %u packets.", yaf_pcap_drop);
    }

    if (yaf_ifdrop) {
        g_warning("Network Interface dropped %u packets.", yaf_ifdrop);
    }
}


static pcap_dumper_t *
yfCapPcapRotate(
    yfContext_t  *ctx)
{
    pcap_dumper_t *pcap_ret = NULL;
    GString *namebuf = g_string_new(NULL);
    AirLock *lock = &(ctx->pcap_lock);
    GError *err = NULL;
    static uint32_t serial = 0;

    if (ctx->pcap) {
        pcap_dump_flush(ctx->pcap);
        pcap_dump_close(ctx->pcap);
        air_lock_release(lock);
    }

    ctx->pcap_offset = sizeof(struct pcap_file_header);

    g_string_append_printf(namebuf, "%s", ctx->cfg->pcapdir);
    air_time_g_string_append(namebuf, time(NULL), AIR_TIME_SQUISHED);
    g_string_append_printf(namebuf, "_%05u.pcap", serial++);

    air_lock_acquire(lock, namebuf->str, &err);

    yfUpdateRollingPcapFile(ctx->flowtab, namebuf->str);

    pcap_ret = pcap_dump_open(yaf_pcap, namebuf->str);

    if (pcap_ret == NULL) {
        g_warning("Could not open new rolling pcap file: %s",
                  pcap_geterr(yaf_pcap));
        g_warning("Turning off pcap export...");
        ctx->cfg->pcapdir = NULL;
    }

    g_string_free(namebuf, TRUE);

    if (ctx->cfg->pcap_timer) {
        if (!timer_pcap_file) {
            timer_pcap_file = g_timer_new();
        }
        g_timer_start(timer_pcap_file);
    }

    return pcap_ret;
}


/**
 * yfCapHandle
 *
 * This is the function that gets the call back from the PCAP library
 * when a packet arrives; it does not get called directly from within
 * yaf.
 *
 * @param ctx opaque pointer to PCAP, holds the YAF context for the capture
 * @param hdr PCAP capture details (time, packet length, capture length)
 * @param pkt pointer to the captured packet
 *
 */
static void
yfCapHandle(
    yfContext_t               *ctx,
    const struct pcap_pkthdr  *hdr,
    const uint8_t             *pkt)
{
#ifdef YAF_ENABLE_BIVIO
    int iface = 0;
#endif
    yfPBuf_t       *pbuf;
    yfCapSource_t  *cs = (yfCapSource_t *)ctx->pktsrc;
    yfTime_t        ptime;
    yfIPFragInfo_t  fraginfo_buf;
    yfIPFragInfo_t *fraginfo = (ctx->fragtab ? &fraginfo_buf : NULL);

    /* get next spot in ring buffer */
    pbuf = (yfPBuf_t *)rgaNextHead(ctx->pbufring);
    g_assert(pbuf);

    /* pcap-per-flow info to pass to decode */
    pbuf->pcap_hdr.ts = hdr->ts;
    pbuf->pcap_hdr.len = hdr->len;
    pbuf->pcap_hdr.caplen = hdr->caplen;
    pbuf->pcapt = yaf_pcap;

#ifdef YAF_ENABLE_BIVIO
    iface = pcap_zcopy_get_origin(cs->pcap, pkt);
    if (iface < 0) {
        g_warning("Unable to retrieve interface ID %s", pcap_geterr(cs->pcap));
    } else {
        pbuf->key.netIf = iface;
    }
#endif /* ifdef YAF_ENABLE_BIVIO */

    /* rolling pcap dump */
    if (ctx->pcap) {
        pcap_dump((u_char *)ctx->pcap, hdr, pkt);
    }

    pbuf->pcap_offset = ctx->pcap_offset;

    if (cs->pcapng) {
        ctx->pcap_offset += yfCapPcapNGBlockLen(cs);
    } else {
        ctx->pcap_offset += (16 + pbuf->pcap_hdr.caplen);
    }

    /* Get the packet's timestamp. */
#ifdef HAVE_PCAP_SET_TSTAMP_PRECISION
    if (cs->is_nano) {
        /* Fractional seconds in timespec may be 32-bits or 64-bits */
        struct timespec ts;
        if (sizeof(hdr->ts.tv_usec) == sizeof(ts.tv_nsec)) {
            yfTimeFromTimespec(&ptime, (struct timespec *)&hdr->ts);
        } else {
            /* Always copy when sizes differ since there is no guarantee the
             * unused bytes in the timeval are zero. */
            ts.tv_sec = hdr->ts.tv_sec;
            ts.tv_nsec = hdr->ts.tv_usec;
            yfTimeFromTimespec(&ptime, &ts);
        }
    } else
#endif  /* HAVE_PCAP_SET_TSTAMP_PRECISION */
    {
        yfTimeFromTimeval(&ptime, &hdr->ts);
    }

    /* Decode packet into packet buffer */
    if (!yfDecodeToPBuf(ctx->dectx, &ptime,
                        hdr->caplen, pkt,
                        fraginfo, ctx->pbuflen, pbuf))
    {
        /* Couldn't decode packet; counted in dectx. Skip. */
        return;
    }

    /* Handle fragmentation if necessary */
    if (fraginfo && fraginfo->frag) {
        if (!yfDefragPBuf(ctx->fragtab, fraginfo,
                          ctx->pbuflen, pbuf, pkt, hdr->caplen))
        {
            /* No complete defragmented packet available. Skip. */
            return;
        }
    }
}


/**
 * yfCapMain
 *
 *
 *
 *
 */
gboolean
yfCapMain(
    yfContext_t  *ctx)
{
    gboolean ok = TRUE;
    gboolean buf_excess = FALSE;
    yfCapSource_t *cs = (yfCapSource_t *)ctx->pktsrc;
    int pcrv = 0;
    char *bp_filter = (char *)ctx->cfg->bpf_expr;
    GTimer *stimer = NULL;                   /* to export stats */

    if (cs->pcapng) {
        ctx->pcap_offset = ftell(cs->pcapng);
    } else {
        ctx->pcap_offset = sizeof(struct pcap_file_header);
    }

    if (!cs->is_live) {
        yfUpdateRollingPcapFile(ctx->flowtab, cs->last_filename);
    }

    if (!ctx->cfg->nostats) {
        stimer = g_timer_new();
    }

    if (ctx->cfg->pcapdir) {
        if (!yfTimeOutFlush(ctx, yaf_pcap_drop + yaf_ifdrop, &yaf_stats_out,
                            yfStatGetTimer(), stimer,
                            &(ctx->err)))
        {
            ok = FALSE;
            yaf_quit = TRUE;
        }
    }

#ifdef YAF_ENABLE_BIVIO
    if (pcap_zcopy_add_all_interfaces(cs->pcap) == -1) {
        g_warning("Error adding zcopy interfaces %s", pcap_geterr(cs->pcap));
    }
#endif

    if (ctx->cfg->pcapdir && !ctx->cfg->pcap_per_flow) {
        yaf_pcap = cs->pcap;
        ctx->pcap = yfCapPcapRotate(ctx);
    }

    if (bp_filter) {
        if (!yfSetPcapFilter(cs->pcap, bp_filter, &(ctx->err))) {
            return FALSE;
        }
    }

    /* process input until we're done */
    while (!yaf_quit) {
        yaf_pcap = cs->pcap;

        /* Process some packets */
        pcrv = pcap_dispatch(cs->pcap, YAF_CAP_COUNT,
                             (pcap_handler)yfCapHandle, (void *)ctx);

        /* Handle the aftermath */
        if (pcrv == 0) {
            /* No packet available */
            if (cs->lfp) {
                /* Advance to next capfile */
                if (!yfCapFileListNext(cs, &(ctx->err))) {
                    if (!g_error_matches(ctx->err, YAF_ERROR_DOMAIN,
                                         YAF_ERROR_EOF))
                    {
                        ok = FALSE;
                    }
                    buf_excess = TRUE;
                    g_clear_error(&(ctx->err));
                    break;
                }
                /* new packet source, set the filter */
                if (bp_filter) {
                    yfSetPcapFilter(cs->pcap, bp_filter, &(ctx->err));
                }
                yfDecodeResetOffset(ctx->dectx);
                yfUpdateRollingPcapFile(ctx->flowtab, cs->last_filename);
                if (!ctx->pcap) {
                    if (cs->pcapng) {
                        ctx->pcap_offset = ftell(cs->pcapng);
                    } else {
                        ctx->pcap_offset = sizeof(struct pcap_file_header);
                    }
                }
            } else if (!cs->is_live) {
                /* EOF in single capfile mode; break; will check to see if
                 * excess in buffer */
                buf_excess = TRUE;
                break;
            } else {
                /* Live, no packet processed (timeout). Flush buffer */
                if (!yfTimeOutFlush(ctx, yaf_pcap_drop + yaf_ifdrop,
                                    &yaf_stats_out,
                                    yfStatGetTimer(), stimer,
                                    &(ctx->err)))
                {
                    ok = FALSE;
                    break;
                }
                continue;
            }
        } else if (pcrv < 0) {
            if (ctx->cfg->noerror && cs->lfp) {
                g_warning("Couldn't read next pcap record from %s: %s",
                          ctx->cfg->inspec, pcap_geterr(cs->pcap));
                if (!yfCapFileListNext(cs, &(ctx->err))) {
                    /* An error occurred reading packets. */
                    ok = FALSE;
                    break;
                }
                /* now that we have a new packet source, set the filter */
                if (bp_filter) {
                    yfSetPcapFilter(cs->pcap, bp_filter, &(ctx->err));
                }
                yfDecodeResetOffset(ctx->dectx);
                yfUpdateRollingPcapFile(ctx->flowtab, cs->last_filename);
                if (!ctx->pcap) {
                    if (cs->pcapng) {
                        ctx->pcap_offset = ftell(cs->pcapng);
                    } else {
                        ctx->pcap_offset = sizeof(struct pcap_file_header);
                    }
                }
            } else {
                if (ctx->cfg->noerror) {
                    g_warning("Couldn't read next pcap record from %s: %s",
                              ctx->cfg->inspec, pcap_geterr(cs->pcap));
                    ok = TRUE;
                } else {
                    /* An error occurred reading packets. */
                    g_set_error(&(ctx->err), YAF_ERROR_DOMAIN, YAF_ERROR_IO,
                                "Couldn't read next pcap record from %s: %s",
                                ctx->cfg->inspec, pcap_geterr(cs->pcap));
                    ok = FALSE;
                }
                break;
            }
        }

        /* Process the packet buffer */
        if (ok && !yfProcessPBufRing(ctx, &(ctx->err))) {
            ok = FALSE;
            break;
        }

        if (ok && !ctx->cfg->nostats) {
            if (g_timer_elapsed(stimer, NULL) > ctx->cfg->stats_interval) {
                /* Update packet drop statistics for live capture */
                if (cs->is_live) {
                    yfCapUpdateStats(cs->pcap);
                }

                if (!yfWriteOptionsDataFlows(ctx, yaf_pcap_drop + yaf_ifdrop,
                                             yfStatGetTimer(),
                                             &(ctx->err)))
                {
                    ok = FALSE;
                    break;
                }
                g_timer_start(stimer);
                yaf_stats_out++;
            }
        }

        if (ok && ctx->cfg->pcapdir && !ctx->cfg->pcap_per_flow) {
            if (!ctx->pcap ||
                (ftell(pcap_dump_file(ctx->pcap)) > (long)ctx->cfg->max_pcap) ||
                (timer_pcap_file && (g_timer_elapsed(timer_pcap_file, NULL) >
                                     ctx->cfg->pcap_timer)))
            {
                ctx->pcap = yfCapPcapRotate(ctx);
            }
        }
    }

    /* Process any excess in packet buffer */
    if (buf_excess) {
        if (ok && !yfProcessPBufRing(ctx, &(ctx->err))) {
            ok = FALSE;
        }
    }

    /* Update packet drop statistics for live capture */
    if (cs->is_live) {
        yfCapUpdateStats(cs->pcap);
    }

    /* Handle final flush */
    if (!ctx->cfg->nostats) {
        /* add one for final flush */
        if (ok) {
            yaf_stats_out++;
        }
        /* free timer */
        g_timer_destroy(stimer);
    }

    if (ctx->pcap) {
        pcap_dump_flush(ctx->pcap);
        pcap_dump_close(ctx->pcap);
        air_lock_release(&(ctx->pcap_lock));
        air_lock_cleanup(&(ctx->pcap_lock));
        if (timer_pcap_file) {
            g_timer_destroy(timer_pcap_file);
        }
    }

    return yfFinalFlush(ctx, ok, yaf_pcap_drop + yaf_ifdrop,
                        yfStatGetTimer(), &(ctx->err));
}
