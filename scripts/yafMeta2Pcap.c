/*
 *  Copyright 2006-2025 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  yafMeta2Pcap
 *  Creates a PCAP file from a YAF meta file.
 *
 *  ------------------------------------------------------------------------
 *  Author: Emily Sarneso
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

/**
 *  @file yafMeta2Pcap
 *
 *  This program takes the pcap meta file created by YAF
 *  and a flow key hash and start time and creates the pcap file
 *  for the flow.
 *  Use the getFlowKeyHash program to calculate the flow key hash.
 */


/*
 *  _XOPEN_SOURCE is required on RHEL8+ for strptime()
 *
 *  Either _DEFAULT_SOURCE (glibc >= 2.19) or _BSD_SOURCE (glibc < 2.19) is
 *  also needed since specifying _XOPEN_SOURCE disables them.
 */
#define _XOPEN_SOURCE
#define _DEFAULT_SOURCE
#define _BSD_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <libgen.h>
#include <glib.h>
#include <string.h>
#include <pcap.h>
#include <fixbuf/public.h>
#include <glob.h>
#include <time.h>
#include <airframe/airutil.h>

/* fixbuf 2.x uses char* as the type of the name of info elements in
 * fbInfoElementSpec_t; wrap this around string literals to quiet compiler
 * warnings */
#define C(String) (char *)String

#define MAX_LINE 4096
#define MAX_PATH 100
#define MAX_WINDOW 30

/* Possible Environment Variables */
#define YAF_PCAP_META_FILE "YAF_PCAP_META_FILE"
#define YAF_CAPLIST "YAF_CAPLIST"
#define YAF_PCAP_META_LIST "YAF_PCAP_META_LIST"

static const char   temp_suffix[] = ".XXXXXX";
static char        *meta_file = NULL;
static char       **meta_array = NULL;
static char        *out_file = NULL;
static uint64_t        flowkeyhash = 0;
static char        *flowstarttime = NULL;
static char        *flowendtime = NULL;
static char        *pcap_glob = NULL;
static char       **pcap_array = NULL;
static char        *caplist = NULL;
static char        *metalist = NULL;
static gboolean     verbose = FALSE;
static int          num_packets = -1;
static gboolean     ipfix = FALSE;
static int          meta_files_num = 0;
static int          pcap_files_num = 0;
static char        *yaf_prog_path = NULL;
static int          timewindow = 0;

static GOptionEntry md_core_option[] = {
    {"pcap-meta-file", 'f', 0, G_OPTION_ARG_STRING, &meta_file,
     "Pcap meta file (pattern) created by YAF. Required.", "file" },
    {"pcap", 'p', 0, G_OPTION_ARG_STRING, &pcap_glob,
     "Pcap file (pattern) to read if full path \n\t\t\t\t"
     "is not specified in pcap_meta_file.", "file"},
    {"caplist", 'c', 0, G_OPTION_ARG_STRING, &caplist,
     "Ordered List of pcap files [--caplist] given to "
     "\n\t\t\t\tyaf with full paths to pcaps.", "file" },
    {"metalist", 'm', 0, G_OPTION_ARG_STRING, &metalist,
     "Ordered List of meta files created by yaf "
     "\n\t\t\t\twith full paths to files.", "file"},
    {"out", 'o', 0, G_OPTION_ARG_STRING, &out_file,
     "Pcap output file.", "file" },
    {"hash", 'h', 0, G_OPTION_ARG_INT64, &flowkeyhash,
     "Flow Key Hash. Required.", "hash" },
    {"time", 't', 0, G_OPTION_ARG_STRING, &flowstarttime,
     "Time in milliseconds. Suggested, \n\t\t\t\tbut not required.", "ms" },
    {"etime", 'e', 0, G_OPTION_ARG_STRING, &flowendtime,
     "End time in milliseconds. Suggested, \n\t\t\t\tbut not required.", "ms" },
    {"window", 'w', 0, G_OPTION_ARG_INT, &timewindow,
     "Number of milliseconds past the start \n\t\t\t\ttime to search "
     "for flow key hash. Search time window, not exact time.", "ms"},
    {"packets", 'n', 0, G_OPTION_ARG_INT, &num_packets,
     "Use to limit number of packets searched \n\t\t\t\tfor/found [all]",
     "num"},
    {"yaf-program", 'y', 0, G_OPTION_ARG_STRING, &yaf_prog_path,
     "The location of the YAF program to use. When not\n\t\t\t\tspecified,"
     " yafMeta2Pcap assumes there is a \n\t\t\t\tprogram yaf on your $PATH",
     "path"},
    {"verbose", 'v', 0, G_OPTION_ARG_NONE, &verbose,
     "Print debug information to stdout.", NULL },
    { NULL, 0, 0, G_OPTION_ARG_NONE, NULL, NULL, NULL }
};


static fbInfoElement_t     new_info_elements[] = {
    FB_IE_INIT("yafFlowKeyHash", 6841, 106, 4,
               FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_NULL
};


static fbInfoElementSpec_t simple_flow[] = {
    {C("flowStartMilliseconds"),            8, 0 },
    {C("flowEndMilliseconds"),              8, 0 },
    {C("packetTotalCount"),                 8, 0 },
    {C("yafFlowKeyHash"),                   4, 0 },
    {C("reverseYafFlowKeyHash"),            4, 0 },
    FB_IESPEC_NULL
};

typedef struct simpleFlow_st {
    uint64_t   sms;
    uint64_t   ems;
    uint64_t   pkt;
    uint32_t   hash;
    uint32_t   rhash;
} simpleFlow_t;


static gboolean
collectIPFIX(
    simpleFlow_t  *rec,
    GError       **err)
{
    fbSession_t   *session = NULL;
    fbTemplate_t  *template = NULL;
    fbTemplate_t  *nt = NULL;
    fBuf_t        *buf = NULL;
    fbCollector_t *coll = NULL;
    fbInfoModel_t *infoModel = NULL;
    simpleFlow_t   flow;
    size_t         len;
    int            rc;
    int            count = 0;
    uint16_t       tid;

    infoModel = fbInfoModelAlloc();

    fbInfoModelAddElementArray(infoModel, new_info_elements);

    template = fbTemplateAlloc(infoModel);

    rc = fbTemplateAppendSpecArray(template, simple_flow, 0, err);
    if (!rc) {
        return FALSE;
    }

    session = fbSessionAlloc(infoModel);
    rc = fbSessionAddTemplate(session, TRUE, 999, template, err);
    if (!rc) {
        return FALSE;
    }

    coll = fbCollectorAllocFile(NULL, "-", err);
    if (!coll) {
        return FALSE;
    }

    buf = fBufAllocForCollection(session, coll);

    rc = fBufSetInternalTemplate(buf, 999, err);
    if (!rc) {
        return FALSE;
    }

    len = sizeof(flow);

    while (1) {
        nt = fBufNextCollectionTemplate(buf, &tid, err);
        if (nt) {
            if (fbTemplateGetOptionsScope(nt)) {
                rc = fBufNext(buf, (uint8_t *)&flow, &len, err);
                if (!rc) {goto err;}
                continue;
            }
        } else {goto err;}

        rc = fBufNext(buf, (uint8_t *)&flow, &len, err);

        if (!rc) {goto err;}

        if (!count) {
            rec->sms = flow.sms;
            rec->ems = flow.ems;
            rec->pkt = flow.pkt;
            rec->hash = flow.hash;
            rec->rhash = flow.rhash;
            count++;
        } else if (count == 1) {
            if (rec->sms == flow.sms) {
                /* add packet count together for bi-flow */
                rec->pkt += flow.pkt;
            }
            count++;
        }

        continue;

      err:
        if (g_error_matches(*err, FB_ERROR_DOMAIN, FB_ERROR_EOM)) {
            g_clear_error(err);
            continue;
        } else {
            fBufFree(buf);
            if (g_error_matches(*err, FB_ERROR_DOMAIN, FB_ERROR_EOF)) {
                g_clear_error(err);
                return TRUE;
            }
            return FALSE;
        }
    }
    return TRUE;
}


static void
yfPcapWrite(
    pcap_dumper_t             *file,
    const struct pcap_pkthdr  *hdr,
    const uint8_t             *pkt)
{
    pcap_dump((u_char *)file, hdr, pkt);
}


static void
yfUseIndex(
    FILE      *fp,
    uint64_t   rstart,
    uint64_t   offset,
    uint64_t   start_to_find,
    uint64_t   etime)
{
    long  last_offset = 0;
    char  line[4092];
    char *tok = NULL;
    int   done = 0;

    if (etime) {
        if (etime < rstart) {
            return;
        }
    }

    fseek(fp, offset, SEEK_SET);

    while (fgets(line, 4092, fp)) {
        tok = strtok(line, "|");
        rstart = strtoull(tok, NULL, 10);
        if (start_to_find <= rstart) {
            /* go to the last one */
            fseek(fp, last_offset, SEEK_SET);
            fgets(line, 4092, fp);
            /* skip index line */
            return;
        } else if (etime) {
            if (etime < rstart) {
                /* done */
                return;
            }
        } else {
            /* go to the next one */
            tok = strtok(NULL, "|");
            last_offset = offset;
            offset = strtoull(tok, NULL, 10);
            if (offset == 0) {
                if (done) {
                    return;
                }
                done = 1;
            }
            fseek(fp, offset, SEEK_SET);
        }
    }
    fseek(fp, last_offset, SEEK_SET);
    fgets(line, 4092, fp);
    /* jump to last index */
}


static void
yfMetaParseOptions(
    void)
{
    FILE  *fp = NULL;
    char   line[MAX_LINE];
    size_t i;

    if (meta_file == NULL && metalist == NULL) {
        const char *env = getenv(YAF_PCAP_META_FILE);
        const char *env2 = getenv(YAF_PCAP_META_LIST);
        if (env == NULL && env2 == NULL) {
            fprintf(stderr,
                    "Error: --pcap-meta-file or --metalist  is required\n");
            fprintf(stderr, "Use --help for usage.\n");
            exit(-1);
        } else {
            if (env2) {
                metalist = g_strdup(env2);
            } else {
                meta_file = g_strdup(env);
                /* meta_array = (char **)calloc(1, sizeof(char *));
                 * meta_array[0] = g_strdup(env);
                 * meta_files_num = 1;*/
            }
        }
    }

    if (metalist) {
        /* read list of meta files */
        fp = fopen(metalist, "r");
        if (fp == NULL) {
            fprintf(stderr, "Cannot open metalist file %s\n", metalist);
            exit(-1);
        }
        meta_array = (char **)calloc(MAX_LINE, sizeof(char *));
        while (fgets(line, MAX_LINE, fp) && meta_files_num < MAX_LINE) {
            meta_array[meta_files_num] = (char *)calloc(1, MAX_LINE);
            strncpy(meta_array[meta_files_num], line, strlen(line) - 1);
            meta_files_num++;
        }
        fclose(fp);
        fp = NULL;
    } else if (meta_file) {
        glob_t gbuf;
        int    grc;

        grc = glob(meta_file, GLOB_NOSORT, NULL, &gbuf);
        if (grc == GLOB_NOMATCH) {
            fprintf(stderr, "No match for %s. No such file(s).\n", meta_file);
            exit(-1);
        }
        meta_array = (char **)calloc(MAX_LINE, sizeof(char *));
        for (i = 0; i < gbuf.gl_pathc; i++) {
            meta_array[i] = g_strdup(gbuf.gl_pathv[i]);
            meta_files_num++;
        }
        globfree(&gbuf);
    }

    if (pcap_glob == NULL && !caplist) {
        /* is env variable set? */
        const char *env = getenv(YAF_CAPLIST);
        if (env) {
            caplist = g_strdup(env);
        } else {
            /* either full path or files aren't indexed */
        }
    }

    if (caplist) {
        /* read list of capture files */
        fp = fopen(caplist, "r");
        if (fp == NULL) {
            fprintf(stderr, "Can't open caplist file %s\n", caplist);
            exit(-1);
        }
        pcap_array = (char **)calloc(MAX_LINE, sizeof(char *));
        while (fgets(line, MAX_LINE, fp)) {
            pcap_array[pcap_files_num] = (char *)calloc(1, MAX_LINE);
            strncpy(pcap_array[pcap_files_num], line, (strlen(line) - 1));
            pcap_files_num++;
        }
        fclose(fp);
        fp = NULL;
    } else if (pcap_glob) {
        glob_t gbuf;
        int    grc;

        grc = glob(pcap_glob, 0, NULL, &gbuf);
        if (grc == GLOB_NOMATCH) {
            fprintf(stderr, "No match for %s. No such file(s).\n", pcap_glob);
            exit(-1);
        }
        pcap_array = (char **)calloc(MAX_LINE, sizeof(char *));
        for (i = 0; i < gbuf.gl_pathc; i++) {
            pcap_array[i] = g_strdup(gbuf.gl_pathv[i]);
            pcap_files_num++;
        }
        globfree(&gbuf);
        g_free(pcap_glob);
        pcap_glob = NULL;
    }
}


static FILE *
yfMetaMakeTemp(
    char    *tmpname,
    size_t   tmpsize)
{
    int         fd;
    FILE       *temp;
    const char *env = getenv("TMPDIR");

    if (env) {
        snprintf(tmpname, tmpsize,
                 "%s/yaf_m2p_temp%s", env, temp_suffix);
    } else {
        snprintf(tmpname, tmpsize,
                 "/tmp/yaf_m2p_temp%s", temp_suffix);
    }

    fd = mkstemp(tmpname);

    if (fd == -1) {
        fprintf(stderr, "Unable to create and open temp file '%s': %s",
                tmpname, strerror(errno));
        out_file = NULL;
        return NULL;
    } else {
        temp = fdopen(fd, "w+");
        return temp;
    }
}


static pcap_t *
yfMetaOpenPcapIn(
    char    *filename,
    pcap_t  *pcap)
{
    static char pcap_errbuf[PCAP_ERRBUF_SIZE];

    if (pcap) {
        pcap_close(pcap);
    }

    if (verbose) {
        fprintf(stdout, "Opening PCAP File: %s\n", filename);
    }

    pcap = pcap_open_offline(filename, pcap_errbuf);

    if (!pcap) {
        fprintf(stderr, "Could not open PCAP file %s: %s\n", filename,
                pcap_errbuf);
        return NULL;
    }

    return pcap;
}


static pcap_dumper_t *
yfMetaOpenPcapOut(
    char    *filename,
    pcap_t  *pcap)
{
    pcap_dumper_t *dump = NULL;

    if (verbose) {
        fprintf(stdout, "Opening output PCAP file %s\n", filename);
    }

    dump = pcap_dump_open(pcap, filename);

    if (dump == NULL) {
        fprintf(stderr,
                "Could not open output PCAP file: %s\n", pcap_geterr(pcap));
        return NULL;
    }

    return dump;
}


static void
yfCreatePcap(
    FILE      *capfile,
    char      *filename,
    uint32_t   hash,
    uint64_t   time)
{
    char param[MAX_LINE];

    if (yaf_prog_path) {
        snprintf(param, MAX_LINE, "%s --in %s --no-output --caplist"
                 " --noerror --max-payload=4000 --pcap=%s --hash=%u "
                 "--stime=%" PRIu64, yaf_prog_path, filename, out_file,
                 hash, time);
    } else {
        snprintf(param, MAX_LINE, "yaf --in %s --no-output --caplist"
                 " --noerror --max-payload=4000 --pcap=%s --hash=%u"
                 " --stime=%" PRIu64, filename, out_file, hash, time);
    }

    fseek(capfile, 0, SEEK_SET);
    system(param);
}
/* Take user's -time or -etime input and calculate approppiate
 * milliseconds. Milliseconds will be returned.
 */
static uint64_t
Timestamp(
    const char  *arg1,
    const char  *arg2)
{
    struct        tm tm;
    time_t           epoch_ms;
    char            *isDigit = NULL;
    uint64_t         total_ms;
    double           ms = 0;
    const char      *formats[] = {"%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S",
                                  NULL};
    char            *result;
    /* Check user input against the valid time stamp format
     * Parse millisecond field and verify that only numbers
     * are used. */
    if (strchr(arg2, ':') == NULL) {
        total_ms = strtoull(arg2, &isDigit, 10);
        if (*isDigit != '\0') {
            goto ERROR;
        }
        return total_ms;
    }
    for (uint32_t i = 0; formats[i] != NULL; i++) {
        result = strptime(arg2, formats[i], &tm);
        if (result != NULL) {
            if (*result == '.') {
                ms = strtod(strchr(arg2, '.'), &isDigit);
                if (*isDigit != '\0') {
                    goto ERROR;
                }
                goto TIME;
            } else if (*result != '\0') {
                goto ERROR;
            }
            goto TIME;
        }
    }
    if (result == NULL) {
        goto ERROR;
    }
  TIME:
    epoch_ms = air_time_gm(tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                           tm.tm_hour, tm.tm_min, tm.tm_sec);
    total_ms = (epoch_ms + ms) * 1000;
    return total_ms;
  ERROR:
    fprintf(stderr,
            "Options parsing failed: Cannot parse integer value “%s” for --%s\n",
            arg2,arg1);
    exit(-1);
    return 0;
}

/**
 * main
 *
 */
int
main(
    int    argc,
    char  *argv[])
{
    GOptionContext *ctx = NULL;
    GError         *err = NULL;
    uint64_t        start, end;
    uint32_t        key_hash = 0;
    uint32_t        rev_key_hash = 0;
    uint64_t        windowstarts[MAX_WINDOW];
    int             numstarts = 0;
    FILE           *fp = NULL;
    FILE           *temp = NULL;
    char           *last_file = NULL;
    char            tmpname[MAX_PATH];
    char            line[MAX_LINE];
    char            old_file_path[MAX_LINE];
    unsigned long long int offset;
    unsigned long long int rstart;
    uint32_t        rhash;
    gboolean        do_once = TRUE;
    gboolean        list = FALSE;
    gboolean        new_file;
    gboolean        key_hash_matched = FALSE;
    gboolean        rev_key_hash_matched = FALSE;
    int             pfile, i, n, rv;
    int             counter = 0;
    int             file = 0;
    pcap_t         *pcap_in = NULL;
    pcap_dumper_t  *dump = NULL;
    gchar         **tok = NULL;

    ctx = g_option_context_new(" - yafMeta2Pcap Options");

    g_option_context_add_main_entries(ctx, md_core_option, NULL);

    g_option_context_set_help_enabled(ctx, TRUE);

    if (!g_option_context_parse(ctx, &argc, &argv, &err)) {
        fprintf(stderr, "option parsing failed: %s\n", err->message);
        exit(-1);
    }

    yfMetaParseOptions();

    if (timewindow) {
        for (i = 0; i < MAX_WINDOW; i++) {
            windowstarts[i] = 0;
        }
    }

    memset(tmpname, 0, MAX_PATH);

    if (flowkeyhash == 0) {
        ipfix = TRUE;
    }

    /* Analyze -time flag input*/
    if (flowstarttime) {
        start = Timestamp("time", flowstarttime);
    } else {
        start = 0;
    }
    /* Analyze etime input */
    if (flowendtime) {
        end = Timestamp("etime", flowendtime);
    } else {
        end = 0;
    }
    /* Set the hash value */
    if (!ipfix) {
        key_hash = (uint32_t)flowkeyhash;
    }

    if (ipfix) {
        simpleFlow_t rec;

        if (!collectIPFIX(&rec, &err)) {
            fprintf(stderr, "Error Processing IPFIX %s\n", err->message);
            exit(-1);
        }

        key_hash = rec.hash;

        if (!start) {
            start = rec.sms;
        }

        if (!end) {
            end = rec.ems;
        }

        if (num_packets < 0) {
            num_packets = rec.pkt;
        }

        if (rec.rhash) {
            rev_key_hash = rec.rhash;
        }
    }

    if (verbose) {
        fprintf(stdout, "Looking for hash: %u at start time: %llu\n",
                key_hash, (long long unsigned int)start);
    }

    if (key_hash == 0) {
        fprintf(stderr, "Invalid key hash: 0\n");
        exit(-1);
    }

    pfile = -1;

    for (i = 0; i < meta_files_num; i++) {
        if (fp) {
            fclose(fp);
        }

        if (verbose) {
            fprintf(stdout, "Opening PCAP Meta File: %s\n", meta_array[i]);
        }

        fp = fopen(meta_array[i], "r");
        if (fp == NULL) {
            fprintf(stderr, "Can't open PCAP Meta file %s\n", meta_array[i]);
            goto end;
        }

        new_file = TRUE;

        while (fgets(line, MAX_LINE, fp)) {
            if (tok) {
                g_strfreev(tok);
            }

            tok = g_strsplit(line, "|", -1);
            n = 0;
            while (tok[n] && *tok[n]) {
                ++n;
            }

            if (new_file) {
                if (n == 2) {
                    rstart = strtoul(tok[0], NULL, 10);
                    offset = strtoull(tok[1], NULL, 10);
                    yfUseIndex(fp, rstart, offset, start, end);
                    continue;
                } else if (n == 3) {
                    if (out_file && !temp) {
                        temp = yfMetaMakeTemp(tmpname, MAX_PATH);
                    }
                    list = TRUE;
                }

                new_file = FALSE;
            }

            if (n == 2) {
                /* Index line */
                continue;
            }

            rhash = strtoul(tok[0], NULL, 10);
            rstart = strtoull(tok[1], NULL, 10);

            if (rhash != key_hash) {
                if (rhash != rev_key_hash) {
                    continue;
                } else {
                    rev_key_hash_matched = TRUE;
                }
            } else {
                key_hash_matched = TRUE;
            }

            if (start) {
                if (timewindow) {
                    /* if we are looking for the reverse flow, the start time
                     * of the forward flow occurred before the reverse flow */
                    if (start < rstart) {continue;}
                    if (rstart < (start - timewindow)) {continue;}
                    if (start != rstart) {
                        if (numstarts < MAX_WINDOW) {
                            windowstarts[numstarts] = rstart;
                            numstarts++;
                        }
                    }
                } else if (start != rstart) {continue;}
            }
            if (list) {
                if (last_file) {
                    if (strcmp(last_file, tok[2]) == 0) {
                        /* file already in list */
                        continue;
                    }
                    g_free(last_file);
                }
                last_file = g_strdup(tok[2]);
                if (temp) {
                    fprintf(temp, "%s", tok[2]);
                } else {
                    fprintf(stdout, "%s", tok[2]);
                }
                counter++;
                continue;
            }

            if (n != 5) {
                if (!pcap_array) {
                    fprintf(stderr, "Invalid PCAP meta file. \n Expecting:"
                            " hash|stime|path_to_pcap|offset|length");
                    goto end;
                } else {
                    fprintf(stderr, "Error: Invalid Pcap Meta File "
                            "Format.\n");
                    fprintf(stderr, "Expecting: hash|stime|file_number"
                            "|offset|length\n");
                    goto end;
                }
            }

            offset = strtoull(tok[3], NULL, 10);
            if (offset == 0) {
                if (!pcap_array) {
                    fprintf(stderr, "Invalid PCAP meta file.\n Expecting: "
                            "hash|stime|path_to_pcap|offset|length");
                    goto end;
                } else {
                    fprintf(stderr, "Error: Invalid Pcap Meta File "
                            "Format.\n");
                    fprintf(stderr, "Expecting: hash|stime|file_number|"
                            "offset|length\n");
                    goto end;
                }
            }

            if (pcap_array) {
                file = strtoull(tok[2], NULL, 10);

                if (file != pfile && (file < pcap_files_num)) {
                    pcap_in = yfMetaOpenPcapIn(pcap_array[file], pcap_in);
                    if (!pcap_in) {
                        goto end;
                    }
                    pfile = file;
                }
            } else {
                if (strcmp(tok[2], old_file_path)) {
                    strcpy(old_file_path, tok[2]);
                    pcap_in = yfMetaOpenPcapIn(tok[2], pcap_in);
                    if (!pcap_in) {
                        goto end;
                    }
                }
            }

            if (do_once) {
                if (out_file) {
                    dump = yfMetaOpenPcapOut(out_file, pcap_in);
                    if (!dump) {goto end;}
                    do_once = FALSE;
                }
            }

            counter++;

            if (dump) {
                fseek(pcap_file(pcap_in), offset, SEEK_SET);

                rv = pcap_dispatch(pcap_in, 1, (pcap_handler)yfPcapWrite,
                                   (void *)dump);
                if (rv <= 0) {
                    fprintf(stderr, "RV %d Error writing packet: %s\n",
                            rv, pcap_geterr(pcap_in));
                    break;
                }
            } else {
                if (pcap_array) {
                    if (strcmp(tmpname, pcap_array[file])) {
                        fprintf(stdout, "%s\n", pcap_array[file]);
                        strcpy(tmpname, pcap_array[file]);
                    }
                } else {
                    if (strcmp(tmpname, tok[2])) {
                        fprintf(stdout, "%s\n", tok[2]);
                        strcpy(tmpname, tok[2]);
                    }
                }
            }

            if (num_packets && counter == num_packets) {
                break;
            }
        }

        if (num_packets && counter == num_packets) {
            break;
        }
    }

    if (list) {
        if (temp && counter) {
            if (key_hash_matched) {
                if (numstarts) {
                    i = 0;
                    while (i < numstarts) {
                        yfCreatePcap(temp, tmpname, key_hash, windowstarts[i]);
                        i++;
                    }
                } else {
                    yfCreatePcap(temp, tmpname, key_hash, start);
                }
            }
            if (access(out_file, F_OK)) {
                if (rev_key_hash && rev_key_hash_matched) {
                    if (numstarts) {
                        i = 0;
                        while (i < numstarts) {
                            yfCreatePcap(temp, tmpname, rev_key_hash,
                                         windowstarts[i]);
                            i++;
                        }
                    } else {
                        yfCreatePcap(temp, tmpname, rev_key_hash, start);
                    }
                }
            }
            /*
             * if (yaf_prog_path) {
             *  snprintf(param, MAX_LINE, "%s --in %s --no-output --caplist"
             *           " --noerror --max-payload=4000 --pcap=%s --hash=%u "
             *           "--stime=%"PRIu64, yaf_prog_path, tmpname, out_file,
             *           key_hash, start);
             * } else {
             *  snprintf(param, MAX_LINE, "yaf --in %s --no-output --caplist"
             *           " --noerror --max-payload=4000 --pcap=%s --hash=%u"
             *           " --stime=%"PRIu64, tmpname, out_file, key_hash,
             * start);
             *
             * }
             *
             * fseek(temp, 0, SEEK_SET);
             * system(param);
             *
             * if (access(out_file, F_OK)) {
             *  if (rev_key_hash) {
             *      if (yaf_prog_path) {
             *          snprintf(param, MAX_LINE, "%s --in %s --no-output "
             *                   "--caplist --noerror --max-payload=4000 "
             *                   "--pcap=%s --hash=%u --stime=%"PRIu64,
             *                   yaf_prog_path, tmpname, out_file,
             *                   rev_key_hash, start);
             *      } else {
             *          snprintf(param, MAX_LINE, "yaf --in %s --no-output "
             *                   "--caplist --noerror --max-payload=4000 "
             *                   "--pcap=%s --hash=%u --stime=%"PRIu64,
             *                   tmpname, out_file, rev_key_hash, start);
             *      }
             *
             *      fseek(temp, 0, SEEK_SET);
             *      system(param);
             *  }
             * }
             */
        }
    }

  end:
    if (tok) {
        g_strfreev(tok);
    }

    if (!list) {
        fprintf(stdout, "Found %d packets that match criteria.\n", counter);

        if (fp) {
            fclose(fp);
        }

        if (dump) {
            pcap_dump_flush(dump);
            pcap_dump_close(dump);
        }

        if (pcap_in) {
            pcap_close(pcap_in);
        }
    } else {
        /* close temporary file and remove it */
        fprintf(stdout, "Found %d files that match criteria.\n", counter);

        if (temp) {
            unlink(tmpname);
        }
    }

    if (last_file) {
        g_free(last_file);
    }

    if (pcap_files_num) {
        for (i = 0; i < pcap_files_num; i++) {
            free(pcap_array[i]);
        }
    }

    if (meta_files_num) {
        for (i = 0; i < meta_files_num; i++) {
            free(meta_array[i]);
        }
    }

    g_option_context_free(ctx);

    return 0;
}
