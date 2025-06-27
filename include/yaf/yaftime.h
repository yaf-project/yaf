/*
 *  Copyright 2024 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  yaftime.h
 *
 *  Types, functions, and macros for holding and manipluating timestamps and
 *  time-differences.
 *
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
#ifndef _YAF_TIME_H_
#define _YAF_TIME_H_


/**
 *    YAF timestamp: represents a moment in time
 */
typedef struct yfTime_st {
    /* Epoch nanoseconds.  Valid until 2554-07-21 */
    uint64_t  t;
} yfTime_t;

/**
 *    YAF time difference: represents the difference of two yfTime_t
 */
typedef struct yfDiffTime_st {
    /* Nanosecond difference */
    int64_t   d;
} yfDiffTime_t;

/**
 *    Some high-performance network cards use a custom 64-bit structure
 *    similar to the standard timeval or timespec but which stores seconds in
 *    a 32-bit unsigned integer.  Used by yfTimeFromTimespec32() and
 *    yfTimeFromTimeval32().
 */
typedef struct yf_timespec32_st {
    uint32_t  tv_sec;
    uint32_t  tv_frac;
} yf_timespec32_t;

/**
 *    A structure similar to timeval and timespec but which stores seconds and
 *    milliseconds.
 */
typedef struct yf_time_milli_st {
    long long  tv_sec;
    long       tv_msec;
} yf_time_milli_t;

/**
 *    Mask to apply to NTP timestamps that contain microsecond precision.
 *
 *    Since dateTimeMicroseconds is intended to represent a value having only
 *    microsecond precision, the bottom 11 bits of the fraction field are
 *    expected to be zero.  (See Section 6.1.9 of RFC7011.)
 *
 *    The caller should apply this mask to the value returned by yfTimeToNTP()
 *    when setting microseconds.
 */
#define YF_TIME_NTP_USEC_MASK  UINT64_C(0xfffffffffffff800)

/**
 *    Initializes a yfTime_t on the stack.
 */
#define YF_TIME_INIT      { 0 }

/**
 *    Initializes a yfDiffTime_t on the stack.
 */
#define YF_DIFFTIME_INIT  { 0 }

/**
 *    Initializes a yfDiffTime_t on the stack to the specified milliseconds
 *    value.
 */
#define YF_DIFFTIME_INIT_MILLI(ms_)  { INT64_C(1000000) * (ms_) }

/**
 *    An empty yfTime_t constant.
 */
static const yfTime_t yfTimeZeroConstant = YF_TIME_INIT;

/**
 *    An empty yfDiffTime_t constant.
 */
static const yfDiffTime_t yfDiffTimeZeroConstant = YF_DIFFTIME_INIT;



/*
 *    Note: If we are going to continue to use functions below (instead of
 *    changing them to macros), it would make sense for the return type to be
 *    the yfTime_t* that was passed in.  Doing this would allow these function
 *    calls to appear in other function calls.
 */



/*
 *    *********************************************************************
 *
 *    Functions and Macros for yfTime_t
 *
 *    *********************************************************************
 */

/**
 *    Sets the referent of `yftime` to zero.
 */
static inline void
yfTimeClear(
    yfTime_t  *yftime)
{
    yftime->t = 0;
}

/**
 *    Returns TRUE if the value in `yftime` is not zero.  Returns FALSE if the
 *    value is zero.
 */
static inline gboolean
yfTimeIsSet(
    const yfTime_t  yftime)
{
    return (0 != yftime.t);
}

/**
 *    Adds a yfDiffTime_t to a yfTime_t.  Specifically, sets the referent of
 *    `yftime_new` to the sum of `yftime_old` and `yfdifftime`.
 *
 *    `yftime_old` and `yftime_new` may reference the same yfTime_t.
 */
static inline void
yfTimeAdd(
    yfTime_t            *yftime_new,
    const yfTime_t       yftime_old,
    const yfDiffTime_t   yfdifftime)
{
    yftime_new->t = yftime_old.t + yfdifftime.d;
}

/**
 *    Subtracts a yfDiffTime_t from a yfTime_t.  Specifically, sets the
 *    referent of `yftime_new` to `yftime_old` minus `yfdifftime`.
 *
 *    @see Use yfTimeDifference() to compute the difference of two yfTime_t.
 */
static inline void
yfTimeSub(
    yfTime_t            *yftime_new,
    const yfTime_t       yftime_old,
    const yfDiffTime_t   yfdifftime)
{
    yftime_new->t = yftime_old.t - yfdifftime.d;
}

/**
 *    Compares two yfTime_t's using an arbitrary operator.  Specifically,
 *    tests whether (`yftime_a` `oper_` `yftime_b`) is TRUE where `oper_` is
 *    one of
 *
 *    <  <=  ==  >=  >  !=
 *
 *    @see Use yfTimeCompare() for a qsort-compatible comparison function.
 */
#define yfTimeCmpOp(yftime_a, yftime_b, oper_)  \
    ((yftime_a).t oper_ (yftime_b).t)

/**
 *    Compares two yfTime_t's.  Returns a value less than, equal to, or
 *    greater than zero if `yftime_a` is less than, equal to, or greater than
 *    `yftime_b`, respectively.
 *
 *    @see Use yfTimeCmpOp() to compare two yfTime_t's using an arbitrary
 *    operator
 */
static inline int
yfTimeCompare(
    const yfTime_t  yftime_a,
    const yfTime_t  yftime_b)
{
    return ((yftime_a.t < yftime_b.t) ? -1 : (yftime_a.t > yftime_b.t));
}

/**
 *    Computes the difference of two yfTime_t's.  Specifically, sets the
 *    referent of `yfdiff` to `yftime_end` minus `yftime_start`.
 *
 *    @see Use yfTimeSub() to subtact a yfDiffTime_t from a yfTime_t.
 */
static inline void
yfTimeDifference(
    yfDiffTime_t     *yfdiff,
    const yfTime_t    yftime_end,
    const yfTime_t    yftime_start)
{
    yfdiff->d = yftime_end.t - yftime_start.t;
}

/**
 *    Sets the referent of `yftime` from `epoch_usec`, which holds the number
 *    of microseconds since the unix epoch.
 */
static inline void
yfTimeFromMicro(
    yfTime_t       *yftime,
    const uint64_t  epoch_usec)
{
    yftime->t = UINT64_C(1000) * epoch_usec;
}

/**
 *    Sets the referent of `yftime` from `epoch_msec`, which holds the number
 *    of milliseconds since the unix epoch.
 */
static inline void
yfTimeFromMilli(
    yfTime_t       *yftime,
    const uint64_t  epoch_msec)
{
    yftime->t = UINT64_C(1000000) * epoch_msec;
}

/**
 *    Sets the referent of `yftime` from `epoch_nsec`, which holds the number
 *    of nanoseconds since the unix epoch.  Rolls over in 2554.
 */
static inline void
yfTimeFromNano(
    yfTime_t       *yftime,
    const uint64_t  epoch_nsec)
{
    yftime->t = epoch_nsec;
}

/**
 *    Sets the referent of `yftime` from `ntp`, a value holding a timestamp in
 *    the NTP represenation, where `is_micro` should be TRUE for
 *    dateTimeMicroseconds values and FALSE for dateTimeNanoseconds values.
 */
static inline void
yfTimeFromNTP(
    yfTime_t       *yftime,
    const uint64_t  ntp,
    gboolean        is_micro)
{
    /* The number of seconds between the NTP epoch (Jan 1, 1900) and the UNIX
     * epoch (Jan 1, 1970).  Seventy 365-day years plus 17 leap days, at 86400
     * sec/day: ((70 * 365 + 17) * 86400) */
    const uint64_t NTP_EPOCH_TO_UNIX_EPOCH = UINT64_C(0x83AA7E80);

    /* use all lower 32 bits for the Nanosecond mask */
    const uint64_t NANO_MASK      = UINT64_C(0xffffffff);
    /* nanoseconds per whole second, 1e9 */
    const uint64_t NANO_PER_SEC   = UINT64_C(1000000000);

    /* IETF says the Microsecond mask must ignore the lowest 11 bits */
    const uint64_t MICRO_MASK     = UINT64_C(0xfffff800);
    /* microseconds per whole second, 1e6 */
    const uint64_t MICRO_PER_SEC  = UINT64_C(1000000);

    /* When the NTP value rolls over in 2036, must add 2^32 seconds to the
     * UNIX time */
    const uint64_t NTP_ROLLOVER = UINT64_C(0x100000000);

    /* To get a proper value when converting to fractional seconds, add 1<<31
     * before the >>32 to round up values.  Not doing so introduces errors
     * that can accumulate with repeated conversions. */
    const uint64_t ROUNDING_DIFF = UINT64_C(0x80000000);

    /* Handle fractional seconds */
    if (!is_micro) {
        /* Mask the lower 32 bits of `ntp` to get the fractional second part.
         * Divide by 2^32 to get a floating point number that is a fraction of
         * a second, and multiply by NANO_PER_SEC to get nanoeconds, but do
         * those in reverse order, use shift for the division, and handle
         * rounding before the division */
        yftime->t = ((ntp & NANO_MASK) * NANO_PER_SEC + ROUNDING_DIFF) >> 32;
    } else {
        /* Do something similar as for nanoseconds but using microseconds,
         * then multiply by 1000 at the end to get nanoseconds as a whole
         * number of microseconds */
        yftime->t = ((((ntp & MICRO_MASK) * MICRO_PER_SEC + ROUNDING_DIFF)
                      >> 32) * 1000);
    }

    /* Seconds: Right shift `ntp` by 32 to get the whole seconds since 1900.
     * Subtract the difference between the epochs to get a UNIX time, then
     * multiply by NANO_PER_SEC to get nanoseconds.
     *
     * Use the highest bit of ntp to determine (assume) the NTP Era and add
     * NTP_ROLLOVER if Era 1; this is valid from 1968 to 2104. */
    if (ntp >> 63) {
        /* Assume NTP Era 0 */
        /* valid for 1968-01-20 03:14:08Z to 2036-02-07 06:28:15Z */
        yftime->t += ((ntp >> 32) - NTP_EPOCH_TO_UNIX_EPOCH) * NANO_PER_SEC;
    } else {
        /* Assume NTP Era 1 */
        /* valid for 2036-02-07 06:28:16Z to 2104-02-26 09:42:23Z */
        yftime->t += (((ntp >> 32) + NTP_ROLLOVER - NTP_EPOCH_TO_UNIX_EPOCH)
                      * NANO_PER_SEC);
    }
}

/**
 *    Sets the referent of `yftime` from `epoch_sec`, which holds the number
 *    of seconds since the unix epoch.
 */
static inline void
yfTimeFromSeconds(
    yfTime_t       *yftime,
    const uint64_t  epoch_sec)
{
    yftime->t = UINT64_C(1000000000) * epoch_sec;
}

/**
 *    Sets the referent of `yftime` from `tspec`, a pointer to a struct
 *    holding seconds and nanoseconds.
 */
static inline void
yfTimeFromTimespec(
    yfTime_t              *yftime,
    const struct timespec *tspec)
{
    yftime->t = UINT64_C(1000000000) * tspec->tv_sec + tspec->tv_nsec;
}

/**
 *    Sets the referent of `yftime` from `yfspec32`, a pointer to a struct
 *    holding seconds and nanoseconds but using only 32-bits for the seconds.
 */
static inline void
yfTimeFromTimespec32(
    yfTime_t              *yftime,
    const yf_timespec32_t *yfspec32)
{
    yftime->t = UINT64_C(1000000000) * yfspec32->tv_sec + yfspec32->tv_frac;
}

/**
 *    Sets the referent of `yftime` from `tval`, a pointer to a struct holding
 *    seconds and microseconds.
 */
static inline void
yfTimeFromTimeval(
    yfTime_t             *yftime,
    const struct timeval *tval)
{
    yftime->t = (UINT64_C(1000000000) * tval->tv_sec
                 + UINT64_C(1000) * tval->tv_usec);
}

/**
 *    Sets the referent of `yftime` from `yfval32`, a pointer to a struct
 *    holding seconds and microseconds but using only 32-bits for the seconds.
 */
static inline void
yfTimeFromTimeval32(
    yfTime_t              *yftime,
    const yf_timespec32_t *yfval32)
{
    yftime->t = (UINT64_C(1000000000) * yfval32->tv_sec
                 + UINT64_C(1000) * yfval32->tv_frac);
}

/**
 *    Returns TRUE if `later_time` is strictly greater than `earlier_time`
 *    plus `elapsed`.  Returns FALSE otherwise.
 */
static inline gboolean
yfTimeCheckElapsed(
    const yfTime_t      later_time,
    const yfTime_t      earlier_time,
    const yfDiffTime_t  elapsed)
{
    return (later_time.t > earlier_time.t + elapsed.d);
}

/**
 *    Sets the referent of `yftime` to the current time.
 */
static inline void
yfTimeNow(
    yfTime_t  *yftime)
{
    struct timeval ct;

    gettimeofday(&ct, NULL);
    yfTimeFromTimeval(yftime, &ct);
}


/**
 *    Returns the number of microseconds since the unix epoch represented by
 *    `yftime`.  Truncates any fractional seconds less than 1usec.
 */
static inline uint64_t
yfTimeToMicro(
    const yfTime_t  yftime)
{
    const uint64_t divisor = UINT64_C(1000);

    return yftime.t / divisor;
}

/**
 *    Returns the number of milliseconds since the unix epoch represented by
 *    `yftime`.  Truncates any fractional seconds less than 1msec.
 */
static inline uint64_t
yfTimeToMilli(
    const yfTime_t  yftime)
{
    const uint64_t divisor = UINT64_C(1000000);

    return yftime.t / divisor;
}

/**
 *    Returns the number of nanoseconds since the unix epoch represented by
 *    `yftime`.  Truncates any fractional seconds less than 1nsec.
 */
static inline uint64_t
yfTimeToNano(
    const yfTime_t  yftime)
{
    return yftime.t;
}

/**
 *    Sets the referent of `ntp`, a value holding a timestamp in the NTP
 *    represenation, from `yftime`.
 *
 *    If `ntp` is to represent a dateTimeMicroseconds value, the caller should
 *    apply the YF_TIME_NTP_USEC_MASK to the result.
 */
static inline void
yfTimeToNTP(
    uint64_t       *ntp,
    const yfTime_t  yftime)
{
    /* The number of seconds between the NTP epoch (Jan 1, 1900) and the UNIX
     * epoch (Jan 1, 1970).  Seventy 365-day years plus 17 leap days, at 86400
     * sec/day: ((70 * 365 + 17) * 86400) */
    const uint64_t NTP_EPOCH_TO_UNIX_EPOCH = UINT64_C(0x83AA7E80);
    /* Seconds and fractional-seconds divisor */
    const long long divisor = 1000000000LL;
    /* seconds */
    lldiv_t split = lldiv(yftime.t, divisor);
    uint64_t sec;
    uint64_t frac;

    /* Adjust seconds for the difference in epochs.  When NTP rolls over in
     * 2036, sec will be > UINT32_MAX, but those are chopped off when the <<32
     * is applied. */
    sec = (uint64_t)split.quot + NTP_EPOCH_TO_UNIX_EPOCH;

    /* Divide number of nanoseconds by 1e9 to get a fractional second, then
     * multiply by 2^32.  Do those in the reverse order and use shift for the
     * multiplication.  */
    frac = (((uint64_t)split.rem) << UINT64_C(32)) / divisor;

    *ntp = ((sec << UINT64_C(32)) | frac);
}

/**
 *    Returns the number of seconds since the unix epoch represented by
 *    `yftime`.  Truncates the fractional seconds.
 */
static inline uint64_t
yfTimeToSeconds(
    const yfTime_t  yftime)
{
    const uint64_t divisor = UINT64_C(1000000000);

    return yftime.t / divisor;
}

/**
 *    Sets `tmilli`, a pointer to a struct holding seconds and milliseconds,
 *    from `yftime`.  Truncates any fractional seconds less than 1msec.
 */
static inline void
yfTimeToTimemilli(
    yf_time_milli_t    *tmilli,
    const yfTime_t      yftime)
{
    /* convert epoch nanosec to epoch millisec, then split into seconds and
     * fractional seconds */
    const long long nsec_per_msec = 1000000LL;
    const long long msec_per_sec = 1000LL;
    lldiv_t sec = lldiv((yftime.t / nsec_per_msec), msec_per_sec);

    tmilli->tv_sec = sec.quot;
    tmilli->tv_msec = sec.rem;
}

/**
 *    Sets `tspec`, a pointer to a struct holding seconds and nanoseconds,
 *    from `yftime`.  Truncates any fractional seconds less than 1nsec.
 */
static inline void
yfTimeToTimespec(
    struct timespec       *tspec,
    const yfTime_t         yftime)
{
    const long long divisor = 1000000000LL;
    lldiv_t sec = lldiv(yftime.t, divisor);

    tspec->tv_sec = sec.quot;
    tspec->tv_nsec = sec.rem;
}

/**
 *    Sets `yfspec32`, a pointer to a struct holding seconds (as a 32-bit
 *    number) and nanoseconds, from `yftime`.  Truncates any fractional
 *    seconds less than 1nsec.
 */
static inline void
yfTimeToTimespec32(
    yf_timespec32_t       *yfspec32,
    const yfTime_t         yftime)
{
    const long long divisor = 1000000000LL;
    lldiv_t sec = lldiv(yftime.t, divisor);

    yfspec32->tv_sec = sec.quot;
    yfspec32->tv_frac = sec.rem;
}

/**
 *    Sets `tval`, a pointer to a struct holding seconds and microseconds,
 *    from `yftime`.  Truncates any fractional seconds less than 1usec.
 */
static inline void
yfTimeToTimeval(
    struct timeval       *tval,
    const yfTime_t        yftime)
{
    /* convert epoch nanosec to epoch microsec, then split into seconds and
     * fractional seconds */
    const long long nsec_per_usec = 1000LL;
    const long long usec_per_sec = 1000000LL;
    lldiv_t sec = lldiv((yftime.t / nsec_per_usec), usec_per_sec);

    tval->tv_sec = sec.quot;
    tval->tv_usec = sec.rem;
}

/**
 *    Sets `yfval32`, a pointer to a struct holding seconds (as a 32-bit
 *    number) and microseconds, from `yftime`.  Truncates any fractional
 *    seconds less than 1usec.
 */
static inline void
yfTimeToTimeval32(
    yf_timespec32_t       *yfval32,
    const yfTime_t         yftime)
{
    /* convert epoch nanosec to epoch microsec, then split into seconds and
     * fractional seconds */
    const long long nsec_per_usec = 1000LL;
    const long long usec_per_sec = 1000000LL;
    lldiv_t sec = lldiv((yftime.t / nsec_per_usec), usec_per_sec);

    yfval32->tv_sec = sec.quot;
    yfval32->tv_frac = sec.rem;
}



/*
 *    *********************************************************************
 *
 *    Functions / Macros for yfDiffTime_t
 *
 *    *********************************************************************
 */

/**
 *    Sets the referent of `yfdifftime` to zero.
 */
static inline void
yfDiffTimeClear(
    yfDiffTime_t *yfdifftime)
{
    yfdifftime->d = 0;
}

/**
 *    Returns TRUE if `yfdifftime` is not zero.  Returns FALSE if it is zero.
 */
static inline gboolean
yfDiffTimeIsSet(
    const yfDiffTime_t  yfdifftime)
{
    return (0 != yfdifftime.d);
}

/**
 *    Adds `yfdiff_addend` to `yfdiff_old` and stores the result in the
 *    referent of `yfdiff_new`.
 *
 *    The same `yfDiffTime_t` may be appear in any of the parameters.
 *
 *    @see Use yfTimeAdd() to add a yfDiffTime_t to a yfTime_t.
 */
static inline void
yfDiffTimeAdd(
    yfDiffTime_t        *yfdiff_new,
    const yfDiffTime_t   yfdiff_old,
    const yfDiffTime_t   yfdiff_addend)
{
    yfdiff_new->d = yfdiff_old.d + yfdiff_addend.d;
}

/**
 *    Subtracts `yfdiff_subtrahend` from `yfdiff_old` and stores the result in
 *    the referent of `yfdiff_new`.
 *
 *    The same `yfDiffTime_t` may be appear in any of the parameters.
 *
 *    @see Use yfTimeSub() to subtract a yfDiffTime_t from a yfTime_t.  Use
 *    yfTimeComputeDiff() to set a yfDiffTime_t as the difference of two
 *    yfTime_t.
 */
static inline void
yfDiffTimeSub(
    yfDiffTime_t        *yfdiff_new,
    const yfDiffTime_t   yfdiff_old,
    const yfDiffTime_t   yfdiff_subtrahend)
{
    yfdiff_new->d = yfdiff_old.d - yfdiff_subtrahend.d;
}

/**
 *    Compares two yfDiffTime_t's using an arbitrary operator.  Specifically,
 *    tests whether (`yfdiff_a` `oper_` `yfdiff_b`) is TRUE where `oper_` is
 *    one of
 *
 *    <  <=  ==  >=  >  !=
 */
#define yfDiffTimeCmpOp(yfdiff_a, yfdiff_b, oper_)      \
    ((yfdiff_a).d oper_ (yfdiff_b).d)

/**
 *    Sets the referent of `yfdifftime` from `diff_usec`, which holds a time
 *    difference stored as microseconds.
 */
static inline void
yfDiffTimeFromMicro(
    yfDiffTime_t   *yfdifftime,
    const int64_t   diff_usec)
{
    yfdifftime->d = INT64_C(1000) * diff_usec;
}

/**
 *    Sets the referent of `yfdifftime` from `diff_msec`, which holds a time
 *    difference stored as milliseconds.
 */
static inline void
yfDiffTimeFromMilli(
    yfDiffTime_t   *yfdifftime,
    const int64_t   diff_msec)
{
    yfdifftime->d = INT64_C(1000000) * diff_msec;
}

/**
 *    Sets the referent of `yfdifftime` from `diff_msec`, which holds a time
 *    difference stored as seconds.
 */
static inline void
yfDiffTimeFromSeconds(
    yfDiffTime_t   *yfdifftime,
    const int64_t   diff_sec)
{
    yfdifftime->d = INT64_C(1000000000) * diff_sec;
}

/**
 *    Returns `yfdifftime` as a floating-point number of seconds.
 */
static inline double
yfDiffTimeToDouble(
    const yfDiffTime_t  yfdifftime)
{
    const double divisor = 1e9;

    return (double)yfdifftime.d / divisor;
}

/**
 *    Returns `yfdifftime` as a number of milliseconds.  Truncates any
 *    fractional seconds less than 1msec.
 */
static inline int64_t
yfDiffTimeToMilli(
    const yfDiffTime_t  yfdifftime)
{
    const int64_t divisor = INT64_C(1000000);

    return yfdifftime.d / divisor;
}

/**
 *    Returns `yfdifftime` as a number of microseconds.  Truncates any
 *    fractional seconds less than 1usec.
 */
static inline int64_t
yfDiffTimeToMicro(
    const yfDiffTime_t  yfdifftime)
{
    const int64_t divisor = INT64_C(1000);

    return yfdifftime.d / divisor;
}

/**
 *    Returns `yfdifftime` as a number of nanoseconds.  Truncates any
 *    fractional seconds less than 1nsec.
 */
static inline int64_t
yfDiffTimeToNano(
    const yfDiffTime_t  yfdifftime)
{
    return yfdifftime.d;
}

/**
 *    Sets `tmilli`, a pointer to a struct holding seconds and milliseconds,
 *    from `yfdifftime`.  Truncates any fractional seconds less than 1msec.
 */
static inline void
yfDiffTimeToTimemilli(
    yf_time_milli_t    *tmilli,
    const yfDiffTime_t  yfdifftime)
{
    /* convert the nanosec difference to a millisec difference, then split
     * into seconds and fractional seconds */
    const long long nsec_per_msec = 1000000LL;
    const long long msec_per_sec = 1000LL;
    lldiv_t sec;

    sec = lldiv((yfdifftime.d / nsec_per_msec), msec_per_sec);

    tmilli->tv_sec = sec.quot;
    tmilli->tv_msec = sec.rem;

}

/**
 *    Sets `tspec`, a pointer to a struct holding seconds and nanoseconds,
 *    from `yfdifftime`.  Truncates any fractional seconds less than 1nsec.
 */
static inline void
yfDiffTimeToTimespec(
    struct timespec    *tspec,
    const yfDiffTime_t  yfdifftime)
{
    const long long divisor = 1000000000LL;
    lldiv_t sec = lldiv(yfdifftime.d, divisor);

    tspec->tv_sec = sec.quot;
    tspec->tv_nsec = sec.rem;
}

/**
 *    Sets `tval`, a pointer to a struct holding seconds and microseconds,
 *    from `yfdifftime`.  Truncates any fractional seconds less than 1usec.
 */
static inline void
yfDiffTimeToTimeval(
    struct timeval     *tval,
    const yfDiffTime_t  yfdifftime)
{
    /* convert the nanosec difference to a microsec difference, then split
     * into seconds and fractional seconds */
    const long long nsec_per_usec = 1000LL;
    const long long usec_per_sec = 1000000LL;
    lldiv_t sec;

    sec = lldiv((yfdifftime.d / nsec_per_usec), usec_per_sec);

    tval->tv_sec = sec.quot;
    tval->tv_usec = sec.rem;
}

#endif  /* #ifndef _YAF_TIME_H_ */
