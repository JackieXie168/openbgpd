/*	$OpenBSD: timer.c,v 1.13 2009/01/21 20:32:53 henning Exp $ */

/*
 * Copyright (c) 2003-2007 Henning Brauer <henning@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <stdlib.h>

#include "bgpd.h"
#include "session.h"
#if defined(darwin) || defined(__APPLE__) || defined(MACOSX)
#include <mach/mach.h>
#include <mach/clock.h>
#include <mach/mach_time.h>

/* The opengroup spec isn't clear on the mapping from REALTIME to CALENDAR
 being appropriate or not.
 http://pubs.opengroup.org/onlinepubs/009695299/basedefs/time.h.html */

// XXX only supports a single timer
#define TIMER_ABSTIME -1
#ifndef CLOCK_REALTIME
#define CLOCK_REALTIME CALENDAR_CLOCK
#endif
#define CLOCK_MONOTONIC SYSTEM_CLOCK

typedef int clockid_t;

/* the mach kernel uses struct mach_timespec, so struct timespec
    is loaded from <sys/_types/_timespec.h> for compatability */
// struct timespec { time_t tv_sec; long tv_nsec; };
#define MT_NANO (+1.0E-9)
#define MT_GIGA UINT64_C(1000000000)

// TODO create a list of timers,
static double mt_timebase = 0.0;
static uint64_t mt_timestart = 0;

// TODO be more careful in a multithreaded environement
int clock_gettime(clockid_t clk_id, struct timespec *tp)
{
    kern_return_t retval = KERN_SUCCESS;
    if( clk_id == TIMER_ABSTIME)
    {
        if (!mt_timestart) { // only one timer, initilized on the first call to the TIMER
            mach_timebase_info_data_t tb = { 0 };
            mach_timebase_info(&tb);
            mt_timebase = tb.numer;
            mt_timebase /= tb.denom;
            mt_timestart = mach_absolute_time();
        }

        double diff = (mach_absolute_time() - mt_timestart) * mt_timebase;
        tp->tv_sec = diff * MT_NANO;
        tp->tv_nsec = diff - (tp->tv_sec * MT_GIGA);
    }
    else // other clk_ids are mapped to the coresponding mach clock_service
    {
        clock_serv_t cclock;
        mach_timespec_t mts;

        host_get_clock_service(mach_host_self(), clk_id, &cclock);
        retval = clock_get_time(cclock, &mts);
        mach_port_deallocate(mach_task_self(), cclock);

        tp->tv_sec = mts.tv_sec;
        tp->tv_nsec = mts.tv_nsec;
    }

    return retval;
}
#endif

time_t	getmonotime(void);

time_t
getmonotime(void)
{
	struct timespec	ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		fatal("clock_gettime");

	return (ts.tv_sec);
}

struct peer_timer *
timer_get(struct peer *p, enum Timer timer)
{
	struct peer_timer *pt;

	TAILQ_FOREACH(pt, &p->timers, entry)
		if (pt->type == timer)
				break;

	return (pt);
}

struct peer_timer *
timer_nextisdue(struct peer *p)
{
	struct peer_timer *pt;

	pt = TAILQ_FIRST(&p->timers);
	if (pt != NULL && pt->val > 0 && pt->val <= getmonotime())
		return (pt);
	return (NULL);
}

time_t
timer_nextduein(struct peer *p)
{
	struct peer_timer *pt;

	if ((pt = TAILQ_FIRST(&p->timers)) != NULL && pt->val > 0)
		return (MAX(pt->val - getmonotime(), 0));
	return (-1);
}

int
timer_running(struct peer *p, enum Timer timer, time_t *left)
{
	struct peer_timer	*pt = timer_get(p, timer);

	if (pt != NULL && pt->val > 0) {
		if (left != NULL)
			*left = pt->val - getmonotime();
		return (1);
	}
	return (0);
}

void
timer_set(struct peer *p, enum Timer timer, u_int offset)
{
	struct peer_timer	*t, *pt = timer_get(p, timer);

	if (pt == NULL) {	/* have to create */
		if ((pt = malloc(sizeof(*pt))) == NULL)
			fatal("timer_set");
		pt->type = timer;
	} else {
		if (pt->val == getmonotime() + (time_t)offset)
			return;
		TAILQ_REMOVE(&p->timers, pt, entry);
	}

	pt->val = getmonotime() + offset;

	TAILQ_FOREACH(t, &p->timers, entry)
		if (t->val == 0 || t->val > pt->val)
			break;
	if (t != NULL)
		TAILQ_INSERT_BEFORE(t, pt, entry);
	else
		TAILQ_INSERT_TAIL(&p->timers, pt, entry);
}

void
timer_stop(struct peer *p, enum Timer timer)
{
	struct peer_timer	*pt = timer_get(p, timer);

	if (pt != NULL) {
		pt->val = 0;
		TAILQ_REMOVE(&p->timers, pt, entry);
		TAILQ_INSERT_TAIL(&p->timers, pt, entry);
	}
}

void
timer_remove(struct peer *p, enum Timer timer)
{
	struct peer_timer	*pt = timer_get(p, timer);

	if (pt != NULL) {
		TAILQ_REMOVE(&p->timers, pt, entry);
		free(pt);
	}
}

void
timer_remove_all(struct peer *p)
{
	struct peer_timer	*pt;

	while ((pt = TAILQ_FIRST(&p->timers)) != NULL) {
		TAILQ_REMOVE(&p->timers, pt, entry);
		free(pt);
	}
}
