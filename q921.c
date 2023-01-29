/*
 * libpri: An implementation of Primary Rate ISDN
 *
 * Written by Mark Spencer <markster@digium.com>
 *
 * Copyright (C) 2001-2005, Digium, Inc.
 * All Rights Reserved.
 */

/*
 * See http://www.asterisk.org for more information about
 * the Asterisk project. Please do not directly contact
 * any of the maintainers of this project for assistance;
 * the project provides a web site, mailing lists and IRC
 * channels for your use.
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2 as published by the
 * Free Software Foundation. See the LICENSE file included with
 * this program for more details.
 *
 * In addition, when this program is distributed with Asterisk in
 * any form that would qualify as a 'combined work' or as a
 * 'derivative work' (but not mere aggregation), you can redistribute
 * and/or modify the combination under the terms of the license
 * provided with that copy of Asterisk, instead of the license
 * terms granted here.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include "compat.h"
#include "libpri.h"
#include "pri_internal.h"
#include "pri_q921.h" 
#include "pri_q931.h"

/*
 * Define RANDOM_DROPS To randomly drop packets in order to simulate loss for testing
 * retransmission functionality
 */
//#define RANDOM_DROPS	1

#define Q921_INIT(fr, l_sapi, l_tei) \
	do { \
		(fr)->h.sapi = l_sapi; \
		(fr)->h.ea1 = 0; \
		(fr)->h.ea2 = 1; \
		(fr)->h.tei = l_tei; \
	} while (0)

#define Q921_CLEAR_INIT(fr, l_sapi, l_tei) \
	do { \
		memset((fr), 0, sizeof(*(fr))); \
		Q921_INIT((fr), (l_sapi), (l_tei)); \
	} while (0)

static void q921_dump_pri(struct q921_link *link, char direction_tag);
static void q921_establish_data_link(struct q921_link *link);
static void q921_mdl_error(struct q921_link *link, char error);
static void q921_mdl_remove(struct q921_link *link);
static void q921_mdl_destroy(struct q921_link *link);

/*!
 * \internal
 * \brief Convert Q.921 TEI management message type to a string.
 *
 * \param message Q.921 TEI management message type to convert.
 *
 * \return TEI management message type name string
 */
static const char *q921_tei_mgmt2str(enum q921_tei_identity message)
{
	switch (message) {
	case Q921_TEI_IDENTITY_REQUEST:
		return "TEI Identity Request";
	case Q921_TEI_IDENTITY_ASSIGNED:
		return "TEI Identity Assigned";
	case Q921_TEI_IDENTITY_CHECK_REQUEST:
		return "TEI Identity Check Request";
	case Q921_TEI_IDENTITY_REMOVE:
		return "TEI Identity Remove";
	case Q921_TEI_IDENTITY_DENIED:
		return "TEI Identity Denied";
	case Q921_TEI_IDENTITY_CHECK_RESPONSE:
		return "TEI Identity Check Response";
	case Q921_TEI_IDENTITY_VERIFY:
		return "TEI Identity Verify";
	}

	return "Unknown";
}

/*!
 * \internal
 * \brief Convert Q.921 state to a string.
 *
 * \param state Q.921 state to convert.
 *
 * \return State name string
 */
static const char *q921_state2str(enum q921_state state)
{
	switch (state) {
	case Q921_TEI_UNASSIGNED:
		return "TEI unassigned";
	case Q921_ASSIGN_AWAITING_TEI:
		return "Assign awaiting TEI";
	case Q921_ESTABLISH_AWAITING_TEI:
		return "Establish awaiting TEI";
	case Q921_TEI_ASSIGNED:
		return "TEI assigned";
	case Q921_AWAITING_ESTABLISHMENT:
		return "Awaiting establishment";
	case Q921_AWAITING_RELEASE:
		return "Awaiting release";
	case Q921_MULTI_FRAME_ESTABLISHED:
		return "Multi-frame established";
	case Q921_TIMER_RECOVERY:
		return "Timer recovery";
	}

	return "Unknown state";
}

static void q921_setstate(struct q921_link *link, int newstate)
{
	struct pri *ctrl;

	ctrl = link->ctrl;
	if (ctrl->debug & PRI_DEBUG_Q921_STATE) {
		/*
		 * Suppress displaying these state transitions:
		 * Q921_MULTI_FRAME_ESTABLISHED <--> Q921_TIMER_RECOVERY
		 *
		 * Q921 keeps flipping back and forth between these two states
		 * when it has nothing better to do.
		 */
		switch (link->state) {
		case Q921_MULTI_FRAME_ESTABLISHED:
		case Q921_TIMER_RECOVERY:
			switch (newstate) {
			case Q921_MULTI_FRAME_ESTABLISHED:
			case Q921_TIMER_RECOVERY:
				/* Suppress displaying this state transition. */
				link->state = newstate;
				return;
			default:
				break;
			}
			break;
		default:
			break;
		}
		if (link->state != newstate) {
			pri_message(ctrl, "Changing from state %d(%s) to %d(%s)\n",
				link->state, q921_state2str(link->state),
				newstate, q921_state2str(newstate));
		}
	}
	link->state = newstate;
}

static void q921_discard_iqueue(struct q921_link *link)
{
	struct q921_frame *f, *p;

	f = link->tx_queue;
	while (f) {
		p = f;
		f = f->next;
		/* Free frame */
		free(p);
	}
	link->tx_queue = NULL;
}

static int q921_transmit(struct pri *ctrl, q921_h *h, int len) 
{
	int res;

#ifdef RANDOM_DROPS
	if (!(random() % 3)) {
		pri_message(ctrl, " === Dropping Packet ===\n");
		return 0;
	}
#endif
	ctrl->q921_txcount++;
	/* Just send it raw */
	if (ctrl->debug & (PRI_DEBUG_Q921_DUMP | PRI_DEBUG_Q921_RAW))
		q921_dump(ctrl, h, len, ctrl->debug, 1);
	/* Write an extra two bytes for the FCS */
	res = ctrl->write_func ? ctrl->write_func(ctrl, h, len + 2) : 0;
	if (res != (len + 2)) {
		pri_error(ctrl, "Short write: %d/%d (%s)\n", res, len + 2, strerror(errno));
		return -1;
	}
	return 0;
}

static void q921_mdl_send(struct pri *ctrl, enum q921_tei_identity message, int ri, int ai, int iscommand)
{
	q921_u *f;

	if (!(f = calloc(1, sizeof(*f) + 5)))
		return;

	Q921_INIT(f, Q921_SAPI_LAYER2_MANAGEMENT, Q921_TEI_GROUP);
	f->h.c_r = (ctrl->localtype == PRI_NETWORK) ? iscommand : !iscommand;
	f->ft = Q921_FRAMETYPE_U;
	f->data[0] = 0x0f;	/* Management entity */
	f->data[1] = (ri >> 8) & 0xff;
	f->data[2] = ri & 0xff;
	f->data[3] = message;
	f->data[4] = (ai << 1) | 1;
	if (ctrl->debug & PRI_DEBUG_Q921_STATE) {
		pri_message(ctrl,
			"Sending MDL message: %d(%s), TEI=%d\n",
			message, q921_tei_mgmt2str(message), ai);
	}
	q921_transmit(ctrl, (q921_h *)f, 8);
	free(f);
}

static void t202_expire(void *vlink)
{
	struct q921_link *link = vlink;
	struct pri *ctrl;

	ctrl = link->ctrl;

	/* Start the TEI request timer. */
	pri_schedule_del(ctrl, link->t202_timer);
	link->t202_timer =
		pri_schedule_event(ctrl, ctrl->timers[PRI_TIMER_T202], t202_expire, link);

	if (ctrl->l2_persistence != PRI_L2_PERSISTENCE_KEEP_UP) {
		/* Only try to get a TEI for N202 times if layer 2 is not persistent. */
		++link->n202_counter;
	}
	if (!link->t202_timer || link->n202_counter > ctrl->timers[PRI_TIMER_N202]) {
		if (!link->t202_timer) {
			pri_error(ctrl, "Could not start T202 timer.");
		} else {
			pri_schedule_del(ctrl, link->t202_timer);
			link->t202_timer = 0;
		}
		pri_error(ctrl, "Unable to receive TEI from network in state %d(%s)!\n",
			link->state, q921_state2str(link->state));
		switch (link->state) {
		case Q921_ASSIGN_AWAITING_TEI:
			break;
		case Q921_ESTABLISH_AWAITING_TEI:
			q921_discard_iqueue(link);
			/* DL-RELEASE indication */
			q931_dl_event(link, Q931_DL_EVENT_DL_RELEASE_IND);
			break;
		default:
			break;
		}
		q921_setstate(link, Q921_TEI_UNASSIGNED);
		return;
	}

	/* Send TEI request */
	link->ri = random() % 65535;
	q921_mdl_send(ctrl, Q921_TEI_IDENTITY_REQUEST, link->ri, Q921_TEI_GROUP, 1);
}

static void q921_tei_request(struct q921_link *link)
{
	link->n202_counter = 0;
	t202_expire(link);
}

static void q921_tei_remove(struct pri *ctrl, int tei)
{
	/*
	 * Q.921 Section 5.3.2 says we should send the remove message
	 * twice, in case of message loss.
	 */
	q921_mdl_send(ctrl, Q921_TEI_IDENTITY_REMOVE, 0, tei, 1);
	q921_mdl_send(ctrl, Q921_TEI_IDENTITY_REMOVE, 0, tei, 1);
}

static void q921_send_dm(struct q921_link *link, int fbit)
{
	q921_h h;
	struct pri *ctrl;

	ctrl = link->ctrl;

	Q921_CLEAR_INIT(&h, link->sapi, link->tei);
	h.u.m3 = 0;	/* M3 = 0 */
	h.u.m2 = 3;	/* M2 = 3 */
	h.u.p_f = fbit;	/* Final set appropriately */
	h.u.ft = Q921_FRAMETYPE_U;
	switch (ctrl->localtype) {
	case PRI_NETWORK:
		h.h.c_r = 0;
		break;
	case PRI_CPE:
		h.h.c_r = 1;
		break;
	default:
		pri_error(ctrl, "Don't know how to DM on a type %d node\n", ctrl->localtype);
		return;
	}
	if (ctrl->debug & PRI_DEBUG_Q921_STATE) {
		pri_message(ctrl, "TEI=%d Sending DM\n", link->tei);
	}
	q921_transmit(ctrl, &h, 3);
}

static void q921_send_disc(struct q921_link *link, int pbit)
{
	q921_h h;
	struct pri *ctrl;

	ctrl = link->ctrl;

	Q921_CLEAR_INIT(&h, link->sapi, link->tei);
	h.u.m3 = 2;	/* M3 = 2 */
	h.u.m2 = 0;	/* M2 = 0 */
	h.u.p_f = pbit;	/* Poll set appropriately */
	h.u.ft = Q921_FRAMETYPE_U;
	switch (ctrl->localtype) {
	case PRI_NETWORK:
		h.h.c_r = 0;
		break;
	case PRI_CPE:
		h.h.c_r = 1;
		break;
	default:
		pri_error(ctrl, "Don't know how to DISC on a type %d node\n", ctrl->localtype);
		return;
	}
	if (ctrl->debug & PRI_DEBUG_Q921_STATE) {
		pri_message(ctrl, "TEI=%d Sending DISC\n", link->tei);
	}
	q921_transmit(ctrl, &h, 3);
}

static void q921_send_ua(struct q921_link *link, int fbit)
{
	q921_h h;
	struct pri *ctrl;

	ctrl = link->ctrl;

	Q921_CLEAR_INIT(&h, link->sapi, link->tei);
	h.u.m3 = 3;		/* M3 = 3 */
	h.u.m2 = 0;		/* M2 = 0 */
	h.u.p_f = fbit;	/* Final set appropriately */
	h.u.ft = Q921_FRAMETYPE_U;
	switch (ctrl->localtype) {
	case PRI_NETWORK:
		h.h.c_r = 0;
		break;
	case PRI_CPE:
		h.h.c_r = 1;
		break;
	default:
		pri_error(ctrl, "Don't know how to UA on a type %d node\n", ctrl->localtype);
		return;
	}
	if (ctrl->debug & PRI_DEBUG_Q921_STATE) {
		pri_message(ctrl, "TEI=%d Sending UA\n", link->tei);
	}
	q921_transmit(ctrl, &h, 3);
}

static void q921_send_sabme(struct q921_link *link)
{
	q921_h h;
	struct pri *ctrl;

	ctrl = link->ctrl;

	Q921_CLEAR_INIT(&h, link->sapi, link->tei);
	h.u.m3 = 3;	/* M3 = 3 */
	h.u.m2 = 3;	/* M2 = 3 */
	h.u.p_f = 1;	/* Poll bit set */
	h.u.ft = Q921_FRAMETYPE_U;
	switch (ctrl->localtype) {
	case PRI_NETWORK:
		h.h.c_r = 1;
		break;
	case PRI_CPE:
		h.h.c_r = 0;
		break;
	default:
		pri_error(ctrl, "Don't know how to SABME on a type %d node\n", ctrl->localtype);
		return;
	}
	if (ctrl->debug & PRI_DEBUG_Q921_STATE) {
		pri_message(ctrl, "TEI=%d Sending SABME\n", link->tei);
	}
	q921_transmit(ctrl, &h, 3);
}

static int q921_ack_packet(struct q921_link *link, int num)
{
	struct q921_frame *f;
	struct q921_frame *prev;
	struct pri *ctrl;

	ctrl = link->ctrl;

	for (prev = NULL, f = link->tx_queue; f; prev = f, f = f->next) {
		if (f->status != Q921_TX_FRAME_SENT) {
			break;
		}
		if (f->h.n_s == num) {
			/* Cancel each packet as necessary */
			/* That's our packet */
			if (prev)
				prev->next = f->next;
			else
				link->tx_queue = f->next;
			if (ctrl->debug & PRI_DEBUG_Q921_DUMP) {
				pri_message(ctrl,
					"-- ACKing N(S)=%d, tx_queue head is N(S)=%d (-1 is empty, -2 is not transmitted)\n",
					f->h.n_s,
					link->tx_queue
						? link->tx_queue->status == Q921_TX_FRAME_SENT
							? link->tx_queue->h.n_s
							: -2
						: -1);
			}
			/* Update v_a */
			free(f);
			return 1;
		}
	}
	return 0;
}

static void t203_expire(void *vlink);
static void t200_expire(void *vlink);

#define restart_t200(link) reschedule_t200(link)
static void reschedule_t200(struct q921_link *link)
{
	struct pri *ctrl;

	ctrl = link->ctrl;

	if (ctrl->debug & PRI_DEBUG_Q921_DUMP)
		pri_message(ctrl, "-- Restarting T200 timer\n");
	pri_schedule_del(ctrl, link->t200_timer);
	link->t200_timer = pri_schedule_event(ctrl, ctrl->timers[PRI_TIMER_T200], t200_expire, link);
}

#if 0
static void reschedule_t203(struct q921_link *link)
{
	struct pri *ctrl;

	ctrl = link->ctrl;

	if (ctrl->debug & PRI_DEBUG_Q921_DUMP)
		pri_message(ctrl, "-- Restarting T203 timer\n");
	pri_schedule_del(ctrl, link->t203_timer);
	link->t203_timer = pri_schedule_event(ctrl, ctrl->timers[PRI_TIMER_T203], t203_expire, link);
}
#endif

static void start_t203(struct q921_link *link)
{
	struct pri *ctrl;

	ctrl = link->ctrl;

	if (link->t203_timer) {
		if (ctrl->debug & PRI_DEBUG_Q921_DUMP)
			pri_message(ctrl, "T203 requested to start without stopping first\n");
		pri_schedule_del(ctrl, link->t203_timer);
	}
	if (ctrl->debug & PRI_DEBUG_Q921_DUMP)
		pri_message(ctrl, "-- Starting T203 timer\n");
	link->t203_timer = pri_schedule_event(ctrl, ctrl->timers[PRI_TIMER_T203], t203_expire, link);
}

static void stop_t203(struct q921_link *link)
{
	struct pri *ctrl;

	ctrl = link->ctrl;

	if (link->t203_timer) {
		if (ctrl->debug & PRI_DEBUG_Q921_DUMP)
			pri_message(ctrl, "-- Stopping T203 timer\n");
		pri_schedule_del(ctrl, link->t203_timer);
		link->t203_timer = 0;
	} else {
		if (ctrl->debug & PRI_DEBUG_Q921_DUMP)
			pri_message(ctrl, "-- T203 requested to stop when not started\n");
	}
}

static void start_t200(struct q921_link *link)
{
	struct pri *ctrl;

	ctrl = link->ctrl;

	if (link->t200_timer) {
		if (ctrl->debug & PRI_DEBUG_Q921_DUMP)
			pri_message(ctrl, "T200 requested to start without stopping first\n");
		pri_schedule_del(ctrl, link->t200_timer);
	}
	if (ctrl->debug & PRI_DEBUG_Q921_DUMP)
		pri_message(ctrl, "-- Starting T200 timer\n");
	link->t200_timer = pri_schedule_event(ctrl, ctrl->timers[PRI_TIMER_T200], t200_expire, link);
}

static void stop_t200(struct q921_link *link)
{
	struct pri *ctrl;

	ctrl = link->ctrl;

	if (link->t200_timer) {
		if (ctrl->debug & PRI_DEBUG_Q921_DUMP)
			pri_message(ctrl, "-- Stopping T200 timer\n");
		pri_schedule_del(ctrl, link->t200_timer);
		link->t200_timer = 0;
	} else {
		if (ctrl->debug & PRI_DEBUG_Q921_DUMP)
			pri_message(ctrl, "-- T200 requested to stop when not started\n");
	}
}

/*!
 * \internal
 * \brief Initiate bringing up layer 2 link.
 *
 * \param link Layer 2 link to bring up.
 *
 * \return Nothing
 */
static void kick_start_link(struct q921_link *link)
{
	struct pri *ctrl;

	ctrl = link->ctrl;

	switch (link->state) {
	case Q921_TEI_UNASSIGNED:
		if (ctrl->debug & PRI_DEBUG_Q921_STATE) {
			pri_message(ctrl, "Kick starting link from no TEI.\n");
		}
		q921_setstate(link, Q921_ESTABLISH_AWAITING_TEI);
		q921_tei_request(link);
		break;
	case Q921_ASSIGN_AWAITING_TEI:
		if (ctrl->debug & PRI_DEBUG_Q921_STATE) {
			pri_message(ctrl, "Kick starting link when awaiting TEI.\n");
		}
		q921_setstate(link, Q921_ESTABLISH_AWAITING_TEI);
		break;
	case Q921_TEI_ASSIGNED:
		if (ctrl->debug & PRI_DEBUG_Q921_STATE) {
			pri_message(ctrl, "SAPI/TEI=%d/%d Kick starting link\n", link->sapi,
				link->tei);
		}
		q921_discard_iqueue(link);
		q921_establish_data_link(link);
		link->l3_initiated = 1;
		q921_setstate(link, Q921_AWAITING_ESTABLISHMENT);
		break;
	default:
		break;
	}
}

static void restart_timer_expire(void *vlink)
{
	struct q921_link *link = vlink;
	struct pri *ctrl;

	ctrl = link->ctrl;

	link->restart_timer = 0;

	switch (link->state) {
	case Q921_TEI_UNASSIGNED:
	case Q921_ASSIGN_AWAITING_TEI:
	case Q921_TEI_ASSIGNED:
		/* Try to bring layer 2 up. */
		kick_start_link(link);
		break;
	default:
		/* Looks like someone forgot to stop the restart timer. */
		pri_error(ctrl, "SAPI/TEI=%d/%d Link restart delay timer expired in state %d(%s)\n",
			link->sapi, link->tei, link->state, q921_state2str(link->state));
		break;
	}
}

static void restart_timer_stop(struct q921_link *link)
{
	struct pri *ctrl;

	ctrl = link->ctrl;
	pri_schedule_del(ctrl, link->restart_timer);
	link->restart_timer = 0;
}

/*! \note Only call on the transition to state Q921_TEI_ASSIGNED or already there. */
static void restart_timer_start(struct q921_link *link)
{
	struct pri *ctrl;

	ctrl = link->ctrl;

	if (ctrl->debug & PRI_DEBUG_Q921_DUMP) {
		pri_message(ctrl, "SAPI/TEI=%d/%d Starting link restart delay timer\n",
			link->sapi, link->tei);
	}
	pri_schedule_del(ctrl, link->restart_timer);
	link->restart_timer =
		pri_schedule_event(ctrl, ctrl->timers[PRI_TIMER_T200], restart_timer_expire, link);
}

/*! \note Only call on the transition to state Q921_TEI_ASSIGNED or already there. */
static pri_event *q921_check_delay_restart(struct q921_link *link)
{
	pri_event *ev;
	struct pri *ctrl;

	ctrl = link->ctrl;

	if (ctrl->l2_persistence == PRI_L2_PERSISTENCE_KEEP_UP) {
		/*
		 * For PTP links:
		 * This is where we act a bit like L3 instead of L2, since we've
		 * got an L3 that depends on us keeping L2 automatically alive
		 * and happy.
		 *
		 * For PTMP links:
		 * We can optionally keep L2 automatically alive and happy.
		 */
		restart_timer_start(link);
	}
	if (PTP_MODE(ctrl)) {
		switch (link->state) {
		case Q921_MULTI_FRAME_ESTABLISHED:
		case Q921_TIMER_RECOVERY:
			/* Notify the upper layer that layer 2 went down. */
			ctrl->schedev = 1;
			ctrl->ev.gen.e = PRI_EVENT_DCHAN_DOWN;
			ev = &ctrl->ev;
			break;
		default:
			ev = NULL;
			break;
		}
	} else {
		ev = NULL;
	}
	return ev;
}

/*!
 * \brief Bring all layer 2 links up.
 *
 * \param ctrl D channel controller.
 *
 * \return Nothing
 */
void q921_bring_layer2_up(struct pri *ctrl)
{
	struct q921_link *link;

	if (PTMP_MODE(ctrl)) {
		/* Don't start with the broadcast link. */
		link = ctrl->link.next;
	} else {
		link = &ctrl->link;
	}
	for (; link; link = link->next) {
		if (!link->restart_timer) {
			/* A restart on the link is not already in the works. */
			kick_start_link(link);
		}
	}
}

/* This is the equivalent of the I-Frame queued up path in Figure B.7 in MULTI_FRAME_ESTABLISHED */
static int q921_send_queued_iframes(struct q921_link *link)
{
	struct pri *ctrl;
	struct q921_frame *f;
	int frames_txd = 0;

	ctrl = link->ctrl;

	for (f = link->tx_queue; f; f = f->next) {
		if (f->status != Q921_TX_FRAME_SENT) {
			/* This frame needs to be sent. */
			break;
		}
	}
	if (!f) {
		/* The Tx queue has no pending frames. */
		return 0;
	}

	if (link->peer_rx_busy) {
		/* Don't flood debug trace if not really looking at Q.921 layer. */
		if (ctrl->debug & (/* PRI_DEBUG_Q921_STATE | */ PRI_DEBUG_Q921_DUMP)) {
			pri_message(ctrl,
				"TEI=%d Couldn't transmit I-frame at this time due to peer busy condition\n",
				link->tei);
		}
		return 0;
	}
	if (link->v_s == Q921_ADD(link->v_a, ctrl->timers[PRI_TIMER_K])) {
		/* Don't flood debug trace if not really looking at Q.921 layer. */
		if (ctrl->debug & (/* PRI_DEBUG_Q921_STATE | */ PRI_DEBUG_Q921_DUMP)) {
			pri_message(ctrl,
				"TEI=%d Couldn't transmit I-frame at this time due to window shut\n",
				link->tei);
		}
		return 0;
	}

	/* Send all pending frames that fit in the window. */
	for (; f; f = f->next) {
		if (link->v_s == Q921_ADD(link->v_a, ctrl->timers[PRI_TIMER_K])) {
			/* The window is no longer open. */
			break;
		}

		/* Send it now... */
		switch (f->status) {
		case Q921_TX_FRAME_NEVER_SENT:
			if (ctrl->debug & PRI_DEBUG_Q921_STATE) {
				pri_message(ctrl,
					"TEI=%d Transmitting N(S)=%d, window is open V(A)=%d K=%d\n",
					link->tei, link->v_s, link->v_a, ctrl->timers[PRI_TIMER_K]);
			}
			break;
		case Q921_TX_FRAME_PUSHED_BACK:
			if (f->h.n_s != link->v_s) {
				/* Should never happen. */
				pri_error(ctrl,
					"TEI=%d Retransmitting frame with old N(S)=%d as N(S)=%d!\n",
					link->tei, f->h.n_s, link->v_s);
			} else if (ctrl->debug & PRI_DEBUG_Q921_STATE) {
				pri_message(ctrl, "TEI=%d Retransmitting frame N(S)=%d now!\n",
					link->tei, link->v_s);
			}
			break;
		default:
			/* Should never happen. */
			pri_error(ctrl, "Unexpected Tx Q frame status: %d", f->status);
			break;
		}

		/*
		 * Send the frame out on the assigned TEI.
		 * Done now because the frame may have been queued before we
		 * had an assigned TEI.
		 */
		f->h.h.tei = link->tei;

		f->h.n_s = link->v_s;
		f->h.n_r = link->v_r;
		f->h.ft = 0;
		f->h.p_f = 0;
		q921_transmit(ctrl, (q921_h *) (&f->h), f->len);
		Q921_INC(link->v_s);
		++frames_txd;

		if ((ctrl->debug & PRI_DEBUG_Q931_DUMP)
			&& f->status == Q921_TX_FRAME_NEVER_SENT) {
			/*
			 * The transmit operation might dump the Q.921 header, so logging
			 * the Q.931 message body after the transmit puts the sections of
			 * the message in the right order in the log.
			 *
			 * Also dump the Q.931 part only once instead of for every
			 * retransmission.
			 */
			q931_dump(ctrl, link->tei, (q931_h *) f->h.data, f->len - 4, 1);
		}
		f->status = Q921_TX_FRAME_SENT;
	}

	if (frames_txd) {
		link->acknowledge_pending = 0;
		if (!link->t200_timer) {
			stop_t203(link);
			start_t200(link);
		}
	}

	return frames_txd;
}

static void q921_reject(struct q921_link *link, int pf)
{
	q921_h h;
	struct pri *ctrl;

	ctrl = link->ctrl;

	Q921_CLEAR_INIT(&h, link->sapi, link->tei);
	h.s.x0 = 0;	/* Always 0 */
	h.s.ss = 2;	/* Reject */
	h.s.ft = 1;	/* Frametype (01) */
	h.s.n_r = link->v_r;	/* Where to start retransmission N(R) */
	h.s.p_f = pf;	
	switch (ctrl->localtype) {
	case PRI_NETWORK:
		h.h.c_r = 0;
		break;
	case PRI_CPE:
		h.h.c_r = 1;
		break;
	default:
		pri_error(ctrl, "Don't know how to REJ on a type %d node\n", ctrl->localtype);
		return;
	}
	if (ctrl->debug & PRI_DEBUG_Q921_STATE) {
		pri_message(ctrl, "TEI=%d Sending REJ N(R)=%d\n", link->tei, link->v_r);
	}
	q921_transmit(ctrl, &h, 4);
}

static void q921_rr(struct q921_link *link, int pbit, int cmd)
{
	q921_h h;
	struct pri *ctrl;

	ctrl = link->ctrl;

	Q921_CLEAR_INIT(&h, link->sapi, link->tei);
	h.s.x0 = 0;	/* Always 0 */
	h.s.ss = 0; /* Receive Ready */
	h.s.ft = 1;	/* Frametype (01) */
	h.s.n_r = link->v_r;	/* N(R) */
	h.s.p_f = pbit;		/* Poll/Final set appropriately */
	switch (ctrl->localtype) {
	case PRI_NETWORK:
		if (cmd)
			h.h.c_r = 1;
		else
			h.h.c_r = 0;
		break;
	case PRI_CPE:
		if (cmd)
			h.h.c_r = 0;
		else
			h.h.c_r = 1;
		break;
	default:
		pri_error(ctrl, "Don't know how to RR on a type %d node\n", ctrl->localtype);
		return;
	}
#if 0	/* Don't flood debug trace with RR if not really looking at Q.921 layer. */
	if (ctrl->debug & PRI_DEBUG_Q921_STATE) {
		pri_message(ctrl, "TEI=%d Sending RR N(R)=%d\n", link->tei, link->v_r);
	}
#endif
	q921_transmit(ctrl, &h, 4);
}

static void transmit_enquiry(struct q921_link *link)
{
	if (!link->own_rx_busy) {
		q921_rr(link, 1, 1);
		link->acknowledge_pending = 0;
		start_t200(link);
	} else {
		/* XXX: Implement me... */
	}
}

static void t200_expire(void *vlink)
{
	struct q921_link *link = vlink;
	struct pri *ctrl;

	ctrl = link->ctrl;

	if (ctrl->debug & PRI_DEBUG_Q921_DUMP) {
		pri_message(ctrl, "%s\n", __FUNCTION__);
		q921_dump_pri(link, ' ');
	}

	link->t200_timer = 0;

	switch (link->state) {
	case Q921_MULTI_FRAME_ESTABLISHED:
		link->RC = 0;
		transmit_enquiry(link);
		link->RC++;
		q921_setstate(link, Q921_TIMER_RECOVERY);
		break;
	case Q921_TIMER_RECOVERY:
		/* SDL Flow Figure B.8/Q.921 Page 81 */
		if (link->RC != ctrl->timers[PRI_TIMER_N200]) {
#if 0
			if (link->v_s == link->v_a) {
				transmit_enquiry(link);
			}
#else
			/* We are chosing to enquiry by default (to reduce risk of T200 timer errors at the other
			 * side, instead of retransmission of the last I-frame we sent */
			transmit_enquiry(link);
#endif
			link->RC++;
		} else {
			q921_mdl_error(link, 'I');
			q921_establish_data_link(link);
			link->l3_initiated = 0;
			q921_setstate(link, Q921_AWAITING_ESTABLISHMENT);
			if (PTP_MODE(ctrl)) {
				ctrl->schedev = 1;
				ctrl->ev.gen.e = PRI_EVENT_DCHAN_DOWN;
			}
		}
		break;
	case Q921_AWAITING_ESTABLISHMENT:
		if (link->RC != ctrl->timers[PRI_TIMER_N200]) {
			link->RC++;
			q921_send_sabme(link);
			start_t200(link);
		} else {
			q921_check_delay_restart(link);
			q921_discard_iqueue(link);
			q921_mdl_error(link, 'G');
			q921_setstate(link, Q921_TEI_ASSIGNED);
			/* DL-RELEASE indication */
			q931_dl_event(link, Q931_DL_EVENT_DL_RELEASE_IND);
		}
		break;
	case Q921_AWAITING_RELEASE:
		if (link->RC != ctrl->timers[PRI_TIMER_N200]) {
			++link->RC;
			q921_send_disc(link, 1);
			start_t200(link);
		} else {
			q921_check_delay_restart(link);
			q921_mdl_error(link, 'H');
			/* DL-RELEASE confirm */
			q931_dl_event(link, Q931_DL_EVENT_DL_RELEASE_CONFIRM);
			q921_setstate(link, Q921_TEI_ASSIGNED);
		}
		break;
	default:
		/* Looks like someone forgot to stop the T200 timer. */
		pri_error(ctrl, "T200 expired in state %d(%s)\n",
			link->state, q921_state2str(link->state));
		break;
	}
}

/* This is sending a DL-UNIT-DATA request */
int q921_transmit_uiframe(struct q921_link *link, void *buf, int len)
{
	uint8_t ubuf[512];
	q921_h *h = (void *)&ubuf[0];
	struct pri *ctrl;

	ctrl = link->ctrl;

	if (len >= 512) {
		pri_error(ctrl, "Requested to send UI-frame larger than 512 bytes!\n");
		return -1;
	}

	memset(ubuf, 0, sizeof(ubuf));
	h->h.sapi = 0;
	h->h.ea1 = 0;
	h->h.ea2 = 1;
	h->h.tei = link->tei;
	h->u.m3 = 0;
	h->u.m2 = 0;
	h->u.p_f = 0;	/* Poll bit set */
	h->u.ft = Q921_FRAMETYPE_U;

	switch (ctrl->localtype) {
	case PRI_NETWORK:
		h->h.c_r = 1;
		break;
	case PRI_CPE:
		h->h.c_r = 0;
		break;
	default:
		pri_error(ctrl, "Don't know how to UI-frame on a type %d node\n", ctrl->localtype);
		return -1;
	}

	memcpy(h->u.data, buf, len);

	q921_transmit(ctrl, h, len + 3);

	return 0;
}

static struct q921_link *pri_find_tei(struct pri *ctrl, int sapi, int tei)
{
	struct q921_link *link;

	for (link = &ctrl->link; link; link = link->next) {
		if (link->tei == tei && link->sapi == sapi)
			return link;
	}

	return NULL;
}

/* This is the equivalent of a DL-DATA request, as well as the I-frame queued up outcome */
int q921_transmit_iframe(struct q921_link *link, void *buf, int len, int cr)
{
	struct q921_frame *f, *prev=NULL;
	struct pri *ctrl;

	ctrl = link->ctrl;

	if (PTMP_MODE(ctrl)) {
		if (link->tei == Q921_TEI_GROUP) {
			pri_error(ctrl, "Huh?! For PTMP, we shouldn't be sending I-frames out the group TEI\n");
			return 0;
		}
		if (BRI_TE_PTMP(ctrl)) {
			switch (link->state) {
			case Q921_TEI_UNASSIGNED:
				q921_setstate(link, Q921_ESTABLISH_AWAITING_TEI);
				q921_tei_request(link);
				break;
			case Q921_ASSIGN_AWAITING_TEI:
				q921_setstate(link, Q921_ESTABLISH_AWAITING_TEI);
				break;
			default:
				break;
			}
		}
	} else {
		/* PTP modes, which shouldn't have subs */
	}

	/* Figure B.7/Q.921 Page 70 */
	switch (link->state) {
	case Q921_TEI_ASSIGNED:
		/* If we aren't in a state compatiable with DL-DATA requests, start getting us there here */
		restart_timer_stop(link);
		q921_establish_data_link(link);
		link->l3_initiated = 1;
		q921_setstate(link, Q921_AWAITING_ESTABLISHMENT);
		/* For all rest, we've done the work to get us up prior to this and fall through */
	case Q921_ESTABLISH_AWAITING_TEI:
	case Q921_TIMER_RECOVERY:
	case Q921_AWAITING_ESTABLISHMENT:
	case Q921_MULTI_FRAME_ESTABLISHED:
		/* Find queue tail. */
		for (f = link->tx_queue; f; f = f->next) {
			prev = f;
		}

		f = calloc(1, sizeof(struct q921_frame) + len + 2);
		if (f) {
			Q921_INIT(&f->h, link->sapi, link->tei);
			switch (ctrl->localtype) {
			case PRI_NETWORK:
				if (cr)
					f->h.h.c_r = 1;
				else
					f->h.h.c_r = 0;
				break;
			case PRI_CPE:
				if (cr)
					f->h.h.c_r = 0;
				else
					f->h.h.c_r = 1;
				break;
			}

			/* Put new frame on queue tail. */
			f->next = NULL;
			f->status = Q921_TX_FRAME_NEVER_SENT;
			f->len = len + 4;
			memcpy(f->h.data, buf, len);
			if (prev)
				prev->next = f;
			else
				link->tx_queue = f;

			if (link->state != Q921_MULTI_FRAME_ESTABLISHED) {
				if (ctrl->debug & PRI_DEBUG_Q921_STATE) {
					pri_message(ctrl,
						"TEI=%d Just queued I-frame since in state %d(%s)\n",
						link->tei,
						link->state, q921_state2str(link->state));
				}
				break;
			}
			if (link->peer_rx_busy) {
				if (ctrl->debug & PRI_DEBUG_Q921_STATE) {
					pri_message(ctrl,
						"TEI=%d Just queued I-frame due to peer busy condition\n",
						link->tei);
				}
				break;
			}

			if (!q921_send_queued_iframes(link)) {
				/*
				 * No frames sent even though we just put a frame on the queue.
				 *
				 * Special debug message/test here because we want to say what
				 * happened to the Q.931 message just queued but we don't want
				 * to flood the debug trace if we are not really looking at the
				 * Q.921 layer.
				 */
				if ((ctrl->debug & (PRI_DEBUG_Q921_STATE | PRI_DEBUG_Q921_DUMP))
					== PRI_DEBUG_Q921_STATE) {
					pri_message(ctrl, "TEI=%d Just queued I-frame due to window shut\n",
						link->tei);
				}
			}
		} else {
			pri_error(ctrl, "!! Out of memory for Q.921 transmit\n");
			return -1;
		}
		break;
	case Q921_TEI_UNASSIGNED:
	case Q921_ASSIGN_AWAITING_TEI:
	case Q921_AWAITING_RELEASE:
	default:
		pri_error(ctrl, "Cannot transmit frames in state %d(%s)\n",
			link->state, q921_state2str(link->state));
		break;
	}
	return 0;
}

static void t203_expire(void *vlink)
{
	struct q921_link *link = vlink;
	struct pri *ctrl;

	ctrl = link->ctrl;

	if (ctrl->debug & PRI_DEBUG_Q921_DUMP)
		pri_message(ctrl, "%s\n", __FUNCTION__);

	link->t203_timer = 0;

	switch (link->state) {
	case Q921_MULTI_FRAME_ESTABLISHED:
		transmit_enquiry(link);
		link->RC = 0;
		q921_setstate(link, Q921_TIMER_RECOVERY);
		break;
	default:
		/* Looks like someone forgot to stop the T203 timer. */
		pri_error(ctrl, "T203 expired in state %d(%s)\n",
			link->state, q921_state2str(link->state));
		break;
	}
}

static void q921_dump_iqueue_info(struct q921_link *link)
{
	struct pri *ctrl;
	struct q921_frame *f;
	int pending = 0;
	int unacked = 0;

	ctrl = link->ctrl;

	for (f = link->tx_queue; f; f = f->next) {
		if (f->status == Q921_TX_FRAME_SENT) {
			unacked++;
		} else {
			pending++;
		}
	}

	pri_error(ctrl, "Number of pending packets %d, sent but unacked %d\n", pending, unacked);
}

static void q921_dump_pri_by_h(struct pri *ctrl, char direction_tag, q921_h *h);

void q921_dump(struct pri *ctrl, q921_h *h, int len, int debugflags, int txrx)
{
	int x;
	const char *type;
	char direction_tag;
	
	direction_tag = txrx ? '>' : '<';

	pri_message(ctrl, "\n");
	if (debugflags & PRI_DEBUG_Q921_DUMP) {
		q921_dump_pri_by_h(ctrl, direction_tag, h);
	}

	if (debugflags & PRI_DEBUG_Q921_RAW) {
		char *buf = malloc(len * 3 + 1);
		int buflen = 0;
		if (buf) {
			for (x=0;x<len;x++) 
				buflen += sprintf(buf + buflen, "%02x ", h->raw[x]);
			pri_message(ctrl, "%c [ %s]\n", direction_tag, buf);
			free(buf);
		}
	}

	if (debugflags & PRI_DEBUG_Q921_DUMP) {
		switch (h->h.data[0] & Q921_FRAMETYPE_MASK) {
		case 0:
		case 2:
			pri_message(ctrl, "%c Informational frame:\n", direction_tag);
			break;
		case 1:
			pri_message(ctrl, "%c Supervisory frame:\n", direction_tag);
			break;
		case 3:
			pri_message(ctrl, "%c Unnumbered frame:\n", direction_tag);
			break;
		}
		
		pri_message(ctrl, "%c SAPI: %02d  C/R: %d EA: %d\n",
			direction_tag,
			h->h.sapi, 
			h->h.c_r,
			h->h.ea1);
		pri_message(ctrl, "%c  TEI: %03d        EA: %d\n", 
			direction_tag,
			h->h.tei,
			h->h.ea2);
	
		switch (h->h.data[0] & Q921_FRAMETYPE_MASK) {
		case 0:
		case 2:
			/* Informational frame */
			pri_message(ctrl, "%c N(S): %03d   0: %d\n",
				direction_tag,
				h->i.n_s,
				h->i.ft);
			pri_message(ctrl, "%c N(R): %03d   P: %d\n",
				direction_tag,
				h->i.n_r,
				h->i.p_f);
			pri_message(ctrl, "%c %d bytes of data\n",
				direction_tag,
				len - 4);
			break;
		case 1:
			/* Supervisory frame */
			type = "???";
			switch (h->s.ss) {
			case 0:
				type = "RR (receive ready)";
				break;
			case 1:
				type = "RNR (receive not ready)";
				break;
			case 2:
				type = "REJ (reject)";
				break;
			}
			pri_message(ctrl, "%c Zero: %d     S: %d 01: %d  [ %s ]\n",
				direction_tag,
				h->s.x0,
				h->s.ss,
				h->s.ft,
				type);
			pri_message(ctrl, "%c N(R): %03d P/F: %d\n",
				direction_tag,
				h->s.n_r,
				h->s.p_f);
			pri_message(ctrl, "%c %d bytes of data\n",
				direction_tag,
				len - 4);
			break;
		case 3:		
			/* Unnumbered frame */
			type = "???";
			if (h->u.ft == 3) {
				switch (h->u.m3) {
				case 0:
					if (h->u.m2 == 3)
						type = "DM (disconnect mode)";
					else if (h->u.m2 == 0)
						type = "UI (unnumbered information)";
					break;
				case 2:
					if (h->u.m2 == 0)
						type = "DISC (disconnect)";
					break;
				case 3:
					if (h->u.m2 == 3)
						type = "SABME (set asynchronous balanced mode extended)";
					else if (h->u.m2 == 0)
						type = "UA (unnumbered acknowledgement)";
					break;
				case 4:
					if (h->u.m2 == 1)
						type = "FRMR (frame reject)";
					break;
				case 5:
					if (h->u.m2 == 3)
						type = "XID (exchange identification note)";
					break;
				default:
					break;
				}
			}
			pri_message(ctrl, "%c   M3: %d   P/F: %d M2: %d 11: %d  [ %s ]\n",
				direction_tag,
				h->u.m3,
				h->u.p_f,
				h->u.m2,
				h->u.ft,
				type);
			pri_message(ctrl, "%c %d bytes of data\n",
				direction_tag,
				len - 3);
			break;
		}
	
		if ((h->u.ft == 3) && (h->u.m3 == 0) && (h->u.m2 == 0) && (h->u.data[0] == 0x0f)) {
			int ri;
			u_int8_t *action;
	
			/* TEI management related */
			type = q921_tei_mgmt2str(h->u.data[3]);
			pri_message(ctrl, "%c MDL Message: %d(%s)\n", direction_tag, h->u.data[3], type);
			ri = (h->u.data[1] << 8) | h->u.data[2];
			pri_message(ctrl, "%c Ri: %d\n", direction_tag, ri);
			action = &h->u.data[4];
			for (x = len - (action - (u_int8_t *) h); 0 < x; --x, ++action) {
				pri_message(ctrl, "%c Ai: %d E:%d\n",
					direction_tag, (*action >> 1) & 0x7f, *action & 0x01);
			}
		}
	}
}

static void q921_dump_pri(struct q921_link *link, char direction_tag)
{
	struct pri *ctrl;

	ctrl = link->ctrl;

	pri_message(ctrl, "%c TEI: %d State %d(%s)\n",
		direction_tag, link->tei, link->state, q921_state2str(link->state));
	pri_message(ctrl, "%c V(A)=%d, V(S)=%d, V(R)=%d\n",
		direction_tag, link->v_a, link->v_s, link->v_r);
	pri_message(ctrl, "%c K=%d, RC=%d, l3_initiated=%d, reject_except=%d, ack_pend=%d\n",
		direction_tag, ctrl->timers[PRI_TIMER_K], link->RC, link->l3_initiated,
		link->reject_exception, link->acknowledge_pending);
	pri_message(ctrl, "%c T200_id=%d, N200=%d, T203_id=%d\n",
		direction_tag, link->t200_timer, ctrl->timers[PRI_TIMER_N200], link->t203_timer);
}

static void q921_dump_pri_by_h(struct pri *ctrl, char direction_tag, q921_h *h)
{
	struct q921_link *link;

	if (!ctrl) {
		return;
	}

	if (BRI_NT_PTMP(ctrl)) {
		link = pri_find_tei(ctrl, h->h.sapi, h->h.tei);
	} else if (BRI_TE_PTMP(ctrl)) {
		/* We're operating on the specific TEI link */
		link = ctrl->link.next;
	} else {
		link = &ctrl->link;
	}

	if (link) {
		q921_dump_pri(link, direction_tag);
	} else {
		pri_message(ctrl, "%c Link not found for this frame.\n", direction_tag);
	}
}

#define Q921_TEI_CHECK_MAX_POLLS	2

static void t201_expire(void *vctrl)
{
	struct pri *ctrl;
	struct q921_link *link;
	struct q921_link *link_next;

	ctrl = vctrl;

	/* Start the TEI check timer. */
	ctrl->t201_timer =
		pri_schedule_event(ctrl, ctrl->timers[PRI_TIMER_T201], t201_expire, ctrl);

	++ctrl->t201_expirycnt;
	if (Q921_TEI_CHECK_MAX_POLLS < ctrl->t201_expirycnt) {
		pri_schedule_del(ctrl, ctrl->t201_timer);
		ctrl->t201_timer = 0;

		/* Reclaim any dead TEI links. */
		for (link = ctrl->link.next; link; link = link_next) {
			link_next = link->next;

			switch (link->tei_check) {
			case Q921_TEI_CHECK_DEAD:
				link->tei_check = Q921_TEI_CHECK_NONE;
				q921_tei_remove(ctrl, link->tei);
				q921_mdl_destroy(link);
				break;
			default:
				link->tei_check = Q921_TEI_CHECK_NONE;
				break;
			}
		}
		return;
	}

	if (!ctrl->t201_timer) {
		pri_error(ctrl, "Could not start T201 timer.");

		/* Abort the remaining TEI check. */
		for (link = ctrl->link.next; link; link = link->next) {
			link->tei_check = Q921_TEI_CHECK_NONE;
		}
		return;
	}

	if (ctrl->t201_expirycnt == 1) {
		/* First poll.  Setup TEI check state. */
		for (link = ctrl->link.next; link; link = link->next) {
			if (link->state < Q921_TEI_ASSIGNED) {
				/* We do not have a TEI. */
				link->tei_check = Q921_TEI_CHECK_NONE;
			} else {
				/* Mark TEI as dead until proved otherwise. */
				link->tei_check = Q921_TEI_CHECK_DEAD;
			}
		}
	} else {
		/* Subsequent polls.  Setup for new TEI check poll. */
		for (link = ctrl->link.next; link; link = link->next) {
			switch (link->tei_check) {
			case Q921_TEI_CHECK_REPLY:
				link->tei_check = Q921_TEI_CHECK_DEAD_REPLY;
				break;
			default:
				break;
			}
		}
	}
	q921_mdl_send(ctrl, Q921_TEI_IDENTITY_CHECK_REQUEST, 0, Q921_TEI_GROUP, 1);
}

static void q921_tei_check(struct pri *ctrl)
{
	if (ctrl->t201_timer) {
		/* TEI check procedure already in progress.  Do not disturb it. */
		return;
	}
	ctrl->t201_expirycnt = 0;
	t201_expire(ctrl);
}

static void q921_mdl_ignore(struct pri *ctrl, q921_u *h, const char *reason)
{
	if (ctrl->debug & PRI_DEBUG_Q921_STATE) {
		/*
		 * Send out this message in debug modes since it is possible the
		 * user has misconfigured their link for the wrong mode.
		 */
		pri_message(ctrl, "Ignoring MDL message: %d(%s)  %s\n",
			h->data[3], q921_tei_mgmt2str(h->data[3]), reason);
	}
}

static pri_event *q921_mdl_receive(struct pri *ctrl, q921_u *h, int len)
{
	int ri;
	struct q921_link *sub;
	struct q921_link *link;
	pri_event *res = NULL;
	u_int8_t *action;
	int count;
	int tei;

	if (len <= &h->data[0] - (u_int8_t *) h) {
		pri_error(ctrl, "Received short MDL frame\n");
		return NULL;
	}
	if (h->data[0] != 0x0f) {
		pri_error(ctrl, "Received MDL with unsupported management entity %02x\n",
			h->data[0]);
		return NULL;
	}
	if (len <= &h->data[4] - (u_int8_t *) h) {
		pri_error(ctrl, "Received short MDL message\n");
		return NULL;
	}
	if (h->data[3] != Q921_TEI_IDENTITY_CHECK_RESPONSE
		&& !(h->data[4] & 0x01)) {
		pri_error(ctrl, "Received MDL message: %d(%s) with Ai E bit not set.\n",
			h->data[3], q921_tei_mgmt2str(h->data[3]));
		return NULL;
	}
	if (ctrl->debug & PRI_DEBUG_Q921_STATE) {
		pri_message(ctrl, "Received MDL message: %d(%s)\n",
			h->data[3], q921_tei_mgmt2str(h->data[3]));
	}
	if (PTP_MODE(ctrl) && NT_MODE(ctrl)) {
		/*
		 * We are not managing automatic TEI's in this mode so we can
		 * ignore MDL messages from the CPE.
		 */
		q921_mdl_ignore(ctrl, h, "We are in NT-PTP mode.");
		return NULL;
	}
	ri = (h->data[1] << 8) | h->data[2];
	tei = (h->data[4] >> 1);

	switch (h->data[3]) {
	case Q921_TEI_IDENTITY_REQUEST:
		if (!BRI_NT_PTMP(ctrl)) {
			q921_mdl_ignore(ctrl, h, "We are not in NT-PTMP mode.");
			return NULL;
		}

		if (tei != Q921_TEI_GROUP) {
			pri_error(ctrl, "Received %s with invalid TEI %d\n",
				q921_tei_mgmt2str(Q921_TEI_IDENTITY_REQUEST), tei);
			q921_mdl_send(ctrl, Q921_TEI_IDENTITY_DENIED, ri, tei, 1);
			return NULL;
		}

		/* Find a TEI that is not allocated. */
		tei = Q921_TEI_AUTO_FIRST;
		do {
			for (sub = &ctrl->link; sub->next; sub = sub->next) {
				if (sub->next->tei == tei) {
					/* This TEI is already assigned, try next one. */
					++tei;
					if (tei <= Q921_TEI_AUTO_LAST) {
						break;
					}
					pri_error(ctrl, "TEI pool exhausted.  Reclaiming dead TEIs.\n");
					q921_mdl_send(ctrl, Q921_TEI_IDENTITY_DENIED, ri, Q921_TEI_GROUP, 1);
					q921_tei_check(ctrl);
					return NULL;
				}
			}
		} while (sub->next);

		if (ctrl->debug & PRI_DEBUG_Q921_STATE) {
			pri_message(ctrl, "Allocating new TEI %d\n", tei);
		}
		link = pri_link_new(ctrl, Q921_SAPI_CALL_CTRL, tei);
		if (!link) {
			pri_error(ctrl, "Unable to allocate layer 2 link for new TEI %d\n", tei);
			return NULL;
		}
		sub->next = link;
		q921_setstate(link, Q921_TEI_ASSIGNED);
		q921_mdl_send(ctrl, Q921_TEI_IDENTITY_ASSIGNED, ri, tei, 1);

		count = 0;
		for (sub = ctrl->link.next; sub; sub = sub->next) {
			++count;
		}
		if (Q921_TEI_AUTO_LAST - Q921_TEI_AUTO_FIRST + 1 <= count) {
			/*
			 * We just allocated the last TEI.  Try to reclaim dead TEIs
			 * before another is requested.
			 */
			if (ctrl->debug & PRI_DEBUG_Q921_STATE) {
				pri_message(ctrl, "Allocated last TEI.  Reclaiming dead TEIs.\n");
			}
			q921_tei_check(ctrl);
		}

		if (ctrl->l2_persistence == PRI_L2_PERSISTENCE_KEEP_UP) {
			/*
			 * Layer 2 is persistent so give the peer some time to setup
			 * it's new TEI and bring the link up itself before we bring the
			 * link up.
			 */
			restart_timer_start(link);
		}
		break;
	case Q921_TEI_IDENTITY_CHECK_RESPONSE:
		if (!BRI_NT_PTMP(ctrl)) {
			/* Silently ignore the message since we never asked for the check. */
			return NULL;
		}

		/* For each TEI listed in the message */
		action = &h->data[4];
		len -= (action - (u_int8_t *) h);
		for (; len; --len, ++action) {
			if (*action & 0x01) {
				/* This is the last TEI in the list because the Ai E bit is set. */
				len = 1;
			}
			tei = (*action >> 1);

			if (tei == Q921_TEI_GROUP) {
				pri_error(ctrl, "Received %s with invalid TEI %d\n",
					q921_tei_mgmt2str(Q921_TEI_IDENTITY_CHECK_RESPONSE), tei);
				continue;
			}

			for (sub = ctrl->link.next; sub; sub = sub->next) {
				if (sub->tei == tei) {
					/* Found the TEI. */
					switch (sub->tei_check) {
					case Q921_TEI_CHECK_NONE:
						break;
					case Q921_TEI_CHECK_DEAD:
					case Q921_TEI_CHECK_DEAD_REPLY:
						sub->tei_check = Q921_TEI_CHECK_REPLY;
						break;
					case Q921_TEI_CHECK_REPLY:
						/* Duplicate TEI detected. */
						sub->tei_check = Q921_TEI_CHECK_NONE;
						q921_tei_remove(ctrl, tei);
						q921_mdl_destroy(sub);
						break;
					}
					break;
				}
			}
			if (!sub) {
				/* TEI not found. */
				q921_tei_remove(ctrl, tei);
			}
		}
		break;
	case Q921_TEI_IDENTITY_VERIFY:
		if (!BRI_NT_PTMP(ctrl)) {
			q921_mdl_ignore(ctrl, h, "We are not in NT-PTMP mode.");
			return NULL;
		}
		if (tei == Q921_TEI_GROUP) {
			pri_error(ctrl, "Received %s with invalid TEI %d\n",
				q921_tei_mgmt2str(Q921_TEI_IDENTITY_VERIFY), tei);
			return NULL;
		}
		q921_tei_check(ctrl);
		break;
	case Q921_TEI_IDENTITY_ASSIGNED:
		if (NT_MODE(ctrl)) {
			/* We should not be receiving this message. */
			q921_mdl_ignore(ctrl, h, "We are the network.");
			return NULL;
		}
		if (!BRI_TE_PTMP(ctrl)) {
			/*
			 * Silently ignore the message.  It must not be for us
			 * since we will never ask for one.
			 */
			return NULL;
		}

		/* We're operating on the specific TEI link here */
		link = ctrl->link.next;
		
		switch (link->state) {
		case Q921_TEI_UNASSIGNED:
			/*
			 * We do not have a TEI and we are not currently asking for one.
			 * Start asking for one.
			 */
			q921_setstate(link, Q921_ASSIGN_AWAITING_TEI);
			q921_tei_request(link);
			return NULL;
		case Q921_ASSIGN_AWAITING_TEI:
		case Q921_ESTABLISH_AWAITING_TEI:
			/* We do not have a TEI and we want one. */
			break;
		default:
			/* We already have a TEI. */
			if (tei == link->tei) {
				/*
				 * The TEI assignment conflicts with ours.  Our TEI is the
				 * duplicate so we should remove it.  Q.921 Section 5.3.4.2
				 * condition c.
				 */
				pri_error(ctrl, "TEI=%d Conflicting TEI assignment.  Removing our TEI.\n",
					tei);
				q921_mdl_remove(link);
				q921_start(link);
			}
			return NULL;
		}

		if (ri != link->ri) {
			if (ctrl->debug & PRI_DEBUG_Q921_STATE) {
				pri_message(ctrl,
					"TEI assignment received for another Ri %02x (ours is %02x)\n",
					ri, link->ri);
			}
			return NULL;
		}

		pri_schedule_del(ctrl, link->t202_timer);
		link->t202_timer = 0;

		link->tei = tei;
		if (ctrl->debug & PRI_DEBUG_Q921_STATE) {
			pri_message(ctrl, "Got assigned TEI %d\n", tei);
		}

		switch (link->state) {
		case Q921_ASSIGN_AWAITING_TEI:
			q921_setstate(link, Q921_TEI_ASSIGNED);
			if (ctrl->l2_persistence != PRI_L2_PERSISTENCE_KEEP_UP) {
				ctrl->ev.gen.e = PRI_EVENT_DCHAN_UP;
				res = &ctrl->ev;
				break;
			}
			/* Fall through: Layer 2 is persistent so bring it up. */
		case Q921_ESTABLISH_AWAITING_TEI:
			q921_establish_data_link(link);
			link->l3_initiated = 1;
			q921_setstate(link, Q921_AWAITING_ESTABLISHMENT);
			ctrl->ev.gen.e = PRI_EVENT_DCHAN_UP;
			res = &ctrl->ev;
			break;
		default:
			break;
		}
		break;
	case Q921_TEI_IDENTITY_CHECK_REQUEST:
		if (NT_MODE(ctrl)) {
			/* We should not be receiving this message. */
			q921_mdl_ignore(ctrl, h, "We are the network.");
			return NULL;
		}

		if (PTP_MODE(ctrl)) {
			/*
			 * Some telco switches/devices get very unhappy if we don't
			 * respond to the TEI check request with our permanently
			 * assigned TEI.
			 */
			link = &ctrl->link;
		} else if (BRI_TE_PTMP(ctrl)) {
			/* We're operating on the specific TEI link here */
			link = ctrl->link.next;

			if (link->state < Q921_TEI_ASSIGNED) {
				/* We do not have a TEI. */
				return NULL;
			}
		} else {
			/* Should never get here. */
			return NULL;
		}

		/* If it's addressed to the group TEI or to our TEI specifically, we respond */
		if (tei == Q921_TEI_GROUP || tei == link->tei) {
			q921_mdl_send(ctrl, Q921_TEI_IDENTITY_CHECK_RESPONSE, random() % 65535, link->tei, 1);
		}
		break;
	case Q921_TEI_IDENTITY_REMOVE:
		if (NT_MODE(ctrl)) {
			/* We should not be receiving this message. */
			q921_mdl_ignore(ctrl, h, "We are the network.");
			return NULL;
		}
		if (!BRI_TE_PTMP(ctrl)) {
			/*
			 * Silently ignore the message.  If we are TE-PTP our
			 * TEI is permanently assigned and cannot be removed.
			 */
			return NULL;
		}

		/* We're operating on the specific TEI link here */
		link = ctrl->link.next;

		if (link->state < Q921_TEI_ASSIGNED) {
			/* We do not have a TEI. */
			return NULL;
		}

		/* If it's addressed to the group TEI or to our TEI specifically, we respond */
		if (tei == Q921_TEI_GROUP || tei == link->tei) {
			q921_mdl_remove(link);
			q921_start(link);
		}
		break;
	}
	return res;	/* Do we need to return something??? */
}

static int is_command(struct pri *ctrl, q921_h *h)
{
	int command = 0;
	int c_r = h->s.h.c_r;

	if ((ctrl->localtype == PRI_NETWORK && c_r == 0) ||
		(ctrl->localtype == PRI_CPE && c_r == 1))
		command = 1;

	return command;
}

static void q921_clear_exception_conditions(struct q921_link *link)
{
	link->own_rx_busy = 0;
	link->peer_rx_busy = 0;
	link->reject_exception = 0;
	link->acknowledge_pending = 0;
}

static pri_event *q921_sabme_rx(struct q921_link *link, q921_h *h)
{
	pri_event *res = NULL;
	struct pri *ctrl;
	enum Q931_DL_EVENT delay_q931_dl_event;

	ctrl = link->ctrl;

	switch (link->state) {
	case Q921_TIMER_RECOVERY:
		/* Timer recovery state handling is same as multiframe established */
	case Q921_MULTI_FRAME_ESTABLISHED:
		/* Send Unnumbered Acknowledgement */
		q921_send_ua(link, h->u.p_f);
		q921_clear_exception_conditions(link);
		q921_mdl_error(link, 'F');
		if (link->v_s != link->v_a) {
			q921_discard_iqueue(link);
			/* DL-ESTABLISH indication */
			delay_q931_dl_event = Q931_DL_EVENT_DL_ESTABLISH_IND;
		} else {
			delay_q931_dl_event = Q931_DL_EVENT_NONE;
		}
		stop_t200(link);
		start_t203(link);
		link->v_s = link->v_a = link->v_r = 0;
		q921_setstate(link, Q921_MULTI_FRAME_ESTABLISHED);
		if (delay_q931_dl_event != Q931_DL_EVENT_NONE) {
			/* Delayed because Q.931 could send STATUS messages. */
			q931_dl_event(link, delay_q931_dl_event);
		}
		break;
	case Q921_TEI_ASSIGNED:
		restart_timer_stop(link);
		q921_send_ua(link, h->u.p_f);
		q921_clear_exception_conditions(link);
		link->v_s = link->v_a = link->v_r = 0;
		/* DL-ESTABLISH indication */
		delay_q931_dl_event = Q931_DL_EVENT_DL_ESTABLISH_IND;
		if (PTP_MODE(ctrl)) {
			ctrl->ev.gen.e = PRI_EVENT_DCHAN_UP;
			res = &ctrl->ev;
		}
		start_t203(link);
		q921_setstate(link, Q921_MULTI_FRAME_ESTABLISHED);
		if (delay_q931_dl_event != Q931_DL_EVENT_NONE) {
			/* Delayed because Q.931 could send STATUS messages. */
			q931_dl_event(link, delay_q931_dl_event);
		}
		break;
	case Q921_AWAITING_ESTABLISHMENT:
		q921_send_ua(link, h->u.p_f);
		break;
	case Q921_AWAITING_RELEASE:
		q921_send_dm(link, h->u.p_f);
		break;
	default:
		pri_error(ctrl, "Cannot handle SABME in state %d(%s)\n",
			link->state, q921_state2str(link->state));
		break;
	}

	return res;
}

static pri_event *q921_disc_rx(struct q921_link *link, q921_h *h)
{
	pri_event *res = NULL;
	struct pri *ctrl;

	ctrl = link->ctrl;

	if (ctrl->debug & PRI_DEBUG_Q921_STATE) {
		pri_message(ctrl, "TEI=%d Got DISC\n", link->tei);
	}

	switch (link->state) {
	case Q921_TEI_ASSIGNED:
	case Q921_AWAITING_ESTABLISHMENT:
		q921_send_dm(link, h->u.p_f);
		break;
	case Q921_AWAITING_RELEASE:
		q921_send_ua(link, h->u.p_f);
		break;
	case Q921_MULTI_FRAME_ESTABLISHED:
	case Q921_TIMER_RECOVERY:
		res = q921_check_delay_restart(link);
		q921_discard_iqueue(link);
		q921_send_ua(link, h->u.p_f);
		/* DL-RELEASE indication */
		q931_dl_event(link, Q931_DL_EVENT_DL_RELEASE_IND);
		stop_t200(link);
		if (link->state == Q921_MULTI_FRAME_ESTABLISHED)
			stop_t203(link);
		q921_setstate(link, Q921_TEI_ASSIGNED);
		break;
	default:
		pri_error(ctrl, "Don't know what to do with DISC in state %d(%s)\n",
			link->state, q921_state2str(link->state));
		break;
	}

	return res;
}

static void q921_mdl_remove(struct q921_link *link)
{
	int mdl_free_me;
	struct pri *ctrl;

	ctrl = link->ctrl;

	if (ctrl->debug & PRI_DEBUG_Q921_STATE) {
		pri_message(ctrl, "MDL-REMOVE: Removing TEI %d\n", link->tei);
	}
	if (BRI_NT_PTMP(ctrl)) {
		if (link == &ctrl->link) {
			pri_error(ctrl, "Bad bad bad!  Cannot MDL-REMOVE master\n");
			return;
		}
		mdl_free_me = 1;
	} else {
		mdl_free_me = 0;
	}

	switch (link->state) {
	case Q921_TEI_ASSIGNED:
		if (mdl_free_me) {
			restart_timer_stop(link);
		}
		/* XXX: deviation! Since we don't have a UI queue, we just discard our I-queue */
		q921_discard_iqueue(link);
		q921_setstate(link, Q921_TEI_UNASSIGNED);
		break;
	case Q921_AWAITING_ESTABLISHMENT:
		q921_discard_iqueue(link);
		/* DL-RELEASE indication */
		q931_dl_event(link, Q931_DL_EVENT_DL_RELEASE_IND);
		stop_t200(link);
		q921_setstate(link, Q921_TEI_UNASSIGNED);
		break;
	case Q921_AWAITING_RELEASE:
		q921_discard_iqueue(link);
		/* DL-RELEASE confirm */
		q931_dl_event(link, Q931_DL_EVENT_DL_RELEASE_CONFIRM);
		stop_t200(link);
		q921_setstate(link, Q921_TEI_UNASSIGNED);
		break;
	case Q921_MULTI_FRAME_ESTABLISHED:
		q921_discard_iqueue(link);
		/* DL-RELEASE indication */
		q931_dl_event(link, Q931_DL_EVENT_DL_RELEASE_IND);
		stop_t200(link);
		stop_t203(link);
		q921_setstate(link, Q921_TEI_UNASSIGNED);
		break;
	case Q921_TIMER_RECOVERY:
		q921_discard_iqueue(link);
		/* DL-RELEASE indication */
		q931_dl_event(link, Q931_DL_EVENT_DL_RELEASE_IND);
		stop_t200(link);
		q921_setstate(link, Q921_TEI_UNASSIGNED);
		break;
	default:
		pri_error(ctrl, "MDL-REMOVE when in state %d(%s)\n",
			link->state, q921_state2str(link->state));
		return;
	}

	q931_dl_event(link, Q931_DL_EVENT_TEI_REMOVAL);

	/*
	 * Negate the TEI value so debug messages will display a
	 * negated TEI when it is actually unassigned.
	 */
	link->tei = -link->tei;

	link->mdl_free_me = mdl_free_me;
}

static void q921_mdl_link_destroy(struct q921_link *link)
{
	struct pri *ctrl;
	struct q921_link *freep;
	struct q921_link *prev;

	ctrl = link->ctrl;

	freep = NULL;
	for (prev = &ctrl->link; prev->next; prev = prev->next) {
		if (prev->next == link) {
			prev->next = link->next;
			freep = link;
			break;
		}
	}
	if (freep == NULL) {
		pri_error(ctrl, "Huh!? no match found in list for TEI %d\n", -link->tei);
		return;
	}

	if (ctrl->debug & PRI_DEBUG_Q921_STATE) {
		pri_message(ctrl, "Freeing TEI of %d\n", -freep->tei);
	}

	pri_link_destroy(freep);
}

static void q921_mdl_destroy(struct q921_link *link)
{
	q921_mdl_remove(link);
	if (link->mdl_free_me) {
		q921_mdl_link_destroy(link);
	}
}

static void q921_mdl_handle_network_error(struct q921_link *link, char error)
{
	struct pri *ctrl;

	switch (error) {
	case 'C':
	case 'D':
	case 'G':
	case 'H':
		q921_mdl_remove(link);
		break;
	case 'A':
	case 'B':
	case 'E':
	case 'F':
	case 'I':
	case 'J':
	case 'K':
		break;
	default:
		ctrl = link->ctrl;
		pri_error(ctrl, "Network MDL can't handle error of type %c\n", error);
		break;
	}
}

static void q921_mdl_handle_cpe_error(struct q921_link *link, char error)
{
	struct pri *ctrl;

	switch (error) {
	case 'C':
	case 'D':
	case 'G':
	case 'H':
		q921_mdl_remove(link);
		break;
	case 'A':
	case 'B':
	case 'E':
	case 'F':
	case 'I':
	case 'J':
	case 'K':
		break;
	default:
		ctrl = link->ctrl;
		pri_error(ctrl, "CPE MDL can't handle error of type %c\n", error);
		break;
	}
}

static void q921_mdl_handle_ptp_error(struct q921_link *link, char error)
{
	struct pri *ctrl;

	ctrl = link->ctrl;

	switch (error) {
	case 'J':
		/*
		 * This is for the transition to Q921_AWAITING_ESTABLISHMENT.
		 * The event is genereated here rather than where the MDL_ERROR
		 * 'J' is posted because of the potential event conflict with
		 * incoming I-frame information passed to Q.931.
		 */
		ctrl->schedev = 1;
		ctrl->ev.gen.e = PRI_EVENT_DCHAN_DOWN;
		break;
	case 'A':
	case 'B':
	case 'C':
	case 'D':
	case 'E':
	case 'F':
	case 'G':
	case 'H':
	case 'I':
	case 'K':
		break;
	default:
		pri_error(ctrl, "PTP MDL can't handle error of type %c\n", error);
		break;
	}
}

static void q921_mdl_handle_error(struct q921_link *link, char error)
{
	struct pri *ctrl;

	ctrl = link->ctrl;

	if (PTP_MODE(ctrl)) {
		q921_mdl_handle_ptp_error(link, error);
	} else {
		if (ctrl->localtype == PRI_NETWORK) {
			q921_mdl_handle_network_error(link, error);
		} else {
			q921_mdl_handle_cpe_error(link, error);
		}
	}
}

static void q921_mdl_handle_error_callback(void *vlink)
{
	struct q921_link *link = vlink;

	q921_mdl_handle_error(link, link->mdl_error);

	link->mdl_error = 0;
	link->mdl_timer = 0;

	if (link->mdl_free_me) {
		q921_mdl_link_destroy(link);
	}
}

static void q921_mdl_error(struct q921_link *link, char error)
{
	int is_debug_q921_state;
	struct pri *ctrl;

	ctrl = link->ctrl;

	/* Log the MDL-ERROR event when detected. */
	is_debug_q921_state = (ctrl->debug & PRI_DEBUG_Q921_STATE);
	switch (error) {
	case 'A':
		pri_message(ctrl,
			"TEI=%d MDL-ERROR (A): Got supervisory frame with F=1 in state %d(%s)\n",
			link->tei, link->state, q921_state2str(link->state));
		break;
	case 'B':
	case 'E':
		pri_message(ctrl, "TEI=%d MDL-ERROR (%c): DM (F=%c) in state %d(%s)\n",
			link->tei, error, (error == 'B') ? '1' : '0',
			link->state, q921_state2str(link->state));
		break;
	case 'C':
	case 'D':
		if (is_debug_q921_state || PTP_MODE(ctrl)) {
			pri_message(ctrl, "TEI=%d MDL-ERROR (%c): UA (F=%c) in state %d(%s)\n",
				link->tei, error, (error == 'C') ? '1' : '0',
				link->state, q921_state2str(link->state));
		}
		break;
	case 'F':
		/*
		 * The peer is restarting the link.
		 * Some reasons this might happen:
		 * 1) Our link establishment requests collided.
		 * 2) They got reset.
		 * 3) They could not talk to us for some reason because
		 * their T200 timer expired N200 times.
		 * 4) They got an MDL-ERROR (J).
		 */
		if (is_debug_q921_state) {
			/*
			 * This message is rather annoying and is normal for
			 * reasons 1-3 above.
			 */
			pri_message(ctrl, "TEI=%d MDL-ERROR (F): SABME in state %d(%s)\n",
				link->tei, link->state, q921_state2str(link->state));
		}
		break;
	case 'G':
		/* We could not get a response from the peer. */
		if (is_debug_q921_state) {
			pri_message(ctrl,
				"TEI=%d MDL-ERROR (G): T200 expired N200 times sending SABME in state %d(%s)\n",
				link->tei, link->state, q921_state2str(link->state));
		}
		break;
	case 'H':
		/* We could not get a response from the peer. */
		if (is_debug_q921_state) {
			pri_message(ctrl,
				"TEI=%d MDL-ERROR (H): T200 expired N200 times sending DISC in state %d(%s)\n",
				link->tei, link->state, q921_state2str(link->state));
		}
		break;
	case 'I':
		/* We could not get a response from the peer. */
		if (is_debug_q921_state) {
			pri_message(ctrl,
				"TEI=%d MDL-ERROR (I): T200 expired N200 times sending RR/RNR in state %d(%s)\n",
				link->tei, link->state, q921_state2str(link->state));
		}
		break;
	case 'J':
		/* N(R) not within ack window. */
		pri_error(ctrl, "TEI=%d MDL-ERROR (J): N(R) error in state %d(%s)\n",
			link->tei, link->state, q921_state2str(link->state));
		break;
	case 'K':
		/*
		 * Received a frame reject frame.
		 * The other end does not like what we are doing at all for some reason.
		 */
		pri_error(ctrl, "TEI=%d MDL-ERROR (K): FRMR in state %d(%s)\n",
			link->tei, link->state, q921_state2str(link->state));
		break;
	default:
		pri_message(ctrl, "TEI=%d MDL-ERROR (%c): in state %d(%s)\n",
			link->tei, error, link->state, q921_state2str(link->state));
		break;
	}

	if (link->mdl_error) {
		/* This should not happen. */
		pri_error(ctrl,
			"Trying to queue MDL-ERROR (%c) when MDL-ERROR (%c) is already scheduled\n",
			error, link->mdl_error);
		return;
	}
	link->mdl_error = error;
	link->mdl_timer = pri_schedule_event(ctrl, 0, q921_mdl_handle_error_callback, link);
	if (!link->mdl_timer) {
		/* Timer allocation failed */
		link->mdl_error = 0;
	}
}

static pri_event *q921_ua_rx(struct q921_link *link, q921_h *h)
{
	struct pri *ctrl;
	pri_event *res = NULL;
	enum Q931_DL_EVENT delay_q931_dl_event;

	ctrl = link->ctrl;

	if (ctrl->debug & PRI_DEBUG_Q921_STATE) {
		pri_message(ctrl, "TEI=%d Got UA\n", link->tei);
	}

	switch (link->state) {
	case Q921_TEI_ASSIGNED:
	case Q921_MULTI_FRAME_ESTABLISHED:
	case Q921_TIMER_RECOVERY:
		if (h->u.p_f) {
			q921_mdl_error(link, 'C');
		} else {
			q921_mdl_error(link, 'D');
		}
		break;
	case Q921_AWAITING_ESTABLISHMENT:
		if (!h->u.p_f) {
			q921_mdl_error(link, 'D');
			break;
		}

		delay_q931_dl_event = Q931_DL_EVENT_NONE;
		if (!link->l3_initiated) {
			if (link->v_s != link->v_a) {
				q921_discard_iqueue(link);
				/* DL-ESTABLISH indication */
				delay_q931_dl_event = Q931_DL_EVENT_DL_ESTABLISH_IND;
			}
		} else {
			link->l3_initiated = 0;
			/* DL-ESTABLISH confirm */
			delay_q931_dl_event = Q931_DL_EVENT_DL_ESTABLISH_CONFIRM;
		}

		if (PTP_MODE(ctrl)) {
			ctrl->ev.gen.e = PRI_EVENT_DCHAN_UP;
			res = &ctrl->ev;
		}

		stop_t200(link);
		start_t203(link);

		link->v_r = link->v_s = link->v_a = 0;

		q921_setstate(link, Q921_MULTI_FRAME_ESTABLISHED);
		if (delay_q931_dl_event != Q931_DL_EVENT_NONE) {
			/* Delayed because Q.931 could send STATUS messages. */
			q931_dl_event(link, delay_q931_dl_event);
		}
		break;
	case Q921_AWAITING_RELEASE:
		if (!h->u.p_f) {
			q921_mdl_error(link, 'D');
		} else {
			res = q921_check_delay_restart(link);
			/* DL-RELEASE confirm */
			q931_dl_event(link, Q931_DL_EVENT_DL_RELEASE_CONFIRM);
			stop_t200(link);
			q921_setstate(link, Q921_TEI_ASSIGNED);
		}
		break;
	default:
		pri_error(ctrl, "Don't know what to do with UA in state %d(%s)\n",
			link->state, q921_state2str(link->state));
		break;
	}

	return res;
}

static void q921_enquiry_response(struct q921_link *link)
{
	struct pri *ctrl;

	if (link->own_rx_busy) {
		/* XXX : TODO later sometime */
		ctrl = link->ctrl;
		pri_error(ctrl, "Implement me %s: own_rx_busy\n", __FUNCTION__);
		//q921_rnr(link);
	} else {
		q921_rr(link, 1, 0);
	}

	link->acknowledge_pending = 0;
}

static void n_r_error_recovery(struct q921_link *link)
{
	q921_mdl_error(link, 'J');

	q921_establish_data_link(link);

	link->l3_initiated = 0;
}

static void update_v_a(struct q921_link *link, int n_r)
{
	int idealcnt = 0, realcnt = 0;
	int x;
	struct pri *ctrl;

	ctrl = link->ctrl;

	/* Cancel each packet as necessary */
	if (ctrl->debug & PRI_DEBUG_Q921_DUMP)
		pri_message(ctrl, "-- Got ACK for N(S)=%d to (but not including) N(S)=%d\n", link->v_a, n_r);
	for (x = link->v_a; x != n_r; Q921_INC(x)) {
		idealcnt++;
		realcnt += q921_ack_packet(link, x);	
	}
	if (idealcnt != realcnt) {
		pri_error(ctrl, "Ideally should have ack'd %d frames, but actually ack'd %d.  This is not good.\n", idealcnt, realcnt);
		q921_dump_iqueue_info(link);
	}

	link->v_a = n_r;
}

/*! \brief Is V(A) <= N(R) <= V(S) ? */
static int n_r_is_valid(struct q921_link *link, int n_r)
{
	int x;

	for (x = link->v_a; x != n_r && x != link->v_s; Q921_INC(x)) {
	}
	if (x != n_r) {
		return 0;
	} else {
		return 1;
	}
}

static int q921_invoke_retransmission(struct q921_link *link, int n_r);

static pri_event *timer_recovery_rr_rej_rx(struct q921_link *link, q921_h *h)
{
	struct pri *ctrl;

	ctrl = link->ctrl;

	/* Figure B.7/Q.921 Page 74 */
	link->peer_rx_busy = 0;

	if (is_command(ctrl, h)) {
		if (h->s.p_f) {
			/* Enquiry response */
			q921_enquiry_response(link);
		}
		if (n_r_is_valid(link, h->s.n_r)) {
			update_v_a(link, h->s.n_r);
		} else {
			goto n_r_error_out;
		}
	} else {
		if (!h->s.p_f) {
			if (n_r_is_valid(link, h->s.n_r)) {
				update_v_a(link, h->s.n_r);
			} else {
				goto n_r_error_out;
			}
		} else {
			if (n_r_is_valid(link, h->s.n_r)) {
				update_v_a(link, h->s.n_r);
				stop_t200(link);
				start_t203(link);
				q921_invoke_retransmission(link, h->s.n_r);
				q921_setstate(link, Q921_MULTI_FRAME_ESTABLISHED);
			} else {
				goto n_r_error_out;
			}
		}
	}
	return NULL;
n_r_error_out:
	n_r_error_recovery(link);
	q921_setstate(link, Q921_AWAITING_ESTABLISHMENT);
	return NULL;
}

static pri_event *q921_rr_rx(struct q921_link *link, q921_h *h)
{
	pri_event *res = NULL;
	struct pri *ctrl;

	ctrl = link->ctrl;

#if 0	/* Don't flood debug trace with RR if not really looking at Q.921 layer. */
	if (ctrl->debug & PRI_DEBUG_Q921_STATE) {
		pri_message(ctrl, "TEI=%d Got RR N(R)=%d\n", link->tei, h->s.n_r);
	}
#endif

	switch (link->state) {
	case Q921_TIMER_RECOVERY:
		res = timer_recovery_rr_rej_rx(link, h);
		break;
	case Q921_MULTI_FRAME_ESTABLISHED:
		/* Figure B.7/Q.921 Page 74 */
		link->peer_rx_busy = 0;

		if (is_command(ctrl, h)) {
			if (h->s.p_f) {
				/* Enquiry response */
				q921_enquiry_response(link);
			}
		} else {
			if (h->s.p_f) {
				q921_mdl_error(link, 'A');
			}
		}

		if (!n_r_is_valid(link, h->s.n_r)) {
			n_r_error_recovery(link);
			q921_setstate(link, Q921_AWAITING_ESTABLISHMENT);
		} else {
			if (h->s.n_r == link->v_s) {
				update_v_a(link, h->s.n_r);
				stop_t200(link);
				start_t203(link);
			} else {
				if (h->s.n_r != link->v_a) {
					/* Need to check the validity of n_r as well.. */
					update_v_a(link, h->s.n_r);
					restart_t200(link);
				}
			}
		}
		break;
	case Q921_TEI_ASSIGNED:
	case Q921_AWAITING_ESTABLISHMENT:
	case Q921_AWAITING_RELEASE:
		/*
		 * Ignore this frame.
		 * We likely got reset and the other end has not realized it yet.
		 */
		break;
	default:
		pri_error(ctrl, "Don't know what to do with RR in state %d(%s)\n",
			link->state, q921_state2str(link->state));
		break;
	}

	return res;
}

static int q921_invoke_retransmission(struct q921_link *link, int n_r)
{
	struct q921_frame *f;
	struct pri *ctrl;

	ctrl = link->ctrl;

	/*
	 * All acked frames should already have been removed from the queue.
	 * Push back all sent frames.
	 */
	for (f = link->tx_queue; f && f->status == Q921_TX_FRAME_SENT; f = f->next) {
		f->status = Q921_TX_FRAME_PUSHED_BACK;

		/* Sanity check: Is V(A) <= N(S) <= V(S)? */
		if (!n_r_is_valid(link, f->h.n_s)) {
			pri_error(ctrl,
				"Tx Q frame with invalid N(S)=%d.  Must be (V(A)=%d) <= N(S) <= (V(S)=%d)\n",
				f->h.n_s, link->v_a, link->v_s);
		}
	}
	link->v_s = n_r;
	return q921_send_queued_iframes(link);
}

static pri_event *q921_rej_rx(struct q921_link *link, q921_h *h)
{
	pri_event *res = NULL;
	struct pri *ctrl;

	ctrl = link->ctrl;

	if (ctrl->debug & PRI_DEBUG_Q921_STATE) {
		pri_message(ctrl, "TEI=%d Got REJ N(R)=%d\n", link->tei, h->s.n_r);
	}

	switch (link->state) {
	case Q921_TIMER_RECOVERY:
		res = timer_recovery_rr_rej_rx(link, h);
		break;
	case Q921_MULTI_FRAME_ESTABLISHED:
		/* Figure B.7/Q.921 Page 74 */
		link->peer_rx_busy = 0;

		if (is_command(ctrl, h)) {
			if (h->s.p_f) {
				/* Enquiry response */
				q921_enquiry_response(link);
			}
		} else {
			if (h->s.p_f) {
				q921_mdl_error(link, 'A');
			}
		}

		if (!n_r_is_valid(link, h->s.n_r)) {
			n_r_error_recovery(link);
			q921_setstate(link, Q921_AWAITING_ESTABLISHMENT);
		} else {
			update_v_a(link, h->s.n_r);
			stop_t200(link);
			start_t203(link);
			q921_invoke_retransmission(link, h->s.n_r);
		}
		break;
	case Q921_TEI_ASSIGNED:
	case Q921_AWAITING_ESTABLISHMENT:
	case Q921_AWAITING_RELEASE:
		/*
		 * Ignore this frame.
		 * We likely got reset and the other end has not realized it yet.
		 */
		break;
	default:
		pri_error(ctrl, "Don't know what to do with REJ in state %d(%s)\n",
			link->state, q921_state2str(link->state));
		break;
	}

	return res;
}

static pri_event *q921_frmr_rx(struct q921_link *link, q921_h *h)
{
	pri_event *res = NULL;
	struct pri *ctrl;

	ctrl = link->ctrl;

	if (ctrl->debug & PRI_DEBUG_Q921_STATE) {
		pri_message(ctrl, "TEI=%d Got FRMR\n", link->tei);
	}

	switch (link->state) {
	case Q921_TIMER_RECOVERY:
	case Q921_MULTI_FRAME_ESTABLISHED:
		q921_mdl_error(link, 'K');
		q921_establish_data_link(link);
		link->l3_initiated = 0;
		q921_setstate(link, Q921_AWAITING_ESTABLISHMENT);
		if (PTP_MODE(ctrl)) {
			ctrl->ev.gen.e = PRI_EVENT_DCHAN_DOWN;
			res = &ctrl->ev;
		}
		break;
	case Q921_TEI_ASSIGNED:
	case Q921_AWAITING_ESTABLISHMENT:
	case Q921_AWAITING_RELEASE:
		/*
		 * Ignore this frame.
		 * We likely got reset and the other end has not realized it yet.
		 */
		if (ctrl->debug & PRI_DEBUG_Q921_STATE) {
			pri_message(ctrl, "TEI=%d Ignoring FRMR.\n", link->tei);
		}
		break;
	default:
		pri_error(ctrl, "Don't know what to do with FRMR in state %d(%s)\n",
			link->state, q921_state2str(link->state));
		break;
	}

	return res;
}

static pri_event *q921_iframe_rx(struct q921_link *link, q921_h *h, int len)
{
	struct pri *ctrl;
	pri_event *eres = NULL;
	int res = 0;
	int delay_q931_receive;

	ctrl = link->ctrl;

	switch (link->state) {
	case Q921_TIMER_RECOVERY:
	case Q921_MULTI_FRAME_ESTABLISHED:
		delay_q931_receive = 0;
		/* FIXME: Verify that it's a command ... */
		if (link->own_rx_busy) {
			/* DEVIATION: Handle own rx busy */
		} else if (h->i.n_s == link->v_r) {
			Q921_INC(link->v_r);

			link->reject_exception = 0;

			/*
			 * Dump Q.931 message where Q.921 says to queue it to Q.931 so if
			 * Q.921 is dumping its frames they will be in the correct order.
			 */
			if (ctrl->debug & PRI_DEBUG_Q931_DUMP) {
				q931_dump(ctrl, h->h.tei, (q931_h *) h->i.data, len - 4, 0);
			}
			delay_q931_receive = 1;

			if (h->i.p_f) {
				q921_rr(link, 1, 0);
				link->acknowledge_pending = 0;
			} else {
				link->acknowledge_pending = 1;
			}
		} else {
			if (link->reject_exception) {
				if (h->i.p_f) {
					q921_rr(link, 1, 0);
					link->acknowledge_pending = 0;
				}
			} else {
				link->reject_exception = 1;
				q921_reject(link, h->i.p_f);
				link->acknowledge_pending = 0;
			}
		}

		if (!n_r_is_valid(link, h->i.n_r)) {
			n_r_error_recovery(link);
			q921_setstate(link, Q921_AWAITING_ESTABLISHMENT);
		} else {
			if (link->state == Q921_TIMER_RECOVERY) {
				update_v_a(link, h->i.n_r);
			} else {
				if (link->peer_rx_busy) {
					update_v_a(link, h->i.n_r);
				} else {
					if (h->i.n_r == link->v_s) {
						update_v_a(link, h->i.n_r);
						stop_t200(link);
						start_t203(link);
					} else {
						if (h->i.n_r != link->v_a) {
							update_v_a(link, h->i.n_r);
							reschedule_t200(link);
						}
					}
				}
			}
		}
		if (delay_q931_receive) {
			/* Q.921 has finished processing the frame so we can give it to Q.931 now. */
			res = q931_receive(link, (q931_h *) h->i.data, len - 4);
			if (res != -1 && (res & Q931_RES_HAVEEVENT)) {
				eres = &ctrl->ev;
			}
		}
		break;
	case Q921_TEI_ASSIGNED:
	case Q921_AWAITING_ESTABLISHMENT:
	case Q921_AWAITING_RELEASE:
		/*
		 * Ignore this frame.
		 * We likely got reset and the other end has not realized it yet.
		 */
		break;
	default:
		pri_error(ctrl, "Don't know what to do with an I-frame in state %d(%s)\n",
			link->state, q921_state2str(link->state));
		break;
	}

	return eres;
}

static pri_event *q921_dm_rx(struct q921_link *link, q921_h *h)
{
	pri_event *res = NULL;
	struct pri *ctrl;

	ctrl = link->ctrl;

	if (ctrl->debug & PRI_DEBUG_Q921_STATE) {
		pri_message(ctrl, "TEI=%d Got DM\n", link->tei);
	}

	switch (link->state) {
	case Q921_TEI_ASSIGNED:
		if (h->u.p_f)
			break;
		/* else */
		restart_timer_stop(link);
		q921_establish_data_link(link);
		link->l3_initiated = 1;
		q921_setstate(link, Q921_AWAITING_ESTABLISHMENT);
		break;
	case Q921_AWAITING_ESTABLISHMENT:
		if (!h->u.p_f)
			break;

		res = q921_check_delay_restart(link);
		q921_discard_iqueue(link);
		/* DL-RELEASE indication */
		q931_dl_event(link, Q931_DL_EVENT_DL_RELEASE_IND);
		stop_t200(link);
		q921_setstate(link, Q921_TEI_ASSIGNED);
		break;
	case Q921_AWAITING_RELEASE:
		if (!h->u.p_f)
			break;
		res = q921_check_delay_restart(link);
		/* DL-RELEASE confirm */
		q931_dl_event(link, Q931_DL_EVENT_DL_RELEASE_CONFIRM);
		stop_t200(link);
		q921_setstate(link, Q921_TEI_ASSIGNED);
		break;
	case Q921_MULTI_FRAME_ESTABLISHED:
		if (h->u.p_f) {
			q921_mdl_error(link, 'B');
			break;
		}

		q921_mdl_error(link, 'E');
		q921_establish_data_link(link);
		link->l3_initiated = 0;
		q921_setstate(link, Q921_AWAITING_ESTABLISHMENT);
		if (PTP_MODE(ctrl)) {
			ctrl->ev.gen.e = PRI_EVENT_DCHAN_DOWN;
			res = &ctrl->ev;
		}
		break;
	case Q921_TIMER_RECOVERY:
		if (h->u.p_f) {
			q921_mdl_error(link, 'B');
		} else {
			q921_mdl_error(link, 'E');
		}
		q921_establish_data_link(link);
		link->l3_initiated = 0;
		q921_setstate(link, Q921_AWAITING_ESTABLISHMENT);
		if (PTP_MODE(ctrl)) {
			ctrl->ev.gen.e = PRI_EVENT_DCHAN_DOWN;
			res = &ctrl->ev;
		}
		break;
	default:
		pri_error(ctrl, "Don't know what to do with DM frame in state %d(%s)\n",
			link->state, q921_state2str(link->state));
		break;
	}

	return res;
}

static pri_event *q921_rnr_rx(struct q921_link *link, q921_h *h)
{
	pri_event *res = NULL;
	struct pri *ctrl;

	ctrl = link->ctrl;

	if (ctrl->debug & PRI_DEBUG_Q921_STATE) {
		pri_message(ctrl, "TEI=%d Got RNR N(R)=%d\n", link->tei, h->s.n_r);
	}

	switch (link->state) {
	case Q921_MULTI_FRAME_ESTABLISHED:
		link->peer_rx_busy = 1;
		if (!is_command(ctrl, h)) {
			if (h->s.p_f) {
				q921_mdl_error(link, 'A');
			}
		} else {
			if (h->s.p_f) {
				q921_enquiry_response(link);
			}
		}

		if (!n_r_is_valid(link, h->s.n_r)) {
			n_r_error_recovery(link);
			q921_setstate(link, Q921_AWAITING_ESTABLISHMENT);
		} else {
			update_v_a(link, h->s.n_r);
			stop_t203(link);
			restart_t200(link);
		}
		break;
	case Q921_TIMER_RECOVERY:
		/* Q.921 Figure B.8 Q921 (Sheet 6 of 9) Page 85 */
		link->peer_rx_busy = 1;
		if (is_command(ctrl, h)) {
			if (h->s.p_f) {
				q921_enquiry_response(link);
			}
			if (n_r_is_valid(link, h->s.n_r)) {
				update_v_a(link, h->s.n_r);
				break;
			} else {
				n_r_error_recovery(link);
				q921_setstate(link, Q921_AWAITING_ESTABLISHMENT);
				break;
			}
		} else {
			if (h->s.p_f) {
				if (n_r_is_valid(link, h->s.n_r)) {
					update_v_a(link, h->s.n_r);
					restart_t200(link);
					q921_invoke_retransmission(link, h->s.n_r);
					q921_setstate(link, Q921_MULTI_FRAME_ESTABLISHED);
					break;
				} else {
					n_r_error_recovery(link);
					q921_setstate(link, Q921_AWAITING_ESTABLISHMENT);
					break;
				}
			} else {
				if (n_r_is_valid(link, h->s.n_r)) {
					update_v_a(link, h->s.n_r);
					break;
				} else {
					n_r_error_recovery(link);
					q921_setstate(link, Q921_AWAITING_ESTABLISHMENT);
					break;
				}
			}
		}
		break;
	case Q921_TEI_ASSIGNED:
	case Q921_AWAITING_ESTABLISHMENT:
	case Q921_AWAITING_RELEASE:
		/*
		 * Ignore this frame.
		 * We likely got reset and the other end has not realized it yet.
		 */
		break;
	default:
		pri_error(ctrl, "Don't know what to do with RNR in state %d(%s)\n",
			link->state, q921_state2str(link->state));
		break;
	}

	return res;
}

static void q921_acknowledge_pending_check(struct q921_link *link)
{
	if (link->acknowledge_pending) {
		link->acknowledge_pending = 0;
		q921_rr(link, 0, 0);
	}
}

static void q921_statemachine_check(struct q921_link *link)
{
	switch (link->state) {
	case Q921_MULTI_FRAME_ESTABLISHED:
		q921_send_queued_iframes(link);
		q921_acknowledge_pending_check(link);
		break;
	case Q921_TIMER_RECOVERY:
		q921_acknowledge_pending_check(link);
		break;
	default:
		break;
	}
}

static pri_event *__q921_receive_qualified(struct q921_link *link, q921_h *h, int len)
{
	int res;
	pri_event *ev = NULL;
	struct pri *ctrl;

	ctrl = link->ctrl;

	switch (h->h.data[0] & Q921_FRAMETYPE_MASK) {
	case 0:
	case 2:
		ev = q921_iframe_rx(link, h, len);
		break;
	case 1:
		switch ((h->s.x0 << 2) | h->s.ss) {
		case 0x00:
			ev = q921_rr_rx(link, h);
			break;
 		case 0x01:
			ev = q921_rnr_rx(link, h);
			break;
 		case 0x02:
			ev = q921_rej_rx(link, h);
			break;
		default:
			pri_error(ctrl,
				"!! XXX Unknown Supervisory frame x0=%d ss=%d, pf=%d, N(R)=%d, V(A)=%d, V(S)=%d XXX\n",
				h->s.x0, h->s.ss, h->s.p_f, h->s.n_r, link->v_a, link->v_s);
			break;
		}
		break;
	case 3:
		if (len < 3) {
			pri_error(ctrl, "!! Received short unnumbered frame\n");
			break;
		}
		switch ((h->u.m3 << 2) | h->u.m2) {
		case 0x03:
			ev = q921_dm_rx(link, h);
			break;
		case 0x00:
			/* UI-frame */
			if (ctrl->debug & PRI_DEBUG_Q931_DUMP) {
				q931_dump(ctrl, h->h.tei, (q931_h *) h->u.data, len - 3, 0);
			}
			res = q931_receive(link, (q931_h *) h->u.data, len - 3);
			if (res != -1 && (res & Q931_RES_HAVEEVENT)) {
				ev = &ctrl->ev;
			}
			break;
		case 0x08:
			ev = q921_disc_rx(link, h);
			break;
		case 0x0F:
			/* SABME */
			if (ctrl->debug & PRI_DEBUG_Q921_STATE) {
				pri_message(ctrl, "TEI=%d Got SABME from %s peer.\n",
					link->tei, h->h.c_r ? "network" : "cpe");
			}
			if (h->h.c_r) {
				ctrl->remotetype = PRI_NETWORK;
				if (ctrl->localtype == PRI_NETWORK) {
					/* We can't both be networks */
					ev = pri_mkerror(ctrl, "We think we're the network, but they think they're the network, too.");
					break;
				}
			} else {
				ctrl->remotetype = PRI_CPE;
				if (ctrl->localtype == PRI_CPE) {
					/* We can't both be CPE */
					ev = pri_mkerror(ctrl, "We think we're the CPE, but they think they're the CPE too.\n");
					break;
				}
			}
			ev = q921_sabme_rx(link, h);
			break;
		case 0x0C:
			ev = q921_ua_rx(link, h);
			break;
		case 0x11:
			ev = q921_frmr_rx(link, h);
			break;
		case 0x17:
			pri_error(ctrl, "!! XID frames not supported\n");
			break;
		default:
			pri_error(ctrl, "!! Don't know what to do with u-frame (m3=%d, m2=%d)\n",
				h->u.m3, h->u.m2);
			break;
		}
		break;
	}

	q921_statemachine_check(link);

	return ev;
}

static pri_event *q921_handle_unmatched_frame(struct pri *ctrl, q921_h *h, int len)
{
	if (!BRI_NT_PTMP(ctrl)) {
		return NULL;
	}

	if (h->h.tei < Q921_TEI_AUTO_FIRST) {
		if (ctrl->debug & PRI_DEBUG_Q921_STATE) {
			pri_message(ctrl, "Manual TEI range is not supported in NT-PTMP mode. Discarding\n");
		}
		return NULL;
	}

	if (h->h.sapi != Q921_SAPI_CALL_CTRL) {
		if (ctrl->debug & PRI_DEBUG_Q921_STATE) {
			pri_message(ctrl, "Message with SAPI other than CALL CTRL is discarded\n");
		}
		return NULL;
	}

	/* This means an unrecognized TEI that we'll kill */
	if (ctrl->debug & PRI_DEBUG_Q921_STATE) {
		pri_message(ctrl,
			"Could not find a layer 2 link for received frame with SAPI/TEI of %d/%d.\n",
			h->h.sapi, h->h.tei);
		pri_message(ctrl, "Sending TEI release, in order to re-establish TEI state\n");
	}
	q921_tei_remove(ctrl, h->h.tei);

	return NULL;
}

/* This code assumes that the pri structure is the master pri */
static pri_event *__q921_receive(struct pri *ctrl, q921_h *h, int len)
{
	pri_event *ev = NULL;
	struct q921_link *link;

	/* Discard FCS */
	len -= 2;
	
	if (ctrl->debug & (PRI_DEBUG_Q921_DUMP | PRI_DEBUG_Q921_RAW)) {
		q921_dump(ctrl, h, len, ctrl->debug, 0);
	}

	/* Check some reject conditions -- Start by rejecting improper ea's */
	if (h->h.ea1 || !h->h.ea2) {
		return NULL;
	}

	if (h->h.sapi == Q921_SAPI_LAYER2_MANAGEMENT) {
		return q921_mdl_receive(ctrl, &h->u, len);
	}

	if (h->h.tei == Q921_TEI_GROUP && h->h.sapi != Q921_SAPI_CALL_CTRL) {
		pri_error(ctrl, "Do not handle group messages to services other than MDL or CALL CTRL\n");
		return NULL;
	}

	if (BRI_TE_PTMP(ctrl)) {
		/* We're operating on the specific TEI link */
		link = ctrl->link.next;
		if (h->h.sapi == link->sapi
			&& ((link->state >= Q921_TEI_ASSIGNED
				&& h->h.tei == link->tei)
				|| h->h.tei == Q921_TEI_GROUP)) {
			ev = __q921_receive_qualified(link, h, len);
		}
		/* Only support reception on our specific TEI link */
	} else if (BRI_NT_PTMP(ctrl)) {
		link = pri_find_tei(ctrl, h->h.sapi, h->h.tei);
		if (link) {
			ev = __q921_receive_qualified(link, h, len);
		} else {
			ev = q921_handle_unmatched_frame(ctrl, h, len);
		}
	} else if (PTP_MODE(ctrl)
		&& h->h.sapi == ctrl->link.sapi
		&& (h->h.tei == ctrl->link.tei || h->h.tei == Q921_TEI_GROUP)) {
		ev = __q921_receive_qualified(&ctrl->link, h, len);
	} else {
		ev = NULL;
	}

	if (ctrl->debug & PRI_DEBUG_Q921_DUMP) {
		pri_message(ctrl, "Done handling message for SAPI/TEI=%d/%d\n", h->h.sapi, h->h.tei);
	}

	return ev;
}

pri_event *q921_receive(struct pri *ctrl, q921_h *h, int len)
{
	pri_event *e;
	e = __q921_receive(ctrl, h, len);
	ctrl->q921_rxcount++;
	return e;
}

static void q921_establish_data_link(struct q921_link *link)
{
	q921_clear_exception_conditions(link);
	link->RC = 0;
	stop_t203(link);
	reschedule_t200(link);
	q921_send_sabme(link);
}

static void nt_ptmp_dchannel_up(void *vpri)
{
	struct pri *ctrl = vpri;

	ctrl->schedev = 1;
	ctrl->ev.gen.e = PRI_EVENT_DCHAN_UP;
}

void q921_start(struct q921_link *link)
{
	struct pri *ctrl;

	ctrl = link->ctrl;
	if (PTMP_MODE(ctrl)) {
		if (TE_MODE(ctrl)) {
			q921_setstate(link, Q921_ASSIGN_AWAITING_TEI);
			q921_tei_request(link);
		} else {
			q921_setstate(link, Q921_TEI_UNASSIGNED);
			pri_schedule_event(ctrl, 0, nt_ptmp_dchannel_up, ctrl);
			if (!ctrl->link.next) {
				/*
				 * We do not have any TEI's so make sure there are no devices
				 * that think they have a TEI.  A device may think it has a TEI
				 * if the upper layer program is restarted or the system
				 * reboots.
				 */
				q921_tei_remove(ctrl, Q921_TEI_GROUP);
			}
		}
	} else {
		/* PTP mode, no need for TEI management junk */
		q921_establish_data_link(link);
		link->l3_initiated = 1;
		q921_setstate(link, Q921_AWAITING_ESTABLISHMENT);
	}
}

