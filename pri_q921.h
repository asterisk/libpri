/*
 * libpri: An implementation of Primary Rate ISDN
 *
 * Written by Mark Spencer <markster@digium.com>
 *
 * Copyright (C) 2001, Digium, Inc.
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
 
#ifndef _PRI_Q921_H
#define _PRI_Q921_H

#include <sys/types.h>
#if defined(__linux__)
#include <endian.h>
#elif defined(__FreeBSD__)
#include <sys/endian.h>
#define __BYTE_ORDER _BYTE_ORDER
#define __BIG_ENDIAN _BIG_ENDIAN
#define __LITTLE_ENDIAN _LITTLE_ENDIAN
#endif

/* Timer values */

#define T_WAIT_MIN	2000
#define T_WAIT_MAX	10000

#define Q921_FRAMETYPE_MASK	0x3

#define Q921_FRAMETYPE_U	0x3
#define Q921_FRAMETYPE_I	0x0
#define Q921_FRAMETYPE_S	0x1

#define Q921_TEI_GROUP					127
#define Q921_TEI_PRI					0
#define Q921_TEI_GR303_EOC_PATH			0
#define Q921_TEI_GR303_EOC_OPS			4
#define Q921_TEI_GR303_TMC_SWITCHING	0
#define Q921_TEI_GR303_TMC_CALLPROC		0
#define Q921_TEI_AUTO_FIRST				64
#define Q921_TEI_AUTO_LAST				126

#define Q921_SAPI_CALL_CTRL		0
#define Q921_SAPI_GR303_EOC		1
#define Q921_SAPI_GR303_TMC_SWITCHING	1
#define Q921_SAPI_GR303_TMC_CALLPROC	0


#define Q921_SAPI_PACKET_MODE		1
#define Q921_SAPI_X25_LAYER3      	16
#define Q921_SAPI_LAYER2_MANAGEMENT	63


/*! Q.921 TEI management message type */
enum q921_tei_identity {
	Q921_TEI_IDENTITY_REQUEST = 1,
	Q921_TEI_IDENTITY_ASSIGNED = 2,
	Q921_TEI_IDENTITY_DENIED = 3,
	Q921_TEI_IDENTITY_CHECK_REQUEST = 4,
	Q921_TEI_IDENTITY_CHECK_RESPONSE = 5,
	Q921_TEI_IDENTITY_REMOVE = 6,
	Q921_TEI_IDENTITY_VERIFY = 7,
};

typedef struct q921_header {
#if __BYTE_ORDER == __BIG_ENDIAN
	u_int8_t	sapi:6;	/* Service Access Point Indentifier (always 0 for PRI) (0) */
	u_int8_t	c_r:1;		/* Command/Response (0 if CPE, 1 if network) */
	u_int8_t	ea1:1;		/* Extended Address (0) */
	u_int8_t	tei:7;		/* Terminal Endpoint Identifier (0) */
	u_int8_t	ea2:1;		/* Extended Address Bit (1) */
#else	
	u_int8_t	ea1:1;		/* Extended Address (0) */
	u_int8_t	c_r:1;		/* Command/Response (0 if CPE, 1 if network) */
	u_int8_t	sapi:6;	/* Service Access Point Indentifier (always 0 for PRI) (0) */
	u_int8_t	ea2:1;		/* Extended Address Bit (1) */
	u_int8_t	tei:7;		/* Terminal Endpoint Identifier (0) */
#endif
	u_int8_t	data[0];	/* Further data */
} __attribute__ ((packed)) q921_header;

/* A Supervisory Format frame */
typedef struct q921_s {
	struct q921_header h;	/* Header */
#if __BYTE_ORDER == __BIG_ENDIAN
	u_int8_t x0:4;			/* Unused */
	u_int8_t ss:2;			/* Supervisory frame bits */
	u_int8_t ft:2;			/* Frame type bits (01) */
	u_int8_t n_r:7;			/* Number Received */
	u_int8_t p_f:1;			/* Poll/Final bit */
#else	
	u_int8_t ft:2;			/* Frame type bits (01) */
	u_int8_t ss:2;			/* Supervisory frame bits */
	u_int8_t x0:4;			/* Unused */
	u_int8_t p_f:1;			/* Poll/Final bit */
	u_int8_t n_r:7;			/* Number Received */
#endif
	u_int8_t data[0];		/* Any further data */
} __attribute__ ((packed)) q921_s;

/* An Unnumbered Format frame */
typedef struct q921_u {
	struct q921_header h;	/* Header */
#if __BYTE_ORDER == __BIG_ENDIAN
	u_int8_t m3:3;			/* Top 3 modifier bits */
	u_int8_t p_f:1;			/* Poll/Final bit */
	u_int8_t m2:2;			/* Two more modifier bits */
	u_int8_t ft:2;			/* Frame type bits (11) */
#else	
	u_int8_t ft:2;			/* Frame type bits (11) */
	u_int8_t m2:2;			/* Two more modifier bits */
	u_int8_t p_f:1;			/* Poll/Final bit */
	u_int8_t m3:3;			/* Top 3 modifier bits */
#endif
	u_int8_t data[0];		/* Any further data */
} __attribute__ ((packed)) q921_u;

/* An Information frame */
typedef struct q921_i {
	struct q921_header h;	/* Header */
#if __BYTE_ORDER == __BIG_ENDIAN
	u_int8_t n_s:7;			/* Number sent */
	u_int8_t ft:1;			/* Frame type (0) */
	u_int8_t n_r:7;			/* Number received */
	u_int8_t p_f:1;			/* Poll/Final bit */	
#else	
	u_int8_t ft:1;			/* Frame type (0) */
	u_int8_t n_s:7;			/* Number sent */
	u_int8_t p_f:1;			/* Poll/Final bit */	
	u_int8_t n_r:7;			/* Number received */
#endif
	u_int8_t data[0];		/* Any further data */
} q921_i;

typedef union {
	u_int8_t raw[0];
	q921_u u;
	q921_s s;
	q921_i i;
	struct q921_header h;
} q921_h;

enum q921_tx_frame_status {
	Q921_TX_FRAME_NEVER_SENT,
	Q921_TX_FRAME_PUSHED_BACK,
	Q921_TX_FRAME_SENT,
};

typedef struct q921_frame {
	struct q921_frame *next;			/*!< Next in list */
	int len;							/*!< Length of header + body */
	enum q921_tx_frame_status status;	/*!< Tx frame status */
	q921_i h;							/*!< Actual frame contents. */
} q921_frame;

#define Q921_INC(j) (j) = (((j) + 1) % 128)
#define Q921_DEC(j) (j) = (((j) - 1) % 128)

typedef enum q921_state {
	/* All states except Q921_DOWN are defined in Q.921 SDL diagrams */
	Q921_TEI_UNASSIGNED = 1,
	Q921_ASSIGN_AWAITING_TEI = 2,
	Q921_ESTABLISH_AWAITING_TEI = 3,
	Q921_TEI_ASSIGNED = 4,
	Q921_AWAITING_ESTABLISHMENT = 5,
	Q921_AWAITING_RELEASE = 6,
	Q921_MULTI_FRAME_ESTABLISHED = 7,
	Q921_TIMER_RECOVERY = 8,
} q921_state;

/*! TEI identity check procedure states. */
enum q921_tei_check_state {
	/*! Not participating in the TEI check procedure. */
	Q921_TEI_CHECK_NONE,
	/*! No reply to TEI check received. */
	Q921_TEI_CHECK_DEAD,
	/*! Reply to TEI check received in current poll. */
	Q921_TEI_CHECK_REPLY,
	/*! No reply to current TEI check poll received.  A previous poll got a reply. */
	Q921_TEI_CHECK_DEAD_REPLY,
};

/*! \brief Q.921 link controller structure */
struct q921_link {
	/*! Next Q.921 link in the chain. */
	struct q921_link *next;
	/*! D channel controller associated with this link. */
	struct pri *ctrl;

	/*!
	 * \brief Q.931 Dummy call reference call associated with this TEI.
	 *
	 * \note If present then this call is allocated with the D
	 * channel control structure or the link control structure
	 * unless this is the TE PTMP broadcast TEI or a GR303 link.
	 */
	struct q931_call *dummy_call;

	/*! Q.921 Re-transmission queue */
	struct q921_frame *tx_queue;

	/*! Q.921 State */
	enum q921_state state;

	/*! TEI identity check procedure state. */
	enum q921_tei_check_state tei_check;

	/*! Service Access Profile Identifier (SAPI) of this link */
	int sapi;
	/*! Terminal Endpoint Identifier (TEI) of this link */
	int tei;
	/*! TEI assignment random indicator. */
	int ri;

	/*! V(A) - Next I-frame sequence number needing ack */
	int v_a;
	/*! V(S) - Next I-frame sequence number to send */
	int v_s;
	/*! V(R) - Next I-frame sequence number expected to receive */
	int v_r;

	/* Various timers */

	/*! T-200 retransmission timer */
	int t200_timer;
	/*! Retry Count (T200) */
	int RC;
	int t202_timer;
	int n202_counter;
	/*! Max idle time */
	int t203_timer;
	/*! Layer 2 persistence restart delay timer */
	int restart_timer;

	/* MDL variables */
	int mdl_timer;
	int mdl_error;
	unsigned int mdl_free_me:1;

	unsigned int peer_rx_busy:1;
	unsigned int own_rx_busy:1;
	unsigned int acknowledge_pending:1;
	unsigned int reject_exception:1;
	unsigned int l3_initiated:1;
};

static inline int Q921_ADD(int a, int b)
{
	return (a + b) % 128;
}

/* Dumps a *known good* Q.921 packet */
extern void q921_dump(struct pri *pri, q921_h *h, int len, int debugflags, int txrx);

/* Bring up the D-channel */
void q921_start(struct q921_link *link);
void q921_bring_layer2_up(struct pri *ctrl);

//extern void q921_reset(struct pri *pri, int reset_iqueue);

extern pri_event *q921_receive(struct pri *pri, q921_h *h, int len);

int q921_transmit_iframe(struct q921_link *link, void *buf, int len, int cr);

int q921_transmit_uiframe(struct q921_link *link, void *buf, int len);

extern pri_event *q921_dchannel_up(struct pri *pri);

//extern pri_event *q921_dchannel_down(struct pri *pri);

#endif
