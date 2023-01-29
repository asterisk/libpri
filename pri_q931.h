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
 
#ifndef _PRI_Q931_H
#define _PRI_Q931_H

typedef enum q931_mode {
	UNKNOWN_MODE,
	CIRCUIT_MODE,
	PACKET_MODE
} q931_mode;

typedef struct q931_h {
	u_int8_t pd;		/* Protocol Discriminator */
#if __BYTE_ORDER == __BIG_ENDIAN
	u_int8_t x0:4;
	u_int8_t crlen:4;/*!< Call reference length */
#else
	u_int8_t crlen:4;/*!< Call reference length */
	u_int8_t x0:4;
#endif
	u_int8_t contents[0];
	u_int8_t crv[3];/*!< Call reference value */
} __attribute__ ((packed)) q931_h;

typedef union {
  unsigned char raw[0];
  q931_h h;
} q931_union;
  
/* Message type header */
typedef struct q931_mh {
#if __BYTE_ORDER == __BIG_ENDIAN
	u_int8_t f:1;
	u_int8_t msg:7;
#else
	u_int8_t msg:7;
	u_int8_t f:1;
#endif
	u_int8_t data[0];
} __attribute__ ((packed)) q931_mh;

/* Information element format */
typedef struct q931_ie {
	u_int8_t ie;
	u_int8_t len;
	u_int8_t data[0];
} __attribute__ ((packed)) q931_ie;

#define Q931_RES_HAVEEVENT (1 << 0)
#define Q931_RES_INERRROR  (1 << 1)

#define Q931_PROTOCOL_DISCRIMINATOR 0x08
#define GR303_PROTOCOL_DISCRIMINATOR 0x4f
/* AT&T Maintenance Protocol Discriminator */
#define MAINTENANCE_PROTOCOL_DISCRIMINATOR_1 0x03
/* National Maintenance Protocol Discriminator */
#define MAINTENANCE_PROTOCOL_DISCRIMINATOR_2 0x43

/* Q.931 / National ISDN Message Types */

/*! Send this facility APDU on the next message to go out. */
#define Q931_ANY_MESSAGE			-1

/* Call Establishment Messages */
#define Q931_ALERTING 				0x01
#define Q931_CALL_PROCEEDING		0x02
#define Q931_CONNECT				0x07
#define Q931_CONNECT_ACKNOWLEDGE	0x0f
#define Q931_PROGRESS				0x03
#define Q931_SETUP					0x05
#define Q931_SETUP_ACKNOWLEDGE		0x0d

/* Call Disestablishment Messages */
#define Q931_DISCONNECT				0x45
#define Q931_RELEASE				0x4d
#define Q931_RELEASE_COMPLETE		0x5a
#define Q931_RESTART				0x46
#define Q931_RESTART_ACKNOWLEDGE	0x4e

/* Miscellaneous Messages */
#define Q931_STATUS					0x7d
#define Q931_STATUS_ENQUIRY			0x75
#define Q931_USER_INFORMATION		0x20
#define Q931_SEGMENT				0x60
#define Q931_CONGESTION_CONTROL		0x79
#define Q931_INFORMATION			0x7b
#define Q931_FACILITY				0x62
#define Q931_REGISTER				0x64	/* Q.932 */
#define Q931_NOTIFY					0x6e

/* Call Management Messages */
#define Q931_HOLD					0x24
#define Q931_HOLD_ACKNOWLEDGE		0x28
#define Q931_HOLD_REJECT			0x30
#define Q931_RETRIEVE				0x31
#define Q931_RETRIEVE_ACKNOWLEDGE	0x33
#define Q931_RETRIEVE_REJECT		0x37
#define Q931_RESUME					0x26
#define Q931_RESUME_ACKNOWLEDGE		0x2e
#define Q931_RESUME_REJECT			0x22
#define Q931_SUSPEND				0x25
#define Q931_SUSPEND_ACKNOWLEDGE	0x2d
#define Q931_SUSPEND_REJECT			0x21

/* Maintenance messages (codeset 0 only) */
#define ATT_SERVICE                 0x0f
#define ATT_SERVICE_ACKNOWLEDGE     0x07
#define NATIONAL_SERVICE            0x07
#define NATIONAL_SERVICE_ACKNOWLEDGE 0x0f

#define SERVICE_CHANGE_STATUS_INSERVICE           0
#define SERVICE_CHANGE_STATUS_LOOPBACK            1  /* not supported */
#define SERVICE_CHANGE_STATUS_OUTOFSERVICE        2
#define SERVICE_CHANGE_STATUS_REQCONTINUITYCHECK  3  /* not supported */
#define SERVICE_CHANGE_STATUS_SHUTDOWN            4  /* not supported */

/* Q.931 / National ISDN Information Elements */
#define Q931_LOCKING_SHIFT			0x90
#define Q931_NON_LOCKING_SHIFT		0x98
#define Q931_BEARER_CAPABILITY		0x04
#define Q931_CAUSE					0x08
#define Q931_IE_CALL_STATE			0x14
#define Q931_CHANNEL_IDENT			0x18
#define Q931_PROGRESS_INDICATOR		0x1e
#define Q931_NETWORK_SPEC_FAC		0x20
#define Q931_CALLING_PARTY_CATEGORY	(0x32 | Q931_CODESET(5))
#define Q931_INFORMATION_RATE		0x40
#define Q931_TRANSIT_DELAY			0x42
#define Q931_TRANS_DELAY_SELECT		0x43
#define Q931_BINARY_PARAMETERS		0x44
#define Q931_WINDOW_SIZE			0x45
#define Q931_PACKET_SIZE			0x46
#define Q931_CLOSED_USER_GROUP		0x47
#define Q931_REVERSE_CHARGE_INDIC	0x4a
#define Q931_CALLING_PARTY_NUMBER	0x6c
#define Q931_CALLING_PARTY_SUBADDR	0x6d
#define Q931_CALLED_PARTY_NUMBER	0x70
#define Q931_CALLED_PARTY_SUBADDR	0x71
#define Q931_REDIRECTING_NUMBER		0x74
#define Q931_REDIRECTING_SUBADDR	0x75
#define Q931_TRANSIT_NET_SELECT		0x78
#define Q931_RESTART_INDICATOR		0x79
#define Q931_LOW_LAYER_COMPAT		0x7c
#define Q931_HIGH_LAYER_COMPAT		0x7d

#define Q931_CODESET(x)			((x) << 8)
#define Q931_IE_CODESET(x)		((x) >> 8)
#define Q931_IE_IE(x)			((x) & 0xff)
#define Q931_FULL_IE(codeset, ie)	(((codeset) << 8) | ((ie) & 0xff))

#define Q931_DISPLAY					0x28
#define Q931_IE_SEGMENTED_MSG			0x00
#define Q931_IE_CHANGE_STATUS			0x01
#define Q931_IE_ORIGINATING_LINE_INFO		(0x01 | Q931_CODESET(6))
#define Q931_IE_CONNECTED_ADDR			0x0c
#define Q931_IE_CONNECTED_NUM			0x4c
#define Q931_IE_CONNECTED_SUBADDR		0x4d
#define Q931_IE_CALL_IDENTITY			0x10
#define Q931_IE_FACILITY				0x1c
#define Q931_IE_ENDPOINT_ID				0x26
#define Q931_IE_NOTIFY_IND				0x27
#define Q931_IE_TIME_DATE				0x29
#define Q931_IE_KEYPAD_FACILITY			0x2c
#define Q931_IE_CALL_STATUS				0x2d
#define Q931_IE_UPDATE                  0x31
#define Q931_IE_INFO_REQUEST            0x32
#define Q931_IE_SIGNAL					0x34
#define Q931_IE_SWITCHHOOK				0x36
#define Q931_IE_GENERIC_DIGITS			(0x37 | Q931_CODESET(6))
#define Q931_IE_FEATURE_ACTIVATE		0x38
#define Q931_IE_FEATURE_IND				0x39
#define Q931_IE_ORIGINAL_CALLED_NUMBER 	0x73
#define Q931_IE_REDIRECTION_NUMBER		0x76
#define Q931_IE_REDIRECTION_SUBADDR		0x77
#define Q931_IE_USER_USER_FACILITY		0x7A
#define Q931_IE_USER_USER				0x7E
#define Q931_IE_ESCAPE_FOR_EXT			0x7F


/*! Q.931 call states */
enum Q931_CALL_STATE {
	/*!
	 * \details
	 *   null state (U0):
	 *     No call exists.
	 * \details
	 *   null state (N0):
	 *     No call exists.
	 */
	Q931_CALL_STATE_NULL = 0,
	/*!
	 * \details
	 *   call initiated (U1):
	 *     This state exists for an outgoing call, when the user requests
	 *     call establishment from the network.
	 * \details
	 *   call initiated (N1):
	 *     This state exists for an outgoing call when the network has received
	 *     a call establishment request but has not yet responded.
	 */
	Q931_CALL_STATE_CALL_INITIATED = 1,
	/*!
	 * \details
	 *   overlap sending (U2):
	 *     This state exists for an outgoing call when the user has
	 *     received acknowledgement of the call establishment request which
	 *     permits the user to send additional call information to the network
	 *     in overlap mode.
	 * \details
	 *   overlap sending (N2):
	 *     This state exists for an outgoing call when the network has acknowledged
	 *     the call establishment request and is prepared to receive additional
	 *     call information (if any) in overlap mode.
	 */
	Q931_CALL_STATE_OVERLAP_SENDING = 2,
	/*!
	 * \details
	 *   outgoing call proceeding (U3):
	 *     This state exists for an outgoing call when the user has
	 *     received acknowledgement that the network has received all
	 *     call information necessary to effect call establishment.
	 * \details
	 *   outgoing call proceeding (N3):
	 *     This state exists for an outgoing call when the network has sent
	 *     acknowledgement that the network has received all call information
	 *     necessary to effect call establishment.
	 */
	Q931_CALL_STATE_OUTGOING_CALL_PROCEEDING = 3,
	/*!
	 * \details
	 *   call delivered (U4):
	 *     This state exists for an outgoing call when the calling user has
	 *     received an indication that remote user alerting has been initiated.
	 * \details
	 *   call delivered (N4):
	 *     This state exists for an outgoing call when the network has indicated
	 *     that remote user alerting has been initiated.
	 */
	Q931_CALL_STATE_CALL_DELIVERED = 4,
	/*!
	 * \details
	 *   call present (U6):
	 *     This state exists for an incoming call when the user has received a
	 *     call establishment request but has not yet responded.
	 * \details
	 *   call present (N6):
	 *     This state exists for an incoming call when the network has sent a
	 *     call establishment request but has not yet received a satisfactory
	 *     response.
	 */
	Q931_CALL_STATE_CALL_PRESENT = 6,
	/*!
	 * \details
	 *   call received (U7):
	 *     This state exists for an incoming call when the user has indicated
	 *     alerting but has not yet answered.
	 * \details
	 *   call received (N7):
	 *     This state exists for an incoming call when the network has received
	 *     an indication that the user is alerting but has not yet received an
	 *     answer.
	 */
	Q931_CALL_STATE_CALL_RECEIVED = 7,
	/*!
	 * \details
	 *   connect request (U8):
	 *     This state exists for an incoming call when the user has answered
	 *     the call and is waiting to be awarded the call.
	 * \details
	 *   connect request (N8):
	 *     This state exists for an incoming call when the network has received
	 *     an answer but the network has not yet awarded the call.
	 */
	Q931_CALL_STATE_CONNECT_REQUEST = 8,
	/*!
	 * \details
	 *   incoming call proceeding (U9):
	 *     This state exists for an incoming call when the user has sent
	 *     acknowledgement that the user has received all call information
	 *     necessary to effect call establishment.
	 * \details
	 *   incoming call proceeding (N9):
	 *     This state exists for an incoming call when the network has received
	 *     acknowledgement that the user has received all call information
	 *     necessary to effect call establishment.
	 */
	Q931_CALL_STATE_INCOMING_CALL_PROCEEDING = 9,
	/*!
	 * \details
	 *   active (U10):
	 *     This state exists for an incoming call when the user has received
	 *     an acknowledgement from the network that the user has been awarded
	 *     the call. This state exists for an outgoing call when the user has
	 *     received an indication that the remote user has answered the call.
	 * \details
	 *   active (N10):
	 *     This state exists for an incoming call when the network has awarded
	 *     the call to the called user. This state exists for an outgoing call
	 *     when the network has indicated that the remote user has answered
	 *     the call.
	 */
	Q931_CALL_STATE_ACTIVE = 10,
	/*!
	 * \details
	 *   disconnect request (U11):
	 *     This state exists when the user has requested the network to clear
	 *     the end-to-end connection (if any) and is waiting for a response.
	 * \details
	 *   disconnect request (N11):
	 *     This state exists when the network has received a request from the
	 *     user to clear the end-to-end connection (if any).
	 */
	Q931_CALL_STATE_DISCONNECT_REQUEST = 11,
	/*!
	 * \details
	 *   disconnect indication (U12):
	 *     This state exists when the user has received an invitation to
	 *     disconnect because the network has disconnected the end-to-end
	 *     connection (if any).
	 * \details
	 *   disconnect indication (N12):
	 *     This state exists when the network has disconnected the end-to-end
	 *     connection (if any) and has sent an invitation to disconnect the
	 *     user-network connection.
	 */
	Q931_CALL_STATE_DISCONNECT_INDICATION = 12,
	/*!
	 * \details
	 *   suspend request (U15):
	 *     This state exists when the user has requested the network to suspend
	 *     the call and is waiting for a response.
	 * \details
	 *   suspend request (N15):
	 *     This state exists when the network has received a request to suspend
	 *     the call but has not yet responded.
	 */
	Q931_CALL_STATE_SUSPEND_REQUEST = 15,
	/*!
	 * \details
	 *   resume request (U17):
	 *     This state exists when the user has requested the network to resume
	 *     a previously suspended call and is waiting for a response.
	 * \details
	 *   resume request (N17):
	 *     This state exists when the network has received a request to resume
	 *     a previously suspended call but has not yet responded.
	 */
	Q931_CALL_STATE_RESUME_REQUEST = 17,
	/*!
	 * \details
	 *   release request (U19):
	 *     This state exists when the user has requested the network to release
	 *     and is waiting for a response.
	 * \details
	 *   release request (N19):
	 *     This state exists when the network has requested the user to release
	 *     and is waiting for a response.
	 */
	Q931_CALL_STATE_RELEASE_REQUEST = 19,
	/*!
	 * \details
	 *   call abort (N22):
	 *     This state exists for an incoming call for the point-to-multipoint
	 *     configuration when the call is being cleared before any user has been
	 *     awarded the call.
	 */
	Q931_CALL_STATE_CALL_ABORT = 22,
	/*!
	 * \details
	 *   overlap receiving (U25):
	 *     This state exists for an incoming call when the user has acknowledged
	 *     the call establishment request from the network and is prepared to
	 *     receive additional call information (if any) in overlap mode.
	 * \details
	 *   overlap receiving (N25):
	 *     This state exists for an incoming call when the network has received
	 *     acknowledgement of the call establishment request which permits the
	 *     network to send additional call information (if any) in the overlap
	 *     mode.
	 */
	Q931_CALL_STATE_OVERLAP_RECEIVING = 25,
	/*!
	 * \details
	 *   call independent service (U31): (From Q.932)
	 *     This state exists when a call independent supplementary service
	 *     signalling connection is established.
	 * \details
	 *   call independent service (N31): (From Q.932)
	 *     This state exists when a call independent supplementary service
	 *     signalling connection is established.
	 */
	Q931_CALL_STATE_CALL_INDEPENDENT_SERVICE = 31,
	Q931_CALL_STATE_RESTART_REQUEST = 61,
	Q931_CALL_STATE_RESTART = 62,
	/*!
	 * \details
	 * Call state has not been set.
	 * Call state does not exist.
	 * Call state not initialized.
	 * Call state internal use only.
	 */
	Q931_CALL_STATE_NOT_SET = 0xFF,
};

/*! Q.931 call establishment state ranking for competing calls in PTMP NT mode. */
enum Q931_RANKED_CALL_STATE {
	/*! Call is present but has no response yet. */
	Q931_RANKED_CALL_STATE_PRESENT,
	/*! Call is collecting digits. */
	Q931_RANKED_CALL_STATE_OVERLAP,
	/*! Call routing is happening. */
	Q931_RANKED_CALL_STATE_PROCEEDING,
	/*! Called party is being alerted of the call. */
	Q931_RANKED_CALL_STATE_ALERTING,
	/*! Call is connected.  A winner has been declared. */
	Q931_RANKED_CALL_STATE_CONNECT,
	/*! Call is in some non-call establishment state (likely disconnecting). */
	Q931_RANKED_CALL_STATE_OTHER,
	/*! Master call is aborting. */
	Q931_RANKED_CALL_STATE_ABORT,
};

/* EuroISDN  */
#define Q931_SENDING_COMPLETE		0xa1

extern int maintenance_service(struct pri *pri, int span, int channel, int changestatus);


/* Q.SIG specific */
#define QSIG_IE_TRANSIT_COUNT		0x31

int q931_receive(struct q921_link *link, q931_h *h, int len);

extern int q931_alerting(struct pri *pri, q931_call *call, int channel, int info);

extern int q931_call_progress_with_cause(struct pri *pri, q931_call *call, int channel, int info, int cause);

extern int q931_call_progress(struct pri *pri, q931_call *call, int channel, int info);

extern int q931_notify(struct pri *pri, q931_call *call, int channel, int info);

extern int q931_call_proceeding(struct pri *pri, q931_call *call, int channel, int info);

extern int q931_setup_ack(struct pri *ctrl, q931_call *c, int channel, int nonisdn, int inband);

extern int q931_information(struct pri *pri, q931_call *call, char digit);

extern int q931_keypad_facility(struct pri *pri, q931_call *call, const char *digits);

extern int q931_connect(struct pri *pri, q931_call *call, int channel, int nonisdn);
int q931_connect_acknowledge(struct pri *ctrl, q931_call *call, int channel);

extern int q931_release(struct pri *pri, q931_call *call, int cause);

extern int q931_disconnect(struct pri *pri, q931_call *call, int cause);

extern int q931_hangup(struct pri *pri, q931_call *call, int cause);

extern int q931_restart(struct pri *pri, int channel);

extern int q931_facility(struct pri *pri, q931_call *call);

extern int q931_call_getcrv(struct pri *pri, q931_call *call, int *callmode);

extern int q931_call_setcrv(struct pri *pri, q931_call *call, int crv, int callmode);

struct q931_call *q931_new_call(struct pri *ctrl);

extern int q931_setup(struct pri *pri, q931_call *c, struct pri_sr *req);

int q931_register(struct pri *ctrl, q931_call *call);

void q931_dump(struct pri *ctrl, int tei, q931_h *h, int len, int txrx);

void q931_destroycall(struct pri *pri, q931_call *c);

enum Q931_DL_EVENT {
	Q931_DL_EVENT_NONE,
	Q931_DL_EVENT_DL_ESTABLISH_IND,
	Q931_DL_EVENT_DL_ESTABLISH_CONFIRM,
	Q931_DL_EVENT_DL_RELEASE_IND,
	Q931_DL_EVENT_DL_RELEASE_CONFIRM,
	Q931_DL_EVENT_TEI_REMOVAL,
};
void q931_dl_event(struct q921_link *link, enum Q931_DL_EVENT event);

int q931_send_hold(struct pri *ctrl, struct q931_call *call);
int q931_send_hold_ack(struct pri *ctrl, struct q931_call *call);
int q931_send_hold_rej(struct pri *ctrl, struct q931_call *call, int cause);

int q931_send_retrieve(struct pri *ctrl, struct q931_call *call, int channel);
int q931_send_retrieve_ack(struct pri *ctrl, struct q931_call *call, int channel);
int q931_send_retrieve_rej(struct pri *ctrl, struct q931_call *call, int cause);

#endif
