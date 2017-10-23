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

#include "compat.h"
#include "libpri.h"
#include "pri_internal.h"
#include "pri_facility.h"

#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <limits.h>

enum mandatory_ie_status {
	MAND_STATUS_OK,
	MAND_STATUS_CONTENT_ERROR,
	MAND_STATUS_MISSING,
};

#define MAX_MAND_IES 10

struct msgtype {
	int msgnum;
	char *name;
	int mandies[MAX_MAND_IES];
};

static struct msgtype msgs[] = {
	/* Call establishment messages */
	{ Q931_ALERTING, "ALERTING", { Q931_CHANNEL_IDENT } },
	{ Q931_CALL_PROCEEDING, "CALL PROCEEDING", { Q931_CHANNEL_IDENT } },
	{ Q931_CONNECT, "CONNECT", { Q931_CHANNEL_IDENT } },
	{ Q931_CONNECT_ACKNOWLEDGE, "CONNECT ACKNOWLEDGE" },
	/*
	 * Very early in libpri SVN history (SVN -r154) a change was explicitly
	 * made to not care about a missing Progress Indicator ie.  There is no
	 * explanation in the commit message why this was done even though
	 * Q.931 and ECMA-143 clearly show that the ie is mandatory for a
	 * PROGRESS message.
	 *
	 * Hazzarding a guess, I think it was because of the
	 * ALERTING_NO_PROGRESS support for Mitel switches.  (SVN -r44)
	 */
#ifdef ALERTING_NO_PROGRESS
	{ Q931_PROGRESS, "PROGRESS" },
#else
	{ Q931_PROGRESS, "PROGRESS", { Q931_PROGRESS_INDICATOR } },
#endif
	{ Q931_SETUP, "SETUP", { Q931_BEARER_CAPABILITY, Q931_CHANNEL_IDENT } },
	{ Q931_SETUP_ACKNOWLEDGE, "SETUP ACKNOWLEDGE", { Q931_CHANNEL_IDENT } },
	
	/* Call disestablishment messages */
	{ Q931_DISCONNECT, "DISCONNECT", { Q931_CAUSE } },
	{ Q931_RELEASE, "RELEASE" },
	{ Q931_RELEASE_COMPLETE, "RELEASE COMPLETE" },
	{ Q931_RESTART, "RESTART", { Q931_RESTART_INDICATOR } },
	{ Q931_RESTART_ACKNOWLEDGE, "RESTART ACKNOWLEDGE", { Q931_RESTART_INDICATOR } },

	/* Miscellaneous */
	{ Q931_STATUS, "STATUS", { Q931_CAUSE, Q931_IE_CALL_STATE } },
	{ Q931_STATUS_ENQUIRY, "STATUS ENQUIRY" },
	{ Q931_USER_INFORMATION, "USER_INFORMATION" },
	{ Q931_SEGMENT, "SEGMENT" },
	{ Q931_CONGESTION_CONTROL, "CONGESTION CONTROL" },
	{ Q931_INFORMATION, "INFORMATION" },
	{ Q931_FACILITY, "FACILITY" },
	{ Q931_REGISTER, "REGISTER" },
	{ Q931_NOTIFY, "NOTIFY", { Q931_IE_NOTIFY_IND } },

	/* Call Management */
	{ Q931_HOLD, "HOLD" },
	{ Q931_HOLD_ACKNOWLEDGE, "HOLD ACKNOWLEDGE" },
	{ Q931_HOLD_REJECT, "HOLD REJECT", { Q931_CAUSE } },
	{ Q931_RETRIEVE, "RETRIEVE" },
	{ Q931_RETRIEVE_ACKNOWLEDGE, "RETRIEVE ACKNOWLEDGE" },
	{ Q931_RETRIEVE_REJECT, "RETRIEVE REJECT", { Q931_CAUSE } },
	{ Q931_RESUME, "RESUME" },
	{ Q931_RESUME_ACKNOWLEDGE, "RESUME ACKNOWLEDGE", { Q931_CHANNEL_IDENT } },
	{ Q931_RESUME_REJECT, "RESUME REJECT", { Q931_CAUSE } },
	{ Q931_SUSPEND, "SUSPEND" },
	{ Q931_SUSPEND_ACKNOWLEDGE, "SUSPEND ACKNOWLEDGE" },
	{ Q931_SUSPEND_REJECT, "SUSPEND REJECT" },

	{ Q931_ANY_MESSAGE, "ANY MESSAGE" },
};

static int post_handle_q931_message(struct pri *ctrl, struct q931_mh *mh, struct q931_call *c, enum mandatory_ie_status mand_status);
static void nt_ptmp_handle_q931_message(struct pri *ctrl, struct q931_mh *mh, struct q931_call *c, int *allow_event, int *allow_posthandle);

struct msgtype att_maintenance_msgs[] = {
	{ ATT_SERVICE, "SERVICE", { Q931_CHANNEL_IDENT } },
	{ ATT_SERVICE_ACKNOWLEDGE, "SERVICE ACKNOWLEDGE", { Q931_CHANNEL_IDENT } },
};

struct msgtype national_maintenance_msgs[] = {
	{ NATIONAL_SERVICE, "SERVICE", { Q931_CHANNEL_IDENT } },
	{ NATIONAL_SERVICE_ACKNOWLEDGE, "SERVICE ACKNOWLEDGE", { Q931_CHANNEL_IDENT } },
};
static int post_handle_maintenance_message(struct pri *ctrl, int protodisc, struct q931_mh *mh, struct q931_call *c);

static struct msgtype causes[] = {
	{ PRI_CAUSE_UNALLOCATED, "Unallocated (unassigned) number" },
	{ PRI_CAUSE_NO_ROUTE_TRANSIT_NET, "No route to specified transmit network" },
	{ PRI_CAUSE_NO_ROUTE_DESTINATION, "No route to destination" },
	{ PRI_CAUSE_CHANNEL_UNACCEPTABLE, "Channel unacceptable" },
	{ PRI_CAUSE_CALL_AWARDED_DELIVERED, "Call awarded and being delivered in an established channel" },
	{ PRI_CAUSE_NORMAL_CLEARING, "Normal Clearing" },
	{ PRI_CAUSE_USER_BUSY, "User busy" },
	{ PRI_CAUSE_NO_USER_RESPONSE, "No user responding" },
	{ PRI_CAUSE_NO_ANSWER, "User alerting, no answer" },
	{ PRI_CAUSE_CALL_REJECTED, "Call Rejected" },
	{ PRI_CAUSE_NUMBER_CHANGED, "Number changed" },
	{ PRI_CAUSE_NONSELECTED_USER_CLEARING, "Non-selected user clearing" },
	{ PRI_CAUSE_DESTINATION_OUT_OF_ORDER, "Destination out of order" },
	{ PRI_CAUSE_INVALID_NUMBER_FORMAT, "Invalid number format" },
	{ PRI_CAUSE_FACILITY_REJECTED, "Facility rejected" },
	{ PRI_CAUSE_RESPONSE_TO_STATUS_ENQUIRY, "Response to STATus ENQuiry" },
	{ PRI_CAUSE_NORMAL_UNSPECIFIED, "Normal, unspecified" },
	{ PRI_CAUSE_NORMAL_CIRCUIT_CONGESTION, "Circuit/channel congestion" },
	{ PRI_CAUSE_NETWORK_OUT_OF_ORDER, "Network out of order" },
	{ PRI_CAUSE_NORMAL_TEMPORARY_FAILURE, "Temporary failure" },
	{ PRI_CAUSE_SWITCH_CONGESTION, "Switching equipment congestion" },
	{ PRI_CAUSE_ACCESS_INFO_DISCARDED, "Access information discarded" },
	{ PRI_CAUSE_REQUESTED_CHAN_UNAVAIL, "Requested channel not available" },
	{ PRI_CAUSE_PRE_EMPTED, "Pre-empted" },
	{ PRI_CAUSE_RESOURCE_UNAVAIL_UNSPECIFIED, "Resource unavailable, unspecified" },
	{ PRI_CAUSE_FACILITY_NOT_SUBSCRIBED, "Facility not subscribed" },
	{ PRI_CAUSE_OUTGOING_CALL_BARRED, "Outgoing call barred" },
	{ PRI_CAUSE_INCOMING_CALL_BARRED, "Incoming call barred" },
	{ PRI_CAUSE_BEARERCAPABILITY_NOTAUTH, "Bearer capability not authorized" },
	{ PRI_CAUSE_BEARERCAPABILITY_NOTAVAIL, "Bearer capability not available" },
	{ PRI_CAUSE_SERVICEOROPTION_NOTAVAIL, "Service or option not available, unspecified" },
	{ PRI_CAUSE_BEARERCAPABILITY_NOTIMPL, "Bearer capability not implemented" },
	{ PRI_CAUSE_CHAN_NOT_IMPLEMENTED, "Channel not implemented" },
	{ PRI_CAUSE_FACILITY_NOT_IMPLEMENTED, "Facility not implemented" },
	{ PRI_CAUSE_INVALID_CALL_REFERENCE, "Invalid call reference value" },
	{ PRI_CAUSE_IDENTIFIED_CHANNEL_NOTEXIST, "Identified channel does not exist" },
	{ PRI_CAUSE_INCOMPATIBLE_DESTINATION, "Incompatible destination" },
	{ PRI_CAUSE_INVALID_MSG_UNSPECIFIED, "Invalid message unspecified" },
	{ PRI_CAUSE_MANDATORY_IE_MISSING, "Mandatory information element is missing" },
	{ PRI_CAUSE_MESSAGE_TYPE_NONEXIST, "Message type nonexist." },
	{ PRI_CAUSE_WRONG_MESSAGE, "Wrong message" },
	{ PRI_CAUSE_IE_NONEXIST, "Info. element nonexist or not implemented" },
	{ PRI_CAUSE_INVALID_IE_CONTENTS, "Invalid information element contents" },
	{ PRI_CAUSE_WRONG_CALL_STATE, "Message not compatible with call state" },
	{ PRI_CAUSE_RECOVERY_ON_TIMER_EXPIRE, "Recover on timer expiry" },
	{ PRI_CAUSE_MANDATORY_IE_LENGTH_ERROR, "Mandatory IE length error" },
	{ PRI_CAUSE_PROTOCOL_ERROR, "Protocol error, unspecified" },
	{ PRI_CAUSE_INTERWORKING, "Interworking, unspecified" },
};

static struct msgtype facilities[] = {
       { PRI_NSF_SID_PREFERRED, "CPN (SID) preferred" },
       { PRI_NSF_ANI_PREFERRED, "BN (ANI) preferred" },
       { PRI_NSF_SID_ONLY, "CPN (SID) only" },
       { PRI_NSF_ANI_ONLY, "BN (ANI) only" },
       { PRI_NSF_CALL_ASSOC_TSC, "Call Associated TSC" },
       { PRI_NSF_NOTIF_CATSC_CLEARING, "Notification of CATSC Clearing or Resource Unavailable" },
       { PRI_NSF_OPERATOR, "Operator" },
       { PRI_NSF_PCCO, "Pre-subscribed Common Carrier Operator (PCCO)" },
       { PRI_NSF_SDN, "SDN (including GSDN)" },
       { PRI_NSF_TOLL_FREE_MEGACOM, "Toll Free MEGACOM" },
       { PRI_NSF_MEGACOM, "MEGACOM" },
       { PRI_NSF_ACCUNET, "ACCUNET Switched Digital Service" },
       { PRI_NSF_LONG_DISTANCE_SERVICE, "Long Distance Service" },
       { PRI_NSF_INTERNATIONAL_TOLL_FREE, "International Toll Free Service" },
       { PRI_NSF_ATT_MULTIQUEST, "AT&T MultiQuest" },
       { PRI_NSF_CALL_REDIRECTION_SERVICE, "Call Redirection Service" }
};

#define FLAG_WHOLE_INTERFACE	0x01
#define FLAG_PREFERRED			0x02
#define FLAG_EXCLUSIVE			0x04

#define RESET_INDICATOR_CHANNEL	0
#define RESET_INDICATOR_DS1		6
#define RESET_INDICATOR_PRI		7

#define TRANS_MODE_64_CIRCUIT	0x10
#define TRANS_MODE_2x64_CIRCUIT	0x11
#define TRANS_MODE_384_CIRCUIT	0x13
#define TRANS_MODE_1536_CIRCUIT	0x15
#define TRANS_MODE_1920_CIRCUIT	0x17
#define TRANS_MODE_MULTIRATE	0x18
#define TRANS_MODE_PACKET		0x40

#define RATE_ADAPT_56K			0x0f

#define LAYER_2_LAPB			0x46

#define LAYER_3_X25				0x66

/* The 4ESS uses a different audio field */
#define PRI_TRANS_CAP_AUDIO_4ESS	0x08

/* Don't forget to update PRI_PROG_xxx at libpri.h */
#define Q931_PROG_CALL_NOT_E2E_ISDN						0x01
#define Q931_PROG_CALLED_NOT_ISDN						0x02
#define Q931_PROG_CALLER_NOT_ISDN						0x03
#define Q931_PROG_CALLER_RETURNED_TO_ISDN					0x04
#define Q931_PROG_INBAND_AVAILABLE						0x08
#define Q931_PROG_DELAY_AT_INTERF						0x0a
#define Q931_PROG_INTERWORKING_WITH_PUBLIC				0x10
#define Q931_PROG_INTERWORKING_NO_RELEASE				0x11
#define Q931_PROG_INTERWORKING_NO_RELEASE_PRE_ANSWER	0x12
#define Q931_PROG_INTERWORKING_NO_RELEASE_POST_ANSWER	0x13

#define CODE_CCITT					0x0
#define CODE_INTERNATIONAL 			0x1
#define CODE_NATIONAL 				0x2
#define CODE_NETWORK_SPECIFIC		0x3

#define LOC_USER					0x0
#define LOC_PRIV_NET_LOCAL_USER		0x1
#define LOC_PUB_NET_LOCAL_USER		0x2
#define LOC_TRANSIT_NET				0x3
#define LOC_PUB_NET_REMOTE_USER		0x4
#define LOC_PRIV_NET_REMOTE_USER	0x5
#define LOC_INTERNATIONAL_NETWORK	0x7
#define LOC_NETWORK_BEYOND_INTERWORKING	0xa

static char *ie2str(int ie);


#define FUNC_DUMP(name) void (name)(int full_ie, struct pri *pri, q931_ie *ie, int len, char prefix)
#define FUNC_RECV(name) int (name)(int full_ie, struct pri *pri, q931_call *call, int msgtype, q931_ie *ie, int len)
#define FUNC_SEND(name) int (name)(int full_ie, struct pri *pri, q931_call *call, int msgtype, q931_ie *ie, int len, int order)

#if 1
/* Update call state with transition trace. */
#define UPDATE_OURCALLSTATE(ctrl, call, newstate) \
	do { \
		if (((ctrl)->debug & PRI_DEBUG_Q931_STATE) && (call)->ourcallstate != (newstate)) { \
			pri_message((ctrl), \
				DBGHEAD "%s %d enters state %d (%s).  Hold state: %s\n", \
				DBGINFO, ((call) == (call)->master_call) ? "Call" : "Subcall", \
				(call)->cr, (newstate), q931_call_state_str(newstate), \
				q931_hold_state_str((call)->master_call->hold_state)); \
		} \
		(call)->ourcallstate = (newstate); \
	} while (0)
#else
/* Update call state with no trace. */
#define UPDATE_OURCALLSTATE(ctrl, call, newstate) (call)->ourcallstate = (newstate)
#endif

#if 1
/* Update hold state with transition trace. */
#define UPDATE_HOLD_STATE(ctrl, master_call, newstate) \
	do { \
		if (((ctrl)->debug & PRI_DEBUG_Q931_STATE) \
			&& (master_call)->hold_state != (newstate)) { \
			pri_message((ctrl), \
				DBGHEAD "Call %d in state %d (%s) enters Hold state: %s\n", \
				DBGINFO, (master_call)->cr, (master_call)->ourcallstate, \
				q931_call_state_str((master_call)->ourcallstate), \
				q931_hold_state_str(newstate)); \
		} \
		(master_call)->hold_state = (newstate); \
	} while (0)
#else
/* Update hold state with no trace. */
#define UPDATE_HOLD_STATE(ctrl, master_call, newstate) (master_call)->hold_state = (newstate)
#endif

struct ie {
	/* Maximal count of same IEs at the message (0 - any, 1..n - limited) */
	int max_count;
	/* IE code */
	int ie;
	/* IE friendly name */
	char *name;
	/* Dump an IE for debugging (preceed all lines by prefix) */
	FUNC_DUMP(*dump);
	/* Handle IE  returns 0 on success, -1 on failure */
	FUNC_RECV(*receive);
	/* Add IE to a message, return the # of bytes added or -1 on failure */
	FUNC_SEND(*transmit);
};

/*!
 * \internal
 * \brief Encode the channel id information to pass to upper level.
 *
 * \param call Q.931 call leg
 *
 * \return Encoded channel value.
 */
static int q931_encode_channel(const q931_call *call)
{
	int held_call;
	int channelno;
	int ds1no;

	switch (call->master_call->hold_state) {
	case Q931_HOLD_STATE_CALL_HELD:
	case Q931_HOLD_STATE_RETRIEVE_REQ:
	case Q931_HOLD_STATE_RETRIEVE_IND:
		held_call = 1 << 18;
		break;
	default:
		held_call = 0;
		break;
	}
	if (held_call || call->cis_call) {
		/* So a -1 does not wipe out the held_call or cis_call flags. */
		channelno = call->channelno & 0xFF;
		ds1no = call->ds1no & 0xFF;
	} else {
		channelno = call->channelno;
		ds1no = call->ds1no;
	}
	return channelno | (ds1no << 8) | (call->ds1explicit << 16) | (call->cis_call << 17)
		| held_call;
}

/*!
 * \brief Check if the given call ptr is valid.
 *
 * \param ctrl D channel controller.
 * \param call Q.931 call leg.
 *
 * \retval TRUE if call ptr is valid.
 * \retval FALSE if call ptr is invalid.
 */
int q931_is_call_valid(struct pri *ctrl, struct q931_call *call)
{
	struct q931_call *cur;
	struct q921_link *link;
	int idx;

	if (!call) {
		return 0;
	}

	if (!ctrl) {
		/* Must use suspect ctrl from call ptr. */
		if (!call->pri) {
			/* Definitely a bad call pointer. */
			return 0;
		}
		ctrl = call->pri;
	}

	/* Check real call records. */
	for (cur = *ctrl->callpool; cur; cur = cur->next) {
		if (call == cur) {
			/* Found it. */
			return 1;
		}
		if (cur->outboundbroadcast) {
			/* Check subcalls for call ptr. */
			for (idx = 0; idx < ARRAY_LEN(cur->subcalls); ++idx) {
				if (call == cur->subcalls[idx]) {
					/* Found it. */
					return 1;
				}
			}
		}
	}

	/* Check dummy call records. */
	for (link = &ctrl->link; link; link = link->next) {
		if (link->dummy_call == call) {
			/* Found it. */
			return 1;
		}
	}

	/* Well it looks like this is a stale call ptr. */
	return 0;
}

/*!
 * \brief Check if the given call ptr is valid and gripe if not.
 *
 * \param ctrl D channel controller.
 * \param call Q.931 call leg.
 * \param func_name Calling function name for debug tracing. (__PRETTY_FUNCTION__)
 * \param func_line Calling function line number for debug tracing. (__LINE__)
 *
 * \retval TRUE if call ptr is valid.
 * \retval FALSE if call ptr is invalid.
 */
int q931_is_call_valid_gripe(struct pri *ctrl, struct q931_call *call, const char *func_name, unsigned long func_line)
{
	int res;

	if (!call) {
		/* Let's not gripe about this invalid call pointer. */
		return 0;
	}
	res = q931_is_call_valid(ctrl, call);
	if (!res) {
		pri_message(ctrl, "!! %s() line:%lu Called with invalid call ptr (%p)\n",
			func_name, func_line, call);
	}
	return res;
}

/*!
 * \brief Initialize the given struct q931_party_name
 *
 * \param name Structure to initialize
 *
 * \return Nothing
 */
void q931_party_name_init(struct q931_party_name *name)
{
	name->valid = 0;
	name->presentation = PRI_PRES_UNAVAILABLE;
	name->char_set = PRI_CHAR_SET_ISO8859_1;
	name->str[0] = '\0';
}

/*!
 * \brief Initialize the given struct q931_party_number
 *
 * \param number Structure to initialize
 *
 * \return Nothing
 */
void q931_party_number_init(struct q931_party_number *number)
{
	number->valid = 0;
	number->presentation = PRES_NUMBER_NOT_AVAILABLE;
	number->plan = (PRI_TON_UNKNOWN << 4) | PRI_NPI_E163_E164;
	number->str[0] = '\0';
}

/*!
 * \brief Initialize the given struct q931_party_subaddress
 *
 * \param subaddress Structure to initialize
 *
 * \return Nothing
 */
void q931_party_subaddress_init(struct q931_party_subaddress *subaddress)
{
	subaddress->valid = 0;
	subaddress->type = 0;
	subaddress->odd_even_indicator = 0;
	subaddress->length = 0;
	subaddress->data[0] = '\0';
}

/*!
 * \brief Initialize the given struct q931_party_address
 *
 * \param address Structure to initialize
 *
 * \return Nothing
 */
void q931_party_address_init(struct q931_party_address *address)
{
	q931_party_number_init(&address->number);
	q931_party_subaddress_init(&address->subaddress);
}

/*!
 * \brief Initialize the given struct q931_party_id
 *
 * \param id Structure to initialize
 *
 * \return Nothing
 */
void q931_party_id_init(struct q931_party_id *id)
{
	q931_party_name_init(&id->name);
	q931_party_number_init(&id->number);
	q931_party_subaddress_init(&id->subaddress);
}

/*!
 * \brief Initialize the given struct q931_party_redirecting
 *
 * \param redirecting Structure to initialize
 *
 * \return Nothing
 */
void q931_party_redirecting_init(struct q931_party_redirecting *redirecting)
{
	q931_party_id_init(&redirecting->from);
	q931_party_id_init(&redirecting->to);
	q931_party_id_init(&redirecting->orig_called);
	redirecting->state = Q931_REDIRECTING_STATE_IDLE;
	redirecting->count = 0;
	redirecting->orig_reason = PRI_REDIR_UNKNOWN;
	redirecting->reason = PRI_REDIR_UNKNOWN;
}

/*!
 * \brief Compare the left and right party name.
 *
 * \param left Left parameter party name.
 * \param right Right parameter party name.
 *
 * \retval < 0 when left < right.
 * \retval == 0 when left == right.
 * \retval > 0 when left > right.
 */
int q931_party_name_cmp(const struct q931_party_name *left, const struct q931_party_name *right)
{
	int cmp;

	if (!left->valid) {
		if (!right->valid) {
			return 0;
		}
		return -1;
	} else if (!right->valid) {
		return 1;
	}
	cmp = left->char_set - right->char_set;
	if (cmp) {
		return cmp;
	}
	cmp = strcmp(left->str, right->str);
	if (cmp) {
		return cmp;
	}
	cmp = left->presentation - right->presentation;
	return cmp;
}

/*!
 * \brief Compare the left and right party number.
 *
 * \param left Left parameter party number.
 * \param right Right parameter party number.
 *
 * \retval < 0 when left < right.
 * \retval == 0 when left == right.
 * \retval > 0 when left > right.
 */
int q931_party_number_cmp(const struct q931_party_number *left, const struct q931_party_number *right)
{
	int cmp;

	if (!left->valid) {
		if (!right->valid) {
			return 0;
		}
		return -1;
	} else if (!right->valid) {
		return 1;
	}
	cmp = left->plan - right->plan;
	if (cmp) {
		return cmp;
	}
	cmp = strcmp(left->str, right->str);
	if (cmp) {
		return cmp;
	}
	cmp = left->presentation - right->presentation;
	return cmp;
}

/*!
 * \brief Compare the left and right party subaddress.
 *
 * \param left Left parameter party subaddress.
 * \param right Right parameter party subaddress.
 *
 * \retval < 0 when left < right.
 * \retval == 0 when left == right.
 * \retval > 0 when left > right.
 */
int q931_party_subaddress_cmp(const struct q931_party_subaddress *left, const struct q931_party_subaddress *right)
{
	int cmp;

	if (!left->valid) {
		if (!right->valid) {
			return 0;
		}
		return -1;
	} else if (!right->valid) {
		return 1;
	}
	cmp = left->type - right->type;
	if (cmp) {
		return cmp;
	}
	cmp = memcmp(left->data, right->data,
		(left->length < right->length) ? left->length : right->length);
	if (cmp) {
		return cmp;
	}
	cmp = left->length - right->length;
	if (cmp) {
		return cmp;
	}
	cmp = left->odd_even_indicator - right->odd_even_indicator;
	return cmp;
}

/*!
 * \brief Compare the left and right party address.
 *
 * \param left Left parameter party address.
 * \param right Right parameter party address.
 *
 * \retval < 0 when left < right.
 * \retval == 0 when left == right.
 * \retval > 0 when left > right.
 */
int q931_party_address_cmp(const struct q931_party_address *left, const struct q931_party_address *right)
{
	int cmp;

	cmp = q931_party_number_cmp(&left->number, &right->number);
	if (cmp) {
		return cmp;
	}
	cmp = q931_party_subaddress_cmp(&left->subaddress, &right->subaddress);
	return cmp;
}

/*!
 * \brief Compare the left and right party id.
 *
 * \param left Left parameter party id.
 * \param right Right parameter party id.
 *
 * \retval < 0 when left < right.
 * \retval == 0 when left == right.
 * \retval > 0 when left > right.
 */
int q931_party_id_cmp(const struct q931_party_id *left, const struct q931_party_id *right)
{
	int cmp;

	cmp = q931_party_number_cmp(&left->number, &right->number);
	if (cmp) {
		return cmp;
	}
	cmp = q931_party_subaddress_cmp(&left->subaddress, &right->subaddress);
	if (cmp) {
		return cmp;
	}
	cmp = q931_party_name_cmp(&left->name, &right->name);
	return cmp;
}

/*!
 * \brief Compare the left and right party id addresses.
 *
 * \param left Left parameter party id.
 * \param right Right parameter party id.
 *
 * \retval < 0 when left < right.
 * \retval == 0 when left == right.
 * \retval > 0 when left > right.
 */
int q931_party_id_cmp_address(const struct q931_party_id *left, const struct q931_party_id *right)
{
	int cmp;

	cmp = q931_party_number_cmp(&left->number, &right->number);
	if (cmp) {
		return cmp;
	}
	cmp = q931_party_subaddress_cmp(&left->subaddress, &right->subaddress);
	return cmp;
}

/*!
 * \brief Compare the party id to the party address.
 *
 * \param id Party id.
 * \param address Party address.
 *
 * \retval < 0 when id < address.
 * \retval == 0 when id == address.
 * \retval > 0 when id > address.
 */
int q931_cmp_party_id_to_address(const struct q931_party_id *id, const struct q931_party_address *address)
{
	int cmp;

	cmp = q931_party_number_cmp(&id->number, &address->number);
	if (cmp) {
		return cmp;
	}
	cmp = q931_party_subaddress_cmp(&id->subaddress, &address->subaddress);
	return cmp;
}

/*!
 * \brief Copy a party id into a party address.
 *
 * \param address Party address.
 * \param id Party id.
 *
 * \return Nothing
 */
void q931_party_id_copy_to_address(struct q931_party_address *address, const struct q931_party_id *id)
{
	address->number = id->number;
	address->subaddress = id->subaddress;
}

/*!
 * \brief Copy the Q.931 party name to the PRI party name structure.
 *
 * \param pri_name PRI party name structure
 * \param q931_name Q.931 party name structure
 *
 * \return Nothing
 */
void q931_party_name_copy_to_pri(struct pri_party_name *pri_name, const struct q931_party_name *q931_name)
{
	if (q931_name->valid) {
		pri_name->valid = 1;
		pri_name->presentation = q931_name->presentation;
		pri_name->char_set = q931_name->char_set;
		libpri_copy_string(pri_name->str, q931_name->str, sizeof(pri_name->str));
	} else {
		pri_name->valid = 0;
		pri_name->presentation = PRI_PRES_UNAVAILABLE;
		pri_name->char_set = PRI_CHAR_SET_ISO8859_1;
		pri_name->str[0] = '\0';
	}
}

/*!
 * \brief Copy the Q.931 party number to the PRI party number structure.
 *
 * \param pri_number PRI party number structure
 * \param q931_number Q.931 party number structure
 *
 * \return Nothing
 */
void q931_party_number_copy_to_pri(struct pri_party_number *pri_number, const struct q931_party_number *q931_number)
{
	if (q931_number->valid) {
		pri_number->valid = 1;
		pri_number->presentation = q931_number->presentation;
		pri_number->plan = q931_number->plan;
		libpri_copy_string(pri_number->str, q931_number->str, sizeof(pri_number->str));
	} else {
		pri_number->valid = 0;
		pri_number->presentation = PRES_NUMBER_NOT_AVAILABLE;
		pri_number->plan = (PRI_TON_UNKNOWN << 4) | PRI_NPI_E163_E164;
		pri_number->str[0] = '\0';
	}
}

/*!
 * \brief Copy the Q.931 party subaddress to the PRI party subaddress structure.
 *
 * \param pri_subaddress PRI party subaddress structure
 * \param q931_subaddress Q.931 party subaddress structure
 *
 * \return Nothing
 */
void q931_party_subaddress_copy_to_pri(struct pri_party_subaddress *pri_subaddress, const struct q931_party_subaddress *q931_subaddress)
{
	int length;

	if (!q931_subaddress->valid) {
		pri_subaddress->valid = 0;
		pri_subaddress->type = 0;
		pri_subaddress->odd_even_indicator = 0;
		pri_subaddress->length = 0;
		pri_subaddress->data[0] = '\0';
		return;
	}

	pri_subaddress->valid = 1;
	pri_subaddress->type = q931_subaddress->type;
	pri_subaddress->odd_even_indicator = q931_subaddress->odd_even_indicator;

	/*
	 * The size of pri_subaddress->data[] is not the same as the size of
	 * q931_subaddress->data[].
	 */
	length = q931_subaddress->length;
	pri_subaddress->length = length;
	memcpy(pri_subaddress->data, q931_subaddress->data, length);
	pri_subaddress->data[length] = '\0';
}

/*!
 * \brief Copy the Q.931 party address to the PRI party address structure.
 *
 * \param pri_address PRI party address structure
 * \param q931_address Q.931 party address structure
 *
 * \return Nothing
 */
void q931_party_address_copy_to_pri(struct pri_party_address *pri_address, const struct q931_party_address *q931_address)
{
	q931_party_number_copy_to_pri(&pri_address->number, &q931_address->number);
	q931_party_subaddress_copy_to_pri(&pri_address->subaddress, &q931_address->subaddress);
}

/*!
 * \brief Copy the Q.931 party id to the PRI party id structure.
 *
 * \param pri_id PRI party id structure
 * \param q931_id Q.931 party id structure
 *
 * \return Nothing
 */
void q931_party_id_copy_to_pri(struct pri_party_id *pri_id, const struct q931_party_id *q931_id)
{
	q931_party_name_copy_to_pri(&pri_id->name, &q931_id->name);
	q931_party_number_copy_to_pri(&pri_id->number, &q931_id->number);
	q931_party_subaddress_copy_to_pri(&pri_id->subaddress, &q931_id->subaddress);
}

/*!
 * \brief Copy the Q.931 redirecting data to the PRI redirecting structure.
 *
 * \param pri_redirecting PRI redirecting structure
 * \param q931_redirecting Q.931 redirecting structure
 *
 * \return Nothing
 */
void q931_party_redirecting_copy_to_pri(struct pri_party_redirecting *pri_redirecting, const struct q931_party_redirecting *q931_redirecting)
{
	q931_party_id_copy_to_pri(&pri_redirecting->from, &q931_redirecting->from);
	q931_party_id_copy_to_pri(&pri_redirecting->to, &q931_redirecting->to);
	q931_party_id_copy_to_pri(&pri_redirecting->orig_called,
		&q931_redirecting->orig_called);
	pri_redirecting->count = q931_redirecting->count;
	pri_redirecting->orig_reason = q931_redirecting->orig_reason;
	pri_redirecting->reason = q931_redirecting->reason;
}

/*!
 * \brief Fixup some values in the q931_party_id that may be objectionable by switches.
 *
 * \param ctrl D channel controller.
 * \param id Party ID to tweak.
 *
 * \return Nothing
 */
void q931_party_id_fixup(const struct pri *ctrl, struct q931_party_id *id)
{
	switch (ctrl->switchtype) {
	case PRI_SWITCH_DMS100:
	case PRI_SWITCH_ATT4ESS:
		/* Doesn't like certain presentation types */
		if (id->number.valid
			&& (id->number.presentation & PRI_PRES_RESTRICTION) == PRI_PRES_ALLOWED) {
			/* i.e., If presentation is allowed it must be a network number */
			id->number.presentation = PRES_ALLOWED_NETWORK_NUMBER;
		}
		break;
	default:
		break;
	}
}

/*!
 * \brief Determine the overall presentation value for the given party.
 *
 * \param id Party to determine the overall presentation value.
 *
 * \return Overall presentation value for the given party.
 */
int q931_party_id_presentation(const struct q931_party_id *id)
{
	int number_priority;
	int number_value;
	int number_screening;
	int name_priority;
	int name_value;

	/* Determine name presentation priority. */
	if (!id->name.valid) {
		name_value = PRI_PRES_UNAVAILABLE;
		name_priority = 3;
	} else {
		name_value = id->name.presentation & PRI_PRES_RESTRICTION;
		switch (name_value) {
		case PRI_PRES_RESTRICTED:
			name_priority = 0;
			break;
		case PRI_PRES_ALLOWED:
			name_priority = 1;
			break;
		case PRI_PRES_UNAVAILABLE:
			name_priority = 2;
			break;
		default:
			name_value = PRI_PRES_UNAVAILABLE;
			name_priority = 3;
			break;
		}
	}

	/* Determine number presentation priority. */
	if (!id->number.valid) {
		number_screening = PRI_PRES_USER_NUMBER_UNSCREENED;
		number_value = PRI_PRES_UNAVAILABLE;
		number_priority = 3;
	} else {
		number_screening = id->number.presentation & PRI_PRES_NUMBER_TYPE;
		number_value = id->number.presentation & PRI_PRES_RESTRICTION;
		switch (number_value) {
		case PRI_PRES_RESTRICTED:
			number_priority = 0;
			break;
		case PRI_PRES_ALLOWED:
			number_priority = 1;
			break;
		case PRI_PRES_UNAVAILABLE:
			number_priority = 2;
			break;
		default:
			number_screening = PRI_PRES_USER_NUMBER_UNSCREENED;
			number_value = PRI_PRES_UNAVAILABLE;
			number_priority = 3;
			break;
		}
	}

	/* Select the wining presentation value. */
	if (name_priority < number_priority) {
		number_value = name_value;
	}
	if (number_value == PRI_PRES_UNAVAILABLE) {
		return PRES_NUMBER_NOT_AVAILABLE;
	}

	return number_value | number_screening;
}

/*!
 * \internal
 * \brief Get binary buffer contents into the destination buffer.
 *
 * \param dst Destination buffer.
 * \param dst_size Destination buffer sizeof()
 * \param src Source buffer.
 * \param src_len Source buffer length to copy.
 *
 * \note The destination buffer is nul terminated just in case
 * the contents are used as a string anyway.
 *
 * \retval 0 on success.
 * \retval -1 on error.  The copy did not happen.
 */
static int q931_memget(unsigned char *dst, size_t dst_size, const unsigned char *src, int src_len)
{
	if (src_len < 0 || src_len > dst_size - 1) {
		dst[0] = 0;
		return -1;
	}
	memcpy(dst, src, src_len);
	dst[src_len] = 0;
	return 0;
}

/*!
 * \internal
 * \brief Get source buffer contents into the destination buffer for a string.
 *
 * \param dst Destination buffer.
 * \param dst_size Destination buffer sizeof()
 * \param src Source buffer.
 * \param src_len Source buffer length to copy.
 *
 * \note The destination buffer is nul terminated.
 * \note Nul bytes from the source buffer are not copied.
 *
 * \retval 0 on success.
 * \retval -1 if nul bytes were found in the source data.
 */
static int q931_strget(unsigned char *dst, size_t dst_size, const unsigned char *src, int src_len)
{
	int saw_nul;

	if (src_len < 1) {
		dst[0] = '\0';
		return 0;
	}

	saw_nul = 0;
	--dst_size;
	while (dst_size && src_len) {
		if (*src) {
			*dst++ = *src;
			--dst_size;
		} else {
			/* Skip nul bytes in the source buffer. */
			saw_nul = -1;
		}
		++src;
		--src_len;
	}
	*dst = '\0';

	return saw_nul;
}


/*!
 * \internal
 * \brief Get source buffer contents into the destination buffer for a string.
 *
 * \param ctrl D channel controller.
 * \param ie_name IE name to report nul bytes found in.
 * \param dst Destination buffer.
 * \param dst_size Destination buffer sizeof()
 * \param src Source buffer.
 * \param src_len Source buffer length to copy.
 *
 * \note The destination buffer is nul terminated.
 * \note Nul bytes from the source buffer are not copied.
 *
 * \retval 0 on success.
 * \retval -1 if nul bytes were found in the source data.
 */
static int q931_strget_gripe(struct pri *ctrl, const char *ie_name, unsigned char *dst, size_t dst_size, const unsigned char *src, int src_len)
{
	int saw_nul;

/* To quietly remove nul octets just comment out the following line. */
#define UNCONDITIONALLY_REPORT_REMOVED_NUL_OCTETS	1

	saw_nul = q931_strget(dst, dst_size, src, src_len);
	if (saw_nul
#if !defined(UNCONDITIONALLY_REPORT_REMOVED_NUL_OCTETS)
		&& (ctrl->debug & PRI_DEBUG_Q931_STATE)
#endif
		) {
		pri_message(ctrl, "!! Removed nul octets from IE '%s' and returning '%s'.\n",
			ie_name, dst);
	}

	return saw_nul;
}

/*!
 * \internal
 * \brief Clear the display text.
 *
 * \param call Q.931 call to clear display text.
 *
 * \return Nothing
 */
static void q931_display_clear(struct q931_call *call)
{
	call->display.text = NULL;
}

/*!
 * \internal
 * \brief Set the display text for the party name.
 *
 * \param call Q.931 call to set display text to the party name.
 *
 * \return Nothing
 */
static void q931_display_name_send(struct q931_call *call, const struct q931_party_name *name)
{
	if (name->valid) {
		switch (name->presentation & PRI_PRES_RESTRICTION) {
		case PRI_PRES_ALLOWED:
			call->display.text = (unsigned char *) name->str;
			call->display.full_ie = 0;
			call->display.length = strlen(name->str);
			call->display.char_set = name->char_set;
			break;
		default:
			call->display.text = NULL;
			break;
		}
	} else {
		call->display.text = NULL;
	}
}

/*!
 * \brief Get the display text into the party name.
 *
 * \param call Q.931 call to get the display text into the party name.
 * \param name Party name to fill if there is display text.
 *
 * \note
 * The party name is not touched if there is no display text.
 *
 * \note
 * The display text is consumed.
 *
 * \return TRUE if party name filled.
 */
int q931_display_name_get(struct q931_call *call, struct q931_party_name *name)
{
	if (!call->display.text) {
		return 0;
	}

	name->valid = 1;
	name->char_set = call->display.char_set;
	q931_strget_gripe(call->pri, ie2str(call->display.full_ie),
		(unsigned char *) name->str, sizeof(name->str), call->display.text,
		call->display.length);
	if (name->str[0]) {
		name->presentation = PRI_PRES_ALLOWED;
	} else {
		name->presentation = PRI_PRES_RESTRICTED;
	}

	/* Mark the display text as consumed. */
	call->display.text = NULL;

	return 1;
}

/*!
 * \internal
 * \brief Fill a subcmd with any display text.
 *
 * \param ctrl D channel controller.
 * \param call Q.931 call leg.
 *
 * \note
 * The display text is consumed.
 *
 * \return Nothing
 */
static void q931_display_subcmd(struct pri *ctrl, struct q931_call *call)
{
	struct pri_subcommand *subcmd;

	if (call->display.text && call->display.length
		&& (ctrl->display_flags.receive & PRI_DISPLAY_OPTION_TEXT)) {
		subcmd = q931_alloc_subcommand(ctrl);
		if (subcmd) {
			/* Setup display text subcommand */
			subcmd->cmd = PRI_SUBCMD_DISPLAY_TEXT;
			subcmd->u.display.char_set = call->display.char_set;
			q931_strget_gripe(ctrl, ie2str(call->display.full_ie),
				(unsigned char *) subcmd->u.display.text, sizeof(subcmd->u.display.text),
				call->display.text, call->display.length);
			subcmd->u.display.length = strlen(subcmd->u.display.text);
		}
	}

	/* Mark the display text as consumed. */
	call->display.text = NULL;
}

/*!
 * \brief Find the winning subcall if it exists or current call if not outboundbroadcast.
 *
 * \param call Starting Q.931 call record of search.
 *
 * \retval winning-call or given call if not outboundbroadcast.
 * \retval NULL if no winning call yet.
 */
struct q931_call *q931_find_winning_call(struct q931_call *call)
{
	struct q931_call *master;

	master = call->master_call;
	if (master->outboundbroadcast) {
		/* We have potential subcalls.  Now get the winning call if declared yet. */
		if (master->pri_winner < 0) {
			/* Winner not declared yet.*/
			call = NULL;
		} else {
			call = master->subcalls[master->pri_winner];
		}
	}
	return call;
}

/*!
 * \internal
 * \brief Append the given ie contents to the save ie location.
 *
 * \param save_ie Saved ie contents to append new ie.
 * \param ie Contents to append.
 *
 * \return Nothing
 */
static void q931_append_ie_contents(struct q931_saved_ie_contents *save_ie, struct q931_ie *ie)
{
	int size;

	size = ie->len + 2;
	if (size < sizeof(save_ie->data) - save_ie->length) {
		/* Contents will fit so append it. */
		memcpy(&save_ie->data[save_ie->length], ie, size);
		save_ie->length += size;
	}
}

static void q931_clr_subcommands(struct pri *ctrl)
{
	ctrl->subcmds.counter_subcmd = 0;
}

struct pri_subcommand *q931_alloc_subcommand(struct pri *ctrl)
{
	if (ctrl->subcmds.counter_subcmd < PRI_MAX_SUBCOMMANDS) {
		return &ctrl->subcmds.subcmd[ctrl->subcmds.counter_subcmd++];
	}

	pri_error(ctrl, "ERROR: Too many facility subcommands\n");
	return NULL;
}

static char *code2str(int code, struct msgtype *codes, int max)
{
	int x;
	for (x=0;x<max; x++) 
		if (codes[x].msgnum == code)
			return codes[x].name;
	return "Unknown";
}

static char *pritype(int type)
{
	switch (type) {
	case PRI_CPE:
		return "CPE";
		break;
	case PRI_NETWORK:
		return "NET";
		break;
	default:
		return "UNKNOWN";
	}
}

static char *binary(int b, int len) {
	static char res[33];
	int x;
	memset(res, 0, sizeof(res));
	if (len > 32)
		len = 32;
	for (x=1;x<=len;x++)
		res[x-1] = b & (1 << (len - x)) ? '1' : '0';
	return res;
}

static int receive_channel_id(int full_ie, struct pri *ctrl, q931_call *call, int msgtype, q931_ie *ie, int len)
{	
	int x;
	int pos = 0;
	int need_extended_channel_octets;/*!< TRUE if octets 3.2 and 3.3 need to be present. */

	call->channel_id_ie_mandatory = 0;

	if (ie->len < 1) {
		/* Must have at least one payload octet. */
		pri_error(ctrl, "!! Channel Identification ie too short\n");
		return -1;
	}

	call->restart.count = 0;

	if (ie->data[0] & 0x08) {
		call->chanflags = FLAG_EXCLUSIVE;
	} else {
		call->chanflags = FLAG_PREFERRED;
	}

	need_extended_channel_octets = 0;
	if (ie->data[0] & 0x20) {
		/* PRI encoded interface type */
		switch (ie->data[0] & 0x03) {
		case 0x00:
			/* No channel */
			call->channelno = 0;
			call->chanflags = FLAG_PREFERRED;
			break;
		case 0x01:
			/* As indicated in following octets */
			need_extended_channel_octets = 1;
			break;
		case 0x03:
			/* Any channel */
			call->chanflags = FLAG_PREFERRED;
			break;
		default:
			pri_error(ctrl, "!! Unexpected Channel selection %d\n", ie->data[0] & 0x03);
			return -1;
		}
	} else {
		/* BRI encoded interface type */
		switch (ie->data[0] & 0x03) {
		case 0x00:
			/* No channel */
			call->channelno = 0;
			call->chanflags = FLAG_PREFERRED;
			break;
		case 0x03:
			/* Any channel */
			call->chanflags = FLAG_PREFERRED;
			break;
		default:
			/* Specified B channel (B1 or B2) */
			call->channelno = ie->data[0] & 0x03;
			break;
		}
	}

	pos++;
	if (ie->data[0] & 0x40) {
		/* Explicitly defined DS1 (One or more 3.1 octets expected) */
		if (ctrl->switchtype == PRI_SWITCH_QSIG) {
			pri_error(ctrl, "!! Q.SIG does not support Channel Identification octet 3.1\n");
			return -1;
		}
		if (ie->len <= pos) {
			pri_error(ctrl, "!! Missing expected Channel Identification octet 3.1\n");
			return -1;
		}

		/* Extract explicit DS1 reference. */
		call->ds1no = ie->data[pos] & 0x7f;
		call->ds1explicit = 1;

		/* Advance to 3.2 octet if present. */
		do {
			++pos;
		} while (pos < ie->len && !(ie->data[pos - 1] & 0x80));
	} else {
		call->ds1explicit = 0;
	}

	if (ie->data[0] & 0x04) {
		/* D channel call.  Signaling only. */
		call->cis_call = 1;
		call->chanflags = FLAG_EXCLUSIVE;/* For safety mark this channel as exclusive. */
		call->channelno = 0;
		return 0;
	}

	if (need_extended_channel_octets && pos + 2 <= ie->len) {
		/*
		 * Octet 3.2 and at least one octet 3.3 are present.
		 *
		 * Process octet 3.2
		 */
		if ((ie->data[pos] & 0x0f) != 3) {
			/* Channel type/mapping is not for B channel units. */
			pri_error(ctrl, "!! Unexpected Channel Type %d\n", ie->data[pos] & 0x0f);
			return -1;
		}
		if ((ie->data[pos] & 0x60) != 0) {
			pri_error(ctrl, "!! Invalid CCITT coding %d\n", (ie->data[pos] & 0x60) >> 5);
			return -1;
		}
		if (ie->data[pos++] & 0x10) {
			/* Process 3.3 octets as a Slot Map */
			call->slotmap = 0;
			call->slotmap_size = (ie->len - pos > 3) ? 1 : 0;

			/*
			 * We will be tolerant of partial slot maps that do not
			 * specify the upper channels.  We will assume they
			 * are not requested.
			 *
			 * We will only read up to 24 or 32 bit channel maps.
			 */
			for (x = call->slotmap_size ? 4 : 3; x--;) {
				call->slotmap <<= 8;
				call->slotmap |= ie->data[pos++];
				if (ie->len <= pos) {
					/* No more ie contents. */
					break;
				}
			}

			if (msgtype == Q931_RESTART) {
				int bit;

				/* Convert the slotmap to a channel list for RESTART support. */
				for (bit = 0; bit < ARRAY_LEN(call->restart.chan_no); ++bit) {
					if (call->slotmap & (1UL << bit)) {
						call->restart.chan_no[call->restart.count++] = bit
							+ (call->slotmap_size ? 0 : 1);
					}
				}
			}
		} else {
			/*
			 * Process 3.3 octets as either a single channel or a channel list
			 *
			 * Get single channel
			 */
			call->channelno = ie->data[pos] & 0x7f;
			if (ctrl->chan_mapping_logical && call->channelno > 15) {
				call->channelno++;
			}

			if (msgtype == Q931_RESTART) {
				/* Read in channel list for RESTART support. */
				while (call->restart.count < ARRAY_LEN(call->restart.chan_no)) {
					int chan_no;
	
					chan_no = ie->data[pos] & 0x7f;
					if (ctrl->chan_mapping_logical && chan_no > 15) {
						++chan_no;
					}
					call->restart.chan_no[call->restart.count++] = chan_no;
					if (ie->data[pos++] & 0x80) {
						/* Channel list finished. */
						break;
					}
					if (ie->len <= pos) {
						/* No more ie contents. */
						break;
					}
				}
			}
		}
	} else if (need_extended_channel_octets) {
		pri_error(ctrl, "!! Missing expected Channel Identification octets 3.2 or 3.3\n");
		return -1;
	}
	return 0;
}

static int transmit_channel_id(int full_ie, struct pri *ctrl, q931_call *call, int msgtype, q931_ie *ie, int len, int order)
{
	int pos = 0;

	/* We are ready to transmit single IE only */
	if (order > 1)
		return 0;

	if (call->cis_call) {
		/*
		 * Read the standards docs to figure this out.
		 * Q.SIG ECMA-165 section 7.3
		 * ITU Q.931 section 4.5.13
		 */
		ie->data[pos++] = ctrl->bri ? 0x8c : 0xac;
		return pos + 2;
	}

	/* Start with standard stuff */
	if (ctrl->switchtype == PRI_SWITCH_GR303_TMC)
		ie->data[pos] = 0x69;
	else if (ctrl->bri) {
		ie->data[pos] = 0x80;
		ie->data[pos] |= (call->channelno & 0x3);
	} else {
		/* PRI */
		if (call->slotmap != -1 || (call->chanflags & FLAG_WHOLE_INTERFACE)) {
			/* Specified channel */
			ie->data[pos] = 0xa1;
		} else if (call->channelno < 0 || call->channelno == 0xff) {
			/* Any channel */
			ie->data[pos] = 0xa3;
		} else if (!call->channelno) {
			/* No channel */
			ie->data[pos] = 0xa0;
		} else {
			/* Specified channel */
			ie->data[pos] = 0xa1;
		}
	}
	if (call->chanflags & FLAG_EXCLUSIVE) {
		/* Channel is exclusive */
		if (!(ie->data[pos] & 0x03)) {
			/* An exclusive no channel id ie is to be discarded. */
			return 0;
		}
		ie->data[pos] |= 0x08;
	} else if (!call->chanflags) {
		/* Don't need this IE */
		return 0;
	}

	if (!ctrl->bri && (((ctrl->switchtype != PRI_SWITCH_QSIG) && (call->ds1no > 0)) || call->ds1explicit)) {
		/* We are specifying the interface.  Octet 3.1 */
		ie->data[pos++] |= 0x40;
		ie->data[pos++] = 0x80 | call->ds1no;
	} else {
		++pos;
	}

	if (!ctrl->bri && (ie->data[0] & 0x03) == 0x01 /* Specified channel */
		&& !(call->chanflags & FLAG_WHOLE_INTERFACE)) {
		/* The 3.2 and 3.3 octets need to be present */
		ie->data[pos] = 0x83;
		if (0 < call->channelno && call->channelno != 0xff) {
			/* Channel number specified and preferred over slot map if we have one. */
			++pos;
			if (msgtype == Q931_RESTART_ACKNOWLEDGE && call->restart.count) {
				int chan_no;
				int idx;

				/* Build RESTART_ACKNOWLEDGE channel list */
				for (idx = 0; idx < call->restart.count; ++idx) {
					chan_no = call->restart.chan_no[idx];
					if (ctrl->chan_mapping_logical && chan_no > 16) {
						--chan_no;
					}
					if (call->restart.count <= idx + 1) {
						/* Last channel list channel. */
						chan_no |= 0x80;
					}
					ie->data[pos++] = chan_no;
				}
			} else {
				if (ctrl->chan_mapping_logical && call->channelno > 16) {
					ie->data[pos++] = 0x80 | (call->channelno - 1);
				} else {
					ie->data[pos++] = 0x80 | call->channelno;
				}
			}
		} else if (call->slotmap != -1) {
			int octet;

			/* We have to send a slot map */
			ie->data[pos++] |= 0x10;
			for (octet = call->slotmap_size ? 4 : 3; octet--;) {
				ie->data[pos++] = (call->slotmap >> (8 * octet)) & 0xff;
			}
		} else {
			pri_error(ctrl, "XXX We need either a channelno or slotmap but have neither!\n");
			/* Discard this malformed ie. */
			return 0;
		}
	}

	return pos + 2;
}

static void dump_channel_id(int full_ie, struct pri *ctrl, q931_ie *ie, int len, char prefix)
{
	int pos;
	int x;
	int res;

	static const char *msg_chan_sel[] = {
		"No channel selected", "B1 channel", "B2 channel", "Any channel selected",
		"No channel selected", "As indicated in following octets", "Reserved", "Any channel selected"
	};

	pri_message(ctrl,
		"%c %s (len=%2d) [ Ext: %d  IntID: %s  %s  Spare: %d  %s  Dchan: %d\n",
		prefix, ie2str(full_ie), len,
		(ie->data[0] & 0x80) ? 1 : 0,
		(ie->data[0] & 0x40) ? "Explicit" : "Implicit",
		(ie->data[0] & 0x20) ? "Other(PRI)" : "BRI",
		(ie->data[0] & 0x10) ? 1 : 0,
		(ie->data[0] & 0x08) ? "Exclusive" : "Preferred",
		(ie->data[0] & 0x04) ? 1 : 0);
	pri_message(ctrl, "%c                       ChanSel: %s\n",
		prefix, msg_chan_sel[(ie->data[0] & 0x03) | ((ie->data[0] & 0x20) >> 3)]);
	pos = 1;
	len -= 2;
	if (ie->data[0] & 0x40) {
		/* Explicitly defined DS1 (One or more 3.1 octets expected) */
		if (ctrl->switchtype == PRI_SWITCH_QSIG) {
			pri_message(ctrl, "%c                       Octet 3.1 specified when Q.SIG!\n",
				prefix);
		}
		if (pos < len) {
			do {
				pri_message(ctrl, "%c                       Ext: %d  DS1 Identifier: %d\n",
					prefix, (ie->data[pos] & 0x80) >> 7, ie->data[pos] & 0x7f);
				++pos;
			} while (!(ie->data[pos - 1] & 0x80) && pos < len);
		} else {
			pri_message(ctrl, "%c                       Octet 3.1 is missing!\n", prefix);
		}
	} else {
		/* Implicitly defined DS1 */
	}
	if (pos < len) {
		/* Octet 3.2 present */
		pri_message(ctrl,
			"%c                       Ext: %d  Coding: %d  %s Specified  Channel Type: %d\n",
			prefix, (ie->data[pos] & 0x80) >> 7, (ie->data[pos] & 60) >> 5,
			(ie->data[pos] & 0x10) ? "Slot Map" : "Number", ie->data[pos] & 0x0f);
		++pos;
	}
	if (pos < len) {
		/* One or more 3.3 octets present */
		if (!(ie->data[pos - 1] & 0x10)) {
			/* Number specified */
			do {
				pri_message(ctrl,
					"%c                       Ext: %d  Channel: %d Type: %s%c\n",
					prefix, (ie->data[pos] & 0x80) >> 7,
					(ie->data[pos]) & 0x7f, pritype(ctrl->localtype),
					(pos + 1 < len) ? ' ' : ']');
				++pos;
			} while (pos < len);
		} else {
			/* Map specified */
			res = 0;
			x = 0;
			do {
				res <<= 8;
				res |= ie->data[pos++];
				++x;
			} while (pos < len);
			pri_message(ctrl, "%c                       Map len: %d  Map: %s ]\n", prefix,
				x, binary(res, x << 3));
		}
	} else {
		pri_message(ctrl, "%c                     ]\n", prefix);
	}
}

static char *ri2str(int ri)
{
	static struct msgtype ris[] = {
		{ 0, "Indicated Channel" },
		{ 6, "Single DS1 Facility" },
		{ 7, "All DS1 Facilities" },
	};
	return code2str(ri, ris, sizeof(ris) / sizeof(ris[0]));
}

static void dump_restart_indicator(int full_ie, struct pri *ctrl, q931_ie *ie, int len, char prefix)
{
	pri_message(ctrl, "%c %s (len=%2d) [ Ext: %d  Spare: %d  Resetting %s (%d) ]\n",
		prefix, ie2str(full_ie), len, (ie->data[0] & 0x80) >> 7,
		(ie->data[0] & 0x78) >> 3, ri2str(ie->data[0] & 0x7), ie->data[0] & 0x7);
}

static int receive_restart_indicator(int full_ie, struct pri *ctrl, q931_call *call, int msgtype, q931_ie *ie, int len)
{
	/* Pretty simple */
	call->ri = ie->data[0] & 0x7;
	return 0;
}

static int transmit_restart_indicator(int full_ie, struct pri *ctrl, q931_call *call, int msgtype, q931_ie *ie, int len, int order)
{
	/* Pretty simple */
	switch(call->ri) {
	case 0:
	case 6:
	case 7:
		ie->data[0] = 0x80 | (call->ri & 0x7);
		break;
	case 5:
		/* Switch compatibility */
		ie->data[0] = 0xA0 | (call->ri & 0x7);
		break;
	default:
		pri_error(ctrl, "!! Invalid restart indicator value %d\n", call->ri);
		return-1;
	}
	return 3;
}

static char *redirection_reason2str(int mode)
{
	static struct msgtype modes[] = {
		{ PRI_REDIR_UNKNOWN, "Unknown" },
		{ PRI_REDIR_FORWARD_ON_BUSY, "Forwarded on busy" },
		{ PRI_REDIR_FORWARD_ON_NO_REPLY, "Forwarded on no reply" },
		{ PRI_REDIR_DEFLECTION, "Call deflected" },
		{ PRI_REDIR_DTE_OUT_OF_ORDER, "Called DTE out of order" },
		{ PRI_REDIR_FORWARDED_BY_DTE, "Forwarded by called DTE" },
		{ PRI_REDIR_UNCONDITIONAL, "Forwarded unconditionally" },
	};
	return code2str(mode, modes, sizeof(modes) / sizeof(modes[0]));
}

static char *cap2str(int mode)
{
	static struct msgtype modes[] = {
		{ PRI_TRANS_CAP_SPEECH, "Speech" },
		{ PRI_TRANS_CAP_DIGITAL, "Unrestricted digital information" },
		{ PRI_TRANS_CAP_RESTRICTED_DIGITAL, "Restricted digital information" },
		{ PRI_TRANS_CAP_3_1K_AUDIO, "3.1kHz audio" },
		{ PRI_TRANS_CAP_DIGITAL_W_TONES, "Unrestricted digital information with tones/announcements" },
		{ PRI_TRANS_CAP_VIDEO, "Video" },
		{ PRI_TRANS_CAP_AUDIO_4ESS, "3.1khz audio (4ESS)" },
	};
	return code2str(mode, modes, sizeof(modes) / sizeof(modes[0]));
}

static char *mode2str(int mode)
{
	static struct msgtype modes[] = {
		{ TRANS_MODE_64_CIRCUIT, "64kbps, circuit-mode" },
		{ TRANS_MODE_2x64_CIRCUIT, "2x64kbps, circuit-mode" },
		{ TRANS_MODE_384_CIRCUIT, "384kbps, circuit-mode" },
		{ TRANS_MODE_1536_CIRCUIT, "1536kbps, circuit-mode" },
		{ TRANS_MODE_1920_CIRCUIT, "1920kbps, circuit-mode" },
		{ TRANS_MODE_MULTIRATE, "Multirate (Nx64kbps)" },
		{ TRANS_MODE_PACKET, "Packet Mode" },
	};
	return code2str(mode, modes, sizeof(modes) / sizeof(modes[0]));
}

static char *l12str(int proto)
{
	static struct msgtype protos[] = {
 		{ PRI_LAYER_1_ITU_RATE_ADAPT, "V.110 Rate Adaption" },
		{ PRI_LAYER_1_ULAW, "u-Law" },
		{ PRI_LAYER_1_ALAW, "A-Law" },
		{ PRI_LAYER_1_G721, "G.721 ADPCM" },
		{ PRI_LAYER_1_G722_G725, "G.722/G.725 7kHz Audio" },
 		{ PRI_LAYER_1_H223_H245, "H.223/H.245 Multimedia" },
		{ PRI_LAYER_1_NON_ITU_ADAPT, "Non-ITU Rate Adaption" },
		{ PRI_LAYER_1_V120_RATE_ADAPT, "V.120 Rate Adaption" },
		{ PRI_LAYER_1_X31_RATE_ADAPT, "X.31 Rate Adaption" },
	};
	return code2str(proto, protos, sizeof(protos) / sizeof(protos[0]));
}

static char *ra2str(int proto)
{
	static struct msgtype protos[] = {
		{ PRI_RATE_ADAPT_9K6, "9.6 kbit/s" },
	};
	return code2str(proto, protos, sizeof(protos) / sizeof(protos[0]));
}

static char *l22str(int proto)
{
	static struct msgtype protos[] = {
		{ LAYER_2_LAPB, "LAPB" },
	};
	return code2str(proto, protos, sizeof(protos) / sizeof(protos[0]));
}

static char *l32str(int proto)
{
	static struct msgtype protos[] = {
		{ LAYER_3_X25, "X.25" },
	};
	return code2str(proto, protos, sizeof(protos) / sizeof(protos[0]));
}

static char *int_rate2str(int proto)
{
    static struct msgtype protos[] = {
		{ PRI_INT_RATE_8K, "8 kbit/s" },
		{ PRI_INT_RATE_16K, "16 kbit/s" },
		{ PRI_INT_RATE_32K, "32 kbit/s" },
    };
    return code2str(proto, protos, sizeof(protos) / sizeof(protos[0]));
}

static void dump_bearer_capability(int full_ie, struct pri *ctrl, q931_ie *ie, int len, char prefix)
{
	int pos=2;
	pri_message(ctrl,
		"%c %s (len=%2d) [ Ext: %d  Coding-Std: %d  Info transfer capability: %s (%d)\n",
		prefix, ie2str(full_ie), len, (ie->data[0] & 0x80 ) >> 7,
		(ie->data[0] & 0x60) >> 5, cap2str(ie->data[0] & 0x1f),
		(ie->data[0] & 0x1f));
	pri_message(ctrl, "%c                              Ext: %d  Trans mode/rate: %s (%d)\n", prefix, (ie->data[1] & 0x80) >> 7, mode2str(ie->data[1] & 0x7f), ie->data[1] & 0x7f);

	/* octet 4.1 exists if mode/rate is multirate */
	if ((ie->data[1] & 0x7f) == 0x18) {
		pri_message(ctrl, "%c                              Ext: %d  Transfer rate multiplier: %d x 64\n", prefix, (ie->data[2] & 0x80) >> 7, ie->data[2] & 0x7f);
		pos++;
	}

	/* don't count the IE num and length as part of the data */
	len -= 2;
	
	/* Look for octet 5; this is identified by bits 5,6 == 01 */
     	if (pos < len &&
		(ie->data[pos] & 0x60) == 0x20) {

		/* although the layer1 is only the bottom 5 bits of the byte,
		   previous versions of this library passed bits 5&6 through
		   too, so we have to do the same for binary compatability */
		u_int8_t layer1 = ie->data[pos] & 0x7f;

		pri_message(ctrl, "%c                                User information layer 1: %s (%d)\n",
		            prefix, l12str(layer1), layer1);
		pos++;
		
		/* octet 5a? */
		if (pos < len && !(ie->data[pos-1] & 0x80)) {
			int ra = ie->data[pos] & 0x7f;

			pri_message(ctrl, "%c                                Async: %d, Negotiation: %d, "
				"User rate: %s (%#x)\n", 
				prefix,
				ra & PRI_RATE_ADAPT_ASYNC ? 1 : 0,
				ra & PRI_RATE_ADAPT_NEGOTIATION_POSS ? 1 : 0,
				ra2str(ra & PRI_RATE_USER_RATE_MASK),
				ra & PRI_RATE_USER_RATE_MASK);
			pos++;
		}
		
		/* octet 5b? */
		if (pos < len && !(ie->data[pos-1] & 0x80)) {
			u_int8_t data = ie->data[pos];
			if (layer1 == PRI_LAYER_1_ITU_RATE_ADAPT) {
				pri_message(ctrl, "%c                                Intermediate rate: %s (%d), "
					"NIC on Tx: %d, NIC on Rx: %d, "
					"Flow control on Tx: %d, "
					"Flow control on Rx: %d\n",
					prefix, int_rate2str((data & 0x60)>>5),
					(data & 0x60)>>5,
					(data & 0x10)?1:0,
					(data & 0x08)?1:0,
					(data & 0x04)?1:0,
					(data & 0x02)?1:0);
			} else if (layer1 == PRI_LAYER_1_V120_RATE_ADAPT) {
				pri_message(ctrl, "%c                                Hdr: %d, Multiframe: %d, Mode: %d, "
					"LLI negot: %d, Assignor: %d, "
					"In-band neg: %d\n", prefix,
					(data & 0x40)?1:0,
					(data & 0x20)?1:0,
					(data & 0x10)?1:0,
					(data & 0x08)?1:0,
					(data & 0x04)?1:0,
					(data & 0x02)?1:0);
			} else {
				pri_message(ctrl, "%c                                Unknown octet 5b: 0x%x\n",
					prefix, data);
			}
			pos++;
		}

		/* octet 5c? */
		if (pos < len && !(ie->data[pos-1] & 0x80)) {
			u_int8_t data = ie->data[pos];
			const char *stop_bits[] = {"?","1","1.5","2"};
			const char *data_bits[] = {"?","5","7","8"};
			const char *parity[] = {"Odd","?","Even","None",
				       "zero","one","?","?"};
	
			pri_message(ctrl, "%c                                Stop bits: %s, data bits: %s, "
			    "parity: %s\n", prefix,
			    stop_bits[(data & 0x60) >> 5],
			    data_bits[(data & 0x18) >> 3],
			    parity[(data & 0x7)]);
	
			pos++;
		}
	
			/* octet 5d? */
		if (pos < len && !(ie->data[pos-1] & 0x80)) {
			u_int8_t data = ie->data[pos];
			pri_message(ctrl, "%c                                Duplex mode: %d, modem type: %d\n",
				prefix, (data & 0x40) ? 1 : 0,data & 0x3F);
 			pos++;
		}
 	}


	/* Look for octet 6; this is identified by bits 5,6 == 10 */
	if (pos < len && 
		(ie->data[pos] & 0x60) == 0x40) {
		pri_message(ctrl, "%c                                User information layer 2: %s (%d)\n",
			prefix, l22str(ie->data[pos] & 0x1f),
			ie->data[pos] & 0x1f);
		pos++;
	}

	/* Look for octet 7; this is identified by bits 5,6 == 11 */
	if (pos < len && (ie->data[pos] & 0x60) == 0x60) {
		pri_message(ctrl, "%c                                User information layer 3: %s (%d)\n",
			prefix, l32str(ie->data[pos] & 0x1f),
			ie->data[pos] & 0x1f);
		pos++;

		/* octets 7a and 7b? */
		if (pos + 1 < len && !(ie->data[pos-1] & 0x80) &&
			!(ie->data[pos] & 0x80)) {
			unsigned int proto;
			proto = ((ie->data[pos] & 0xF) << 4 ) | 
			         (ie->data[pos+1] & 0xF);

			pri_message(ctrl, "%c                                Network layer: 0x%x\n", prefix,
			            proto );
			pos += 2;
		}
	}
}

static int receive_bearer_capability(int full_ie, struct pri *ctrl, q931_call *call, int msgtype, q931_ie *ie, int len)
{
	int pos = 2;

	switch (ie->data[0] & 0x60) {
	case 0x00:/* ITU-T standardized coding */
		call->bc.transcapability = ie->data[0] & 0x1f;
		call->bc.transmoderate = ie->data[1] & 0x7f;

		/* octet 4.1 exists if mode/rate is multirate */
		if (call->bc.transmoderate == TRANS_MODE_MULTIRATE) {
			call->bc.transmultiple = ie->data[pos++] & 0x7f;
		}

		/* Look for octet 5; this is identified by bits 5,6 == 01 */
		if (pos < len && (ie->data[pos] & 0x60) == 0x20) {
			/* although the layer1 is only the bottom 5 bits of the byte,
			   previous versions of this library passed bits 5&6 through
			   too, so we have to do the same for binary compatability */
			call->bc.userl1 = ie->data[pos] & 0x7f;
			pos++;

			/* octet 5a? */
			if (pos < len && !(ie->data[pos-1] & 0x80)) {
				call->bc.rateadaption = ie->data[pos] & 0x7f;
				pos++;
			}

			/* octets 5b through 5d? */
			while (pos < len && !(ie->data[pos-1] & 0x80)) {
				pos++;
			}

		}

		/* Look for octet 6; this is identified by bits 5,6 == 10 */
		if (pos < len && (ie->data[pos] & 0x60) == 0x40) {
			call->bc.userl2 = ie->data[pos++] & 0x1f;
		}

		/* Look for octet 7; this is identified by bits 5,6 == 11 */
		if (pos < len && (ie->data[pos] & 0x60) == 0x60) {
			call->bc.userl3 = ie->data[pos++] & 0x1f;
		}
		break;
	case 0x20:/* ISO/IEC standard */
		if (ie->data[0] == 0xa8 && ie->data[1] == 0x80) {
			/*
			 * Q.SIG uses for CIS calls. ECMA-165 Section 11.3.1
			 * This mandatory ie is more or less a place holder in this case.
			 */
			call->bc.transcapability = PRI_TRANS_CAP_DIGITAL;
			call->bc.transmoderate = TRANS_MODE_64_CIRCUIT;
			break;
		}
		/* Fall through */
	default:
		pri_error(ctrl, "!! Coding-standard field is not Q.931.\n");
		return -1;
	}
	return 0;
}

static int transmit_bearer_capability(int full_ie, struct pri *ctrl, q931_call *call, int msgtype, q931_ie *ie, int len, int order)
{
	int tc;
	int pos;

	/* We are ready to transmit single IE only */	
	if(order > 1)
		return 0;

	if (ctrl->link.next && !ctrl->bri) {
		/* Bearer capability is *hard coded* in GR-303 */
		ie->data[0] = 0x88;
		ie->data[1] = 0x90;
		return 4;
	}

	if (call->cis_call) {
		ie->data[0] = 0xa8;
		ie->data[1] = 0x80;
		return 4;
	}

	tc = call->bc.transcapability;
	ie->data[0] = 0x80 | tc;
	ie->data[1] = call->bc.transmoderate | 0x80;

	pos = 2;
	/* octet 4.1 exists if mode/rate is multirate */
	if (call->bc.transmoderate == TRANS_MODE_MULTIRATE) {
		ie->data[pos++] = call->bc.transmultiple | 0x80;
	}

	if ((tc & PRI_TRANS_CAP_DIGITAL) && (ctrl->switchtype == PRI_SWITCH_EUROISDN_E1) &&
		(call->bc.transmoderate == TRANS_MODE_PACKET)) {
		/* Apparently EuroISDN switches don't seem to like user layer 2/3 */
		return 4;
	}

	if ((tc & PRI_TRANS_CAP_DIGITAL) && (call->bc.transmoderate == TRANS_MODE_64_CIRCUIT)) {
		/* Unrestricted digital 64k data calls don't use user layer 2/3 */
		return 4;
	}

	if (call->bc.transmoderate != TRANS_MODE_PACKET) {
		/* If you have an AT&T 4ESS, you don't send any more info */
		if ((ctrl->switchtype != PRI_SWITCH_ATT4ESS) && (call->bc.userl1 > -1)) {
			ie->data[pos++] = call->bc.userl1 | 0x80; /* XXX Ext bit? XXX */
			if (call->bc.userl1 == PRI_LAYER_1_ITU_RATE_ADAPT) {
				ie->data[pos++] = call->bc.rateadaption | 0x80;
			}
			return pos + 2;
 		}
 
 		ie->data[pos++] = 0xa0 | (call->bc.userl1 & 0x1f);
 
 		if (call->bc.userl1 == PRI_LAYER_1_ITU_RATE_ADAPT) {
 		    ie->data[pos-1] &= ~0x80; /* clear EXT bit in octet 5 */
 		    ie->data[pos++] = call->bc.rateadaption | 0x80;
 		}
 	}
 	
 	
 	if (call->bc.userl2 != -1)
 		ie->data[pos++] = 0xc0 | (call->bc.userl2 & 0x1f);
 
 	if (call->bc.userl3 != -1)
 		ie->data[pos++] = 0xe0 | (call->bc.userl3 & 0x1f);
 
 	return pos + 2;
}

char *pri_plan2str(int plan)
{
	static struct msgtype plans[] = {
		{ PRI_INTERNATIONAL_ISDN, "International number in ISDN" },
		{ PRI_NATIONAL_ISDN, "National number in ISDN" },
		{ PRI_LOCAL_ISDN, "Local number in ISDN" },
		{ PRI_PRIVATE, "Private numbering plan" },
		{ PRI_UNKNOWN, "Unknown numbering plan" },
	};
	return code2str(plan, plans, sizeof(plans) / sizeof(plans[0]));
}

static char *npi2str(int plan)
{
	static struct msgtype plans[] = {
		{ PRI_NPI_UNKNOWN, "Unknown Number Plan" },
		{ PRI_NPI_E163_E164, "ISDN/Telephony Numbering Plan (E.164/E.163)" },
		{ PRI_NPI_X121, "Data Numbering Plan (X.121)" },
		{ PRI_NPI_F69, "Telex Numbering Plan (F.69)" },
		{ PRI_NPI_NATIONAL, "National Standard Numbering Plan" },
		{ PRI_NPI_PRIVATE, "Private Numbering Plan" },
		{ PRI_NPI_RESERVED, "Reserved Number Plan" },
	};
	return code2str(plan, plans, sizeof(plans) / sizeof(plans[0]));
}

static char *ton2str(int plan)
{
	static struct msgtype plans[] = {
		{ PRI_TON_UNKNOWN, "Unknown Number Type" },
		{ PRI_TON_INTERNATIONAL, "International Number" },
		{ PRI_TON_NATIONAL, "National Number" },
		{ PRI_TON_NET_SPECIFIC, "Network Specific Number" },
		{ PRI_TON_SUBSCRIBER, "Subscriber Number" },
		{ PRI_TON_ABBREVIATED, "Abbreviated number" },
		{ PRI_TON_RESERVED, "Reserved Number" },
	};
	return code2str(plan, plans, sizeof(plans) / sizeof(plans[0]));
}

static char *subaddrtype2str(int plan)
{
	static struct msgtype plans[] = {
		{ 0, "NSAP (X.213/ISO 8348 AD2)" },
		{ 2, "User Specified" },
	};
	return code2str(plan, plans, sizeof(plans) / sizeof(plans[0]));
}

/* Calling Party Category (Definitions from Q.763) */
static char *cpc2str(int plan)
{
	static struct msgtype plans[] = {
		{ 0, "Unknown Source" },
		{ 1, "Operator French" },
		{ 2, "Operator English" },
		{ 3, "Operator German" },
		{ 4, "Operator Russian" },
		{ 5, "Operator Spanish" },
		{ 6, "Mut Agree Chinese" },
		{ 7, "Mut Agreement" },
		{ 8, "Mut Agree Japanese" },
		{ 9, "National Operator" },
		{ 10, "Ordinary Toll Caller" },
		{ 11, "Priority Toll Caller" },
		{ 12, "Data Call" },
		{ 13, "Test Call" },
		{ 14, "Spare" },
		{ 15, "Pay Phone" },
	};
	return code2str(plan, plans, ARRAY_LEN(plans));
}

char *pri_pres2str(int pres)
{
	static struct msgtype press[] = {
		{ PRI_PRES_ALLOWED | PRI_PRES_USER_NUMBER_UNSCREENED,        "Presentation allowed, User-provided, not screened" },
		{ PRI_PRES_ALLOWED | PRI_PRES_USER_NUMBER_PASSED_SCREEN,     "Presentation allowed, User-provided, verified and passed" },
		{ PRI_PRES_ALLOWED | PRI_PRES_USER_NUMBER_FAILED_SCREEN,     "Presentation allowed, User-provided, verified and failed" },
		{ PRI_PRES_ALLOWED | PRI_PRES_NETWORK_NUMBER,                "Presentation allowed, Network provided" },

		{ PRI_PRES_RESTRICTED | PRI_PRES_USER_NUMBER_UNSCREENED,     "Presentation restricted, User-provided, not screened" },
		{ PRI_PRES_RESTRICTED | PRI_PRES_USER_NUMBER_PASSED_SCREEN,  "Presentation restricted, User-provided, verified and passed" },
		{ PRI_PRES_RESTRICTED | PRI_PRES_USER_NUMBER_FAILED_SCREEN,  "Presentation restricted, User-provided, verified and failed" },
		{ PRI_PRES_RESTRICTED | PRI_PRES_NETWORK_NUMBER,             "Presentation restricted, Network provided" },

		{ PRI_PRES_UNAVAILABLE | PRI_PRES_USER_NUMBER_UNSCREENED,    "Number not available, User-provided, not screened" },
		{ PRI_PRES_UNAVAILABLE | PRI_PRES_USER_NUMBER_PASSED_SCREEN, "Number not available, User-provided, verified and passed" },
		{ PRI_PRES_UNAVAILABLE | PRI_PRES_USER_NUMBER_FAILED_SCREEN, "Number not available, User-provided, verified and failed" },
		{ PRI_PRES_UNAVAILABLE | PRI_PRES_NETWORK_NUMBER,            "Number not available, Network provided" },

		{ PRI_PRES_RESERVED | PRI_PRES_USER_NUMBER_UNSCREENED,       "Reserved, User-provided, not screened" },
		{ PRI_PRES_RESERVED | PRI_PRES_USER_NUMBER_PASSED_SCREEN,    "Reserved, User-provided, verified and passed" },
		{ PRI_PRES_RESERVED | PRI_PRES_USER_NUMBER_FAILED_SCREEN,    "Reserved, User-provided, verified and failed" },
		{ PRI_PRES_RESERVED | PRI_PRES_NETWORK_NUMBER,               "Reserved, Network provided" },
	};

	pres &= (PRI_PRES_RESTRICTION | PRI_PRES_NUMBER_TYPE);
	return code2str(pres, press, sizeof(press) / sizeof(press[0]));
}

static void q931_get_subaddr_specific(unsigned char *num, int maxlen, unsigned char *src, int len, char oddflag)
{
	/* User Specified */
	int x;
	char *ptr = (char *) num;

	if (len <= 0) {
		num[0] = '\0';
		return;
	}

	if (((len * 2) + 1) > maxlen) {
		len = (maxlen / 2) - 1;
	}

	for (x = 0; x < (len - 1); ++x) {
		ptr += sprintf(ptr, "%02x", src[x]);
	}

	if (oddflag) {
		/* ODD */
		sprintf(ptr, "%01x", (src[len - 1]) >> 4);
	} else {
		/* EVEN */
		sprintf(ptr, "%02x", src[len - 1]);
	}
}

static int transmit_subaddr_helper(int full_ie, struct pri *ctrl, struct q931_party_subaddress *q931_subaddress, int msgtype, q931_ie *ie, int offset, int len, int order)
{
	size_t datalen;

	if (!q931_subaddress->valid) {
		return 0;
	}

	datalen = q931_subaddress->length;
	if (!q931_subaddress->type) {
		/* 0 = NSAP */
		/* 0 = Odd/Even indicator */
		ie->data[0] = 0x80;
	} else {
		/* 2 = User Specified */
		ie->data[0] = q931_subaddress->odd_even_indicator ? 0xA8 : 0xA0;
	}
	memcpy(ie->data + offset, q931_subaddress->data, datalen);

	return datalen + (offset + 2);
}

static int receive_subaddr_helper(int full_ie, struct pri *ctrl, struct q931_party_subaddress *q931_subaddress, int msgtype, q931_ie *ie, int offset, int len)
{
	int i = -1;

	if (len <= 0) {
		return -1;
	}

	/*
	 * To follow Q.931 (4.5.1), we must search for start of octet 4 by
	 * walking through all bytes until one with ext bit (8) set to 1
	 */
	do {
		++i;
		switch (i) {
		case 0:	/* Octet 3 */
			/* type: 0 = NSAP, 2 = User Specified */
			q931_subaddress->type = ((ie->data[0] & 0x70) >> 4);
			q931_subaddress->odd_even_indicator = (ie->data[0] & 0x08) ? 1 : 0;
			break;
		default: /* Octet 3* extra */
			break;
		}
	} while (!(ie->data[i] & 0x80) && len - i);

	q931_subaddress->valid = 1;
	q931_subaddress->length = len - i;
	q931_memget(q931_subaddress->data, sizeof(q931_subaddress->data),
		ie->data + offset + i, len - i);

	return 0;
}

static void dump_subaddr_helper(int full_ie, struct pri *ctrl, q931_ie *ie, int offset, int len, int datalen, char prefix)
{
	unsigned char cnum[256];
	int i = -1;

	/*
	 * To follow Q.931 (4.5.1), we must search for start of octet 4 by
	 * walking through all bytes until one with ext bit (8) set to 1
	 */
	do {
		++i;
	} while (!(ie->data[i] & 0x80) && datalen - i);

	if (!(ie->data[0] & 0x70)) {
		/* NSAP  Get it as a string for dump display purposes only. */
		q931_strget(cnum, sizeof(cnum), ie->data + offset + i, datalen - i);
	} else {
		/* User Specified */
		q931_get_subaddr_specific(cnum, sizeof(cnum), ie->data + offset + i, datalen - i,
			ie->data[0] & 0x08);
	}

	pri_message(ctrl,
		"%c %s (len=%2d) [ Ext: %d  Type: %s (%d)  O: %d  '%s' ]\n",
		prefix, ie2str(full_ie), len, ie->data[0] >> 7,
		subaddrtype2str((ie->data[0] & 0x70) >> 4), (ie->data[0] & 0x70) >> 4,
		(ie->data[0] & 0x08) >> 3, cnum);
}

static void dump_called_party_number(int full_ie, struct pri *ctrl, q931_ie *ie, int len, char prefix)
{
	unsigned char cnum[256];

	q931_strget(cnum, sizeof(cnum), ie->data + 1, len - 3);
	pri_message(ctrl, "%c %s (len=%2d) [ Ext: %d  TON: %s (%d)  NPI: %s (%d)  '%s' ]\n",
		prefix, ie2str(full_ie), len, ie->data[0] >> 7,
		ton2str((ie->data[0] >> 4) & 0x07), (ie->data[0] >> 4) & 0x07,
		npi2str(ie->data[0] & 0x0f), ie->data[0] & 0x0f, cnum);
}

static void dump_called_party_subaddr(int full_ie, struct pri *ctrl, q931_ie *ie, int len, char prefix)
{
	dump_subaddr_helper(full_ie, ctrl, ie, 1, len, len - 3, prefix);
}

static void dump_calling_party_number(int full_ie, struct pri *ctrl, q931_ie *ie, int len, char prefix)
{
	unsigned char cnum[256];

	if (ie->data[0] & 0x80) {
		q931_strget(cnum, sizeof(cnum), ie->data + 1, len - 3);
	} else {
		q931_strget(cnum, sizeof(cnum), ie->data + 2, len - 4);
	}
	pri_message(ctrl, "%c %s (len=%2d) [ Ext: %d  TON: %s (%d)  NPI: %s (%d)\n",
		prefix, ie2str(full_ie), len, ie->data[0] >> 7,
		ton2str((ie->data[0] >> 4) & 0x07), (ie->data[0] >> 4) & 0x07,
		npi2str(ie->data[0] & 0x0f), ie->data[0] & 0x0f);
	if (ie->data[0] & 0x80) {
		pri_message(ctrl, "%c                                 Presentation: %s (%d)  '%s' ]\n",
			prefix, pri_pres2str(0), 0, cnum);
	} else {
		pri_message(ctrl, "%c                                 Presentation: %s (%d)  '%s' ]\n",
			prefix, pri_pres2str(ie->data[1] & 0x7f), ie->data[1] & 0x7f, cnum);
	}
}

static void dump_calling_party_subaddr(int full_ie, struct pri *ctrl, q931_ie *ie, int len, char prefix)
{
	dump_subaddr_helper(full_ie, ctrl, ie, 1, len, len - 3, prefix);
}

static void dump_calling_party_category(int full_ie, struct pri *ctrl, q931_ie *ie, int len, char prefix)
{
	pri_message(ctrl, "%c %s (len=%2d) [ Ext: %d  Cat: %s (%d) ]\n",
		prefix, ie2str(full_ie), len, ie->data[0] >> 7,
		cpc2str(ie->data[0] & 0x0F), ie->data[0] & 0x0F);
}

static void dump_redirecting_number(int full_ie, struct pri *ctrl, q931_ie *ie, int len, char prefix)
{
	unsigned char cnum[256];
	int i = 0;
	/* To follow Q.931 (4.5.1), we must search for start of octet 4 by
	   walking through all bytes until one with ext bit (8) set to 1 */
	do {
		switch(i) {
		case 0:	/* Octet 3 */
			pri_message(ctrl, "%c %s (len=%2d) [ Ext: %d  TON: %s (%d)  NPI: %s (%d)",
				prefix, ie2str(full_ie), len, ie->data[0] >> 7,
				ton2str((ie->data[0] >> 4) & 0x07), (ie->data[0] >> 4) & 0x07,
				npi2str(ie->data[0] & 0x0f), ie->data[0] & 0x0f);
			break;
		case 1: /* Octet 3a */
			pri_message(ctrl, "\n");
			pri_message(ctrl, "%c                               Ext: %d  Presentation: %s (%d)",
				prefix, ie->data[1] >> 7, pri_pres2str(ie->data[1] & 0x7f), ie->data[1] & 0x7f);
			break;
		case 2: /* Octet 3b */
			pri_message(ctrl, "\n");
			pri_message(ctrl, "%c                               Ext: %d  Reason: %s (%d)",
				prefix, ie->data[2] >> 7, redirection_reason2str(ie->data[2] & 0x7f), ie->data[2] & 0x7f);
			break;
		}
	} while (!(ie->data[i++] & 0x80));
	q931_strget(cnum, sizeof(cnum), ie->data + i, ie->len - i);
	pri_message(ctrl, "  '%s' ]\n", cnum);
}

static void dump_redirection_number(int full_ie, struct pri *ctrl, q931_ie *ie, int len, char prefix)
{
	unsigned char cnum[256];
	int i = 0;
	/* To follow Q.931 (4.5.1), we must search for start of octet 4 by
	   walking through all bytes until one with ext bit (8) set to 1 */
	do {
		switch (i) {
		case 0:	/* Octet 3 */
			pri_message(ctrl, "%c %s (len=%2d) [ Ext: %d  TON: %s (%d)  NPI: %s (%d)",
				prefix, ie2str(full_ie), len, ie->data[0] >> 7,
				ton2str((ie->data[0] >> 4) & 0x07), (ie->data[0] >> 4) & 0x07,
				npi2str(ie->data[0] & 0x0f), ie->data[0] & 0x0f);
			break;
		case 1: /* Octet 3a */
			pri_message(ctrl, "\n");
			pri_message(ctrl, "%c                               Ext: %d  Presentation: %s (%d)",
				prefix, ie->data[1] >> 7, pri_pres2str(ie->data[1] & 0x7f), ie->data[1] & 0x7f);
			break;
		}
	} while (!(ie->data[i++] & 0x80));
	q931_strget(cnum, sizeof(cnum), ie->data + i, ie->len - i);
	pri_message(ctrl, "  '%s' ]\n", cnum);
}

static int receive_connected_number(int full_ie, struct pri *ctrl, q931_call *call, int msgtype, q931_ie *ie, int len)
{
	int i = 0;

	/* Reference Q.951 Section 5.4.1 for ie */
	call->connected_number_in_message = 1;
	call->remote_id.number.valid = 1;
	call->remote_id.number.presentation =
		PRI_PRES_ALLOWED | PRI_PRES_USER_NUMBER_UNSCREENED;
	/* To follow Q.931 (4.5.1), we must search for start of octet 4 by
	   walking through all bytes until one with ext bit (8) set to 1 */
	do {
		switch (i) {
		case 0:
			call->remote_id.number.plan = ie->data[i] & 0x7f;

			/*
			 * Work around a bug in a Lucent switch implementation that
			 * sets the extension bit in octet 3 even though octet 3a
			 * is present.
			 *
			 * The same issue was seen in a NI2 switch implementation.
			 * It was probably a Lucent switch configured for NI2
			 * operation.  To avoid further surprises, I'm going to
			 * enable the work around for all North American switch
			 * types.
			 */
			if (ie->data[i] & 0x80) {
				/* Octet 3 extension bit is set */
				if (ctrl->switchtype != PRI_SWITCH_LUCENT5E
					&& ctrl->switchtype != PRI_SWITCH_ATT4ESS
					&& ctrl->switchtype != PRI_SWITCH_NI1
					&& ctrl->switchtype != PRI_SWITCH_NI2
					&& ctrl->switchtype != PRI_SWITCH_DMS100) {
					/* Not a potentially buggy switch type. */
					break;
				}
				if (!(ie->data[i + 1] & 0x80)) {
					/*
					 * The possible octet 3a doesn't have the extension
					 * bit set.  It is likely not the erroneous octet 3a.
					 */
					break;
				}
			}
			/* Octet 3a is present */
			++i;
			/* Fall through */
		case 1:
			/* Keep only the presentation and screening fields */
			call->remote_id.number.presentation =
				ie->data[i] & (PRI_PRES_RESTRICTION | PRI_PRES_NUMBER_TYPE);
			break;
		}
	} while (!(ie->data[i++] & 0x80));
	q931_strget_gripe(ctrl, ie2str(full_ie), (unsigned char *) call->remote_id.number.str,
		sizeof(call->remote_id.number.str), ie->data + i, ie->len - i);

	return 0;
}

static int transmit_connected_number(int full_ie, struct pri *ctrl, q931_call *call, int msgtype, q931_ie *ie, int len, int order)
{
	size_t datalen;

	if (!call->local_id.number.valid) {
		return 0;
	}

	datalen = strlen(call->local_id.number.str);
	ie->data[0] = call->local_id.number.plan;
	ie->data[1] = 0x80 | call->local_id.number.presentation;
	memcpy(ie->data + 2, call->local_id.number.str, datalen);
	return datalen + (2 + 2);
}

static void dump_connected_number(int full_ie, struct pri *ctrl, q931_ie *ie, int len, char prefix)
{
	unsigned char cnum[256];
	int i = 0;
	/* To follow Q.931 (4.5.1), we must search for start of octet 4 by
	   walking through all bytes until one with ext bit (8) set to 1 */
	do {
		switch(i) {
		case 0:	/* Octet 3 */
			pri_message(ctrl, "%c %s (len=%2d) [ Ext: %d  TON: %s (%d)  NPI: %s (%d)",
				prefix, ie2str(full_ie), len, ie->data[0] >> 7,
				ton2str((ie->data[0] >> 4) & 0x07), (ie->data[0] >> 4) & 0x07,
				npi2str(ie->data[0] & 0x0f), ie->data[0] & 0x0f);

			/*
			 * Work around a bug in a Lucent switch implementation that
			 * sets the extension bit in octet 3 even though octet 3a
			 * is present.
			 *
			 * The same issue was seen in a NI2 switch implementation.
			 * It was probably a Lucent switch configured for NI2
			 * operation.  To avoid further surprises, I'm going to
			 * enable the work around for all North American switch
			 * types.
			 */
			if (ie->data[i] & 0x80) {
				/* Octet 3 extension bit is set */
				if (ctrl->switchtype != PRI_SWITCH_LUCENT5E
					&& ctrl->switchtype != PRI_SWITCH_ATT4ESS
					&& ctrl->switchtype != PRI_SWITCH_NI1
					&& ctrl->switchtype != PRI_SWITCH_NI2
					&& ctrl->switchtype != PRI_SWITCH_DMS100) {
					/* Not a potentially buggy switch type. */
					break;
				}
				if (!(ie->data[i + 1] & 0x80)) {
					/*
					 * The possible octet 3a doesn't have the extension
					 * bit set.  It is likely not the erroneous octet 3a.
					 */
					break;
				}
				pri_message(ctrl, "\n");
				pri_message(ctrl, "%c                             Switch bug workaround.\n",
					prefix);
				pri_message(ctrl, "%c                             Assuming octet 3a is present.",
					prefix);
			}
			/* Octet 3a is present */
			++i;
			/* Fall through */
		case 1: /* Octet 3a */
			pri_message(ctrl, "\n");
			pri_message(ctrl, "%c                             Ext: %d  Presentation: %s (%d)",
				prefix, ie->data[1] >> 7, pri_pres2str(ie->data[1] & 0x7f), ie->data[1] & 0x7f);
			break;
		}
	} while(!(ie->data[i++]& 0x80));
	q931_strget(cnum, sizeof(cnum), ie->data + i, ie->len - i);
	pri_message(ctrl, "  '%s' ]\n", cnum);
}

static int receive_connected_subaddr(int full_ie, struct pri *ctrl, q931_call *call, int msgtype, q931_ie *ie, int len)
{
	if (len < 3) {
		return -1;
	}

	return receive_subaddr_helper(full_ie, ctrl, &call->remote_id.subaddress, msgtype, ie,
		1, len - 3);
}

static int transmit_connected_subaddr(int full_ie, struct pri *ctrl, q931_call *call, int msgtype, q931_ie *ie, int len, int order)
{
	return transmit_subaddr_helper(full_ie, ctrl, &call->local_id.subaddress, msgtype, ie,
		1, len, order);
}

static void dump_connected_subaddr(int full_ie, struct pri *ctrl, q931_ie *ie, int len, char prefix)
{
	dump_subaddr_helper(full_ie, ctrl, ie, 1, len, len - 3, prefix);
}

static int receive_redirecting_number(int full_ie, struct pri *ctrl, q931_call *call, int msgtype, q931_ie *ie, int len)
{
	int i = 0;

	/* Reference Q.952 Section 4.1.2 for ie */
	call->redirecting_number_in_message = 1;
	call->redirecting.from.number.valid = 1;
	call->redirecting.from.number.presentation =
		PRI_PRES_ALLOWED | PRI_PRES_USER_NUMBER_UNSCREENED;
	call->redirecting.reason = PRI_REDIR_UNKNOWN;
	/* To follow Q.931 (4.5.1), we must search for start of octet 4 by
	   walking through all bytes until one with ext bit (8) set to 1 */
	do {
		switch (i) {
		case 0:
			call->redirecting.from.number.plan = ie->data[i] & 0x7f;
			break;
		case 1:
			/* Keep only the presentation and screening fields */
			call->redirecting.from.number.presentation =
				ie->data[i] & (PRI_PRES_RESTRICTION | PRI_PRES_NUMBER_TYPE);
			break;
		case 2:
			call->redirecting.reason = ie->data[i] & 0x0f;
			break;
		}
	} while (!(ie->data[i++] & 0x80));
	q931_strget_gripe(ctrl, ie2str(full_ie),
		(unsigned char *) call->redirecting.from.number.str,
		sizeof(call->redirecting.from.number.str), ie->data + i, ie->len - i);
	return 0;
}

static int transmit_redirecting_number(int full_ie, struct pri *ctrl, q931_call *call, int msgtype, q931_ie *ie, int len, int order)
{
	size_t datalen;

	if (order > 1)
		return 0;
	if (!call->redirecting.from.number.valid) {
		return 0;
	}
	if (BRI_TE_PTMP(ctrl)) {
		/*
		 * We should not send this ie to the network if we are the TE
		 * PTMP side since phones do not redirect calls within
		 * themselves.  Well... If you consider someone else dialing the
		 * handset a redirection then how is the network to know?
		 */
		return 0;
	}
	if (call->redirecting.state != Q931_REDIRECTING_STATE_IDLE) {
		/*
		 * There was a DivertingLegInformation2 in the message so the
		 * Q931_REDIRECTING_NUMBER ie is redundant.  Some networks
		 * (Deutsche Telekom) complain about it.
		 */
		return 0;
	}

	datalen = strlen(call->redirecting.from.number.str);
	ie->data[0] = call->redirecting.from.number.plan;
#if 1
	/* ETSI and Q.952 do not define the screening field */
	ie->data[1] = call->redirecting.from.number.presentation & PRI_PRES_RESTRICTION;
#else
	/* Q.931 defines the screening field */
	ie->data[1] = call->redirecting.from.number.presentation;
#endif
	ie->data[2] = (call->redirecting.reason & 0x0f) | 0x80;
	memcpy(ie->data + 3, call->redirecting.from.number.str, datalen);
	return datalen + (3 + 2);
}

static void dump_redirecting_subaddr(int full_ie, struct pri *ctrl, q931_ie *ie, int len, char prefix)
{
	dump_subaddr_helper(full_ie, ctrl, ie, 2, len, len - 4, prefix);
}

static int receive_redirection_number(int full_ie, struct pri *ctrl, q931_call *call, int msgtype, q931_ie *ie, int len)
{
	int i = 0;

	/* Reference Q.952 Section 4.1.3 for ie */
	call->redirection_number.valid = 1;
	call->redirection_number.presentation =
		PRI_PRES_ALLOWED | PRI_PRES_USER_NUMBER_UNSCREENED;
	/* To follow Q.931 (4.5.1), we must search for start of octet 4 by
	   walking through all bytes until one with ext bit (8) set to 1 */
	do {
		switch (i) {
		case 0:
			call->redirection_number.plan = ie->data[i] & 0x7f;
			break;
		case 1:
			/* Keep only the presentation and screening fields */
			call->redirection_number.presentation =
				ie->data[i] & (PRI_PRES_RESTRICTION | PRI_PRES_NUMBER_TYPE);
			break;
		}
	} while (!(ie->data[i++] & 0x80));
	q931_strget_gripe(ctrl, ie2str(full_ie),
		(unsigned char *) call->redirection_number.str,
		sizeof(call->redirection_number.str), ie->data + i, ie->len - i);
	return 0;
}

static int transmit_redirection_number(int full_ie, struct pri *ctrl, q931_call *call, int msgtype, q931_ie *ie, int len, int order)
{
	size_t datalen;

	if (order > 1) {
		return 0;
	}
	if (!call->redirection_number.valid) {
		return 0;
	}

	datalen = strlen(call->redirection_number.str);
	ie->data[0] = call->redirection_number.plan;
	ie->data[1] = (call->redirection_number.presentation & PRI_PRES_RESTRICTION) | 0x80;
	memcpy(ie->data + 2, call->redirection_number.str, datalen);
	return datalen + (2 + 2);
}

static int receive_calling_party_subaddr(int full_ie, struct pri *ctrl, q931_call *call, int msgtype, q931_ie *ie, int len)
{
	if (len < 3) {
		return -1;
	}

	return receive_subaddr_helper(full_ie, ctrl, &call->remote_id.subaddress, msgtype, ie,
		1, len - 3);
}

static int transmit_calling_party_subaddr(int full_ie, struct pri *ctrl, q931_call *call, int msgtype, q931_ie *ie, int len, int order)
{
	return transmit_subaddr_helper(full_ie, ctrl, &call->local_id.subaddress, msgtype, ie,
		1, len, order);
}

static int receive_called_party_subaddr(int full_ie, struct pri *ctrl, q931_call *call, int msgtype, q931_ie *ie, int len)
{
	if (len < 3) {
		return -1;
	}
	return receive_subaddr_helper(full_ie, ctrl, &call->called.subaddress, msgtype, ie, 1,
		len - 3);
}

static int transmit_called_party_subaddr(int full_ie, struct pri *ctrl, q931_call *call, int msgtype, q931_ie *ie, int len, int order)
{
	return transmit_subaddr_helper(full_ie, ctrl, &call->called.subaddress, msgtype, ie,
		1, len, order);
}

static int receive_called_party_number(int full_ie, struct pri *ctrl, q931_call *call, int msgtype, q931_ie *ie, int len)
{
	size_t called_len;
	size_t max_len;
	char *called_end;

	if (len < 3) {
		return -1;
	}

	switch (msgtype) {
	case Q931_FACILITY:
		if (!q931_is_dummy_call(call)) {
			/* Discard the number. */
			return 0;
		}
		/* Fall through */
	case Q931_REGISTER:
		/* Accept the number for REGISTER only because it is so similar to SETUP. */
	case Q931_SETUP:
		q931_strget((unsigned char *) call->called.number.str,
			sizeof(call->called.number.str), ie->data + 1, len - 3);
		break;
	case Q931_INFORMATION:
		if (call->ourcallstate == Q931_CALL_STATE_OVERLAP_RECEIVING) {
			/*
			 * Since we are receiving overlap digits now, we need to append
			 * them to any previously received digits in call->called.number.str.
			 */
			called_len = strlen(call->called.number.str);
			called_end = call->called.number.str + called_len;
			max_len = (sizeof(call->called.number.str) - 1) - called_len;
			if (max_len < len - 3) {
				called_len = max_len;
			} else {
				called_len = len - 3;
			}
			strncat(called_end, (char *) ie->data + 1, called_len);
		}
		break;
	default:
		/* Discard the number. */
		return 0;
	}
	call->called.number.valid = 1;
	call->called.number.plan = ie->data[0] & 0x7f;

	q931_strget_gripe(ctrl, ie2str(full_ie), (unsigned char *) call->overlap_digits,
		sizeof(call->overlap_digits), ie->data + 1, len - 3);
	return 0;
}

static int transmit_called_party_number(int full_ie, struct pri *ctrl, q931_call *call, int msgtype, q931_ie *ie, int len, int order)
{
	size_t datalen;

	if (!call->called.number.valid) {
		return 0;
	}

	datalen = strlen(call->overlap_digits);
	ie->data[0] = 0x80 | call->called.number.plan;
	memcpy(ie->data + 1, call->overlap_digits, datalen);
	return datalen + (1 + 2);
}

static int receive_calling_party_number(int full_ie, struct pri *ctrl, q931_call *call, int msgtype, q931_ie *ie, int len)
{
	int i = 0;
	struct q931_party_number number;

	/* Reference Q.931 Section 4.5.10 for ie */
	q931_party_number_init(&number);
	number.valid = 1;
	number.presentation = PRI_PRES_ALLOWED | PRI_PRES_USER_NUMBER_UNSCREENED;

	/* To follow Q.931 (4.5.1), we must search for start of octet 4 by
	   walking through all bytes until one with ext bit (8) set to 1 */
	do {
		switch (i) {
		case 0:
			number.plan = ie->data[i] & 0x7f;
			break;
		case 1:
			/* Keep only the presentation and screening fields */
			number.presentation =
				ie->data[i] & (PRI_PRES_RESTRICTION | PRI_PRES_NUMBER_TYPE);
			break;
		}
	} while (!(ie->data[i++] & 0x80));
	q931_strget_gripe(ctrl, ie2str(full_ie), (unsigned char *) number.str,
		sizeof(number.str), ie->data + i, ie->len - i);

	/* There can be more than one calling party number ie in the SETUP message. */
	if (number.presentation == (PRI_PRES_ALLOWED | PRI_PRES_NETWORK_NUMBER)
		|| number.presentation == (PRI_PRES_RESTRICTED | PRI_PRES_NETWORK_NUMBER)) {
		/* The number is network provided so it is an ANI number. */
		call->ani = number;
		if (!call->remote_id.number.valid) {
			/* Copy ANI to CallerID if CallerID is not already set. */
			call->remote_id.number = number;
		}
	} else {
		call->remote_id.number = number;
	}

	return 0;
}

static int transmit_calling_party_number(int full_ie, struct pri *ctrl, q931_call *call, int msgtype, q931_ie *ie, int len, int order)
{
	size_t datalen;

	if (!call->local_id.number.valid) {
		return 0;
	}

	datalen = strlen(call->local_id.number.str);
	ie->data[0] = call->local_id.number.plan;
	ie->data[1] = 0x80 | call->local_id.number.presentation;
	memcpy(ie->data + 2, call->local_id.number.str, datalen);
	return datalen + (2 + 2);
}

static void dump_user_user(int full_ie, struct pri *ctrl, q931_ie *ie, int len, char prefix)
{
	int x;

	pri_message(ctrl, "%c %s (len=%2d) [", prefix, ie2str(full_ie), len);
	for (x = 0; x < ie->len; ++x) {
		pri_message(ctrl, " %02x", ie->data[x] & 0x7f);
	}
	pri_message(ctrl, " ]\n");
}


static int receive_user_user(int full_ie, struct pri *ctrl, q931_call *call, int msgtype, q931_ie *ie, int len)
{
	call->useruserprotocoldisc = ie->data[0] & 0xff;
	if (call->useruserprotocoldisc == 4) { /* IA5 */
		q931_memget((unsigned char *) call->useruserinfo, sizeof(call->useruserinfo), ie->data + 1, len - 3);
	}
	return 0;
}

static int transmit_user_user(int full_ie, struct pri *ctrl, q931_call *call, int msgtype, q931_ie *ie, int len, int order)
{        
	int datalen = strlen(call->useruserinfo);
	if (datalen > 0) {
		/* Restricted to 35 characters */
		if (msgtype == Q931_USER_INFORMATION) {
			if (datalen > 260)
				datalen = 260;
		} else {
			if (datalen > 35)
				datalen = 35;
		}
		ie->data[0] = 4; /* IA5 characters */
		memcpy(&ie->data[1], call->useruserinfo, datalen);
		call->useruserinfo[0] = '\0';
		return datalen + 3;
	}

	return 0;
}

static void dump_change_status(int full_ie, struct pri *ctrl, q931_ie *ie, int len, char prefix)
{
	int x;

	pri_message(ctrl, "%c %s (len=%2d) [", prefix, ie2str(full_ie), len);
	for (x = 0; x < ie->len; ++x) {
		pri_message(ctrl, " %02x", ie->data[x] & 0x7f);
	}
	pri_message(ctrl, " ]\n");

	switch (ctrl->switchtype) {
	case PRI_SWITCH_NI2:
	case PRI_SWITCH_DMS100:
	case PRI_SWITCH_LUCENT5E:
	case PRI_SWITCH_ATT4ESS:
		break;
	default:
		/* ie not supported by this switch type */
		pri_message(ctrl, "%c   %s is treated as unknown by current switch type.\n",
			prefix, ie2str(full_ie));
		break;
	}
}

static int receive_change_status(int full_ie, struct pri *ctrl, q931_call *call, int msgtype, q931_ie *ie, int len)
{
	switch (ctrl->switchtype) {
	case PRI_SWITCH_NI2:
	case PRI_SWITCH_DMS100:
	case PRI_SWITCH_LUCENT5E:
	case PRI_SWITCH_ATT4ESS:
		break;
	default:
		/* ie not supported by this switch type */
		return -1;
	}
	call->changestatus = ie->data[0] & 0x0f;
	return 0;
}

static int transmit_change_status(int full_ie, struct pri *ctrl, q931_call *call, int msgtype, q931_ie *ie, int len, int order)
{
	ie->data[0] = 0xc0 | call->changestatus;
	return 3;
}

static char *prog2str(int prog)
{
	static struct msgtype progs[] = {
		{ Q931_PROG_CALL_NOT_E2E_ISDN, "Call is not end-to-end ISDN; further call progress information may be available inband." },
		{ Q931_PROG_CALLED_NOT_ISDN, "Called equipment is non-ISDN." },
		{ Q931_PROG_CALLER_NOT_ISDN, "Calling equipment is non-ISDN." },
		{ Q931_PROG_INBAND_AVAILABLE, "Inband information or appropriate pattern now available." },
		{ Q931_PROG_DELAY_AT_INTERF, "Delay in response at called Interface." },
		{ Q931_PROG_INTERWORKING_WITH_PUBLIC, "Interworking with a public network." },
		{ Q931_PROG_INTERWORKING_NO_RELEASE, "Interworking with a network unable to supply a release signal." },
		{ Q931_PROG_INTERWORKING_NO_RELEASE_PRE_ANSWER, "Interworking with a network unable to supply a release signal before answer." },
		{ Q931_PROG_INTERWORKING_NO_RELEASE_POST_ANSWER, "Interworking with a network unable to supply a release signal after answer." },
	};
	return code2str(prog, progs, sizeof(progs) / sizeof(progs[0]));
}

static char *coding2str(int cod)
{
	static struct msgtype cods[] = {
		{ CODE_CCITT, "CCITT (ITU) standard" },
		{ CODE_INTERNATIONAL, "Non-ITU international standard" }, 
		{ CODE_NATIONAL, "National standard" }, 
		{ CODE_NETWORK_SPECIFIC, "Network specific standard" },
	};
	return code2str(cod, cods, sizeof(cods) / sizeof(cods[0]));
}

static char *loc2str(int loc)
{
	static struct msgtype locs[] = {
		{ LOC_USER, "User" },
		{ LOC_PRIV_NET_LOCAL_USER, "Private network serving the local user" },
		{ LOC_PUB_NET_LOCAL_USER, "Public network serving the local user" },
		{ LOC_TRANSIT_NET, "Transit network" },
		{ LOC_PUB_NET_REMOTE_USER, "Public network serving the remote user" },
		{ LOC_PRIV_NET_REMOTE_USER, "Private network serving the remote user" },
		{ LOC_INTERNATIONAL_NETWORK, "International network" },
		{ LOC_NETWORK_BEYOND_INTERWORKING, "Network beyond the interworking point" },
	};
	return code2str(loc, locs, sizeof(locs) / sizeof(locs[0]));
}

static void dump_progress_indicator(int full_ie, struct pri *ctrl, q931_ie *ie, int len, char prefix)
{
	pri_message(ctrl,
		"%c %s (len=%2d) [ Ext: %d  Coding: %s (%d)  0: %d  Location: %s (%d)\n",
		prefix, ie2str(full_ie), len, ie->data[0] >> 7,
		coding2str((ie->data[0] & 0x60) >> 5), (ie->data[0] & 0x60) >> 5,
		(ie->data[0] & 0x10) >> 4, loc2str(ie->data[0] & 0xf), ie->data[0] & 0xf);
	pri_message(ctrl, "%c                               Ext: %d  Progress Description: %s (%d) ]\n",
		prefix, ie->data[1] >> 7, prog2str(ie->data[1] & 0x7f), ie->data[1] & 0x7f);
}

static int receive_display(int full_ie, struct pri *ctrl, q931_call *call, int msgtype, q931_ie *ie, int len)
{
	u_int8_t *data;

	if (ctrl->display_flags.receive & PRI_DISPLAY_OPTION_BLOCK) {
		return 0;
	}

	data = ie->data;
	if (data[0] & 0x80) {
		/* Skip over character set */
		data++;
		len--;
	}

	call->display.text = data;
	call->display.full_ie = full_ie;
	call->display.length = len - 2;
	call->display.char_set = PRI_CHAR_SET_ISO8859_1;
	return 0;
}

static int transmit_display(int full_ie, struct pri *ctrl, q931_call *call, int msgtype, q931_ie *ie, int len, int order)
{
	size_t datalen;
	int i;

	if (!call->display.text || !call->display.length) {
		return 0;
	}
	if (ctrl->display_flags.send & PRI_DISPLAY_OPTION_BLOCK) {
		return 0;
	}

	i = 0;
	switch (ctrl->switchtype) {
	case PRI_SWITCH_QSIG:
	case PRI_SWITCH_EUROISDN_E1:
	case PRI_SWITCH_EUROISDN_T1:
		break;
	default:
		/* Prefix text with character set indicator. */
		ie->data[0] = 0xb1;
		++i;
		break;
	}

	datalen = call->display.length;
	if (MAX_DISPLAY_TEXT < datalen + i) {
		datalen = MAX_DISPLAY_TEXT - i;
	}
	memcpy(ie->data + i, call->display.text, datalen);
	return 2 + i + datalen;
}

static int receive_progress_indicator(int full_ie, struct pri *ctrl, q931_call *call, int msgtype, q931_ie *ie, int len)
{
	call->progloc = ie->data[0] & 0xf;
	call->progcode = (ie->data[0] & 0x60) >> 5;
	call->progress = (ie->data[1] & 0x7f);
	switch (call->progress) {
	case Q931_PROG_CALL_NOT_E2E_ISDN:
		call->progressmask |= PRI_PROG_CALL_NOT_E2E_ISDN;
		break;
	case Q931_PROG_CALLED_NOT_ISDN:
		call->progressmask |= PRI_PROG_CALLED_NOT_ISDN;
		break;
	case Q931_PROG_CALLER_NOT_ISDN:
		call->progressmask |= PRI_PROG_CALLER_NOT_ISDN;
		break;
	case Q931_PROG_CALLER_RETURNED_TO_ISDN:
		call->progressmask |= PRI_PROG_CALLER_RETURNED_TO_ISDN;
		break;
	case Q931_PROG_INBAND_AVAILABLE:
		call->progressmask |= PRI_PROG_INBAND_AVAILABLE;
		break;
	case Q931_PROG_DELAY_AT_INTERF:
		call->progressmask |= PRI_PROG_DELAY_AT_INTERF;
		break;
	case Q931_PROG_INTERWORKING_WITH_PUBLIC:
		call->progressmask |= PRI_PROG_INTERWORKING_WITH_PUBLIC;
		break;
	case Q931_PROG_INTERWORKING_NO_RELEASE:
		call->progressmask |= PRI_PROG_INTERWORKING_NO_RELEASE;
		break;
	case Q931_PROG_INTERWORKING_NO_RELEASE_PRE_ANSWER:
		call->progressmask |= PRI_PROG_INTERWORKING_NO_RELEASE_PRE_ANSWER;
		break;
	case Q931_PROG_INTERWORKING_NO_RELEASE_POST_ANSWER:
		call->progressmask |= PRI_PROG_INTERWORKING_NO_RELEASE_POST_ANSWER;
		break;
	default:
		pri_error(ctrl, "XXX Invalid Progress indicator value received: %02x\n",(ie->data[1] & 0x7f));
		return -1;
	}
	return 0;
}

static void q931_apdu_timeout(void *data);

static int transmit_facility(int full_ie, struct pri *ctrl, q931_call *call, int msgtype, q931_ie *ie, int len, int order)
{
	struct apdu_event **prev;
	struct apdu_event *cur;
	int apdu_len;

	for (prev = &call->apdus, cur = call->apdus;
		cur;
		prev = &cur->next, cur = cur->next) {
		if (!cur->sent && (cur->message == msgtype || cur->message == Q931_ANY_MESSAGE)) {
			break;
		}
	}
	if (!cur) {
		/* No APDU found */
		return 0;
	}

	if (ctrl->debug & PRI_DEBUG_APDU) {
		pri_message(ctrl, "Adding facility ie contents to send in %s message:\n",
			msg2str(msgtype));
		facility_decode_dump(ctrl, cur->apdu, cur->apdu_len);
	}

	if (len < cur->apdu_len) { 
		pri_error(ctrl,
			"Could not fit facility ie in message.  Size needed:%d  Available space:%d\n",
			cur->apdu_len + 2, len);

		/* Remove APDU from list. */
		*prev = cur->next;

		if (cur->response.callback) {
			/* Indicate to callback that the APDU had a problem getting sent. */
			cur->response.callback(APDU_CALLBACK_REASON_ERROR, ctrl, call, cur, NULL);
		}

		free(cur);
		return 0;
	}

	memcpy(ie->data, cur->apdu, cur->apdu_len);
	apdu_len = cur->apdu_len;
	cur->sent = 1;

	if (cur->response.callback && cur->response.timeout_time) {
		int failed;

		if (0 < cur->response.timeout_time) {
			/* Sender specified a timeout duration. */
			cur->timer = pri_schedule_event(ctrl, cur->response.timeout_time,
				q931_apdu_timeout, cur);
			failed = !cur->timer;
		} else {
			/* Sender wants to "timeout" only when specified messages are received. */
			failed = !cur->response.num_messages;
		}
		if (failed) {
			/* Remove APDU from list. */
			*prev = cur->next;

			/* Indicate to callback that the APDU had a problem getting sent. */
			cur->response.callback(APDU_CALLBACK_REASON_ERROR, ctrl, call, cur, NULL);

			free(cur);
		}
	} else {
		/* Remove APDU from list. */
		*prev = cur->next;
		free(cur);
	}

	return apdu_len + 2;
}

static int receive_facility(int full_ie, struct pri *ctrl, q931_call *call, int msgtype, q931_ie *ie, int len)
{
	/* Delay processing facility ie's till after all other ie's are processed. */
	if (MAX_FACILITY_IES <= ctrl->facility.count) {
		pri_message(ctrl, "!! Too many facility ie's to delay.\n");
		return -1;
	}
	/* Make sure we have enough room for the protocol profile ie octet(s) */
	if (ie->data + ie->len < ie->data + 2) {
		return -1;
	}

	/* Save the facility ie location for delayed decode. */
	ctrl->facility.ie[ctrl->facility.count] = ie;
	ctrl->facility.codeset[ctrl->facility.count] = Q931_IE_CODESET((unsigned) full_ie);
	++ctrl->facility.count;
	return 0;
}

static int process_facility(struct pri *ctrl, q931_call *call, int msgtype, q931_ie *ie)
{
	struct fac_extension_header header;
	struct rose_message rose;
	const unsigned char *pos;
	const unsigned char *end;

	pos = ie->data;
	end = ie->data + ie->len;

	/* Make sure we have enough room for the protocol profile ie octet(s) */
	if (end < pos + 2) {
		return -1;
	}
	switch (*pos & Q932_PROTOCOL_MASK) {
	case Q932_PROTOCOL_ROSE:
	case Q932_PROTOCOL_EXTENSIONS:
		break;
	default:
	case Q932_PROTOCOL_CMIP:
	case Q932_PROTOCOL_ACSE:
		if (ctrl->debug & PRI_DEBUG_APDU) {
			pri_message(ctrl,
				"!! Don't know how to handle Q.932 Protocol Profile type 0x%X\n",
				*pos & Q932_PROTOCOL_MASK);
		}
		return -1;
	}
	if (!(*pos & 0x80)) {
		/* DMS-100 Service indicator octet - Just ignore for now */
		++pos;
	}
	++pos;

	if (ctrl->debug & PRI_DEBUG_APDU) {
		asn1_dump(ctrl, pos, end);
	}

	pos = fac_dec_extension_header(ctrl, pos, end, &header);
	if (!pos) {
		return -1;
	}
	if (header.npp_present) {
		if (ctrl->debug & PRI_DEBUG_APDU) {
			pri_message(ctrl,
				"!! Don't know how to handle Network Protocol Profile type 0x%X\n",
				header.npp);
		}
		return -1;
	}

	/* Process all components in the facility. */
	while (pos < end) {
		pos = rose_decode(ctrl, pos, end, &rose);
		if (!pos) {
			return -1;
		}
		switch (rose.type) {
		case ROSE_COMP_TYPE_INVOKE:
			rose_handle_invoke(ctrl, call, msgtype, ie, &header, &rose.component.invoke);
			break;
		case ROSE_COMP_TYPE_RESULT:
			rose_handle_result(ctrl, call, msgtype, ie, &header, &rose.component.result);
			break;
		case ROSE_COMP_TYPE_ERROR:
			rose_handle_error(ctrl, call, msgtype, ie, &header, &rose.component.error);
			break;
		case ROSE_COMP_TYPE_REJECT:
			rose_handle_reject(ctrl, call, msgtype, ie, &header, &rose.component.reject);
			break;
		default:
			return -1;
		}
	}
	return 0;
}

static void q931_handle_facilities(struct pri *ctrl, q931_call *call, int msgtype)
{
	unsigned idx;
	unsigned codeset;
	unsigned full_ie;
	q931_ie *ie;

	for (idx = 0; idx < ctrl->facility.count; ++idx) {
		ie = ctrl->facility.ie[idx];
		if (ctrl->debug & PRI_DEBUG_Q931_STATE) {
			codeset = ctrl->facility.codeset[idx];
			full_ie = Q931_FULL_IE(codeset, ie->ie);
			pri_message(ctrl, "-- Delayed processing IE %d (cs%d, %s)\n", ie->ie, codeset, ie2str(full_ie));
		}
		process_facility(ctrl, call, msgtype, ie);
	}
}

/*!
 * \internal
 * \brief Check if any APDU responses "timeout" with the current Q.931 message.
 *
 * \param ctrl D channel controller.
 * \param call Q.931 call leg.
 * \param msgtype Q.931 message type received.
 *
 * \return Nothing
 */
static void q931_apdu_msg_expire(struct pri *ctrl, struct q931_call *call, int msgtype)
{
	struct apdu_event **prev;
	struct apdu_event **prev_next;
	struct apdu_event *cur;
	unsigned idx;

	for (prev = &call->apdus; *prev; prev = prev_next) {
		cur = *prev;
		prev_next = &cur->next;
		if (cur->sent) {
			for (idx = 0; idx < cur->response.num_messages; ++idx) {
				if (cur->response.message_type[idx] == msgtype) {
					/*
					 * APDU response message "timeout".
					 *
					 * Extract the APDU from the list so it cannot be
					 * deleted from under us by the callback.
					 */
					prev_next = prev;
					*prev = cur->next;

					/* Stop any response timeout. */
					pri_schedule_del(ctrl, cur->timer);
					cur->timer = 0;

					cur->response.callback(APDU_CALLBACK_REASON_TIMEOUT, ctrl, call, cur, NULL);

					free(cur);
					break;
				}
			}
		}
	}
}

static int transmit_progress_indicator(int full_ie, struct pri *ctrl, q931_call *call, int msgtype, q931_ie *ie, int len, int order)
{
	int code;
	int mask;

	/* Can't send progress indicator on GR-303 -- EVER! */
	if (ctrl->link.next && !ctrl->bri)
		return 0;
	if (call->progressmask > 0) {
		if (call->progressmask & (mask = PRI_PROG_CALL_NOT_E2E_ISDN))
			code = Q931_PROG_CALL_NOT_E2E_ISDN;
		else if (call->progressmask & (mask = PRI_PROG_CALLED_NOT_ISDN))
			code = Q931_PROG_CALLED_NOT_ISDN;
		else if (call->progressmask & (mask = PRI_PROG_CALLER_NOT_ISDN))
			code = Q931_PROG_CALLER_NOT_ISDN;
		else if (call->progressmask & (mask = PRI_PROG_INBAND_AVAILABLE))
			code = Q931_PROG_INBAND_AVAILABLE;
		else if (call->progressmask & (mask = PRI_PROG_DELAY_AT_INTERF))
			code = Q931_PROG_DELAY_AT_INTERF;
		else if (call->progressmask & (mask = PRI_PROG_INTERWORKING_WITH_PUBLIC))
			code = Q931_PROG_INTERWORKING_WITH_PUBLIC;
		else if (call->progressmask & (mask = PRI_PROG_INTERWORKING_NO_RELEASE))
			code = Q931_PROG_INTERWORKING_NO_RELEASE;
		else if (call->progressmask & (mask = PRI_PROG_INTERWORKING_NO_RELEASE_PRE_ANSWER))
			code = Q931_PROG_INTERWORKING_NO_RELEASE_PRE_ANSWER;
		else if (call->progressmask & (mask = PRI_PROG_INTERWORKING_NO_RELEASE_POST_ANSWER))
			code = Q931_PROG_INTERWORKING_NO_RELEASE_POST_ANSWER;
		else {
			code = 0;
			pri_error(ctrl, "XXX Undefined progress bit: %x\n", call->progressmask);
		}
		if (code) {
			ie->data[0] = 0x80 | (call->progcode << 5)  | (call->progloc);
			ie->data[1] = 0x80 | code;
			call->progressmask &= ~mask;
			return 4;
		}
	}
	/* Leave off */
	return 0;
}
static int transmit_call_state(int full_ie, struct pri *ctrl, q931_call *call, int msgtype, q931_ie *ie, int len, int order)
{
	ie->data[0] = Q931_CALL_STATE_NULL;
	switch (call->ourcallstate) {
	case Q931_CALL_STATE_NULL:
	case Q931_CALL_STATE_CALL_INITIATED:
	case Q931_CALL_STATE_OVERLAP_SENDING:
	case Q931_CALL_STATE_OUTGOING_CALL_PROCEEDING:
	case Q931_CALL_STATE_CALL_DELIVERED:
	case Q931_CALL_STATE_CALL_PRESENT:
	case Q931_CALL_STATE_CALL_RECEIVED:
	case Q931_CALL_STATE_CONNECT_REQUEST:
	case Q931_CALL_STATE_INCOMING_CALL_PROCEEDING:
	case Q931_CALL_STATE_ACTIVE:
	case Q931_CALL_STATE_DISCONNECT_REQUEST:
	case Q931_CALL_STATE_DISCONNECT_INDICATION:
	case Q931_CALL_STATE_SUSPEND_REQUEST:
	case Q931_CALL_STATE_RESUME_REQUEST:
	case Q931_CALL_STATE_RELEASE_REQUEST:
	case Q931_CALL_STATE_CALL_ABORT:
	case Q931_CALL_STATE_OVERLAP_RECEIVING:
	case Q931_CALL_STATE_CALL_INDEPENDENT_SERVICE:
	case Q931_CALL_STATE_RESTART_REQUEST:
	case Q931_CALL_STATE_RESTART:
		ie->data[0] = call->ourcallstate;
		break;
	case Q931_CALL_STATE_NOT_SET:
		break;
	}
	return 3;
}

static int receive_call_state(int full_ie, struct pri *ctrl, q931_call *call, int msgtype, q931_ie *ie, int len)
{
	call->sugcallstate = ie->data[0] & 0x3f;
	return 0;
}

/*!
 * \brief Convert the internal Q.931 call state to a string.
 *
 * \param callstate Internal Q.931 call state.
 *
 * \return String equivalent of the given Q.931 call state.
 */
const char *q931_call_state_str(enum Q931_CALL_STATE callstate)
{
	static struct msgtype callstates[] = {
/* *INDENT-OFF* */
		{ Q931_CALL_STATE_NULL,                     "Null" },
		{ Q931_CALL_STATE_CALL_INITIATED,           "Call Initiated" },
		{ Q931_CALL_STATE_OVERLAP_SENDING,          "Overlap Sending" },
		{ Q931_CALL_STATE_OUTGOING_CALL_PROCEEDING, "Outgoing Call Proceeding" },
		{ Q931_CALL_STATE_CALL_DELIVERED,           "Call Delivered" },
		{ Q931_CALL_STATE_CALL_PRESENT,             "Call Present" },
		{ Q931_CALL_STATE_CALL_RECEIVED,            "Call Received" },
		{ Q931_CALL_STATE_CONNECT_REQUEST,          "Connect Request" },
		{ Q931_CALL_STATE_INCOMING_CALL_PROCEEDING, "Incoming Call Proceeding" },
		{ Q931_CALL_STATE_ACTIVE,                   "Active" },
		{ Q931_CALL_STATE_DISCONNECT_REQUEST,       "Disconnect Request" },
		{ Q931_CALL_STATE_DISCONNECT_INDICATION,    "Disconnect Indication" },
		{ Q931_CALL_STATE_SUSPEND_REQUEST,          "Suspend Request" },
		{ Q931_CALL_STATE_RESUME_REQUEST,           "Resume Request" },
		{ Q931_CALL_STATE_RELEASE_REQUEST,          "Release Request" },
		{ Q931_CALL_STATE_CALL_ABORT,               "Call Abort" },
		{ Q931_CALL_STATE_OVERLAP_RECEIVING,        "Overlap Receiving" },
		{ Q931_CALL_STATE_CALL_INDEPENDENT_SERVICE, "Call Independent Service" },
		{ Q931_CALL_STATE_RESTART_REQUEST,          "Restart Request" },
		{ Q931_CALL_STATE_RESTART,                  "Restart" },
		{ Q931_CALL_STATE_NOT_SET,                  "Not set. Internal use only." },
/* *INDENT-ON* */
	};
	return code2str(callstate, callstates, ARRAY_LEN(callstates));
}

/*!
 * \internal
 * \brief Convert the Q.932 supplementary hold state to a string.
 *
 * \param state Q.932 supplementary hold state.
 *
 * \return String equivalent of the given hold state.
 */
static const char *q931_hold_state_str(enum Q931_HOLD_STATE state)
{
	static struct msgtype hold_states[] = {
/* *INDENT-OFF* */
		{ Q931_HOLD_STATE_IDLE,         "Idle" },
		{ Q931_HOLD_STATE_HOLD_REQ,     "Hold Request" },
		{ Q931_HOLD_STATE_HOLD_IND,     "Hold Indication" },
		{ Q931_HOLD_STATE_CALL_HELD,    "Call Held" },
		{ Q931_HOLD_STATE_RETRIEVE_REQ, "Retrieve Request" },
		{ Q931_HOLD_STATE_RETRIEVE_IND, "Retrieve Indication" },
/* *INDENT-ON* */
	};
	return code2str(state, hold_states, ARRAY_LEN(hold_states));
}

static void dump_call_state(int full_ie, struct pri *ctrl, q931_ie *ie, int len, char prefix)
{
	pri_message(ctrl, "%c %s (len=%2d) [ Ext: %d  Coding: %s (%d)  Call state: %s (%d)\n",
		prefix, ie2str(full_ie), len, ie->data[0] >> 7,
		coding2str((ie->data[0] & 0xC0) >> 6), (ie->data[0] & 0xC0) >> 6,
		q931_call_state_str(ie->data[0] & 0x3f), ie->data[0] & 0x3f);
}

static void dump_call_identity(int full_ie, struct pri *ctrl, q931_ie *ie, int len, char prefix)
{
	int x;

	pri_message(ctrl, "%c %s (len=%2d) [ ", prefix, ie2str(full_ie), len);
	for (x = 0; x < ie->len; ++x) {
		pri_message(ctrl, "0x%02X ", ie->data[x]);
	}
	pri_message(ctrl, " ]\n");
}

static void dump_time_date(int full_ie, struct pri *ctrl, q931_ie *ie, int len, char prefix)
{
	pri_message(ctrl, "%c %s (len=%2d) [ ", prefix, ie2str(full_ie), len);
	if (ie->len > 0)
		pri_message(ctrl, "%02d", ie->data[0]);
	if (ie->len > 1)
		pri_message(ctrl, "-%02d", ie->data[1]);
	if (ie->len > 2)
		pri_message(ctrl, "-%02d", ie->data[2]);
	if (ie->len > 3)
		pri_message(ctrl, " %02d", ie->data[3]);
	if (ie->len > 4)
		pri_message(ctrl, ":%02d", ie->data[4]);
	if (ie->len > 5)
		pri_message(ctrl, ":%02d", ie->data[5]);
	pri_message(ctrl, " ]\n");
}

static int receive_time_date(int full_ie, struct pri *ctrl, q931_call *call, int msgtype, q931_ie *ie, int len)
{
	/* Ignore incoming Date/Time since we have no use for it at this time. */
	return 0;
}

static int transmit_time_date(int full_ie, struct pri *ctrl, q931_call *call, int msgtype, q931_ie *ie, int len, int order)
{
	time_t now;
	struct tm timedate;
	int ie_len;

	do {
		if (ctrl->date_time_send < PRI_DATE_TIME_SEND_DATE) {
			ie_len = 0;
			break;
		}

		/* Send the current date/time. */
		time(&now);
		localtime_r(&now, &timedate);
		ie->data[0] = timedate.tm_year - 100; /* 1900+ */
		ie->data[1] = timedate.tm_mon + 1;
		ie->data[2] = timedate.tm_mday;
		ie_len = 2 + 3;
		if (ctrl->date_time_send < PRI_DATE_TIME_SEND_DATE_HH) {
			break;
		}

		/* Add optional hour. */
		ie->data[3] = timedate.tm_hour;
		++ie_len;
		if (ctrl->date_time_send < PRI_DATE_TIME_SEND_DATE_HHMM) {
			break;
		}

		/* Add optional minutes. */
		ie->data[4] = timedate.tm_min;
		++ie_len;
		if (ctrl->date_time_send < PRI_DATE_TIME_SEND_DATE_HHMMSS) {
			break;
		}

		/* Add optional seconds. */
		ie->data[5] = timedate.tm_sec;
		++ie_len;
	} while (0);
	return ie_len;
}

static void dump_keypad_facility(int full_ie, struct pri *ctrl, q931_ie *ie, int len, char prefix)
{
	unsigned char tmp[64];

	q931_strget(tmp, sizeof(tmp), ie->data, ie->len);
	pri_message(ctrl, "%c %s (len=%2d) [ %s ]\n", prefix, ie2str(full_ie), ie->len, tmp);
}

static int receive_keypad_facility(int full_ie, struct pri *ctrl, q931_call *call, int msgtype, q931_ie *ie, int len)
{
	if (ie->len == 0)
		return -1;

	q931_strget_gripe(ctrl, ie2str(full_ie), (unsigned char *) call->keypad_digits,
		sizeof(call->keypad_digits), ie->data, ie->len);

	return 0;
}

static int transmit_keypad_facility(int full_ie, struct pri *ctrl, q931_call *call, int msgtype, q931_ie *ie, int len, int order)
{
	int sublen;

	sublen = strlen(call->keypad_digits);
	if (sublen) {
		libpri_copy_string((char *) ie->data, call->keypad_digits, sizeof(call->keypad_digits));
		return sublen + 2;
	} else
		return 0;
}

static void dump_display(int full_ie, struct pri *ctrl, q931_ie *ie, int len, char prefix)
{
	int x;
	unsigned char buf[2*80 + 1];
	char tmp[20 + 1];

	x = 0;
	if (ie->len && (ie->data[x] & 0x80)) {
		snprintf(tmp, sizeof(tmp), "Charset: %02x ", ie->data[x] & 0x7f);
		++x;
	} else {
		tmp[0] = '\0';
	}
	q931_strget(buf, sizeof(buf), &ie->data[x], ie->len - x);
	pri_message(ctrl, "%c %s (len=%2d) %s[ %s ]\n",
		prefix, ie2str(full_ie), ie->len, tmp, buf);
}

#define CHECK_OVERFLOW(limit) \
	if (tmpptr - tmp + limit >= sizeof(tmp)) { \
		*tmpptr = '\0'; \
		pri_message(ctrl, "%s", tmpptr = tmp); \
	}

static void dump_ie_data(struct pri *ctrl, unsigned char *c, int len)
{
	static char hexs[16] = "0123456789ABCDEF";
	char tmp[1024], *tmpptr;
	int lastascii = 0;
	tmpptr = tmp;
	for (; len; --len, ++c) {
		CHECK_OVERFLOW(7);
		if (isprint(*c)) {
			if (!lastascii) {
				if (tmpptr != tmp) { 
					*tmpptr++ = ',';
					*tmpptr++ = ' ';
				}
				*tmpptr++ = '\'';
				lastascii = 1;
			}
			*tmpptr++ = *c;
		} else {
			if (lastascii) {
				*tmpptr++ = '\'';
				lastascii = 0;
			}
			if (tmpptr != tmp) { 
				*tmpptr++ = ',';
				*tmpptr++ = ' ';
			}
			*tmpptr++ = '0';
			*tmpptr++ = 'x';
			*tmpptr++ = hexs[(*c >> 4) & 0x0f];
			*tmpptr++ = hexs[(*c) & 0x0f];
		}
	}
	if (lastascii)
		*tmpptr++ = '\'';
	*tmpptr = '\0';
	pri_message(ctrl, "%s", tmp);
}

static void dump_facility(int full_ie, struct pri *ctrl, q931_ie *ie, int len, char prefix)
{
	pri_message(ctrl, "%c %s (len=%2d, codeset=%d) [ ",
		prefix, ie2str(full_ie), len, Q931_IE_CODESET(full_ie));
	dump_ie_data(ctrl, ie->data, ie->len);
	pri_message(ctrl, " ]\n");
#if 0	/* Lets not dump parse of facility contents here anymore. */
	/*
	 * The ASN.1 decode dump has already been done when the facility ie was added to the outgoing
	 * message or the ASN.1 decode dump will be done when the facility ie is processed on incoming
	 * messages.  This dump is redundant and very noisy.
	 */
	if (ie->len > 1) {
		int dataat = (ie->data[0] & 0x80) ? 1 : 2;

		pri_message(ctrl, "PROTOCOL %02X\n", ie->data[0] & Q932_PROTOCOL_MASK);
		asn1_dump(ctrl, ie->data + dataat, ie->data + ie->len);
	}
#endif	/* Lets not dump parse of facility contents here anymore. */
}

static void dump_network_spec_fac(int full_ie, struct pri *ctrl, q931_ie *ie, int len, char prefix)
{
	pri_message(ctrl, "%c %s (len=%2d) [ ", prefix, ie2str(full_ie), ie->len);
	if (ie->data[0] == 0x00) {
		pri_message(ctrl, "%s", code2str(ie->data[1], facilities, ARRAY_LEN(facilities)));
	} else {
		dump_ie_data(ctrl, ie->data, ie->len);
	}
	pri_message(ctrl, " ]\n");
}

static int receive_network_spec_fac(int full_ie, struct pri *ctrl, q931_call *call, int msgtype, q931_ie *ie, int len)
{
	return 0;
}

static int transmit_network_spec_fac(int full_ie, struct pri *ctrl, q931_call *call, int msgtype, q931_ie *ie, int len, int order)
{
	/* We are ready to transmit single IE only */
	if (order > 1)
		return 0;

	if (ctrl->nsf != PRI_NSF_NONE) {
		ie->data[0] = 0x00;
		ie->data[1] = ctrl->nsf;
		return 4;
	}
	/* Leave off */
	return 0;
}

char *pri_cause2str(int cause)
{
	return code2str(cause, causes, sizeof(causes) / sizeof(causes[0]));
}

static char *pri_causeclass2str(int cause)
{
	static struct msgtype causeclasses[] = {
		{ 0, "Normal Event" },
		{ 1, "Normal Event" },
		{ 2, "Network Congestion (resource unavailable)" },
		{ 3, "Service or Option not Available" },
		{ 4, "Service or Option not Implemented" },
		{ 5, "Invalid message (e.g. parameter out of range)" },
		{ 6, "Protocol Error (e.g. unknown message)" },
		{ 7, "Interworking" },
	};
	return code2str(cause, causeclasses, sizeof(causeclasses) / sizeof(causeclasses[0]));
}

static void dump_cause(int full_ie, struct pri *ctrl, q931_ie *ie, int len, char prefix)
{
	int x;
	int cause_ind = 1;
	int data_ind = 2;

	pri_message(ctrl,
		"%c %s (len=%2d) [ Ext: %d  Coding: %s (%d)  Spare: %d  Location: %s (%d)\n",
		prefix, ie2str(full_ie), len, ie->data[0] >> 7,
		coding2str((ie->data[0] & 0x60) >> 5), (ie->data[0] & 0x60) >> 5,
		(ie->data[0] & 0x10) >> 4, loc2str(ie->data[0] & 0xf), ie->data[0] & 0xf);
	if ((ie->data[0] & 0x80) == 0) {
		const char *recommendation;

		switch (ie->data[1] & 0x7f) {
		case 0x00:
			recommendation = "Q.931";
			break;
		case 0x03:
			recommendation = "X.21";
			break;
		case 0x04:
			recommendation = "X.25";
			break;
		case 0x05:
			recommendation = "Q.1031/Q.1051";
			break;
		default:
			recommendation = "Reserved";
			break;
		}
		pri_message(ctrl, "%c                  Ext: %d  Recommendation: %s (%d)\n",
			prefix, (ie->data[1] >> 7), recommendation, ie->data[1] & 0x7f);

		cause_ind = 2;
		data_ind = 3;
	}
	pri_message(ctrl, "%c                  Ext: %d  Cause: %s (%d), class = %s (%d) ]\n",
		prefix, (ie->data[cause_ind] >> 7), pri_cause2str(ie->data[cause_ind] & 0x7f), ie->data[cause_ind] & 0x7f,
		pri_causeclass2str((ie->data[cause_ind] & 0x7f) >> 4), (ie->data[cause_ind] & 0x7f) >> 4);
	if (ie->len <= data_ind) {
		return;
	}
	/* Dump cause data in readable form */
	switch(ie->data[cause_ind] & 0x7f) {
	case PRI_CAUSE_IE_NONEXIST:
		for (x = data_ind; x < ie->len; x++) {
			pri_message(ctrl, "%c              Cause data %d: %02x (%d, %s IE)\n", prefix, x-1, ie->data[x], ie->data[x], ie2str(ie->data[x]));
		}
		break;
	case PRI_CAUSE_WRONG_CALL_STATE:
		for (x = data_ind; x < ie->len; x++) {
			pri_message(ctrl, "%c              Cause data %d: %02x (%d, %s message)\n", prefix, x-1, ie->data[x], ie->data[x], msg2str(ie->data[x]));
		}
		break;
	case PRI_CAUSE_RECOVERY_ON_TIMER_EXPIRE:
		pri_message(ctrl, "%c              Cause data:", prefix);
		for (x = data_ind; x < ie->len; x++) {
			pri_message(ctrl, " %02x", ie->data[x]);
		}
		pri_message(ctrl, " (Timer T");
		for (x = data_ind; x < ie->len; x++) {
			pri_message(ctrl, "%c", ((ie->data[x] >= ' ') && (ie->data[x] < 0x7f)) ? ie->data[x] : '.');
		}
		pri_message(ctrl, ")\n");
		break;
	default:
		for (x = data_ind; x < ie->len; x++) {
			pri_message(ctrl, "%c              Cause data %d: %02x (%d)\n", prefix, x-1, ie->data[x], ie->data[x]);
		}
		break;
	}
}

static int receive_cause(int full_ie, struct pri *ctrl, q931_call *call, int msgtype, q931_ie *ie, int len)
{
	call->causeloc = ie->data[0] & 0xf;
	call->causecode = (ie->data[0] & 0x60) >> 5;
	if (ie->data[0] & 0x80) {
		call->cause = (ie->data[1] & 0x7f);
	} else {
		call->cause = (ie->data[2] & 0x7f);
	}
	return 0;
}

static int transmit_cause(int full_ie, struct pri *ctrl, q931_call *call, int msgtype, q931_ie *ie, int len, int order)
{
	/* We are ready to transmit single IE only */
	if (order > 1)
		return 0;

	if (call->cause > 0) {
		ie->data[0] = 0x80 | (call->causecode << 5)  | (call->causeloc);
		ie->data[1] = 0x80 | (call->cause);
		return 4;
	} else {
		/* Leave off */
		return 0;
	}
}

static void dump_sending_complete(int full_ie, struct pri *ctrl, q931_ie *ie, int len, char prefix)
{
	pri_message(ctrl, "%c %s (len=%2d)\n", prefix, ie2str(full_ie), len);
}

static int receive_sending_complete(int full_ie, struct pri *ctrl, q931_call *call, int msgtype, q931_ie *ie, int len)
{
	/* We've got a "Complete" message: Exect no further digits. */
	call->complete = 1; 
	return 0;
}

static int transmit_sending_complete(int full_ie, struct pri *ctrl, q931_call *call, int msgtype, q931_ie *ie, int len, int order)
{
	if ((ctrl->overlapdial && call->complete) || /* Explicit */
		(!ctrl->overlapdial && ((ctrl->switchtype == PRI_SWITCH_EUROISDN_E1) || 
		/* Implicit */   	   (ctrl->switchtype == PRI_SWITCH_EUROISDN_T1)))) {
		/* Include this single-byte IE */
		return 1;
	}
	return 0;
}

static char *notify2str(int info)
{
	/* ITU-T Q.763 */
	static struct msgtype notifies[] = {
		{ PRI_NOTIFY_USER_SUSPENDED, "User suspended" },
		{ PRI_NOTIFY_USER_RESUMED, "User resumed" },
		{ PRI_NOTIFY_BEARER_CHANGE, "Bearer service change (DSS1)" },
		{ PRI_NOTIFY_ASN1_COMPONENT, "ASN.1 encoded component (DSS1)" },
		{ PRI_NOTIFY_COMPLETION_DELAY, "Call completion delay" },
		{ PRI_NOTIFY_CONF_ESTABLISHED, "Conference established" },
		{ PRI_NOTIFY_CONF_DISCONNECTED, "Conference disconnected" },
		{ PRI_NOTIFY_CONF_PARTY_ADDED, "Other party added" },
		{ PRI_NOTIFY_CONF_ISOLATED, "Isolated" },
		{ PRI_NOTIFY_CONF_REATTACHED, "Reattached" },
		{ PRI_NOTIFY_CONF_OTHER_ISOLATED, "Other party isolated" },
		{ PRI_NOTIFY_CONF_OTHER_REATTACHED, "Other party reattached" },
		{ PRI_NOTIFY_CONF_OTHER_SPLIT, "Other party split" },
		{ PRI_NOTIFY_CONF_OTHER_DISCONNECTED, "Other party disconnected" },
		{ PRI_NOTIFY_CONF_FLOATING, "Conference floating" },
		{ PRI_NOTIFY_WAITING_CALL, "Call is waiting call" },
		{ PRI_NOTIFY_DIVERSION_ACTIVATED, "Diversion activated (DSS1)" },
		{ PRI_NOTIFY_TRANSFER_ALERTING, "Call transfer, alerting" },
		{ PRI_NOTIFY_TRANSFER_ACTIVE, "Call transfer, active" },
		{ PRI_NOTIFY_REMOTE_HOLD, "Remote hold" },
		{ PRI_NOTIFY_REMOTE_RETRIEVAL, "Remote retrieval" },
		{ PRI_NOTIFY_CALL_DIVERTING, "Call is diverting" },
	};
	return code2str(info, notifies, sizeof(notifies) / sizeof(notifies[0]));
}

static void dump_notify(int full_ie, struct pri *ctrl, q931_ie *ie, int len, char prefix)
{
	pri_message(ctrl, "%c %s (len=%2d): Ext: %d  %s (%d)\n",
		prefix, ie2str(full_ie), len, ie->data[0] >> 7,
		notify2str(ie->data[0] & 0x7f), ie->data[0] & 0x7f);
}

static int receive_notify(int full_ie, struct pri *ctrl, q931_call *call, int msgtype, q931_ie *ie, int len)
{
	call->notify = ie->data[0] & 0x7F;
	return 0;
}

static int transmit_notify(int full_ie, struct pri *ctrl, q931_call *call, int msgtype, q931_ie *ie, int len, int order)
{
	if (call->notify >= 0) {
		ie->data[0] = 0x80 | call->notify;
		return 3;
	}
	return 0;
}

static void dump_shift(int full_ie, struct pri *ctrl, q931_ie *ie, int len, char prefix)
{
	pri_message(ctrl, "%c %sLocking Shift (len=%02d): Requested codeset %d\n",
		prefix, (full_ie & 8) ? "Non-" : "", len, full_ie & 7);
}

static char *lineinfo2str(int info)
{
	/* NAPNA ANI II digits */
	static struct msgtype lineinfo[] = {
		{  0, "Plain Old Telephone Service (POTS)" },
		{  1, "Multiparty line (more than 2)" },
		{  2, "ANI failure" },
		{  6, "Station Level Rating" },
		{  7, "Special Operator Handling Required" },
		{ 20, "Automatic Identified Outward Dialing (AIOD)" },
		{ 23, "Coing or Non-Coin" },
		{ 24, "Toll free translated to POTS originated for non-pay station" },
		{ 25, "Toll free translated to POTS originated from pay station" },
		{ 27, "Pay station with coin control signalling" },
		{ 29, "Prison/Inmate Service" },
		{ 30, "Intercept (blank)" },
		{ 31, "Intercept (trouble)" },
		{ 32, "Intercept (regular)" },
		{ 34, "Telco Operator Handled Call" },
		{ 52, "Outward Wide Area Telecommunications Service (OUTWATS)" },
		{ 60, "TRS call from unrestricted line" },
		{ 61, "Cellular/Wireless PCS (Type 1)" },
		{ 62, "Cellular/Wireless PCS (Type 2)" },
		{ 63, "Cellular/Wireless PCS (Roaming)" },
		{ 66, "TRS call from hotel/motel" },
		{ 67, "TRS call from restricted line" },
		{ 70, "Line connected to pay station" },
		{ 93, "Private virtual network call" },
	};
	return code2str(info, lineinfo, sizeof(lineinfo) / sizeof(lineinfo[0]));
}

static void dump_line_information(int full_ie, struct pri *ctrl, q931_ie *ie, int len, char prefix)
{
	pri_message(ctrl, "%c %s (len=%02d): %s (%d)\n",
		prefix, ie2str(full_ie), len, lineinfo2str(ie->data[0]), ie->data[0]);
}

static int receive_line_information(int full_ie, struct pri *ctrl, q931_call *call, int msgtype, q931_ie *ie, int len)
{
	call->ani2 = ie->data[0];
	return 0;
}

static int transmit_line_information(int full_ie, struct pri *ctrl, q931_call *call, int msgtype, q931_ie *ie, int len, int order)
{
#if 0	/* XXX Is this IE possible for 4ESS only? XXX */
	if(ctrl->switchtype == PRI_SWITCH_ATT4ESS) {
		ie->data[0] = 0;
		return 3;
	}
#endif
	return 0;
}


static char *gdencoding2str(int encoding)
{
	static struct msgtype gdencoding[] = {
		{ 0, "BCD even" },
		{ 1, "BCD odd" },
		{ 2, "IA5" },
		{ 3, "Binary" },
	};
	return code2str(encoding, gdencoding, sizeof(gdencoding) / sizeof(gdencoding[0]));
}

static char *gdtype2str(int type)
{
	static struct msgtype gdtype[] = {
		{  0, "Account Code" },
		{  1, "Auth Code" },
		{  2, "Customer ID" },
		{  3, "Universal Access" },
		{  4, "Info Digits" },
		{  5, "Callid" },
		{  6, "Opart" },
		{  7, "TCN" },
		{  9, "Adin" },
	};
	return code2str(type, gdtype, sizeof(gdtype) / sizeof(gdtype[0]));
}

static void dump_generic_digits(int full_ie, struct pri *ctrl, q931_ie *ie, int len, char prefix)
{
	int encoding;
	int type;
	int idx;
	int value;
	if (len < 3) {
		pri_message(ctrl, "%c %s (len=%02d): Invalid length\n",
			prefix, ie2str(full_ie), len);
		return;
	}
	encoding = (ie->data[0] >> 5) & 7;
	type = ie->data[0] & 0x1F;
	pri_message(ctrl, "%c %s (len=%02d): Encoding %s  Type %s\n",
		prefix, ie2str(full_ie), len, gdencoding2str(encoding), gdtype2str(type));
	if (encoding == 3) {	/* Binary */
		pri_message(ctrl, "%c                            Don't know how to handle binary encoding\n",
			prefix);
		return;
	}
	if (len == 3)	/* No number information */
		return;
	pri_message(ctrl, "%c                            Digits: ", prefix);
	value = 0;
	for(idx = 3; idx < len; ++idx) {
		switch(encoding) {
		case 0:		/* BCD even */
		case 1:		/* BCD odd */
			pri_message(ctrl, "%d", ie->data[idx-2] & 0x0f);
			value = value * 10 + (ie->data[idx-2] & 0x0f);
			if(!encoding || (idx+1 < len)) {	/* Special handling for BCD odd */
				pri_message(ctrl, "%d", (ie->data[idx-2] >> 4) & 0x0f);
				value = value * 10 + ((ie->data[idx-2] >> 4) & 0x0f);
			}
			break;
		case 2:		/* IA5 */
			pri_message(ctrl, "%c", ie->data[idx-2]);
			value = value * 10 + ie->data[idx-2] - '0';
			break;
		}
	}
	switch(type) {
		case 4:		/* Info Digits */
			pri_message(ctrl, " - %s", lineinfo2str(value));
			break;
	}
	pri_message(ctrl, "\n");
}

static int receive_generic_digits(int full_ie, struct pri *ctrl, q931_call *call, int msgtype, q931_ie *ie, int len)
{
	int encoding;
	int type;
	int idx;
	int value;
	int num_idx;
	char number[260];

	if (len < 3) {
		pri_error(ctrl, "Invalid length of Generic Digits IE\n");
		return -1;
	}
	encoding = (ie->data[0] >> 5) & 7;
	type = ie->data[0] & 0x1F;
	if (encoding == 3) {	/* Binary */
		pri_message(ctrl, "!! Unable to handle binary encoded Generic Digits IE\n");
		return 0;
	}
	if (len == 3)	/* No number information */
		return 0;
	value = 0;
	switch(type) {
	/* Integer value handling */
	case 4:		/* Info Digits */
		for(idx = 3; idx < len; ++idx) {
			switch(encoding) {
			case 0:		/* BCD even */
			case 1:		/* BCD odd */
				value = value * 10 + (ie->data[idx-2] & 0x0f);
				if(!encoding || (idx+1 < len))	/* Special handling for BCD odd */
					value = value * 10 + ((ie->data[idx-2] >> 4) & 0x0f);
				break;
			case 2:		/* IA5 */
				value = value * 10 + (ie->data[idx-2] - '0');
				break;
			}
		}
		break;
	/* String value handling */
	case 5:		/* Callid */
		num_idx = 0;
		for(idx = 3; (idx < len) && (num_idx < sizeof(number) - 4); ++idx) {
			switch(encoding) {
			case 0:		/* BCD even */
			case 1:		/* BCD odd */
				number[num_idx++] = '0' + (ie->data[idx-2] & 0x0f);
				if(!encoding || (idx+1 < len))	/* Special handling for BCD odd */
					number[num_idx++] = '0' + ((ie->data[idx-2] >> 4) & 0x0f);
				break;
			case 2:
				number[num_idx++] = ie->data[idx-2];
				break;
			}
		}
		number[num_idx] = '\0';
		break;
	}
	switch(type) {
	case 4:		/* Info Digits */
		call->ani2 = value;
		break;
#if 0
	case 5:		/* Callid */
		if (!call->remote_id.number.valid) {
			call->remote_id.number.valid = 1;
			call->remote_id.number.presentation =
				PRI_PRES_ALLOWED | PRI_PRES_USER_NUMBER_UNSCREENED;
			call->remote_id.number.plan = PRI_UNKNOWN;
			libpri_copy_string(call->remote_id.number.str, number,
				sizeof(call->remote_id.number.str));
		}
		break;
#endif
	}
	return 0;
}

static int transmit_generic_digits(int full_ie, struct pri *ctrl, q931_call *call, int msgtype, q931_ie *ie, int len, int order)
{
#if 0	/* XXX Is this IE possible for other switches? XXX */
	if (order > 1)
		return 0;

	if(ctrl->switchtype == PRI_SWITCH_NI1) {
		ie->data[0] = 0x04;	/* BCD even, Info Digits */
		ie->data[1] = 0x00;	/* POTS */
		return 4;
	}
#endif
	return 0;
}


static char *signal2str(int signal)
{
	/* From Q.931 4.5.8 Table 4-24 */
	static struct msgtype mtsignal[] = {
		{  0, "Dial tone" },
		{  1, "Ring back tone" },
		{  2, "Intercept tone" },
		{  3, "Network congestion tone" },
		{  4, "Busy tone" },
		{  5, "Confirm tone" },
		{  6, "Answer tone" },
		{  7, "Call waiting tone" },
		{  8, "Off-hook warning tone" },
		{  9, "Pre-emption tone" },
		{ 63, "Tones off" },
		{ 64, "Alerting on - pattern 0" },
		{ 65, "Alerting on - pattern 1" },
		{ 66, "Alerting on - pattern 2" },
		{ 67, "Alerting on - pattern 3" },
		{ 68, "Alerting on - pattern 4" },
		{ 69, "Alerting on - pattern 5" },
		{ 70, "Alerting on - pattern 6" },
		{ 71, "Alerting on - pattern 7" },
		{ 79, "Alerting off" },
	};
	return code2str(signal, mtsignal, sizeof(mtsignal) / sizeof(mtsignal[0]));
}


static void dump_signal(int full_ie, struct pri *ctrl, q931_ie *ie, int len, char prefix)
{
	pri_message(ctrl, "%c %s (len=%02d): ", prefix, ie2str(full_ie), len);
	if (len < 3) {
		pri_message(ctrl, "Invalid length\n");
		return;
	}
	pri_message(ctrl, "Signal %s (%d)\n", signal2str(ie->data[0]), ie->data[0]);
}

static void dump_transit_count(int full_ie, struct pri *ctrl, q931_ie *ie, int len, char prefix)
{
	/* Defined in ECMA-225 */
	pri_message(ctrl, "%c %s (len=%02d): ", prefix, ie2str(full_ie), len);
	if (len < 3) {
		pri_message(ctrl, "Invalid length\n");
		return;
	}
	pri_message(ctrl, "Count=%d (0x%02x)\n", ie->data[0] & 0x1f, ie->data[0] & 0x1f);
}

static void dump_reverse_charging_indication(int full_ie, struct pri *ctrl, q931_ie *ie, int len, char prefix)
{
	pri_message(ctrl, "%c %s (len=%02d): %d\n", prefix, ie2str(full_ie), len, ie->data[0] & 0x7);
}

static int receive_reverse_charging_indication(int full_ie, struct pri *ctrl, q931_call *call, int msgtype, q931_ie *ie, int len)
{
	call->reversecharge = ie->data[0] & 0x7;
	return 0;
}

static int transmit_reverse_charging_indication(int full_ie, struct pri *ctrl, q931_call *call, int msgtype, q931_ie *ie, int len, int order)
{
	if (call->reversecharge != PRI_REVERSECHARGE_NONE) {
		ie->data[0] = 0x80 | (call->reversecharge & 0x7);
		return 3;
	}
	return 0;
}

static struct ie ies[] = {
	/* Codeset 0 - Comprehension required ie's with varying support. */
	{ 1, Q931_IE_SEGMENTED_MSG, "Segmented Message" }, /* Not supported.  Just ie name is available for message decode. */
	{ 1, Q931_IE_CHANGE_STATUS, "Change Status Information", dump_change_status, receive_change_status, transmit_change_status },

	/* Codeset 0 - Common */
	{ 0, Q931_LOCKING_SHIFT, "Locking Shift", dump_shift },
	{ 0, Q931_BEARER_CAPABILITY, "Bearer Capability", dump_bearer_capability, receive_bearer_capability, transmit_bearer_capability },
	{ 0, Q931_CAUSE, "Cause", dump_cause, receive_cause, transmit_cause },
	{ 1, Q931_IE_CALL_STATE, "Call State", dump_call_state, receive_call_state, transmit_call_state },
	{ 0, Q931_CHANNEL_IDENT, "Channel ID", dump_channel_id, receive_channel_id, transmit_channel_id },
	{ 0, Q931_PROGRESS_INDICATOR, "Progress Indicator", dump_progress_indicator, receive_progress_indicator, transmit_progress_indicator },
	{ 0, Q931_NETWORK_SPEC_FAC, "Network-Specific Facilities", dump_network_spec_fac, receive_network_spec_fac, transmit_network_spec_fac },
	{ 1, Q931_INFORMATION_RATE, "Information Rate" },
	{ 1, Q931_TRANSIT_DELAY, "End-to-End Transit Delay" },
	{ 1, Q931_TRANS_DELAY_SELECT, "Transmit Delay Selection and Indication" },
	{ 1, Q931_BINARY_PARAMETERS, "Packet-layer Binary Parameters" },
	{ 1, Q931_WINDOW_SIZE, "Packet-layer Window Size" },
	{ 1, Q931_CLOSED_USER_GROUP, "Closed User Group" },
	{ 1, Q931_REVERSE_CHARGE_INDIC, "Reverse Charging Indication", dump_reverse_charging_indication, receive_reverse_charging_indication, transmit_reverse_charging_indication },
	{ 1, Q931_CALLING_PARTY_NUMBER, "Calling Party Number", dump_calling_party_number, receive_calling_party_number, transmit_calling_party_number },
	{ 1, Q931_CALLING_PARTY_SUBADDR, "Calling Party Subaddress", dump_calling_party_subaddr, receive_calling_party_subaddr, transmit_calling_party_subaddr },
	{ 1, Q931_CALLED_PARTY_NUMBER, "Called Party Number", dump_called_party_number, receive_called_party_number, transmit_called_party_number },
	{ 1, Q931_CALLED_PARTY_SUBADDR, "Called Party Subaddress", dump_called_party_subaddr, receive_called_party_subaddr, transmit_called_party_subaddr },
	{ 0, Q931_REDIRECTING_NUMBER, "Redirecting Number", dump_redirecting_number, receive_redirecting_number, transmit_redirecting_number },
	{ 1, Q931_REDIRECTING_SUBADDR, "Redirecting Subaddress", dump_redirecting_subaddr },
	{ 0, Q931_TRANSIT_NET_SELECT, "Transit Network Selection" },
	{ 1, Q931_RESTART_INDICATOR, "Restart Indicator", dump_restart_indicator, receive_restart_indicator, transmit_restart_indicator },
	{ 0, Q931_LOW_LAYER_COMPAT, "Low-layer Compatibility" },
	{ 0, Q931_HIGH_LAYER_COMPAT, "High-layer Compatibility" },
	{ 1, Q931_PACKET_SIZE, "Packet Size" },
	{ 0, Q931_IE_FACILITY, "Facility" , dump_facility, receive_facility, transmit_facility },
	{ 1, Q931_IE_REDIRECTION_NUMBER, "Redirection Number", dump_redirection_number, receive_redirection_number, transmit_redirection_number },
	{ 1, Q931_IE_REDIRECTION_SUBADDR, "Redirection Subaddress" },
	{ 1, Q931_IE_FEATURE_ACTIVATE, "Feature Activation" },
	{ 1, Q931_IE_INFO_REQUEST, "Feature Request" },
	{ 1, Q931_IE_FEATURE_IND, "Feature Indication" },
	{ 1, Q931_IE_CALL_IDENTITY, "Call Identity", dump_call_identity },
	{ 1, Q931_IE_ENDPOINT_ID, "Endpoint Identification" },
	{ 1, Q931_IE_NOTIFY_IND, "Notification Indicator", dump_notify, receive_notify, transmit_notify },
	{ 1, Q931_DISPLAY, "Display", dump_display, receive_display, transmit_display },
	{ 1, Q931_IE_TIME_DATE, "Date/Time", dump_time_date, receive_time_date, transmit_time_date },
	{ 1, Q931_IE_KEYPAD_FACILITY, "Keypad Facility", dump_keypad_facility, receive_keypad_facility, transmit_keypad_facility },
	{ 0, Q931_IE_SIGNAL, "Signal", dump_signal },
	{ 1, Q931_IE_SWITCHHOOK, "Switch-hook" },
	{ 1, Q931_IE_USER_USER, "User-User Information", dump_user_user, receive_user_user, transmit_user_user },
	{ 1, Q931_IE_ESCAPE_FOR_EXT, "Escape for Extension" },
	{ 1, Q931_IE_CALL_STATUS, "Call Status" },
	{ 1, Q931_IE_CONNECTED_ADDR, "Connected Address", dump_connected_number, receive_connected_number, transmit_connected_number },
	{ 1, Q931_IE_CONNECTED_NUM, "Connected Number", dump_connected_number, receive_connected_number, transmit_connected_number },
	{ 1, Q931_IE_CONNECTED_SUBADDR, "Connected Subaddress", dump_connected_subaddr, receive_connected_subaddr, transmit_connected_subaddr },
	{ 1, Q931_IE_ORIGINAL_CALLED_NUMBER, "Original Called Number", dump_redirecting_number, receive_redirecting_number, transmit_redirecting_number },
	{ 1, Q931_IE_USER_USER_FACILITY, "User-User Facility" },
	{ 1, Q931_IE_UPDATE, "Update" },
	{ 1, Q931_SENDING_COMPLETE, "Sending Complete", dump_sending_complete, receive_sending_complete, transmit_sending_complete },
	/* Codeset 4 - Q.SIG specific */
	{ 1, QSIG_IE_TRANSIT_COUNT | Q931_CODESET(4), "Transit Count", dump_transit_count },
	/* Codeset 5 - National specific (ETSI PISN specific) */
	{ 1, Q931_CALLING_PARTY_CATEGORY, "Calling Party Category", dump_calling_party_category },
	/* Codeset 6 - Network specific */
	{ 1, Q931_IE_ORIGINATING_LINE_INFO, "Originating Line Information", dump_line_information, receive_line_information, transmit_line_information },
	{ 1, Q931_IE_FACILITY | Q931_CODESET(6), "Facility", dump_facility, receive_facility, transmit_facility },
	{ 1, Q931_DISPLAY | Q931_CODESET(6), "Display (CS6)", dump_display, receive_display, transmit_display },
	{ 0, Q931_IE_GENERIC_DIGITS, "Generic Digits", dump_generic_digits, receive_generic_digits, transmit_generic_digits },
	/* Codeset 7 */
};

static char *ie2str(int ie)
{
	unsigned int x;

	/* Special handling for Locking/Non-Locking Shifts */
	switch (ie & 0xf8) {
	case Q931_LOCKING_SHIFT:
		switch (ie & 7) {
		case 0:
			return "!! INVALID Locking Shift To Codeset 0";
		case 1:
			return "Locking Shift To Codeset 1";
		case 2:
			return "Locking Shift To Codeset 2";
		case 3:
			return "Locking Shift To Codeset 3";
		case 4:
			return "Locking Shift To Codeset 4";
		case 5:
			return "Locking Shift To Codeset 5";
		case 6:
			return "Locking Shift To Codeset 6";
		case 7:
			return "Locking Shift To Codeset 7";
		default:
			break;
		}
		break;
	case Q931_NON_LOCKING_SHIFT:
		switch (ie & 7) {
		case 0:
			return "Non-Locking Shift To Codeset 0";
		case 1:
			return "Non-Locking Shift To Codeset 1";
		case 2:
			return "Non-Locking Shift To Codeset 2";
		case 3:
			return "Non-Locking Shift To Codeset 3";
		case 4:
			return "Non-Locking Shift To Codeset 4";
		case 5:
			return "Non-Locking Shift To Codeset 5";
		case 6:
			return "Non-Locking Shift To Codeset 6";
		case 7:
			return "Non-Locking Shift To Codeset 7";
		default:
			break;
		}
		break;
	default:
		break;
	}
	for (x = 0; x < ARRAY_LEN(ies); ++x) {
		if (ie == ies[x].ie) {
			return ies[x].name;
		}
	}
	return "Unknown Information Element";
}

static inline unsigned int ielen(q931_ie *ie)
{
	if ((ie->ie & 0x80) != 0)
		return 1;
	else
		return 2 + ie->len;
}

static inline int ielen_checked(q931_ie *ie, int len_remaining)
{
	int len;

	if (ie->ie & 0x80) {
		len = 1;
	} else if (len_remaining < 2) {
		/* There is no length octet when there should be. */
		len = -1;
	} else {
		len = 2 + ie->len;
		if (len_remaining < len) {
			/* There is not enough room left in the packet for this ie. */
			len = -1;
		}
	}
	return len;
}

const char *msg2str(int msg)
{
	unsigned int x;
	for (x=0;x<sizeof(msgs) / sizeof(msgs[0]); x++) 
		if (msgs[x].msgnum == msg)
			return msgs[x].name;
	return "Unknown Message Type";
}

static char *maintenance_msg2str(int msg, int pd)
{
	unsigned int x, max;
	struct msgtype *m = NULL;

	if (pd == MAINTENANCE_PROTOCOL_DISCRIMINATOR_1) {
		m = att_maintenance_msgs;
		max = ARRAY_LEN(att_maintenance_msgs);
	} else {
		m = national_maintenance_msgs;
		max = ARRAY_LEN(national_maintenance_msgs);
	}

	for (x = 0; x < max; x++) {
		if (m[x].msgnum == msg) {
			return m[x].name;
		}
	}
	return "Unknown Message Type";
}

/* Decode the call reference */
static inline int q931_cr(q931_h *h)
{
	int cr;
	int x;

	if (h->crlen > 3) {
		pri_error(NULL, "Call Reference Length Too long: %d\n", h->crlen);
		return Q931_DUMMY_CALL_REFERENCE;
	}
	switch (h->crlen) {
	case 2:
		cr = 0;
		for (x = 0; x < h->crlen; ++x) {
			cr <<= 8;
			cr |= h->crv[x];
		}
		break;
	case 1:
		cr = h->crv[0];
		if (cr & 0x80) {
			cr &= ~0x80;
			cr |= Q931_CALL_REFERENCE_FLAG;
		}
		break;
	case 0:
		cr = Q931_DUMMY_CALL_REFERENCE;
		break;
	default:
		pri_error(NULL, "Call Reference Length not supported: %d\n", h->crlen);
		cr = Q931_DUMMY_CALL_REFERENCE;
		break;
	}
	return cr;
}

static inline void q931_dumpie(struct pri *ctrl, int codeset, q931_ie *ie, char prefix)
{
	unsigned int x;
	int full_ie = Q931_FULL_IE(codeset, ie->ie);
	int base_ie;
	char *buf = malloc(ielen(ie) * 3 + 1);
	int buflen = 0;

	buf[0] = '\0';
	if (!(ie->ie & 0x80)) {
		buflen += sprintf(buf, " %02x", ielen(ie)-2);
		for (x = 0; x + 2 < ielen(ie); ++x)
			buflen += sprintf(buf + buflen, " %02x", ie->data[x]);
	}
	pri_message(ctrl, "%c [%02x%s]\n", prefix, ie->ie, buf);
	free(buf);

	/* Special treatment for shifts */
	if((full_ie & 0xf0) == Q931_LOCKING_SHIFT)
		full_ie &= 0xff;

	base_ie = (((full_ie & ~0x7f) == Q931_FULL_IE(0, 0x80)) && ((full_ie & 0x70) != 0x20)) ? full_ie & ~0x0f : full_ie;

	for (x = 0; x < ARRAY_LEN(ies); ++x)
		if (ies[x].ie == base_ie) {
			if (ies[x].dump)
				ies[x].dump(full_ie, ctrl, ie, ielen(ie), prefix);
			else
				pri_message(ctrl, "%c IE: %s (len = %d)\n", prefix, ies[x].name, ielen(ie));
			return;
		}
	
	pri_error(ctrl, "!! %c Unknown IE %d (cs%d, len = %d)\n", prefix, Q931_IE_IE(base_ie), Q931_IE_CODESET(base_ie), ielen(ie));
}

/*!
 * \brief Initialize the call record.
 *
 * \param link Q.921 link associated with the call.
 * \param call Q.931 call leg.
 * \param cr Call Reference identifier.
 *
 * \note The call record is assumed to already be memset() to zero.
 *
 * \return Nothing
 */
void q931_init_call_record(struct q921_link *link, struct q931_call *call, int cr)
{
	struct pri *ctrl;

	call->cr = cr;
	call->slotmap = -1;
	call->channelno = -1;
	if (cr != Q931_DUMMY_CALL_REFERENCE) {
		call->newcall = 1;
	}
	call->ourcallstate = Q931_CALL_STATE_NULL;
	call->peercallstate = Q931_CALL_STATE_NULL;
	call->sugcallstate = Q931_CALL_STATE_NOT_SET;
	call->ri = -1;
	call->bc.transcapability = -1;
	call->bc.transmoderate = -1;
	call->bc.transmultiple = -1;
	call->bc.userl1 = -1;
	call->bc.userl2 = -1;
	call->bc.userl3 = -1;
	call->bc.rateadaption = -1;
	call->progress = -1;
	call->causecode = -1;
	call->causeloc = -1;
	call->cause = -1;
	call->useruserprotocoldisc = -1;
	call->aoc_units = -1;
	call->changestatus = -1;
	call->reversecharge = -1;
	call->pri_winner = -1;
	call->master_call = call;
	q931_party_number_init(&call->redirection_number);
	q931_party_address_init(&call->called);
	q931_party_id_init(&call->local_id);
	q931_party_id_init(&call->remote_id);
	q931_party_number_init(&call->ani);
	q931_party_redirecting_init(&call->redirecting);

	/* The call is now attached to whoever called us */
	ctrl = link->ctrl;
	call->pri = ctrl;
	if (cr == Q931_DUMMY_CALL_REFERENCE) {
		/* Dummy calls are always for the given link. */
		call->link = link;
	} else if (BRI_TE_PTMP(ctrl)) {
		/* Always uses the specific TEI link. */
		call->link = ctrl->link.next;
	} else {
		call->link = link;
	}
}

/*!
 * \internal
 * \brief Create a new call record.
 *
 * \param link Q.921 link associated with the call.
 * \param cr Call Reference identifier.
 *
 * \retval record on success.
 * \retval NULL on error.
 */
static struct q931_call *q931_create_call_record(struct q921_link *link, int cr)
{
	struct q931_call *call;
	struct q931_call *prev;
	struct pri *ctrl;

	ctrl = link->ctrl;

	if (ctrl->debug & PRI_DEBUG_Q931_STATE) {
		pri_message(ctrl, "-- Making new call for cref %d\n", cr);
	}

	call = calloc(1, sizeof(*call));
	if (!call) {
		return NULL;
	}

	/* Initialize call structure. */
	q931_init_call_record(link, call, cr);

	/* Append to the list end */
	if (*ctrl->callpool) {
		/* Find the list end. */
		for (prev = *ctrl->callpool; prev->next; prev = prev->next) {
		}
		prev->next = call;
	} else {
		/* List was empty. */
		*ctrl->callpool = call;
	}

	return call;
}

/*!
 * \internal
 * \brief Find a call in the active call pool.
 *
 * \param link Q.921 link associated with the call.
 * \param cr Call Reference identifier.
 *
 * \retval call if found.
 * \retval NULL if not found.
 */
static struct q931_call *q931_find_call(struct q921_link *link, int cr)
{
	struct q931_call *cur;
	struct pri *ctrl;

	if (cr == Q931_DUMMY_CALL_REFERENCE) {
		return link->dummy_call;
	}

	ctrl = link->ctrl;

	if (BRI_NT_PTMP(ctrl) && !(cr & Q931_CALL_REFERENCE_FLAG)) {
		if (link->tei == Q921_TEI_GROUP) {
			/* Broadcast TEI.  This is bad.  We are using the wrong link structure. */
			pri_error(ctrl, "Looking for cref %d when using broadcast TEI.\n", cr);
			return NULL;
		}

		/* We are looking for a call reference value that the other side allocated. */
		for (cur = *ctrl->callpool; cur; cur = cur->next) {
			if (cur->cr == cr && cur->link == link) {
				/* Found existing call.  The call reference and link matched. */
				break;
			}
		}
	} else {
		for (cur = *ctrl->callpool; cur; cur = cur->next) {
			if (cur->cr == cr) {
				/* Found existing call. */
				switch (ctrl->switchtype) {
				case PRI_SWITCH_GR303_EOC:
				case PRI_SWITCH_GR303_TMC:
					break;
				default:
					if (!ctrl->bri) {
						/* The call is now attached to whoever called us */
						cur->pri = ctrl;
						cur->link = link;
					}
					break;
				}
				break;
			}
		}
	}
	return cur;
}

static struct q931_call *q931_getcall(struct q921_link *link, int cr)
{
	struct q931_call *cur;
	struct pri *ctrl;

	cur = q931_find_call(link, cr);
	if (cur) {
		return cur;
	}
	if (cr == Q931_DUMMY_CALL_REFERENCE) {
		/* Do not create new dummy call records. */
		return NULL;
	}
	ctrl = link->ctrl;
	if (link->tei == Q921_TEI_GROUP
		&& BRI_NT_PTMP(ctrl)) {
		/* Do not create NT PTMP broadcast call records here. */
		pri_error(ctrl,
			"NT PTMP cannot create call record for cref %d on the broadcast TEI.\n", cr);
		return NULL;
	}

	/* No call record exists, make a new one */
	return q931_create_call_record(link, cr);
}

/*!
 * \brief Create a new call record for an outgoing call.
 *
 * \param ctrl D channel controller.
 *
 * \retval call on success.
 * \retval NULL on error.
 */
struct q931_call *q931_new_call(struct pri *ctrl)
{
	struct q931_call *cur;
	struct q921_link *link;
	int first_cref;
	int cref;

	/* Find a new call reference value. */
	first_cref = ctrl->cref;
	do {
		cref = Q931_CALL_REFERENCE_FLAG | ctrl->cref;

		/* Next call reference. */
		++ctrl->cref;
		if (!ctrl->bri) {
			if (ctrl->cref > 32767) {
				ctrl->cref = 1;
			}
		} else {
			if (ctrl->cref > 127) {
				ctrl->cref = 1;
			}
		}

		/* Is the call reference value in use? */
		for (cur = *ctrl->callpool; cur; cur = cur->next) {
			if (cur->cr == cref) {
				/* Yes it is in use. */
				if (first_cref == ctrl->cref) {
					/* All call reference values are in use! */
					return NULL;
				}
				break;
			}
		}
	} while (cur);

	link = &ctrl->link;
	return q931_create_call_record(link, cref);
}

static void stop_t303(struct q931_call *call);

static void stop_t312(struct q931_call *call)
{
	/* T312 should only be running on the master call */
	pri_schedule_del(call->pri, call->t312_timer);
	call->t312_timer = 0;
}

static void cleanup_and_free_call(struct q931_call *cur)
{
	struct pri *ctrl;

	ctrl = cur->pri;
	pri_schedule_del(ctrl, cur->restart.timer);
	pri_schedule_del(ctrl, cur->restart_tx.t316_timer);
	pri_schedule_del(ctrl, cur->retranstimer);
	pri_schedule_del(ctrl, cur->hold_timer);
	pri_schedule_del(ctrl, cur->fake_clearing_timer);
	stop_t303(cur);
	stop_t312(cur);
	pri_call_apdu_queue_cleanup(cur);
	if (cur->cc.record) {
		/* Unlink CC associations. */
		if (cur->cc.record->original_call == cur) {
			cur->cc.record->original_call = NULL;
		}
		if (cur->cc.record->signaling == cur) {
			cur->cc.record->signaling = NULL;
		}
	}
	free(cur);
}

int q931_get_subcall_count(struct q931_call *master)
{
	int count = 0;
	int idx;

	for (idx = 0; idx < ARRAY_LEN(master->subcalls); ++idx) {
		if (master->subcalls[idx]) {
			++count;
		}
	}

	return count;
}

static int pri_internal_clear(struct q931_call *call);

/*!
 * \brief Fake RELEASE for NT-PTMP initiated SETUPs w/o response
 *
 * \param param call Call is not a subcall call record.
 */
static void pri_fake_clearing(struct q931_call *call)
{
	struct pri *ctrl;

	ctrl = call->pri;
	if (ctrl->debug & PRI_DEBUG_Q931_STATE) {
		pri_message(ctrl, "Fake clearing.  cref:%d\n", call->cr);
	}

	/*
	 * This does not need to be running since this is what we are
	 * doing right now anyway.
	 */
	pri_schedule_del(ctrl, call->fake_clearing_timer);
	call->fake_clearing_timer = 0;

	if (call->cause == -1) {
		/* Ensure that there is a resonable cause code. */
		call->cause = PRI_CAUSE_NO_USER_RESPONSE;
	}
	if (pri_internal_clear(call) == Q931_RES_HAVEEVENT) {
		ctrl->schedev = 1;
	}
}

static void pri_fake_clearing_expiry(void *data)
{
	struct q931_call *master = data;

	master->fake_clearing_timer = 0;
	pri_fake_clearing(master);
}

static void pri_create_fake_clearing(struct pri *ctrl, struct q931_call *master)
{
	if (ctrl->debug & PRI_DEBUG_Q931_STATE) {
		pri_message(ctrl, "Fake clearing requested.  cref:%d\n", master->cr);
	}
	pri_schedule_del(ctrl, master->fake_clearing_timer);
	master->fake_clearing_timer = pri_schedule_event(ctrl, 0, pri_fake_clearing_expiry,
		master);
}

static void t312_expiry(void *data)
{
	struct q931_call *master = data;
	struct pri *ctrl;

	ctrl = master->pri;
	if (ctrl->debug & PRI_DEBUG_Q931_STATE) {
		pri_message(ctrl, "T312 timed out.  cref:%d\n", master->cr);
	}

	master->t312_timer = 0;
	if (!q931_get_subcall_count(master)) {
		/* No subcalls remain. */
		switch (master->ourcallstate) {
		case Q931_CALL_STATE_CALL_ABORT:
			/* We can destroy the master. */
			q931_destroycall(ctrl, master);
			break;
		default:
			/* Let the upper layer know about the lack of call prospects. */
			UPDATE_OURCALLSTATE(ctrl, master, Q931_CALL_STATE_CALL_ABORT);
			pri_fake_clearing(master);
			break;
		}
	}
}

/*! \param master Master call record for PTMP NT call. */
static void start_t312(struct q931_call *master)
{
	struct pri *ctrl;

	ctrl = master->pri;
	pri_schedule_del(ctrl, master->t312_timer);
	master->t312_timer = pri_schedule_event(ctrl, ctrl->timers[PRI_TIMER_T312],
		t312_expiry, master);
}

/*!
 * \internal
 * \brief Helper function to destroy a subcall.
 *
 * \param master Q.931 master call of subcall to destroy.
 * \param idx Master subcall index to destroy.
 *
 * \return Nothing
 */
static void q931_destroy_subcall(struct q931_call *master, int idx)
{
	struct pri *ctrl = master->pri;

	if (ctrl->debug & PRI_DEBUG_Q931_STATE) {
		pri_message(ctrl, "Destroying subcall %p of call %p at %d\n",
			master->subcalls[idx], master, idx);
	}
	cleanup_and_free_call(master->subcalls[idx]);
	if (master->pri_winner == idx) {
		/* This was the winning subcall. */
		master->pri_winner = -1;
	}
	master->subcalls[idx] = NULL;
}

void q931_destroycall(struct pri *ctrl, q931_call *c)
{
	struct q931_call *cur;
	struct q931_call *prev;
	struct q931_call *slave;
	int i;
	int slavesleft;

	if (q931_is_dummy_call(c)) {
		/* Cannot destroy the dummy call. */
		return;
	}
	if (c->master_call != c) {
		slave = c;
		c = slave->master_call;
	} else {
		slave = NULL;
	}

	prev = NULL;
	cur = *ctrl->callpool;
	while (cur) {
		if (cur == c) {
			if (slave) {
				/* Destroying a slave. */
				for (i = 0; i < ARRAY_LEN(cur->subcalls); ++i) {
					if (cur->subcalls[i] == slave) {
						q931_destroy_subcall(cur, i);
						break;
					}
				}

				/* How many slaves are left? */
				slavesleft = 0;
				for (i = 0; i < ARRAY_LEN(cur->subcalls); ++i) {
					if (cur->subcalls[i]) {
						if (ctrl->debug & PRI_DEBUG_Q931_STATE) {
							pri_message(ctrl, "Subcall still present at %d\n", i);
						}
						++slavesleft;
					}
				}

				if (slavesleft || cur->t312_timer || cur->master_hanging_up) {
					return;
				}

				/* No slaves left. */
				switch (cur->ourcallstate) {
				case Q931_CALL_STATE_CALL_ABORT:
					break;
				default:
					/* Let the upper layer know about the call clearing. */
					UPDATE_OURCALLSTATE(ctrl, cur, Q931_CALL_STATE_CALL_ABORT);
					pri_create_fake_clearing(ctrl, cur);
					return;
				}

				/* We can try to destroy the master now. */
			} else {
				/* Destroy any slaves that may be present as well. */
				slavesleft = 0;
				for (i = 0; i < ARRAY_LEN(cur->subcalls); ++i) {
					if (cur->subcalls[i]) {
						++slavesleft;
						q931_destroy_subcall(cur, i);
					}
				}
			}

			if (cur->fake_clearing_timer) {
				/*
				 * Must wait for the fake clearing to complete before destroying
				 * the master call record.
				 */
				return;
			}
			if (slavesleft) {
				/* This is likely not good. */
				pri_error(ctrl,
					"Destroyed %d subcalls unconditionally with the master.  cref:%d\n",
					slavesleft, cur->cr);
			}

			/* Master call or normal call destruction. */
			if (prev)
				prev->next = cur->next;
			else
				*ctrl->callpool = cur->next;
			if (ctrl->debug & PRI_DEBUG_Q931_STATE)
				pri_message(ctrl,
					"Destroying call %p, ourstate %s, peerstate %s, hold-state %s\n",
					cur,
					q931_call_state_str(cur->ourcallstate),
					q931_call_state_str(cur->peercallstate),
					q931_hold_state_str(cur->hold_state));
			cleanup_and_free_call(cur);
			return;
		}
		prev = cur;
		cur = cur->next;
	}
	pri_error(ctrl, "Can't destroy call %p cref:%d!\n", c, c->cr);
}

static int add_ie(struct pri *ctrl, q931_call *call, int msgtype, int ie, q931_ie *iet, int maxlen, int *codeset)
{
	unsigned int x;
	int res, total_res;
	int have_shift;
	int ies_count, order;

	for (x = 0; x < ARRAY_LEN(ies); ++x) {
		if (ies[x].ie == ie) {
			/* This is our baby */
			if (ies[x].transmit) {
				/* Prepend with CODE SHIFT IE if required */
				if (*codeset != Q931_IE_CODESET(ies[x].ie)) {
					/* Locking shift to codeset 0 isn't possible */
					iet->ie = Q931_IE_CODESET(ies[x].ie) | (Q931_IE_CODESET(ies[x].ie) ? Q931_LOCKING_SHIFT : Q931_NON_LOCKING_SHIFT);
					have_shift = 1;
					iet = (q931_ie *)((char *)iet + 1);
					maxlen--;
				}
				else
					have_shift = 0;
				ies_count = ies[x].max_count;
				if (ies_count == 0)
					ies_count = INT_MAX;
				order = 0;
				total_res = 0;
				do {
					iet->ie = ie;
					res = ies[x].transmit(ie, ctrl, call, msgtype, iet, maxlen, ++order);
					/* Error if res < 0 or ignored if res == 0 */
					if (res < 0)
						return res;
					if (res > 0) {
						if ((iet->ie & 0x80) == 0) /* Multibyte IE */
							iet->len = res - 2;
						if (msgtype == Q931_SETUP && *codeset == 0) {
							switch (iet->ie) {
							case Q931_BEARER_CAPABILITY:
								if (!(call->cc.saved_ie_flags & CC_SAVED_IE_BC)) {
									/* Save first BC ie contents for possible CC. */
									call->cc.saved_ie_flags |= CC_SAVED_IE_BC;
									q931_append_ie_contents(&call->cc.saved_ie_contents,
										iet);
								}
								break;
							case Q931_LOW_LAYER_COMPAT:
								if (!(call->cc.saved_ie_flags & CC_SAVED_IE_LLC)) {
									/* Save first LLC ie contents for possible CC. */
									call->cc.saved_ie_flags |= CC_SAVED_IE_LLC;
									q931_append_ie_contents(&call->cc.saved_ie_contents,
										iet);
								}
								break;
							case Q931_HIGH_LAYER_COMPAT:
								if (!(call->cc.saved_ie_flags & CC_SAVED_IE_HLC)) {
									/* Save first HLC ie contents for possible CC. */
									call->cc.saved_ie_flags |= CC_SAVED_IE_HLC;
									q931_append_ie_contents(&call->cc.saved_ie_contents,
										iet);
								}
								break;
							default:
								break;
							}
						}
						total_res += res;
						maxlen -= res;
						iet = (q931_ie *)((char *)iet + res);
					}
				} while (res > 0 && order < ies_count);
				if (have_shift && total_res) {
					if (Q931_IE_CODESET(ies[x].ie))
						*codeset = Q931_IE_CODESET(ies[x].ie);
					return total_res + 1; /* Shift is single-byte IE */
				}
				return total_res;
			} else {
				pri_error(ctrl, "!! Don't know how to add IE %d (%s)\n", ie, ie2str(ie));
				return -1;
			}
		}
	}
	pri_error(ctrl, "!! Unknown IE %d (%s)\n", ie, ie2str(ie));
	return -1;
}

static char *disc2str(int disc)
{
	static struct msgtype discs[] = {
		{ Q931_PROTOCOL_DISCRIMINATOR, "Q.931" },
		{ GR303_PROTOCOL_DISCRIMINATOR, "GR-303" },
		{ MAINTENANCE_PROTOCOL_DISCRIMINATOR_1, "AT&T Maintenance" },
		{ MAINTENANCE_PROTOCOL_DISCRIMINATOR_2, "New AT&T Maintenance" },
	};
	return code2str(disc, discs, sizeof(discs) / sizeof(discs[0]));
}

/*!
 * \internal
 * \brief Dump the Q.931 message header.
 *
 * \param ctrl D channel controller.
 * \param tei TEI the packet is associated with.
 * \param h Q.931 packet contents/header.
 * \param len Received length of the Q.931 packet.
 * \param c Message direction prefix character.
 *
 * \retval 0 on success.
 * \retval -1 on error.
 */
static int q931_dump_header(struct pri *ctrl, int tei, q931_h *h, int len, char c)
{
	q931_mh *mh;
	int cref;

	pri_message(ctrl, "%c Protocol Discriminator: %s (%d)  len=%d\n", c, disc2str(h->pd), h->pd, len);

	if (len < 2 || len < 2 + h->crlen) {
		pri_message(ctrl, "%c Message too short for call reference. len=%d\n",
			c, len);
		return -1;
	}
	cref = q931_cr(h);
	pri_message(ctrl, "%c TEI=%d Call Ref: len=%2d (reference %d/0x%X) (%s)\n",
		c, tei, h->crlen, cref & ~Q931_CALL_REFERENCE_FLAG,
		cref & ~Q931_CALL_REFERENCE_FLAG, (cref == Q931_DUMMY_CALL_REFERENCE)
			? "Dummy"
			: (cref & Q931_CALL_REFERENCE_FLAG)
				? "Sent to originator" : "Sent from originator");

	if (len < 3 + h->crlen) {
		pri_message(ctrl, "%c Message too short for supported protocols. len=%d\n",
			c, len);
		return -1;
	}

	/* Message header begins at the end of the call reference number */
	mh = (q931_mh *)(h->contents + h->crlen);
	switch (h->pd) {
	case MAINTENANCE_PROTOCOL_DISCRIMINATOR_1:
	case MAINTENANCE_PROTOCOL_DISCRIMINATOR_2:
		pri_message(ctrl, "%c Message Type: %s (%d)\n", c, maintenance_msg2str(mh->msg, h->pd), mh->msg);
		break;
	default:
		/* Unknown protocol discriminator but we will treat it as Q.931 anyway. */
	case GR303_PROTOCOL_DISCRIMINATOR:
	case Q931_PROTOCOL_DISCRIMINATOR:
		pri_message(ctrl, "%c Message Type: %s (%d)\n", c, msg2str(mh->msg), mh->msg);
		break;
	}

	return 0;
}

/*!
 * \internal
 * \brief Q.931 is passing this message to Q.921 debug indication.
 *
 * \param ctrl D channel controller.
 * \param tei TEI the packet is associated with.
 * \param h Q.931 packet contents/header.
 * \param len Received length of the Q.931 packet
 *
 * \return Nothing
 */
static void q931_to_q921_passing_dump(struct pri *ctrl, int tei, q931_h *h, int len)
{
	char c;

	c = '>';

	pri_message(ctrl, "\n");
	pri_message(ctrl, "%c DL-DATA request\n", c);
	q931_dump_header(ctrl, tei, h, len, c);
}

/*!
 * \brief Debug dump the given Q.931 packet.
 *
 * \param ctrl D channel controller.
 * \param tei TEI the packet is associated with.
 * \param h Q.931 packet contents/header.
 * \param len Received length of the Q.931 packet
 * \param txrx TRUE if packet is transmitted/outgoing
 *
 * \return Nothing
 */
void q931_dump(struct pri *ctrl, int tei, q931_h *h, int len, int txrx)
{
	q931_mh *mh;
	char c;
	int x;
	int r;
	int cur_codeset;
	int codeset;

	c = txrx ? '>' : '<';

	if (!(ctrl->debug & (PRI_DEBUG_Q921_DUMP | PRI_DEBUG_Q921_RAW))) {
		/* Put out a blank line if Q.921 is not dumping. */
		pri_message(ctrl, "\n");
	}
	if (q931_dump_header(ctrl, tei, h, len, c)) {
		return;
	}

	/* Drop length of header, including call reference */
	mh = (q931_mh *)(h->contents + h->crlen);
	len -= (h->crlen + 3);
	codeset = cur_codeset = 0;
	for (x = 0; x < len; x += r) {
		r = ielen_checked((q931_ie *) (mh->data + x), len - x);
		if (r < 0) {
			/* We have garbage on the end of the packet. */
			pri_message(ctrl, "Not enough room for codeset:%d ie:%d(%02x)\n", cur_codeset,
				mh->data[x], mh->data[x]);
			break;
		}
		q931_dumpie(ctrl, cur_codeset, (q931_ie *)(mh->data + x), c);
		switch (mh->data[x] & 0xf8) {
		case Q931_LOCKING_SHIFT:
			if ((mh->data[x] & 7) > 0)
				codeset = cur_codeset = mh->data[x] & 7;
			break;
		case Q931_NON_LOCKING_SHIFT:
			cur_codeset = mh->data[x] & 7;
			break;
		default:
			/* Reset temporary codeset change */
			cur_codeset = codeset;
			break;
		}
	}
}

static int q931_handle_ie(int codeset, struct pri *ctrl, q931_call *c, int msg, q931_ie *ie)
{
	unsigned int x;
	int full_ie = Q931_FULL_IE(codeset, ie->ie);

	if (ctrl->debug & PRI_DEBUG_Q931_STATE)
		pri_message(ctrl, "-- Processing IE %d (cs%d, %s)\n", ie->ie, codeset, ie2str(full_ie));
	if (msg == Q931_SETUP && codeset == 0) {
		switch (ie->ie) {
		case Q931_BEARER_CAPABILITY:
			if (!(c->cc.saved_ie_flags & CC_SAVED_IE_BC)) {
				/* Save first BC ie contents for possible CC. */
				c->cc.saved_ie_flags |= CC_SAVED_IE_BC;
				q931_append_ie_contents(&c->cc.saved_ie_contents, ie);
			}
			break;
		case Q931_LOW_LAYER_COMPAT:
			if (!(c->cc.saved_ie_flags & CC_SAVED_IE_LLC)) {
				/* Save first LLC ie contents for possible CC. */
				c->cc.saved_ie_flags |= CC_SAVED_IE_LLC;
				q931_append_ie_contents(&c->cc.saved_ie_contents, ie);
			}
			break;
		case Q931_HIGH_LAYER_COMPAT:
			if (!(c->cc.saved_ie_flags & CC_SAVED_IE_HLC)) {
				/* Save first HLC ie contents for possible CC. */
				c->cc.saved_ie_flags |= CC_SAVED_IE_HLC;
				q931_append_ie_contents(&c->cc.saved_ie_contents, ie);
			}
			break;
		default:
			break;
		}
	}
	for (x = 0; x < ARRAY_LEN(ies); ++x) {
		if (full_ie == ies[x].ie) {
			if (ies[x].receive)
				return ies[x].receive(full_ie, ctrl, c, msg, ie, ielen(ie));
			else {
				if (ctrl->debug & PRI_DEBUG_Q931_ANOMALY)
					pri_message(ctrl, "!! No handler for IE %d (cs%d, %s)\n", ie->ie, codeset, ie2str(full_ie));
				return -1;
			}
		}
	}
	pri_message(ctrl, "!! Unknown IE %d (cs%d)\n", ie->ie, codeset);
	return -1;
}

/* Returns header and message header and modifies length in place */
static void init_header(struct pri *ctrl, q931_call *call, unsigned char *buf, q931_h **hb, q931_mh **mhb, int *len, int protodisc)
{
	q931_h *h = (q931_h *) buf;
	q931_mh *mh;
	unsigned crv;

	if (protodisc) {
		h->pd = protodisc;
	} else {
		h->pd = ctrl->protodisc;
	}
	h->x0 = 0;		/* Reserved 0 */
	if (q931_is_dummy_call(call)) {
		h->crlen = 0;
	} else if (!ctrl->bri) {
		/* Two bytes of Call Reference. */
		h->crlen = 2;
		if (ctrl->link.next) {
			/* On GR-303, Q931_CALL_REFERENCE_FLAG is always 0 */
			crv = ((unsigned) call->cr) & ~Q931_CALL_REFERENCE_FLAG;
		} else {
			/* Invert the Q931_CALL_REFERENCE_FLAG to make it from our sense */
			crv = ((unsigned) call->cr) ^ Q931_CALL_REFERENCE_FLAG;
		}
		h->crv[0] = (crv >> 8) & 0xff;
		h->crv[1] = crv & 0xff;
	} else {
		h->crlen = 1;
		/* Invert the Q931_CALL_REFERENCE_FLAG to make it from our sense */
		crv = ((unsigned) call->cr) ^ Q931_CALL_REFERENCE_FLAG;
		h->crv[0] = ((crv >> 8) & 0x80) | (crv & 0x7f);
	}
	*hb = h;

	*len -= 3;/* Protocol discriminator, call reference length, message type id */
	*len -= h->crlen;

	mh = (q931_mh *) (h->contents + h->crlen);
	mh->f = 0;
	*mhb = mh;
}

static void q931_xmit(struct q921_link *link, q931_h *h, int len, int cr, int uiframe)
{
	struct pri *ctrl;

	ctrl = link->ctrl;
	ctrl->q931_txcount++;
	if (uiframe) {
		if (link->tei != Q921_TEI_GROUP) {
			pri_error(ctrl, "Huh?! Attempting to send UI-frame on TEI %d\n", link->tei);
			return;
		}
		q921_transmit_uiframe(link, h, len);
		if (ctrl->debug & PRI_DEBUG_Q931_DUMP) {
			/*
			 * The transmit operation might dump the Q.921 header, so logging
			 * the Q.931 message body after the transmit puts the sections of
			 * the message in the right order in the log,
			 */
			q931_dump(ctrl, link->tei, h, len, 1);
		}
	} else {
		/*
		 * Indicate passing the Q.931 message to Q.921 first.  Q.921 may
		 * have to request a TEI or bring the connection up before it can
		 * actually send the message.  Therefore, the Q.931 message may
		 * actually get sent a few seconds later.  Q.921 will dump the
		 * Q.931 message as appropriate at that time.
		 */
		if (ctrl->debug & PRI_DEBUG_Q931_DUMP) {
			q931_to_q921_passing_dump(ctrl, link->tei, h, len);
		}
		q921_transmit_iframe(link, h, len, cr);
	}
}

/*!
 * \internal
 * \brief Build and send the requested message.
 *
 * \param ctrl D channel controller.
 * \param call Q.931 call leg
 * \param msgtype Q.931 message type to build.
 * \param ies List of ie's to put in the message.
 *
 * \note The ie's in the ie list must be in numerical order.
 * See Q.931 section 4.5.1 coding rules.
 *
 * \retval 0 on success.
 * \retval -1 on error.
 */
static int send_message(struct pri *ctrl, q931_call *call, int msgtype, int ies[])
{
	unsigned char buf[1024];
	q931_h *h;
	q931_mh *mh;
	int len;
	int res;
	int offset=0;
	int x;
	int codeset;
	int uiframe;

	if (call->outboundbroadcast && call->master_call == call && msgtype != Q931_SETUP) {
		pri_error(ctrl,
			"Attempting to use master call record to send %s on BRI PTMP NT %p\n",
			msg2str(msgtype), ctrl);
		return -1;
	}

	if (!call->link) {
		pri_error(ctrl,
			"Call w/ cref:%d is not associated with a link.  TEI removed due to error conditions?\n",
			call->cr);
		return -1;
	}

	memset(buf, 0, sizeof(buf));
	len = sizeof(buf);
	init_header(ctrl, call, buf, &h, &mh, &len, (msgtype >> 8));
	mh->msg = msgtype & 0x00ff;
	x=0;
	codeset = 0;
	while(ies[x] > -1) {
		res = add_ie(ctrl, call, mh->msg, ies[x], (q931_ie *)(mh->data + offset), len, &codeset);
		if (res < 0) {
			pri_error(ctrl, "!! Unable to add IE '%s'\n", ie2str(ies[x]));
			return -1;
		}

		offset += res;
		len -= res;
		x++;
	}
	/* Invert the logic */
	len = sizeof(buf) - len;

	uiframe = 0;
	if (BRI_NT_PTMP(ctrl)) {
		/* NT PTMP is the only mode that can broadcast Q.931 messages. */
		switch (msgtype) {
		case Q931_SETUP:
			/* 
			 * For NT-PTMP mode, we need to check the following:
			 * MODE = NT-PTMP
			 * MESSAGE = SETUP
			 *
			 * If those are true, we need to send the SETUP in a UI frame
			 * instead of an I-frame.
			 */
			uiframe = 1;
			break;
		case Q931_FACILITY:
			if (call->link->tei == Q921_TEI_GROUP) {
				/* Broadcast TEI. */
				if (q931_is_dummy_call(call)) {
					/*
					 * This is a FACILITY message on the dummy call reference
					 * for the broadcast TEI.
					 */
					uiframe = 1;
				} else {
					pri_error(ctrl,
						"Attempting to broadcast %s on cref %d\n",
						msg2str(msgtype), call->cr);
					return -1;
				}
			}
			break;
		default:
			break;
		}
		if (ctrl->debug & PRI_DEBUG_Q931_STATE) {
			/* This message is only interesting for NT PTMP mode. */
			pri_message(ctrl,
				"Sending message for call %p on call->link: %p with TEI/SAPI %d/%d\n",
				call, call->link, call->link->tei, call->link->sapi);
		}
	}
	q931_xmit(call->link, h, len, 1, uiframe);
	call->acked = 1;
	return 0;
}

static int maintenance_service_ies[] = { Q931_IE_CHANGE_STATUS, Q931_CHANNEL_IDENT, -1 };

static int maintenance_service_ack(struct pri *ctrl, q931_call *c)
{
	int pd = MAINTENANCE_PROTOCOL_DISCRIMINATOR_1;
	int mt = ATT_SERVICE_ACKNOWLEDGE;

	if (ctrl->switchtype == PRI_SWITCH_NI2) {
		pd = MAINTENANCE_PROTOCOL_DISCRIMINATOR_2;
		mt = NATIONAL_SERVICE_ACKNOWLEDGE;
	}
	return send_message(ctrl, c, (pd << 8) | mt, maintenance_service_ies);
}

/*!
 * \note Maintenance service messages only supported in PRI mode.
 */
int maintenance_service(struct pri *ctrl, int span, int channel, int changestatus)
{
	struct q931_call *c;
	int pd = MAINTENANCE_PROTOCOL_DISCRIMINATOR_1;
	int mt = ATT_SERVICE;

	c = q931_getcall(&ctrl->link, 0 | Q931_CALL_REFERENCE_FLAG);
	if (!c) {
		return -1;
	}
	if (channel > -1) {
		c->channelno = channel & 0xff;
		c->chanflags = FLAG_EXCLUSIVE;
	} else {
		c->channelno = channel;
		c->chanflags = FLAG_EXCLUSIVE | FLAG_WHOLE_INTERFACE;
	}
	c->ds1no = span;
	c->ds1explicit = 0;
	c->changestatus = changestatus;

	if (ctrl->switchtype == PRI_SWITCH_NI2) {
		pd = MAINTENANCE_PROTOCOL_DISCRIMINATOR_2;
		mt = NATIONAL_SERVICE;
	}
	return send_message(ctrl, c, (pd << 8) | mt, maintenance_service_ies);
}

static int q931_status(struct pri *ctrl, q931_call *call, int cause)
{
	static int status_ies[] = {
		Q931_CAUSE,
		Q931_IE_CALL_STATE,
		-1
	};

	call->cause = cause;
	call->causecode = CODE_CCITT;
	call->causeloc = LOC_USER;
	return send_message(ctrl, call, Q931_STATUS, status_ies);
}

int q931_information(struct pri *ctrl, q931_call *c, char digit)
{
	static int information_ies[] = {
		Q931_CALLED_PARTY_NUMBER,
		-1
	};

	c->overlap_digits[0] = digit;
	c->overlap_digits[1] = '\0';

	/*
	 * Since we are doing overlap dialing now, we need to accumulate
	 * the digits into call->called.number.str.
	 */
	c->called.number.valid = 1;
	if (strlen(c->called.number.str) < sizeof(c->called.number.str) - 1) {
		/* There is enough room for the new digit. */
		strcat(c->called.number.str, c->overlap_digits);
	}

	return send_message(ctrl, c, Q931_INFORMATION, information_ies);
}

/*!
 * \internal
 * \brief Actually send display text if in the right call state.
 *
 * \param ctrl D channel controller.
 * \param call Q.931 call leg
 * \param display Display text to send.
 *
 * \retval 0 on success.
 * \retval -1 on error.
 */
static int q931_display_text_helper(struct pri *ctrl, struct q931_call *call, const struct pri_subcmd_display_txt *display)
{
	int status;
	static int information_display_ies[] = {
		Q931_DISPLAY,
		-1
	};

	switch (call->ourcallstate) {
	case Q931_CALL_STATE_OVERLAP_SENDING:
	case Q931_CALL_STATE_OUTGOING_CALL_PROCEEDING:
	case Q931_CALL_STATE_CALL_DELIVERED:
	case Q931_CALL_STATE_CALL_RECEIVED:
	case Q931_CALL_STATE_CONNECT_REQUEST:
	case Q931_CALL_STATE_INCOMING_CALL_PROCEEDING:
	case Q931_CALL_STATE_ACTIVE:
	case Q931_CALL_STATE_OVERLAP_RECEIVING:
		call->display.text = (unsigned char *) display->text;
		call->display.full_ie = 0;
		call->display.length = display->length;
		call->display.char_set = display->char_set;
		status = send_message(ctrl, call, Q931_INFORMATION, information_display_ies);
		q931_display_clear(call);
		break;
	default:
		status = 0;
		break;
	}

	return status;
}

/*!
 * \brief Send display text during a call.
 *
 * \param ctrl D channel controller.
 * \param call Q.931 call leg
 * \param display Display text to send.
 *
 * \retval 0 on success.
 * \retval -1 on error.
 */
int q931_display_text(struct pri *ctrl, struct q931_call *call, const struct pri_subcmd_display_txt *display)
{
	int status;
	unsigned idx;
	struct q931_call *subcall;

	if ((ctrl->display_flags.send & (PRI_DISPLAY_OPTION_BLOCK | PRI_DISPLAY_OPTION_TEXT))
		!= PRI_DISPLAY_OPTION_TEXT) {
		/* Not enabled */
		return 0;
	}
	if (call->outboundbroadcast && call->master_call == call) {
		status = 0;
		for (idx = 0; idx < ARRAY_LEN(call->subcalls); ++idx) {
			subcall = call->subcalls[idx];
			if (subcall && q931_display_text_helper(ctrl, subcall, display)) {
				status = -1;
			}
		}
	} else {
		status = q931_display_text_helper(ctrl, call, display);
	}
	return status;
}


static int keypad_facility_ies[] = { Q931_IE_KEYPAD_FACILITY, -1 };

int q931_keypad_facility(struct pri *ctrl, q931_call *call, const char *digits)
{
	libpri_copy_string(call->keypad_digits, digits, sizeof(call->keypad_digits));
	return send_message(ctrl, call, Q931_INFORMATION, keypad_facility_ies);
}

static int restart_ack_ies[] = { Q931_CHANNEL_IDENT, Q931_RESTART_INDICATOR, -1 };

static int restart_ack(struct pri *ctrl, q931_call *c)
{
	UPDATE_OURCALLSTATE(ctrl, c, Q931_CALL_STATE_NULL);
	c->peercallstate = Q931_CALL_STATE_NULL;
	return send_message(ctrl, c, Q931_RESTART_ACKNOWLEDGE, restart_ack_ies);
}

int q931_facility(struct pri *ctrl, struct q931_call *call)
{
	static int facility_ies[] = {
		Q931_IE_FACILITY,
		-1
	};

	return send_message(ctrl, call, Q931_FACILITY, facility_ies);
}

/*!
 * \brief Send a FACILITY message with the called party number and subaddress ies.
 *
 * \param ctrl D channel controller.
 * \param call Call leg to send message over.
 * \param called Called party information to send.
 *
 * \note
 * This function can only be used by the dummy call because the call's called
 * structure is used by normal calls to contain persistent information.
 *
 * \retval 0 on success.
 * \retval -1 on error.
 */
int q931_facility_called(struct pri *ctrl, struct q931_call *call, const struct q931_party_id *called)
{
	static int facility_called_ies[] = {
		Q931_IE_FACILITY,
		Q931_CALLED_PARTY_NUMBER,
		Q931_CALLED_PARTY_SUBADDR,
		-1
	};

	q931_party_id_copy_to_address(&call->called, called);
	libpri_copy_string(call->overlap_digits, call->called.number.str,
		sizeof(call->overlap_digits));
	return send_message(ctrl, call, Q931_FACILITY, facility_called_ies);
}

int q931_facility_display_name(struct pri *ctrl, struct q931_call *call, const struct q931_party_name *name)
{
	int status;
	static int facility_display_ies[] = {
		Q931_IE_FACILITY,
		Q931_DISPLAY,
		-1
	};

	q931_display_name_send(call, name);
	status = send_message(ctrl, call, Q931_FACILITY, facility_display_ies);
	q931_display_clear(call);
	return status;
}

/*!
 * \brief Send a FACILITY RequestSubaddress with optional redirection name and number.
 *
 * \param ctrl D channel controller.
 * \param call Q.931 call leg
 * \param notify Notification indicator
 * \param name Redirection name to send if not NULL.
 * \param number Redirection number to send if not NULL.
 *
 * \retval 0 on success.
 * \retval -1 on error.
 */
int q931_request_subaddress(struct pri *ctrl, struct q931_call *call, int notify, const struct q931_party_name *name, const struct q931_party_number *number)
{
	int status;
	struct q931_call *winner;
	static int facility_notify_ies[] = {
		Q931_IE_FACILITY,
		Q931_IE_NOTIFY_IND,
		Q931_DISPLAY,
		Q931_IE_REDIRECTION_NUMBER,
		-1
	};

	winner = q931_find_winning_call(call);
	if (!winner) {
		return -1;
	}
	q931_display_clear(winner);
	if (number) {
		winner->redirection_number = *number;
		if (number->valid && name
			&& (ctrl->display_flags.send & PRI_DISPLAY_OPTION_NAME_UPDATE)) {
			q931_display_name_send(winner, name);
		}
	} else {
		q931_party_number_init(&winner->redirection_number);
	}
	winner->notify = notify;
	if (rose_request_subaddress_encode(ctrl, winner)
		|| send_message(ctrl, winner, Q931_FACILITY, facility_notify_ies)) {
		pri_message(ctrl,
			"Could not schedule facility message for request subaddress.\n");
		status = -1;
	} else {
		status = 0;
	}
	q931_display_clear(winner);

	return status;
}

/*!
 * \brief Send a FACILITY SubaddressTransfer to all parties.
 *
 * \param ctrl D channel controller.
 * \param call Q.931 call leg
 *
 * \retval 0 on success.
 * \retval -1 on error.
 */
int q931_subaddress_transfer(struct pri *ctrl, struct q931_call *call)
{
	int status;
	unsigned idx;
	struct q931_call *subcall;

	if (call->outboundbroadcast && call->master_call == call) {
		status = 0;
		for (idx = 0; idx < ARRAY_LEN(call->subcalls); ++idx) {
			subcall = call->subcalls[idx];
			if (subcall) {
				/* Send to all subcalls that have given a positive response. */
				switch (subcall->ourcallstate) {
				case Q931_CALL_STATE_OUTGOING_CALL_PROCEEDING:
				case Q931_CALL_STATE_CALL_DELIVERED:
				case Q931_CALL_STATE_ACTIVE:
					if (send_subaddress_transfer(ctrl, subcall)) {
						status = -1;
					}
					break;
				default:
					break;
				}
			}
		}
	} else {
		status = send_subaddress_transfer(ctrl, call);
	}
	return status;
}

/*!
 * \internal
 * \brief Actually send a NOTIFY message with optional redirection name and number.
 *
 * \param ctrl D channel controller.
 * \param call Q.931 call leg
 * \param notify Notification indicator
 * \param name Redirection display name to send if not NULL.
 * \param number Redirection number to send if not NULL.
 *
 * \retval 0 on success.
 * \retval -1 on error.
 */
static int q931_notify_redirection_helper(struct pri *ctrl, struct q931_call *call, int notify, const struct q931_party_name *name, const struct q931_party_number *number)
{
	int status;
	static int notify_ies[] = {
		Q931_IE_NOTIFY_IND,
		Q931_DISPLAY,
		Q931_IE_REDIRECTION_NUMBER,
		-1
	};

	q931_display_clear(call);
	if (number) {
		call->redirection_number = *number;
		if (number->valid && name
			&& (ctrl->display_flags.send & PRI_DISPLAY_OPTION_NAME_UPDATE)) {
			q931_display_name_send(call, name);
		}
	} else {
		q931_party_number_init(&call->redirection_number);
	}
	call->notify = notify;
	status = send_message(ctrl, call, Q931_NOTIFY, notify_ies);
	q931_display_clear(call);
	return status;
}

/*!
 * \brief Send a NOTIFY message with optional redirection name and number.
 *
 * \param ctrl D channel controller.
 * \param call Q.931 call leg
 * \param notify Notification indicator
 * \param name Redirection display name to send if not NULL.
 * \param number Redirection number to send if not NULL.
 *
 * \retval 0 on success.
 * \retval -1 on error.
 */
int q931_notify_redirection(struct pri *ctrl, struct q931_call *call, int notify, const struct q931_party_name *name, const struct q931_party_number *number)
{
	int status;
	unsigned idx;
	struct q931_call *subcall;

	if (call->outboundbroadcast && call->master_call == call) {
		status = 0;
		for (idx = 0; idx < ARRAY_LEN(call->subcalls); ++idx) {
			subcall = call->subcalls[idx];
			if (subcall) {
				/* Send to all subcalls that have given a positive response. */
				switch (subcall->ourcallstate) {
				case Q931_CALL_STATE_OUTGOING_CALL_PROCEEDING:
				case Q931_CALL_STATE_CALL_DELIVERED:
				case Q931_CALL_STATE_ACTIVE:
					if (q931_notify_redirection_helper(ctrl, subcall, notify, name, number)) {
						status = -1;
					}
					break;
				default:
					break;
				}
			}
		}
	} else {
		status = q931_notify_redirection_helper(ctrl, call, notify, name, number);
	}
	return status;
}

int q931_notify(struct pri *ctrl, q931_call *c, int channel, int info)
{
	switch (ctrl->switchtype) {
	case PRI_SWITCH_EUROISDN_T1:
	case PRI_SWITCH_EUROISDN_E1:
		break;
	default:
		if ((info > 0x2) || (info < 0x00)) {
			return -1;
		}
		break;
	}

	if (info >= 0) {
		info &= 0x7F;
	} else {
		/* Cannot send NOTIFY message if the mandatory ie is not going to be present. */
		return -1;
	}
	return q931_notify_redirection(ctrl, c, info, NULL, NULL);
}

static int call_progress_ies[] = {
#ifndef ALERTING_NO_PROGRESS
	Q931_PROGRESS_INDICATOR,
#endif
	-1
};

int q931_call_progress(struct pri *ctrl, q931_call *c, int channel, int info)
{
	if (c->ourcallstate == Q931_CALL_STATE_CALL_INDEPENDENT_SERVICE) {
		/* Cannot send this message when in this state */
		return 0;
	}
	if (channel) { 
		c->ds1no = (channel & 0xff00) >> 8;
		c->ds1explicit = (channel & 0x10000) >> 16;
		c->channelno = channel & 0xff;
	}

	if (info) {
		c->progloc = LOC_PRIV_NET_LOCAL_USER;
		c->progcode = CODE_CCITT;
		c->progressmask = PRI_PROG_INBAND_AVAILABLE;
	} else {
		/* PI is mandatory IE for PROGRESS message - Q.931 3.1.8 */
		pri_error(ctrl, "XXX Progress message requested but no information is provided\n");
		c->progressmask = 0;
	}

	c->alive = 1;
	return send_message(ctrl, c, Q931_PROGRESS, call_progress_ies);
}

static int call_progress_with_cause_ies[] = {
	Q931_CAUSE,
#ifndef ALERTING_NO_PROGRESS
	Q931_PROGRESS_INDICATOR,
#endif
	-1
};

int q931_call_progress_with_cause(struct pri *ctrl, q931_call *c, int channel, int info, int cause)
{
	if (c->ourcallstate == Q931_CALL_STATE_CALL_INDEPENDENT_SERVICE) {
		/* Cannot send this message when in this state */
		return 0;
	}
	if (channel) { 
		c->ds1no = (channel & 0xff00) >> 8;
		c->ds1explicit = (channel & 0x10000) >> 16;
		c->channelno = channel & 0xff;
	}

	if (info) {
		c->progloc = LOC_PRIV_NET_LOCAL_USER;
		c->progcode = CODE_CCITT;
		c->progressmask = PRI_PROG_INBAND_AVAILABLE;
	} else {
		/* PI is mandatory IE for PROGRESS message - Q.931 3.1.8 */
		pri_error(ctrl, "XXX Progress message requested but no information is provided\n");
		c->progressmask = 0;
	}

	c->cause = cause;
	c->causecode = CODE_CCITT;
	c->causeloc = LOC_PRIV_NET_LOCAL_USER;

	c->alive = 1;
	return send_message(ctrl, c, Q931_PROGRESS, call_progress_with_cause_ies);
}

static int call_proceeding_ies[] = {
	Q931_CHANNEL_IDENT,
#ifndef ALERTING_NO_PROGRESS
	Q931_PROGRESS_INDICATOR,
#endif
	-1
};

int q931_call_proceeding(struct pri *ctrl, q931_call *c, int channel, int info)
{
	if (c->proc) {
		/* We have already sent a PROCEEDING message.  Don't send another one. */
		return 0;
	}
	if (c->ourcallstate == Q931_CALL_STATE_CALL_INDEPENDENT_SERVICE) {
		/* Cannot send this message when in this state */
		return 0;
	}
	if (channel) { 
		c->ds1no = (channel & 0xff00) >> 8;
		c->ds1explicit = (channel & 0x10000) >> 16;
		c->channelno = channel & 0xff;
	}
	c->chanflags &= ~FLAG_PREFERRED;
	c->chanflags |= FLAG_EXCLUSIVE;
	UPDATE_OURCALLSTATE(ctrl, c, Q931_CALL_STATE_INCOMING_CALL_PROCEEDING);
	c->peercallstate = Q931_CALL_STATE_OUTGOING_CALL_PROCEEDING;
	if (info) {
		c->progloc = LOC_PRIV_NET_LOCAL_USER;
		c->progcode = CODE_CCITT;
		c->progressmask = PRI_PROG_INBAND_AVAILABLE;
	} else
		c->progressmask = 0;
	c->proc = 1;
	c->alive = 1;
	return send_message(ctrl, c, Q931_CALL_PROCEEDING, call_proceeding_ies);
}

static int alerting_ies[] = {
	Q931_IE_FACILITY,
#ifndef ALERTING_NO_PROGRESS
	Q931_PROGRESS_INDICATOR,
#endif
	Q931_IE_USER_USER,
	-1
};

int q931_alerting(struct pri *ctrl, q931_call *c, int channel, int info)
{
	if (c->ourcallstate == Q931_CALL_STATE_CALL_INDEPENDENT_SERVICE) {
		/* Cannot send this message when in this state */
		return 0;
	}
	if (!c->proc) 
		q931_call_proceeding(ctrl, c, channel, 0);
	if (info) {
		c->progloc = LOC_PRIV_NET_LOCAL_USER;
		c->progcode = CODE_CCITT;
		c->progressmask = PRI_PROG_INBAND_AVAILABLE;
	} else
		c->progressmask = 0;
	UPDATE_OURCALLSTATE(ctrl, c, Q931_CALL_STATE_CALL_RECEIVED);
	c->peercallstate = Q931_CALL_STATE_CALL_DELIVERED;
	c->alive = 1;

	switch (ctrl->switchtype) {
	case PRI_SWITCH_QSIG:
		if (c->local_id.name.valid) {
			/* Send calledName with ALERTING */
			rose_called_name_encode(ctrl, c, Q931_ALERTING);
		}
		break;
	default:
		break;
	}

	if (c->cc.record) {
		pri_cc_event(ctrl, c, c->cc.record, CC_EVENT_MSG_ALERTING);
	}

	return send_message(ctrl, c, Q931_ALERTING, alerting_ies);
}

static int setup_ack_ies[] = {
	Q931_CHANNEL_IDENT,
	Q931_IE_FACILITY,
	Q931_PROGRESS_INDICATOR,
	-1
};
 
int q931_setup_ack(struct pri *ctrl, q931_call *c, int channel, int nonisdn, int inband)
{
	if (c->ourcallstate == Q931_CALL_STATE_CALL_INDEPENDENT_SERVICE) {
		/* Cannot send this message when in this state */
		return 0;
	}
	if (channel) { 
		c->ds1no = (channel & 0xff00) >> 8;
		c->ds1explicit = (channel & 0x10000) >> 16;
		c->channelno = channel & 0xff;
	}
	c->chanflags &= ~FLAG_PREFERRED;
	c->chanflags |= FLAG_EXCLUSIVE;

	c->progressmask = 0;
	if (nonisdn && (ctrl->switchtype != PRI_SWITCH_DMS100)) {
		c->progloc = LOC_PRIV_NET_LOCAL_USER;
		c->progcode = CODE_CCITT;
		c->progressmask |= PRI_PROG_CALLED_NOT_ISDN;
	}
	if (inband) {
		/* Inband audio is present (i.e. dialtone) */
		c->progloc = LOC_PRIV_NET_LOCAL_USER;
		c->progcode = CODE_CCITT;
		c->progressmask |= PRI_PROG_INBAND_AVAILABLE;
	}

	UPDATE_OURCALLSTATE(ctrl, c, Q931_CALL_STATE_OVERLAP_RECEIVING);
	c->peercallstate = Q931_CALL_STATE_OVERLAP_SENDING;
	c->alive = 1;
	return send_message(ctrl, c, Q931_SETUP_ACKNOWLEDGE, setup_ack_ies);
}

/* T313 expiry, first time */
static void pri_connect_timeout(void *data)
{
	struct q931_call *c = data;
	struct pri *ctrl = c->pri;

	if (ctrl->debug & PRI_DEBUG_Q931_STATE)
		pri_message(ctrl, "Timed out looking for connect acknowledge\n");
	c->retranstimer = 0;
	q931_disconnect(ctrl, c, PRI_CAUSE_NORMAL_CLEARING);
}

/* T308 expiry, first time */
static void pri_release_timeout(void *data)
{
	struct q931_call *c = data;
	struct pri *ctrl = c->pri;

	if (ctrl->debug & PRI_DEBUG_Q931_STATE)
		pri_message(ctrl, "Timed out looking for release complete\n");
	c->t308_timedout++;
	c->retranstimer = 0;
	c->alive = 1;

	/* The call to q931_release will re-schedule T308 */
	q931_release(ctrl, c, c->cause);
}

/* T308 expiry, second time */
static void pri_release_finaltimeout(void *data)
{
	struct q931_call *c = data;
	struct pri *ctrl = c->pri;

	c->retranstimer = 0;
	c->alive = 1;
	if (ctrl->debug & PRI_DEBUG_Q931_STATE)
		pri_message(ctrl, "Final time-out looking for release complete\n");
	c->t308_timedout++;
	c->ourcallstate = Q931_CALL_STATE_NULL;
	c->peercallstate = Q931_CALL_STATE_NULL;
	q931_clr_subcommands(ctrl);
	ctrl->schedev = 1;
	ctrl->ev.e = PRI_EVENT_HANGUP_ACK;
	ctrl->ev.hangup.subcmds = &ctrl->subcmds;
	ctrl->ev.hangup.channel = q931_encode_channel(c);
	ctrl->ev.hangup.cause = c->cause;
	ctrl->ev.hangup.cref = c->cr;
	ctrl->ev.hangup.call = c->master_call;
	ctrl->ev.hangup.aoc_units = c->aoc_units;
	ctrl->ev.hangup.call_held = NULL;
	ctrl->ev.hangup.call_active = NULL;
	libpri_copy_string(ctrl->ev.hangup.useruserinfo, c->useruserinfo, sizeof(ctrl->ev.hangup.useruserinfo));
	pri_hangup(ctrl, c, c->cause);
}

/* T305 expiry, first time */
static void pri_disconnect_timeout(void *data)
{
	struct q931_call *c = data;
	struct pri *ctrl = c->pri;

	if (ctrl->debug & PRI_DEBUG_Q931_STATE)
		pri_message(ctrl, "Timed out looking for release\n");
	c->retranstimer = 0;
	c->alive = 1;
	q931_release(ctrl, c, PRI_CAUSE_NORMAL_CLEARING);
}

static int connect_ies[] = {
	Q931_CHANNEL_IDENT,
	Q931_IE_FACILITY,
	Q931_PROGRESS_INDICATOR,
	Q931_DISPLAY,
	Q931_IE_TIME_DATE,
	Q931_IE_CONNECTED_NUM,
	Q931_IE_CONNECTED_SUBADDR,
	-1
};

int q931_connect(struct pri *ctrl, q931_call *c, int channel, int nonisdn)
{
	if (c->ourcallstate == Q931_CALL_STATE_CALL_INDEPENDENT_SERVICE) {
		/* Cannot send this message when in this state */
		return 0;
	}
	if (channel) { 
		c->ds1no = (channel & 0xff00) >> 8;
		c->ds1explicit = (channel & 0x10000) >> 16;
		c->channelno = channel & 0xff;
	}
	c->chanflags &= ~FLAG_PREFERRED;
	c->chanflags |= FLAG_EXCLUSIVE;
	if (nonisdn && (ctrl->switchtype != PRI_SWITCH_DMS100)) {
		c->progloc = LOC_PRIV_NET_LOCAL_USER;
		c->progcode = CODE_CCITT;
		c->progressmask = PRI_PROG_CALLED_NOT_ISDN;
	} else
		c->progressmask = 0;
	if(ctrl->localtype == PRI_NETWORK || ctrl->switchtype == PRI_SWITCH_QSIG)
		UPDATE_OURCALLSTATE(ctrl, c, Q931_CALL_STATE_ACTIVE);
	else
		UPDATE_OURCALLSTATE(ctrl, c, Q931_CALL_STATE_CONNECT_REQUEST);
	c->peercallstate = Q931_CALL_STATE_ACTIVE;
	c->alive = 1;
	/* Connect request timer */
	pri_schedule_del(ctrl, c->retranstimer);
	c->retranstimer = 0;
	if ((c->ourcallstate == Q931_CALL_STATE_CONNECT_REQUEST) && (ctrl->bri || (!ctrl->link.next)))
		c->retranstimer = pri_schedule_event(ctrl, ctrl->timers[PRI_TIMER_T313], pri_connect_timeout, c);

	if (c->redirecting.state == Q931_REDIRECTING_STATE_PENDING_TX_DIV_LEG_3) {
		c->redirecting.state = Q931_REDIRECTING_STATE_IDLE;
		/* Send DivertingLegInformation3 with CONNECT. */
		c->redirecting.to = c->local_id;
		if (!c->redirecting.to.number.valid) {
			q931_party_number_init(&c->redirecting.to.number);
			c->redirecting.to.number.valid = 1;
			c->redirecting.to.number.presentation =
				PRI_PRES_RESTRICTED | PRI_PRES_USER_NUMBER_UNSCREENED;
		}
		rose_diverting_leg_information3_encode(ctrl, c, Q931_CONNECT);
	}
	switch (ctrl->switchtype) {
	case PRI_SWITCH_QSIG:
		if (c->local_id.name.valid) {
			/* Send connectedName with CONNECT */
			rose_connected_name_encode(ctrl, c, Q931_CONNECT);
		}
		break;
	default:
		break;
	}
	if (ctrl->display_flags.send & PRI_DISPLAY_OPTION_NAME_INITIAL) {
		q931_display_name_send(c, &c->local_id.name);
	} else {
		q931_display_clear(c);
	}
	return send_message(ctrl, c, Q931_CONNECT, connect_ies);
}

static int release_ies[] = { Q931_CAUSE, Q931_IE_FACILITY, Q931_IE_USER_USER, -1 };

int q931_release(struct pri *ctrl, q931_call *c, int cause)
{
	UPDATE_OURCALLSTATE(ctrl, c, Q931_CALL_STATE_RELEASE_REQUEST);
	/* c->peercallstate stays the same */
	if (c->alive) {
		c->alive = 0;
		c->cause = cause;
		c->causecode = CODE_CCITT;
		c->causeloc = LOC_PRIV_NET_LOCAL_USER;
		if (c->acked) {
			pri_schedule_del(ctrl, c->retranstimer);
			if (!c->t308_timedout) {
				c->retranstimer = pri_schedule_event(ctrl, ctrl->timers[PRI_TIMER_T308], pri_release_timeout, c);
			} else {
				c->retranstimer = pri_schedule_event(ctrl, ctrl->timers[PRI_TIMER_T308], pri_release_finaltimeout, c);
			}
			if (c->cc.record) {
				pri_cc_event(ctrl, c, c->cc.record, CC_EVENT_MSG_RELEASE);
			}
			return send_message(ctrl, c, Q931_RELEASE, release_ies);
		} else {
			if (c->cc.record) {
				pri_cc_event(ctrl, c, c->cc.record, CC_EVENT_MSG_RELEASE_COMPLETE);
			}
			return send_message(ctrl, c, Q931_RELEASE_COMPLETE, release_ies); /* Yes, release_ies, not release_complete_ies */
		}
	} else
		return 0;
}

static int restart_ies[] = { Q931_CHANNEL_IDENT, Q931_RESTART_INDICATOR, -1 };

static void t316_expire(void *vcall);

/*!
 * \internal
 * \brief Send the RESTART message to the peer.
 *
 * \param call Q.931 call leg
 * \param channel Encoded channel id to use.
 *
 * \retval 0 on success.
 * \retval -1 on error.
 */
static int q931_send_restart(struct q931_call *call)
{
	struct pri *ctrl = call->pri;
	int channel = call->restart_tx.channel;

	/* Start timer T316 if enabled. */
	if (0 < ctrl->timers[PRI_TIMER_T316]) {
		call->restart_tx.t316_timer =
			pri_schedule_event(ctrl, ctrl->timers[PRI_TIMER_T316], t316_expire, call);
		--call->restart_tx.remain;
	}

	call->ri = 0;
	call->ds1no = (channel >> 8) & 0xFF;
	call->ds1explicit = (channel >> 16) & 0x1;
	call->channelno = channel & 0xFF;
	call->chanflags &= ~FLAG_PREFERRED;
	call->chanflags |= FLAG_EXCLUSIVE;
	UPDATE_OURCALLSTATE(ctrl, call, Q931_CALL_STATE_RESTART);
	call->peercallstate = Q931_CALL_STATE_RESTART_REQUEST;
	return send_message(ctrl, call, Q931_RESTART, restart_ies);
}

/*!
 * \internal
 * \brief T316 expired.
 *
 * \param vcall Q.931 call leg
 *
 * \return Nothing
 */
static void t316_expire(void *vcall)
{
	struct q931_call *call = vcall;

	call->restart_tx.t316_timer = 0;

	if (call->restart_tx.remain) {
		/* Retransmit the RESTART */
		q931_send_restart(call);
	} else {
		int channel = call->restart_tx.channel;

		pri_message(call->pri,
			"!! Peer failed to ack our RESTART request for ds1/channel:%d/%d.\n",
			(channel >> 8) & 0xFF, channel & 0xFF);
	}
}

/*!
 * \internal
 * \brief Stop timer T316.
 *
 * \param call Q.931 call leg
 *
 * \return Nothing
 */
static void stop_t316(struct q931_call *call)
{
	pri_schedule_del(call->pri, call->restart_tx.t316_timer);
	call->restart_tx.t316_timer = 0;
}

/*!
 * \brief Send the RESTART message to the peer.
 *
 * \param ctrl D channel controller.
 * \param channel Encoded channel id to use.
 *
 * \note
 * Sending RESTART in NT PTMP mode is not supported at the
 * present time.
 *
 * \note
 * NT PTMP should broadcast the RESTART if there is a TEI
 * allocated.  Otherwise it should immediately ACK the RESTART
 * itself to avoid the T316 timeout delay (2 minutes) since
 * there might not be anything connected.  The broadcast could
 * be handled in a similar manner to the broadcast SETUP.
 *
 * \todo NT PTMP mode should implement some protection from
 * receiving a RESTART on channels in use by another TEI.
 *
 * \retval 0 on success.
 * \retval -1 on error.
 */
int q931_restart(struct pri *ctrl, int channel)
{
	struct q931_call *call;

	if (!channel) {
		return -1;
	}
	call = q931_getcall(&ctrl->link, 0 | Q931_CALL_REFERENCE_FLAG);
	if (!call) {
		return -1;
	}

	stop_t316(call);
	call->restart_tx.remain = (0 < ctrl->timers[PRI_TIMER_N316])
		? ctrl->timers[PRI_TIMER_N316] : 1;
	call->restart_tx.channel = channel;
	return q931_send_restart(call);
}

static int disconnect_ies[] = { Q931_CAUSE, Q931_IE_FACILITY, Q931_IE_USER_USER, -1 };

int q931_disconnect(struct pri *ctrl, q931_call *c, int cause)
{
	UPDATE_OURCALLSTATE(ctrl, c, Q931_CALL_STATE_DISCONNECT_REQUEST);
	c->peercallstate = Q931_CALL_STATE_DISCONNECT_INDICATION;
	if (c->alive) {
		c->alive = 0;
		c->cause = cause;
		c->causecode = CODE_CCITT;
		c->causeloc = LOC_PRIV_NET_LOCAL_USER;
		c->sendhangupack = 1;

		if (c->cc.record) {
			pri_cc_event(ctrl, c, c->cc.record, CC_EVENT_MSG_DISCONNECT);
		}

		pri_schedule_del(ctrl, c->retranstimer);
		c->retranstimer = pri_schedule_event(ctrl, ctrl->timers[PRI_TIMER_T305], pri_disconnect_timeout, c);
		return send_message(ctrl, c, Q931_DISCONNECT, disconnect_ies);
	} else
		return 0;
}

static int setup_ies[] = {
	Q931_BEARER_CAPABILITY,
	Q931_CHANNEL_IDENT,
	Q931_IE_FACILITY,
	Q931_PROGRESS_INDICATOR,
	Q931_NETWORK_SPEC_FAC,
	Q931_DISPLAY,
	Q931_IE_KEYPAD_FACILITY,
	Q931_REVERSE_CHARGE_INDIC,
	Q931_CALLING_PARTY_NUMBER,
	Q931_CALLING_PARTY_SUBADDR,
	Q931_CALLED_PARTY_NUMBER,
	Q931_CALLED_PARTY_SUBADDR,
	Q931_REDIRECTING_NUMBER,
	Q931_IE_USER_USER,
	Q931_SENDING_COMPLETE,
	Q931_IE_ORIGINATING_LINE_INFO,
	Q931_IE_GENERIC_DIGITS,
	-1
};

static int gr303_setup_ies[] = {
	Q931_BEARER_CAPABILITY,
	Q931_CHANNEL_IDENT,
	-1
};

/*! Call Independent Signalling SETUP ie's */
static int cis_setup_ies[] = {
	Q931_BEARER_CAPABILITY,
	Q931_CHANNEL_IDENT,
	Q931_IE_FACILITY,
	Q931_IE_KEYPAD_FACILITY,
	Q931_CALLING_PARTY_NUMBER,
	Q931_CALLING_PARTY_SUBADDR,
	Q931_CALLED_PARTY_NUMBER,
	Q931_CALLED_PARTY_SUBADDR,
	Q931_SENDING_COMPLETE,
	-1
};

static void stop_t303(struct q931_call *call)
{
	/* T303 should only be running on the master call */
	pri_schedule_del(call->pri, call->t303_timer);
	call->t303_timer = 0;
}

static void t303_expiry(void *data);

/*! \param call Call is not a subcall call record. */
static void start_t303(struct q931_call *call)
{
	struct pri *ctrl;

	ctrl = call->pri;
	pri_schedule_del(ctrl, call->t303_timer);
	call->t303_timer = pri_schedule_event(ctrl, ctrl->timers[PRI_TIMER_T303], t303_expiry,
		call);
}

static void t303_expiry(void *data)
{
	struct q931_call *c = data;/* Call is not a subcall call record. */
	struct pri *ctrl = c->pri;
	int res;

	if (ctrl->debug & PRI_DEBUG_Q931_STATE) {
		pri_message(ctrl, "T303 timed out.  cref:%d\n", c->cr);
	}

	c->t303_expirycnt++;
	c->t303_timer = 0;

	if (c->cause != -1) {
		/* We got a DISCONNECT, RELEASE, or RELEASE_COMPLETE and no other responses. */
		if (c->outboundbroadcast) {
			UPDATE_OURCALLSTATE(ctrl, c, Q931_CALL_STATE_CALL_ABORT);
		} else {
			/* This should never happen.  T303 should not be running in this case. */
			UPDATE_OURCALLSTATE(ctrl, c, Q931_CALL_STATE_NULL);
			c->peercallstate = Q931_CALL_STATE_NULL;
		}
		pri_fake_clearing(c);
	} else if (c->t303_expirycnt < 2) {
		/*!
		 * \todo XXX Resending the SETUP message loses any facility ies
		 * that the original may have had that were not added by
		 * pri_call_add_standard_apdus().  Actually any message Q.931
		 * retransmits will lose the facility ies.
		 */
		pri_call_add_standard_apdus(ctrl, c);
		if (ctrl->display_flags.send & PRI_DISPLAY_OPTION_NAME_INITIAL) {
			q931_display_name_send(c, &c->local_id.name);
		} else {
			q931_display_clear(c);
		}
		c->cc.saved_ie_contents.length = 0;
		c->cc.saved_ie_flags = 0;
		if (ctrl->link.next && !ctrl->bri)
			res = send_message(ctrl, c, Q931_SETUP, gr303_setup_ies);
		else if (c->cis_call)
			res = send_message(ctrl, c, Q931_SETUP, cis_setup_ies);
		else
			res = send_message(ctrl, c, Q931_SETUP, setup_ies);
		if (res) {
			pri_error(ctrl, "Error resending setup message!\n");
		}
		start_t303(c);
		if (c->outboundbroadcast) {
			start_t312(c);
		}
	} else {
		/*
		 * We never got any response for a normal call or an
		 * establishment response from any TEI for a master/subcall
		 * call.
		 */
		c->cause = PRI_CAUSE_NO_USER_RESPONSE;
		if (c->outboundbroadcast) {
			UPDATE_OURCALLSTATE(ctrl, c, Q931_CALL_STATE_CALL_ABORT);
		} else {
			UPDATE_OURCALLSTATE(ctrl, c, Q931_CALL_STATE_NULL);
			c->peercallstate = Q931_CALL_STATE_NULL;
		}
		pri_fake_clearing(c);
	}
}

int q931_setup(struct pri *ctrl, q931_call *c, struct pri_sr *req)
{
	int res;

	if (!req->called.number.valid && (!req->keypad_digits || !req->keypad_digits[0])) {
		/* No called number or keypad digits to send. */
		return -1;
	}

	c->called = req->called;
	libpri_copy_string(c->overlap_digits, req->called.number.str, sizeof(c->overlap_digits));

	if (req->keypad_digits) {
		libpri_copy_string(c->keypad_digits, req->keypad_digits,
			sizeof(c->keypad_digits));
	} else {
		c->keypad_digits[0] = '\0';
	}

	c->bc.transcapability = req->transmode;
	c->bc.transmoderate = TRANS_MODE_64_CIRCUIT;
	if (!req->userl1)
		req->userl1 = PRI_LAYER_1_ULAW;
	c->bc.userl1 = req->userl1;
	c->bc.userl2 = -1;
	c->bc.userl3 = -1;

	c->ds1no = (req->channel & 0xff00) >> 8;
	c->ds1explicit = (req->channel & 0x10000) >> 16;
	if ((ctrl->localtype == PRI_CPE) && ctrl->link.next && !ctrl->bri) {
		c->channelno = 0;
		c->chanflags = 0;
	} else {
		c->channelno = req->channel & 0xff;
		if (req->exclusive) {
			c->chanflags = FLAG_EXCLUSIVE;
		} else {
			c->chanflags = FLAG_PREFERRED;
		}
	}
	if (ctrl->localtype == PRI_CPE) {
		c->channel_id_ie_mandatory = 1;
	}

	c->slotmap = -1;
	c->nonisdn = req->nonisdn;
	c->newcall = 0;
	c->cis_call = req->cis_call;
	c->cis_recognized = req->cis_call;
	c->cis_auto_disconnect = req->cis_auto_disconnect;
	c->complete = req->numcomplete; 

	if (req->caller.number.valid) {
		c->local_id = req->caller;
		q931_party_id_fixup(ctrl, &c->local_id);
	}

	if (req->redirecting.from.number.valid) {
		c->redirecting = req->redirecting;
		q931_party_id_fixup(ctrl, &c->redirecting.from);
		q931_party_id_fixup(ctrl, &c->redirecting.to);
		q931_party_id_fixup(ctrl, &c->redirecting.orig_called);
	}

	if (req->useruserinfo)
		libpri_copy_string(c->useruserinfo, req->useruserinfo, sizeof(c->useruserinfo));
	else
		c->useruserinfo[0] = '\0';

	if (req->nonisdn && (ctrl->switchtype == PRI_SWITCH_NI2))
		c->progressmask = PRI_PROG_CALLER_NOT_ISDN;
	else
		c->progressmask = 0;

	c->reversecharge = req->reversecharge;

	c->aoc_charging_request = req->aoc_charging_request;

	pri_call_add_standard_apdus(ctrl, c);
	if (ctrl->display_flags.send & PRI_DISPLAY_OPTION_NAME_INITIAL) {
		q931_display_name_send(c, &c->local_id.name);
	} else {
		q931_display_clear(c);
	}

	/* Save the initial cc-parties. */
	c->cc.party_a = c->local_id;
	c->cc.originated = 1;
	if (c->redirecting.from.number.valid) {
		c->cc.initially_redirected = 1;
	}

	c->cc.saved_ie_contents.length = 0;
	c->cc.saved_ie_flags = 0;
	if (BRI_NT_PTMP(ctrl)) {
		c->outboundbroadcast = 1;
	}
	if (ctrl->link.next && !ctrl->bri)
		res = send_message(ctrl, c, Q931_SETUP, gr303_setup_ies);
	else if (c->cis_call)
		res = send_message(ctrl, c, Q931_SETUP, cis_setup_ies);
	else
		res = send_message(ctrl, c, Q931_SETUP, setup_ies);
	if (!res) {
		c->alive = 1;
		/* make sure we call PRI_EVENT_HANGUP_ACK once we send/receive RELEASE_COMPLETE */
		c->sendhangupack = 1;
		UPDATE_OURCALLSTATE(ctrl, c, Q931_CALL_STATE_CALL_INITIATED);
		c->peercallstate = Q931_CALL_STATE_CALL_PRESENT;
		c->t303_expirycnt = 0;
		start_t303(c);
		if (c->outboundbroadcast) {
			start_t312(c);
		}
	}
	return res;
}

static int register_ies[] = { Q931_IE_FACILITY, -1 };

/*!
 * \brief Build and send the REGISTER message.
 *
 * \param ctrl D channel controller.
 * \param call Q.931 call leg
 *
 * \retval 0 on success.
 * \retval -1 on error.
 */
int q931_register(struct pri *ctrl, q931_call *call)
{
	int res;

	call->newcall = 0;

	call->cis_call = 1;
	call->cis_recognized = 1;
	call->cis_auto_disconnect = 0;
	call->chanflags = FLAG_EXCLUSIVE;/* For safety mark this channel as exclusive. */
	call->channelno = 0;

	res = send_message(ctrl, call, Q931_REGISTER, register_ies);
	if (!res) {
		call->alive = 1;

		UPDATE_OURCALLSTATE(ctrl, call, Q931_CALL_STATE_CALL_INDEPENDENT_SERVICE);
		call->peercallstate = Q931_CALL_STATE_CALL_INDEPENDENT_SERVICE;
	}
	return res;
}

static int release_complete_ies[] = { Q931_IE_FACILITY, Q931_IE_USER_USER, -1 };

static int q931_release_complete(struct pri *ctrl, q931_call *c, int cause)
{
	int res = 0;
	UPDATE_OURCALLSTATE(ctrl, c, Q931_CALL_STATE_NULL);
	c->peercallstate = Q931_CALL_STATE_NULL;
	if (c->cc.record) {
		pri_cc_event(ctrl, c, c->cc.record, CC_EVENT_MSG_RELEASE_COMPLETE);
	}
	if (cause > -1) {
		c->cause = cause;
		c->causecode = CODE_CCITT;
		c->causeloc = LOC_PRIV_NET_LOCAL_USER;
		/* release_ies has CAUSE in it */
		res = send_message(ctrl, c, Q931_RELEASE_COMPLETE, release_ies);
	} else
		res = send_message(ctrl, c, Q931_RELEASE_COMPLETE, release_complete_ies);
	c->alive = 0;
	/* release the structure */
	res += pri_hangup(ctrl, c, cause);
	return res;
}

static int connect_ack_ies[] = { -1 };
static int connect_ack_w_chan_id_ies[] = { Q931_CHANNEL_IDENT, -1 };
static int gr303_connect_ack_ies[] = { Q931_CHANNEL_IDENT, -1 };

int q931_connect_acknowledge(struct pri *ctrl, q931_call *call, int channel)
{
	int *use_ies;
	struct q931_call *winner;

	winner = q931_find_winning_call(call);
	if (!winner) {
		return -1;
	}

	if (winner != call) {
		UPDATE_OURCALLSTATE(ctrl, call, Q931_CALL_STATE_ACTIVE);
		call->peercallstate = Q931_CALL_STATE_ACTIVE;
	}
	UPDATE_OURCALLSTATE(ctrl, winner, Q931_CALL_STATE_ACTIVE);
	winner->peercallstate = Q931_CALL_STATE_ACTIVE;
	if (channel) {
		winner->ds1no = (channel & 0xff00) >> 8;
		winner->ds1explicit = (channel & 0x10000) >> 16;
		winner->channelno = channel & 0xff;
		winner->chanflags &= ~FLAG_PREFERRED;
		winner->chanflags |= FLAG_EXCLUSIVE;
	}
	use_ies = NULL;
	if (ctrl->link.next && !ctrl->bri) {
		if (ctrl->localtype == PRI_CPE) {
			use_ies = gr303_connect_ack_ies;
		}
	} else if (channel) {
		use_ies = connect_ack_w_chan_id_ies;
	} else {
		use_ies = connect_ack_ies;
	}
	if (use_ies) {
		return send_message(ctrl, winner, Q931_CONNECT_ACKNOWLEDGE, use_ies);
	}
	return 0;
}

/*!
 * \internal
 * \brief Send HOLD message response wait timeout.
 *
 * \param data Q.931 call leg. (Master Q.931 subcall structure)
 *
 * \return Nothing
 */
static void q931_hold_timeout(void *data)
{
	struct q931_call *call = data;
	struct q931_call *master = call->master_call;
	struct pri *ctrl = call->pri;

	if (ctrl->debug & PRI_DEBUG_Q931_STATE) {
		pri_message(ctrl, "Time-out waiting for HOLD response\n");
	}

	/* Ensure that the timer is deleted. */
	pri_schedule_del(ctrl, master->hold_timer);
	master->hold_timer = 0;

	/* Don't change the hold state if there was HOLD a collision. */
	switch (master->hold_state) {
	case Q931_HOLD_STATE_HOLD_REQ:
		UPDATE_HOLD_STATE(ctrl, master, Q931_HOLD_STATE_IDLE);
		break;
	default:
		break;
	}

	q931_clr_subcommands(ctrl);
	ctrl->schedev = 1;
	ctrl->ev.e = PRI_EVENT_HOLD_REJ;
	ctrl->ev.hold_rej.channel = q931_encode_channel(call);
	ctrl->ev.hold_rej.call = master;
	ctrl->ev.hold_rej.cause = PRI_CAUSE_MESSAGE_TYPE_NONEXIST;
	ctrl->ev.hold_rej.subcmds = &ctrl->subcmds;
}

/*!
 * \internal
 * \brief Determine if a hold request is allowed now.
 *
 * \param ctrl D channel controller.
 * \param call Q.931 call leg. (Master Q.931 subcall structure)
 *
 * \retval TRUE if we can send a HOLD request.
 * \retval FALSE if not allowed.
 */
static int q931_is_hold_allowed(const struct pri *ctrl, const struct q931_call *call)
{
	int allowed;

	allowed = 0;
	switch (call->ourcallstate) {
	case Q931_CALL_STATE_CALL_RECEIVED:
	case Q931_CALL_STATE_CONNECT_REQUEST:
	case Q931_CALL_STATE_INCOMING_CALL_PROCEEDING:
		if (PTMP_MODE(ctrl)) {
			/* HOLD request only allowed in these states if point-to-point mode. */
			break;
		}
		/* Fall through */
	case Q931_CALL_STATE_OUTGOING_CALL_PROCEEDING:
	case Q931_CALL_STATE_CALL_DELIVERED:
	case Q931_CALL_STATE_ACTIVE:
		switch (call->hold_state) {
		case Q931_HOLD_STATE_IDLE:
			allowed = 1;
			break;
		default:
			break;
		}
		break;
	case Q931_CALL_STATE_DISCONNECT_INDICATION:
	case Q931_CALL_STATE_RELEASE_REQUEST:
		/* Ignore HOLD request in these states. */
		break;
	default:
		break;
	}

	return allowed;
}

static int hold_ies[] = {
	-1
};

/*!
 * \brief Send the HOLD message.
 *
 * \param ctrl D channel controller.
 * \param call Q.931 call leg. (Master Q.931 subcall structure)
 *
 * \retval 0 on success.
 * \retval -1 on error.
 */
int q931_send_hold(struct pri *ctrl, struct q931_call *call)
{
	struct q931_call *winner;

	winner = q931_find_winning_call(call);
	if (!winner || !q931_is_hold_allowed(ctrl, call)) {
		return -1;
	}
	pri_schedule_del(ctrl, call->hold_timer);
	call->hold_timer = pri_schedule_event(ctrl, ctrl->timers[PRI_TIMER_T_HOLD],
		q931_hold_timeout, winner);
	if (!call->hold_timer || send_message(ctrl, winner, Q931_HOLD, hold_ies)) {
		pri_schedule_del(ctrl, call->hold_timer);
		call->hold_timer = 0;
		return -1;
	}
	UPDATE_HOLD_STATE(ctrl, call, Q931_HOLD_STATE_HOLD_REQ);
	return 0;
}

static int hold_ack_ies[] = {
	-1
};

/*!
 * \brief Send the HOLD ACKNOWLEDGE message.
 *
 * \param ctrl D channel controller.
 * \param call Q.931 call leg. (Master Q.931 subcall structure)
 *
 * \retval 0 on success.
 * \retval -1 on error.
 */
int q931_send_hold_ack(struct pri *ctrl, struct q931_call *call)
{
	struct q931_call *winner;

	UPDATE_HOLD_STATE(ctrl, call, Q931_HOLD_STATE_CALL_HELD);

	winner = q931_find_winning_call(call);
	if (!winner) {
		return -1;
	}

	/* Call is now on hold so forget the channel. */
	winner->channelno = 0;/* No channel */
	winner->ds1no = 0;
	winner->ds1explicit = 0;
	winner->chanflags = 0;

	return send_message(ctrl, winner, Q931_HOLD_ACKNOWLEDGE, hold_ack_ies);
}

static int hold_reject_ies[] = {
	Q931_CAUSE,
	-1
};

/*!
 * \internal
 * \brief Send the HOLD REJECT message only.
 *
 * \param ctrl D channel controller.
 * \param call Q.931 call leg. (subcall)
 * \param cause Q.931 cause code for rejecting the hold request.
 *
 * \retval 0 on success.
 * \retval -1 on error.
 */
static int q931_send_hold_rej_msg(struct pri *ctrl, struct q931_call *call, int cause)
{
	call->cause = cause;
	call->causecode = CODE_CCITT;
	call->causeloc = LOC_PRIV_NET_LOCAL_USER;
	return send_message(ctrl, call, Q931_HOLD_REJECT, hold_reject_ies);
}

/*!
 * \brief Send the HOLD REJECT message.
 *
 * \param ctrl D channel controller.
 * \param call Q.931 call leg. (Master Q.931 subcall structure)
 * \param cause Q.931 cause code for rejecting the hold request.
 *
 * \retval 0 on success.
 * \retval -1 on error.
 */
int q931_send_hold_rej(struct pri *ctrl, struct q931_call *call, int cause)
{
	struct q931_call *winner;

	UPDATE_HOLD_STATE(ctrl, call, Q931_HOLD_STATE_IDLE);

	winner = q931_find_winning_call(call);
	if (!winner) {
		return -1;
	}

	return q931_send_hold_rej_msg(ctrl, winner, cause);
}

/*!
 * \internal
 * \brief Send RETRIEVE message response wait timeout.
 *
 * \param data Q.931 call leg. (Master Q.931 subcall structure)
 *
 * \return Nothing
 */
static void q931_retrieve_timeout(void *data)
{
	struct q931_call *call = data;
	struct q931_call *master = call->master_call;
	struct pri *ctrl = call->pri;

	if (ctrl->debug & PRI_DEBUG_Q931_STATE) {
		pri_message(ctrl, "Time-out waiting for RETRIEVE response\n");
	}

	/* Ensure that the timer is deleted. */
	pri_schedule_del(ctrl, master->hold_timer);
	master->hold_timer = 0;

	/* Don't change the hold state if there was RETRIEVE a collision. */
	switch (master->hold_state) {
	case Q931_HOLD_STATE_CALL_HELD:
	case Q931_HOLD_STATE_RETRIEVE_REQ:
		UPDATE_HOLD_STATE(ctrl, master, Q931_HOLD_STATE_CALL_HELD);

		/* Call is still on hold so forget the channel. */
		call->channelno = 0;/* No channel */
		call->ds1no = 0;
		call->ds1explicit = 0;
		call->chanflags = 0;
		break;
	default:
		break;
	}

	q931_clr_subcommands(ctrl);
	ctrl->schedev = 1;
	ctrl->ev.e = PRI_EVENT_RETRIEVE_REJ;
	ctrl->ev.retrieve_rej.channel = q931_encode_channel(call);
	ctrl->ev.retrieve_rej.call = master;
	ctrl->ev.retrieve_rej.cause = PRI_CAUSE_MESSAGE_TYPE_NONEXIST;
	ctrl->ev.retrieve_rej.subcmds = &ctrl->subcmds;
}

/*!
 * \internal
 * \brief Determine if a retrieve request is allowed now.
 *
 * \param ctrl D channel controller.
 * \param call Q.931 call leg. (Master Q.931 subcall structure)
 *
 * \retval TRUE if we can send a RETRIEVE request.
 * \retval FALSE if not allowed.
 */
static int q931_is_retrieve_allowed(const struct pri *ctrl, const struct q931_call *call)
{
	int allowed;

	allowed = 0;
	switch (call->ourcallstate) {
	case Q931_CALL_STATE_CALL_RECEIVED:
	case Q931_CALL_STATE_CONNECT_REQUEST:
	case Q931_CALL_STATE_INCOMING_CALL_PROCEEDING:
		if (PTMP_MODE(ctrl)) {
			/* RETRIEVE request only allowed in these states if point-to-point mode. */
			break;
		}
		/* Fall through */
	case Q931_CALL_STATE_OUTGOING_CALL_PROCEEDING:
	case Q931_CALL_STATE_CALL_DELIVERED:
	case Q931_CALL_STATE_ACTIVE:
		switch (call->hold_state) {
		case Q931_HOLD_STATE_CALL_HELD:
			allowed = 1;
			break;
		default:
			break;
		}
		break;
	case Q931_CALL_STATE_DISCONNECT_INDICATION:
	case Q931_CALL_STATE_RELEASE_REQUEST:
		/* Ignore RETRIEVE request in these states. */
		break;
	default:
		break;
	}

	return allowed;
}

static int retrieve_ies[] = {
	Q931_CHANNEL_IDENT,
	-1
};

/*!
 * \brief Send the RETRIEVE message.
 *
 * \param ctrl D channel controller.
 * \param call Q.931 call leg. (Master Q.931 subcall structure)
 * \param channel Encoded channel id to use.  If zero do not send channel id.
 *
 * \retval 0 on success.
 * \retval -1 on error.
 */
int q931_send_retrieve(struct pri *ctrl, struct q931_call *call, int channel)
{
	struct q931_call *winner;

	winner = q931_find_winning_call(call);
	if (!winner || !q931_is_retrieve_allowed(ctrl, call)) {
		return -1;
	}

	if (channel) {
		winner->ds1no = (channel & 0xff00) >> 8;
		winner->ds1explicit = (channel & 0x10000) >> 16;
		winner->channelno = channel & 0xff;
		if (ctrl->localtype == PRI_NETWORK && winner->channelno != 0xFF) {
			winner->chanflags = FLAG_EXCLUSIVE;
		} else {
			winner->chanflags = FLAG_PREFERRED;
		}
	} else {
		/* Do not send Q931_CHANNEL_IDENT */
		winner->chanflags = 0;
	}

	pri_schedule_del(ctrl, call->hold_timer);
	call->hold_timer = pri_schedule_event(ctrl, ctrl->timers[PRI_TIMER_T_RETRIEVE],
		q931_retrieve_timeout, winner);
	if (!call->hold_timer || send_message(ctrl, winner, Q931_RETRIEVE, retrieve_ies)) {
		pri_schedule_del(ctrl, call->hold_timer);
		call->hold_timer = 0;

		/* Call is still on hold so forget the channel. */
		winner->channelno = 0;/* No channel */
		winner->ds1no = 0;
		winner->ds1explicit = 0;
		winner->chanflags = 0;
		return -1;
	}
	UPDATE_HOLD_STATE(ctrl, call, Q931_HOLD_STATE_RETRIEVE_REQ);
	return 0;
}

static int retrieve_ack_ies[] = {
	Q931_CHANNEL_IDENT,
	-1
};

/*!
 * \brief Send the RETRIEVE ACKNOWLEDGE message.
 *
 * \param ctrl D channel controller.
 * \param call Q.931 call leg. (Master Q.931 subcall structure)
 * \param channel Encoded channel id to use.
 *
 * \retval 0 on success.
 * \retval -1 on error.
 */
int q931_send_retrieve_ack(struct pri *ctrl, struct q931_call *call, int channel)
{
	struct q931_call *winner;

	winner = q931_find_winning_call(call);
	if (!winner) {
		return -1;
	}

	winner->ds1no = (channel & 0xff00) >> 8;
	winner->ds1explicit = (channel & 0x10000) >> 16;
	winner->channelno = channel & 0xff;
	winner->chanflags = FLAG_EXCLUSIVE;

	UPDATE_HOLD_STATE(ctrl, call, Q931_HOLD_STATE_IDLE);

	return send_message(ctrl, winner, Q931_RETRIEVE_ACKNOWLEDGE, retrieve_ack_ies);
}

static int retrieve_reject_ies[] = {
	Q931_CAUSE,
	-1
};

/*!
 * \internal
 * \brief Send the RETRIEVE REJECT message only.
 *
 * \param ctrl D channel controller.
 * \param call Q.931 call leg. (subcall)
 * \param cause Q.931 cause code for rejecting the retrieve request.
 *
 * \retval 0 on success.
 * \retval -1 on error.
 */
static int q931_send_retrieve_rej_msg(struct pri *ctrl, struct q931_call *call, int cause)
{
	call->cause = cause;
	call->causecode = CODE_CCITT;
	call->causeloc = LOC_PRIV_NET_LOCAL_USER;
	return send_message(ctrl, call, Q931_RETRIEVE_REJECT, retrieve_reject_ies);
}

/*!
 * \brief Send the RETRIEVE REJECT message.
 *
 * \param ctrl D channel controller.
 * \param call Q.931 call leg. (Master Q.931 subcall structure)
 * \param cause Q.931 cause code for rejecting the retrieve request.
 *
 * \retval 0 on success.
 * \retval -1 on error.
 */
int q931_send_retrieve_rej(struct pri *ctrl, struct q931_call *call, int cause)
{
	struct q931_call *winner;

	UPDATE_HOLD_STATE(ctrl, call, Q931_HOLD_STATE_CALL_HELD);

	winner = q931_find_winning_call(call);
	if (!winner) {
		return -1;
	}

	/* Call is still on hold so forget the channel. */
	winner->channelno = 0;/* No channel */
	winner->ds1no = 0;
	winner->ds1explicit = 0;
	winner->chanflags = 0;

	return q931_send_retrieve_rej_msg(ctrl, winner, cause);
}

static int __q931_hangup(struct pri *ctrl, q931_call *c, int cause)
{
	int disconnect = 1;
	int release_compl = 0;

	if (!ctrl || !c) {
		return -1;
	}
	if (ctrl->debug & PRI_DEBUG_Q931_STATE) {
		pri_message(ctrl,
			DBGHEAD "ourstate %s, peerstate %s, hold-state %s\n", DBGINFO,
			q931_call_state_str(c->ourcallstate),
			q931_call_state_str(c->peercallstate),
			q931_hold_state_str(c->master_call->hold_state));
	}

	/* If mandatory IE was missing, insist upon that cause code */
	if (c->cause == PRI_CAUSE_MANDATORY_IE_MISSING)
		cause = c->cause;
	switch (cause) {
	case PRI_CAUSE_NORMAL_CIRCUIT_CONGESTION:
	case PRI_CAUSE_REQUESTED_CHAN_UNAVAIL:
	case PRI_CAUSE_IDENTIFIED_CHANNEL_NOTEXIST:
	case PRI_CAUSE_UNALLOCATED:
		if (!ctrl->hangup_fix_enabled) {
			/* Legacy: We'll send RELEASE_COMPLETE with these causes */
			disconnect = 0;
			release_compl = 1;
			break;
		}
		/* Fall through */
	case PRI_CAUSE_INCOMPATIBLE_DESTINATION:
		/* See Q.931 Section 5.3.2 a) */
		switch (c->ourcallstate) {
		case Q931_CALL_STATE_NULL:
		case Q931_CALL_STATE_CALL_INITIATED:
		case Q931_CALL_STATE_CALL_PRESENT:
			/*
			 * Send RELEASE_COMPLETE because some other message
			 * has not been sent previously.
			 */
			disconnect = 0;
			release_compl = 1;
			break;
		case Q931_CALL_STATE_CONNECT_REQUEST:
			/*
			 * Send RELEASE because the B channel negotiation failed
			 * for call waiting.
			 */
			disconnect = 0;
			break;
		default:
			/*
			 * Send DISCONNECT because some other message
			 * has been sent previously.
			 */
			break;
		}
		break;
	case PRI_CAUSE_INVALID_CALL_REFERENCE:
		/* We'll send RELEASE_COMPLETE with these causes */
		disconnect = 0;
		release_compl = 1;
		break;
	case PRI_CAUSE_CHANNEL_UNACCEPTABLE:
	case PRI_CAUSE_CALL_AWARDED_DELIVERED:
	case PRI_CAUSE_NONSELECTED_USER_CLEARING:
		/* We'll send RELEASE with these causes */
		disconnect = 0;
		break;
	default:
		break;
	}
	if (c->cis_call) {
		disconnect = 0;
	}

	c->hangupinitiated = 1;
	stop_t303(c);

	/* All other causes we send with DISCONNECT */
	switch(c->ourcallstate) {
	case Q931_CALL_STATE_NULL:
		if (c->peercallstate == Q931_CALL_STATE_NULL)
			/* free the resources if we receive or send REL_COMPL */
			pri_destroycall(ctrl, c);
		else if (c->peercallstate == Q931_CALL_STATE_RELEASE_REQUEST)
			q931_release_complete(ctrl,c,cause);
		break;
	case Q931_CALL_STATE_CALL_INITIATED:
		/* we sent SETUP */
	case Q931_CALL_STATE_OVERLAP_SENDING:
		/* received SETUP_ACKNOWLEDGE */
	case Q931_CALL_STATE_OUTGOING_CALL_PROCEEDING:
		/* received CALL_PROCEEDING */
	case Q931_CALL_STATE_CALL_DELIVERED:
		/* received ALERTING */
	case Q931_CALL_STATE_CALL_PRESENT:
		/* received SETUP */
	case Q931_CALL_STATE_CALL_RECEIVED:
		/* sent ALERTING */
	case Q931_CALL_STATE_CONNECT_REQUEST:
		/* sent CONNECT */
	case Q931_CALL_STATE_INCOMING_CALL_PROCEEDING:
		/* we sent CALL_PROCEEDING */
	case Q931_CALL_STATE_OVERLAP_RECEIVING:
		/* received SETUP_ACKNOWLEDGE */
		/* send DISCONNECT in general */
		switch (c->peercallstate) {
		default:
			if (disconnect)
				q931_disconnect(ctrl,c,cause);
			else if (release_compl)
				q931_release_complete(ctrl,c,cause);
			else
				q931_release(ctrl,c,cause);
			break;
		case Q931_CALL_STATE_NULL:
		case Q931_CALL_STATE_DISCONNECT_REQUEST:
		case Q931_CALL_STATE_DISCONNECT_INDICATION:
		case Q931_CALL_STATE_RELEASE_REQUEST:
		case Q931_CALL_STATE_RESTART_REQUEST:
		case Q931_CALL_STATE_RESTART:
			pri_error(ctrl,
				"Weird, doing nothing but this shouldn't happen, ourstate %s, peerstate %s\n",
				q931_call_state_str(c->ourcallstate),
				q931_call_state_str(c->peercallstate));
			break;
		}
		break;
	case Q931_CALL_STATE_ACTIVE:
		/* received CONNECT */
		if (c->cis_call) {
			q931_release(ctrl, c, cause);
			break;
		}
		q931_disconnect(ctrl,c,cause);
		break;
	case Q931_CALL_STATE_DISCONNECT_REQUEST:
		/* sent DISCONNECT */
		q931_release(ctrl,c,cause);
		break;
	case Q931_CALL_STATE_CALL_ABORT:
		/* Don't do anything, waiting for T312 to expire. */
		break;
	case Q931_CALL_STATE_DISCONNECT_INDICATION:
		/* received DISCONNECT */
		if (c->peercallstate == Q931_CALL_STATE_DISCONNECT_REQUEST) {
			c->alive = 1;
			q931_release(ctrl,c,cause);
		}
		break;
	case Q931_CALL_STATE_RELEASE_REQUEST:
		/* sent RELEASE */
		/* don't do anything, waiting for RELEASE_COMPLETE */
		break;
	case Q931_CALL_STATE_CALL_INDEPENDENT_SERVICE:
		/* we sent or received REGISTER */
		q931_release_complete(ctrl, c, cause);
		break;
	case Q931_CALL_STATE_RESTART:
	case Q931_CALL_STATE_RESTART_REQUEST:
		/* sent RESTART */
		pri_error(ctrl,
			"q931_hangup shouldn't be called in this state, ourstate %s, peerstate %s\n",
			q931_call_state_str(c->ourcallstate),
			q931_call_state_str(c->peercallstate));
		break;
	default:
		pri_error(ctrl,
			"We're not yet handling hanging up when our state is %d, contact support@digium.com, ourstate %s, peerstate %s\n",
			c->ourcallstate,
			q931_call_state_str(c->ourcallstate),
			q931_call_state_str(c->peercallstate));
		return -1;
	}
	/* we did handle hangup properly at this point */
	return 0;
}

static void initiate_hangup_if_needed(struct q931_call *master, int idx, int cause);

int q931_hangup(struct pri *ctrl, q931_call *call, int cause)
{
	int i;

	if (call->master_call->outboundbroadcast) {
		if (call->master_call == call) {
			int slaves;

			if (ctrl->debug & PRI_DEBUG_Q931_STATE) {
				pri_message(ctrl, DBGHEAD "Hangup master cref:%d\n", DBGINFO, call->cr);
			}

			UPDATE_OURCALLSTATE(ctrl, call, Q931_CALL_STATE_CALL_ABORT);
			if (call->pri_winner < 0 && call->alive) {
				/*
				 * Fake clearing if we have no winner to get rid of the upper
				 * layer.
				 */
				pri_create_fake_clearing(ctrl, call);
			} else if (call->fake_clearing_timer) {
				/*
				 * No need for fake clearing to be running anymore.
				 * Will this actually happen?
				 */
				if (ctrl->debug & PRI_DEBUG_Q931_STATE) {
					pri_message(ctrl, "Fake clearing request cancelled.  cref:%d\n",
						call->cr);
				}
				pri_schedule_del(ctrl, call->fake_clearing_timer);
				call->fake_clearing_timer = 0;
			}

			/* Initiate hangup of slaves */
			call->master_hanging_up = 1;
			for (i = 0; i < ARRAY_LEN(call->subcalls); ++i) {
				if (call->subcalls[i]) {
					if (ctrl->debug & PRI_DEBUG_Q931_STATE) {
						pri_message(ctrl, DBGHEAD "Hanging up %d, winner:%d subcall:%p\n",
							DBGINFO, i, call->pri_winner, call->subcalls[i]);
					}
					if (i == call->pri_winner) {
						q931_hangup(ctrl, call->subcalls[i], cause);
					} else {
						initiate_hangup_if_needed(call, i, cause);
					}
				}
			}
			call->master_hanging_up = 0;

			slaves = q931_get_subcall_count(call);
			if (ctrl->debug & PRI_DEBUG_Q931_STATE) {
				pri_message(ctrl, DBGHEAD "Remaining slaves %d\n", DBGINFO, slaves);
			}

			stop_t303(call);
			if (!call->t312_timer && !slaves) {
				/*
				 * T312 has expired and no slaves are left so we can safely
				 * destroy the master.
				 */
				q931_destroycall(ctrl, call);
			}
			return 0;
		} else {
			if (ctrl->debug & PRI_DEBUG_Q931_STATE) {
				pri_message(ctrl, DBGHEAD "Hangup slave cref:%d\n", DBGINFO, call->cr);
			}
			return __q931_hangup(ctrl, call, cause);
		}
	} else {
		if (ctrl->debug & PRI_DEBUG_Q931_STATE) {
			pri_message(ctrl, DBGHEAD "Hangup other cref:%d\n", DBGINFO, call->cr);
		}
		return __q931_hangup(ctrl, call, cause);
	}
	return 0;
}

static int prepare_to_handle_maintenance_message(struct pri *ctrl, q931_mh *mh, q931_call *c)
{
	if ((!ctrl) || (!mh) || (!c)) {
		return -1;
	}
	/* SERVICE messages are a superset of messages that can take b-channels
	 * or entire d-channels in and out of service */
	switch(mh->msg) {
		/* the ATT_SERVICE/ATT_SERVICE_ACKNOWLEDGE and NATIONAL_SERVICE/NATIONAL_SERVICE_ACKNOWLEDGE
		 * are mirrors of each other.  We only have to check for one type because they are pre-handled
		 * the same way as each other */
		case ATT_SERVICE:
		case ATT_SERVICE_ACKNOWLEDGE:
			c->channelno = -1;
			c->slotmap = -1;
			c->chanflags = 0;
			c->ds1explicit = 0;
			c->ds1no = 0;
			c->cis_call = 0;
			c->ri = -1;
			c->changestatus = -1;
			break;
		default:
			pri_error(ctrl,
				"!! Don't know how to pre-handle maintenance message type '0x%X'\n",
				mh->msg);
			return -1;
	}
	return 0;
}

static int prepare_to_handle_q931_message(struct pri *ctrl, q931_mh *mh, q931_call *c)
{
	if ((!ctrl) || (!mh) || (!c)) {
		return -1;
	}
	
	switch(mh->msg) {
	case Q931_RESTART:
		if (ctrl->debug & PRI_DEBUG_Q931_STATE)
			pri_message(ctrl, "-- Processing Q.931 Restart\n");
		/* Reset information */
		c->channelno = -1;
		c->slotmap = -1;
		c->chanflags = 0;
		c->ds1no = 0;
		c->ds1explicit = 0;
		c->cis_call = 0;
		c->ri = -1;
		break;
	case Q931_FACILITY:
		c->notify = -1;
		q931_party_number_init(&c->redirection_number);
		if (q931_is_dummy_call(c)) {
			q931_party_address_init(&c->called);
		}
		break;
	case Q931_SETUP:
		if (ctrl->debug & PRI_DEBUG_Q931_STATE)
			pri_message(ctrl, "-- Processing Q.931 Call Setup\n");
		c->cc.saved_ie_contents.length = 0;
		c->cc.saved_ie_flags = 0;
		/* Fall through */
	case Q931_REGISTER:
		c->channelno = -1;
		c->slotmap = -1;
		c->chanflags = 0;
		c->ds1no = 0;
		c->ri = -1;

		c->bc.transcapability = -1;
		c->bc.transmoderate = -1;
		c->bc.transmultiple = -1;
		c->bc.userl1 = -1;
		c->bc.userl2 = -1;
		c->bc.userl3 = -1;
		c->bc.rateadaption = -1;

		q931_party_address_init(&c->called);
		q931_party_id_init(&c->local_id);
		q931_party_id_init(&c->remote_id);
		q931_party_number_init(&c->ani);
		q931_party_redirecting_init(&c->redirecting);

		/*
		 * Make sure that keypad and overlap digit buffers are empty in
		 * case they are not in the message.
		 */
		c->keypad_digits[0] = '\0';
		c->overlap_digits[0] = '\0';

		c->useruserprotocoldisc = -1; 
		c->useruserinfo[0] = '\0';
		c->complete = 0;
		c->nonisdn = 0;
		c->aoc_units = -1;
		c->reversecharge = -1;
		/* Fall through */
	case Q931_CONNECT:
	case Q931_ALERTING:
	case Q931_PROGRESS:
		c->useruserinfo[0] = '\0';
		c->cause = -1;
		/* Fall through */
	case Q931_SETUP_ACKNOWLEDGE:
	case Q931_CALL_PROCEEDING:
		c->progress = -1;
		c->progressmask = 0;
		break;
	case Q931_CONNECT_ACKNOWLEDGE:
		pri_schedule_del(ctrl, c->retranstimer);
		c->retranstimer = 0;
		break;
	case Q931_RELEASE:
	case Q931_DISCONNECT:
		c->cause = -1;
		c->causecode = -1;
		c->causeloc = -1;
		c->progress = -1;
		c->progressmask = 0;
		c->aoc_units = -1;
		pri_schedule_del(ctrl, c->retranstimer);
		c->retranstimer = 0;
		c->useruserinfo[0] = '\0';
		break;
	case Q931_RELEASE_COMPLETE:
		pri_schedule_del(ctrl, c->retranstimer);
		c->retranstimer = 0;
		c->useruserinfo[0] = '\0';
		/* Fall through */
	case Q931_STATUS:
		c->cause = -1;
		c->causecode = -1;
		c->causeloc = -1;
		c->sugcallstate = Q931_CALL_STATE_NOT_SET;
		c->aoc_units = -1;
		break;
	case Q931_RESTART_ACKNOWLEDGE:
		c->channelno = -1;
		c->ds1no = 0;
		c->ds1explicit = 0;
		c->cis_call = 0;
		break;
	case Q931_INFORMATION:
		/*
		 * Make sure that keypad and overlap digit buffers are empty in
		 * case they are not in the message.
		 */
		c->keypad_digits[0] = '\0';
		c->overlap_digits[0] = '\0';
		break;
	case Q931_STATUS_ENQUIRY:
		break;
	case Q931_NOTIFY:
		c->notify = -1;
		q931_party_number_init(&c->redirection_number);
		break;
	case Q931_HOLD:
		break;
	case Q931_HOLD_ACKNOWLEDGE:
		break;
	case Q931_HOLD_REJECT:
		c->cause = -1;
		break;
	case Q931_RETRIEVE:
		c->channelno = 0xFF;
		c->ds1no = 0;
		c->ds1explicit = 0;
		break;
	case Q931_RETRIEVE_ACKNOWLEDGE:
		break;
	case Q931_RETRIEVE_REJECT:
		c->cause = -1;
		break;
	case Q931_USER_INFORMATION:
	case Q931_SEGMENT:
	case Q931_CONGESTION_CONTROL:
	case Q931_RESUME:
	case Q931_RESUME_ACKNOWLEDGE:
	case Q931_RESUME_REJECT:
	case Q931_SUSPEND:
	case Q931_SUSPEND_ACKNOWLEDGE:
	case Q931_SUSPEND_REJECT:
		pri_error(ctrl, "!! Not yet handling pre-handle message type %s (0x%X)\n",
			msg2str(mh->msg), mh->msg);
		/* Fall through */
	default:
		pri_error(ctrl, "!! Don't know how to pre-handle message type %s (0x%X)\n",
			msg2str(mh->msg), mh->msg);
		q931_status(ctrl,c, PRI_CAUSE_MESSAGE_TYPE_NONEXIST);
		return -1;
	}
	return 0;
}

static struct q931_call *q931_get_subcall_winner(struct q931_call *master)
{
	if (master->pri_winner < 0) {
		return NULL;
	} else {
		return master->subcalls[master->pri_winner];
	}
}

static void initiate_hangup_if_needed(struct q931_call *master, int idx, int cause)
{
	struct pri *ctrl;
	struct q931_call *subcall;

	ctrl = master->pri;
	subcall = master->subcalls[idx];

	if (!subcall->hangupinitiated) {
		q931_hangup(ctrl, subcall, cause);
		if (master->subcalls[idx] == subcall) {
			/* The subcall was not destroyed. */
			subcall->alive = 0;
		}
	}
}

static void q931_set_subcall_winner(struct q931_call *subcall)
{
	struct q931_call *master = subcall->master_call;
	int i;

	/* Set the winner first */
	for (i = 0; ; ++i) {
		if (ARRAY_LEN(master->subcalls) <= i) {
			pri_error(subcall->pri, "We should always find the winner in the list!\n");
			return;
		}
		if (master->subcalls[i] == subcall) {
			master->pri_winner = i;
			break;
		}
	}

	/* Start tear down of calls that were not chosen */
	for (i = 0; i < ARRAY_LEN(master->subcalls); ++i) {
		if (master->subcalls[i] && master->subcalls[i] != subcall) {
			initiate_hangup_if_needed(master, i, PRI_CAUSE_NONSELECTED_USER_CLEARING);
		}
	}
}

static struct q931_call *q931_get_subcall(struct q921_link *link, struct q931_call *master_call)
{
	int i;
	struct q931_call *cur;
	struct pri *ctrl;
	int firstfree = -1;

	ctrl = link->ctrl;

	/* First try to locate our subcall */
	for (i = 0; i < ARRAY_LEN(master_call->subcalls); ++i) {
		if (master_call->subcalls[i]) {
			if (master_call->subcalls[i]->link == link) {
				return master_call->subcalls[i];
			}
		} else if (firstfree == -1) {
			firstfree = i;
		}
	}
	if (firstfree < 0) {
		pri_error(ctrl, "Tried to add more than %d TEIs to call and failed\n",
			(int) ARRAY_LEN(master_call->subcalls));
		return NULL;
	}

	/* Create new subcall. */
	cur = malloc(sizeof(*cur));
	if (!cur) {
		pri_error(ctrl, "Unable to allocate call\n");
		return NULL;
	}
	*cur = *master_call;
	//cur->pri = ctrl;/* We get this assignment for free. */
	cur->link = link;
	cur->next = NULL;
	cur->apdus = NULL;
	cur->bridged_call = NULL;
	//cur->master_call = master_call; /* We get this assignment for free. */
	for (i = 0; i < ARRAY_LEN(cur->subcalls); ++i) {
		cur->subcalls[i] = NULL;
	}
	cur->t303_timer = 0;/* T303 should only be on on the master call */
	cur->t312_timer = 0;/* T312 should only be on on the master call */
	cur->fake_clearing_timer = 0;/* Fake clearing should only be on on the master call */
	cur->hold_timer = 0;
	cur->retranstimer = 0;

	/*
	 * Mark this subcall as a newcall until it is determined if the
	 * subcall can compete for the call.
	 */
	cur->newcall = 1;

	/* Assume we sent a SETUP and this is the first response to it from this peer. */
	cur->ourcallstate = Q931_CALL_STATE_CALL_INITIATED;
	cur->peercallstate = Q931_CALL_STATE_CALL_PRESENT;

	master_call->subcalls[firstfree] = cur;

	if (ctrl->debug & PRI_DEBUG_Q931_STATE) {
		pri_message(ctrl, "Adding subcall %p for TEI %d to call %p at position %d\n",
			cur, link->tei, master_call, firstfree);
	}
	/* Should only get here if the TEI is not found */
	return cur;
}

int q931_receive(struct q921_link *link, q931_h *h, int len)
{
	q931_mh *mh;
	struct q931_call *c;
	struct pri *ctrl;
	q931_ie *ie;
	unsigned int x;
	int y;
	int res;
	int r;
	int mandies[MAX_MAND_IES];
	int is_mandatory;
	int codeset, cur_codeset;
	int last_ie[8];
	int cref;
	int allow_event;
	int allow_posthandle;
	enum mandatory_ie_status mand_status;

	ctrl = link->ctrl;
	memset(last_ie, 0, sizeof(last_ie));
	ctrl->q931_rxcount++;
	if (len < 3 || len < 3 + h->crlen) {
		/* Message too short for supported protocols. */
		return -1;
	}
	switch (h->pd) {
	case MAINTENANCE_PROTOCOL_DISCRIMINATOR_1:
	case MAINTENANCE_PROTOCOL_DISCRIMINATOR_2:
		if (!ctrl->service_message_support) {
			/* Real service message support has not been enabled (and is OFF in libpri by default),
			 * so we have to revert to the 'traditional' KLUDGE of changing byte 4 from a 0xf (SERVICE)
			 * to a 0x7 (SERVICE ACKNOWLEDGE) */
			/* This is the weird maintenance stuff.  We majorly
			   KLUDGE this by changing byte 4 from a 0xf (SERVICE)
			   to a 0x7 (SERVICE ACKNOWLEDGE) */
			h->raw[h->crlen + 2] -= 0x8;
			q931_xmit(link, h, len, 1, 0);
			return 0;
		}
		break;
	default:
		if (h->pd != ctrl->protodisc) {
			pri_error(ctrl,
				"Warning: unknown/inappropriate protocol discriminator received (%02x/%d)\n",
				h->pd, h->pd);
			return 0;
		}
		break;
	}

	cref = q931_cr(h);
	c = q931_getcall(link, cref);
	if (!c) {
		pri_error(ctrl, "Unable to locate call %d\n", cref);
		return -1;
	}
	if (c->master_call->outboundbroadcast && link != &ctrl->link) {
		c = q931_get_subcall(link, c->master_call);
		if (!c) {
			pri_error(ctrl, "Unable to locate subcall for %d\n", cref);
			return -1;
		}
	}

	if (ctrl->debug & PRI_DEBUG_Q931_STATE) {
		pri_message(ctrl,
			"Received message for call %p on link %p TEI/SAPI %d/%d\n",
			c, link, link->tei, link->sapi);
	}

	/* Preliminary handling */
	ctrl->facility.count = 0;
	c->connected_number_in_message = 0;
	c->redirecting_number_in_message = 0;
	mh = (q931_mh *)(h->contents + h->crlen);
	switch (h->pd) {
	case MAINTENANCE_PROTOCOL_DISCRIMINATOR_1:
	case MAINTENANCE_PROTOCOL_DISCRIMINATOR_2:
		prepare_to_handle_maintenance_message(ctrl, mh, c);
		break;
	default:
		/* Unknown protocol discriminator but we will treat it as Q.931 anyway. */
	case GR303_PROTOCOL_DISCRIMINATOR:
	case Q931_PROTOCOL_DISCRIMINATOR:
		if (prepare_to_handle_q931_message(ctrl, mh, c)) {
			/* Discard message.  We don't know how to handle it. */
			if (c->newcall) {
				pri_destroycall(ctrl, c);
			}
			return 0;
		}
		break;
	}
	q931_clr_subcommands(ctrl);
	q931_display_clear(c);

	/* Determine which ies are mandatory for this message. */
	memset(mandies, 0, sizeof(mandies));
	for (x = 0; x < ARRAY_LEN(msgs); ++x)  {
		if (msgs[x].msgnum == mh->msg) {
			memcpy(mandies, msgs[x].mandies, sizeof(mandies));
			break;
		}
	}
	for (x = 0; x < ARRAY_LEN(mandies); ++x) {
		if (mandies[x]) {
			/* Check mandatory channel identification ie exceptions */
			if (mandies[x] != Q931_CHANNEL_IDENT
				/* Always mandatory for RESUME_ACKNOWLEDGE */
				|| mh->msg == Q931_RESUME_ACKNOWLEDGE
				/* Mandatory in Net -> CPE direction for SETUP */
				|| (mh->msg == Q931_SETUP && ctrl->localtype == PRI_CPE)
				/* Mandatory for first SETUP response message in Net -> CPE direction. */
				|| c->channel_id_ie_mandatory) {
				/* ie is mandatory for this message */
				continue;
			}
			/* ie is not mandatory for this message */
			mandies[x] = 0;
		}
	}
	mand_status = MAND_STATUS_OK;

	/* Do real IE processing */
	len -= (h->crlen + 3);
	codeset = cur_codeset = 0;
	for (x = 0; x < len; x += r) {
		ie = (q931_ie *)(mh->data + x);
		r = ielen_checked(ie, len - x);
		if (r < 0) {
			/* We have garbage on the end of the packet. */
			pri_error(ctrl, "XXX Message longer than it should be?? XXX\n");
			if (x) {
				/* Allow the message anyway.  We have already processed an ie. */
				break;
			}
			q931_display_clear(c);
			return -1;
		}

		/* Check if processing a mandatory ie. */
		is_mandatory = 0;
		for (y = 0; y < ARRAY_LEN(mandies); ++y) {
			if (mandies[y] == Q931_FULL_IE(cur_codeset, ie->ie)) {
				mandies[y] = 0;
				is_mandatory = 1;
			}
		}

		/* Special processing for codeset shifts */
		switch (ie->ie & 0xf8) {
		case Q931_LOCKING_SHIFT:
			y = ie->ie & 7;	/* Requested codeset */
			/* Locking shifts couldn't go to lower codeset, and couldn't follows non-locking shifts - verify this */
			if ((cur_codeset != codeset) && (ctrl->debug & PRI_DEBUG_Q931_ANOMALY))
				pri_message(ctrl, "XXX Locking shift immediately follows non-locking shift (from %d through %d to %d) XXX\n", codeset, cur_codeset, y);
			if (y > 0) {
				if ((y < codeset) && (ctrl->debug & PRI_DEBUG_Q931_ANOMALY))
					pri_error(ctrl, "!! Trying to locked downshift codeset from %d to %d !!\n", codeset, y);
				codeset = cur_codeset = y;
			}
			else {
				/* Locking shift to codeset 0 is forbidden by all specifications */
				pri_error(ctrl, "!! Invalid locking shift to codeset 0 !!\n");
			}
			break;
		case Q931_NON_LOCKING_SHIFT:
			cur_codeset = ie->ie & 7;
			break;
		default:
			/* Sanity check for IE code order */
			if (!(ie->ie & 0x80)) {
				if (last_ie[cur_codeset] > ie->ie) {
					if ((ctrl->debug & PRI_DEBUG_Q931_ANOMALY))
						pri_message(ctrl, "XXX Out-of-order IE %d at codeset %d (last was %d)\n", ie->ie, cur_codeset, last_ie[cur_codeset]);
				}
				else
					last_ie[cur_codeset] = ie->ie;
			}
			/* Ignore non-locking shifts for TR41459-based signalling */
			switch (ctrl->switchtype) {
			case PRI_SWITCH_LUCENT5E:
			case PRI_SWITCH_ATT4ESS:
				if (cur_codeset != codeset) {
					if ((ctrl->debug & PRI_DEBUG_Q931_DUMP))
						pri_message(ctrl, "XXX Ignoring IE %d for temporary codeset %d XXX\n", ie->ie, cur_codeset);
					break;
				}
				/* Fall through */
			default:
				y = q931_handle_ie(cur_codeset, ctrl, c, mh->msg, ie);
				if (y < 0 && is_mandatory) {
					/* Error processing mandatory ie. */
					mand_status = MAND_STATUS_CONTENT_ERROR;
					pri_error(ctrl, "%s: Error in mandatory IE %d (cs%d, %s)\n",
						msg2str(mh->msg),
						ie->ie,
						cur_codeset,
						ie2str(Q931_FULL_IE(codeset, ie->ie)));
				}
				/* XXX Applicable to codeset 0 only? XXX */
				if (!cur_codeset && !(ie->ie & 0xf0) && (y < 0)) {
					/*
					 * Q.931 Section 5.8.7.1
					 * Unhandled ies in codeset 0 with the
					 * upper nybble zero are mandatory.
					 */
					mandies[MAX_MAND_IES - 1] = Q931_FULL_IE(cur_codeset, ie->ie);
				}
				break;
			}
			/* Reset current codeset */
			cur_codeset = codeset;
			break;
		}
	}

	/* Check for missing mandatory ies. */
	for (x = 0; x < ARRAY_LEN(mandies); ++x) {
		if (mandies[x]) {
			/* This mandatory ie was not processed. */
			mand_status = MAND_STATUS_MISSING;
			pri_error(ctrl, "%s: Missing mandatory IE %d (cs%d, %s)\n",
				msg2str(mh->msg),
				Q931_IE_IE(mandies[x]),
				Q931_IE_CODESET(mandies[x]),
				ie2str(mandies[x]));
		}
	}

	if (mand_status == MAND_STATUS_OK) {
		switch (mh->msg) {
		case Q931_SETUP:
		case Q931_CONNECT:
			if (ctrl->display_flags.receive & PRI_DISPLAY_OPTION_NAME_INITIAL) {
				q931_display_name_get(c, &c->remote_id.name);
			}
			break;
		default:
			break;
		}

		/* Now handle the facility ie's after all the other ie's were processed. */
		q931_handle_facilities(ctrl, c, mh->msg);
	}
	q931_apdu_msg_expire(ctrl, c, mh->msg);

	/* Post handling */
	switch (h->pd) {
	case MAINTENANCE_PROTOCOL_DISCRIMINATOR_1:
	case MAINTENANCE_PROTOCOL_DISCRIMINATOR_2:
		res = post_handle_maintenance_message(ctrl, h->pd, mh, c);
		q931_display_clear(c);
		break;
	default:
		allow_event = 1;
		allow_posthandle = 1;

		if (c->master_call->outboundbroadcast) {
			nt_ptmp_handle_q931_message(ctrl, mh, c, &allow_event, &allow_posthandle);
			if (allow_event) {
				q931_apdu_msg_expire(ctrl, c->master_call, mh->msg);
			}
		}

		if (allow_posthandle) {
			res = post_handle_q931_message(ctrl, mh, c, mand_status);
			if (res == Q931_RES_HAVEEVENT && !allow_event) {
				res = 0;
			}
		} else {
			q931_display_clear(c);
			res = 0;
		}
		break;
	}
	return res;
}

static int post_handle_maintenance_message(struct pri *ctrl, int protodisc, struct q931_mh *mh, struct q931_call *c)
{
	/* Do some maintenance stuff */
	if (((protodisc == MAINTENANCE_PROTOCOL_DISCRIMINATOR_1) && (mh->msg == ATT_SERVICE))
		|| ((protodisc == MAINTENANCE_PROTOCOL_DISCRIMINATOR_2) && (mh->msg == NATIONAL_SERVICE))) {
		if (c->channelno > 0) {
			ctrl->ev.e = PRI_EVENT_SERVICE;
			ctrl->ev.service.channel = q931_encode_channel(c);
			ctrl->ev.service.changestatus = 0x0f & c->changestatus;
		} else {
			switch (0x0f & c->changestatus) {
			case SERVICE_CHANGE_STATUS_INSERVICE:
				ctrl->ev.e = PRI_EVENT_DCHAN_UP;
				//q921_dchannel_up(ctrl);
				break;
			case SERVICE_CHANGE_STATUS_OUTOFSERVICE:
				ctrl->ev.e = PRI_EVENT_DCHAN_DOWN;
				//q921_dchannel_down(ctrl);
				break;
			default:
				pri_error(ctrl, "!! Don't know how to handle span service change status '%d'\n", (0x0f & c->changestatus));
				return -1;
			}
		}
		maintenance_service_ack(ctrl, c);
		return Q931_RES_HAVEEVENT;
	}
	if (((protodisc == MAINTENANCE_PROTOCOL_DISCRIMINATOR_1) && (mh->msg == ATT_SERVICE_ACKNOWLEDGE))
		|| ((protodisc == MAINTENANCE_PROTOCOL_DISCRIMINATOR_2) && (mh->msg == NATIONAL_SERVICE_ACKNOWLEDGE))) {
		if (c->channelno > 0) {
			ctrl->ev.e = PRI_EVENT_SERVICE_ACK;
			ctrl->ev.service_ack.channel = q931_encode_channel(c);
			ctrl->ev.service_ack.changestatus = 0x0f & c->changestatus;
		} else {
			switch (0x0f & c->changestatus) {
			case SERVICE_CHANGE_STATUS_INSERVICE:
				ctrl->ev.e = PRI_EVENT_DCHAN_UP;
				//q921_dchannel_up(ctrl);
				break;
			case SERVICE_CHANGE_STATUS_OUTOFSERVICE:
				ctrl->ev.e = PRI_EVENT_DCHAN_DOWN;
				//q921_dchannel_down(ctrl);
				break;
			default:
				pri_error(ctrl, "!! Don't know how to handle span service change status '%d'\n", (0x0f & c->changestatus));
				return -1;
			}
		}
		return Q931_RES_HAVEEVENT;
	}

	pri_error(ctrl, "!! Don't know how to post-handle maintenance message type 0x%X\n",
		mh->msg);
	return -1;
}

/*!
 * \internal
 * \brief Rank the given Q.931 call state for call etablishment.
 *
 * \param state Q.931 call state to rank for competing PTMP NT calls.
 *
 * \return Call establishment state ranking.
 */
static enum Q931_RANKED_CALL_STATE q931_rank_state(enum Q931_CALL_STATE state)
{
	enum Q931_RANKED_CALL_STATE rank;

	switch (state) {
	case Q931_CALL_STATE_CALL_INITIATED:
	case Q931_CALL_STATE_CALL_PRESENT:
		rank = Q931_RANKED_CALL_STATE_PRESENT;
		break;
	case Q931_CALL_STATE_OVERLAP_SENDING:
	case Q931_CALL_STATE_OVERLAP_RECEIVING:
		rank = Q931_RANKED_CALL_STATE_OVERLAP;
		break;
	case Q931_CALL_STATE_OUTGOING_CALL_PROCEEDING:
	case Q931_CALL_STATE_INCOMING_CALL_PROCEEDING:
		rank = Q931_RANKED_CALL_STATE_PROCEEDING;
		break;
	case Q931_CALL_STATE_CALL_DELIVERED:
	case Q931_CALL_STATE_CALL_RECEIVED:
	case Q931_CALL_STATE_CONNECT_REQUEST:
		rank = Q931_RANKED_CALL_STATE_ALERTING;
		break;
	case Q931_CALL_STATE_ACTIVE:
	case Q931_CALL_STATE_CALL_INDEPENDENT_SERVICE:
		rank = Q931_RANKED_CALL_STATE_CONNECT;
		break;
	case Q931_CALL_STATE_CALL_ABORT:
		rank = Q931_RANKED_CALL_STATE_ABORT;
		break;
	default:
		rank = Q931_RANKED_CALL_STATE_OTHER;
		break;
	}

	return rank;
}

/*!
 * \brief Determine if the master will pass an event to the upper layer.
 *
 * \param ctrl D channel controller.
 * \param subcall Q.931 call leg.
 * \param msg_type Current message type being processed.
 *
 * \note This function must parallel nt_ptmp_handle_q931_message().
 *
 * \retval TRUE if the master will pass an event to the upper layer.
 * \retval FALSE if the event will be blocked.
 */
int q931_master_pass_event(struct pri *ctrl, struct q931_call *subcall, int msg_type)
{
	struct q931_call *winner;
	struct q931_call *master;
	enum Q931_RANKED_CALL_STATE master_rank;
	enum Q931_RANKED_CALL_STATE subcall_rank;
	int will_pass;	/*!< TRUE if the master will pass an event to the upper layer. */

	master = subcall->master_call;
	if (subcall == master) {
		/* We are the master call so of course the master will pass an event. */
		return 1;
	}

	winner = q931_get_subcall_winner(master);
	if (winner && subcall == winner) {
		/* We are the winner so of course the master will pass an event. */
		return 1;
	}

	master_rank = q931_rank_state(master->ourcallstate);
	will_pass = 0;
	switch (msg_type) {
	case Q931_SETUP_ACKNOWLEDGE:
#if 0	/* Overlap dialing in PTMP NT mode not supported at the present time. */
		if (master_rank < Q931_RANKED_CALL_STATE_OVERLAP) {
			will_pass = 1;
		}
#endif	/* Overlap dialing in PTMP NT mode not supported at the present time. */
		break;
	case Q931_CALL_PROCEEDING:
		if (master_rank < Q931_RANKED_CALL_STATE_PROCEEDING) {
			will_pass = 1;
		}
		break;
	case Q931_PROGRESS:
		/*
		 * We will just ignore this message since there could be multiple devices
		 * competing for this call.  Who has access to the B channel at this time
		 * to give in-band signals anyway?
		 */
		break;
	case Q931_ALERTING:
		if (master_rank < Q931_RANKED_CALL_STATE_ALERTING) {
			will_pass = 1;
		}
		break;
	case Q931_CONNECT:
		if (master_rank < Q931_RANKED_CALL_STATE_CONNECT) {
			/* We are expected to be the winner for the next message. */
			will_pass = 1;
		}
		break;
	case Q931_DISCONNECT:
	case Q931_RELEASE:
	case Q931_RELEASE_COMPLETE:
		/* Only deal with the winner. */
		break;
	case Q931_FACILITY:
	case Q931_NOTIFY:
		if (!winner) {
			/* The overlap rank does not count here. */
			if (master_rank == Q931_RANKED_CALL_STATE_OVERLAP) {
				master_rank = Q931_RANKED_CALL_STATE_PRESENT;
			}
			subcall_rank = q931_rank_state(subcall->ourcallstate);
			if (subcall_rank == Q931_RANKED_CALL_STATE_OVERLAP) {
				subcall_rank = Q931_RANKED_CALL_STATE_PRESENT;
			}
			if (master_rank == subcall_rank) {
				/*
				 * No winner yet but the subcall is as advanced as the master.
				 * Allow the supplementary service event to pass.
				 */
				will_pass = 1;
			}
		}
		break;
	default:
		/* Only deal with the winner. */
		break;
	}

	return will_pass;
}

/*!
 * \internal
 * \brief Handle outboundbroadcast incoming messages for the master_call's state.
 *
 * \param ctrl D channel controller.
 * \param mh Q.931 message type header.
 * \param subcall Q.931 call leg.
 * \param allow_event Where to set the allow event to upper layer flag.
 * \param allow_posthandle Where to set the allow post handle event flag.
 *
 * \details
 * This is where we interact the subcalls state with the master_call's state.
 *
 * \note This function must parallel q931_master_pass_event().
 *
 * \return Nothing
 */
static void nt_ptmp_handle_q931_message(struct pri *ctrl, struct q931_mh *mh, struct q931_call *subcall, int *allow_event, int *allow_posthandle)
{
	struct q931_call *master = subcall->master_call;
	struct q931_call *winner = q931_get_subcall_winner(master);
	enum Q931_RANKED_CALL_STATE master_rank;
	enum Q931_RANKED_CALL_STATE subcall_rank;

	/* For broadcast calls, we default to not allowing events to keep events received to a minimum
	 * and to allow post processing, since that is where hangup and subcall state handling and other processing is done */
	*allow_event = 0;
	*allow_posthandle = 1;

	master_rank = q931_rank_state(master->ourcallstate);
	if (master_rank < Q931_RANKED_CALL_STATE_CONNECT) {
		/* This subcall can compete for the call. */
		subcall->newcall = 0;
	}

	switch (mh->msg) {
	case Q931_SETUP_ACKNOWLEDGE:
#if 0	/* Overlap dialing in PTMP NT mode not supported at the present time. */
		if (master_rank < Q931_RANKED_CALL_STATE_OVERLAP) {
			*allow_event = 1;
			UPDATE_OURCALLSTATE(ctrl, master, Q931_CALL_STATE_OVERLAP_SENDING);
		}
#endif	/* Overlap dialing in PTMP NT mode not supported at the present time. */
		break;
	case Q931_CALL_PROCEEDING:
		if (master_rank < Q931_RANKED_CALL_STATE_PROCEEDING) {
			*allow_event = 1;
			UPDATE_OURCALLSTATE(ctrl, master, Q931_CALL_STATE_OUTGOING_CALL_PROCEEDING);
		}
		break;
	case Q931_PROGRESS:
		/*
		 * We will just ignore this message since there could be multiple devices
		 * competing for this call.  Who has access to the B channel at this time
		 * to give in-band signals anyway?
		 */
		break;
	case Q931_ALERTING:
		if (master_rank < Q931_RANKED_CALL_STATE_ALERTING) {
			*allow_event = 1;
			UPDATE_OURCALLSTATE(ctrl, master, Q931_CALL_STATE_CALL_DELIVERED);
		}
		break;
	case Q931_CONNECT:
		if (master_rank < Q931_RANKED_CALL_STATE_CONNECT) {
			UPDATE_OURCALLSTATE(ctrl, master, Q931_CALL_STATE_ACTIVE);
			q931_set_subcall_winner(subcall);
			*allow_event = 1;
		} else {
			/* Call clearing of non selected calls occurs in
			 * q931_set_subcall_winner() - All we need to do is make sure
			 * that this connect is not acknowledged */
			*allow_posthandle = 0;
		}
		break;
	case Q931_DISCONNECT:
	case Q931_RELEASE:
	case Q931_RELEASE_COMPLETE:
		if (!winner) {
			int master_priority;
			int slave_priority;

			/* Pass up the cause on a priority basis. */
			switch (master->cause) {
			case PRI_CAUSE_USER_BUSY:
				master_priority = 2;
				break;
			case PRI_CAUSE_CALL_REJECTED:
				master_priority = 1;
				break;
			default:
				master_priority = 0;
				break;
			case -1:
				/* First time priority. */
				master_priority = -2;
				break;
			}
			switch (subcall->cause) {
			case PRI_CAUSE_USER_BUSY:
				slave_priority = 2;
				break;
			case PRI_CAUSE_CALL_REJECTED:
				slave_priority = 1;
				break;
			default:
				slave_priority = 0;
				break;
			case PRI_CAUSE_INCOMPATIBLE_DESTINATION:
				/* Cause explicitly ignored */
				slave_priority = -1;
				break;
			}
			if (master_priority < slave_priority) {
				/* Pass up the cause to the master. */
				master->cause = subcall->cause;
			}
		} else {
			/* There *is* a winner */
			if (subcall == winner) {
				/* .. and we're it: */
				*allow_event = 1;
				UPDATE_OURCALLSTATE(ctrl, master, Q931_CALL_STATE_CALL_ABORT);
			}
		}
		break;
	case Q931_FACILITY:
	case Q931_NOTIFY:
		if (winner) {
			if (subcall == winner) {
				/* Only deal with the winner. */
				*allow_event = 1;
			}
		} else {
			/* The overlap rank does not count here. */
			if (master_rank == Q931_RANKED_CALL_STATE_OVERLAP) {
				master_rank = Q931_RANKED_CALL_STATE_PRESENT;
			}
			subcall_rank = q931_rank_state(subcall->ourcallstate);
			if (subcall_rank == Q931_RANKED_CALL_STATE_OVERLAP) {
				subcall_rank = Q931_RANKED_CALL_STATE_PRESENT;
			}
			if (master_rank == subcall_rank) {
				/*
				 * No winner yet but the subcall is as advanced as the master.
				 * Allow the supplementary service event to pass.
				 */
				*allow_event = 1;
			}
		}
		break;
	default:
		if (winner && subcall == winner) {
			/* Only deal with the winner. */
			*allow_event = 1;
		}
		break;
	}
}

/*!
 * \internal
 * \brief Fill in the RING event fields.
 *
 * \param ctrl D channel controller.
 * \param call Q.931 call leg
 *
 * \return Nothing
 */
static void q931_fill_ring_event(struct pri *ctrl, struct q931_call *call)
{
	struct pri_subcommand *subcmd;

	if (call->redirecting.from.number.valid && !call->redirecting.count) {
		/*
		 * This is most likely because the redirecting number came in
		 * with the redirecting ie only and not a DivertingLegInformation2.
		 */
		call->redirecting.count = 1;
	}
	if (call->redirecting.state == Q931_REDIRECTING_STATE_PENDING_TX_DIV_LEG_3) {
		/*
		 * Valid for Q.SIG and ETSI PRI/BRI-PTP modes:
		 * Setup the redirecting.to informtion so we can identify
		 * if the user wants to manually supply the COLR for this
		 * redirected to number if further redirects could happen.
		 *
		 * All the user needs to do is set the REDIRECTING(to-pres)
		 * to the COLR and REDIRECTING(to-num) = complete-dialed-number
		 * (i.e. CALLERID(dnid)) to be safe after determining that the
		 * incoming call was redirected by checking if the
		 * REDIRECTING(count) is nonzero.
		 */
		call->redirecting.to.number = call->called.number;
		call->redirecting.to.number.presentation =
			PRI_PRES_RESTRICTED | PRI_PRES_USER_NUMBER_UNSCREENED;
	}

	ctrl->ev.e = PRI_EVENT_RING;
	ctrl->ev.ring.subcmds = &ctrl->subcmds;
	ctrl->ev.ring.channel = q931_encode_channel(call);

	/* Calling party information */
	ctrl->ev.ring.callingpres = q931_party_id_presentation(&call->remote_id);
	ctrl->ev.ring.callingplan = call->remote_id.number.plan;
	if (call->ani.valid) {
		ctrl->ev.ring.callingplanani = call->ani.plan;
		libpri_copy_string(ctrl->ev.ring.callingani, call->ani.str,
			sizeof(ctrl->ev.ring.callingani));
	} else {
		ctrl->ev.ring.callingplanani = -1;
		ctrl->ev.ring.callingani[0] = '\0';
	}
	libpri_copy_string(ctrl->ev.ring.callingnum, call->remote_id.number.str,
		sizeof(ctrl->ev.ring.callingnum));
	libpri_copy_string(ctrl->ev.ring.callingname, call->remote_id.name.str,
		sizeof(ctrl->ev.ring.callingname));
	q931_party_id_copy_to_pri(&ctrl->ev.ring.calling, &call->remote_id);
	/* for backwards compatibility, still need ctrl->ev.ring.callingsubaddr */
	if (!call->remote_id.subaddress.type) {
		/* NSAP: Type = 0 */
		libpri_copy_string(ctrl->ev.ring.callingsubaddr,
			(char *) call->remote_id.subaddress.data,
			sizeof(ctrl->ev.ring.callingsubaddr));
	} else {
		ctrl->ev.ring.callingsubaddr[0] = '\0';
	}

	ctrl->ev.ring.ani2 = call->ani2;

	/* Called party information */
	ctrl->ev.ring.calledplan = call->called.number.plan;
	libpri_copy_string(ctrl->ev.ring.callednum, call->called.number.str,
		sizeof(ctrl->ev.ring.callednum));
	q931_party_subaddress_copy_to_pri(&ctrl->ev.ring.called_subaddress,
		&call->called.subaddress);

	/* Original called party information (For backward compatibility) */
	libpri_copy_string(ctrl->ev.ring.origcalledname,
		call->redirecting.orig_called.name.str, sizeof(ctrl->ev.ring.origcalledname));
	libpri_copy_string(ctrl->ev.ring.origcallednum,
		call->redirecting.orig_called.number.str, sizeof(ctrl->ev.ring.origcallednum));
	ctrl->ev.ring.callingplanorigcalled = call->redirecting.orig_called.number.plan;
	if (call->redirecting.orig_called.number.valid
		|| call->redirecting.orig_called.name.valid) {
		ctrl->ev.ring.origredirectingreason = call->redirecting.orig_reason;
	} else {
		ctrl->ev.ring.origredirectingreason = -1;
	}

	/* Redirecting from party information (For backward compatibility) */
	ctrl->ev.ring.callingplanrdnis = call->redirecting.from.number.plan;
	libpri_copy_string(ctrl->ev.ring.redirectingnum, call->redirecting.from.number.str,
		sizeof(ctrl->ev.ring.redirectingnum));
	libpri_copy_string(ctrl->ev.ring.redirectingname, call->redirecting.from.name.str,
		sizeof(ctrl->ev.ring.redirectingname));

	ctrl->ev.ring.redirectingreason = call->redirecting.reason;

	libpri_copy_string(ctrl->ev.ring.useruserinfo, call->useruserinfo,
		sizeof(ctrl->ev.ring.useruserinfo));
	call->useruserinfo[0] = '\0';

	libpri_copy_string(ctrl->ev.ring.keypad_digits, call->keypad_digits,
		sizeof(ctrl->ev.ring.keypad_digits));

	ctrl->ev.ring.flexible = !(call->chanflags & FLAG_EXCLUSIVE);
	ctrl->ev.ring.cref = call->cr;
	ctrl->ev.ring.call = call->master_call;
	ctrl->ev.ring.layer1 = call->bc.userl1;
	ctrl->ev.ring.complete = call->complete;
	ctrl->ev.ring.ctype = call->bc.transcapability;
	ctrl->ev.ring.progress = call->progress;
	ctrl->ev.ring.progressmask = call->progressmask;
	ctrl->ev.ring.reversecharge = call->reversecharge;

	if (call->redirecting.count) {
		subcmd = q931_alloc_subcommand(ctrl);
		if (subcmd) {
			/* Setup redirecting subcommand */
			subcmd->cmd = PRI_SUBCMD_REDIRECTING;
			q931_party_redirecting_copy_to_pri(&subcmd->u.redirecting,
				&call->redirecting);
		}
	}
}

/*!
 * \internal
 * \brief Fill in the FACILITY event fields.
 *
 * \param ctrl D channel controller.
 * \param call Q.931 call leg.
 *
 * \return Nothing
 */
static void q931_fill_facility_event(struct pri *ctrl, struct q931_call *call)
{
	ctrl->ev.e = PRI_EVENT_FACILITY;
	ctrl->ev.facility.subcmds = &ctrl->subcmds;
	ctrl->ev.facility.channel = q931_encode_channel(call);
	ctrl->ev.facility.cref = call->cr;
	if (q931_is_dummy_call(call)) {
		ctrl->ev.facility.call = NULL;
	} else {
		ctrl->ev.facility.call = call->master_call;
	}
	ctrl->ev.facility.subcall = call;

	/* Need to do this for backward compatibility with struct pri_event_facname */
	libpri_copy_string(ctrl->ev.facility.callingname, call->remote_id.name.str,
		sizeof(ctrl->ev.facility.callingname));
	libpri_copy_string(ctrl->ev.facility.callingnum, call->remote_id.number.str,
		sizeof(ctrl->ev.facility.callingnum));
	ctrl->ev.facility.callingpres = q931_party_id_presentation(&call->remote_id);
	ctrl->ev.facility.callingplan = call->remote_id.number.plan;
}

/*!
 * \internal
 * \brief APDU wait for response message timeout.
 *
 * \param data Callback data pointer.
 *
 * \return Nothing
 */
static void q931_apdu_timeout(void *data)
{
	struct apdu_event *apdu;
	struct pri *ctrl;
	struct q931_call *call;
	int free_it;

	apdu = data;
	call = apdu->call;
	ctrl = call->pri;

	/*
	 * Extract the APDU from the list so it cannot be
	 * deleted from under us by the callback.
	 */
	free_it = pri_call_apdu_extract(call, apdu);

	q931_clr_subcommands(ctrl);
	apdu->response.callback(APDU_CALLBACK_REASON_TIMEOUT, ctrl, call, apdu, NULL);
	if (ctrl->subcmds.counter_subcmd) {
		q931_fill_facility_event(ctrl, call);
		ctrl->schedev = 1;
	}

	if (free_it) {
		free(apdu);
	}
}

/*!
 * \brief Generic call-completion timeout event handler.
 *
 * \param ctrl D channel controller.
 * \param cc_record Call completion record to process event.
 * \param event Event to process.
 *
 * \retval nonzero if cc record destroyed because FSM completed.
 */
int q931_cc_timeout(struct pri *ctrl, struct pri_cc_record *cc_record, enum CC_EVENTS event)
{
	q931_call *call;
	q931_call *dummy;
	int fsm_complete;

	q931_clr_subcommands(ctrl);
	dummy = ctrl->link.dummy_call;
	call = cc_record->signaling;
	if (!call) {
		/* Substitute the broadcast dummy call reference call. */
		call = dummy;
	}
	fsm_complete = pri_cc_event(ctrl, call, cc_record, event);
	if (ctrl->subcmds.counter_subcmd) {
		q931_fill_facility_event(ctrl, dummy);
		ctrl->schedev = 1;
	}
	return fsm_complete;
}

/*!
 * \brief Generic call-completion indirect event creation.
 *
 * \param ctrl D channel controller.
 * \param cc_record Call completion record to process event.
 * \param func Function to call that will generate a libpri event.
 *
 * \return Nothing
 */
void q931_cc_indirect(struct pri *ctrl, struct pri_cc_record *cc_record, void (*func)(struct pri *ctrl, q931_call *call, struct pri_cc_record *cc_record))
{
	q931_call *call;
	q931_call *dummy;

	q931_clr_subcommands(ctrl);
	dummy = ctrl->link.dummy_call;
	call = cc_record->signaling;
	if (!call) {
		/* Substitute the broadcast dummy call reference call. */
		call = dummy;
	}
	func(ctrl, call, cc_record);
	if (ctrl->subcmds.counter_subcmd) {
		q931_fill_facility_event(ctrl, dummy);
		ctrl->schedev = 1;
	}
}

/*!
 * \brief Find the transfer call indicated by the given link_id.
 *
 * \param ctrl D channel controller.
 * \param link_id Link id of the other call involved in the transfer.
 *
 * \retval found-master-call on success.
 * \retval NULL on error.
 */
struct q931_call *q931_find_link_id_call(struct pri *ctrl, int link_id)
{
	struct q931_call *cur;
	struct q931_call *winner;
	struct q931_call *match;

	match = NULL;
	for (cur = *ctrl->callpool; cur; cur = cur->next) {
		if (cur->is_link_id_valid && cur->link_id == link_id) {
			/* Found the link_id call. */
			winner = q931_find_winning_call(cur);
			if (!winner) {
				/* There is no winner. */
				break;
			}
			switch (winner->ourcallstate) {
			case Q931_CALL_STATE_OUTGOING_CALL_PROCEEDING:
			case Q931_CALL_STATE_CALL_DELIVERED:
			case Q931_CALL_STATE_CALL_RECEIVED:
			case Q931_CALL_STATE_CONNECT_REQUEST:
			case Q931_CALL_STATE_INCOMING_CALL_PROCEEDING:
			case Q931_CALL_STATE_ACTIVE:
				/* The link_id call is in a state suitable for transfer. */
				match = cur;
				break;
			default:
				/* The link_id call is not in a good state to transfer. */
				break;
			}
			break;
		}
	}

	return match;
}

/*!
 * \brief Find the active call given the held call.
 *
 * \param ctrl D channel controller.
 * \param held_call Held call to help locate a compatible active call.
 *
 * \retval master-active-call on success.
 * \retval NULL on error.
 */
struct q931_call *q931_find_held_active_call(struct pri *ctrl, struct q931_call *held_call)
{
	struct q931_call *cur;
	struct q931_call *winner;
	struct q931_call *match;

	if (!held_call->link) {
		/* Held call does not have an active link. */
		return NULL;
	}
	match = NULL;
	for (cur = *ctrl->callpool; cur; cur = cur->next) {
		if (cur->hold_state == Q931_HOLD_STATE_IDLE) {
			/* Found an active call. */
			winner = q931_find_winning_call(cur);
			if (!winner || (BRI_NT_PTMP(ctrl) && winner->link != held_call->link)) {
				/* There is no winner or the active call does not go to the same TEI. */
				continue;
			}
			switch (winner->ourcallstate) {
			case Q931_CALL_STATE_OUTGOING_CALL_PROCEEDING:
			case Q931_CALL_STATE_CALL_DELIVERED:
			case Q931_CALL_STATE_CALL_RECEIVED:
			case Q931_CALL_STATE_CONNECT_REQUEST:
			case Q931_CALL_STATE_INCOMING_CALL_PROCEEDING:
			case Q931_CALL_STATE_ACTIVE:
				break;
			default:
				/* Active call not in a good state to transfer. */
				continue;
			}
			if (q931_party_number_cmp(&winner->remote_id.number,
				&held_call->remote_id.number)) {
				/* The remote party number does not match.  This is a weak match. */
				match = cur;
				continue;
			}
			/* Found an exact match. */
			match = cur;
			break;
		}
	}

	return match;
}

/*!
 * \internal
 * \brief Find the held call given the active call.
 *
 * \param ctrl D channel controller.
 * \param active_call Active call to help locate a compatible held call.
 *
 * \retval master-held-call on success.
 * \retval NULL on error.
 */
static struct q931_call *q931_find_held_call(struct pri *ctrl, struct q931_call *active_call)
{
	struct q931_call *cur;
	struct q931_call *winner;
	struct q931_call *match;

	if (!active_call->link) {
		/* Active call does not have an active link. */
		return NULL;
	}
	match = NULL;
	for (cur = *ctrl->callpool; cur; cur = cur->next) {
		if (cur->hold_state == Q931_HOLD_STATE_CALL_HELD) {
			/* Found a held call. */
			winner = q931_find_winning_call(cur);
			if (!winner || (BRI_NT_PTMP(ctrl) && winner->link != active_call->link)) {
				/* There is no winner or the held call does not go to the same TEI. */
				continue;
			}
			switch (winner->ourcallstate) {
			case Q931_CALL_STATE_OUTGOING_CALL_PROCEEDING:
			case Q931_CALL_STATE_CALL_DELIVERED:
			case Q931_CALL_STATE_CALL_RECEIVED:
			case Q931_CALL_STATE_CONNECT_REQUEST:
			case Q931_CALL_STATE_INCOMING_CALL_PROCEEDING:
			case Q931_CALL_STATE_ACTIVE:
				break;
			default:
				/* Held call not in a good state to transfer. */
				continue;
			}
			if (q931_party_number_cmp(&winner->remote_id.number,
				&active_call->remote_id.number)) {
				/* The remote party number does not match.  This is a weak match. */
				match = cur;
				continue;
			}
			/* Found an exact match. */
			match = cur;
			break;
		}
	}

	return match;
}

/*!
 * \internal
 * \brief Determine RELEASE_COMPLETE cause code for newcall rejection.
 *
 * \param call Q.931 call leg.
 *
 * \return Cause code for RELEASE_COMPLETE.
 */
static int newcall_rel_comp_cause(struct q931_call *call)
{
	struct q931_call *master;
	int cause;

	cause = PRI_CAUSE_INVALID_CALL_REFERENCE;
	master = call->master_call;
	if (master != call && master->t312_timer) {
		switch (master->ourcallstate) {
		case Q931_CALL_STATE_CALL_ABORT:
			cause = PRI_CAUSE_RECOVERY_ON_TIMER_EXPIRE;
			break;
		default:
			break;
		}
	}

	return cause;
}

/*!
 * \internal
 * \brief Restart channel notify event for upper layer notify chain timeout.
 *
 * \param data Callback data pointer.
 *
 * \return Nothing
 */
static void q931_restart_notify_timeout(void *data)
{
	struct q931_call *call = data;
	struct pri *ctrl = call->pri;

	/* Create channel restart event to upper layer. */
	call->channelno = call->restart.chan_no[call->restart.idx++];
	ctrl->ev.e = PRI_EVENT_RESTART;
	ctrl->ev.restart.channel = q931_encode_channel(call);
	ctrl->schedev = 1;

	/* Reschedule for next channel restart event needed. */
	if (call->restart.idx < call->restart.count) {
		call->restart.timer = pri_schedule_event(ctrl, 0, q931_restart_notify_timeout,
			call);
	} else {
		/* No more restart events needed. */
		call->restart.timer = 0;

		/* Send back the Restart Acknowledge.  All channels are now restarted. */
		if (call->slotmap != -1) {
			/* Send slotmap format. */
			call->channelno = -1;
		}
		restart_ack(ctrl, call);
	}
}

/*!
 * \internal
 * \brief Setup restart channel notify events for upper layer.
 *
 * \param call Q.931 call leg.
 *
 * \return Nothing
 */
static void q931_restart_notify(struct q931_call *call)
{
	struct pri *ctrl = call->pri;

	/* Start notify chain. */
	pri_schedule_del(ctrl, call->restart.timer);
	call->restart.idx = 0;
	q931_restart_notify_timeout(call);
}

/*!
 * \internal
 * \brief Process the decoded information in the Q.931 message.
 *
 * \param ctrl D channel controller.
 * \param mh Q.931 message header.
 * \param c Q.931 call leg.
 * \param mand_status Mandatory ie status
 *
 * \note
 * When this function returns c may be destroyed so you can no
 * longer dereference it.
 *
 * \retval 0 if no error or event.
 * \retval Q931_RES_HAVEEVENT if have an event.
 * \retval -1 on error.
 */
static int post_handle_q931_message(struct pri *ctrl, struct q931_mh *mh, struct q931_call *c, enum mandatory_ie_status mand_status)
{
	int res;
	int changed;
	int mand_cause;
	enum Q931_CALL_STATE ourcallstate_orig;
	struct apdu_event *cur = NULL;
	struct pri_subcommand *subcmd;
	struct q931_call *master_call;

	mand_cause = 0;
	switch (mand_status) {
	case MAND_STATUS_OK:
		break;
	case MAND_STATUS_CONTENT_ERROR:
		mand_cause = PRI_CAUSE_INVALID_IE_CONTENTS;
		break;
	case MAND_STATUS_MISSING:
		mand_cause = PRI_CAUSE_MANDATORY_IE_MISSING;
		break;
	}

	switch(mh->msg) {
	case Q931_RESTART:
		q931_display_subcmd(ctrl, c);
		if (mand_status != MAND_STATUS_OK) {
			q931_status(ctrl, c, mand_cause);
			pri_destroycall(ctrl, c);
			break;
		}
		UPDATE_OURCALLSTATE(ctrl, c, Q931_CALL_STATE_RESTART);
		c->peercallstate = Q931_CALL_STATE_RESTART_REQUEST;

		/* Notify upper layer of restart event */
		if ((c->channelno == -1 && c->slotmap == -1) || !c->restart.count) {
			/*
			 * Whole link restart or channel not identified by Channel ID ie
			 * 3.3 octets.
			 *
			 * Send back the Restart Acknowledge
			 */
			restart_ack(ctrl, c);

			/* Create channel restart event to upper layer. */
			ctrl->ev.e = PRI_EVENT_RESTART;
			ctrl->ev.restart.channel = q931_encode_channel(c);
		} else {
			/* Start notify chain. */
			q931_restart_notify(c);
		}
		return Q931_RES_HAVEEVENT;
	case Q931_REGISTER:
		q931_display_subcmd(ctrl, c);

		/* Must be new call */
		if (!c->newcall) {
			q931_status(ctrl, c, PRI_CAUSE_WRONG_CALL_STATE);
			break;
		}
		c->newcall = 0;
		c->alive = 1;

		c->cis_call = 1;
		c->chanflags = FLAG_EXCLUSIVE;/* For safety mark this channel as exclusive. */
		c->channelno = 0;

		UPDATE_OURCALLSTATE(ctrl, c, Q931_CALL_STATE_CALL_INDEPENDENT_SERVICE);
		c->peercallstate = Q931_CALL_STATE_CALL_INDEPENDENT_SERVICE;

		if (c->cc.hangup_call) {
			q931_release_complete(ctrl, c, PRI_CAUSE_NORMAL_CLEARING);
			break;
		}
		if (/* c->cis_call && */ !c->cis_recognized) {
			pri_message(ctrl,
				"-- CIS connection not marked as handled.  Disconnecting it.\n");
			q931_release_complete(ctrl, c, PRI_CAUSE_FACILITY_NOT_IMPLEMENTED);
			break;
		}

		q931_fill_ring_event(ctrl, c);
		return Q931_RES_HAVEEVENT;
	case Q931_SETUP:
		q931_display_subcmd(ctrl, c);
		if (mand_status != MAND_STATUS_OK) {
			q931_release_complete(ctrl, c, mand_cause);
			break;
		}
		/* Must be new call */
		if (!c->newcall) {
			break;
		}
		if (c->progressmask & PRI_PROG_CALLER_NOT_ISDN)
			c->nonisdn = 1;
		c->newcall = 0;
		UPDATE_OURCALLSTATE(ctrl, c, Q931_CALL_STATE_CALL_PRESENT);
		c->peercallstate = Q931_CALL_STATE_CALL_INITIATED;
		if (c->cis_call) {
			/*
			 * Make call alive so any message events clearing this
			 * signaling call can pass up any subcmds.
			 */
			c->alive = 1;
		} else {
			/* it's not yet a call since higher level can respond with RELEASE or RELEASE_COMPLETE */
			c->alive = 0;
		}
		if (c->bc.transmoderate != TRANS_MODE_64_CIRCUIT) {
			q931_release_complete(ctrl, c, PRI_CAUSE_BEARERCAPABILITY_NOTIMPL);
			break;
		}
		if (c->cc.hangup_call) {
			q931_release_complete(ctrl, c, PRI_CAUSE_NORMAL_CLEARING);
			break;
		}
		if (c->cis_call && !c->cis_recognized) {
			pri_message(ctrl, "-- CIS call not marked as handled.  Disconnecting it.\n");
			q931_release_complete(ctrl, c, PRI_CAUSE_FACILITY_NOT_IMPLEMENTED);
			break;
		}

		/* Save the initial cc-parties. (Incoming SETUP can only be a master call.) */
		c->cc.party_a = c->remote_id;

		q931_fill_ring_event(ctrl, c);
		return Q931_RES_HAVEEVENT;
	case Q931_ALERTING:
		q931_display_subcmd(ctrl, c);
		if (mand_status != MAND_STATUS_OK) {
			q931_status(ctrl, c, mand_cause);
			break;
		}
		stop_t303(c->master_call);
		if (c->newcall) {
			q931_release_complete(ctrl, c, newcall_rel_comp_cause(c));
			break;
		}
		switch (c->ourcallstate) {
		default:
			q931_status(ctrl, c, PRI_CAUSE_WRONG_CALL_STATE);
			return 0;
		case Q931_CALL_STATE_CALL_INITIATED:
		case Q931_CALL_STATE_OVERLAP_SENDING:
		case Q931_CALL_STATE_OUTGOING_CALL_PROCEEDING:
			break;
		}
		UPDATE_OURCALLSTATE(ctrl, c, Q931_CALL_STATE_CALL_DELIVERED);
		c->peercallstate = Q931_CALL_STATE_CALL_RECEIVED;
		ctrl->ev.e = PRI_EVENT_RINGING;
		ctrl->ev.ringing.subcmds = &ctrl->subcmds;
		ctrl->ev.ringing.channel = q931_encode_channel(c);
		ctrl->ev.ringing.cref = c->cr;
		ctrl->ev.ringing.call = c->master_call;
		ctrl->ev.ringing.progress = c->progress;
		ctrl->ev.ringing.progressmask = c->progressmask;

		libpri_copy_string(ctrl->ev.ringing.useruserinfo, c->useruserinfo, sizeof(ctrl->ev.ringing.useruserinfo));
		c->useruserinfo[0] = '\0';

		switch (ctrl->switchtype) {
		case PRI_SWITCH_QSIG:
			pri_cc_qsig_determine_available(ctrl, c);
			break;
		default:
			break;
		}

		for (cur = c->apdus; cur; cur = cur->next) {
			if (!cur->sent && cur->message == Q931_FACILITY) {
				q931_facility(ctrl, c);
				break;
			}
		}

		return Q931_RES_HAVEEVENT;
	case Q931_CONNECT:
		q931_display_subcmd(ctrl, c);
		if (mand_status != MAND_STATUS_OK) {
			q931_status(ctrl, c, mand_cause);
			break;
		}
		stop_t303(c->master_call);
		if (c->newcall) {
			q931_release_complete(ctrl, c, newcall_rel_comp_cause(c));
			break;
		}
		switch (c->ourcallstate) {
		case Q931_CALL_STATE_CALL_INITIATED:
		case Q931_CALL_STATE_OVERLAP_SENDING:
		case Q931_CALL_STATE_OUTGOING_CALL_PROCEEDING:
		case Q931_CALL_STATE_CALL_DELIVERED:
		case Q931_CALL_STATE_CALL_PRESENT:
		case Q931_CALL_STATE_CALL_RECEIVED:
		case Q931_CALL_STATE_INCOMING_CALL_PROCEEDING:
		case Q931_CALL_STATE_OVERLAP_RECEIVING:
			/* Accept CONNECT in these states. */
			break;
		default:
			q931_status(ctrl, c, PRI_CAUSE_WRONG_CALL_STATE);
			return 0;
		}

		ctrl->ev.e = PRI_EVENT_ANSWER;
		ctrl->ev.answer.subcmds = &ctrl->subcmds;
		ctrl->ev.answer.channel = q931_encode_channel(c);
		ctrl->ev.answer.cref = c->cr;
		ctrl->ev.answer.call = c->master_call;
		ctrl->ev.answer.progress = c->progress;
		ctrl->ev.answer.progressmask = c->progressmask;
		libpri_copy_string(ctrl->ev.answer.useruserinfo, c->useruserinfo, sizeof(ctrl->ev.answer.useruserinfo));
		c->useruserinfo[0] = '\0';

		if (!ctrl->manual_connect_ack) {
			q931_connect_acknowledge(ctrl, c, 0);
		} else {
			UPDATE_OURCALLSTATE(ctrl, c, Q931_CALL_STATE_CONNECT_REQUEST);
			c->peercallstate = Q931_CALL_STATE_CONNECT_REQUEST;
		}

		if (c->cis_auto_disconnect && c->cis_call) {
			/* Make sure WE release when we initiate a signalling only connection */
			q931_hangup(ctrl, c, PRI_CAUSE_NORMAL_CLEARING);
		} else {
			c->incoming_ct_state = INCOMING_CT_STATE_IDLE;

			/* Setup connected line subcommand */
			subcmd = q931_alloc_subcommand(ctrl);
			if (subcmd) {
				subcmd->cmd = PRI_SUBCMD_CONNECTED_LINE;
				q931_party_id_copy_to_pri(&subcmd->u.connected_line.id, &c->remote_id);
			}

			return Q931_RES_HAVEEVENT;
		}
		break;
	case Q931_FACILITY:
		q931_display_subcmd(ctrl, c);
		if (c->newcall) {
			q931_release_complete(ctrl, c, newcall_rel_comp_cause(c));
			break;
		}
		switch (c->incoming_ct_state) {
		case INCOMING_CT_STATE_POST_CONNECTED_LINE:
			c->incoming_ct_state = INCOMING_CT_STATE_IDLE;
			subcmd = q931_alloc_subcommand(ctrl);
			if (subcmd) {
				subcmd->cmd = PRI_SUBCMD_CONNECTED_LINE;
				q931_party_id_copy_to_pri(&subcmd->u.connected_line.id, &c->remote_id);
			}
			break;
		default:
			break;
		}
		if (ctrl->subcmds.counter_subcmd) {
			q931_fill_facility_event(ctrl, c);
			return Q931_RES_HAVEEVENT;
		}
		break;
	case Q931_PROGRESS:
		ctrl->ev.e = PRI_EVENT_PROGRESS;
		ctrl->ev.proceeding.cause = c->cause;
		/* Fall through */
	case Q931_CALL_PROCEEDING:
		q931_display_subcmd(ctrl, c);
		if (mand_status != MAND_STATUS_OK) {
			q931_status(ctrl, c, mand_cause);
			break;
		}
		stop_t303(c->master_call);
		ctrl->ev.proceeding.subcmds = &ctrl->subcmds;
		if (c->newcall) {
			q931_release_complete(ctrl, c, newcall_rel_comp_cause(c));
			break;
		}
		if ((c->ourcallstate != Q931_CALL_STATE_CALL_INITIATED) &&
		    (c->ourcallstate != Q931_CALL_STATE_OVERLAP_SENDING) && 
		    (c->ourcallstate != Q931_CALL_STATE_CALL_DELIVERED) && 
		    (c->ourcallstate != Q931_CALL_STATE_OUTGOING_CALL_PROCEEDING)) {
			if (mh->msg == Q931_PROGRESS
				&& c->ourcallstate == Q931_CALL_STATE_ACTIVE
				&& ctrl->switchtype == PRI_SWITCH_QSIG) {
				/*
				 * Q.SIG is odd to allow PROGRESS when in the Active state since
				 * the media path is already open.  Ignore it since it doesn't
				 * convey anything very useful.  Maybe they will stop doing it.
				 *
				 * See ECMA-143 Section 10.1.7.2.
				 */
				break;
			}
			q931_status(ctrl,c,PRI_CAUSE_WRONG_MESSAGE);
			break;
		}
		ctrl->ev.proceeding.channel = q931_encode_channel(c);
		if (mh->msg == Q931_CALL_PROCEEDING) {
			ctrl->ev.e = PRI_EVENT_PROCEEDING;
			UPDATE_OURCALLSTATE(ctrl, c, Q931_CALL_STATE_OUTGOING_CALL_PROCEEDING);
			c->peercallstate = Q931_CALL_STATE_INCOMING_CALL_PROCEEDING;
		}
		ctrl->ev.proceeding.progress = c->progress;
		ctrl->ev.proceeding.progressmask = c->progressmask;
		ctrl->ev.proceeding.cref = c->cr;
		ctrl->ev.proceeding.call = c->master_call;

		for (cur = c->apdus; cur; cur = cur->next) {
			if (!cur->sent && cur->message == Q931_FACILITY) {
				q931_facility(ctrl, c);
				break;
			}
		}
		return Q931_RES_HAVEEVENT;
	case Q931_CONNECT_ACKNOWLEDGE:
		q931_display_subcmd(ctrl, c);
		if (c->newcall) {
			q931_release_complete(ctrl, c, newcall_rel_comp_cause(c));
			break;
		}
		switch (c->ourcallstate) {
		default:
			q931_status(ctrl, c, PRI_CAUSE_WRONG_CALL_STATE);
			return 0;
		case Q931_CALL_STATE_CONNECT_REQUEST:
		case Q931_CALL_STATE_ACTIVE:
			UPDATE_OURCALLSTATE(ctrl, c, Q931_CALL_STATE_ACTIVE);
			c->peercallstate = Q931_CALL_STATE_ACTIVE;
			if (ctrl->manual_connect_ack) {
				ctrl->ev.e = PRI_EVENT_CONNECT_ACK;
				ctrl->ev.connect_ack.subcmds = &ctrl->subcmds;
				ctrl->ev.connect_ack.channel = q931_encode_channel(c);
				ctrl->ev.connect_ack.call = c->master_call;
				return Q931_RES_HAVEEVENT;
			}
			break;
		}
		break;
	case Q931_STATUS:
		q931_display_subcmd(ctrl, c);
		if (mand_status != MAND_STATUS_OK) {
			q931_status(ctrl, c, mand_cause);
			break;
		}
		if (c->newcall) {
			if (c->cr & 0x7fff)
				q931_release_complete(ctrl,c,PRI_CAUSE_WRONG_CALL_STATE);
			break;
		}
		/* Do nothing */
		/* Also when the STATUS asks for the call of an unexisting reference send RELEASE_COMPLETE */
		if ((ctrl->debug & PRI_DEBUG_Q931_ANOMALY) &&
		    (c->cause != PRI_CAUSE_INTERWORKING)) 
			pri_error(ctrl, "Received unsolicited status: %s\n", pri_cause2str(c->cause));
		if (
#if 0
			/*
			 * Workaround for S-12 ver 7.3 - it responds to
			 * invalid/non-implemented IEs in SETUP with NULL call state.
			 */
			!c->sugcallstate && (c->ourcallstate != Q931_CALL_STATE_CALL_INITIATED)
#else
			/*
			 * Remove "workaround" since it breaks certification testing. If
			 * we receive a STATUS message of call state NULL and we are not
			 * in the call state NULL we must clear resources and return to
			 * the call state to pass testing.  See section 5.8.11 of Q.931.
			 */

			!c->sugcallstate
#endif
			) {
			ctrl->ev.hangup.subcmds = &ctrl->subcmds;
			ctrl->ev.hangup.channel = q931_encode_channel(c);
			ctrl->ev.hangup.cause = c->cause;
			ctrl->ev.hangup.cref = c->cr;
			ctrl->ev.hangup.call = c->master_call;
			ctrl->ev.hangup.aoc_units = c->aoc_units;
			ctrl->ev.hangup.call_held = NULL;
			ctrl->ev.hangup.call_active = NULL;
			libpri_copy_string(ctrl->ev.hangup.useruserinfo, c->useruserinfo, sizeof(ctrl->ev.hangup.useruserinfo));
			/* Free resources */
			UPDATE_OURCALLSTATE(ctrl, c, Q931_CALL_STATE_NULL);
			c->peercallstate = Q931_CALL_STATE_NULL;

			if (c->outboundbroadcast && (c != q931_get_subcall_winner(c->master_call))) {
				/* Complete clearing the disconnecting non-winning subcall. */
				pri_hangup(ctrl, c, -1);
				return 0;
			}

			/* Free resources */
			if (c->alive) {
				ctrl->ev.e = PRI_EVENT_HANGUP;
				c->alive = 0;
			} else if (c->sendhangupack) {
				ctrl->ev.e = PRI_EVENT_HANGUP_ACK;
				pri_hangup(ctrl, c, c->cause);
			} else {
				pri_hangup(ctrl, c, c->cause);
				return 0;
			}
			return Q931_RES_HAVEEVENT;
		}
		break;
	case Q931_RELEASE_COMPLETE:
		q931_display_subcmd(ctrl, c);
		c->hangupinitiated = 1;
		UPDATE_OURCALLSTATE(ctrl, c, Q931_CALL_STATE_NULL);
		c->peercallstate = Q931_CALL_STATE_NULL;

		ctrl->ev.hangup.subcmds = &ctrl->subcmds;
		ctrl->ev.hangup.channel = q931_encode_channel(c);
		ctrl->ev.hangup.cause = c->cause;
		ctrl->ev.hangup.cref = c->cr;
		ctrl->ev.hangup.call = c->master_call;
		ctrl->ev.hangup.aoc_units = c->aoc_units;
		ctrl->ev.hangup.call_held = NULL;
		ctrl->ev.hangup.call_active = NULL;
		libpri_copy_string(ctrl->ev.hangup.useruserinfo, c->useruserinfo, sizeof(ctrl->ev.hangup.useruserinfo));
		c->useruserinfo[0] = '\0';

		if (c->cc.record && c->cc.record->signaling == c) {
			pri_cc_event(ctrl, c, c->cc.record, CC_EVENT_SIGNALING_GONE);
		}

		if (c->outboundbroadcast && (c != q931_get_subcall_winner(c->master_call))) {
			/* Complete clearing the disconnecting non-winning subcall. */
			pri_hangup(ctrl, c, -1);
			return 0;
		}

		/* Free resources */
		if (c->alive) {
			ctrl->ev.e = PRI_EVENT_HANGUP;
			c->alive = 0;
		} else if (c->sendhangupack) {
			ctrl->ev.e = PRI_EVENT_HANGUP_ACK;
			pri_hangup(ctrl, c, c->cause);
		} else {
			pri_hangup(ctrl, c, c->cause);
			return 0;
		}
		return Q931_RES_HAVEEVENT;
	case Q931_RELEASE:
		q931_display_subcmd(ctrl, c);
		c->hangupinitiated = 1;
		if (mand_status != MAND_STATUS_OK) {
			/* Force mandatory ie cause */
			c->cause = mand_cause;
		}

		/*
		 * Don't send RELEASE_COMPLETE if they sent us RELEASE while we
		 * were waiting for RELEASE_COMPLETE from them, assume a NULL state.
		 */
		if (c->ourcallstate == Q931_CALL_STATE_RELEASE_REQUEST) 
			c->peercallstate = Q931_CALL_STATE_NULL;
		else {
			c->peercallstate = Q931_CALL_STATE_RELEASE_REQUEST;
		}
		UPDATE_OURCALLSTATE(ctrl, c, Q931_CALL_STATE_NULL);

		if (c->newcall) {
			q931_release_complete(ctrl, c, newcall_rel_comp_cause(c));
			break;
		}

		ctrl->ev.e = PRI_EVENT_HANGUP;
		ctrl->ev.hangup.subcmds = &ctrl->subcmds;
		ctrl->ev.hangup.channel = q931_encode_channel(c);
		ctrl->ev.hangup.cause = c->cause;
		ctrl->ev.hangup.cref = c->cr;
		ctrl->ev.hangup.call = c->master_call;
		ctrl->ev.hangup.aoc_units = c->aoc_units;
		ctrl->ev.hangup.call_held = NULL;
		ctrl->ev.hangup.call_active = NULL;
		libpri_copy_string(ctrl->ev.hangup.useruserinfo, c->useruserinfo, sizeof(ctrl->ev.hangup.useruserinfo));
		c->useruserinfo[0] = '\0';

		if (c->cc.record && c->cc.record->signaling == c) {
			pri_cc_event(ctrl, c, c->cc.record, CC_EVENT_SIGNALING_GONE);
		}

		if (c->outboundbroadcast && (c != q931_get_subcall_winner(c->master_call))) {
			/* Complete clearing the disconnecting non-winning subcall. */
			pri_hangup(ctrl, c, -1);
			return 0;
		}
		return Q931_RES_HAVEEVENT;
	case Q931_DISCONNECT:
		q931_display_subcmd(ctrl, c);
		c->hangupinitiated = 1;
		if (mand_status != MAND_STATUS_OK) {
			/* Still let user call release */
			c->cause = mand_cause;
		}
		if (c->newcall) {
			q931_release_complete(ctrl, c, newcall_rel_comp_cause(c));
			break;
		}

		/*
		 * Determine if there are any calls that can be proposed for
		 * a transfer of held call on disconnect.
		 */
		ctrl->ev.hangup.call_held = NULL;
		ctrl->ev.hangup.call_active = NULL;
		switch (c->ourcallstate) {
		case Q931_CALL_STATE_OUTGOING_CALL_PROCEEDING:
		case Q931_CALL_STATE_CALL_DELIVERED:
		case Q931_CALL_STATE_CALL_RECEIVED:
		case Q931_CALL_STATE_CONNECT_REQUEST:
		case Q931_CALL_STATE_INCOMING_CALL_PROCEEDING:
		case Q931_CALL_STATE_ACTIVE:
			if (c->master_call->hold_state == Q931_HOLD_STATE_CALL_HELD) {
				/* Held call is being disconnected first. */
				ctrl->ev.hangup.call_held = c->master_call;
				ctrl->ev.hangup.call_active = q931_find_held_active_call(ctrl, c);
			} else {
				/* Active call is being disconnected first. */
				if (q931_find_winning_call(c) == c) {
					/*
					 * Only a normal call or the winning call of a broadcast SETUP
					 * can participate in a transfer of held call on disconnet.
					 */
					ctrl->ev.hangup.call_active = c->master_call;
					ctrl->ev.hangup.call_held = q931_find_held_call(ctrl, c);
				}
			}
			break;
		default:
			break;
		}
		if (ctrl->debug & PRI_DEBUG_Q931_STATE) {
			if (ctrl->ev.hangup.call_held) {
				pri_message(ctrl, "-- Found held call: %p cref:%d\n",
					ctrl->ev.hangup.call_held, ctrl->ev.hangup.call_held->cr);
			}
			if (ctrl->ev.hangup.call_active) {
				pri_message(ctrl, "-- Found active call: %p cref:%d\n",
					ctrl->ev.hangup.call_active, ctrl->ev.hangup.call_active->cr);
			}
			if (ctrl->ev.hangup.call_held && ctrl->ev.hangup.call_active) {
				pri_message(ctrl, "-- Transfer held call on disconnect possible.\n");
			}
		}

		ourcallstate_orig = c->ourcallstate;
		UPDATE_OURCALLSTATE(ctrl, c, Q931_CALL_STATE_DISCONNECT_INDICATION);
		c->peercallstate = Q931_CALL_STATE_DISCONNECT_REQUEST;
		c->sendhangupack = 1;

		/* wait for a RELEASE so that sufficient time has passed
		   for the inband audio to be heard */
		if (ctrl->acceptinbanddisconnect
			&& (c->progressmask & PRI_PROG_INBAND_AVAILABLE)) {
			switch (ourcallstate_orig) {
			case Q931_CALL_STATE_CALL_INITIATED:
			case Q931_CALL_STATE_OVERLAP_SENDING:
			case Q931_CALL_STATE_OUTGOING_CALL_PROCEEDING:
			case Q931_CALL_STATE_CALL_DELIVERED:
				/*
				 * Open the media path if it isn't already open so
				 * the user can hear the inband audio.
				 */
				if (ctrl->debug & PRI_DEBUG_Q931_STATE) {
					pri_message(ctrl, "Report the DISCONNECT as a PROGRESS instead.\n");
				}
				ctrl->ev.e = PRI_EVENT_PROGRESS;
				ctrl->ev.proceeding.cause = c->cause;
				ctrl->ev.proceeding.subcmds = &ctrl->subcmds;
				ctrl->ev.proceeding.channel = q931_encode_channel(c);
				ctrl->ev.proceeding.progress = c->progress;
				ctrl->ev.proceeding.progressmask = c->progressmask;
				ctrl->ev.proceeding.cref = c->cr;
				ctrl->ev.proceeding.call = c->master_call;
				return Q931_RES_HAVEEVENT;
			default:
				break;
			}
			/*
			 * Suppress reporting DISCONNECT to the upper layer.  The
			 * media path should already be open and we cannot report
			 * a PROGRESS at this time anyway.
			 */
			break;
		}

		/* Return such an event */
		ctrl->ev.e = PRI_EVENT_HANGUP_REQ;
		ctrl->ev.hangup.subcmds = &ctrl->subcmds;
		ctrl->ev.hangup.channel = q931_encode_channel(c);
		ctrl->ev.hangup.cause = c->cause;
		ctrl->ev.hangup.cref = c->cr;
		ctrl->ev.hangup.call = c->master_call;
		ctrl->ev.hangup.aoc_units = c->aoc_units;
		libpri_copy_string(ctrl->ev.hangup.useruserinfo, c->useruserinfo, sizeof(ctrl->ev.hangup.useruserinfo));
		c->useruserinfo[0] = '\0';

		if (c->outboundbroadcast && (c != q931_get_subcall_winner(c->master_call))) {
			/* Complete clearing the disconnecting non-winning subcall. */
			pri_hangup(ctrl, c, -1);
			return 0;
		}

		if (c->alive) {
			switch (c->cause) {
			case PRI_CAUSE_USER_BUSY:
			case PRI_CAUSE_NORMAL_CIRCUIT_CONGESTION:
				switch (ctrl->switchtype) {
				case PRI_SWITCH_QSIG:
					pri_cc_qsig_determine_available(ctrl, c);
					break;
				default:
					break;
				}
				break;
			default:
				break;
			}

			return Q931_RES_HAVEEVENT;
		} else {
			pri_hangup(ctrl,c,c->cause);
		}
		break;
	case Q931_RESTART_ACKNOWLEDGE:
		q931_display_subcmd(ctrl, c);
		UPDATE_OURCALLSTATE(ctrl, c, Q931_CALL_STATE_NULL);
		c->peercallstate = Q931_CALL_STATE_NULL;
		ctrl->ev.e = PRI_EVENT_RESTART_ACK;
		ctrl->ev.restartack.channel = q931_encode_channel(c);
		if (c->restart_tx.t316_timer
			/*
			 * Since the DS1 value can vary, only check the channel number.
			 * We're only supposed to have one RESTART request outstanding
			 * at a time anyway.
			 */
			&& (c->restart_tx.channel & 0xFF) == (ctrl->ev.restartack.channel & 0xFF)) {
			/* This is the RESTART ACKNOWLEDGE we are expecting. */
			stop_t316(c);
		}
		return Q931_RES_HAVEEVENT;
	case Q931_INFORMATION:
		/* XXX We're handling only INFORMATION messages that contain
		       overlap dialing received digit
		       +  the "Complete" msg which is basically an EOF on further digits
		   XXX */
		q931_display_subcmd(ctrl, c);
		if (c->newcall) {
			q931_release_complete(ctrl, c, newcall_rel_comp_cause(c));
			break;
		}
		if (strlen(c->keypad_digits)) {
			ctrl->ev.e = PRI_EVENT_KEYPAD_DIGIT;
			ctrl->ev.digit.subcmds = &ctrl->subcmds;
			ctrl->ev.digit.call = c->master_call;
			ctrl->ev.digit.channel = q931_encode_channel(c);
			libpri_copy_string(ctrl->ev.digit.digits, c->keypad_digits, sizeof(ctrl->ev.digit.digits));
			return Q931_RES_HAVEEVENT;
		}
		ctrl->ev.e = PRI_EVENT_INFO_RECEIVED;
		ctrl->ev.ring.subcmds = &ctrl->subcmds;
		ctrl->ev.ring.call = c->master_call;
		ctrl->ev.ring.channel = q931_encode_channel(c);
		libpri_copy_string(ctrl->ev.ring.callednum, c->overlap_digits, sizeof(ctrl->ev.ring.callednum));

		q931_party_id_copy_to_pri(&ctrl->ev.ring.calling, &c->remote_id);
		/* for backwards compatibility, still need ctrl->ev.ring.callingsubaddr */
		if (!c->remote_id.subaddress.type) {	/* NSAP: Type = 0 */
			libpri_copy_string(ctrl->ev.ring.callingsubaddr, (char *) c->remote_id.subaddress.data, sizeof(ctrl->ev.ring.callingsubaddr));
		} else {
			ctrl->ev.ring.callingsubaddr[0] = '\0';
		}

		ctrl->ev.ring.complete = c->complete;	/* this covers IE 33 (Sending Complete) */
		return Q931_RES_HAVEEVENT;
	case Q931_STATUS_ENQUIRY:
		q931_display_clear(c);
		if (c->newcall) {
			q931_release_complete(ctrl, c, newcall_rel_comp_cause(c));
		} else
			q931_status(ctrl,c, PRI_CAUSE_RESPONSE_TO_STATUS_ENQUIRY);
		break;
	case Q931_SETUP_ACKNOWLEDGE:
		q931_display_subcmd(ctrl, c);
		if (mand_status != MAND_STATUS_OK) {
			q931_status(ctrl, c, mand_cause);
			break;
		}
		stop_t303(c->master_call);
		if (c->newcall) {
			q931_release_complete(ctrl, c, newcall_rel_comp_cause(c));
			break;
		}
		switch (c->ourcallstate) {
		default:
			q931_status(ctrl, c, PRI_CAUSE_WRONG_CALL_STATE);
			return 0;
		case Q931_CALL_STATE_CALL_INITIATED:
			break;
		}
		UPDATE_OURCALLSTATE(ctrl, c, Q931_CALL_STATE_OVERLAP_SENDING);
		c->peercallstate = Q931_CALL_STATE_OVERLAP_RECEIVING;
		ctrl->ev.e = PRI_EVENT_SETUP_ACK;
		ctrl->ev.setup_ack.subcmds = &ctrl->subcmds;
		ctrl->ev.setup_ack.channel = q931_encode_channel(c);
		ctrl->ev.setup_ack.call = c->master_call;
		ctrl->ev.setup_ack.progressmask = c->progressmask;

		for (cur = c->apdus; cur; cur = cur->next) {
			if (!cur->sent && cur->message == Q931_FACILITY) {
				q931_facility(ctrl, c);
				break;
			}
		}

		return Q931_RES_HAVEEVENT;
	case Q931_NOTIFY:
		res = 0;
		changed = 0;
		switch (c->notify) {
		case PRI_NOTIFY_CALL_DIVERTING:
			if (c->redirection_number.valid) {
				c->redirecting.to.number = c->redirection_number;
				if (c->redirecting.count < PRI_MAX_REDIRECTS) {
					++c->redirecting.count;
				}
				switch (c->ourcallstate) {
				case Q931_CALL_STATE_CALL_DELIVERED:
					/* Call is deflecting after we have seen an ALERTING message */
					c->redirecting.reason = PRI_REDIR_FORWARD_ON_NO_REPLY;
					break;
				default:
					/* Call is deflecting for call forwarding unconditional or busy reason. */
					c->redirecting.reason = PRI_REDIR_UNKNOWN;
					break;
				}

				/* Setup redirecting subcommand */
				subcmd = q931_alloc_subcommand(ctrl);
				if (subcmd) {
					subcmd->cmd = PRI_SUBCMD_REDIRECTING;
					q931_party_redirecting_copy_to_pri(&subcmd->u.redirecting,
						&c->redirecting);
				}
			}

			q931_display_subcmd(ctrl, c);
			if (ctrl->subcmds.counter_subcmd) {
				q931_fill_facility_event(ctrl, c);
				res = Q931_RES_HAVEEVENT;
			}
			break;
		case PRI_NOTIFY_TRANSFER_ACTIVE:
			if (q931_party_number_cmp(&c->remote_id.number, &c->redirection_number)) {
				/* The remote party number information changed. */
				c->remote_id.number = c->redirection_number;
				changed = 1;
			}
			/* Fall through */
		case PRI_NOTIFY_TRANSFER_ALERTING:
			if (ctrl->display_flags.receive & PRI_DISPLAY_OPTION_NAME_UPDATE) {
				struct q931_party_name name;

				if (q931_display_name_get(c, &name)) {
					if (q931_party_name_cmp(&c->remote_id.name, &name)) {
						/* The remote party name information changed. */
						c->remote_id.name = name;
						changed = 1;
					}
				}
			}
			if (c->redirection_number.valid
				&& q931_party_number_cmp(&c->remote_id.number, &c->redirection_number)) {
				/* The remote party number information changed. */
				c->remote_id.number = c->redirection_number;
				changed = 1;
			}
			if (c->remote_id.subaddress.valid) {
				/*
				 * Clear the subaddress as the remote party has been changed.
				 * Any new subaddress will arrive later.
				 */
				q931_party_subaddress_init(&c->remote_id.subaddress);
				changed = 1;
			}
			if (changed) {
				/* Setup connected line subcommand */
				subcmd = q931_alloc_subcommand(ctrl);
				if (subcmd) {
					subcmd->cmd = PRI_SUBCMD_CONNECTED_LINE;
					q931_party_id_copy_to_pri(&subcmd->u.connected_line.id,
						&c->remote_id);
				}
			}

			q931_display_subcmd(ctrl, c);
			if (ctrl->subcmds.counter_subcmd) {
				q931_fill_facility_event(ctrl, c);
				res = Q931_RES_HAVEEVENT;
			}
			break;
		default:
			ctrl->ev.e = PRI_EVENT_NOTIFY;
			ctrl->ev.notify.subcmds = &ctrl->subcmds;
			ctrl->ev.notify.channel = q931_encode_channel(c);
			ctrl->ev.notify.info = c->notify;
			ctrl->ev.notify.call = c->master_call;
			res = Q931_RES_HAVEEVENT;
			break;
		}
		q931_display_subcmd(ctrl, c);
		return res;
	case Q931_HOLD:
		q931_display_subcmd(ctrl, c);
		res = 0;
		if (!ctrl->hold_support) {
			/*
			 * Blocking any calls from getting on HOLD effectively
			 * disables HOLD/RETRIEVE.
			 */
			q931_send_hold_rej_msg(ctrl, c, PRI_CAUSE_FACILITY_NOT_IMPLEMENTED);
			break;
		}
		switch (c->ourcallstate) {
		case Q931_CALL_STATE_CALL_RECEIVED:
		case Q931_CALL_STATE_CONNECT_REQUEST:
		case Q931_CALL_STATE_INCOMING_CALL_PROCEEDING:
			if (PTMP_MODE(ctrl)) {
				/* HOLD request only allowed in these states if point-to-point mode. */
				q931_send_hold_rej_msg(ctrl, c, PRI_CAUSE_WRONG_CALL_STATE);
				break;
			}
			/* Fall through */
		case Q931_CALL_STATE_OUTGOING_CALL_PROCEEDING:
		case Q931_CALL_STATE_CALL_DELIVERED:
		case Q931_CALL_STATE_ACTIVE:
			if (!q931_find_winning_call(c)) {
				/*
				 * Only the winning call of a broadcast SETUP can do hold since the
				 * call must be answered first.
				 */
				q931_send_hold_rej_msg(ctrl, c, PRI_CAUSE_WRONG_CALL_STATE);
				break;
			}
			master_call = c->master_call;
			switch (master_call->hold_state) {
			case Q931_HOLD_STATE_HOLD_REQ:
				if (ctrl->debug & PRI_DEBUG_Q931_STATE) {
					pri_message(ctrl, "HOLD collision\n");
				}
				if (ctrl->localtype == PRI_NETWORK) {
					/* The network ignores HOLD request on a hold collision. */
					break;
				}
				/* Fall through */
			case Q931_HOLD_STATE_IDLE:
				ctrl->ev.e = PRI_EVENT_HOLD;
				ctrl->ev.hold.channel = q931_encode_channel(c);
				ctrl->ev.hold.call = master_call;
				ctrl->ev.hold.subcmds = &ctrl->subcmds;
				res = Q931_RES_HAVEEVENT;

				UPDATE_HOLD_STATE(ctrl, master_call, Q931_HOLD_STATE_HOLD_IND);
				break;
			default:
				q931_send_hold_rej_msg(ctrl, c, PRI_CAUSE_WRONG_CALL_STATE);
				break;
			}
			break;
		case Q931_CALL_STATE_DISCONNECT_INDICATION:
		case Q931_CALL_STATE_RELEASE_REQUEST:
			/* Ignore HOLD request in these states. */
			break;
		default:
			q931_send_hold_rej_msg(ctrl, c, PRI_CAUSE_WRONG_CALL_STATE);
			break;
		}
		return res;
	case Q931_HOLD_ACKNOWLEDGE:
		q931_display_subcmd(ctrl, c);
		res = 0;
		master_call = c->master_call;
		switch (master_call->hold_state) {
		case Q931_HOLD_STATE_HOLD_REQ:
			ctrl->ev.e = PRI_EVENT_HOLD_ACK;
			ctrl->ev.hold_ack.channel = q931_encode_channel(c);
			ctrl->ev.hold_ack.call = master_call;
			ctrl->ev.hold_ack.subcmds = &ctrl->subcmds;
			res = Q931_RES_HAVEEVENT;

			UPDATE_HOLD_STATE(ctrl, master_call, Q931_HOLD_STATE_CALL_HELD);

			/* Call is now on hold so forget the channel. */
			c->channelno = 0;/* No channel */
			c->ds1no = 0;
			c->ds1explicit = 0;
			c->chanflags = 0;

			/* Stop T-HOLD timer */
			pri_schedule_del(ctrl, master_call->hold_timer);
			master_call->hold_timer = 0;
			break;
		default:
			/* Ignore response.  Response is late or spurrious. */
			break;
		}
		return res;
	case Q931_HOLD_REJECT:
		q931_display_subcmd(ctrl, c);
		res = 0;
		master_call = c->master_call;
		switch (master_call->hold_state) {
		case Q931_HOLD_STATE_HOLD_REQ:
			if (mand_status != MAND_STATUS_OK) {
				/* Still, let hold rejection continue. */
				c->cause = mand_cause;
			}
			ctrl->ev.e = PRI_EVENT_HOLD_REJ;
			ctrl->ev.hold_rej.channel = q931_encode_channel(c);
			ctrl->ev.hold_rej.call = master_call;
			ctrl->ev.hold_rej.cause = c->cause;
			ctrl->ev.hold_rej.subcmds = &ctrl->subcmds;
			res = Q931_RES_HAVEEVENT;

			UPDATE_HOLD_STATE(ctrl, master_call, Q931_HOLD_STATE_IDLE);

			/* Stop T-HOLD timer */
			pri_schedule_del(ctrl, master_call->hold_timer);
			master_call->hold_timer = 0;
			break;
		default:
			/* Ignore response.  Response is late or spurrious. */
			break;
		}
		return res;
	case Q931_RETRIEVE:
		q931_display_subcmd(ctrl, c);
		res = 0;
		switch (c->ourcallstate) {
		case Q931_CALL_STATE_CALL_RECEIVED:
		case Q931_CALL_STATE_CONNECT_REQUEST:
		case Q931_CALL_STATE_INCOMING_CALL_PROCEEDING:
			if (PTMP_MODE(ctrl)) {
				/* RETRIEVE request only allowed in these states if point-to-point mode. */
				q931_send_retrieve_rej_msg(ctrl, c, PRI_CAUSE_WRONG_CALL_STATE);
				break;
			}
			/* Fall through */
		case Q931_CALL_STATE_OUTGOING_CALL_PROCEEDING:
		case Q931_CALL_STATE_CALL_DELIVERED:
		case Q931_CALL_STATE_ACTIVE:
			if (!q931_find_winning_call(c)) {
				/*
				 * Only the winning call of a broadcast SETUP can do hold since the
				 * call must be answered first.
				 */
				q931_send_retrieve_rej_msg(ctrl, c, PRI_CAUSE_WRONG_CALL_STATE);
				break;
			}
			master_call = c->master_call;
			switch (master_call->hold_state) {
			case Q931_HOLD_STATE_RETRIEVE_REQ:
				if (ctrl->debug & PRI_DEBUG_Q931_STATE) {
					pri_message(ctrl, "RETRIEVE collision\n");
				}
				if (ctrl->localtype == PRI_NETWORK) {
					/* The network ignores RETRIEVE request on a retrieve collision. */
					break;
				}
				/* Fall through */
			case Q931_HOLD_STATE_CALL_HELD:
				ctrl->ev.e = PRI_EVENT_RETRIEVE;
				ctrl->ev.retrieve.channel = q931_encode_channel(c);
				ctrl->ev.retrieve.call = master_call;
				ctrl->ev.retrieve.flexible = !(c->chanflags & FLAG_EXCLUSIVE);
				ctrl->ev.retrieve.subcmds = &ctrl->subcmds;
				res = Q931_RES_HAVEEVENT;

				UPDATE_HOLD_STATE(ctrl, master_call, Q931_HOLD_STATE_RETRIEVE_IND);
				break;
			default:
				q931_send_retrieve_rej_msg(ctrl, c, PRI_CAUSE_WRONG_CALL_STATE);
				break;
			}
			break;
		case Q931_CALL_STATE_DISCONNECT_INDICATION:
		case Q931_CALL_STATE_RELEASE_REQUEST:
			/* Ignore RETRIEVE request in these states. */
			break;
		default:
			q931_send_retrieve_rej_msg(ctrl, c, PRI_CAUSE_WRONG_CALL_STATE);
			break;
		}
		return res;
	case Q931_RETRIEVE_ACKNOWLEDGE:
		q931_display_subcmd(ctrl, c);
		res = 0;
		master_call = c->master_call;
		switch (master_call->hold_state) {
		case Q931_HOLD_STATE_RETRIEVE_REQ:
			UPDATE_HOLD_STATE(ctrl, master_call, Q931_HOLD_STATE_IDLE);

			/* Stop T-RETRIEVE timer */
			pri_schedule_del(ctrl, master_call->hold_timer);
			master_call->hold_timer = 0;

			ctrl->ev.e = PRI_EVENT_RETRIEVE_ACK;
			ctrl->ev.retrieve_ack.channel = q931_encode_channel(c);
			ctrl->ev.retrieve_ack.call = master_call;
			ctrl->ev.retrieve_ack.subcmds = &ctrl->subcmds;
			res = Q931_RES_HAVEEVENT;
			break;
		default:
			/* Ignore response.  Response is late or spurrious. */
			break;
		}
		return res;
	case Q931_RETRIEVE_REJECT:
		q931_display_subcmd(ctrl, c);
		res = 0;
		master_call = c->master_call;
		switch (master_call->hold_state) {
		case Q931_HOLD_STATE_CALL_HELD:
			/* In this state likely because of a RETRIEVE collision. */
		case Q931_HOLD_STATE_RETRIEVE_REQ:
			UPDATE_HOLD_STATE(ctrl, master_call, Q931_HOLD_STATE_CALL_HELD);

			/* Call is still on hold so forget the channel. */
			c->channelno = 0;/* No channel */
			c->ds1no = 0;
			c->ds1explicit = 0;
			c->chanflags = 0;

			/* Stop T-RETRIEVE timer */
			pri_schedule_del(ctrl, master_call->hold_timer);
			master_call->hold_timer = 0;

			if (mand_status != MAND_STATUS_OK) {
				/* Still, let retrive rejection continue. */
				c->cause = mand_cause;
			}
			ctrl->ev.e = PRI_EVENT_RETRIEVE_REJ;
			ctrl->ev.retrieve_rej.channel = q931_encode_channel(c);
			ctrl->ev.retrieve_rej.call = master_call;
			ctrl->ev.retrieve_rej.cause = c->cause;
			ctrl->ev.retrieve_rej.subcmds = &ctrl->subcmds;
			res = Q931_RES_HAVEEVENT;
			break;
		default:
			/* Ignore response.  Response is late or spurrious. */
			break;
		}
		return res;
	case Q931_USER_INFORMATION:
	case Q931_SEGMENT:
	case Q931_CONGESTION_CONTROL:
	case Q931_RESUME:
	case Q931_RESUME_ACKNOWLEDGE:
	case Q931_RESUME_REJECT:
	case Q931_SUSPEND:
	case Q931_SUSPEND_ACKNOWLEDGE:
	case Q931_SUSPEND_REJECT:
		pri_error(ctrl, "!! Not yet handling post-handle message type %s (0x%X)\n",
			msg2str(mh->msg), mh->msg);
		/* Fall through */
	default:
		pri_error(ctrl, "!! Don't know how to post-handle message type %s (0x%X)\n",
			msg2str(mh->msg), mh->msg);
		q931_display_clear(c);
		q931_status(ctrl,c, PRI_CAUSE_MESSAGE_TYPE_NONEXIST);
		if (c->newcall) {
			pri_destroycall(ctrl, c);
		}
		return -1;
	}
	return 0;
}

/* Clear a call, although we did not receive any hangup notification. */
static int pri_internal_clear(struct q931_call *c)
{
	struct pri *ctrl = c->pri;
	int res;

	pri_schedule_del(ctrl, c->retranstimer);
	c->retranstimer = 0;
	c->useruserinfo[0] = '\0';
	//c->cause = -1;
	c->causecode = -1;
	c->causeloc = -1;
	c->sugcallstate = Q931_CALL_STATE_NOT_SET;
	c->aoc_units = -1;

	if (c->master_call->outboundbroadcast
		&& c == q931_find_winning_call(c)) {
		/* Pass the hangup cause to the master_call. */
		c->master_call->cause = c->cause;
	}

	q931_clr_subcommands(ctrl);
	ctrl->ev.hangup.subcmds = &ctrl->subcmds;
	ctrl->ev.hangup.channel = q931_encode_channel(c);
	ctrl->ev.hangup.cause = c->cause;      		
	ctrl->ev.hangup.cref = c->cr;          		
	ctrl->ev.hangup.call = c->master_call;
	ctrl->ev.hangup.aoc_units = c->aoc_units;
	ctrl->ev.hangup.call_held = NULL;
	ctrl->ev.hangup.call_active = NULL;
	libpri_copy_string(ctrl->ev.hangup.useruserinfo, c->useruserinfo, sizeof(ctrl->ev.hangup.useruserinfo));

	if (ctrl->debug & PRI_DEBUG_Q931_STATE) {
		pri_message(ctrl, DBGHEAD "alive %d, hangupack %d\n", DBGINFO, c->alive,
			c->sendhangupack);
	}

	if (c->cc.record) {
		if (c->cc.record->signaling == c) {
			pri_cc_event(ctrl, c, c->cc.record, CC_EVENT_SIGNALING_GONE);
		} else if (c->cc.record->original_call == c) {
			pri_cc_event(ctrl, c, c->cc.record, CC_EVENT_INTERNAL_CLEARING);
		}
	}

	/* Free resources */
	if (c->alive) {
		c->alive = 0;
		ctrl->ev.e = PRI_EVENT_HANGUP;
		res = Q931_RES_HAVEEVENT;
	} else if (c->sendhangupack) {
		pri_hangup(ctrl, c, c->cause);
		ctrl->ev.e = PRI_EVENT_HANGUP_ACK;
		res = Q931_RES_HAVEEVENT;
	} else {
		pri_hangup(ctrl, c, c->cause);
		if (ctrl->subcmds.counter_subcmd) {
			q931_fill_facility_event(ctrl, ctrl->link.dummy_call);
			res = Q931_RES_HAVEEVENT;
		} else {
			res = 0;
		}
	}

	return res;
}

/* Handle T309 timeout for an active call. */
static void pri_dl_down_timeout(void *data)
{
	struct q931_call *c = data;
	struct pri *ctrl = c->pri;

	if (ctrl->debug & PRI_DEBUG_Q931_STATE) {
		pri_message(ctrl, "T309 timed out waiting for data link re-establishment\n");
	}

	c->retranstimer = 0;
	c->cause = PRI_CAUSE_DESTINATION_OUT_OF_ORDER;
	UPDATE_OURCALLSTATE(ctrl, c, Q931_CALL_STATE_NULL);
	c->peercallstate = Q931_CALL_STATE_NULL;
	if (pri_internal_clear(c) == Q931_RES_HAVEEVENT) {
		ctrl->schedev = 1;
	}
}

/* Handle Layer 2 down event for a non active call. */
static void pri_dl_down_cancelcall(void *data)
{
	struct q931_call *c = data;
	struct pri *ctrl = c->pri;

	if (ctrl->debug & PRI_DEBUG_Q931_STATE) {
		pri_message(ctrl, "Cancel call after data link failure\n");
	}

	c->retranstimer = 0;
	c->cause = PRI_CAUSE_DESTINATION_OUT_OF_ORDER;
	UPDATE_OURCALLSTATE(ctrl, c, Q931_CALL_STATE_NULL);
	c->peercallstate = Q931_CALL_STATE_NULL;
	if (pri_internal_clear(c) == Q931_RES_HAVEEVENT) {
		ctrl->schedev = 1;
	}
}

/*!
 * \internal
 * \brief Convert the DL event to a string.
 *
 * \param event Data-link event to convert to a string.
 *
 * \return DL event string
 */
static const char *q931_dl_event2str(enum Q931_DL_EVENT event)
{
	const char *str;

	str = "Unknown";
	switch (event) {
	case Q931_DL_EVENT_NONE:
		str = "Q931_DL_EVENT_NONE";
		break;
	case Q931_DL_EVENT_DL_ESTABLISH_IND:
		str = "Q931_DL_EVENT_DL_ESTABLISH_IND";
		break;
	case Q931_DL_EVENT_DL_ESTABLISH_CONFIRM:
		str = "Q931_DL_EVENT_DL_ESTABLISH_CONFIRM";
		break;
	case Q931_DL_EVENT_DL_RELEASE_IND:
		str = "Q931_DL_EVENT_DL_RELEASE_IND";
		break;
	case Q931_DL_EVENT_DL_RELEASE_CONFIRM:
		str = "Q931_DL_EVENT_DL_RELEASE_CONFIRM";
		break;
	case Q931_DL_EVENT_TEI_REMOVAL:
		str = "Q931_DL_EVENT_TEI_REMOVAL";
		break;
	}
	return str;
}

/*!
 * \brief Receive a DL event from layer 2.
 *
 * \param link Q.921 link event occurred on.
 * \param event Data-link event reporting.
 *
 * \return Nothing
 */
void q931_dl_event(struct q921_link *link, enum Q931_DL_EVENT event)
{
	struct q931_call *cur;
	struct q931_call *cur_next;
	struct q931_call *call;
	struct pri *ctrl;
	int idx;

	if (!link) {
		return;
	}

	ctrl = link->ctrl;

	if (ctrl->debug & PRI_DEBUG_Q931_STATE) {
		pri_message(ctrl, "TEI=%d DL event: %s(%d)\n", link->tei,
			q931_dl_event2str(event), event);
	}

	switch (event) {
	case Q931_DL_EVENT_TEI_REMOVAL:
		if (!BRI_NT_PTMP(ctrl)) {
			/* Only NT PTMP has anything to worry about when the TEI is removed. */
			break;
		}

		/*
		 * For NT PTMP, this deviation from the specifications is needed
		 * because we have no way to re-associate any T309 calls on the
		 * removed TEI.
		 */
		for (cur = *ctrl->callpool; cur; cur = cur->next) {
			if (cur->outboundbroadcast) {
				/* Does this master call have a subcall on the link that went down? */
				call = NULL;
				for (idx = 0; idx < ARRAY_LEN(cur->subcalls); ++idx) {
					if (cur->subcalls[idx] && cur->subcalls[idx]->link == link) {
						/* This subcall is on the link that went down. */
						call = cur->subcalls[idx];
						break;
					}
				}
				if (!call) {
					/* No subcall is on the link that went down. */
					continue;
				}
			} else if (cur->link != link) {
				/* This call is not on the link that went down. */
				continue;
			} else {
				call = cur;
			}

			if (!(cur->cr & ~Q931_CALL_REFERENCE_FLAG)) {
				/* Simply destroy the global call reference call record. */
				if (ctrl->debug & PRI_DEBUG_Q931_STATE) {
					pri_message(ctrl, "TEI=%d Destroying global call record\n",
						link->tei);
				}
				q931_destroycall(ctrl, call);
				continue;
			}

			/*
			 * NOTE:  We are gambling that no T309 timer's have had a chance
			 * to expire.  They should not expire since we are either called
			 * immediately after the Q931_DL_EVENT_DL_RELEASE_xxx or after a
			 * timeout of 0.
			 */
			if (ctrl->debug & PRI_DEBUG_Q931_STATE) {
				pri_message(ctrl, "Cancel call cref=%d on channel %d in state %d (%s)\n",
					call->cr, call->channelno, call->ourcallstate,
					q931_call_state_str(call->ourcallstate));
			}
			call->link = NULL;
			pri_schedule_del(ctrl, call->retranstimer);
			call->retranstimer = pri_schedule_event(ctrl, 0, pri_dl_down_cancelcall,
				call);
		}
		break;
	case Q931_DL_EVENT_DL_RELEASE_IND:
	case Q931_DL_EVENT_DL_RELEASE_CONFIRM:
		for (cur = *ctrl->callpool; cur; cur = cur_next) {
			/* The master call could get destroyed if the last subcall dies. */
			cur_next = cur->next;

			if (!(cur->cr & ~Q931_CALL_REFERENCE_FLAG)) {
				/* Don't do anything on the global call reference call record. */
				continue;
			}
			if (cur->outboundbroadcast) {
				/* Does this master call have a subcall on the link that went down? */
				call = NULL;
				for (idx = 0; idx < ARRAY_LEN(cur->subcalls); ++idx) {
					if (cur->subcalls[idx] && cur->subcalls[idx]->link == link) {
						/* This subcall is on the link that went down. */
						call = cur->subcalls[idx];
						break;
					}
				}
				if (!call) {
					/* No subcall is on the link that went down. */
					continue;
				}
			} else if (cur->link != link) {
				/* This call is not on the link that went down. */
				continue;
			} else {
				call = cur;
			}
			switch (call->ourcallstate) {
			case Q931_CALL_STATE_ACTIVE:
				/* NOTE: Only a winning subcall can get to the active state. */
				if (ctrl->nfas) {
					/*
					 * The upper layer should handle T309 for NFAS since the calls
					 * could be maintained by a backup D channel if the B channel
					 * for the call did not go into alarm.
					 */
					break;
				}
				/*
				 * For a call in Active state, activate T309 only if there is
				 * no timer already running.
				 *
				 * NOTE: cur != call when we have a winning subcall.
				 */
				if (!cur->retranstimer || !call->retranstimer) {
					if (ctrl->debug & PRI_DEBUG_Q931_STATE) {
						pri_message(ctrl, "Start T309 for call cref=%d on channel %d\n",
							call->cr, call->channelno);
					}
					call->retranstimer = pri_schedule_event(ctrl,
						ctrl->timers[PRI_TIMER_T309], pri_dl_down_timeout, call);
				}
				break;
			case Q931_CALL_STATE_NULL:
				break;
			default:
				/*
				 * For a call that is not in Active state, schedule internal
				 * clearing of the call 'ASAP' (delay 0).
				 *
				 * NOTE: We are killing NFAS calls that are not connected yet
				 * because there are likely messages in flight when this link
				 * went down that could leave the call in an unknown/stuck state.
				 */
				if (ctrl->debug & PRI_DEBUG_Q931_STATE) {
					pri_message(ctrl,
						"Cancel call cref=%d on channel %d in state %d (%s)\n",
						call->cr, call->channelno, call->ourcallstate,
						q931_call_state_str(call->ourcallstate));
				}
				if (cur->outboundbroadcast) {
					/* Simply destroy non-winning subcalls. */
					q931_destroycall(ctrl, call);
					continue;
				}
				pri_schedule_del(ctrl, call->retranstimer);
				call->retranstimer = pri_schedule_event(ctrl, 0, pri_dl_down_cancelcall,
					call);
				break;
			}
		}
		break;
	case Q931_DL_EVENT_DL_ESTABLISH_IND:
	case Q931_DL_EVENT_DL_ESTABLISH_CONFIRM:
		for (cur = *ctrl->callpool; cur; cur = cur->next) {
			if (!(cur->cr & ~Q931_CALL_REFERENCE_FLAG)) {
				/* Don't do anything on the global call reference call record. */
				continue;
			}
			if (cur->outboundbroadcast) {
				/* Does this master call have a subcall on the link that came up? */
				call = NULL;
				for (idx = 0; idx < ARRAY_LEN(cur->subcalls); ++idx) {
					if (cur->subcalls[idx] && cur->subcalls[idx]->link == link) {
						/* This subcall is on the link that came up. */
						call = cur->subcalls[idx];
						break;
					}
				}
				if (!call) {
					/* No subcall is on the link that came up. */
					continue;
				}
			} else if (cur->link != link) {
				/* This call is not on the link that came up. */
				continue;
			} else {
				call = cur;
			}
			switch (call->ourcallstate) {
			case Q931_CALL_STATE_ACTIVE:
				/* NOTE: Only a winning subcall can get to the active state. */
				if (pri_schedule_check(ctrl, call->retranstimer, pri_dl_down_timeout, call)) {
					if (ctrl->debug & PRI_DEBUG_Q931_STATE) {
						pri_message(ctrl, "Stop T309 for call cref=%d on channel %d\n",
							call->cr, call->channelno);
					}
					pri_schedule_del(ctrl, call->retranstimer);
					call->retranstimer = 0;
				}
				q931_status(ctrl, call, PRI_CAUSE_NORMAL_UNSPECIFIED);
				break;
			case Q931_CALL_STATE_NULL:
			case Q931_CALL_STATE_DISCONNECT_REQUEST:
			case Q931_CALL_STATE_DISCONNECT_INDICATION:
			case Q931_CALL_STATE_RELEASE_REQUEST:
				break;
			default:
				if (event == Q931_DL_EVENT_DL_ESTABLISH_CONFIRM) {
					/*
					 * Lets not send a STATUS message for this call as we
					 * requested the link to be established as a likely
					 * result of this call.
					 */
					break;
				}
				/*
				 * The STATUS message sent here is not required by Q.931,
				 * but it may help anyway.
				 * This looks like a new call started while the link was down.
				 */
				q931_status(ctrl, call, PRI_CAUSE_NORMAL_UNSPECIFIED);
				break;
			}
		}
		break;
	default:
		pri_message(ctrl, DBGHEAD "unexpected event %d.\n", DBGINFO, event);
		break;
	}
}

int q931_call_getcrv(struct pri *ctrl, q931_call *call, int *callmode)
{
	if (callmode)
		*callmode = call->cr & 0x7;
	return ((call->cr & 0x7fff) >> 3);
}

int q931_call_setcrv(struct pri *ctrl, q931_call *call, int crv, int callmode)
{
	/* Do not allow changing the dummy call reference */
	if (!q931_is_dummy_call(call)) {
		call->cr = (crv << 3) & 0x7fff;
		call->cr |= (callmode & 0x7);
	}
	return 0;
}
