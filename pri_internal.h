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
 
#ifndef _PRI_INTERNAL_H
#define _PRI_INTERNAL_H

#include <stddef.h>
#include <sys/time.h>
#include "pri_q921.h"
#include "pri_q931.h"

#define ARRAY_LEN(arr)	(sizeof(arr) / sizeof((arr)[0]))

#define DBGHEAD __FILE__ ":%d %s: "
#define DBGINFO __LINE__,__PRETTY_FUNCTION__

/* Forward declare some structs */
struct apdu_event;
struct pri_cc_record;

struct pri_sched {
	struct timeval when;
	void (*callback)(void *data);
	void *data;
};

/*
 * libpri needs to be able to allocate B channels to support Q.SIG path reservation.
 * Until that happens, path reservation is not possible.  Fortunately,
 * path reservation is optional with a fallback to what we can implement.
 */
//#define QSIG_PATH_RESERVATION_SUPPORT	1

/*! Maximum number of facility ie's to handle per incoming message. */
#define MAX_FACILITY_IES	8

/*! Maximum length of sent display text string.  (No null terminator.) */
#define MAX_DISPLAY_TEXT	80

/*! Accumulated pri_message() line until a '\n' is seen on the end. */
struct pri_msg_line {
	/*! Accumulated buffer used. */
	unsigned length;
	/*! Accumulated pri_message() contents. */
	char str[2048];
};

/*! \brief D channel controller structure */
struct pri {
	int fd;				/* File descriptor for D-Channel */
	pri_io_cb read_func;		/* Read data callback */
	pri_io_cb write_func;		/* Write data callback */
	void *userdata;
	/*! Accumulated pri_message() line. (Valid in master record only) */
	struct pri_msg_line *msg_line;
	/*! NFAS master/primary channel if appropriate */
	struct pri *master;
	/*! Next NFAS slaved D channel if appropriate */
	struct pri *slave;
	struct {
		/*! Dynamically allocated array of timers that can grow as needed. */
		struct pri_sched *timer;
		/*! Numer of timer slots in the allocated array of timers. */
		unsigned num_slots;
		/*! Maximum timer slots currently needed. */
		unsigned max_used;
		/*! First timer id in this timer pool. */
		unsigned first_id;
	} sched;
	int debug;			/* Debug stuff */
	int state;			/* State of D-channel */
	int switchtype;		/* Switch type */
	int nsf;		/* Network-Specific Facility (if any) */
	int localtype;		/* Local network type (unknown, network, cpe) */
	int remotetype;		/* Remote network type (unknown, network, cpe) */

	int protodisc;	/* Layer 3 protocol discriminator */

	unsigned int nfas:1;/* TRUE if this D channel is involved with an NFAS group */
	unsigned int bri:1;
	unsigned int acceptinbanddisconnect:1;	/* Should we allow inband progress after DISCONNECT? */
	unsigned int sendfacility:1;
	unsigned int overlapdial:1;/* TRUE if we do overlap dialing */
	unsigned int chan_mapping_logical:1;/* TRUE if do not skip channel 16 (Q.SIG) */
	unsigned int service_message_support:1;/* TRUE if upper layer supports SERVICE messages */
	unsigned int hold_support:1;/* TRUE if upper layer supports call hold. */
	unsigned int deflection_support:1;/* TRUE if upper layer supports call deflection/rerouting. */
	unsigned int hangup_fix_enabled:1;/* TRUE if should follow Q.931 Section 5.3.2 instead of blindly sending RELEASE_COMPLETE for certain causes */
	unsigned int cc_support:1;/* TRUE if upper layer supports call completion. */
	unsigned int transfer_support:1;/* TRUE if the upper layer supports ECT */
	unsigned int aoc_support:1;/* TRUE if can send AOC events to the upper layer. */
	unsigned int manual_connect_ack:1;/* TRUE if the CONNECT_ACKNOWLEDGE is sent with API call */
	unsigned int mcid_support:1;/* TRUE if the upper layer supports MCID */

	/*! Layer 2 link control for D channel. */
	struct q921_link link;
	/*! Layer 2 persistence option. */
	enum pri_layer2_persistence l2_persistence;
	/*! T201 TEI Identity Check timer. */
	int t201_timer;
	/*! Number of times T201 has expired. */
	int t201_expirycnt;
	
	int cref;			/* Next call reference value */

	/* All ISDN Timer values */
	int timers[PRI_MAX_TIMERS];

	/* Used by scheduler */
	int schedev;
	pri_event ev;		/* Static event thingy */
	/*! Subcommands for static event thingy. */
	struct pri_subcommands subcmds;
	
	/* Q.931 calls */
	struct q931_call **callpool;
	struct q931_call *localpool;

	/* q921/q931 packet counters */
	unsigned int q921_txcount;
	unsigned int q921_rxcount;
	unsigned int q931_txcount;
	unsigned int q931_rxcount;

	short last_invoke;	/* Last ROSE invoke ID (Valid in master record only) */

	/*! Call completion (Valid in master record only) */
	struct {
		/*! Active CC records */
		struct pri_cc_record *pool;
		/*! Last CC record id allocated. */
		unsigned short last_record_id;
		/*! Last CC PTMP reference id allocated. (0-127) */
		unsigned char last_reference_id;
		/*! Last CC PTMP linkage id allocated. (0-127) */
		unsigned char last_linkage_id;
		/*! Configured CC options. */
		struct {
			/*! PTMP recall mode: globalRecall(0), specificRecall(1) */
			unsigned char recall_mode;
			/*! Q.SIG Request signaling link retention: release(0), retain(1), do-not-care(2) */
			unsigned char signaling_retention_req;
			/*! Q.SIG Response request signaling link retention: release(0), retain(1) */
			unsigned char signaling_retention_rsp;
#if defined(QSIG_PATH_RESERVATION_SUPPORT)
			/*! Q.SIG TRUE if response request can support path reservation. */
			unsigned char allow_path_reservation;
#endif	/* defined(QSIG_PATH_RESERVATION_SUPPORT) */
		} option;
	} cc;

	/*! For delayed processing of facility ie's. */
	struct {
		/*! Array of facility ie locations in the current received message. */
		q931_ie *ie[MAX_FACILITY_IES];
		/*! Codeset facility ie found within. */
		unsigned char codeset[MAX_FACILITY_IES];
		/*! Number of facility ie's in the array from the current received message. */
		unsigned char count;
	} facility;
	/*! Display text policy handling options. */
	struct {
		/*! Send display text policy option flags. */
		unsigned long send;
		/*! Receive display text policy option flags. */
		unsigned long receive;
	} display_flags;
	/*! Configured date/time ie send policy option. */
	int date_time_send;
};

/*! \brief Maximum name length plus null terminator (From ECMA-164) */
#define PRI_MAX_NAME_LEN		(50 + 1)

/*! \brief Q.SIG name information. */
struct q931_party_name {
	/*! \brief TRUE if name data is valid */
	unsigned char valid;
	/*!
	 * \brief Q.931 presentation-indicator encoded field
	 * \note Must tollerate the Q.931 screening-indicator field values being present.
	 */
	unsigned char presentation;
	/*!
	 * \brief Character set the name is using.
	 * \details
	 * unknown(0),
	 * iso8859-1(1),
	 * enum-value-withdrawn-by-ITU-T(2)
	 * iso8859-2(3),
	 * iso8859-3(4),
	 * iso8859-4(5),
	 * iso8859-5(6),
	 * iso8859-7(7),
	 * iso10646-BmpString(8),
	 * iso10646-utf-8String(9)
	 */
	unsigned char char_set;
	/*! \brief Name data with null terminator. */
	char str[PRI_MAX_NAME_LEN];
};

/*! \brief Maximum phone number (address) length plus null terminator */
#define PRI_MAX_NUMBER_LEN		(31 + 1)

struct q931_party_number {
	/*! \brief TRUE if number data is valid */
	unsigned char valid;
	/*! \brief Q.931 presentation-indicator and screening-indicator encoded fields */
	unsigned char presentation;
	/*! \brief Q.931 Type-Of-Number and numbering-plan encoded fields */
	unsigned char plan;
	/*! \brief Number data with terminator. */
	char str[PRI_MAX_NUMBER_LEN];
};

/*! \brief Maximum subaddress length plus null terminator */
#define PRI_MAX_SUBADDRESS_LEN	(20 + 1)

struct q931_party_subaddress {
	/*! \brief TRUE if the subaddress information is valid/present */
	unsigned char valid;
	/*!
	 * \brief Subaddress type.
	 * \details
	 * nsap(0),
	 * user_specified(2)
	 */
	unsigned char type;
	/*!
	 * \brief TRUE if odd number of address signals
	 * \note The odd/even indicator is used when the type of subaddress is
	 * user_specified and the coding is BCD.
	 */
	unsigned char odd_even_indicator;
	/*! \brief Length of the subaddress data */
	unsigned char length;
	/*!
	 * \brief Subaddress data with null terminator.
	 * \note The null terminator is a convenience only since the data could be
	 * BCD/binary and thus have a null byte as part of the contents.
	 */
	unsigned char data[PRI_MAX_SUBADDRESS_LEN];
};

struct q931_party_address {
	/*! \brief Subscriber phone number */
	struct q931_party_number number;
	/*! \brief Subscriber subaddress */
	struct q931_party_subaddress subaddress;
};

/*! \brief Information needed to identify an endpoint in a call. */
struct q931_party_id {
	/*! \brief Subscriber name */
	struct q931_party_name name;
	/*! \brief Subscriber phone number */
	struct q931_party_number number;
	/*! \brief Subscriber subaddress */
	struct q931_party_subaddress subaddress;
};

enum Q931_REDIRECTING_STATE {
	/*!
	 * \details
	 * CDO-Idle/CDF-Inv-Idle
	 */
	Q931_REDIRECTING_STATE_IDLE,
	/*!
	 * \details
	 * CDF-Inv-Wait - A DivLeg2 has been received and
	 * we are waiting for valid presentation restriction information to send.
	 */
	Q931_REDIRECTING_STATE_PENDING_TX_DIV_LEG_3,
	/*!
	 * \details
	 * CDO-Divert - A DivLeg1 has been received and
	 * we are waiting for the presentation restriction information to come in.
	 */
	Q931_REDIRECTING_STATE_EXPECTING_RX_DIV_LEG_3,
};

/*!
 * \brief Do not increment above this count.
 * \details
 * It is not our responsibility to enforce the maximum number of redirects.
 * However, we cannot allow an increment past this number without breaking things.
 * Besides, more than 255 redirects is probably not a good thing.
 */
#define PRI_MAX_REDIRECTS	0xFF

/*! \brief Redirecting information struct */
struct q931_party_redirecting {
	enum Q931_REDIRECTING_STATE state;
	/*! \brief Who is redirecting the call (Sent to the party the call is redirected toward) */
	struct q931_party_id from;
	/*! \brief Call is redirecting to a new party (Sent to the caller) */
	struct q931_party_id to;
	/*! Originally called party (in cases of multiple redirects) */
	struct q931_party_id orig_called;
	/*!
	 * \brief Number of times the call was redirected
	 * \note The call is being redirected if the count is non-zero.
	 */
	unsigned char count;
	/*! Original reason for redirect (in cases of multiple redirects) */
	unsigned char orig_reason;
	/*! \brief Redirection reasons */
	unsigned char reason;
};

/*! \brief New call setup parameter structure */
struct pri_sr {
	int transmode;
	int channel;
	int exclusive;
	int nonisdn;
	struct q931_party_redirecting redirecting;
	struct q931_party_id caller;
	struct q931_party_address called;
	int userl1;
	int numcomplete;
	int cis_call;
	int cis_auto_disconnect;
	const char *useruserinfo;
	const char *keypad_digits;
	int transferable;
	int reversecharge;
	int aoc_charging_request;
};

#define Q931_MAX_TEI	8

/*! \brief Incoming call transfer states. */
enum INCOMING_CT_STATE {
	/*!
	 * \details
	 * Incoming call transfer is not active.
	 */
	INCOMING_CT_STATE_IDLE,
	/*!
	 * \details
	 * We have seen an incoming CallTransferComplete(alerting)
	 * so we are waiting for the expected CallTransferActive
	 * before updating the connected line about the remote party id.
	 */
	INCOMING_CT_STATE_EXPECT_CT_ACTIVE,
	/*!
	 * \details
	 * A call transfer message came in that updated the remote party id
	 * that we need to post a connected line update.
	 */
	INCOMING_CT_STATE_POST_CONNECTED_LINE
};

/*! Call hold supplementary states. */
enum Q931_HOLD_STATE {
	/*! \brief No call hold activity. */
	Q931_HOLD_STATE_IDLE,
	/*! \brief Request made to hold call. */
	Q931_HOLD_STATE_HOLD_REQ,
	/*! \brief Request received to hold call. */
	Q931_HOLD_STATE_HOLD_IND,
	/*! \brief Call is held. */
	Q931_HOLD_STATE_CALL_HELD,
	/*! \brief Request made to retrieve call. */
	Q931_HOLD_STATE_RETRIEVE_REQ,
	/*! \brief Request received to retrieve call. */
	Q931_HOLD_STATE_RETRIEVE_IND,
};

/* Only save the first of each BC, HLC, and LLC from the initial SETUP. */
#define CC_SAVED_IE_BC	(1 << 0)	/*!< BC has already been saved. */
#define CC_SAVED_IE_HLC	(1 << 1)	/*!< HLC has already been saved. */
#define CC_SAVED_IE_LLC	(1 << 2)	/*!< LLC has already been saved. */

/*! Saved ie contents for BC, HLC, and LLC. (Only the first of each is saved.) */
struct q931_saved_ie_contents {
	/*! Length of saved ie contents. */
	unsigned char length;
	/*! Saved ie contents data. */
	unsigned char data[
		/* Bearer Capability has a max length of 12. */
		12
		/* High Layer Compatibility has a max length of 5. */
		+ 5
		/* Low Layer Compatibility has a max length of 18. */
		+ 18
		/* Room for null terminator just in case. */
		+ 1];
};

/*! Digested BC parameters. */
struct decoded_bc {
	int transcapability;
	int transmoderate;
	int transmultiple;
	int userl1;
	int userl2;
	int userl3;
	int rateadaption;
};

/* q931_call datastructure */
struct q931_call {
	struct pri *pri;	/* D channel controller (master) */
	struct q921_link *link;	/* Q.921 link associated with this call. */
	struct q931_call *next;
	int cr;				/* Call Reference */
	/* Slotmap specified (bitmap of channels 31/24-1) (Channel Identifier IE) (-1 means not specified) */
	int slotmap;
	/* An explicit channel (Channel Identifier IE) (-1 means not specified) */
	int channelno;
	/* An explicit DS1 (-1 means not specified) */
	int ds1no;
	/* Whether or not the ds1 is explicitly identified or implicit.  If implicit
	   the bchan is on the same span as the current active dchan (NFAS) */
	int ds1explicit;
	/* Channel flags (0 means none retrieved) */
	int chanflags;
	
	int alive;			/* Whether or not the call is alive */
	int acked;			/* Whether setup has been acked or not */
	int sendhangupack;	/* Whether or not to send a hangup ack */
	int proc;			/* Whether we've sent a call proceeding / alerting */
	
	int ri;				/* Restart Indicator (Restart Indicator IE) */

	/*! Bearer Capability */
	struct decoded_bc bc;

	/*!
	 * \brief TRUE if the call is a Call Independent Signalling connection.
	 * \note The call has no B channel associated with it. (Just signalling)
	 */
	int cis_call;
	/*!
	 * \brief TRUE if we have recognized a use for this CIS call.
	 * \note An incoming CIS call will be immediately disconnected if not set.
	 * This is a safeguard against unhandled incoming CIS calls to protect the
	 * call reference pool.
	 */
	int cis_recognized;
	/*! \brief TRUE if we will auto disconnect the cis_call we originated. */
	int cis_auto_disconnect;

	int progcode;			/* Progress coding */
	int progloc;			/* Progress Location */	
	int progress;			/* Progress indicator */
	int progressmask;		/* Progress Indicator bitmask */
	
	int notify;				/* Notification indicator. */
	
	int causecode;			/* Cause Coding */
	int causeloc;			/* Cause Location */
	int cause;				/* Cause of clearing */
	
	enum Q931_CALL_STATE peercallstate;	/* Call state of peer as reported */
	enum Q931_CALL_STATE ourcallstate;	/* Our call state */
	enum Q931_CALL_STATE sugcallstate;	/* Status call state */

	int ani2;               /* ANI II */

	/*! Buffer for digits that come in KEYPAD_FACILITY */
	char keypad_digits[32 + 1];

	/*! Current dialed digits to be sent or just received. */
	char overlap_digits[PRI_MAX_NUMBER_LEN];

	/*!
	 * \brief Local party ID
	 * \details
	 * The Caller-ID and connected-line ID are just roles the local and remote party
	 * play while a call is being established.  Which roll depends upon the direction
	 * of the call.
	 * Outgoing party info is to identify the local party to the other end.
	 *    (Caller-ID for originated or connected-line for answered calls.)
	 * Incoming party info is to identify the remote party to us.
	 *    (Caller-ID for answered or connected-line for originated calls.)
	 */
	struct q931_party_id local_id;
	/*!
	 * \brief Remote party ID
	 * \details
	 * The Caller-ID and connected-line ID are just roles the local and remote party
	 * play while a call is being established.  Which roll depends upon the direction
	 * of the call.
	 * Outgoing party info is to identify the local party to the other end.
	 *    (Caller-ID for originated or connected-line for answered calls.)
	 * Incoming party info is to identify the remote party to us.
	 *    (Caller-ID for answered or connected-line for originated calls.)
	 */
	struct q931_party_id remote_id;
	/*! \brief Automatic Number Identification (ANI) */
	struct q931_party_number ani;

	/*!
	 * \brief Staging place for the Q.931 redirection number ie.
	 * \note
	 * The number could be the remote_id.number or redirecting.to.number
	 * depending upon the notification indicator.
	 */
	struct q931_party_number redirection_number;

	/*!
	 * \brief Called party address.
	 * \note The called.number.str is the accumulated overlap dial digits
	 * and enbloc digits.
	 * \note The called.number.presentation value is not used.
	 */
	struct q931_party_address called;
	int nonisdn;
	int complete;			/* no more digits coming */
	int newcall;			/* if the received message has a new call reference value */

	int retranstimer;		/* Timer for retransmitting DISC */
	int t308_timedout;		/* Whether t308 timed out once */

	struct q931_party_redirecting redirecting;

	/*! \brief Incoming call transfer state. */
	enum INCOMING_CT_STATE incoming_ct_state;
	/*! Call hold supplementary state.  Valid on master call record only. */
	enum Q931_HOLD_STATE hold_state;
	/*! Call hold event timer.  Valid on master call record only. */
	int hold_timer;

	int deflection_in_progress;	/*!< CallDeflection for NT PTMP in progress. */
	/*! TRUE if the connected number ie was in the current received message. */
	int connected_number_in_message;
	/*! TRUE if the redirecting number ie was in the current received message. */
	int redirecting_number_in_message;

	int useruserprotocoldisc;
	char useruserinfo[256];
	
	long aoc_units;				/* Advice of Charge Units */

	struct apdu_event *apdus;	/* APDU queue for call */

	int transferable;			/* RLT call is transferable */
	unsigned int rlt_call_id;	/* RLT call id */

	/*! ETSI Explicit Call Transfer link id. */
	int link_id;
	/*! TRUE if link_id is valid. */
	int is_link_id_valid;

	/* Bridged call info */
	struct q931_call *bridged_call;        /* Pointer to other leg of bridged call (Used by Q.SIG when eliminating tromboned calls) */

	int changestatus;		/* SERVICE message changestatus */
	int reversecharge;		/* Reverse charging indication:
							   -1 - No reverse charging
							    1 - Reverse charging
							0,2-7 - Reserved for future use */
	int t303_timer;
	int t303_expirycnt;
	int t312_timer;
	int fake_clearing_timer;

	int hangupinitiated;
	/*! \brief TRUE if we broadcast this call's SETUP message. */
	int outboundbroadcast;
	/*! TRUE if the master call is processing a hangup.  Don't destroy it now. */
	int master_hanging_up;
	/*!
	 * \brief Master call controlling this call.
	 * \note Always valid.  Master and normal calls point to self.
	 */
	struct q931_call *master_call;

	/* These valid in master call only */
	struct q931_call *subcalls[Q931_MAX_TEI];
	int pri_winner;

	/* Call completion */
	struct {
		/*!
		 * \brief CC record associated with this call.
		 * \note
		 * CC signaling link or original call when cc-available indicated.
		 */
		struct pri_cc_record *record;
		/*! Original calling party. */
		struct q931_party_id party_a;
		/*! Saved BC, HLC, and LLC from initial SETUP */
		struct q931_saved_ie_contents saved_ie_contents;
		/*! Only save the first of each BC, HLC, and LLC from the initial SETUP. */
		unsigned char saved_ie_flags;
		/*! TRUE if call needs to be hung up. */
		unsigned char hangup_call;
		/*! TRUE if we originated this call. */
		unsigned char originated;
		/*! TRUE if outgoing call was already redirected. */
		unsigned char initially_redirected;
	} cc;

	/*! Display text ie contents. */
	struct {
		/*! Display ie text.  NULL if not present or consumed as remote name. */
		const unsigned char *text;
		/*! Full IE code of received display text */
		int full_ie;
		/*! Length of display text. */
		unsigned char length;
		/*!
		 * \brief Character set the text is using.
		 * \details
		 * unknown(0),
		 * iso8859-1(1),
		 * enum-value-withdrawn-by-ITU-T(2)
		 * iso8859-2(3),
		 * iso8859-3(4),
		 * iso8859-4(5),
		 * iso8859-5(6),
		 * iso8859-7(7),
		 * iso10646-BmpString(8),
		 * iso10646-utf-8String(9)
		 */
		unsigned char char_set;
	} display;

	/*! AOC charge requesting on Setup */
	int aoc_charging_request;

	/*! TRUE if the slotmap is E1 (32 bits). */
	unsigned int slotmap_size:1;
	/*! TRUE if need to see the channel id ie in first response to SETUP. */
	unsigned int channel_id_ie_mandatory:1;

	/*! Control the RESTART reception to the upper layer. */
	struct {
		/*! Timer ID of RESTART notification events to upper layer. */
		int timer;
		/*! Current RESTART notification index. */
		int idx;
		/*! Number of channels in the channel ID list. */
		int count;
		/*! Channel ID list */
		char chan_no[32];
	} restart;
	/*! Control the RESTART retransmissions. */
	struct {
		/*! T316 RESTART retransmit timer. */
		int t316_timer;
		/*! Number of times remaining that RESTART can be transmitted. */
		int remain;
		/*! Encoded RESTART channel id. */
		int channel;
	} restart_tx;
	/*! Message retransmission cache */
	struct {
		/*! Cache status: set valid as soon as filled in */
		int valid;
		/*! Sent message type */
		int msgtype;
		/*! User-user information */
		char useruserinfo[256];
	} retrans_cache;
};

enum CC_STATES {
	/*! CC is not active. */
	CC_STATE_IDLE,
	// /*! CC has recorded call information in anticipation of CC availability. */
	// CC_STATE_RECORD_RETENTION,
	/*! CC is available and waiting on ALERTING or DISCONNECT to go out. */
	CC_STATE_PENDING_AVAILABLE,
	/*! CC is available and waiting on possible CC request. */
	CC_STATE_AVAILABLE,
	/*! CC is requested to be activated and waiting on party B to acknowledge. */
	CC_STATE_REQUESTED,
	/*! CC is activated and waiting for party B to become available. */
	CC_STATE_ACTIVATED,
	/*! CC party B is available and waiting for status of party A. */
	CC_STATE_B_AVAILABLE,
	/*! CC is suspended because party A is not available. (Monitor party A.) */
	CC_STATE_SUSPENDED,
	/*! CC is waiting for party A to initiate CC callback. */
	CC_STATE_WAIT_CALLBACK,
	/*! CC callback in progress. */
	CC_STATE_CALLBACK,
	/*! CC is waiting for signaling link to be cleared before destruction. */
	CC_STATE_WAIT_DESTRUCTION,

	/*! Number of CC states.  Must be last in enum. */
	CC_STATE_NUM
};

enum CC_EVENTS {
	/*! CC is available for the current call. */
	CC_EVENT_AVAILABLE,
	/*! Requesting CC activation. */
	CC_EVENT_CC_REQUEST,
	/*! Requesting CC activation accepted. */
	CC_EVENT_CC_REQUEST_ACCEPT,
	/*! Requesting CC activation failed (error/reject received). */
	CC_EVENT_CC_REQUEST_FAIL,
	/*! CC party B is available, party A is considered free. */
	CC_EVENT_REMOTE_USER_FREE,
	/*! CC party B is available, party A is busy or CCBS busy. */
	CC_EVENT_B_FREE,
	/*! Someone else responded to the CC recall. */
	CC_EVENT_STOP_ALERTING,
	/*! CC poll/prompt for party A status. */
	CC_EVENT_A_STATUS,
	/*! CC party A is free/available for recall. */
	CC_EVENT_A_FREE,
	/*! CC party A is busy/not-available for recall. */
	CC_EVENT_A_BUSY,
	/*! Suspend monitoring party B because party A is busy. */
	CC_EVENT_SUSPEND,
	/*! Resume monitoring party B because party A is now available. */
	CC_EVENT_RESUME,
	/*! This is the CC recall call attempt. */
	CC_EVENT_RECALL,
	/*! Link request to cancel/deactivate CC received. */
	CC_EVENT_LINK_CANCEL,
	/*! Tear down CC request from upper layer. */
	CC_EVENT_CANCEL,
	/*! Abnormal clearing of original call.  (T309 processing/T309 timeout/TEI removal) */
	CC_EVENT_INTERNAL_CLEARING,
	/*! Received message indicating tear down of CC signaling link completed. */
	CC_EVENT_SIGNALING_GONE,
	/*! Delayed hangup request for the signaling link to allow subcmd events to be passed up. */
	CC_EVENT_HANGUP_SIGNALING,
	/*! Sent ALERTING message. */
	CC_EVENT_MSG_ALERTING,
	/*! Sent DISCONNECT message. */
	CC_EVENT_MSG_DISCONNECT,
	/*! Sent RELEASE message. */
	CC_EVENT_MSG_RELEASE,
	/*! Sent RELEASE_COMPLETE message. */
	CC_EVENT_MSG_RELEASE_COMPLETE,
	/*! T_ACTIVATE timer timed out. */
	CC_EVENT_TIMEOUT_T_ACTIVATE,
#if 0
	/*! T_DEACTIVATE timer timed out. */
	CC_EVENT_TIMEOUT_T_DEACTIVATE,
	/*! T_INTERROGATE timer timed out. */
	CC_EVENT_TIMEOUT_T_INTERROGATE,
#endif
	/*! T_RETENTION timer timed out. */
	CC_EVENT_TIMEOUT_T_RETENTION,
	/*! T-STATUS timer equivalent for CC user A status timed out. */
	CC_EVENT_TIMEOUT_T_CCBS1,
	/*! Timeout for valid party A status. */
	CC_EVENT_TIMEOUT_EXTENDED_T_CCBS1,
	/*! Max time the CCBS/CCNR service will be active. */
	CC_EVENT_TIMEOUT_T_SUPERVISION,
	/*! Max time to wait for user A to respond to user B availability. */
	CC_EVENT_TIMEOUT_T_RECALL,
};

enum CC_PARTY_A_AVAILABILITY {
	CC_PARTY_A_AVAILABILITY_INVALID,
	CC_PARTY_A_AVAILABILITY_BUSY,
	CC_PARTY_A_AVAILABILITY_FREE,
};

/* Invalid PTMP call completion reference and linkage id value. */
#define CC_PTMP_INVALID_ID  0xFF

/*! \brief Call-completion record */
struct pri_cc_record {
	/*! Next call-completion record in the list */
	struct pri_cc_record *next;
	/*! D channel control structure. */
	struct pri *ctrl;
	/*! Original call that is offered CC availability. (NULL if no longer exists.) */
	struct q931_call *original_call;
	/*!
	 * \brief Associated signaling link. (NULL if not established.)
	 * \note
	 * PTMP - Broadcast dummy call reference call.
	 * (If needed, the TE side could use this pointer to locate its specific
	 * dummy call reference call.)
	 * \note
	 * PTP - REGISTER signaling link.
	 * \note
	 * Q.SIG - SETUP signaling link.
	 */
	struct q931_call *signaling;
	/*! Call-completion record id (0 - 65535) */
	long record_id;
	/*! Call-completion state */
	enum CC_STATES state;
	/*! Original calling party. */
	struct q931_party_id party_a;
	/*! Original called party. */
	struct q931_party_address party_b;
	/*! Saved BC, HLC, and LLC from initial SETUP */
	struct q931_saved_ie_contents saved_ie_contents;
	/*! Saved decoded BC */
	struct decoded_bc bc;

	/*! FSM parameters. */
	union {
		/*! PTMP FSM parameters. */
		struct {
			/*! Extended T_CCBS1 timer id for CCBSStatusRequest handling. */
			int extended_t_ccbs1;
			/*! Invoke id for the CCBSStatusRequest message to find if T_CCBS1 still running. */
			int t_ccbs1_invoke_id;
			/*! Number of times party A status request got no responses. */
			int party_a_status_count;
			/*! Accumulating party A availability status */
			enum CC_PARTY_A_AVAILABILITY party_a_status_acc;
		} ptmp;
		/*! PTP FSM parameters. */
		struct {
		} ptp;
		struct {
			/*! Q.931 message type the current message event came in on. */
			int msgtype;
		} qsig;
	} fsm;
	/*! Received message parameters of interest. */
	union {
		/*! cc-request error/reject response */
		struct {
			/*! enum APDU_CALLBACK_REASON reason */
			int reason;
			/*! MSG_ERROR/MSG_REJECT fail code. */
			int code;
		} cc_req_rsp;
	} msg;
	/*! Party A availability status */
	enum CC_PARTY_A_AVAILABILITY party_a_status;
	/*! Indirect timer id to abort indirect action events. */
	int t_indirect;
	/*!
	 * \brief PTMP T_RETENTION timer id.
	 * \note
	 * This timer is used by all CC agents to implement
	 * the Asterisk CC core offer timer.
	 */
	int t_retention;
	/*!
	 * \brief CC service supervision timer.
	 *
	 * \details
	 * This timer is one of the following timer id's depending upon
	 * switch type and CC mode:
	 * PTMP - T_CCBS2/T_CCNR2,
	 * PTP - T_CCBS5/T_CCNR5/T_CCBS6/T_CCNR6,
	 * Q.SIG - QSIG_CCBS_T2/QSIG_CCNR_T2
	 */
	int t_supervision;
	/*!
	 * \brief Party A response to B availability for recall timer.
	 * \details
	 * This timer is one of the following timer id's:
	 * PTMP - T_CCBS3
	 * Q.SIG - QSIG_CC_T3
	 */
	int t_recall;
	/*! Invoke id for the cc-request message to find if T_ACTIVATE/QSIG_CC_T1 still running. */
	int t_activate_invoke_id;
	/*! Pending response information. */
	struct {
		/*!
		 * \brief Send response on this signaling link.
		 * \note Used by PTMP for CCBSRequest/CCNRRequest/CCBSCall responses.
		 * \note Used by Q.SIG for ccRingout responses.
		 */
		struct q931_call *signaling;
		/*! Invoke operation code */
		int invoke_operation;
		/*! Invoke id to use in the pending response. */
		short invoke_id;
	} response;

	/*! TRUE if the call-completion FSM has completed and this record needs to be destroyed. */
	unsigned char fsm_complete;
	/*! TRUE if we are a call completion agent. */
	unsigned char is_agent;
	/*! TRUE if active cc mode is CCNR. */
	unsigned char is_ccnr;
	/*! PTMP pre-activation reference id. (0-127) */
	unsigned char call_linkage_id;
	/*! PTMP active CCBS reference id. (0-127) */
	unsigned char ccbs_reference_id;
	/*! Negotiated options */
	struct {
		/*! PTMP recall mode: globalRecall(0), specificRecall(1) */
		unsigned char recall_mode;
		/*! TRUE if negotiated for Q.SIG signaling link to be retained. */
		unsigned char retain_signaling_link;
#if defined(QSIG_PATH_RESERVATION_SUPPORT)
		/*! Q.SIG TRUE if can do path reservation. */
		unsigned char do_path_reservation;
#endif	/* defined(QSIG_PATH_RESERVATION_SUPPORT) */
	} option;
};

/*! D channel control structure with associated dummy call reference record. */
struct d_ctrl_dummy {
	/*! D channel control structure. Must be first in the structure. */
	struct pri ctrl;
	/*! Dummy call reference call record. */
	struct q931_call dummy_call;
};

/*! Layer 2 link control structure with associated dummy call reference record. */
struct link_dummy {
	/*! Layer 2 control structure. Must be first in the structure. */
	struct q921_link link;
	/*! Dummy call reference call record. */
	struct q931_call dummy_call;
};

/*!
 * \brief Check if the given call ptr is valid and gripe if not.
 *
 * \param ctrl D channel controller.
 * \param call Q.931 call leg.
 *
 * \retval TRUE if call ptr is valid.
 * \retval FALSE if call ptr is invalid.
 */
#define pri_is_call_valid(ctrl, call)	\
	q931_is_call_valid_gripe(ctrl, call, __PRETTY_FUNCTION__, __LINE__)

int q931_is_call_valid(struct pri *ctrl, struct q931_call *call);
int q931_is_call_valid_gripe(struct pri *ctrl, struct q931_call *call, const char *func_name, unsigned long func_line);

unsigned pri_schedule_event(struct pri *ctrl, int ms, void (*function)(void *data), void *data);

extern pri_event *pri_schedule_run(struct pri *pri);

void pri_schedule_del(struct pri *ctrl, unsigned id);
int pri_schedule_check(struct pri *ctrl, unsigned id, void (*function)(void *data), void *data);

extern pri_event *pri_mkerror(struct pri *pri, char *errstr);

void pri_message(struct pri *ctrl, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void pri_error(struct pri *ctrl, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

void libpri_copy_string(char *dst, const char *src, size_t size);

void pri_link_destroy(struct q921_link *link);
struct q921_link *pri_link_new(struct pri *ctrl, int sapi, int tei);

void q931_init_call_record(struct q921_link *link, struct q931_call *call, int cr);

void pri_sr_init(struct pri_sr *req);

void q931_party_name_init(struct q931_party_name *name);
void q931_party_number_init(struct q931_party_number *number);
void q931_party_subaddress_init(struct q931_party_subaddress *subaddr);
void q931_party_address_init(struct q931_party_address *address);
void q931_party_id_init(struct q931_party_id *id);
void q931_party_redirecting_init(struct q931_party_redirecting *redirecting);

static inline void q931_party_address_to_id(struct q931_party_id *id, const struct q931_party_address *address)
{
	id->number = address->number;
	id->subaddress = address->subaddress;
}

static inline void q931_party_id_to_address(struct q931_party_address *address, const struct q931_party_id *id)
{
	address->number = id->number;
	address->subaddress = id->subaddress;
}

int q931_party_name_cmp(const struct q931_party_name *left, const struct q931_party_name *right);
int q931_party_number_cmp(const struct q931_party_number *left, const struct q931_party_number *right);
int q931_party_subaddress_cmp(const struct q931_party_subaddress *left, const struct q931_party_subaddress *right);
int q931_party_address_cmp(const struct q931_party_address *left, const struct q931_party_address *right);
int q931_party_id_cmp(const struct q931_party_id *left, const struct q931_party_id *right);
int q931_party_id_cmp_address(const struct q931_party_id *left, const struct q931_party_id *right);

int q931_cmp_party_id_to_address(const struct q931_party_id *id, const struct q931_party_address *address);
void q931_party_id_copy_to_address(struct q931_party_address *address, const struct q931_party_id *id);

void q931_party_name_copy_to_pri(struct pri_party_name *pri_name, const struct q931_party_name *q931_name);
void q931_party_number_copy_to_pri(struct pri_party_number *pri_number, const struct q931_party_number *q931_number);
void q931_party_subaddress_copy_to_pri(struct pri_party_subaddress *pri_subaddress, const struct q931_party_subaddress *q931_subaddress);
void q931_party_address_copy_to_pri(struct pri_party_address *pri_address, const struct q931_party_address *q931_address);
void q931_party_id_copy_to_pri(struct pri_party_id *pri_id, const struct q931_party_id *q931_id);
void q931_party_redirecting_copy_to_pri(struct pri_party_redirecting *pri_redirecting, const struct q931_party_redirecting *q931_redirecting);

void pri_copy_party_name_to_q931(struct q931_party_name *q931_name, const struct pri_party_name *pri_name);
void pri_copy_party_number_to_q931(struct q931_party_number *q931_number, const struct pri_party_number *pri_number);
void pri_copy_party_subaddress_to_q931(struct q931_party_subaddress *q931_subaddress, const struct pri_party_subaddress *pri_subaddress);
void pri_copy_party_id_to_q931(struct q931_party_id *q931_id, const struct pri_party_id *pri_id);

void q931_party_id_fixup(const struct pri *ctrl, struct q931_party_id *id);
int q931_party_id_presentation(const struct q931_party_id *id);

int q931_display_name_get(struct q931_call *call, struct q931_party_name *name);
int q931_display_text(struct pri *ctrl, struct q931_call *call, const struct pri_subcmd_display_txt *display);

int q931_facility_display_name(struct pri *ctrl, struct q931_call *call, const struct q931_party_name *name);
int q931_facility_called(struct pri *ctrl, struct q931_call *call, const struct q931_party_id *called);

const char *q931_call_state_str(enum Q931_CALL_STATE callstate);
const char *msg2str(int msg);

int q931_get_subcall_count(struct q931_call *master);
struct q931_call *q931_find_winning_call(struct q931_call *call);
int q931_master_pass_event(struct pri *ctrl, struct q931_call *subcall, int msg_type);
struct pri_subcommand *q931_alloc_subcommand(struct pri *ctrl);

struct q931_call *q931_find_link_id_call(struct pri *ctrl, int link_id);
struct q931_call *q931_find_held_active_call(struct pri *ctrl, struct q931_call *held_call);

int q931_request_subaddress(struct pri *ctrl, struct q931_call *call, int notify, const struct q931_party_name *name, const struct q931_party_number *number);
int q931_subaddress_transfer(struct pri *ctrl, struct q931_call *call);
int q931_notify_redirection(struct pri *ctrl, struct q931_call *call, int notify, const struct q931_party_name *name, const struct q931_party_number *number);

struct pri_cc_record *pri_cc_find_by_reference(struct pri *ctrl, unsigned reference_id);
struct pri_cc_record *pri_cc_find_by_linkage(struct pri *ctrl, unsigned linkage_id);
struct pri_cc_record *pri_cc_find_by_addressing(struct pri *ctrl, const struct q931_party_address *party_a, const struct q931_party_address *party_b, unsigned length, const unsigned char *q931_ies);
struct pri_cc_record *pri_cc_new_record(struct pri *ctrl, q931_call *call);
void pri_cc_qsig_determine_available(struct pri *ctrl, q931_call *call);
const char *pri_cc_fsm_state_str(enum CC_STATES state);
const char *pri_cc_fsm_event_str(enum CC_EVENTS event);
int pri_cc_event(struct pri *ctrl, q931_call *call, struct pri_cc_record *cc_record, enum CC_EVENTS event);
int q931_cc_timeout(struct pri *ctrl, struct pri_cc_record *cc_record, enum CC_EVENTS event);
void q931_cc_indirect(struct pri *ctrl, struct pri_cc_record *cc_record, void (*func)(struct pri *ctrl, q931_call *call, struct pri_cc_record *cc_record));

/*!
 * \brief Get the NFAS master PRI control structure.
 *
 * \param ctrl D channel controller.
 *
 * \return NFAS master PRI control structure.
 */
static inline struct pri *PRI_NFAS_MASTER(struct pri *ctrl)
{
	if (ctrl->master) {
		ctrl = ctrl->master;
	}
	return ctrl;
}

/*!
 * \brief Determine if layer 2 is in BRI NT PTMP mode.
 *
 * \param ctrl D channel controller.
 *
 * \retval TRUE if in BRI NT PTMP mode.
 * \retval FALSE otherwise.
 */
static inline int BRI_NT_PTMP(const struct pri *ctrl)
{
	struct pri *my_ctrl = (struct pri *) ctrl;

	return my_ctrl->bri && my_ctrl->localtype == PRI_NETWORK
		&& my_ctrl->link.tei == Q921_TEI_GROUP;
}

/*!
 * \brief Determine if layer 2 is in BRI TE PTMP mode.
 *
 * \param ctrl D channel controller.
 *
 * \retval TRUE if in BRI TE PTMP mode.
 * \retval FALSE otherwise.
 */
static inline int BRI_TE_PTMP(const struct pri *ctrl)
{
	struct pri *my_ctrl = (struct pri *) ctrl;

	return my_ctrl->bri && my_ctrl->localtype == PRI_CPE
		&& my_ctrl->link.tei == Q921_TEI_GROUP;
}

/*!
 * \brief Determine if layer 2 is in NT mode.
 *
 * \param ctrl D channel controller.
 *
 * \retval TRUE if in NT mode.
 * \retval FALSE otherwise.
 */
static inline int NT_MODE(const struct pri *ctrl)
{
	struct pri *my_ctrl = (struct pri *) ctrl;

	return my_ctrl->localtype == PRI_NETWORK;
}

/*!
 * \brief Determine if layer 2 is in TE mode.
 *
 * \param ctrl D channel controller.
 *
 * \retval TRUE if in TE mode.
 * \retval FALSE otherwise.
 */
static inline int TE_MODE(const struct pri *ctrl)
{
	struct pri *my_ctrl = (struct pri *) ctrl;

	return my_ctrl->localtype == PRI_CPE;
}

/*!
 * \brief Determine if layer 2 is in PTP mode.
 *
 * \param ctrl D channel controller.
 *
 * \retval TRUE if in PTP mode.
 * \retval FALSE otherwise.
 */
static inline int PTP_MODE(const struct pri *ctrl)
{
	struct pri *my_ctrl = (struct pri *) ctrl;

	return my_ctrl->link.tei == Q921_TEI_PRI;
}

/*!
 * \brief Determine if layer 2 is in PTMP mode.
 *
 * \param ctrl D channel controller.
 *
 * \retval TRUE if in PTMP mode.
 * \retval FALSE otherwise.
 */
static inline int PTMP_MODE(const struct pri *ctrl)
{
	struct pri *my_ctrl = (struct pri *) ctrl;

	return my_ctrl->link.tei == Q921_TEI_GROUP;
}

#define Q931_DUMMY_CALL_REFERENCE	-1
#define Q931_CALL_REFERENCE_FLAG	0x8000	/* Identify which end allocted the CR. */

/*!
 * \brief Deterimine if the given call control pointer is a dummy call.
 *
 * \retval TRUE if given call is a dummy call.
 * \retval FALSE otherwise.
 */
static inline int q931_is_dummy_call(const struct q931_call *call)
{
	return (call->cr == Q931_DUMMY_CALL_REFERENCE) ? 1 : 0;
}

static inline short get_invokeid(struct pri *ctrl)
{
	return ++ctrl->last_invoke;
}

#endif
