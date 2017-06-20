/*
The MIT License (MIT)

Copyright (c) 2017 Eugene Zagidullin

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#ifndef BLYNK_H
#define BLYNK_H

#include <inttypes.h>
#include <stdarg.h>

#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "lwip/opt.h"

#if !LWIP_NETIF_LOOPBACK
#	error "LwIP loopback must be enabled"
#endif

#define BLYNK_MAX_PAYLOAD_LEN 512
#define BLYNK_MAX_ARGS 32
#define BLYNK_MAX_AWAITING 32
#define BLYNK_MAX_HANDLERS 8

typedef struct _blynk_options_t blynk_options_t;
typedef struct _blynk_client_t blynk_client_t;
typedef struct _blynk_message_t blynk_message_t;
typedef struct _blynk_state_evt_t blynk_state_evt_t;
typedef struct _blynk_state_data_t blynk_state_data_t;
typedef struct _blynk_private_t blynk_private_t;
typedef struct _blynk_awaiting_t blynk_awaiting_t;
typedef struct _blynk_handler_data_t blynk_handler_data_t;
typedef struct _blynk_arg_t blynk_arg_t;

enum {
	BLYNK_CMD_RESPONSE       = 0,
	BLYNK_CMD_REGISTER       = 1,
	BLYNK_CMD_LOGIN          = 2,
	BLYNK_CMD_SAVE_PROF      = 3,
	BLYNK_CMD_LOAD_PROF      = 4,
	BLYNK_CMD_GET_TOKEN      = 5,
	BLYNK_CMD_PING           = 6,
	BLYNK_CMD_ACTIVATE       = 7,
	BLYNK_CMD_DEACTIVATE     = 8,
	BLYNK_CMD_REFRESH        = 9,
	BLYNK_CMD_GET_GRAPH_DATA = 10,
	BLYNK_CMD_GET_GRAPH_DATA_RESPONSE = 11,

	BLYNK_CMD_TWEET          = 12,
	BLYNK_CMD_EMAIL          = 13,
	BLYNK_CMD_NOTIFY         = 14,
	BLYNK_CMD_BRIDGE         = 15,
	BLYNK_CMD_HARDWARE_SYNC  = 16,
	BLYNK_CMD_INTERNAL       = 17,
	BLYNK_CMD_SMS            = 18,
	BLYNK_CMD_PROPERTY       = 19,
	BLYNK_CMD_HARDWARE       = 20,

	BLYNK_CMD_CREATE_DASH    = 21,
	BLYNK_CMD_SAVE_DASH      = 22,
	BLYNK_CMD_DELETE_DASH    = 23,
	BLYNK_CMD_LOAD_PROF_GZ   = 24,
	BLYNK_CMD_SYNC           = 25,
	BLYNK_CMD_SHARING        = 26,
	BLYNK_CMD_ADD_PUSH_TOKEN = 27,

	//sharing commands
	BLYNK_CMD_GET_SHARED_DASH = 29,
	BLYNK_CMD_GET_SHARE_TOKEN = 30,
	BLYNK_CMD_REFRESH_SHARE_TOKEN = 31,
	BLYNK_CMD_SHARE_LOGIN     = 32,

	BLYNK_CMD_REDIRECT        = 41,

	BLYNK_CMD_DEBUG_PRINT     = 55,

	BLYNK_CMD_EVENT_LOG       = 60,
};

typedef enum {
	BLYNK_OK = 0,
	BLYNK_ERR_INVALID_OPTION,
	BLYNK_ERR_RUNNING,
	BLYNK_ERR_NOT_INITIALIZED,
	BLYNK_ERR_NOT_CONNECTED,
	BLYNK_ERR_NOT_AUTHENTICATED,
	BLYNK_ERR_TIMEOUT,
	BLYNK_ERR_ERRNO,
	BLYNK_ERR_GAI,
	BLYNK_ERR_STATUS,
	BLYNK_ERR_CLOSED,
	BLYNK_ERR_MEM,
} blynk_err_t;

enum {
	BLYNK_STATUS_SUCCESS                = 200,
	BLYNK_STATUS_QUOTA_LIMIT_EXCEPTION  = 1,
	BLYNK_STATUS_ILLEGAL_COMMAND        = 2,
	BLYNK_STATUS_NOT_REGISTERED         = 3,
	BLYNK_STATUS_ALREADY_REGISTERED     = 4,
	BLYNK_STATUS_NOT_AUTHENTICATED      = 5,
	BLYNK_STATUS_NOT_ALLOWED            = 6,
	BLYNK_STATUS_DEVICE_NOT_IN_NETWORK  = 7,
	BLYNK_STATUS_NO_ACTIVE_DASHBOARD    = 8,
	BLYNK_STATUS_INVALID_TOKEN          = 9,
	BLYNK_STATUS_ILLEGAL_COMMAND_BODY   = 11,
	BLYNK_STATUS_GET_GRAPH_DATA_EXCEPTION = 12,
	BLYNK_STATUS_NO_DATA_EXCEPTION      = 17,
	BLYNK_STATUS_DEVICE_WENT_OFFLINE    = 18,
	BLYNK_STATUS_SERVER_EXCEPTION       = 19,
	BLYNK_STATUS_NTF_INVALID_BODY       = 13,
	BLYNK_STATUS_NTF_NOT_AUTHORIZED     = 14,
	BLYNK_STATUS_NTF_ECXEPTION          = 15,
	BLYNK_STATUS_TIMEOUT                = 16,
	BLYNK_STATUS_NOT_SUPPORTED_VERSION  = 20,
	BLYNK_STATUS_ENERGY_LIMIT           = 21,

	BLYNK_STATUS_RESPONSE_TIMEOUT = 0xffff,
};

typedef enum {
	BLYNK_STATE_STOPPED = 0,
	BLYNK_STATE_DISCONNECTED,
	BLYNK_STATE_CONNECTED,
	BLYNK_STATE_AUTHENTICATED,
} blynk_state_t;

struct _blynk_state_evt_t {
	blynk_state_t state;
	struct {
		blynk_err_t reason;
		int code;
	} disconnected;
};

typedef void (*blynk_state_handler_t)(blynk_client_t *c, const blynk_state_evt_t*, void*);
typedef void (*blynk_response_handler_t)(blynk_client_t*, uint16_t, void*);
typedef void (*blynk_handler_t)(blynk_client_t*, uint16_t, const char*, int, char**, void*);

struct _blynk_options_t {
	char server[64];
	char token[64];
	unsigned int reconnect_delay;
	unsigned int ping_interval; /* ms */
	unsigned int timeout; /* ms */
};

struct _blynk_message_t {
	uint8_t command;
	uint16_t id;
	uint16_t len;
	uint8_t payload[BLYNK_MAX_PAYLOAD_LEN];
};

struct _blynk_awaiting_t {
	uint16_t id;
	TickType_t deadline;
	blynk_response_handler_t handler;
	void *data;
};

struct _blynk_handler_data_t {
	char command[8];
	blynk_handler_t handler;
	void *data;
};

struct _blynk_state_data_t {
	SemaphoreHandle_t mtx;
	TaskHandle_t task;
	blynk_state_t state;
	blynk_options_t opt;
	blynk_state_handler_t evt_handler;
	void *evt_handler_data;
	blynk_handler_data_t handlers[BLYNK_MAX_HANDLERS];
};

struct _blynk_private_t {
	int ctl[2];
	QueueHandle_t ctl_queue;
	uint16_t id;
	void (*parse) (blynk_client_t *ctx, uint8_t d);
	blynk_message_t message;
	unsigned int cnt;
	blynk_awaiting_t awaiting[BLYNK_MAX_AWAITING];
	TickType_t ping_deadline;
	uint8_t rd_buf[BLYNK_MAX_PAYLOAD_LEN];
	uint8_t wr_buf[BLYNK_MAX_PAYLOAD_LEN];
	int buf_total;
	int buf_sent;
};

struct _blynk_client_t {
	uint32_t magic;
	blynk_state_data_t state;
	blynk_private_t priv;
};

blynk_err_t blynk_init(blynk_client_t *c);
blynk_err_t blynk_set_options(blynk_client_t *c, const blynk_options_t *opt);
blynk_err_t blynk_set_state_handler(blynk_client_t *c, blynk_state_handler_t handler, void *data);
blynk_err_t blynk_start(blynk_client_t *c);
blynk_err_t blynk_set_handler(blynk_client_t *c, const char* command, blynk_handler_t handler, void *data);
blynk_err_t blynk_remove_handler(blynk_client_t *c, const char* command);
blynk_state_t blynk_get_state(blynk_client_t *c);

blynk_err_t blynk_send_with_callback_v(blynk_client_t *c,
                                       uint8_t cmd,
                                       blynk_response_handler_t handler,
                                       void *data,
                                       TickType_t wait, const char *fmt, va_list ap);

blynk_err_t blynk_send_with_callback(blynk_client_t *c,
                                     uint8_t cmd,
                                     blynk_response_handler_t handler,
                                     void *data,
                                     TickType_t wait, const char *fmt, ...);

blynk_err_t blynk_send(blynk_client_t *c, uint8_t cmd, TickType_t wait, const char *fmt, ...);
blynk_err_t blynk_send_response(blynk_client_t *c, uint16_t id, uint16_t status, TickType_t wait);

#endif