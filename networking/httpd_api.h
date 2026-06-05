/* vi: set sw=4 ts=4: */
/*
 * Generic BusyBox httpd API provider registry.
 *
 * Copyright (C) 2026 Droidspaces contributors
 *
 * Licensed under GPLv2 or later, see file LICENSE in this source tree.
 */
#ifndef NETWORKING_HTTPD_API_H
#define NETWORKING_HTTPD_API_H 1

struct httpd_api_request;

enum {
	HTTPD_API_NOT_HANDLED = 0,
	HTTPD_API_HANDLED = 1,
	HTTPD_API_ERROR = -1,
};

typedef int (*httpd_api_handler_t)(const struct httpd_api_request *req);
typedef int (*httpd_api_prefix_resolver_t)(const struct httpd_api_request *req);

struct httpd_api_request {
	const char *method;       /* "GET", "HEAD", "POST", etc. */
	const char *target;       /* original request target, including query */
	const char *path;         /* query-stripped path */
	const char *query;        /* query without '?', or NULL */
	int in_fd;                /* request body source */
	int out_fd;               /* response target */
	unsigned content_length;
	unsigned is_head;
};

struct httpd_api_registrar {
	int (*endpoint)(const char *handle_name, httpd_api_handler_t handler);
	int (*prefix)(const char *prefix_name, httpd_api_prefix_resolver_t resolver);
};

struct httpd_api_provider {
	const char *name;
	int (*register_provider)(const struct httpd_api_registrar *reg);
};

int httpd_api_enable_provider(const char *name);
int httpd_api_enable_providers(const char *names);
int httpd_api_try_handle(const struct httpd_api_request *req);

#endif
