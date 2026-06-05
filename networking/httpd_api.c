/* vi: set sw=4 ts=4: */
/*
 * Generic BusyBox httpd API provider registry.
 *
 * Providers are explicitly enabled at httpd startup and register exact
 * endpoints and prefix resolvers. httpd remains provider-agnostic.
 *
 * Copyright (C) 2026 Droidspaces contributors
 *
 * Licensed under GPLv2 or later, see file LICENSE in this source tree.
 */
//kbuild:lib-$(CONFIG_FEATURE_HTTPD_API_REGISTRY) += httpd_api.o

#include "libbb.h"
#include "httpd_api.h"

#define HTTPD_API_MAX_ENDPOINTS 32
#define HTTPD_API_MAX_PREFIXES 16
#define HTTPD_API_MAX_PROVIDERS 8

struct httpd_api_endpoint {
	const char *name;
	httpd_api_handler_t handler;
};

struct httpd_api_prefix {
	const char *prefix;
	httpd_api_prefix_resolver_t resolver;
};

static struct httpd_api_endpoint registered_endpoints[HTTPD_API_MAX_ENDPOINTS];
static struct httpd_api_prefix registered_prefixes[HTTPD_API_MAX_PREFIXES];
static const struct httpd_api_provider *enabled_providers[HTTPD_API_MAX_PROVIDERS];

static unsigned registered_endpoint_count;
static unsigned registered_prefix_count;
static unsigned enabled_provider_count;

/*
 * Portable BusyBox-style provider table. Phase 7 intentionally ships with
 * no provider wired in; Phase 8 will add dswebd here under ENABLE_DSWEBD.
 */
static const struct httpd_api_provider *const available_providers[] = {
	NULL,
};

static const struct httpd_api_provider *find_provider(const char *name)
{
	unsigned i;

	for (i = 0; available_providers[i]; ++i) {
		if (strcmp(available_providers[i]->name, name) == 0)
			return available_providers[i];
	}
	return NULL;
}

static int register_endpoint(const char *handle_name, httpd_api_handler_t handler)
{
	unsigned i;

	if (!handle_name || !handler || handle_name[0] != '/')
		return -1;

	for (i = 0; i < registered_endpoint_count; ++i) {
		if (strcmp(registered_endpoints[i].name, handle_name) == 0) {
			bb_error_msg("httpd api: duplicate endpoint: %s", handle_name);
			return -1;
		}
	}

	if (registered_endpoint_count >= ARRAY_SIZE(registered_endpoints)) {
		bb_error_msg("httpd api: too many endpoints");
		return -1;
	}

	registered_endpoints[registered_endpoint_count].name = handle_name;
	registered_endpoints[registered_endpoint_count].handler = handler;
	registered_endpoint_count++;
	return 0;
}

static int register_prefix(const char *prefix_name, httpd_api_prefix_resolver_t resolver)
{
	unsigned i;
	unsigned insert_at;
	size_t prefix_len;

	if (!prefix_name || !resolver || prefix_name[0] != '/')
		return -1;

	for (i = 0; i < registered_prefix_count; ++i) {
		if (strcmp(registered_prefixes[i].prefix, prefix_name) == 0) {
			bb_error_msg("httpd api: duplicate prefix: %s", prefix_name);
			return -1;
		}
	}

	if (registered_prefix_count >= ARRAY_SIZE(registered_prefixes)) {
		bb_error_msg("httpd api: too many prefixes");
		return -1;
	}

	/* Keep prefixes sorted by descending length for longest-prefix dispatch. */
	prefix_len = strlen(prefix_name);
	insert_at = registered_prefix_count;
	for (i = 0; i < registered_prefix_count; ++i) {
		if (prefix_len > strlen(registered_prefixes[i].prefix)) {
			insert_at = i;
			break;
		}
	}
	for (i = registered_prefix_count; i > insert_at; --i)
		registered_prefixes[i] = registered_prefixes[i - 1];

	registered_prefixes[insert_at].prefix = prefix_name;
	registered_prefixes[insert_at].resolver = resolver;
	registered_prefix_count++;
	return 0;
}

static const struct httpd_api_registrar registrar = {
	.endpoint = register_endpoint,
	.prefix = register_prefix,
};

int httpd_api_enable_provider(const char *name)
{
	const struct httpd_api_provider *provider;
	unsigned i;

	if (!name || !name[0])
		return 0;

	for (i = 0; i < enabled_provider_count; ++i) {
		if (strcmp(enabled_providers[i]->name, name) == 0)
			return 0;
	}

	provider = find_provider(name);
	if (!provider) {
		bb_error_msg("unknown API provider: %s", name);
		return -1;
	}

	if (enabled_provider_count >= ARRAY_SIZE(enabled_providers)) {
		bb_error_msg("httpd api: too many providers");
		return -1;
	}

	if (provider->register_provider(&registrar) != 0) {
		bb_error_msg("failed to register API provider: %s", name);
		return -1;
	}

	enabled_providers[enabled_provider_count++] = provider;
	return 0;
}

int httpd_api_enable_providers(const char *names)
{
	char *copy;
	char *name;
	char *next;
	int rc = 0;

	if (!names || !names[0])
		return 0;

	copy = xstrdup(names);
	name = copy;
	while (name) {
		char *end;

		next = strchr(name, ',');
		if (next)
			*next++ = '\0';

		name = skip_whitespace(name);
		end = name + strlen(name);
		while (end > name && isspace((unsigned char)end[-1]))
			*--end = '\0';

		if (name[0] && httpd_api_enable_provider(name) != 0) {
			rc = -1;
			break;
		}

		name = next;
	}
	free(copy);
	return rc;
}

int httpd_api_try_handle(const struct httpd_api_request *req)
{
	unsigned i;

	if (!req || !req->path)
		return HTTPD_API_NOT_HANDLED;

	for (i = 0; i < registered_endpoint_count; ++i) {
		if (strcmp(registered_endpoints[i].name, req->path) == 0)
			return registered_endpoints[i].handler(req);
	}

	for (i = 0; i < registered_prefix_count; ++i) {
		const char *prefix = registered_prefixes[i].prefix;
		if (is_prefixed_with(req->path, prefix)) {
			int rc = registered_prefixes[i].resolver(req);
			if (rc != HTTPD_API_NOT_HANDLED)
				return rc;
		}
	}

	return HTTPD_API_NOT_HANDLED;
}
