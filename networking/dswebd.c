/* vi: set sw=4 ts=4: */
/*
 * dswebd - Droidspaces Docker-compatible Web/API daemon
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
//config:config DSWEBD
//config:	bool "dswebd (Droidspaces Web API daemon)"
//config:	default y
//config:	help
//config:	Small Docker-compatible HTTP API daemon for Droidspaces WebUI.
//config:	It intentionally reuses BusyBox/libbb networking and I/O helpers.
//config:	For static WebUI files, use the existing httpd applet.
//config:	For TLS, run dswebd in inetd mode behind ssl_server.

//applet:IF_DSWEBD(APPLET(dswebd, BB_DIR_USR_SBIN, BB_SUID_DROP))

//kbuild:lib-$(CONFIG_DSWEBD) += dswebd.o

//usage:#define dswebd_trivial_usage
//usage:       "[-ifv] [-p [ADDR:]PORT]"
//usage:#define dswebd_full_usage "\n\n"
//usage:       "Droidspaces Docker-compatible Web/API daemon\n"
//usage:     "\n\t-i\tInetd mode: handle one request on stdin/stdout"
//usage:     "\n\t-f\tRun in foreground"
//usage:     "\n\t-v\tVerbose request logging"
//usage:     "\n\t-p ARG\tListen on PORT or ADDR:PORT (default 0.0.0.0:2375)"

#include "libbb.h"

#include <sys/socket.h>
#include <sys/utsname.h>
#include <signal.h>

#define DSWEBD_MAX_REQUEST_HEADER_BYTES (16 * 1024)
#define DSWEBD_IOBUF_SIZE 4096
#define DSWEBD_DEFAULT_BIND_ADDR "0.0.0.0"
#define DSWEBD_DEFAULT_PORT 2375
#define DSWEBD_API_VERSION "1.41"
#define DSWEBD_MIN_API_VERSION "1.40"
#define DSWEBD_OS_TYPE "linux"
#define DSWEBD_PROJECT_NAME "Droidspaces"
#define DSWEBD_VERSION "6.2.5"

struct dswebd_req {
	char *target;
	unsigned is_get;
	unsigned is_head;
	unsigned is_post;
};

static unsigned option_mask;
#define OPT_INETD      (1u << 0)
#define OPT_FOREGROUND (1u << 1)
#define OPT_VERBOSE    (1u << 2)
#define OPT_PORT       (1u << 3)

static int dswebd_send_all(int fd, const void *buf, size_t len)
{
	return full_write(fd, buf, len) == (ssize_t)len;
}

static const char *dswebd_arch_name(void)
{
#if defined(__x86_64__)
	return "amd64";
#elif defined(__i386__)
	return "386";
#elif defined(__aarch64__)
	return "arm64";
#elif defined(__arm__)
	return "arm";
#elif defined(__riscv) && (__riscv_xlen == 64)
	return "riscv64";
#else
	return "unknown";
#endif
}

static char *dswebd_kernel_version(void)
{
	struct utsname uts;

	if (uname(&uts) != 0)
		return xstrdup("");
	return xstrdup(uts.release);
}

static void dswebd_buf_append(char **buf, size_t *len, const char *s)
{
	size_t slen = strlen(s);
	*buf = xrealloc(*buf, *len + slen + 1);
	memcpy(*buf + *len, s, slen + 1);
	*len += slen;
}

static void dswebd_buf_append_json_string(char **buf, size_t *len, const char *s)
{
	static const char hex[] = "0123456789abcdef";
	const unsigned char *p = (const unsigned char *)s;

	dswebd_buf_append(buf, len, "\"");
	while (*p) {
		char tmp[7];
		unsigned char c = *p++;

		switch (c) {
		case '"':
			dswebd_buf_append(buf, len, "\\\"");
			break;
		case '\\':
			dswebd_buf_append(buf, len, "\\\\");
			break;
		case '\b':
			dswebd_buf_append(buf, len, "\\b");
			break;
		case '\f':
			dswebd_buf_append(buf, len, "\\f");
			break;
		case '\n':
			dswebd_buf_append(buf, len, "\\n");
			break;
		case '\r':
			dswebd_buf_append(buf, len, "\\r");
			break;
		case '\t':
			dswebd_buf_append(buf, len, "\\t");
			break;
		default:
			if (c < 0x20) {
				tmp[0] = '\\';
				tmp[1] = 'u';
				tmp[2] = '0';
				tmp[3] = '0';
				tmp[4] = hex[(c >> 4) & 0xf];
				tmp[5] = hex[c & 0xf];
				tmp[6] = '\0';
				dswebd_buf_append(buf, len, tmp);
			} else {
				tmp[0] = (char)c;
				tmp[1] = '\0';
				dswebd_buf_append(buf, len, tmp);
			}
			break;
		}
	}
	dswebd_buf_append(buf, len, "\"");
}

static int dswebd_send_response(int fd, int status, const char *reason,
					const char *content_type, const char *body,
					unsigned suppress_body)
{
	char *header;
	size_t body_len = body ? strlen(body) : 0;
	int ok;

	if (!content_type)
		content_type = "application/json";

	header = xasprintf(
		"HTTP/1.1 %d %s\r\n"
		"Content-Type: %s\r\n"
		"Content-Length: %u\r\n"
		"Server: Droidspaces/6 (Container, like Docker)\r\n"
		"Api-Version: %s\r\n"
		"Ostype: %s\r\n"
		"Connection: close\r\n"
		"\r\n",
		status, reason, content_type, (unsigned)body_len,
		DSWEBD_API_VERSION, DSWEBD_OS_TYPE);

	ok = dswebd_send_all(fd, header, strlen(header));
	free(header);
	if (!ok)
		return 0;
	if (!suppress_body && body_len)
		return dswebd_send_all(fd, body, body_len);
	return 1;
}

static int dswebd_send_bad_request(int fd, unsigned suppress_body)
{
	return dswebd_send_response(fd, 400, "Bad Request",
		"application/json", "{\"message\":\"bad request\"}\n", suppress_body);
}

static int dswebd_send_header_too_large(int fd, unsigned suppress_body)
{
	return dswebd_send_response(fd, 431, "Request Header Fields Too Large",
		"application/json", "{\"message\":\"request headers too large\"}\n", suppress_body);
}

static int dswebd_send_not_found(int fd, unsigned suppress_body)
{
	return dswebd_send_response(fd, 404, "Not Found",
		"application/json", "{\"message\":\"not found\"}\n", suppress_body);
}

static int dswebd_send_ping(int fd, unsigned suppress_body)
{
	return dswebd_send_response(fd, 200, "OK",
		"text/plain; charset=utf-8", "OK", suppress_body);
}

static char *dswebd_build_version_json(void)
{
	char *body = NULL;
	size_t len = 0;
	char *kernel = dswebd_kernel_version();
	const char *arch = dswebd_arch_name();

	dswebd_buf_append(&body, &len, "{\"Platform\":{\"Name\":");
	dswebd_buf_append_json_string(&body, &len, DSWEBD_PROJECT_NAME);
	dswebd_buf_append(&body, &len, "},\"Components\":[{\"Name\":\"Engine\",\"Version\":");
	dswebd_buf_append_json_string(&body, &len, DSWEBD_VERSION);
	dswebd_buf_append(&body, &len, ",\"Details\":{}}],\"Version\":");
	dswebd_buf_append_json_string(&body, &len, DSWEBD_VERSION);
	dswebd_buf_append(&body, &len, ",\"ApiVersion\":\"");
	dswebd_buf_append(&body, &len, DSWEBD_API_VERSION);
	dswebd_buf_append(&body, &len, "\",\"MinAPIVersion\":\"");
	dswebd_buf_append(&body, &len, DSWEBD_MIN_API_VERSION);
	dswebd_buf_append(&body, &len, "\",\"Os\":\"");
	dswebd_buf_append(&body, &len, DSWEBD_OS_TYPE);
	dswebd_buf_append(&body, &len, "\",\"Arch\":");
	dswebd_buf_append_json_string(&body, &len, arch);
	if (kernel[0]) {
		dswebd_buf_append(&body, &len, ",\"KernelVersion\":");
		dswebd_buf_append_json_string(&body, &len, kernel);
	}
	dswebd_buf_append(&body, &len, "}\n");
	free(kernel);
	return body;
}

static int dswebd_send_version(int fd, unsigned suppress_body)
{
	char *body = dswebd_build_version_json();
	int ok = dswebd_send_response(fd, 200, "OK", "application/json",
		body, suppress_body);
	free(body);
	return ok;
}

static int is_ascii_digit(char c)
{
	return c >= '0' && c <= '9';
}

static int dswebd_is_versioned_api_path(const char *path, const char *endpoint)
{
	size_t path_len = strlen(path);
	size_t endpoint_len = strlen(endpoint);
	size_t prefix_len;
	size_t i;

	if (path_len <= endpoint_len)
		return 0;
	if (strcmp(path + path_len - endpoint_len, endpoint) != 0)
		return 0;

	prefix_len = path_len - endpoint_len;
	if (prefix_len < 5 || path[0] != '/' || path[1] != 'v')
		return 0;

	i = 2;
	if (!is_ascii_digit(path[i]))
		return 0;
	while (i < prefix_len && is_ascii_digit(path[i]))
		i++;
	if (i >= prefix_len || path[i] != '.')
		return 0;
	i++;
	if (i >= prefix_len || !is_ascii_digit(path[i]))
		return 0;
	while (i < prefix_len && is_ascii_digit(path[i]))
		i++;
	return i == prefix_len;
}

static int dswebd_is_api_target(const char *target, const char *endpoint)
{
	char *path;
	char *q;
	int result;

	path = xstrdup(target);
	q = strchr(path, '?');
	if (q)
		*q = '\0';
	result = (strcmp(path, endpoint) == 0)
		|| dswebd_is_versioned_api_path(path, endpoint);
	free(path);
	return result;
}

static int dswebd_parse_request_line(char *line, struct dswebd_req *req)
{
	char *method;
	char *target;
	char *version;
	char *trailing;

	method = strtok(line, " ");
	target = strtok(NULL, " ");
	version = strtok(NULL, " ");
	trailing = strtok(NULL, " ");
	if (!method || !target || !version || trailing)
		return 0;
	if (!is_prefixed_with(version, "HTTP/"))
		return 0;

	req->is_get = (strcmp(method, "GET") == 0);
	req->is_head = (strcmp(method, "HEAD") == 0);
	req->is_post = (strcmp(method, "POST") == 0);
	req->target = target;
	return 1;
}

static int dswebd_read_request_header(int fd, char **request_out)
{
	char buf[DSWEBD_IOBUF_SIZE];
	char *request = xzalloc(1);
	size_t len = 0;

	for (;;) {
		ssize_t n;

		if (strstr(request, "\r\n\r\n")) {
			*request_out = request;
			return 1;
		}

		n = safe_read(fd, buf, sizeof(buf));
		if (n < 0) {
			bb_perror_msg("read");
			free(request);
			return 0;
		}
		if (n == 0) {
			free(request);
			return 0;
		}
		if (len + n > DSWEBD_MAX_REQUEST_HEADER_BYTES) {
			free(request);
			return -1;
		}
		request = xrealloc(request, len + n + 1);
		memcpy(request + len, buf, n);
		len += n;
		request[len] = '\0';
	}
}

static int dswebd_handle_one(int in_fd, int out_fd)
{
	char *request;
	char *line_end;
	struct dswebd_req req;
	int r;

	r = dswebd_read_request_header(in_fd, &request);
	if (r < 0)
		return dswebd_send_header_too_large(out_fd, 0) ? 0 : 1;
	if (r == 0)
		return 1;

	if (option_mask & OPT_VERBOSE) {
		char *headers_end = strstr(request, "\r\n\r\n");
		bb_error_msg("received HTTP request headers");
		if (headers_end) {
			char saved = headers_end[4];
			headers_end[4] = '\0';
			bb_error_msg("%s", request);
			headers_end[4] = saved;
		}
	}

	line_end = strstr(request, "\r\n");
	if (!line_end) {
		free(request);
		return dswebd_send_bad_request(out_fd, 0) ? 0 : 1;
	}
	*line_end = '\0';

	memset(&req, 0, sizeof(req));
	if (!dswebd_parse_request_line(request, &req)) {
		free(request);
		return dswebd_send_bad_request(out_fd, 0) ? 0 : 1;
	}

	if ((req.is_get || req.is_head) && dswebd_is_api_target(req.target, "/_ping")) {
		r = dswebd_send_ping(out_fd, req.is_head);
		free(request);
		return r ? 0 : 1;
	}

	if (req.is_get && dswebd_is_api_target(req.target, "/version")) {
		r = dswebd_send_version(out_fd, 0);
		free(request);
		return r ? 0 : 1;
	}

	free(request);
	return dswebd_send_not_found(out_fd, 0) ? 0 : 1;
}

static void dswebd_parse_port_arg(const char *arg, char **bind_addr, unsigned *port)
{
	const char *port_text = arg;
	const char *colon = strrchr(arg, ':');
	char *end;
	unsigned value;

	if (colon) {
		if (colon == arg)
			bb_simple_error_msg_and_die("empty TCP bind address");
		free(*bind_addr);
		*bind_addr = xstrndup(arg, colon - arg);
		port_text = colon + 1;
	}

	errno = 0;
	value = bb_strtou(port_text, &end, 10);
	if (errno || *end || value == 0 || value > 0xffff)
		bb_error_msg_and_die("invalid TCP port: %s", port_text);
	*port = value;
}

int dswebd_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int dswebd_main(int argc UNUSED_PARAM, char **argv)
{
	char *port_arg = NULL;
	char *bind_addr = xstrdup(DSWEBD_DEFAULT_BIND_ADDR);
	unsigned port = DSWEBD_DEFAULT_PORT;

	option_mask = getopt32(argv, "ifvp:", &port_arg);

	if ((option_mask & OPT_INETD) && (option_mask & OPT_PORT))
		bb_simple_error_msg_and_die("-i and -p cannot be used together");

	if (option_mask & OPT_PORT)
		dswebd_parse_port_arg(port_arg, &bind_addr, &port);

	bb_signals(0
#ifdef SIGPIPE
		+ (1 << SIGPIPE)
#endif
		, SIG_IGN);

	if (option_mask & OPT_INETD) {
		free(bind_addr);
		return dswebd_handle_one(STDIN_FILENO, STDOUT_FILENO);
	}

	if (!(option_mask & OPT_FOREGROUND))
		bb_daemonize_or_rexec(0, argv);

	{
		int listen_fd;

		listen_fd = create_and_bind_stream_or_die(bind_addr, port);
		xlisten(listen_fd, SOMAXCONN);
		bb_error_msg("listening on http://%s:%u", bind_addr, port);

		for (;;) {
			int client_fd = accept(listen_fd, NULL, NULL);
			if (client_fd < 0) {
				if (errno == EINTR)
					continue;
				bb_perror_msg("accept");
				continue;
			}
			if (dswebd_handle_one(client_fd, client_fd) != 0)
				bb_simple_error_msg("client request failed");
			close(client_fd);
		}
	}
}
