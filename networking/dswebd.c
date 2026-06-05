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
#include <sys/un.h>
#include <sys/utsname.h>
#include <arpa/inet.h>
#include <signal.h>
#include <stddef.h>
#include <time.h>

#define DSWEBD_MAX_REQUEST_HEADER_BYTES (16 * 1024)
#define DSWEBD_IOBUF_SIZE 4096
#define DSWEBD_DEFAULT_BIND_ADDR "0.0.0.0"
#define DSWEBD_DEFAULT_PORT 2375
#define DSWEBD_API_VERSION "1.41"
#define DSWEBD_MIN_API_VERSION "1.40"
#define DSWEBD_OS_TYPE "linux"
#define DSWEBD_PROJECT_NAME "Droidspaces"
#define DSWEBD_VERSION "6.2.5"

#define DS_SOCKETD_BACKEND_SOCK_NAME "droidspaces-socketd-backend"
#define DS_SOCKETD_PROTO_MAGIC 0x44534150u
#define DS_SOCKETD_PROTO_VERSION 1u
#define DS_SOCKETD_MAX_PAYLOAD (1024u * 1024u)

#define DS_SOCKETD_OP_PING 1u
#define DS_SOCKETD_OP_CAPABILITIES 2u
#define DS_SOCKETD_OP_INFO 3u
#define DS_SOCKETD_OP_LIST_CONTAINERS 4u
#define DS_SOCKETD_OP_INSPECT_CONTAINER 5u

#define DS_SOCKETD_STATUS_OK 0u
#define DS_SOCKETD_STATUS_NOT_FOUND 3u

#define DS_UUID_LEN 32
#define DS_SOCKETD_RECORD_NAME_MAX 256
#define DS_SOCKETD_RECORD_PATH_MAX 1024
#define DS_SOCKETD_RECORD_PORTS_MAX 16
#define DS_SOCKETD_INSPECT_ENV_MAX 32
#define DS_SOCKETD_INSPECT_BINDS_MAX 32
#define DS_SOCKETD_INSPECT_STRING_MAX 1024

#define DS_SOCKETD_CAP_PROTOCOL_V1 (1u << 0)
#define DS_SOCKETD_CAP_PING (1u << 1)
#define DS_SOCKETD_CAP_CAPABILITIES (1u << 2)
#define DS_SOCKETD_CAP_INFO (1u << 3)
#define DS_SOCKETD_CAP_LIST_CONTAINERS (1u << 4)
#define DS_SOCKETD_CAP_INSPECT_CONTAINER (1u << 5)

#define DS_SOCKETD_REQUIRED_BASE_CAPS \
	(DS_SOCKETD_CAP_PROTOCOL_V1 | DS_SOCKETD_CAP_PING | DS_SOCKETD_CAP_CAPABILITIES)

#if defined(__GNUC__)
#define DS_SOCKETD_PACKED __attribute__((packed))
#else
#define DS_SOCKETD_PACKED
#endif

struct DS_SOCKETD_PACKED ds_socketd_request_header {
	uint32_t magic_be;
	uint16_t version_be;
	uint16_t opcode_be;
	uint32_t payload_len_be;
};

struct DS_SOCKETD_PACKED ds_socketd_response_header {
	uint32_t magic_be;
	uint16_t version_be;
	uint16_t status_be;
	uint32_t payload_len_be;
};

struct DS_SOCKETD_PACKED ds_socketd_list_containers_req {
	uint8_t include_all;
	uint8_t _pad[3];
};

struct DS_SOCKETD_PACKED ds_socketd_port_record {
	uint16_t host_port_be;
	uint16_t host_port_end_be;
	uint16_t container_port_be;
	uint16_t container_port_end_be;
	uint8_t proto;
	uint8_t _pad[3];
};

struct DS_SOCKETD_PACKED ds_socketd_container_record {
	char name[DS_SOCKETD_RECORD_NAME_MAX];
	char uuid[DS_UUID_LEN + 1];
	char rootfs_path[DS_SOCKETD_RECORD_PATH_MAX];
	char hostname[DS_SOCKETD_RECORD_NAME_MAX];
	char nat_ip[INET_ADDRSTRLEN];
	char custom_init[DS_SOCKETD_RECORD_PATH_MAX];
	int32_t pid_be;
	uint8_t net_mode;
	uint8_t port_count;
	uint8_t _pad[2];
	struct ds_socketd_port_record ports[DS_SOCKETD_RECORD_PORTS_MAX];
	int64_t started_at_be;
};

struct DS_SOCKETD_PACKED ds_socketd_inspect_container_req {
	char target[DS_SOCKETD_RECORD_NAME_MAX];
};

struct DS_SOCKETD_PACKED ds_socketd_env_record {
	char key[DS_SOCKETD_RECORD_NAME_MAX];
	char value[DS_SOCKETD_INSPECT_STRING_MAX];
};

struct DS_SOCKETD_PACKED ds_socketd_bind_record {
	char source[DS_SOCKETD_RECORD_PATH_MAX];
	char destination[DS_SOCKETD_RECORD_PATH_MAX];
	uint8_t read_only;
	uint8_t _pad[3];
};

struct DS_SOCKETD_PACKED ds_socketd_inspect_container_record_v1 {
	uint16_t record_version_be;
	uint16_t _header_pad;
	uint32_t record_size_be;
	char name[DS_SOCKETD_RECORD_NAME_MAX];
	char uuid[DS_UUID_LEN + 1];
	char rootfs_path[DS_SOCKETD_RECORD_PATH_MAX];
	char image_ref[DS_SOCKETD_RECORD_PATH_MAX];
	char hostname[DS_SOCKETD_RECORD_NAME_MAX];
	char nat_ip[INET_ADDRSTRLEN];
	char custom_init[DS_SOCKETD_RECORD_PATH_MAX];
	char dns_servers[DS_SOCKETD_INSPECT_STRING_MAX];
	int32_t pid_be;
	int64_t started_at_be;
	int64_t memory_limit_be;
	int64_t cpu_quota_be;
	int64_t cpu_period_be;
	int64_t pids_limit_be;
	int32_t privileged_mask_be;
	uint8_t net_mode;
	uint8_t foreground;
	uint8_t volatile_mode;
	uint8_t force_cgroupv1;
	uint8_t disable_ipv6;
	uint8_t android_storage;
	uint8_t selinux_permissive;
	uint8_t hw_access;
	uint8_t gpu_mode;
	uint8_t termux_x11;
	uint8_t block_nested_ns;
	uint8_t is_img_mount;
	uint16_t env_count_be;
	uint16_t env_total_count_be;
	uint16_t bind_count_be;
	uint16_t bind_total_count_be;
	uint16_t port_count_be;
	uint16_t port_total_count_be;
	struct ds_socketd_env_record env[DS_SOCKETD_INSPECT_ENV_MAX];
	struct ds_socketd_bind_record binds[DS_SOCKETD_INSPECT_BINDS_MAX];
	struct ds_socketd_port_record ports[DS_SOCKETD_RECORD_PORTS_MAX];
};

struct DS_SOCKETD_PACKED ds_socketd_info_payload {
	uint32_t containers_total_be;
	uint32_t containers_running_be;
	uint32_t containers_stopped_be;
};

struct dswebd_info_result {
	uint32_t containers_total;
	uint32_t containers_running;
	uint32_t containers_stopped;
};

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

static uint64_t dswebd_ntoh64(uint64_t value)
{
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
	return value;
#else
	return ((uint64_t)ntohl((uint32_t)(value & 0xffffffffULL)) << 32)
		| (uint64_t)ntohl((uint32_t)(value >> 32));
#endif
}

static char *dswebd_decode_fixed_string(const char *data, size_t size)
{
	const char *nul;
	size_t len;

	if (!data || !size)
		return xstrdup("");
	nul = memchr(data, '\0', size);
	len = nul ? (size_t)(nul - data) : size;
	return xstrndup(data, len);
}

static char *dswebd_kernel_version(void)
{
	struct utsname uts;

	if (uname(&uts) != 0)
		return xstrdup("");
	return xstrdup(uts.release);
}


static void dswebd_set_error(char **error, char *message)
{
	if (error) {
		free(*error);
		*error = message;
	} else {
		free(message);
	}
}

static int dswebd_read_exact(int fd, void *buf, size_t len, char **error)
{
	char *p = buf;

	while (len) {
		ssize_t n = safe_read(fd, p, len);

		if (n < 0) {
			dswebd_set_error(error, xasprintf("read() failed: %s", strerror(errno)));
			return 0;
		}
		if (n == 0) {
			dswebd_set_error(error, xstrdup("peer closed connection before full response arrived"));
			return 0;
		}
		p += n;
		len -= n;
	}
	return 1;
}

static int dswebd_write_exact(int fd, const void *buf, size_t len, char **error)
{
	if (full_write(fd, buf, len) != (ssize_t)len) {
		dswebd_set_error(error, xasprintf("write() failed: %s", strerror(errno)));
		return 0;
	}
	return 1;
}

static int dswebd_backend_connect(char **error)
{
	int fd;
	struct sockaddr_un addr;
	socklen_t addr_len;
	size_t name_len = strlen(DS_SOCKETD_BACKEND_SOCK_NAME);

	if (name_len >= sizeof(addr.sun_path)) {
		dswebd_set_error(error, xstrdup("backend abstract socket name is too long"));
		return -1;
	}

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		dswebd_set_error(error, xasprintf("socket(AF_UNIX) failed: %s", strerror(errno)));
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	memcpy(addr.sun_path + 1, DS_SOCKETD_BACKEND_SOCK_NAME, name_len);
	addr_len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + name_len);

	if (connect(fd, (const struct sockaddr *)&addr, addr_len) < 0) {
		dswebd_set_error(error,
			xasprintf("connect(@%s) failed: %s",
				DS_SOCKETD_BACKEND_SOCK_NAME, strerror(errno)));
		close(fd);
		return -1;
	}

	return fd;
}

static int dswebd_backend_request(uint16_t opcode,
		const void *payload, uint32_t payload_len,
		uint16_t *status_out, char **payload_out,
		uint32_t *payload_len_out, char **error)
{
	int fd;
	struct ds_socketd_request_header req;
	struct ds_socketd_response_header resp;
	uint32_t magic;
	uint16_t version;
	uint32_t response_payload_len;
	char *response_payload = NULL;

	if (payload_len > DS_SOCKETD_MAX_PAYLOAD) {
		dswebd_set_error(error, xstrdup("request payload exceeds DS_SOCKETD_MAX_PAYLOAD"));
		return 0;
	}

	fd = dswebd_backend_connect(error);
	if (fd < 0)
		return 0;

	memset(&req, 0, sizeof(req));
	req.magic_be = htonl(DS_SOCKETD_PROTO_MAGIC);
	req.version_be = htons(DS_SOCKETD_PROTO_VERSION);
	req.opcode_be = htons(opcode);
	req.payload_len_be = htonl(payload_len);

	if (!dswebd_write_exact(fd, &req, sizeof(req), error))
		goto fail;
	if (payload_len && payload && !dswebd_write_exact(fd, payload, payload_len, error))
		goto fail;

	if (!dswebd_read_exact(fd, &resp, sizeof(resp), error))
		goto fail;

	magic = ntohl(resp.magic_be);
	version = ntohs(resp.version_be);
	response_payload_len = ntohl(resp.payload_len_be);

	if (magic != DS_SOCKETD_PROTO_MAGIC) {
		dswebd_set_error(error, xstrdup("backend response used invalid protocol magic"));
		goto fail;
	}
	if (version != DS_SOCKETD_PROTO_VERSION) {
		dswebd_set_error(error, xstrdup("backend response used unsupported protocol version"));
		goto fail;
	}
	if (response_payload_len > DS_SOCKETD_MAX_PAYLOAD) {
		dswebd_set_error(error, xstrdup("backend response payload exceeds DS_SOCKETD_MAX_PAYLOAD"));
		goto fail;
	}

	if (response_payload_len) {
		response_payload = xmalloc(response_payload_len);
		if (!dswebd_read_exact(fd, response_payload, response_payload_len, error))
			goto fail;
	}

	close(fd);
	*status_out = ntohs(resp.status_be);
	*payload_out = response_payload;
	*payload_len_out = response_payload_len;
	return 1;

 fail:
	free(response_payload);
	close(fd);
	return 0;
}

static int dswebd_backend_ping(char **error)
{
	uint16_t status;
	uint32_t payload_len;
	char *payload = NULL;
	int ok;

	ok = dswebd_backend_request(DS_SOCKETD_OP_PING, NULL, 0,
		&status, &payload, &payload_len, error);
	if (!ok)
		return 0;
	if (status != DS_SOCKETD_STATUS_OK) {
		dswebd_set_error(error,
			xasprintf("PING returned backend status %u", (unsigned)status));
		free(payload);
		return 0;
	}
	if (payload_len != 4 || memcmp(payload, "PONG", 4) != 0) {
		dswebd_set_error(error, xstrdup("PING returned unexpected payload"));
		free(payload);
		return 0;
	}
	free(payload);
	return 1;
}

static int dswebd_backend_capabilities(uint32_t *mask_out, char **error)
{
	uint16_t status;
	uint32_t payload_len;
	char *payload = NULL;
	uint32_t mask_be;
	int ok;

	ok = dswebd_backend_request(DS_SOCKETD_OP_CAPABILITIES, NULL, 0,
		&status, &payload, &payload_len, error);
	if (!ok)
		return 0;
	if (status != DS_SOCKETD_STATUS_OK) {
		dswebd_set_error(error,
			xasprintf("CAPABILITIES returned backend status %u", (unsigned)status));
		free(payload);
		return 0;
	}
	if (payload_len != sizeof(mask_be)) {
		dswebd_set_error(error, xstrdup("CAPABILITIES returned payload of unexpected size"));
		free(payload);
		return 0;
	}
	memcpy(&mask_be, payload, sizeof(mask_be));
	*mask_out = ntohl(mask_be);
	free(payload);
	return 1;
}

static int dswebd_backend_info(struct dswebd_info_result *out, char **error)
{
	uint16_t status;
	uint32_t payload_len;
	char *payload = NULL;
	struct ds_socketd_info_payload wire;
	int ok;

	ok = dswebd_backend_request(DS_SOCKETD_OP_INFO, NULL, 0,
		&status, &payload, &payload_len, error);
	if (!ok)
		return 0;
	if (status != DS_SOCKETD_STATUS_OK) {
		dswebd_set_error(error,
			xasprintf("INFO returned backend status %u", (unsigned)status));
		free(payload);
		return 0;
	}
	if (payload_len != sizeof(wire)) {
		dswebd_set_error(error, xstrdup("INFO returned payload of unexpected size"));
		free(payload);
		return 0;
	}

	memcpy(&wire, payload, sizeof(wire));
	out->containers_total = ntohl(wire.containers_total_be);
	out->containers_running = ntohl(wire.containers_running_be);
	out->containers_stopped = ntohl(wire.containers_stopped_be);
	free(payload);
	return 1;
}

static int dswebd_backend_list_containers(unsigned include_all,
		char **payload_out, uint32_t *payload_len_out, char **error)
{
	struct ds_socketd_list_containers_req req;
	uint16_t status;
	uint32_t payload_len;
	char *payload = NULL;
	int ok;

	memset(&req, 0, sizeof(req));
	req.include_all = include_all ? 1u : 0u;

	ok = dswebd_backend_request(DS_SOCKETD_OP_LIST_CONTAINERS,
		&req, sizeof(req), &status, &payload, &payload_len, error);
	if (!ok)
		return 0;
	if (status != DS_SOCKETD_STATUS_OK) {
		dswebd_set_error(error,
			xasprintf("LIST_CONTAINERS returned backend status %u",
				(unsigned)status));
		free(payload);
		return 0;
	}
	if (payload_len % sizeof(struct ds_socketd_container_record) != 0) {
		dswebd_set_error(error,
			xstrdup("LIST_CONTAINERS returned payload of invalid size"));
		free(payload);
		return 0;
	}

	*payload_out = payload;
	*payload_len_out = payload_len;
	return 1;
}

static int dswebd_backend_inspect_container(const char *ref,
		struct ds_socketd_inspect_container_record_v1 *out,
		unsigned *not_found, char **error)
{
	struct ds_socketd_inspect_container_req req;
	uint16_t status;
	uint32_t payload_len;
	char *payload = NULL;
	uint16_t record_version;
	uint32_t record_size;
	int ok;

	*not_found = 0;
	if (!ref || !ref[0] || strlen(ref) >= DS_SOCKETD_RECORD_NAME_MAX) {
		dswebd_set_error(error, xstrdup("container reference is empty or too long"));
		return 0;
	}

	memset(&req, 0, sizeof(req));
	strncpy(req.target, ref, sizeof(req.target) - 1);

	ok = dswebd_backend_request(DS_SOCKETD_OP_INSPECT_CONTAINER,
		&req, sizeof(req), &status, &payload, &payload_len, error);
	if (!ok)
		return 0;
	if (status == DS_SOCKETD_STATUS_NOT_FOUND) {
		*not_found = 1;
		dswebd_set_error(error, xstrdup("container not found"));
		free(payload);
		return 0;
	}
	if (status != DS_SOCKETD_STATUS_OK) {
		dswebd_set_error(error,
			xasprintf("INSPECT_CONTAINER returned backend status %u",
				(unsigned)status));
		free(payload);
		return 0;
	}
	if (payload_len != sizeof(*out)) {
		dswebd_set_error(error,
			xstrdup("INSPECT_CONTAINER returned payload of unexpected size"));
		free(payload);
		return 0;
	}

	memcpy(out, payload, sizeof(*out));
	free(payload);

	record_version = ntohs(out->record_version_be);
	record_size = ntohl(out->record_size_be);
	if (record_version != 1u || record_size != sizeof(*out)) {
		dswebd_set_error(error,
			xstrdup("INSPECT_CONTAINER returned unsupported inspect record version"));
		return 0;
	}

	return 1;
}

static int dswebd_check_backend(char **error)
{
	uint32_t caps;

	if (!dswebd_backend_ping(error)) {
		char *old = error ? *error : NULL;
		if (error) {
			*error = xasprintf("backend PING failed: %s", old ? old : "unknown error");
			free(old);
		}
		return 0;
	}

	if (!dswebd_backend_capabilities(&caps, error)) {
		char *old = error ? *error : NULL;
		if (error) {
			*error = xasprintf("backend CAPABILITIES failed: %s", old ? old : "unknown error");
			free(old);
		}
		return 0;
	}

	if ((caps & DS_SOCKETD_REQUIRED_BASE_CAPS) != DS_SOCKETD_REQUIRED_BASE_CAPS) {
		dswebd_set_error(error, xstrdup("backend is missing required base capabilities"));
		return 0;
	}

	bb_error_msg("backend handshake OK, capabilities mask: 0x%x", caps);
	return 1;
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


static void dswebd_buf_append_u32(char **buf, size_t *len, uint32_t value)
{
	char tmp[sizeof("4294967295")];
	snprintf(tmp, sizeof(tmp), "%u", (unsigned)value);
	dswebd_buf_append(buf, len, tmp);
}

static void dswebd_buf_append_u64(char **buf, size_t *len, uint64_t value)
{
	char tmp[sizeof("18446744073709551615")];
	snprintf(tmp, sizeof(tmp), "%llu", (unsigned long long)value);
	dswebd_buf_append(buf, len, tmp);
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

static int dswebd_send_internal_server_error(int fd, const char *message,
		unsigned suppress_body)
{
	char *body = NULL;
	size_t len = 0;
	int ok;

	if (!message || !message[0])
		message = "internal server error";

	dswebd_buf_append(&body, &len, "{\"message\":");
	dswebd_buf_append_json_string(&body, &len, message);
	dswebd_buf_append(&body, &len, "}\n");
	ok = dswebd_send_response(fd, 500, "Internal Server Error",
		"application/json", body, suppress_body);
	free(body);
	return ok;
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


static uint64_t dswebd_mem_total_bytes(void)
{
	FILE *fp;
	char key[64];
	char unit[16];
	unsigned long long value_kib;
	uint64_t result = 0;

	fp = fopen_for_read("/proc/meminfo");
	if (!fp)
		return 0;

	while (fscanf(fp, "%63s %llu %15s", key, &value_kib, unit) == 3) {
		if (strcmp(key, "MemTotal:") == 0) {
			result = (uint64_t)value_kib * 1024ULL;
			break;
		}
	}
	fclose(fp);
	return result;
}

static unsigned dswebd_ncpu(void)
{
	long value = sysconf(_SC_NPROCESSORS_ONLN);

	if (value <= 0)
		return 0;
	if ((unsigned long)value > UINT_MAX)
		return UINT_MAX;
	return (unsigned)value;
}

static char *dswebd_hostname(void)
{
	char hostname[256];

	if (gethostname(hostname, sizeof(hostname) - 1) != 0)
		return xstrdup("droidspaces");
	hostname[sizeof(hostname) - 1] = '\0';
	if (!hostname[0])
		return xstrdup("droidspaces");
	return xstrdup(hostname);
}

static char *dswebd_system_time_utc(void)
{
	time_t now = time(NULL);
	struct tm tm;
	char buf[64];

	if (now == (time_t)-1)
		return xstrdup("");
	if (!gmtime_r(&now, &tm))
		return xstrdup("");
	if (strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm) == 0)
		return xstrdup("");
	return xstrdup(buf);
}

static char *dswebd_build_info_json(const struct dswebd_info_result *info)
{
	char *body = NULL;
	size_t len = 0;
	char *kernel = dswebd_kernel_version();
	char *hostname = dswebd_hostname();
	char *system_time = dswebd_system_time_utc();
	const char *arch = dswebd_arch_name();
	unsigned ncpu = dswebd_ncpu();
	uint64_t mem_total = dswebd_mem_total_bytes();

	dswebd_buf_append(&body, &len, "{");
	dswebd_buf_append(&body, &len, "\"ID\":\"\",");
	dswebd_buf_append(&body, &len, "\"Containers\":");
	dswebd_buf_append_u32(&body, &len, info->containers_total);
	dswebd_buf_append(&body, &len, ",\"ContainersRunning\":");
	dswebd_buf_append_u32(&body, &len, info->containers_running);
	dswebd_buf_append(&body, &len, ",\"ContainersPaused\":0,");
	dswebd_buf_append(&body, &len, "\"ContainersStopped\":");
	dswebd_buf_append_u32(&body, &len, info->containers_stopped);
	dswebd_buf_append(&body, &len, ",\"Images\":0,");
	dswebd_buf_append(&body, &len, "\"Driver\":\"droidspaces\",");
	dswebd_buf_append(&body, &len, "\"DriverStatus\":[],");
	dswebd_buf_append(&body, &len, "\"Plugins\":{\"Volume\":[],\"Network\":[],\"Authorization\":[],\"Log\":[]},");
	dswebd_buf_append(&body, &len, "\"MemoryLimit\":false,\"SwapLimit\":false,");
	dswebd_buf_append(&body, &len, "\"CpuCfsPeriod\":false,\"CpuCfsQuota\":false,");
	dswebd_buf_append(&body, &len, "\"CPUShares\":false,\"CPUSet\":false,\"PidsLimit\":false,");
	dswebd_buf_append(&body, &len, "\"IPv4Forwarding\":false,\"Debug\":false,\"NFd\":0,");
	dswebd_buf_append(&body, &len, "\"OomKillDisable\":false,\"NGoroutines\":0,");
	dswebd_buf_append(&body, &len, "\"SystemTime\":");
	dswebd_buf_append_json_string(&body, &len, system_time);
	dswebd_buf_append(&body, &len, ",\"LoggingDriver\":\"\",\"CgroupDriver\":\"\",\"NEventsListener\":0,");
	dswebd_buf_append(&body, &len, "\"KernelVersion\":");
	dswebd_buf_append_json_string(&body, &len, kernel);
	dswebd_buf_append(&body, &len, ",\"OperatingSystem\":\"Droidspaces\",\"OSVersion\":\"\",\"OSType\":\"linux\",");
	dswebd_buf_append(&body, &len, "\"Architecture\":");
	dswebd_buf_append_json_string(&body, &len, arch);
	dswebd_buf_append(&body, &len, ",\"IndexServerAddress\":\"\",\"RegistryConfig\":null,");
	dswebd_buf_append(&body, &len, "\"NCPU\":");
	dswebd_buf_append_u32(&body, &len, ncpu);
	dswebd_buf_append(&body, &len, ",\"MemTotal\":");
	dswebd_buf_append_u64(&body, &len, mem_total);
	dswebd_buf_append(&body, &len, ",\"GenericResources\":[],\"DockerRootDir\":\"\",");
	dswebd_buf_append(&body, &len, "\"HttpProxy\":\"\",\"HttpsProxy\":\"\",\"NoProxy\":\"\",");
	dswebd_buf_append(&body, &len, "\"Name\":");
	dswebd_buf_append_json_string(&body, &len, hostname);
	dswebd_buf_append(&body, &len, ",\"Labels\":[],\"ExperimentalBuild\":false,");
	dswebd_buf_append(&body, &len, "\"ServerVersion\":");
	dswebd_buf_append_json_string(&body, &len, DSWEBD_VERSION);
	dswebd_buf_append(&body, &len, ",\"Runtimes\":{},\"DefaultRuntime\":\"\",");
	dswebd_buf_append(&body, &len, "\"Swarm\":{\"NodeID\":\"\"},\"LiveRestoreEnabled\":false,");
	dswebd_buf_append(&body, &len, "\"Isolation\":\"\",\"InitBinary\":\"\",");
	dswebd_buf_append(&body, &len, "\"ContainerdCommit\":{\"ID\":\"\"},\"RuncCommit\":{\"ID\":\"\"},");
	dswebd_buf_append(&body, &len, "\"InitCommit\":{\"ID\":\"\"},\"SecurityOptions\":[],\"Warnings\":[]");
	dswebd_buf_append(&body, &len, "}\n");

	free(kernel);
	free(hostname);
	free(system_time);
	return body;
}

static int dswebd_send_info(int fd, unsigned suppress_body)
{
	struct dswebd_info_result info;
	char *body;
	char *error = NULL;
	int ok;

	memset(&info, 0, sizeof(info));
	if (!dswebd_backend_info(&info, &error)) {
		ok = dswebd_send_internal_server_error(fd, error, suppress_body);
		free(error);
		return ok;
	}

	body = dswebd_build_info_json(&info);
	ok = dswebd_send_response(fd, 200, "OK", "application/json",
		body, suppress_body);
	free(body);
	return ok;
}

static const char *dswebd_container_state(const struct ds_socketd_container_record *record)
{
	int32_t pid = (int32_t)ntohl((uint32_t)record->pid_be);

	return pid > 0 ? "running" : "exited";
}

static const char *dswebd_container_status(const struct ds_socketd_container_record *record)
{
	int32_t pid = (int32_t)ntohl((uint32_t)record->pid_be);

	return pid > 0 ? "Up" : "Exited";
}

static const char *dswebd_port_type(uint8_t proto)
{
	return proto == 1u ? "udp" : "tcp";
}

static void dswebd_append_ports_json(char **body, size_t *len,
		const struct ds_socketd_container_record *record)
{
	unsigned i;
	unsigned port_count = record->port_count;

	if (port_count > DS_SOCKETD_RECORD_PORTS_MAX)
		port_count = DS_SOCKETD_RECORD_PORTS_MAX;

	dswebd_buf_append(body, len, "\"Ports\":[");
	for (i = 0; i < port_count; ++i) {
		const struct ds_socketd_port_record *port = &record->ports[i];

		if (i)
			dswebd_buf_append(body, len, ",");
		dswebd_buf_append(body, len, "{\"PrivatePort\":");
		dswebd_buf_append_u32(body, len, ntohs(port->container_port_be));
		dswebd_buf_append(body, len, ",\"PublicPort\":");
		dswebd_buf_append_u32(body, len, ntohs(port->host_port_be));
		dswebd_buf_append(body, len, ",\"Type\":");
		dswebd_buf_append_json_string(body, len, dswebd_port_type(port->proto));
		dswebd_buf_append(body, len, "}");
	}
	dswebd_buf_append(body, len, "]");
}

static void dswebd_append_network_settings_json(char **body, size_t *len,
		const struct ds_socketd_container_record *record)
{
	char *nat_ip;

	dswebd_buf_append(body, len, "\"NetworkSettings\":{\"Networks\":{");
	nat_ip = dswebd_decode_fixed_string(record->nat_ip, sizeof(record->nat_ip));
	if (record->net_mode == 1u && nat_ip[0]) {
		dswebd_buf_append(body, len, "\"droidspaces-bridge\":{\"IPAddress\":");
		dswebd_buf_append_json_string(body, len, nat_ip);
		dswebd_buf_append(body, len, "}");
	}
	free(nat_ip);
	dswebd_buf_append(body, len, "}}");
}

static void dswebd_append_container_json(char **body, size_t *len,
		const struct ds_socketd_container_record *record)
{
	char *name = dswebd_decode_fixed_string(record->name, sizeof(record->name));
	char *uuid = dswebd_decode_fixed_string(record->uuid, sizeof(record->uuid));
	char *rootfs_path = dswebd_decode_fixed_string(record->rootfs_path,
		sizeof(record->rootfs_path));
	char *custom_init = dswebd_decode_fixed_string(record->custom_init,
		sizeof(record->custom_init));
	const char *command = custom_init[0] ? custom_init : "/sbin/init";
	int64_t started_at = (int64_t)dswebd_ntoh64((uint64_t)record->started_at_be);

	dswebd_buf_append(body, len, "{\"Id\":");
	dswebd_buf_append_json_string(body, len, uuid);
	{
		char *docker_name = xasprintf("/%s", name);
		dswebd_buf_append(body, len, ",\"Names\":[");
		dswebd_buf_append_json_string(body, len, docker_name);
		dswebd_buf_append(body, len, "],\"Image\":");
		free(docker_name);
	}
	dswebd_buf_append_json_string(body, len, rootfs_path);
	dswebd_buf_append(body, len, ",\"ImageID\":");
	dswebd_buf_append_json_string(body, len, uuid);
	dswebd_buf_append(body, len, ",\"Command\":");
	dswebd_buf_append_json_string(body, len, command);
	dswebd_buf_append(body, len, ",\"Created\":");
	dswebd_buf_append_u64(body, len, started_at > 0 ? (uint64_t)started_at : 0);
	dswebd_buf_append(body, len, ",");
	dswebd_append_ports_json(body, len, record);
	dswebd_buf_append(body, len, ",\"Labels\":{},\"State\":");
	dswebd_buf_append_json_string(body, len, dswebd_container_state(record));
	dswebd_buf_append(body, len, ",\"Status\":");
	dswebd_buf_append_json_string(body, len, dswebd_container_status(record));
	dswebd_buf_append(body, len, ",");
	dswebd_append_network_settings_json(body, len, record);
	dswebd_buf_append(body, len, ",\"Mounts\":[]}");

	free(name);
	free(uuid);
	free(rootfs_path);
	free(custom_init);
}

static unsigned dswebd_is_truthy_query_value(const char *value, size_t len)
{
	return len == 0
		|| (len == 1 && value[0] == '1')
		|| (len == 4 && memcmp(value, "true", 4) == 0);
}

static unsigned dswebd_parse_container_list_include_all(const char *target)
{
	const char *pos = strchr(target, '?');
	unsigned include_all = 0;

	if (!pos || !*++pos)
		return 0;

	while (*pos) {
		const char *end = strchr(pos, '&');
		const char *eq;
		size_t item_len;
		size_t key_len;
		const char *value;
		size_t value_len;

		if (!end)
			end = pos + strlen(pos);
		item_len = (size_t)(end - pos);
		eq = memchr(pos, '=', item_len);
		key_len = eq ? (size_t)(eq - pos) : item_len;
		value = eq ? eq + 1 : end;
		value_len = eq ? (size_t)(end - value) : 0;

		if (key_len == 3 && memcmp(pos, "all", 3) == 0)
			include_all = dswebd_is_truthy_query_value(value, value_len);

		pos = *end ? end + 1 : end;
	}
	return include_all;
}

static char *dswebd_build_container_list_json(const char *payload, uint32_t payload_len)
{
	char *body = NULL;
	size_t len = 0;
	uint32_t count = payload_len / sizeof(struct ds_socketd_container_record);
	uint32_t i;

	dswebd_buf_append(&body, &len, "[");
	for (i = 0; i < count; ++i) {
		struct ds_socketd_container_record wire;

		if (i)
			dswebd_buf_append(&body, &len, ",");
		memcpy(&wire, payload + i * sizeof(wire), sizeof(wire));
		dswebd_append_container_json(&body, &len, &wire);
	}
	dswebd_buf_append(&body, &len, "]\n");
	return body;
}

static int dswebd_send_container_list(int fd, const char *target,
		unsigned suppress_body)
{
	char *payload = NULL;
	uint32_t payload_len = 0;
	char *body;
	char *error = NULL;
	unsigned include_all;
	int ok;

	include_all = dswebd_parse_container_list_include_all(target);
	if (!dswebd_backend_list_containers(include_all, &payload, &payload_len, &error)) {
		ok = dswebd_send_internal_server_error(fd, error, suppress_body);
		free(error);
		return ok;
	}

	body = dswebd_build_container_list_json(payload, payload_len);
	free(payload);
	ok = dswebd_send_response(fd, 200, "OK", "application/json",
		body, suppress_body);
	free(body);
	return ok;
}

static char *dswebd_rfc3339_utc(int64_t unix_seconds)
{
	static const char zero_time[] = "0001-01-01T00:00:00Z";
	time_t value;
	struct tm tm;
	char buf[64];

	if (unix_seconds <= 0)
		return xstrdup(zero_time);
	value = (time_t)unix_seconds;
	if ((int64_t)value != unix_seconds)
		return xstrdup(zero_time);
	if (!gmtime_r(&value, &tm))
		return xstrdup(zero_time);
	if (strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm) == 0)
		return xstrdup(zero_time);
	return xstrdup(buf);
}

static int32_t dswebd_inspect_pid(const struct ds_socketd_inspect_container_record_v1 *record)
{
	return (int32_t)ntohl((uint32_t)record->pid_be);
}

static uint16_t dswebd_inspect_port_count(const struct ds_socketd_inspect_container_record_v1 *record)
{
	uint16_t count = ntohs(record->port_count_be);

	return count > DS_SOCKETD_RECORD_PORTS_MAX ? DS_SOCKETD_RECORD_PORTS_MAX : count;
}

static const char *dswebd_docker_network_mode(uint8_t mode)
{
	switch (mode) {
	case 1u:
		return "bridge";
	case 2u:
		return "none";
	case 0u:
	default:
		return "host";
	}
}

static void dswebd_append_named_json_string(char **body, size_t *len,
		const char *name, const char *value)
{
	dswebd_buf_append(body, len, "\"");
	dswebd_buf_append(body, len, name);
	dswebd_buf_append(body, len, "\":");
	dswebd_buf_append_json_string(body, len, value ? value : "");
}

static void dswebd_append_inspect_port_map_json(char **body, size_t *len,
		const struct ds_socketd_inspect_container_record_v1 *record,
		unsigned include_host_bindings)
{
	uint16_t port_count = dswebd_inspect_port_count(record);
	uint16_t i;

	dswebd_buf_append(body, len, "{");
	for (i = 0; i < port_count; ++i) {
		const struct ds_socketd_port_record *port = &record->ports[i];

		if (i)
			dswebd_buf_append(body, len, ",");
		dswebd_buf_append(body, len, "\"");
		dswebd_buf_append_u32(body, len, ntohs(port->container_port_be));
		dswebd_buf_append(body, len, "/");
		dswebd_buf_append(body, len, dswebd_port_type(port->proto));
		dswebd_buf_append(body, len, "\":");
		if (include_host_bindings) {
			dswebd_buf_append(body, len, "[{\"HostIp\":\"\",\"HostPort\":\"");
			dswebd_buf_append_u32(body, len, ntohs(port->host_port_be));
			dswebd_buf_append(body, len, "\"}]");
		} else {
			dswebd_buf_append(body, len, "{}");
		}
	}
	dswebd_buf_append(body, len, "}");
}

static void dswebd_append_inspect_config_json(char **body, size_t *len,
		const struct ds_socketd_inspect_container_record_v1 *record,
		const char *command, const char *image)
{
	char *hostname = dswebd_decode_fixed_string(record->hostname, sizeof(record->hostname));

	dswebd_buf_append(body, len, "\"Config\":{");
	dswebd_append_named_json_string(body, len, "Hostname", hostname);
	dswebd_buf_append(body, len, ",\"Domainname\":\"\",");
	dswebd_buf_append(body, len, "\"User\":\"\",\"AttachStdin\":false,");
	dswebd_buf_append(body, len, "\"AttachStdout\":false,\"AttachStderr\":false,");
	dswebd_buf_append(body, len, "\"ExposedPorts\":");
	dswebd_append_inspect_port_map_json(body, len, record, 0);
	dswebd_buf_append(body, len, ",\"Tty\":false,\"OpenStdin\":false,");
	dswebd_buf_append(body, len, "\"StdinOnce\":false,\"Env\":[],\"Cmd\":[");
	dswebd_buf_append_json_string(body, len, command);
	dswebd_buf_append(body, len, "],");
	dswebd_append_named_json_string(body, len, "Image", image);
	dswebd_buf_append(body, len, ",\"Volumes\":{},\"WorkingDir\":\"\",");
	dswebd_buf_append(body, len, "\"Entrypoint\":[],\"OnBuild\":[],\"Labels\":{}");
	dswebd_buf_append(body, len, "}");

	free(hostname);
}

static void dswebd_append_inspect_host_config_json(char **body, size_t *len,
		const struct ds_socketd_inspect_container_record_v1 *record)
{
	dswebd_buf_append(body, len, "\"HostConfig\":{");
	dswebd_buf_append(body, len, "\"Binds\":[],\"ContainerIDFile\":\"\",");
	dswebd_buf_append(body, len, "\"LogConfig\":{\"Type\":\"\",\"Config\":{}},");
	dswebd_buf_append(body, len, "\"NetworkMode\":\"");
	dswebd_buf_append(body, len, dswebd_docker_network_mode(record->net_mode));
	dswebd_buf_append(body, len, "\",\"PortBindings\":");
	dswebd_append_inspect_port_map_json(body, len, record, 1);
	dswebd_buf_append(body, len, ",\"RestartPolicy\":{\"Name\":\"\",\"MaximumRetryCount\":0},");
	dswebd_buf_append(body, len, "\"AutoRemove\":false,\"VolumeDriver\":\"\",\"VolumesFrom\":[],");
	dswebd_buf_append(body, len, "\"CapAdd\":[],\"CapDrop\":[],\"CgroupnsMode\":\"\",");
	dswebd_buf_append(body, len, "\"Dns\":[],\"DnsOptions\":[],\"DnsSearch\":[],\"ExtraHosts\":[],");
	dswebd_buf_append(body, len, "\"GroupAdd\":[],\"IpcMode\":\"\",\"Cgroup\":\"\",\"Links\":[],");
	dswebd_buf_append(body, len, "\"OomScoreAdj\":0,\"PidMode\":\"\",");
	dswebd_buf_append(body, len, "\"Privileged\":false,\"PublishAllPorts\":false,");
	dswebd_buf_append(body, len, "\"ReadonlyRootfs\":false,\"SecurityOpt\":[],\"UTSMode\":\"\",");
	dswebd_buf_append(body, len, "\"UsernsMode\":\"\",\"ShmSize\":0,\"Runtime\":\"\",");
	dswebd_buf_append(body, len, "\"ConsoleSize\":[0,0],\"Isolation\":\"\",");
	dswebd_buf_append(body, len, "\"CpuShares\":0,\"Memory\":0,\"NanoCpus\":0,");
	dswebd_buf_append(body, len, "\"CgroupParent\":\"\",\"BlkioWeight\":0,");
	dswebd_buf_append(body, len, "\"BlkioWeightDevice\":[],\"BlkioDeviceReadBps\":[],");
	dswebd_buf_append(body, len, "\"BlkioDeviceWriteBps\":[],\"BlkioDeviceReadIOps\":[],");
	dswebd_buf_append(body, len, "\"BlkioDeviceWriteIOps\":[],\"CpuPeriod\":0,\"CpuQuota\":0,");
	dswebd_buf_append(body, len, "\"CpuRealtimePeriod\":0,\"CpuRealtimeRuntime\":0,");
	dswebd_buf_append(body, len, "\"CpusetCpus\":\"\",\"CpusetMems\":\"\",\"Devices\":[],");
	dswebd_buf_append(body, len, "\"DeviceCgroupRules\":[],\"DeviceRequests\":[],");
	dswebd_buf_append(body, len, "\"KernelMemory\":0,\"KernelMemoryTCP\":0,");
	dswebd_buf_append(body, len, "\"MemoryReservation\":0,\"MemorySwap\":0,");
	dswebd_buf_append(body, len, "\"MemorySwappiness\":0,\"OomKillDisable\":false,");
	dswebd_buf_append(body, len, "\"PidsLimit\":0,\"Ulimits\":[],\"CpuCount\":0,");
	dswebd_buf_append(body, len, "\"CpuPercent\":0,\"IOMaximumIOps\":0,");
	dswebd_buf_append(body, len, "\"IOMaximumBandwidth\":0,\"MaskedPaths\":[],\"ReadonlyPaths\":[]");
	dswebd_buf_append(body, len, "}");
}

static void dswebd_append_inspect_state_json(char **body, size_t *len,
		const struct ds_socketd_inspect_container_record_v1 *record,
		const char *started_at)
{
	int32_t pid = dswebd_inspect_pid(record);

	dswebd_buf_append(body, len, "\"State\":{");
	dswebd_buf_append(body, len, "\"Status\":\"");
	dswebd_buf_append(body, len, pid > 0 ? "running" : "exited");
	dswebd_buf_append(body, len, "\",\"Running\":");
	dswebd_buf_append(body, len, pid > 0 ? "true" : "false");
	dswebd_buf_append(body, len, ",\"Paused\":false,\"Restarting\":false,");
	dswebd_buf_append(body, len, "\"OOMKilled\":false,\"Dead\":false,\"Pid\":");
	dswebd_buf_append_u32(body, len, pid > 0 ? (uint32_t)pid : 0);
	dswebd_buf_append(body, len, ",\"ExitCode\":0,\"Error\":\"\",\"StartedAt\":");
	dswebd_buf_append_json_string(body, len, started_at);
	dswebd_buf_append(body, len, ",\"FinishedAt\":\"0001-01-01T00:00:00Z\"");
	dswebd_buf_append(body, len, "}");
}

static void dswebd_append_inspect_networks_json(char **body, size_t *len,
		const struct ds_socketd_inspect_container_record_v1 *record)
{
	char *nat_ip = dswebd_decode_fixed_string(record->nat_ip, sizeof(record->nat_ip));

	dswebd_buf_append(body, len, "\"Networks\":{");
	if (record->net_mode == 1u) {
		dswebd_buf_append(body, len, "\"droidspaces-bridge\":{");
		dswebd_buf_append(body, len, "\"IPAMConfig\":{},\"Links\":[],\"Aliases\":[],");
		dswebd_buf_append(body, len, "\"NetworkID\":\"\",\"EndpointID\":\"\",\"Gateway\":\"\",");
		dswebd_buf_append(body, len, "\"IPAddress\":");
		dswebd_buf_append_json_string(body, len, nat_ip);
		dswebd_buf_append(body, len, ",\"IPPrefixLen\":0,\"IPv6Gateway\":\"\",");
		dswebd_buf_append(body, len, "\"GlobalIPv6Address\":\"\",\"GlobalIPv6PrefixLen\":0,");
		dswebd_buf_append(body, len, "\"MacAddress\":\"\",\"DriverOpts\":{}");
		dswebd_buf_append(body, len, "}");
	}
	dswebd_buf_append(body, len, "}");
	free(nat_ip);
}

static void dswebd_append_inspect_network_settings_json(char **body, size_t *len,
		const struct ds_socketd_inspect_container_record_v1 *record)
{
	char *nat_ip = dswebd_decode_fixed_string(record->nat_ip, sizeof(record->nat_ip));

	dswebd_buf_append(body, len, "\"NetworkSettings\":{");
	dswebd_buf_append(body, len, "\"Bridge\":\"\",\"SandboxID\":\"\",\"HairpinMode\":false,");
	dswebd_buf_append(body, len, "\"LinkLocalIPv6Address\":\"\",\"LinkLocalIPv6PrefixLen\":0,");
	dswebd_buf_append(body, len, "\"Ports\":");
	dswebd_append_inspect_port_map_json(body, len, record, 1);
	dswebd_buf_append(body, len, ",\"SandboxKey\":\"\",\"SecondaryIPAddresses\":[],");
	dswebd_buf_append(body, len, "\"SecondaryIPv6Addresses\":[],\"EndpointID\":\"\",\"Gateway\":\"\",");
	dswebd_buf_append(body, len, "\"GlobalIPv6Address\":\"\",\"GlobalIPv6PrefixLen\":0,");
	dswebd_buf_append(body, len, "\"IPAddress\":");
	dswebd_buf_append_json_string(body, len, record->net_mode == 1u ? nat_ip : "");
	dswebd_buf_append(body, len, ",\"IPPrefixLen\":0,\"IPv6Gateway\":\"\",\"MacAddress\":\"\",");
	dswebd_append_inspect_networks_json(body, len, record);
	dswebd_buf_append(body, len, "}");

	free(nat_ip);
}

static char *dswebd_build_container_inspect_json(
		const struct ds_socketd_inspect_container_record_v1 *record)
{
	char *body = NULL;
	size_t len = 0;
	char *name = dswebd_decode_fixed_string(record->name, sizeof(record->name));
	char *uuid = dswebd_decode_fixed_string(record->uuid, sizeof(record->uuid));
	char *rootfs_path = dswebd_decode_fixed_string(record->rootfs_path, sizeof(record->rootfs_path));
	char *image_ref = dswebd_decode_fixed_string(record->image_ref, sizeof(record->image_ref));
	char *custom_init = dswebd_decode_fixed_string(record->custom_init, sizeof(record->custom_init));
	const char *command = custom_init[0] ? custom_init : "/sbin/init";
	const char *image = image_ref[0] ? image_ref : rootfs_path;
	int64_t started_epoch = (int64_t)dswebd_ntoh64((uint64_t)record->started_at_be);
	char *started_at = dswebd_rfc3339_utc(started_epoch);
	char *docker_name = xasprintf("/%s", name);

	dswebd_buf_append(&body, &len, "{");
	dswebd_buf_append(&body, &len, "\"AppArmorProfile\":\"\",\"Args\":[],");
	dswebd_append_inspect_config_json(&body, &len, record, command, image);
	dswebd_buf_append(&body, &len, ",\"Created\":");
	dswebd_buf_append_json_string(&body, &len, started_at);
	dswebd_buf_append(&body, &len, ",\"Driver\":\"droidspaces\",\"ExecIDs\":[],");
	dswebd_append_inspect_host_config_json(&body, &len, record);
	dswebd_buf_append(&body, &len, ",\"HostnamePath\":\"\",\"HostsPath\":\"\",\"LogPath\":\"\",");
	dswebd_append_named_json_string(&body, &len, "Id", uuid);
	dswebd_buf_append(&body, &len, ",");
	dswebd_append_named_json_string(&body, &len, "Image", image);
	dswebd_buf_append(&body, &len, ",\"MountLabel\":\"\",");
	dswebd_append_named_json_string(&body, &len, "Name", docker_name);
	dswebd_buf_append(&body, &len, ",");
	dswebd_append_inspect_network_settings_json(&body, &len, record);
	dswebd_buf_append(&body, &len, ",");
	dswebd_append_named_json_string(&body, &len, "Path", command);
	dswebd_buf_append(&body, &len, ",\"ProcessLabel\":\"\",\"ResolvConfPath\":\"\",");
	dswebd_buf_append(&body, &len, "\"RestartCount\":0,");
	dswebd_append_inspect_state_json(&body, &len, record, started_at);
	dswebd_buf_append(&body, &len, ",\"Mounts\":[]");
	dswebd_buf_append(&body, &len, "}\n");

	free(name);
	free(uuid);
	free(rootfs_path);
	free(image_ref);
	free(custom_init);
	free(started_at);
	free(docker_name);
	return body;
}

static int dswebd_send_container_inspect(int fd, const char *ref,
		unsigned suppress_body)
{
	struct ds_socketd_inspect_container_record_v1 record;
	unsigned not_found = 0;
	char *body;
	char *error = NULL;
	int ok;

	memset(&record, 0, sizeof(record));
	if (!dswebd_backend_inspect_container(ref, &record, &not_found, &error)) {
		if (not_found) {
			free(error);
			return dswebd_send_not_found(fd, suppress_body);
		}
		ok = dswebd_send_internal_server_error(fd, error, suppress_body);
		free(error);
		return ok;
	}

	body = dswebd_build_container_inspect_json(&record);
	ok = dswebd_send_response(fd, 200, "OK", "application/json", body, suppress_body);
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

static char *dswebd_strip_api_version_prefix(char *path)
{
	size_t i;
	size_t major_start;
	size_t minor_start;

	if (!is_prefixed_with(path, "/v"))
		return path;
	i = 2;
	major_start = i;
	while (path[i] && is_ascii_digit(path[i]))
		i++;
	if (i == major_start || path[i] != '.')
		return path;
	i++;
	minor_start = i;
	while (path[i] && is_ascii_digit(path[i]))
		i++;
	if (i == minor_start || path[i] != '/')
		return path;
	return path + i;
}

static char *dswebd_parse_container_ref_with_suffix(const char *target,
		const char *suffix)
{
	static const char prefix[] = "/containers/";
	char *path = xstrdup(target);
	char *q = strchr(path, '?');
	char *unversioned;
	size_t path_len;
	size_t prefix_len = sizeof(prefix) - 1;
	size_t suffix_len = strlen(suffix);
	char *ref;
	char *slash;

	if (q)
		*q = '\0';
	unversioned = dswebd_strip_api_version_prefix(path);
	path_len = strlen(unversioned);
	if (path_len <= prefix_len + suffix_len
	 || strncmp(unversioned, prefix, prefix_len) != 0
	 || strcmp(unversioned + path_len - suffix_len, suffix) != 0) {
		free(path);
		return NULL;
	}

	ref = xstrndup(unversioned + prefix_len,
		path_len - prefix_len - suffix_len);
	slash = strchr(ref, '/');
	if (!ref[0] || slash) {
		free(ref);
		free(path);
		return NULL;
	}

	free(path);
	return ref;
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

	if (req.is_get && dswebd_is_api_target(req.target, "/info")) {
		r = dswebd_send_info(out_fd, 0);
		free(request);
		return r ? 0 : 1;
	}

	if (req.is_get && dswebd_is_api_target(req.target, "/containers/json")) {
		r = dswebd_send_container_list(out_fd, req.target, 0);
		free(request);
		return r ? 0 : 1;
	}

	if (req.is_get) {
		char *ref = dswebd_parse_container_ref_with_suffix(req.target, "/json");
		if (ref) {
			r = dswebd_send_container_inspect(out_fd, ref, 0);
			free(ref);
			free(request);
			return r ? 0 : 1;
		}
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

	{
		char *error = NULL;

		if (!dswebd_check_backend(&error)) {
			bb_error_msg("warning: %s", error ? error : "backend handshake failed");
			bb_simple_error_msg("warning: continuing without backend handshake");
		}
		free(error);
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
