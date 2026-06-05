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

#define DS_SOCKETD_STATUS_OK 0u

#define DS_SOCKETD_CAP_PROTOCOL_V1 (1u << 0)
#define DS_SOCKETD_CAP_PING (1u << 1)
#define DS_SOCKETD_CAP_CAPABILITIES (1u << 2)

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

	if (req.is_get && dswebd_is_api_target(req.target, "/info")) {
		r = dswebd_send_info(out_fd, 0);
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
