// Kernel TLS fixtures for run_scope.sh (DESIGN T-21). One loopback
// connection A on PORT, both ends in this process; built static, 64- and
// 32-bit (the 32-bit build reaches the kernel through the compat paths):
//
//   ktls_drv ulp   PORT TAG N   TCP_ULP "tls" on both ends of A, no keys:
//                               an ordinary socket, plaintext on the wire
//   ktls_drv keys  PORT TAG N   as ulp, plus TLS_TX and TLS_RX (AES-GCM-128):
//                               ciphertext on the wire
//   ktls_drv uring PORT TAG N   as ulp, the ULP set through io_uring
//                               (SOCKET_URING_OP_SETSOCKOPT, Linux 6.7+)
//   ktls_drv half  PORT TAG N   as ulp, plus a TLS_RX key on the client end
//                               and a TLS_TX key on the server end: both ends
//                               have a key installed, and the client's
//                               markers are plaintext on the wire (the
//                               packet-path view of hardware offload)
//   ktls_drv uhalf PORT TAG N   as half, ULP and keys through io_uring (6.7+)
//   ktls_drv recv  PORT TAG N   as half, and what A's server end receives is
//   ktls_drv splice PORT TAG N  relayed to an ordinary connection B on
//                               PORT+1, by read+write or by splice
//
// Each end of A sends N markers "B2M-<TAG>-<i>" (the client B2M-TAG-c<i>,
// the server B2M-TAG-s<i>), 20 ms apart. Prints "OK <mode>" on success.
// Build: gcc -O2 -static ktls_drv.c -o ktls_drv64; gcc -O2 -static -m32 ...
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#define SOL_TCP_ 6
#define TCP_ULP_ 31
#define SOL_TLS_ 282
#define TLS_TX_ 1
#define TLS_RX_ 2

static void die(const char *what)
{
	fprintf(stderr, "ktls_drv: %s: %s\n", what, strerror(errno));
	exit(1);
}

static struct sockaddr_in addr(int port)
{
	struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port)};
	a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	return a;
}

// A connected pair on port: *c the client, *s the accepted server end.
static void pair(int port, int *c, int *s)
{
	int l = socket(AF_INET, SOCK_STREAM, 0), one = 1;
	struct sockaddr_in a = addr(port);
	setsockopt(l, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	if (bind(l, (void *)&a, sizeof(a)) || listen(l, 4))
		die("listen");
	*c = socket(AF_INET, SOCK_STREAM, 0);
	if (connect(*c, (void *)&a, sizeof(a)))
		die("connect");
	*s = accept(l, 0, 0);
	if (*s < 0)
		die("accept");
	close(l);
}

static void ulp(int fd)
{
	if (setsockopt(fd, SOL_TCP_, TCP_ULP_, "tls", 3))
		die("setsockopt TCP_ULP");
}

// struct tls12_crypto_info_aes_gcm_128
struct gcm128 {
	uint16_t version, cipher;
	uint8_t iv[8], key[16], salt[4], rec_seq[8];
};

static struct gcm128 key(void)
{
	struct gcm128 k = {.version = 0x0303, .cipher = 51};
	memset(k.key, 7, sizeof(k.key));
	memset(k.iv, 3, sizeof(k.iv));
	return k;
}

static void key_dir(int fd, int dir)
{
	struct gcm128 k = key();
	if (setsockopt(fd, SOL_TLS_, dir, &k, sizeof(k)))
		die(dir == TLS_TX_ ? "setsockopt TLS_TX" : "setsockopt TLS_RX");
}

static void keys(int fd)
{
	key_dir(fd, TLS_TX_);
	key_dir(fd, TLS_RX_);
}

// io_uring with one SQE: IORING_OP_URING_CMD / SOCKET_URING_OP_SETSOCKOPT.
struct sqring_off {
	uint32_t head, tail, ring_mask, ring_entries, flags, dropped, array, resv1;
	uint64_t user_addr;
};
struct cqring_off {
	uint32_t head, tail, ring_mask, ring_entries, overflow, cqes, flags, resv1;
	uint64_t user_addr;
};
struct uring_params {
	uint32_t sq_entries, cq_entries, flags, sq_thread_cpu, sq_thread_idle, features, wq_fd, resv[3];
	struct sqring_off sq_off;
	struct cqring_off cq_off;
};
struct sqe {
	uint8_t opcode, flags;
	uint16_t ioprio;
	int32_t fd;
	uint32_t cmd_op, pad1;
	uint32_t level, optname;
	uint32_t len, rw_flags;
	uint64_t user_data;
	uint16_t buf_index, personality;
	uint32_t optlen;
	uint64_t optval, pad2;
};

static void uring_setsockopt(int fd, int level, int optname, const void *val, int len, const char *what)
{
	struct uring_params p;
	memset(&p, 0, sizeof(p));
	int r = syscall(__NR_io_uring_setup, 4, &p);
	if (r < 0)
		die("io_uring_setup");
	size_t sqsz = p.sq_off.array + p.sq_entries * 4, cqsz = p.cq_off.cqes + p.cq_entries * 16;
	char *sq = mmap(0, sqsz, PROT_READ | PROT_WRITE, MAP_SHARED, r, 0);
	char *cq = mmap(0, cqsz, PROT_READ | PROT_WRITE, MAP_SHARED, r, 0x8000000);
	struct sqe *sqes = mmap(0, p.sq_entries * sizeof(struct sqe), PROT_READ | PROT_WRITE, MAP_SHARED, r,
				0x10000000);
	if (sq == MAP_FAILED || cq == MAP_FAILED || sqes == MAP_FAILED)
		die("mmap io_uring");
	memset(&sqes[0], 0, sizeof(sqes[0]));
	sqes[0].opcode = 46; // IORING_OP_URING_CMD
	sqes[0].fd = fd;
	sqes[0].cmd_op = 3; // SOCKET_URING_OP_SETSOCKOPT
	sqes[0].level = level;
	sqes[0].optname = optname;
	sqes[0].optlen = len;
	sqes[0].optval = (uintptr_t)val;
	uint32_t *tail = (uint32_t *)(sq + p.sq_off.tail);
	((uint32_t *)(sq + p.sq_off.array))[*tail & *(uint32_t *)(sq + p.sq_off.ring_mask)] = 0;
	__atomic_store_n(tail, *tail + 1, __ATOMIC_RELEASE);
	if (syscall(__NR_io_uring_enter, r, 1, 1, 1 /* GETEVENTS */, 0, 0) < 0)
		die("io_uring_enter");
	uint32_t head = *(uint32_t *)(cq + p.cq_off.head);
	int32_t res = *(int32_t *)(cq + p.cq_off.cqes + (head & *(uint32_t *)(cq + p.cq_off.ring_mask)) * 16 + 8);
	if (res < 0) {
		errno = -res;
		die(what);
	}
	close(r);
}

static void uring_ulp(int fd)
{
	uring_setsockopt(fd, SOL_TCP_, TCP_ULP_, "tls", 3, "io_uring setsockopt TCP_ULP");
}

static void uring_key_dir(int fd, int dir)
{
	struct gcm128 k = key();
	uring_setsockopt(fd, SOL_TLS_, dir, &k, sizeof(k), "io_uring setsockopt SOL_TLS");
}

static void readn(int fd, char *buf, int n)
{
	for (int got = 0; got < n;) {
		int r = read(fd, buf + got, n - got);
		if (r <= 0)
			die("read");
		got += r;
	}
}

int main(int argc, char **argv)
{
	if (argc < 5) {
		fprintf(stderr, "usage: ktls_drv ulp|keys|uring|half|uhalf|recv|splice PORT TAG N\n");
		return 2;
	}
	const char *mode = argv[1], *tag = argv[3];
	int port = atoi(argv[2]), n = atoi(argv[4]), c, s, bc = -1, bs = -1;
	pair(port, &c, &s);
	int relay = !strcmp(mode, "recv") || !strcmp(mode, "splice");
	if (!strcmp(mode, "uring") || !strcmp(mode, "uhalf")) {
		uring_ulp(c);
		uring_ulp(s);
	} else {
		ulp(c);
		ulp(s);
	}
	if (!strcmp(mode, "keys")) {
		keys(c);
		keys(s);
	} else if (!strcmp(mode, "uhalf")) {
		uring_key_dir(c, TLS_RX_);
		uring_key_dir(s, TLS_TX_);
	} else if (!strcmp(mode, "half") || relay) {
		key_dir(c, TLS_RX_);
		key_dir(s, TLS_TX_);
	}
	if (relay)
		pair(port + 1, &bc, &bs);
	int pipefd[2];
	if (!strcmp(mode, "splice") && pipe(pipefd))
		die("pipe");
	for (int i = 0; i < n; i++) {
		char m[64], buf[64];
		int len = snprintf(m, sizeof(m), "B2M-%s-c%d\n", tag, i);
		if (write(c, m, len) != len)
			die("write");
		if (!relay) {
			readn(s, buf, len);
		} else if (!strcmp(mode, "recv")) {
			readn(s, buf, len);
			if (write(bc, buf, len) != len)
				die("relay write");
			readn(bs, buf, len);
		} else {
			for (int got = 0; got < len;) {
				ssize_t r = splice(s, 0, pipefd[1], 0, len - got, 0);
				if (r <= 0)
					die("splice in");
				got += r;
			}
			for (int put = 0; put < len;) {
				ssize_t r = splice(pipefd[0], 0, bc, 0, len - put, 0);
				if (r <= 0)
					die("splice out");
				put += r;
			}
			readn(bs, buf, len);
		}
		if (memcmp(buf, m, len))
			die("relayed bytes differ");
		len = snprintf(m, sizeof(m), "B2M-%s-s%d\n", tag, i);
		if (write(s, m, len) != len)
			die("write");
		readn(c, buf, len);
		usleep(20000);
	}
	printf("OK %s\n", mode);
	return 0;
}
