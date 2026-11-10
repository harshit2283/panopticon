/*
 * tcp_repair.c: a CRIU-style TCP repair round trip for the T-22 lab test
 * (scope_lab.py t22, DESIGN §3.3 "TCP repair").
 *
 *   tcp_repair HOST PORT TAG [uring]
 *
 * Connects, sends 3000 bytes of history and reads the peer's 3000, so the
 * stream is past any small head_only N. Then dumps the connection in repair
 * mode (sequence numbers, window, MSS), closes it silently, and restores it
 * on a new socket bound to the same address: TCP_QUEUE_SEQ for both queues,
 * a repair-mode connect (no handshake), the window and MSS, repair off.
 * Finally sends 2000 bytes carrying "B1T22OUTC<TAG>" markers and reads the
 * peer's 2000-byte reply. With "uring", every setsockopt of the restore goes
 * through io_uring (IORING_OP_URING_CMD, SOCKET_URING_OP_SETSOCKOPT, Linux
 * 6.7+) instead of the syscall. Build both ABIs, statically:
 *   gcc -O2 -static -o tcp_repair tcp_repair.c
 *   gcc -O2 -static -m32 -o tcp_repair32 tcp_repair.c
 * Needs CAP_NET_ADMIN. Exit 0 and "restored" on stdout on success.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <linux/io_uring.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef TCP_REPAIR_WINDOW
#define TCP_REPAIR_WINDOW 29
struct tcp_repair_window {
	uint32_t snd_wl1, snd_wnd, max_window, rcv_wnd, rcv_wup;
};
#endif
#ifndef __NR_io_uring_setup
#define __NR_io_uring_setup 425
#define __NR_io_uring_enter 426
#endif

static int use_uring;
static int ring_fd = -1;
static unsigned *sq_tail, *sq_mask, *sq_array, *cq_head, *cq_tail, *cq_mask;
static struct io_uring_sqe *sqes;
static struct io_uring_cqe *cqes;

static void die(const char *what)
{
	fprintf(stderr, "tcp_repair: %s: %s\n", what, strerror(errno));
	exit(1);
}

static void ring_setup(void)
{
	struct io_uring_params p;
	memset(&p, 0, sizeof(p));
	ring_fd = syscall(__NR_io_uring_setup, 4, &p);
	if (ring_fd < 0)
		die("io_uring_setup");
	size_t sq_len = p.sq_off.array + p.sq_entries * sizeof(unsigned);
	size_t cq_len = p.cq_off.cqes + p.cq_entries * sizeof(struct io_uring_cqe);
	char *sq = mmap(0, sq_len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, ring_fd,
			IORING_OFF_SQ_RING);
	char *cq = mmap(0, cq_len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, ring_fd,
			IORING_OFF_CQ_RING);
	sqes = mmap(0, p.sq_entries * sizeof(struct io_uring_sqe), PROT_READ | PROT_WRITE,
		    MAP_SHARED | MAP_POPULATE, ring_fd, IORING_OFF_SQES);
	if (sq == MAP_FAILED || cq == MAP_FAILED || sqes == MAP_FAILED)
		die("mmap io_uring");
	sq_tail = (unsigned *)(sq + p.sq_off.tail);
	sq_mask = (unsigned *)(sq + p.sq_off.ring_mask);
	sq_array = (unsigned *)(sq + p.sq_off.array);
	cq_head = (unsigned *)(cq + p.cq_off.head);
	cq_tail = (unsigned *)(cq + p.cq_off.tail);
	cq_mask = (unsigned *)(cq + p.cq_off.ring_mask);
	cqes = (struct io_uring_cqe *)(cq + p.cq_off.cqes);
}

/* setsockopt through io_uring: one URING_CMD, waited for. */
static int uring_setsockopt(int fd, int level, int name, const void *val, int len)
{
	unsigned tail = *sq_tail, idx = tail & *sq_mask;
	struct io_uring_sqe *sqe = &sqes[idx];
	memset(sqe, 0, sizeof(*sqe));
	sqe->opcode = IORING_OP_URING_CMD;
	sqe->fd = fd;
	sqe->cmd_op = SOCKET_URING_OP_SETSOCKOPT;
	sqe->level = level;
	sqe->optname = name;
	sqe->optval = (uint64_t)(uintptr_t)val;
	sqe->optlen = len;
	sq_array[idx] = idx;
	__atomic_store_n(sq_tail, tail + 1, __ATOMIC_RELEASE);
	if (syscall(__NR_io_uring_enter, ring_fd, 1, 1, IORING_ENTER_GETEVENTS, NULL, 0) < 0)
		return -1;
	unsigned head = __atomic_load_n(cq_head, __ATOMIC_ACQUIRE);
	if (head == __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE)) {
		errno = EIO;
		return -1;
	}
	int res = cqes[head & *cq_mask].res;
	__atomic_store_n(cq_head, head + 1, __ATOMIC_RELEASE);
	if (res < 0) {
		errno = -res;
		return -1;
	}
	return 0;
}

static void sso(int fd, int level, int name, const void *val, int len, const char *what)
{
	int rc = use_uring ? uring_setsockopt(fd, level, name, val, len)
			   : setsockopt(fd, level, name, val, len);
	if (rc != 0)
		die(what);
}

static void sso_int(int fd, int level, int name, int v, const char *what)
{
	sso(fd, level, name, &v, sizeof(v), what);
}

static void send_all(int fd, const char *buf, size_t len)
{
	while (len) {
		ssize_t n = send(fd, buf, len, 0);
		if (n <= 0)
			die("send");
		buf += n;
		len -= n;
	}
}

static void recv_all(int fd, char *buf, size_t len)
{
	while (len) {
		ssize_t n = recv(fd, buf, len, 0);
		if (n <= 0)
			die("recv");
		buf += n;
		len -= n;
	}
}

/* `len` bytes of 32-byte records "<prefix><TAG>-<n>|...". */
static void fill(char *buf, size_t len, const char *prefix, const char *tag)
{
	char rec[33];
	for (size_t off = 0; off < len; off += 32) {
		int n = snprintf(rec, sizeof(rec), "%s%s-%06zu|", prefix, tag, off / 32);
		memset(rec + n, '.', 32 - n);
		memcpy(buf + off, rec, len - off < 32 ? len - off : 32);
	}
}

int main(int argc, char **argv)
{
	if (argc < 4) {
		fprintf(stderr, "usage: tcp_repair HOST PORT TAG [uring]\n");
		return 2;
	}
	use_uring = argc > 4 && strcmp(argv[4], "uring") == 0;
	struct sockaddr_in peer = {.sin_family = AF_INET, .sin_port = htons(atoi(argv[2]))};
	inet_pton(AF_INET, argv[1], &peer.sin_addr);
	const char *tag = argv[3];
	static char buf[4096];

	int s = socket(AF_INET, SOCK_STREAM, 0);
	if (s < 0 || connect(s, (struct sockaddr *)&peer, sizeof(peer)) != 0)
		die("connect");
	fill(buf, 3000, "B1T22HISTC", tag);
	send_all(s, buf, 3000);
	recv_all(s, buf, 3000);
	usleep(200000); /* let the ACKs settle: both queues empty */

	/* Dump. */
	int one = 1;
	if (setsockopt(s, IPPROTO_TCP, TCP_REPAIR, &one, sizeof(one)) != 0)
		die("TCP_REPAIR on (dump)");
	struct sockaddr_in local;
	socklen_t alen = sizeof(local);
	if (getsockname(s, (struct sockaddr *)&local, &alen) != 0)
		die("getsockname");
	uint32_t snd_seq, rcv_seq;
	socklen_t olen = sizeof(uint32_t);
	int q = TCP_SEND_QUEUE;
	if (setsockopt(s, IPPROTO_TCP, TCP_REPAIR_QUEUE, &q, sizeof(q)) != 0 ||
	    getsockopt(s, IPPROTO_TCP, TCP_QUEUE_SEQ, &snd_seq, &olen) != 0)
		die("dump send seq");
	q = TCP_RECV_QUEUE;
	if (setsockopt(s, IPPROTO_TCP, TCP_REPAIR_QUEUE, &q, sizeof(q)) != 0 ||
	    getsockopt(s, IPPROTO_TCP, TCP_QUEUE_SEQ, &rcv_seq, &olen) != 0)
		die("dump recv seq");
	struct tcp_repair_window win;
	olen = sizeof(win);
	if (getsockopt(s, IPPROTO_TCP, TCP_REPAIR_WINDOW, &win, &olen) != 0)
		die("dump window");
	int mss;
	olen = sizeof(mss);
	if (getsockopt(s, IPPROTO_TCP, TCP_MAXSEG, &mss, &olen) != 0)
		die("dump mss");
	close(s); /* in repair mode: no FIN, no RST */

	/* Restore. */
	if (use_uring)
		ring_setup();
	int n = socket(AF_INET, SOCK_STREAM, 0);
	if (n < 0)
		die("socket");
	/* Repair mode forces address reuse for the bind; a later SO_REUSEADDR
	 * would downgrade that and collide with the dumped socket's port. */
	sso_int(n, IPPROTO_TCP, TCP_REPAIR, 1, "TCP_REPAIR on");
	if (bind(n, (struct sockaddr *)&local, sizeof(local)) != 0)
		die("bind");
	sso_int(n, IPPROTO_TCP, TCP_REPAIR_QUEUE, TCP_RECV_QUEUE, "queue recv");
	sso(n, IPPROTO_TCP, TCP_QUEUE_SEQ, &rcv_seq, sizeof(rcv_seq), "recv seq");
	sso_int(n, IPPROTO_TCP, TCP_REPAIR_QUEUE, TCP_SEND_QUEUE, "queue send");
	sso(n, IPPROTO_TCP, TCP_QUEUE_SEQ, &snd_seq, sizeof(snd_seq), "send seq");
	if (connect(n, (struct sockaddr *)&peer, sizeof(peer)) != 0)
		die("repair connect");
	struct tcp_repair_opt opt = {.opt_code = TCPOPT_MAXSEG, .opt_val = (uint32_t)mss};
	sso(n, IPPROTO_TCP, TCP_REPAIR_OPTIONS, &opt, sizeof(opt), "repair options");
	sso(n, IPPROTO_TCP, TCP_REPAIR_WINDOW, &win, sizeof(win), "repair window");
	sso_int(n, IPPROTO_TCP, TCP_REPAIR, 0, "TCP_REPAIR off");

	fill(buf, 2000, "B1T22OUTC", tag);
	send_all(n, buf, 2000);
	recv_all(n, buf, 2000);
	close(n);
	printf("restored %s%s\n", tag, use_uring ? " (io_uring)" : "");
	return 0;
}
