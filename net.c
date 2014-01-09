/*
 * Copyright (C) 2013-2014 Canonical
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 */
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <dirent.h>

#include "list.h"
#include "proc.h"
#include "json.h"
#include "health-check.h"

#ifndef LINE_MAX
#define LINE_MAX	(4096)
#endif

#define NET_HASH_SIZE	(1993)

typedef struct {
	uint64_t        call_count;
	uint64_t        data_total;
} net_stats_t;

typedef struct {
	proc_info_t	*proc;
	uint64_t	inode;
	uint32_t	fd;
	net_stats_t	send;
	net_stats_t	recv;
} net_hash_t;

typedef enum {
	NET_TCP,
	NET_UDP,
	NET_UNIX,
} net_type_t;

typedef struct {
	net_type_t type;
	union {
		struct sockaddr_in  addr4;
		struct sockaddr_in6 addr6;
		char path[PATH_MAX + 1];
	} u;
	int family;
	uint64_t  inode;
} net_addr_info_t;

typedef struct {
	net_addr_info_t	*addr_info;
	net_hash_t	*nh;
	uint64_t	send_recv_total;
} net_dump_info_t;

static const char *net_types[] = {
	"TCP",
	"UDP",
	"UNIX",
};

/*
 *  Cache of addresses used by the applications.
 *  This shouldn't be too large, so O(n) lookup is
 *  just bearable for now.
 */
static list_t net_cached_addrs;

/*
 *  Hash table of inode to process mappings.
 */
static list_t net_hash_table[NET_HASH_SIZE];

/*
 *  net_hash()
 *	hash an inode, just modulo the table size for now
 */
static inline unsigned long net_hash(const uint64_t inode)
{
	return inode % NET_HASH_SIZE;
}

/*
 *  net_hash_add()
 *	add inode, pid and fd to inode hash table
 */
static net_hash_t *net_hash_add(const uint64_t inode, const pid_t pid, const uint32_t fd)
{
	net_hash_t *n;
	link_t *l;
	unsigned long h = net_hash(inode);

	/* Don't add it we have it already */
	for (l = net_hash_table[h].head; l; l = l->next) {
		n = (net_hash_t *)l->data;
		if (n->proc->pid == pid && n->inode == inode)
			return n;
	}

	if ((n = calloc(1, sizeof(*n))) == NULL) {
		health_check_out_of_memory("allocating net hash data");
		return NULL;
	}

	n->inode = inode;
	n->proc = proc_cache_find_by_pid(pid);
	n->fd = fd;

	if (list_append(&net_hash_table[h], n) == NULL) {
		free(n);
		return NULL;
	}

	return n;
}

/*
 *  net_hash_find_inode()
 *	given an inode, find the associated hash'd data
 */
static inline net_hash_t *net_hash_find_inode(const uint64_t inode)
{
	link_t *l;
	unsigned long h = net_hash(inode);

	/* Don't add it we have it already */
	for (l = net_hash_table[h].head; l; l = l->next) {
		net_hash_t *n = (net_hash_t *)l->data;
		if (n->inode == inode)
			return n;
	}
	return NULL;
}

/*
 *  net_get_inode()
 *	find inode in given readlink data, return -1 fail, 0 OK
 */
static int net_get_inode(const char *str, uint64_t *inode)
{
	size_t len = strlen(str);

	/* Likely */
	if (!strncmp(str, "socket:[", 8) && str[len - 1] == ']')
		return sscanf(str + 8, "%" SCNu64, inode) == 1 ? 0 : -1;

	/* Less likely */
	if (!strncmp(str, "[0000]:", 7))
		return sscanf(str + 7, "%" SCNu64, inode) == 1 ? 0 : -1;

	return -1;
}

/*
 *  net_get_inode_by_path()
 *	given a /proc/$pid/fd/fdnum path, look up a network inode
 */
static int net_get_inode_by_path(const char *path, uint64_t *inode)
{
	char link[PATH_MAX];
	ssize_t len;

	if ((len = readlink(path, link, sizeof(link) - 1)) < 0)
		return -1;
	link[len] = '\0';
	return net_get_inode(link, inode);
}

/*
 *  net_cache_inode_by_pid_and_fd()
 *	get a net hash given a file's owner pid and the fd
 */
static net_hash_t *net_cache_inode_by_pid_and_fd(const pid_t pid, const int fd)
{
	char path[PATH_MAX];
	uint64_t inode;
	net_hash_t *nh = NULL;

	snprintf(path, sizeof(path), "/proc/%i/fd/%i", pid, fd);
	if (net_get_inode_by_path(path, &inode) != -1)
		nh = net_hash_add(inode, pid, fd);

	return nh;
}

/*
 *  net_account_send()
 *	account for net send transfers
 */
void net_account_send(const pid_t pid, const int fd, size_t size)
{
	net_hash_t *nh = net_cache_inode_by_pid_and_fd(pid, fd);

	if (nh != NULL) {
		nh->send.call_count++;
		nh->send.data_total += size;
	}
}

/*
 *  net_account_recv()
 *	account for net receive transfers
 */
void net_account_recv(const pid_t pid, const int fd, size_t size)
{
	net_hash_t *nh = net_cache_inode_by_pid_and_fd(pid, fd);

	if (nh != NULL) {
		nh->recv.call_count++;
		nh->recv.data_total += size;
	}
}

/*
 *  net_cache_inodes_pid()
 *	given a pid, find all the network inodes associated
 *	with it's current file descriptors
 */
static int net_cache_inodes_pid(const pid_t pid)
{
	char path[PATH_MAX];
	DIR *fds;
	struct dirent *d;

	snprintf(path, sizeof(path), "/proc/%i/fd", pid);
	if ((fds = opendir(path)) == NULL)
		return -1;

	while ((d = readdir(fds)) != NULL) {
		uint64_t inode;
		char tmp[LINE_MAX];
		uint32_t fd;

		if (d->d_name[0] == '.')
			continue;
		if (strlen(path) + strlen(d->d_name) + 2 > sizeof(tmp))
			continue;
		snprintf(tmp, sizeof(tmp), "%s/%s", path, d->d_name);

		if (net_get_inode_by_path(tmp, &inode) != -1) {
			sscanf(d->d_name, "%" SCNu32, &fd);
			if (net_hash_add(inode, pid, fd) == NULL) {
				closedir(fds);
				return -1;
			}
		}
	}
	closedir(fds);

	return 0;
}

/*
 *  net_cache_inodes()
 *	given a list of pidis, find all the network inodes associated
 *	with the processes' current file descriptors
 */
static int net_cache_inodes(list_t *pids)
{
	link_t *l;

	for (l = pids->head; l; l = l->next) {
		proc_info_t *p = (proc_info_t *)l->data;
		if (net_cache_inodes_pid(p->pid) < 0)
			return -1;
	}
	return 0;
}

/*
 *  net_inet4_resolve()
 *	turn ipv4 addr to human readable address
 */
static void net_inet4_resolve(char *name, const size_t len, struct sockaddr_in *sin)
{
	if ((opt_flags & OPT_ADDR_RESOLVE) &&
	    (sin->sin_addr.s_addr != INADDR_ANY)) {
		struct hostent *e;

		e = gethostbyaddr((char *)&sin->sin_addr.s_addr, sizeof(struct in_addr), AF_INET);
		if (e) {
			strncpy(name, e->h_name, len - 1);
			name[len - 1] = '\0';
			return;
		}
	}
	inet_ntop(AF_INET, &sin->sin_addr, name, len);

	return;
}

/*
 *  net_inet6_resolve()
 *	turn ipv6 addr to human readable address
 */
static void net_inet6_resolve(char *name, const size_t len, struct sockaddr_in6 *sin6)
{
	if ((opt_flags & OPT_ADDR_RESOLVE) &&
	    (!IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr))) {
		struct hostent *e;

		e = gethostbyaddr((char *)&sin6->sin6_addr.s6_addr, sizeof(struct in6_addr), AF_INET);
		if (e) {

			strncpy(name, e->h_name, len - 1);
			name[len - 1] = '\0';
			return;
		}
	}
	inet_ntop(AF_INET6, &sin6->sin6_addr, name, len - 1);

	return;
}

/*
 *  net_addr_add()
 *	Add a new address to the cached list of addresses.
 *	This is an O(n) search and add, so we may need to
 *	re-work this if the number of addresses gets too large.
 */
static void net_addr_add(net_addr_info_t *addr)
{
	link_t *l;
	net_addr_info_t *new_addr;

	for (l = net_cached_addrs.head; l; l = l->next) {
		net_addr_info_t *old_addr = (net_addr_info_t *)l->data;

		if (memcmp(addr, old_addr, sizeof(*addr)) == 0)
			return;		/* Duplicate, ignore */
	}

	if ((new_addr = calloc(1, sizeof(*new_addr))) == NULL) {
		health_check_out_of_memory("allocating net address information");
		return;
	}
	memcpy(new_addr, addr, sizeof(*addr));
	if (list_append(&net_cached_addrs, new_addr) == NULL)
		free(new_addr);
}

/*
 *  net_get_addr()
 *	turn the addr info into human readable form
 */
static char *net_get_addr(net_addr_info_t *addr_info)
{
	static char tmp[256];
	char buf[4096];
	in_port_t port;

	switch (addr_info->type) {
	case NET_TCP:
	case NET_UDP:
		switch (addr_info->family) {
		case AF_INET6:
			net_inet6_resolve(buf, sizeof(buf), &addr_info->u.addr6);
			port = addr_info->u.addr6.sin6_port;
			break;
		case AF_INET:
			net_inet4_resolve(buf, sizeof(buf), &addr_info->u.addr4);
			port = addr_info->u.addr4.sin_port;
			break;
		default:
			/* No idea what it is */
			return NULL;
		}
		snprintf(tmp, sizeof(tmp), "%s:%d", buf, port);
		return tmp;
	case NET_UNIX:
		return addr_info->u.path;
	default:
		break;
	}
	return NULL;
}

/*
 *  net_add_dump_info()
 *	either accumulate existing send/recv net info, or add it if not
 *	already unique
 */
static void net_add_dump_info(list_t *list, net_dump_info_t *new_dump_info)
{
	link_t *l;

	for (l = list->head; l; l = l->next) {
		net_dump_info_t *dump_info = (net_dump_info_t *)l->data;

		if (dump_info->nh->proc == new_dump_info->nh->proc &&
		    dump_info->addr_info->type == new_dump_info->addr_info->type &&
		    memcmp(&dump_info->addr_info->u, &new_dump_info->addr_info->u, sizeof(dump_info->addr_info->u)) == 0 &&
		    dump_info->addr_info->family == new_dump_info->addr_info->family) {
			dump_info->nh->send.call_count += new_dump_info->nh->send.call_count;
			dump_info->nh->send.data_total += new_dump_info->nh->send.data_total;
			dump_info->nh->recv.call_count += new_dump_info->nh->recv.call_count;
			dump_info->nh->recv.data_total += new_dump_info->nh->recv.data_total;
			dump_info->send_recv_total += new_dump_info->send_recv_total;
			free(new_dump_info);
			return;
		}
	}
	list_append(list, new_dump_info);
}

/*
 *  net_dump_info_cmp()
 *  	Sort for dumping net send/recv stats, sorted on total
 *  	data send/recv and then if no difference on pid order
 */
static int net_dump_info_cmp(const void *p1, const void *p2)
{
	const net_dump_info_t *d1 = (const net_dump_info_t *)p1;
	const net_dump_info_t *d2 = (const net_dump_info_t *)p2;
	if (d2->send_recv_total - d1->send_recv_total == 0)
		return d1->nh->proc->pid - d2->nh->proc->pid;
	else
		return d2->send_recv_total - d1->send_recv_total;

}

/*
 *  net_size_to_str()
 *	turn transfer size in bytes to a more human readable form
 */
static void net_size_to_str(char *buf, size_t buf_len, uint64_t size)
{
	double s;
	char unit;

	if (size < 1024) {
 		s = (double)size;
		unit = 'B';
	} else if (size < 1024 * 1024) {
		s = (double)size / 1024.0;
		unit = 'K';
	} else {
		s = (double)size / (1024 * 1024);
		unit = 'M';
	}
	snprintf(buf, buf_len, "%7.2f %c", s, unit);
}

/*
 *  net_connection_dump()
 *	dump out network connections
 */
void net_connection_dump(json_object *j_tests, double duration)
{
	link_t *l;
	list_t dump_info_list;
	list_t sorted;
#ifdef JSON_OUTPUT
	json_object *j_net_test, *j_net_infos = NULL, *j_net_info;
	uint64_t send_total = 0, recv_total = 0;
#else
	(void)j_tests;
	(void)duration;
#endif

	printf("Open Network Connections:\n");

	list_init(&dump_info_list);
	list_init(&sorted);

#ifdef JSON_OUTPUT
	if (j_tests) {
		if ((j_net_test = j_obj_new_obj()) == NULL)
			goto out;
		j_obj_obj_add(j_tests, "network-connections", j_net_test);
		if ((j_net_infos = j_obj_new_array()) == NULL)
			goto out;
		j_obj_obj_add(j_net_test, "network-connections-per-process", j_net_infos);
	}
#endif

	/*
	 *   Collate data
	 */
	for (l = net_cached_addrs.head; l; l = l->next) {
		net_addr_info_t *addr_info = (net_addr_info_t *)l->data;
		link_t *ln;
		unsigned long h;

		h = net_hash(addr_info->inode);
		for (ln = net_hash_table[h].head; ln; ln = ln->next) {
			net_hash_t *nh = (net_hash_t *)ln->data;
			if (nh->inode == addr_info->inode) {
				net_dump_info_t *dump_info;

				/* Skip threads that do nothing */
				if ((nh->send.data_total + nh->recv.data_total == 0) && nh->proc->is_thread)
					continue;

				if ((dump_info = calloc(1, sizeof(net_dump_info_t))) == NULL)
					goto out;
				dump_info->addr_info = addr_info;
				dump_info->nh = nh;
				dump_info->send_recv_total = nh->send.data_total + nh->recv.data_total;

				net_add_dump_info(&dump_info_list, dump_info);
			}
		}
	}


	/*
	 *  We've now got a reduced list of useful data, so now sort it
	 */
	for (l = dump_info_list.head; l; l = l->next) {
		net_dump_info_t *dump_info = l->data;
		list_add_ordered(&sorted, dump_info, net_dump_info_cmp);
	}

	if (!dump_info_list.head) {
		printf(" None.\n\n");
	} else {
		printf("  PID  Process             Proto       Send   Receive  Address\n");
		for (l = sorted.head; l; l = l->next) {
			net_dump_info_t *dump_info = (net_dump_info_t *)l->data;
			char *addr = net_get_addr(dump_info->addr_info);
			char sendbuf[64], recvbuf[64];

			net_size_to_str(sendbuf, sizeof(sendbuf), dump_info->nh->send.data_total);
			net_size_to_str(recvbuf, sizeof(recvbuf), dump_info->nh->recv.data_total);

			printf(" %5i %-20.20s %-4.4s  %s %s  %s\n",
				dump_info->nh->proc->pid,
				dump_info->nh->proc->cmdline,
				net_types[dump_info->addr_info->type],
				sendbuf, recvbuf, addr);

#ifdef JSON_OUTPUT
			if (j_tests) {
				if ((j_net_info = j_obj_new_obj()) == NULL)
					goto out;
				j_obj_new_int32_add(j_net_info, "pid", dump_info->nh->proc->pid);
				j_obj_new_int32_add(j_net_info, "ppid", dump_info->nh->proc->ppid);
				j_obj_new_int32_add(j_net_info, "is-thread", dump_info->nh->proc->is_thread);
				j_obj_new_string_add(j_net_info, "name", dump_info->nh->proc->cmdline);
				j_obj_new_string_add(j_net_info, "protocol", net_types[dump_info->addr_info->type]);
				j_obj_new_string_add(j_net_info, "address", addr);
				j_obj_new_int64_add(j_net_info, "send", dump_info->nh->send.data_total);
				j_obj_new_int64_add(j_net_info, "receive", dump_info->nh->recv.data_total);
				j_obj_array_add(j_net_infos, j_net_info);
				send_total += dump_info->nh->send.data_total;
				recv_total += dump_info->nh->recv.data_total;
			}
#endif
		}
		printf("\n");
	}
#ifdef JSON_OUTPUT
	if (j_tests) {
		if ((j_net_info = j_obj_new_obj()) == NULL)
			goto out;
		j_obj_obj_add(j_net_test, "network-connections-total", j_net_info);
		j_obj_new_int64_add(j_net_info, "send-total", send_total);
		j_obj_new_int64_add(j_net_info, "receive-total", recv_total);
		j_obj_new_double_add(j_net_info, "send-total-rate", (double)send_total / duration);
		j_obj_new_double_add(j_net_info, "receive-total-rate", (double)recv_total / duration);
	}
#endif
out:
	list_free(&sorted, NULL);
	list_free(&dump_info_list, free);

	return;
}

/*
 *  net_unix_parse()
 *	parse /proc/net/unix and cache data
 */
static int net_unix_parse(void)
{
	FILE *fp;
	char buf[4096];
	int i;

	if ((fp = fopen("/proc/net/unix", "r")) == NULL) {
		fprintf(stderr, "Cannot open /proc/net/unix\n");
		return -1;
	}

	for (i = 0; fgets(buf, sizeof(buf), fp) != NULL; i++) {
		uint64_t inode;
		char path[4096];
		net_addr_info_t new_addr;

		if (i == 0)  /* Skip header */
			continue;

		sscanf(buf, "%*x: %*x %*x %*x %*x %*x %" SCNu64 " %s\n",
			&inode, path);

		memset(&new_addr, 0, sizeof(new_addr));
		new_addr.inode = inode;
		new_addr.type = NET_UNIX;
		strncpy(new_addr.u.path, path, PATH_MAX);
		net_addr_add(&new_addr);
	}
	fclose(fp);

	return 0;
}

/*
 *  net_tcp_udp_parse()
 *	parse /proc/net/{tcp,udp} and cache data for
 *	faster lookup
 */
static int net_tcp_udp_parse(const net_type_t type)
{
	FILE *fp;
	char *procfile;
	char buf[4096];
	char addr_str[128];
	in_port_t port;
	int i;
	uint64_t inode;

	switch (type) {
	case NET_TCP:
		procfile = "/proc/net/tcp";
		break;
	case NET_UDP:
		procfile = "/proc/net/udp";
		break;
	default:
		fprintf(stderr, "net_parse given bad net type.\n");
		return -1;
	}

	if ((fp = fopen(procfile, "r")) == NULL) {
		fprintf(stderr, "Cannot open %s.\n", procfile);
		return -1;
	}

	for (i = 0; fgets(buf, sizeof(buf), fp) != NULL; i++) {
		net_addr_info_t new_addr;

		if (i == 0)  /* Skip header */
			continue;

		sscanf(buf,
			"%*d: %*64[0-9A-Fa-f]:%*X %64[0-9A-Fa-f]:%" SCNx16
			" %*X %*X:%*X %*X:%*X %*X %*d %*d %" SCNu64,
			addr_str, &port, &inode);

		memset(&new_addr, 0, sizeof(new_addr));
		new_addr.inode = inode;
		new_addr.type = type;
		if (strlen(addr_str) > 8) {
			new_addr.family = new_addr.u.addr6.sin6_family = AF_INET6;
			new_addr.u.addr6.sin6_port = port;
			sscanf(addr_str, "%08X%08X%08X%08X",
				&new_addr.u.addr6.sin6_addr.s6_addr32[0],
				&new_addr.u.addr6.sin6_addr.s6_addr32[1],
				&new_addr.u.addr6.sin6_addr.s6_addr32[2],
				&new_addr.u.addr6.sin6_addr.s6_addr32[3]);
		} else {
			new_addr.family = new_addr.u.addr4.sin_family = AF_INET;
			new_addr.u.addr4.sin_port = port;
			sscanf(addr_str, "%8X", &new_addr.u.addr4.sin_addr.s_addr);
		}
		net_addr_add(&new_addr);
	}
	fclose(fp);

	return 0;
}

/*
 *  net_parse()
 *	parse various /proc net files
 */
static int net_parse(void)
{
	if (net_tcp_udp_parse(NET_TCP) < 0)
		return -1;
	if (net_tcp_udp_parse(NET_UDP) < 0)
		return -1;
	if (net_unix_parse() < 0)
		return -1;

	return 0;
}

/*
 *  net_connection_pids()
 *	find network inodes assocated with given
 *	pids and find network addresses
 */
int net_connection_pids(list_t *pids)
{
	if (net_cache_inodes(pids) < 0)
		return -1;
	return net_parse();
}

/*
 *  net_connection_pid()
 *	find network inodes assocated with given
 *	pid and find network addresses
 */
int net_connection_pid(const pid_t pid)
{
	if (net_cache_inodes_pid(pid) < 0)
		return -1;
	return net_parse();
}

/*
 *  net_connection_init()
 *	initialise
 */
void net_connection_init(void)
{
	int i;

	list_init(&net_cached_addrs);
	for (i = 0; i < NET_HASH_SIZE; i++)
		list_init(&net_hash_table[i]);
}

/*
 *  net_connection_cleanup()
 *	tidy up behind ourselves
 */
void net_connection_cleanup(void)
{
	int i;

	list_free(&net_cached_addrs, free);
	for (i = 0; i < NET_HASH_SIZE; i++)
		list_free(&net_hash_table[i], free);
}
