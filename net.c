/*
 * Copyright (C) 2013 Canonical
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
	proc_info_t	*proc;
	uint64_t	inode;
	uint32_t	fd;
} net_hash_t;

typedef enum {
	NET_TCP,
	NET_UDP,
} net_type_t;

typedef struct {
	net_type_t type;
	union {
		struct sockaddr_in  addr4;
		struct sockaddr_in6 addr6;
	} u;
	int family;
	proc_info_t *proc;
} net_addr_info_t;

static const char *net_types[] = {
	"TCP",
	"UDP"
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
static void net_hash_add(uint64_t inode, pid_t pid, uint32_t fd)
{
	net_hash_t *n;
	link_t *l;
	unsigned long h = net_hash(inode);

	/* Don't add it we have it already */
	for (l = net_hash_table[h].head; l; l = l->next) {
		n = (net_hash_t *)l->data;
		if (n->proc->pid == pid && n->inode == inode)
			return;
	}

	if ((n = calloc(1, sizeof(*n))) == NULL)
		health_check_out_of_memory("allocating net hash data");

	n->inode = inode;
	n->proc = proc_cache_find_by_pid(pid);
	n->fd = fd;

	list_append(&net_hash_table[h], n);
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
		ssize_t len;
		uint64_t inode;
		char tmp[LINE_MAX];
		char link[64];
		uint32_t fd;

		if (strlen(path) + strlen(d->d_name) + 2 > sizeof(tmp))
			continue;
		snprintf(tmp, sizeof(tmp), "%s/%s", path, d->d_name);
		if ((len = readlink(tmp, link, sizeof(link) - 1)) < 0)
			continue;
		link[len] = '\0';

		if (net_get_inode(link, &inode) != -1) {
			sscanf(d->d_name, "%" SCNu32, &fd);
			net_hash_add(inode, pid, fd);
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
static void net_cache_inodes(list_t *pids)
{
	link_t *l;

	for (l = pids->head; l; l = l->next) {
		proc_info_t *p = (proc_info_t *)l->data;
		net_cache_inodes_pid(p->pid);
	}
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
 *  net_pid_cmp()
 *	list sort compare, sort by pid
 */
static int net_pid_cmp(const void *data1, const void *data2)
{
	net_addr_info_t *n1 = (net_addr_info_t *)data1;
	net_addr_info_t *n2 = (net_addr_info_t *)data2;

	return n1->proc->pid - n2->proc->pid;
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

	if ((new_addr = calloc(1, sizeof(*new_addr))) == NULL)
		health_check_out_of_memory("allocating net address information");
	memcpy(new_addr, addr, sizeof(*addr));
	list_add_ordered(&net_cached_addrs, new_addr, net_pid_cmp);
}

/*
 *  net_connection_dump()
 *	dump out network connections
 */
void net_connection_dump(json_object *j_tests)
{
	link_t *l;
	char buf[4096];
#ifdef JSON_OUTPUT
	json_object *j_net_test, *j_net_infos = NULL, *j_net_info;
#else
	(void)j_tests;
#endif

	printf("Open Network Connections:\n");
	if (!net_cached_addrs.head) {
		printf(" None.\n\n");
		return;
	}

#ifdef JSON_OUTPUT
	if (j_tests) {
		j_obj_obj_add(j_tests, "network-connections", (j_net_test = j_obj_new_obj()));
		j_obj_obj_add(j_net_test, "network-connections-per-process", (j_net_infos = j_obj_new_array()));
	}
#endif

	printf("  PID  Process             Proto  Address:Port\n");
	for (l = net_cached_addrs.head; l; l = l->next) {
		net_addr_info_t *addr_info = (net_addr_info_t *)l->data;
		in_port_t port;

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
			continue;
		}
		printf("%6u %-20.20s %s   %s:%d\n", 
			addr_info->proc->pid, addr_info->proc->cmdline,
			net_types[addr_info->type], buf, port);

#ifdef JSON_OUTPUT
		if (j_tests) {
			j_net_info = j_obj_new_obj();
			j_obj_new_int32_add(j_net_info, "pid", addr_info->proc->pid);
			j_obj_new_int32_add(j_net_info, "ppid", addr_info->proc->ppid);
			j_obj_new_int32_add(j_net_info, "is-thread", addr_info->proc->is_thread);
			j_obj_new_string_add(j_net_info, "name", addr_info->proc->cmdline);
			j_obj_new_string_add(j_net_info, "protocol", net_types[addr_info->type]);
			j_obj_new_string_add(j_net_info, "address", buf);
			j_obj_new_int32_add(j_net_info, "port", (int32_t)port);
			j_obj_array_add(j_net_infos, j_net_info);
		}
#endif
	}
	printf("\n");
}

/*
 *  net_parse()
 *	parse /proc/net/{tcp,udp} and cache data for
 *	faster lookup
 */
static int net_parse(const net_type_t type)
{
	FILE *fp;
	char *procfile;
	char buf[4096];
	char addr_str[128];
	in_port_t port;
	int i;
	uint64_t inode;
	net_hash_t *nh;

	switch (type) {
	case NET_TCP:
		procfile = "/proc/net/tcp";
		break;
	case NET_UDP:
		procfile = "/proc/net/udp";
		break;
	default:
		fprintf(stderr, "net_parse given bad net type\n");
		return -1;
	}

	if ((fp = fopen(procfile, "r")) == NULL) {
		fprintf(stderr, "Cannot open %s\n", procfile);
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

		if ((nh = net_hash_find_inode(inode)) == NULL)
			continue;

		new_addr.proc = nh->proc;
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
			sscanf(addr_str, "%X", &new_addr.u.addr4.sin_addr.s_addr);
		}
		net_addr_add(&new_addr);
	}
	fclose(fp);

	return 0;
}

/*
 *  net_connection_pids()
 *	find network inodes assocated with given
 *	pids and find network addresses
 */
int net_connection_pids(list_t *pids)
{
	net_cache_inodes(pids);
	if (net_parse(NET_TCP) < 0)
		return -1;
	if (net_parse(NET_UDP) < 0)
		return -1;

	return 0;
}

/*
 *  net_connection_pids()
 *	find network inodes assocated with given
 *	pids and find network addresses
 */
int net_connection_pid(pid_t pid)
{
	net_cache_inodes_pid(pid);
	if (net_parse(NET_TCP) < 0)
		return -1;
	if (net_parse(NET_UDP) < 0)
		return -1;

	return 0;
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
