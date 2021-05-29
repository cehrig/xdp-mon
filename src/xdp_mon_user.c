#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdlib.h>
#include <ifaddrs.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <sys/resource.h>
#include <signal.h>
#include <errno.h>
#include <error.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "common.h"

typedef struct ifs_fd {
    int ifs_ix;
    int prog_fd;
    int map_fd;
    int btf_fd;
} t_ifs_fd;

typedef struct ifsarr {
    int *ifs_ix;
    int len;
} t_ifsarr;

t_ifs_fd **ifs_fd = NULL;
t_out_comms comms;
__u32 pkt_count;

int _if_index(char *name)
{
    int if_index;

    if (!(if_index = if_nametoindex(name))) {
        return -1;
    }

    return if_index;
}

int _if_in_ifsarr(struct ifsarr ifsarr, int if_index)
{
    for (int i = 0; i < ifsarr.len; i++) {
        if (ifsarr.ifs_ix[i] == if_index) {
            return 1;
        }
    }
    return 0;
}

int _ct_ifs_fd()
{
    int len = 0;

    t_ifs_fd **_ifs_fd = ifs_fd;
    if (_ifs_fd == NULL) {
        return 0;
    }

    while(*_ifs_fd != NULL) {
        len++;
        _ifs_fd++;
    }

    return len;
}

void _add_ifs_fd(int if_index, int map_fd, int prog_fd, int btf_fd)
{
    int ifs_fd_len = _ct_ifs_fd();

    ifs_fd = realloc(ifs_fd, (ifs_fd_len+2) * sizeof(t_ifs_fd *));
    ifs_fd[ifs_fd_len] = malloc(sizeof(t_ifs_fd));
    ifs_fd[ifs_fd_len+1] = NULL;

    ifs_fd[ifs_fd_len]->ifs_ix = if_index;
    ifs_fd[ifs_fd_len]->map_fd = map_fd;
    ifs_fd[ifs_fd_len]->prog_fd = prog_fd;
    ifs_fd[ifs_fd_len]->btf_fd = btf_fd;
}

t_ifs_fd *_ifs_fd_by_if_index(int if_index)
{
    t_ifs_fd **_ifs_fd = ifs_fd;
    if (_ifs_fd == NULL) {
        return NULL;
    }

    while(*_ifs_fd != NULL) {
        if ((*_ifs_fd)->ifs_ix == if_index) {
            return *_ifs_fd;
        }
        _ifs_fd++;
    }

    return NULL;
}

void _cleanup_ifs_fd()
{
    t_ifs_fd **_ifs_fd = ifs_fd;
    if (_ifs_fd != NULL) {
        while(*_ifs_fd != NULL) {
            free(*_ifs_fd);
            _ifs_fd++;
        }
        free(ifs_fd);
        ifs_fd = NULL;
    }
}

void _rm_comms_client_fd(int _i)
{
    close(comms.client_fds[_i]);

    for (int i = 0; i < comms.client_num; i++) {
        if (i >= _i && i < comms.client_num-1) {
            comms.client_fds[i] = comms.client_fds[i+1];
        }
    }

    comms.client_num--;
    comms.client_fds = realloc(comms.client_fds, comms.client_num * sizeof(int));
    if (comms.client_num > 0 && comms.client_fds == NULL) {
        error(0, errno, "_realloc(comms.client_fds)");
        raise(SIGTERM);
    }
}

void _write_comms_pkt_buf(void * data, size_t len)
{
    pthread_mutex_lock(&comms.mtx_buf);

    // let's protect ourselves from overflows
    if (comms.pkt_buf_num > INT32_MAX) {
        goto unlock;
    }

    comms.pkt_buf_num++;

    comms.pkt_buf = realloc(comms.pkt_buf, comms.pkt_buf_num * sizeof(t_in_pkt));
    if (comms.pkt_buf == NULL) {
        pthread_mutex_unlock(&comms.mtx_buf);
        error(0, errno, "realloc(comms.pkt_buf)");
        raise(SIGTERM);
    }

    memcpy(&comms.pkt_buf[comms.pkt_buf_num-1], data, len);

    unlock:
    pthread_mutex_unlock(&comms.mtx_buf);
}

void _add_comms_client_fd(int fd)
{
    pthread_mutex_lock(&comms.mtx);

    comms.client_num++;
    comms.client_fds = realloc(comms.client_fds, comms.client_num * sizeof(int));

    if (comms.client_fds == NULL) {
        pthread_mutex_unlock(&comms.mtx);
        error(0, errno, "realloc(comms.client_fds)");
        raise(SIGTERM);
    }

    comms.client_fds[comms.client_num-1] = fd;

    pthread_mutex_unlock(&comms.mtx);
}

void xdp_attach(void * data)
{
    char * if_name = (char *)data;
    struct xdp_link_info xdp_info;
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_map *map;
    int prog_fd;
    int if_index;

    if ((if_index = _if_index(if_name)) < 0) {
        return;
    }

    int xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;

    struct bpf_object_open_attr attr = {
            .prog_type = BPF_PROG_TYPE_XDP,
            .file = "xdp_mon_kern.o",
    };

    obj = bpf_object__open_xattr(&attr);
    if (libbpf_get_error(obj)) {
        error(1, errno, "bpf_object__open_xattr");
    }

    map = bpf_object__find_map_by_name(obj, "xdp_ringbuf");
    if (libbpf_get_error(map)) {
        error(1, errno, "bpf_object__find_map_by_name(%s)", "xdp_ringbuf");
    }

    int err = bpf_object__load(obj);
    if (err) {
        error(1, errno, "bpf_object__load, %s", strerror(errno));
    }

    prog = bpf_object__find_program_by_title(obj, "xdp");
    if (!prog) {
        error(1, errno, "bpf_object__find_program_by_title");
    }

    prog_fd = bpf_program__fd(prog);
    if (!prog_fd) {
        error(1, errno, "bpf_program__fd");
    }

    if (bpf_set_link_xdp_fd(if_index, prog_fd, xdp_flags) < 0) {
        error(1, errno, "bpf_set_link_xdp_fd(%s)", attr.file);
    }

    _add_ifs_fd(if_index, bpf_map__fd(map), bpf_program__fd(prog), bpf_object__btf_fd(obj));

    if (bpf_get_link_xdp_info(if_index, &xdp_info, sizeof(struct xdp_link_info), 0) < 0) {
        error(1, errno, "bpf_get_link_xdp_info(%s)", if_name);
    }

    printf("if_index: %d (%s) btf_fd: %d prog_fd: %d map_fd: %d\n", if_index, if_name,
           bpf_object__btf_fd(obj), bpf_program__fd(prog), bpf_map__fd(map));
}

void xdp_term(void * data)
{
    char * if_name = (char *)data;
    int if_index;

    if ((if_index = _if_index(if_name)) < 0) {
        return;
    }

    bpf_set_link_xdp_fd(if_index, -1, 0);

    t_ifs_fd *ifs_fd = _ifs_fd_by_if_index(if_index);
    if (ifs_fd != NULL) {
        close(ifs_fd->map_fd);
        close(ifs_fd->prog_fd);
        close(ifs_fd->btf_fd);

        printf("stopping, if_index: %d (%s) btf_fd: %d prog_fd: %d map_fd: %d\n", if_index, if_name,
               ifs_fd->btf_fd, ifs_fd->prog_fd, ifs_fd->map_fd);
    }
}

static int buf_process_sample(void *ctx, void *data, size_t len) {
    pkt_count++;
    _write_comms_pkt_buf(data, sizeof(t_in_pkt));

    return 0;
}

void ring_read(void *data)
{
    pkt_count = 0;
    char * if_name = (char *)data;
    t_ifs_fd *ifs_fd;
    struct ring_buffer *ring_buffer;
    int if_index;

    if ((if_index = _if_index(if_name)) < 0) {
        return;
    }

    if ((ifs_fd = _ifs_fd_by_if_index(if_index)) == NULL) {
        xdp_attach(if_name);
        // new interface will be picked up during next iteration
        goto no_if;
    }

    if ((ring_buffer = ring_buffer__new(ifs_fd->map_fd, buf_process_sample, NULL, NULL)) == NULL) {
        goto no_if;
    }

    ring_buffer__consume(ring_buffer);
    ring_buffer__free(ring_buffer);
    printf("%-4d%-16s%d\n", if_index, if_name, pkt_count);

    no_if:
    return;
}

void if_iter(void (*if_callback)(void *))
{
    struct ifaddrs *ifap, *_ifap;
    struct ifsarr ifsarr = {
            .ifs_ix = NULL,
            .len = 0
    };

    if (getifaddrs(&ifap) < 0) {
        error(-1, errno, "getifaddrs");
    }

    _ifap = ifap;

    while (ifap->ifa_next) {
        if (_if_in_ifsarr(ifsarr, _if_index(ifap->ifa_name))) {
            goto next;
        }

        if (if_callback != NULL) {
            if_callback((void *)ifap->ifa_name);
        }

        ifsarr.len++;
        ifsarr.ifs_ix = realloc(ifsarr.ifs_ix, ifsarr.len * sizeof(int));
        ifsarr.ifs_ix[ifsarr.len-1] = _if_index(ifap->ifa_name);

        next:
        ifap = ifap->ifa_next;
    }

    free(ifsarr.ifs_ix);
    freeifaddrs(_ifap);
}

static inline int comms_open(t_out_comms *comms)
{
    // initializing comms struct
    comms->sock_fd = 0;
    comms->client_fds = NULL;
    comms->client_num = 0;
    comms->pkt_buf = NULL;
    comms->pkt_buf_num = 0;

    if ((comms->sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        error(-1, errno, "socket");
    }

    int yes = 1;
    if (setsockopt(comms->sock_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) < 0) {
        error(-1, errno, "setsockopt(SO_REUSEADDR)");
    }

    struct sockaddr_in sockaddr_in;
    bzero(&sockaddr_in, sizeof(struct sockaddr_in));

    sockaddr_in.sin_addr.s_addr = INADDR_ANY;
    sockaddr_in.sin_port = htons(COMMS_PORT);
    sockaddr_in.sin_family = AF_INET;

    if (bind(comms->sock_fd, (struct sockaddr *)&sockaddr_in, sizeof(struct sockaddr_in)) < 0) {
        error(-1, errno, "bind");
    }

    if (listen(comms->sock_fd, 4) < 0) {
        error(-1, errno, "listen");
    }
}

void *comms_accept(void *data)
{
    int client_fd;
    struct sockaddr_in s_addr;
    socklen_t sock_size = sizeof(struct sockaddr_in);

    while ((client_fd = accept(comms.sock_fd, (struct sockaddr *)&s_addr, &sock_size)) > 0) {
        _add_comms_client_fd(client_fd);
    }

    error(0, errno, "accept");
    raise(SIGTERM);
}

static inline t_in_pkt_buf mv_pkt_buf(void)
{
    t_in_pkt_buf in_pkt_buf;

    pthread_mutex_lock(&comms.mtx_buf);
    in_pkt_buf.pkt_buf = comms.pkt_buf;
    in_pkt_buf.pkt_buf_num = comms.pkt_buf_num;

    comms.pkt_buf_num = 0;
    comms.pkt_buf = NULL;

    pthread_mutex_unlock(&comms.mtx_buf);
    return in_pkt_buf;
}

static inline int send_pkt_buf(int cfd, t_in_pkt_buf *pkt_buf)
{
    ssize_t wrote;

    for (int i = 0; i < pkt_buf->pkt_buf_num; i++) {
        if ((wrote = write(cfd, pkt_buf->pkt_buf + i, sizeof(t_in_pkt))) < 0) {
            return -1;
        }
    }

    return 0;
}

void *handle_pkt_buf(void *data)
{
    t_in_pkt_buf pkt_buf;

    while (1) {
        pkt_buf = mv_pkt_buf();
        if (pkt_buf.pkt_buf == NULL) {
            goto next;
        }

        pthread_mutex_lock(&comms.mtx);
        for (int i = 0; i < comms.client_num; i++) {
            if (i > comms.client_num-1) {
                continue;
            }

            if (send_pkt_buf(comms.client_fds[i], &pkt_buf) < 0) {
                _rm_comms_client_fd(i);
            }
        }
        pthread_mutex_unlock(&comms.mtx);

        free(pkt_buf.pkt_buf);

        next:
        usleep(100000);
    }
}

void sighandler(int sig, siginfo_t *info, void *ucontext)
{
    // iterate interfaces and remove attached XDP programs
    if_iter(xdp_term);

    // free global array holding interface indices and bpf map FDs
    _cleanup_ifs_fd();

    // closing client sockets
    for (int i = 0; i < comms.client_num; i++) {
        close(comms.client_fds[i]);
    }

    if (comms.client_fds != NULL) {
        free(comms.client_fds);
    }

    // close comms socket
    close(comms.sock_fd);

    // bye
    signal (sig, SIG_DFL);
    raise(sig);
}

int main(int argc, char **argv)
{
    // Start IPcomms
    comms_open(&comms);
    pthread_mutex_init(&comms.mtx, NULL);
    pthread_mutex_init(&comms.mtx_buf, NULL);

    sigset_t sa_mask;
    sigemptyset(&sa_mask);

    struct sigaction sig_action;
    sig_action.sa_sigaction = sighandler;
    sig_action.sa_mask = sa_mask;
    sig_action.sa_flags = 0;

    sigaction(SIGTERM, &sig_action, NULL);
    sigaction(SIGINT, &sig_action, NULL);

    // we do ignore SIGPIPEs in case comms clients leave us
    signal(SIGPIPE, SIG_IGN);

    struct rlimit r = {
            RLIM_INFINITY,
            RLIM_INFINITY
    };

    if (setrlimit(RLIMIT_MEMLOCK, &r)) {
        error(-1, errno, "setrlimit(RLIMIT_MEMLOCK)");
    }

    // attach XDP programs
    if_iter(xdp_term);
    if_iter(xdp_attach);

    // start listening for clients
    pthread_create(&comms.thread_accept, NULL, comms_accept, NULL);

    // handle pkt buffer
    pthread_create(&comms.thread_buf, NULL, handle_pkt_buf, NULL);

    while (1) {
        if_iter(ring_read);
        usleep(500000);
    }

    return 0;
}