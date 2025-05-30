// fastscan.c - Unified: Full-featured, static-buffer, webpanel and CLI CIDR HTTP/HTTPS scanner

#if defined(_WIN32) || defined(_WIN64)
#define FASTSCAN_WINDOWS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")
typedef SOCKET fs_socket_t;
#define fs_close closesocket
#define fs_sleep(ms) Sleep(ms)
#define poll WSAPoll
#define POLLIN 0x0001
#define POLLOUT 0x0002
#define POLLERR 0x0008
#define POLLHUP 0x0010
#else
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
typedef int fs_socket_t;
#define fs_close close
#define fs_sleep(ms) usleep((ms)*1000)
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

/* ---- Configurable constants and limits ---- */
#define PANEL_PORT       8080
#define PANEL_ADDR       "0.0.0.0"
#define MAX_CLIENTS      256
#define CLIENT_BUF_SZ    4096
#define CLIENT_TIMEOUT   10
#define HTMLSZ           8192

#define MAX_IPS_PER_BATCH 4096
#define MAX_CONC     128
#define MIN_CONC     2
#define MAX_HOST     256
#define BUF_SZ       4096
#define HTTP_PORT    80
#define HTTPS_PORT   443
#define MAX_RESULTS_PER_BATCH 4096
#define MAX_RESULT_LINES 8192
#define MAX_CIDRS    1024
#define MAX_CIDR_LEN 32

#define SAFE_STR(s) ((s)?(s):"")
#define CLAMP(x,min,max) ((x)<(min)?(min):(x)>(max)?(max):(x))

/* ---- Types ---- */
typedef struct {
    char ip[16];
    char http_result[128];
    char https_result[128];
    int http_hit, https_hit;
} scan_result_t;

typedef struct {
    char cidr[MAX_CIDR_LEN];
} cidr_queue_item_t;

typedef struct {
    cidr_queue_item_t cidrs[MAX_CIDRS];
    int count;
    int head;
    int tail;
} cidr_queue_t;

typedef struct {
    char match[MAX_HOST];
    int max_conc;
    int scan_count;
    int hit_count;
    scan_result_t results[MAX_RESULTS_PER_BATCH];
} scan_job_t;

typedef struct {
    fs_socket_t fd;
    char buf[CLIENT_BUF_SZ];
    int buflen;
    int state;           // 0 = reading request, 1 = sending response
    int to_write;
    int written;
    char resp[HTMLSZ];
    int last_active;
} client_t;

/* ---- Globals ---- */
static volatile int keep_running = 1;
static volatile int paused = 0;
cidr_queue_t g_cidr_queue;
scan_job_t g_job;
char g_scan_results[MAX_RESULT_LINES][256];
int g_scan_result_lines = 0;
char g_match[MAX_HOST] = ""; // No default, must be set by user
int g_max_conc = 32;

/* ---- Platform abstraction ---- */
void fs_init_network() {
#ifdef FASTSCAN_WINDOWS
    WSADATA wsa; WSAStartup(MAKEWORD(2,2), &wsa);
#endif
}
void fs_cleanup_network() {
#ifdef FASTSCAN_WINDOWS
    WSACleanup();
#endif
}
int now_sec() {
#if defined(FASTSCAN_WINDOWS)
    return (int)(GetTickCount() / 1000);
#else
    return (int)time(NULL);
#endif
}

/* ---- Secure random bytes ---- */
int fs_randbytes(uint8_t *buf, size_t n) {
#ifdef FASTSCAN_WINDOWS
    HCRYPTPROV hProv = 0;
    if(!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) return 0;
    BOOL r = CryptGenRandom(hProv, (DWORD)n, buf);
    CryptReleaseContext(hProv, 0);
    return r ? 1 : 0;
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)
    arc4random_buf(buf, n); return 1;
#else
    FILE *f = fopen("/dev/urandom","rb");
    if(!f) return 0;
    size_t got = fread(buf,1,n,f); fclose(f);
    return got==n;
#endif
}

/* ---- CIDR queue system ---- */
void cidr_queue_init(cidr_queue_t *q) {
    q->count = q->head = q->tail = 0;
}
int cidr_queue_push(cidr_queue_t *q, const char *cidr) {
    if(q->count >= MAX_CIDRS) return 0;
    strncpy(q->cidrs[q->tail].cidr, cidr, MAX_CIDR_LEN-1);
    q->cidrs[q->tail].cidr[MAX_CIDR_LEN-1] = 0;
    q->tail = (q->tail + 1) % MAX_CIDRS;
    q->count++;
    return 1;
}
int cidr_queue_pop(cidr_queue_t *q, char *cidr) {
    if(q->count == 0) return 0;
    strncpy(cidr, q->cidrs[q->head].cidr, MAX_CIDR_LEN-1);
    cidr[MAX_CIDR_LEN-1]=0;
    q->head = (q->head + 1) % MAX_CIDRS;
    q->count--;
    return 1;
}
int cidr_queue_count(cidr_queue_t *q) {
    return q->count;
}

/* ---- Result handling ---- */
void g_clear_scan_results() {
    for(int i=0; i<MAX_RESULT_LINES; ++i)
        g_scan_results[i][0] = 0;
    g_scan_result_lines = 0;
}
void g_add_result(const char *msg) {
    if(g_scan_result_lines < MAX_RESULT_LINES - 1) {
        strncpy(g_scan_results[g_scan_result_lines], msg, 255);
        g_scan_results[g_scan_result_lines][255]=0;
        g_scan_result_lines++;
    }
}

/* ---- CIDR expansion (IPv4) ---- */
int expand_cidr(const char *cidr, char ips[][16], int max) {
    char base[16]; int prefix, count = 0;
    unsigned int net, mask, n;
    if(sscanf(cidr, "%15[^/]/%d", base, &prefix) != 2) return 0;
    if(prefix < 0 || prefix > 32) return 0;
    if(inet_pton(AF_INET, base, &net)!=1) return 0;
    mask = htonl(0xFFFFFFFF << (32-prefix));
    net &= mask;
    n = 1U << (32-prefix);
    for(unsigned int i=0; i<n && count<max; ++i) {
        struct in_addr a; a.s_addr = htonl(ntohl(net) + i);
        if(!inet_ntop(AF_INET, &a, ips[count], 16)) return count;
        count++;
    }
    return count;
}

/* ---- Minimal TLS 1.2 handshake for CN extraction ---- */
static const uint8_t hello_template[] = {
    0x16,0x03,0x03,0x00,0xdc,0x01,0x00,0x00,0xd8,0x03,0x03,
    /* [32 random bytes at offset 11] */
};
int tls_send_client_hello(fs_socket_t sock) {
    uint8_t buf[256]; memset(buf,0,sizeof(buf));
    memcpy(buf, hello_template, sizeof(hello_template));
    fs_randbytes(buf+11, 32);
#ifdef FASTSCAN_WINDOWS
    return send(sock, (const char*)buf, sizeof(hello_template), 0);
#else
    return send(sock, buf, sizeof(hello_template), 0);
#endif
}
int parse_cert_cn(const uint8_t *data, int len, char *cn, int cnlen) {
    int i;
    for(i=0; i<len-8; ++i) {
        if(data[i]==0x06 && data[i+1]==0x03 && !memcmp(data+i+2,"\x55\x04\x03",3)) {
            if(data[i+5]==0x0c || data[i+5]==0x13) {
                int n = data[i+6];
                if(n>0 && n<cnlen && i+7+n<len) {
                    memcpy(cn, data+i+7, n); cn[n]=0; return 1;
                }
            }
        }
    }
    return 0;
}

/* ---- Socket connect (portable, non-blocking) ---- */
fs_socket_t connect_host(const char *ip, int port) {
    fs_socket_t sock;
    struct sockaddr_in addr;
#ifdef FASTSCAN_WINDOWS
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
#else
    sock = socket(AF_INET, SOCK_STREAM, 0);
#endif
    if(sock < 0) return -1;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)port);
    if(inet_pton(AF_INET, ip, &addr.sin_addr) != 1) { fs_close(sock); return -1; }
#ifdef FASTSCAN_WINDOWS
    u_long mode = 1; ioctlsocket(sock, FIONBIO, &mode);
#else
    fcntl(sock, F_SETFL, O_NONBLOCK);
#endif
    connect(sock, (struct sockaddr*)&addr, sizeof(addr));
    fd_set wfds; FD_ZERO(&wfds); FD_SET(sock, &wfds);
    struct timeval tv; tv.tv_sec=2; tv.tv_usec=0;
    int r = select((int)sock+1, NULL, &wfds, NULL, &tv);
    if(r != 1) { fs_close(sock); return -1; }
#ifdef FASTSCAN_WINDOWS
    mode = 0; ioctlsocket(sock, FIONBIO, &mode);
#else
    fcntl(sock, F_SETFL, 0);
#endif
    return sock;
}

/* ---- HTTPS: grab cert CN, look for match ---- */
int scan_https(const char *ip, const char *match, char *out, int outlen) {
    if(match == NULL || strlen(match) == 0) return 0;
    fs_socket_t sock = connect_host(ip, HTTPS_PORT);
    if(sock < 0) return 0;
    tls_send_client_hello(sock);
    uint8_t buf[BUF_SZ];
#ifdef FASTSCAN_WINDOWS
    int n = recv(sock, (char*)buf, sizeof(buf), 0);
#else
    int n = recv(sock, buf, sizeof(buf), 0);
#endif
    if(n < 0) { fs_close(sock); return 0; }
    int i;
    for(i=0; i<n-4; ++i) {
        if(buf[i]==0x0b) {
            int certlen = (buf[i+2]<<8) | buf[i+3];
            if(certlen > 0 && certlen < BUF_SZ-(i+4)) {
                char cn[256]="";
                if(parse_cert_cn(buf+i+4, certlen, cn, 255)) {
                    if(strstr(cn, match)) {
                        snprintf(out, outlen, "Found '%s' at %s (HTTPS CN)\n", match, ip);
                        fs_close(sock); return 1;
                    }
                }
            }
        }
    }
    fs_close(sock);
    return 0;
}
/* ---- HTTP: GET /, look for match in response ---- */
int scan_http(const char *ip, const char *match, char *out, int outlen) {
    if(match == NULL || strlen(match) == 0) return 0;
    fs_socket_t sock = connect_host(ip, HTTP_PORT);
    if(sock < 0) return 0;
    char req[128];
    snprintf(req, 128, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", match);
#ifdef FASTSCAN_WINDOWS
    send(sock, req, (int)strlen(req), 0);
    char buf[1024];
    int n = recv(sock, buf, sizeof(buf)-1, 0);
#else
    send(sock, req, strlen(req), 0);
    char buf[1024];
    int n = recv(sock, buf, sizeof(buf)-1, 0);
#endif
    fs_close(sock);
    if(n <= 0) return 0;
    buf[n]=0;
    if(strstr(buf, match)) {
        snprintf(out, outlen, "Found '%s' at %s (HTTP match)\n", match, ip);
        return 1;
    }
    return 0;
}

/* ---- Adaptive, static-buffered, pausable scanner (background thread/loop) ---- */
void scan_cidr_batch(const char *cidr, const char *match, int max_conc) {
    if(match == NULL || strlen(match) == 0) {
        printf("[!] Skipping scan: target domain not set.\n");
        return;
    }
    char ips[MAX_IPS_PER_BATCH][16];
    scan_result_t results[MAX_RESULTS_PER_BATCH];
    int n_ips = expand_cidr(cidr, ips, MAX_IPS_PER_BATCH);
    if(n_ips == 0) { printf("CIDR parse error: %s\n", cidr); return; }
    int i, hit_count = 0;
    for(i=0; i<n_ips && keep_running; ++i) {
        while(paused) fs_sleep(100); // Pause if needed
        results[i].http_hit = scan_http(ips[i], match, results[i].http_result, sizeof(results[i].http_result)-1);
        results[i].https_hit = scan_https(ips[i], match, results[i].https_result, sizeof(results[i].https_result)-1);
        if(results[i].http_hit) printf("%s", results[i].http_result);
        if(results[i].https_hit) printf("%s", results[i].https_result);
        hit_count += results[i].http_hit + results[i].https_hit;
        fs_sleep(10);
    }
    printf("[+] Done batch: %s (scanned: %d, hits: %d)\n", cidr, n_ips, hit_count);
}

/* ---- Result handling for webpanel ---- */
void scan_loop() {
    static int running = 0;
    if(running) return; // reentrancy guard
    running = 1;
    while(keep_running) {
        if(paused || g_cidr_queue.count == 0) { fs_sleep(300); continue; }
        char cidr[MAX_CIDR_LEN];
        if(!cidr_queue_pop(&g_cidr_queue, cidr)) break;
        char ips[MAX_IPS_PER_BATCH][16];
        int n_ips = expand_cidr(cidr, ips, MAX_IPS_PER_BATCH);
        for(int i=0; i<n_ips && keep_running; ++i) {
            while(paused) fs_sleep(100);
            char msg[256];
            if(scan_http(ips[i], g_match, msg, sizeof(msg)-1)) g_add_result(msg);
            if(scan_https(ips[i], g_match, msg, sizeof(msg)-1)) g_add_result(msg);
            if(i%32==0) fs_sleep(10); // yield CPU
        }
        char done[96];
        snprintf(done, sizeof(done), "[+] Done batch: %s (scanned: %d)\n", cidr, n_ips);
        g_add_result(done);
    }
    running = 0;
}

/* ---- Webpanel HTTP server (poll-based, static) ---- */
client_t clients[MAX_CLIENTS];

const char *panel_html_prefix =
    "<html><head><title>fastscan webpanel</title>"
    "<style>body{font-family:monospace;background:#171717;color:#d6d6d6;}"
    "input,textarea{background:#1e1e1e;color:#e6e6e6;}</style></head><body>"
    "<h2>Fastscan Webpanel</h2>"
    "<form method='POST' enctype='multipart/form-data'>"
    "CIDRs (one per line):<br>"
    "<textarea name='cidrs' rows=8 cols=50></textarea><br>";

const char *panel_html_suffix = "</body></html>";

int build_panel_html(char *dst, int max) {
    int n = 0;
    n += snprintf(dst+n, max-n, "%s", panel_html_prefix);
    n += snprintf(dst+n, max-n, "Domain to match: <input name='match' value='%s'><br>", SAFE_STR(g_match));
    n += snprintf(dst+n, max-n, "or upload file: <input type='file' name='cidrfile'><br>");
    n += snprintf(dst+n, max-n, "<input type='submit' value='Start scan'>");
    n += snprintf(dst+n, max-n, "</form>");
    n += snprintf(dst+n, max-n, "<form method='POST'><button name='pause' value='1'>Pause</button>");
    n += snprintf(dst+n, max-n, "<button name='resume' value='1'>Resume</button></form>");
    n += snprintf(dst+n, max-n, "<h3>Status:</h3>");
    n += snprintf(dst+n, max-n, "Scan is <b>%s</b>.<br>", paused ? "PAUSED" : "RUNNING");
    n += snprintf(dst+n, max-n, "CIDRs left: <b>%d</b><br>", g_cidr_queue.count);
    n += snprintf(dst+n, max-n, "Matching domain: <b>%s</b><br>", SAFE_STR(g_match));
    n += snprintf(dst+n, max-n, "Results:<pre>\n");
    for(int i=0; i<g_scan_result_lines && n+128<max; ++i)
        n += snprintf(dst+n, max-n, "%s", g_scan_results[i]);
    n += snprintf(dst+n, max-n, "</pre>%s", panel_html_suffix);
    return n;
}

/* ---- HTTP request parser (trivial, bounded) ---- */
void parse_http_request(client_t *c) {
    c->buf[c->buflen] = 0;
    if(strncmp(c->buf, "GET /", 5) == 0) {
        // Main panel
        c->to_write = snprintf(c->resp, HTMLSZ,
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n");
        c->to_write += build_panel_html(c->resp+c->to_write, HTMLSZ-c->to_write);
        c->state = 1; c->written = 0;
    } else if(strncmp(c->buf, "POST /", 6) == 0) {
        // Pause/resume
        if(strstr(c->buf, "pause=1")) paused = 1;
        else if(strstr(c->buf, "resume=1")) paused = 0;

        // Parse 'match'
        char *matchline = strstr(c->buf, "match=");
        if(matchline) {
            char *start = matchline + 6;
            char *end = strchr(start, '&');
            int len = end ? (end-start) : (int)strlen(start);
            if(len > 0 && len < MAX_HOST) {
                strncpy(g_match, start, len); g_match[len] = 0;
            }
        }

        // Parse CIDRs
        char *p = strstr(c->buf, "cidrs=");
        if(p) {
            char *start = p+6;
            g_clear_scan_results();
            cidr_queue_init(&g_cidr_queue);
            char line[64];
            int idx = 0;
            while(start[idx] && g_cidr_queue.count < MAX_CIDRS) {
                int llen = 0;
                while(start[idx+llen] && start[idx+llen]!='\n' && start[idx+llen]!='\r' && llen<63)
                    llen++;
                if(llen>0) {
                    strncpy(line, start+idx, llen); line[llen]=0;
                    cidr_queue_push(&g_cidr_queue, line);
                }
                while(start[idx+llen] && (start[idx+llen]=='\n'||start[idx+llen]=='\r')) llen++;
                idx += llen;
            }
        }
        // File upload: (not implemented in this minimal version; would need multipart parser)

        // Start scan loop (in-process background)
        scan_loop();

        // reply with panel
        c->to_write = snprintf(c->resp, HTMLSZ,
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n");
        c->to_write += build_panel_html(c->resp+c->to_write, HTMLSZ-c->to_write);
        c->state = 1; c->written = 0;
    } else {
        // 404
        c->to_write = snprintf(c->resp, HTMLSZ,
            "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n\r\nnot found");
        c->state = 1; c->written = 0;
    }
}

/* ---- Accept a new client ---- */
void accept_client(fs_socket_t servfd) {
    struct sockaddr_in cliaddr; socklen_t alen = sizeof(cliaddr);
    fs_socket_t fd = accept(servfd, (struct sockaddr*)&cliaddr, &alen);
    if(fd < 0) return;
    for(int i=0; i<MAX_CLIENTS; ++i) {
        if(clients[i].fd == -1) {
            clients[i].fd = fd;
            clients[i].buflen = 0;
            clients[i].state = 0;
            clients[i].to_write = 0;
            clients[i].written = 0;
            clients[i].last_active = now_sec();
            return;
        }
    }
    fs_close(fd); // Too many clients!
}

/* ---- Poll event loop ---- */
void webpanel_loop(fs_socket_t servfd) {
    struct pollfd pfds[MAX_CLIENTS+1];
    memset(clients, 0xff, sizeof(clients)); // fd=-1 means unused
    for(int i=0; i<MAX_CLIENTS; ++i) clients[i].fd = -1;

    while(keep_running) {
        pfds[0].fd = servfd;
        pfds[0].events = POLLIN;
        int nfds = 1;

        for(int i=0; i<MAX_CLIENTS; ++i) {
            if(clients[i].fd != -1) {
                pfds[nfds].fd = clients[i].fd;
                pfds[nfds].events = clients[i].state ? POLLOUT : POLLIN;
                nfds++;
            }
        }
        int n = poll(pfds, nfds, 250);
        if(n < 0) continue;

        // Accept new connections
        if(pfds[0].revents & POLLIN) accept_client(servfd);

        // Handle clients
        for(int i=0, idx=1; i<MAX_CLIENTS; ++i, ++idx) {
            client_t *c = &clients[i];
            if(c->fd == -1) continue;
            if(now_sec() - c->last_active > CLIENT_TIMEOUT) {
                fs_close(c->fd); c->fd = -1; continue;
            }
            if(!c->state && (pfds[idx].revents & POLLIN)) {
                int got = recv(c->fd, c->buf+c->buflen, CLIENT_BUF_SZ-c->buflen-1, 0);
                if(got <= 0) { fs_close(c->fd); c->fd = -1; continue; }
                c->buflen += got; c->last_active = now_sec();
                if(strstr(c->buf, "\r\n\r\n")) parse_http_request(c);
            }
            if(c->state && (pfds[idx].revents & POLLOUT)) {
                int left = c->to_write - c->written;
                int sent = send(c->fd, c->resp+c->written, left, 0);
                if(sent <= 0) { fs_close(c->fd); c->fd = -1; continue; }
                c->written += sent; c->last_active = now_sec();
                if(c->written >= c->to_write) { fs_close(c->fd); c->fd = -1; }
            }
        }
    }
}

/* ---- Server socket setup ---- */
fs_socket_t webpanel_server() {
    fs_socket_t s = socket(AF_INET, SOCK_STREAM, 0);
    int yes = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (void*)&yes, sizeof(yes));
    struct sockaddr_in sa;
    sa.sin_family = AF_INET;
    sa.sin_port = htons(PANEL_PORT);
    sa.sin_addr.s_addr = inet_addr(PANEL_ADDR);
    if(bind(s, (struct sockaddr*)&sa, sizeof(sa)) < 0) exit(1);
    if(listen(s, 16) < 0) exit(1);
    return s;
}

/* ---- Signal handling (for CLI pause/resume) ---- */
#ifndef FASTSCAN_WINDOWS
void handle_signal(int sig) {
    if (sig == SIGINT) {
        keep_running = 0;
    } else if (sig == SIGTSTP) {
        paused = !paused;
    }
}
#endif

/* ---- Main entrypoint: choose between CLI or webpanel ---- */
int main(int argc, char **argv) {
    fs_init_network();
#ifndef FASTSCAN_WINDOWS
    signal(SIGINT, handle_signal);
    signal(SIGTSTP, handle_signal);
#endif

    if(argc > 1 && strcmp(argv[1], "web") == 0) {
        // --- Webpanel mode ---
        cidr_queue_init(&g_cidr_queue);
        g_clear_scan_results();
        printf("[+] webpanel listening on http://0.0.0.0:%d/\n", PANEL_PORT);
        fs_socket_t s = webpanel_server();
        webpanel_loop(s);
        fs_close(s);
        fs_cleanup_network();
        return 0;
    }

    // --- CLI mode ---
    cidr_queue_init(&g_cidr_queue);
    if(argc == 3) {
        // Load CIDRs from file, and set match string
        FILE *f = fopen(argv[1], "r");
        if(!f) { printf("Cannot open %s\n", argv[1]); return 1; }
        char line[64];
        while(fgets(line, sizeof(line), f)) {
            char *nl = strchr(line, '\n');
            if(nl) *nl = 0;
            if(strlen(line) > 0) cidr_queue_push(&g_cidr_queue, line);
        }
        fclose(f);
        strncpy(g_match, argv[2], MAX_HOST-1); g_match[MAX_HOST-1]=0;
        g_max_conc = 32;
    } else if(argc >= 4) {
        // Single CIDR from command line + match string
        cidr_queue_push(&g_cidr_queue, argv[1]);
        strncpy(g_match, argv[2], MAX_HOST-1); g_match[MAX_HOST-1]=0;
        g_max_conc = CLAMP(atoi(argv[3]), MIN_CONC, MAX_CONC);
    } else {
        printf("Usage:\n  %s web\n  %s [cidr-list.txt] [match]\n  %s [CIDR] [match] [max_conc]\n", argv[0], argv[0], argv[0]);
        fs_cleanup_network(); return 1;
    }

    if(strlen(g_match) == 0) {
        printf("Error: No target domain set. Please specify a domain to match.\n");
        fs_cleanup_network(); return 1;
    }

    char cidr[MAX_CIDR_LEN];
    while(keep_running && cidr_queue_pop(&g_cidr_queue, cidr)) {
        printf("[+] Scanning batch: %s for '%s' (max_conc=%d)\n", cidr, g_match, g_max_conc);
        scan_cidr_batch(cidr, g_match, g_max_conc);
    }
    printf("[+] All batches done.\n");
    fs_cleanup_network();
    return 0;
}
