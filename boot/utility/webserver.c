#include <sys/prctl.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <syscall.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <pthread.h>

#define DEBUG

#define HTTP "HTTP/1.1"

typedef struct args {
	char *host;
	int port;
	char *root;
} args;

#define PATH_MAX 4096

static char root[PATH_MAX];

enum M {
	GET,
	// more to be added
};

static void err_resp(int fd) {
	char *e = HTTP " 405 Method Not Allowed\r\n"
			"Content-Type: text/html; charset=UTF-8\r\n"
			"\r\n"
			"<html>\r\n"
			"<head>\r\n"
			"<title>405 Method Not Allowed</title>\r\n"
			"</head>\r\n"
			"<body>\r\n"
			"<h1>Method Not Allowed</h1>\r\n"
			"<p>The method is not allowed.</p>\r\n"
			"</body>\r\n"
			"</html>";
	write(fd, e, strlen(e));
}

static void no_content(int fd) {
	char *r = HTTP " 204 No Content\r\n\r\n";
	write(fd, r, strlen(r));
}

#define OK_HEADER HTTP " 200 OK\r\n"

#define CONTENT_LEN "Content-Length: {length}\r\n"

#define FILE_HEADER OK_HEADER\
	"Content-Type: application/octet-stream\r\n"\
	"Content-Disposition: attachment; filename=\"{filename}\"\r\n"\
	CONTENT_LEN

#define TEXT_HEADER(type) "Content-Type: " type ";charset=utf-8\r\n"

#define TYPE_HEADER(type) "Content-Type: " type "\r\n"\

#define HTML_HEADER OK_HEADER\
	TEXT_HEADER("text/html")\
	CONTENT_LEN

#define JS_HEADER OK_HEADER\
	TEXT_HEADER("text/javascript")\
	CONTENT_LEN

#define CSS_HEADER OK_HEADER\
	TEXT_HEADER("text/css")\
	CONTENT_LEN

#define PNG_HEADER OK_HEADER\
	TYPE_HEADER("image/png")\
	CONTENT_LEN

#define JPG_HEADER OK_HEADER\
	TYPE_HEADER("image/jpeg")\
	CONTENT_LEN

#define WEBP_HEADER OK_HEADER\
	TYPE_HEADER("image/webp")\
	CONTENT_LEN

#define DIR_HEADER HTML_HEADER

#define DIR_START "<html>\r\n"\
		"<head>\r\n"\
		"<title></title>\r\n"\
		"</head>\r\n"\
		"<body>\r\n"

#define DIR_END \
		"</body>\r\n"\
		"</html>"


static char *filename(char *file) {
	char *s = file;
	while (*file) {
		if (*file++ == '/')s=file;
	}
	return s;
}

static int has_suffix(const char *file, const char *ext) {
	const char *p = strrchr(file, '.');
	if (p && !strcmp(p + 1, ext)) {
		return 1;
	}
	return 0;
}

static inline int is_html(const char *file) {
	return has_suffix(file, "html");
}

static inline int is_js(const char *file) {
	return has_suffix(file, "js");
}

static inline int is_css(const char *file) {
	return has_suffix(file, "css");
}

static inline int is_jpg(const char *file) {
	return has_suffix(file, "jpg") || has_suffix(file, "jpeg");
}

static inline int is_png(const char *file) {
	return has_suffix(file, "png");
}

static inline int is_webp(const char *file) {
	return has_suffix(file, "webp");
}

static char *resolve_placeholders(const char *src, char *buf, int bl, const char **p, int n) {
	char *s = src;
	int in = 0;
	char *ph = NULL;
	int phl = 0;
	char *start = buf;
	char *end = buf + bl - 1;
	while (*s) {
		char c = *s;
		switch (c) {
		case '{':
			if (in > 0) { // nested placeholder not supported
				goto out;
			}
			in++;
			ph = ++s;
			break;
		case '}':
			if (--in != 0) {
				goto out; // mismatch
			}
			phl = s - ph;
			for (int i = 0; i < n; i+=2) {
				if (!strncmp(ph, p[i], phl)) {
					int rl = strlen(p[i+1]);
					if (buf + rl > end) {
						goto out;
					}
					strncpy(buf, p[i+1], rl);
					buf+=rl;
					goto replaced;
				}
			}
			if (buf + phl+2 > end) {
				goto out;
			}
			strncpy(buf, ph-1, phl + 2);
			buf+= phl+2;
replaced:
			s++;
			break;
		case '\\':
			char ce = *(s+1);
			if (ce == '{' || ce == '}') {
				c=ce;
				s+=1;
			}
			// fall through
		default:
			s++;
			if (in > 0) {
				break;
			}
			if (buf >= end) {
				goto out;
			}
			*buf++=c;
		}
	}
out:
	*buf='\0';
	return start;
}

static char *resolve_placeholder(const char *src, char *buf, int bl, const char *p, const char *r) {
	char *pp[2] = {p, r};
	return resolve_placeholders(src, buf, bl, pp, 2);
}

static void return_file(char *file, size_t size, int fd) {
	FILE *f = fopen(file, "rb");
	if (!f) {
		err_resp(fd);
		return;
	}
	char temp[64];
	char buf[4096];
	char *rep[4];
	snprintf(temp, sizeof(temp), "%d", size);

	rep[0] = "filename";
	rep[1] = filename(file);
	rep[2] = "length";
	rep[3] = temp;

	char *header;
	if (is_html(file)) {
		header = HTML_HEADER;
	} else if (is_js(file)) {
		header = JS_HEADER;
	} else if (is_css(file)) {
		header = CSS_HEADER;
	} else if (is_jpg(file)) {
		header = JPG_HEADER;
	} else if (is_png(file)) {
		header = PNG_HEADER;
	} else if (is_webp(file)) {
		header = WEBP_HEADER;
	} else {
		header = FILE_HEADER;
	}

	char *s = resolve_placeholders(header, buf, sizeof(buf), rep, 4);

	strcat(s, "\r\n");
	write(fd, buf, strlen(buf));
	int count = 0;
	int n;
	pid_t tid = syscall(SYS_gettid);

	prctl(PR_SET_NAME, file);
#ifdef DEBUG
	printf("tid: %d, rfd: %d, wfd: %d, start reading file %s\n", tid, fileno(f), fd, file);
#endif
	while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
#ifdef DEBUG
		//printf("tid: %d, %s: bytes read %d\n", tid, file, n);
#endif
		write(fd, buf, n);
#ifdef DEBUG
		//printf("tid: %d, %s: bytes written %d\n", tid, file, n);
#endif
		count+= n;
	}
#ifdef DEBUG
	printf("tid: %d, rfd: %d, wfd: %d, %s: size: %d, written: %d, n: %d\n", tid, fileno(f), fd, file, size, count, n);
#endif
	fclose(f);
}

static void return_dir(char *dir, char *rp, int fd) {
	DIR *d = opendir(dir);
	if (!d) {
		err_resp(fd);
		return;
	}
#define SIZ (10 * 4096)
	char *buf = malloc(SIZ);
	char temp[64];

	strcpy(buf, DIR_START);
	strcat(buf, "<h1>");
	strcat(buf, rp);
	strcat(buf, "</h1>\r\n");
	strcat(buf, "<ol>\n");

	int len = strlen(buf);
	struct dirent *e;
	char b[1024];
	char * ctx = filename(rp);
	while (e = readdir(d)) {
		strcpy(b, "<li>\n");
		strcat(b, "<a href=\"");
		if (*ctx) {
			strcat(b, ctx);
			strcat(b, "/");
		}
		strcat(b, e->d_name);
		strcat(b, "\">");
		strcat(b, e->d_name);
		strcat(b, "</a>");
		if (e->d_type == DT_REG) {
			struct stat st;
			char p[PATH_MAX];
			strcpy(p, dir);
			strcat(p, "/");
			strcat(p, e->d_name);
			if (stat(p, &st)) {
				printf("error stat file: %s", e->d_name);
				continue;
			}
			snprintf(temp, sizeof(temp), "    %d", st.st_size);
			strcat(b, temp);
		}
		strcat(b, "</li>\n");
		int n = strlen(b);
		if (len + n >= SIZ) {
			// too many
			break;
		}
		strcat(buf, b);
		len += n;

	}
	strcpy(b, "</ol>\n");
	strcat(b, DIR_END);
	strcat(buf, b);
	len += strlen(b);

	snprintf(temp, sizeof(temp), "%d", len);

	char *header = resolve_placeholder(DIR_HEADER, b, sizeof(b), "length", temp);
	strcat(header, "\r\n");

	write(fd, header, strlen(header));

	write(fd, buf, len);

	free(buf);
	closedir(d);
}

static inline int from_hex(char *s) {
	if (*s >= 'a' && *s <= 'f') {
		return 10 + (*s - 'a');
	} else if (*s >= 'A' && *s <= 'F') {
		return 10 + (*s - 'A');
	} else if (*s >= '0' && *s <= '9') {
		return *s - '0';
	}
	return 0;
}

static char *url_decode(char *p, char *dst, int max) {
	char *s = p;
	while (*s) {
		if (*s == '%') {
			*dst++ = (char)(from_hex(s+1) << 4 | from_hex(s+2));
			s+=3;
		} else {
			*dst++=*s++;
		}
	}
	*dst = '\0';
	return dst;
}

static void handle_request(char *s, int len, int fd) {
	int n = 0;
	char *p = s;
	while (*p++ != ' ') n++; // method
	if (strncmp("GET", s, n)) {
		err_resp(fd);
		return;
	}
	s = p;
	n = 0;
	while (*p++ != ' ') n++; // path
	s[n] = '\0';

	char path[PATH_MAX];
	if (*s == '/' && !*(s+1)) {
		strcpy(path, root);
		strcat(path, "/index.html");
		struct stat st;
		if (!stat(path, &st)) {
			if (S_ISREG(st.st_mode)) {
				return_file(path, st.st_size, fd);
				return;
			}
		}
		path[strlen(path) - 1] = '\0';
		if (!stat(path, &st)) {
			if (S_ISREG(st.st_mode)) {
				return_file(path, st.st_size, fd);
				return;
			}
		}
	}
	strcpy(path, root);
	char dec[PATH_MAX];
	url_decode(s, dec, PATH_MAX);
	if (!strcmp("/favicon.ico", dec)) {
		no_content(fd);
		return;
	}
	strncat(path, dec, n);
	struct stat st;
	if (stat(path, &st)) {
		err_resp(fd);
		return;
	}
	if (S_ISREG(st.st_mode)) {
		return_file(path, st.st_size, fd);
	} else if (S_ISDIR(st.st_mode)) {
		return_dir(path, dec, fd);
	}
}

void *handle_connnect(void *a) {
	int sfd  = (int)a;
#define BUFSZ 1024
	char buf[BUFSZ];
	while (1) {
		int n = read(sfd, buf, BUFSZ-1);
		if (n <= 0) {
			goto out;
		}
		buf[n] = '\0';
		handle_request(buf, n, sfd);
	}
out:
	close(sfd);
	return NULL;
}

void *start_server(void *arg) {
	args *a = (args*)arg;
	struct addrinfo ah = {0};
	ah.ai_family = AF_INET;
	ah.ai_socktype = SOCK_STREAM;
	ah.ai_protocol = 0;
	struct addrinfo *ai;
	if (getaddrinfo(a->host, NULL, &ah, &ai)) {
		exit(EXIT_FAILURE);
	}
	int so = socket(PF_INET, SOCK_STREAM, 0);
	struct sockaddr_in addr = *(struct sockaddr_in*)ai->ai_addr;
	freeaddrinfo(ai);
	addr.sin_port = htons(a->port);
	if (bind(so, &addr, sizeof(addr))) {
		exit(EXIT_FAILURE);
	};
	listen(so, 50);
	printf("web server started at %#x:%d\n", ntohl(*(int*)&addr.sin_addr), a->port);

	if (a->root) {
		strncpy(root, a->root, sizeof(root));
	} else {
		if (!getcwd(root, sizeof(root))) {
			exit(EXIT_FAILURE);
		}
	}

	struct sockaddr_in sa;
	socklen_t sl = sizeof(sa);
	int fd;

	while (1) {
		fd = accept(so, &sa, &sl);
		if (fd == -1) {
			perror("error accepting request");
			continue;
		}
#define N 64
		char s[N];
		snprintf(s, N, "connection: %d, addr: %#x, port: %d\n", fd,
				ntohl(*(int*)&sa.sin_addr), ntohs(sa.sin_port));
		printf("%s", s);
    
		pthread_t tid;
		pthread_create(&tid, NULL, handle_connnect, (void*) fd);

	}
	return NULL;
}

#define USAGE \
	"webserver - a simple web server\n\n"\
	"options:\n"\
	"\t-r <directory> optional, root directory which is to be used as the context, default is cwd.\n"\
	"\t-p <port> optional, port to listen on, default is 8080\n"\
	"\t-h <host> optional, host to listen on, default is localhost\n"\
	"\t--help print this message\n"

int main(int argc, char **argv) {
	args a = {"127.0.0.1", 8080, NULL};
	// poor man's arg parse
	for (int i = 1; i< argc; ++i) {
		if (!strcmp(argv[i], "-h") && i < argc - 1) {
			a.host = argv[i+1];
			i+=1;
		} else if (!strcmp(argv[i], "-p") && i < argc - 1) {
			a.port = atoi(argv[i+1]);
			i+=1;
		} else if (!strcmp(argv[i], "-r") && i < argc - 1) {
			a.root = argv[i+1];
			i+=1;
		} else if (!strcmp(argv[i], "--help")) {
			printf("%s", USAGE);
			return 0;
		}
	}
	start_server(&a);
}

