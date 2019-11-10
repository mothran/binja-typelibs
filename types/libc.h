// stdio.h
typedef void* FILE;

struct _obstack_chunk
{
    char *limit;
    struct _obstack_chunk *prev;
    char contents[4];
};

struct obstack
{
    long chunk_size;
    struct _obstack_chunk *chunk;
    char *object_base;
    char *next_free;
    char *chunk_limit;
    union
    {
        int tempint;
        void *tempptr;
    } temp;
    int alignment_mask;
    struct _obstack_chunk *(*chunkfun) (void *, long);
    void (*freefun) (void *, struct _obstack_chunk *);
    void *extra_arg;
    unsigned int bitfield; // Modified, might be wrong
};


struct mbstate_t {
    int count;
    union
    {
        unsigned int wch;
        char wchb[4];
    } value;
};

struct fpos_t {
    long int pos;
    mbstate_t state;
};

// Variadic function params appear to still be broken on x86-64 and all reg calling ABI arch's, ref:
// https://github.com/Vector35/binaryninja-api/issues/1031

#ifdef SUPPORTED_VARIADIC
int printf(const char *format, ...);
int ___printf_chk(const char *format, ...);
int fprintf(FILE *stream, const char *format, ...);
int ___fprintf_chk(FILE *stream, const char *format, ...);
int dprintf(int fd, const char *format, ...);
int __dprintf_chk(int fd, const char *format, ...);

int sprintf(char *str, const char *format, ...);
int __sprintf_chk(char *str, const char *format, ...);

int snprintf(char *str, size_t size, const char *format, ...);
int ___snprintf_chk(char *str, size_t size, const char *format, ...);
int asprintf(char **strp, const char *fmt, ...);
int __asprintf_chk(char **strp, const char *fmt, ...);

long syscall(long number, ...);

int scanf(const char *format, ...);
int fscanf(FILE *stream, const char *format, ...);
int sscanf(const char *str, const char *format, ...);

int execl(const char *pathname, const char *arg, ...);
int execlp(const char *file, const char *arg, ...);
int execle(const char *pathname, const char *arg, ...);

int sigreturn(...);

int obstack_printf(struct obstack *obstack, const char *format, ...);
int __obstack_printf_chk(struct obstack *obstack, const char *format, ...);

#endif

int vprintf(const char *format, va_list ap);
int ___vprintf_chk(const char *format, va_list ap);
int vfprintf(FILE *stream, const char *format, va_list ap);
int ___vfprintf_chk(FILE *stream, const char *format, va_list ap);

int vdprintf(int fd, const char *format, va_list ap);
int __vdprintf_chk(int fd, const char *format, va_list ap);

int vsprintf(char *str, const char *format, va_list ap);
int ___vsprintf_chk(char *str, const char *format, va_list ap);

int vsnprintf(char *str, size_t size, const char *format, va_list ap);
int ___vsnprintf_chk(char *str, size_t size, const char *format, va_list ap);

int vscanf(const char *format, va_list ap);
int vsscanf(const char *str, const char *format, va_list ap);
int vfscanf(FILE *stream, const char *format, va_list ap);

int vasprintf(char **strp, const char *fmt, va_list ap);
int __vasprintf_chk(char **strp, const char *fmt, va_list ap);

int obstack_vprintf(struct obstack *obstack, const char *format, va_list args);
int __obstack_vprintf_chk(struct obstack *obstack, const char *format, va_list args);


char *gets(char *s);
char *__gets_chk(char *s);
int fgetc(FILE *stream);
char *fgets(char *s, int size, FILE *stream);
char *__fgets_chk(char *s, int size, FILE *stream);

int getc(FILE *stream);
int getchar(void);
int ungetc(int c, FILE *stream);
int fputc(int c, FILE *stream);
int fputs(const char *s, FILE *stream);
int putc(int c, FILE *stream);
int putchar(int c);
int puts(const char *s);

int remove(const char *pathname);
int rename(const char *oldpath, const char *newpath);
int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath);
int renameat2(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, unsigned int flags);
FILE *tmpfile(void);
char *tmpnam(char *s);
char *tmpnam_r(char *s);

int fclose(FILE *stream);
int fflush(FILE *stream);
FILE *fopen(const char *pathname, const char *mode);
FILE *fdopen(int fd, const char *mode);
FILE *freopen(const char *pathname, const char *mode, FILE *stream);
void setbuf(FILE *stream, char *buf);
void setbuffer(FILE *stream, char *buf, size_t size);
void setlinebuf(FILE *stream);
int setvbuf(FILE *stream, char *buf, int mode, size_t size);

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream);
size_t __fread_chk(void *ptr, size_t size, size_t nmemb, FILE *stream);

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream);

int fseek(FILE *stream, long offset, int whence);
long ftell(FILE *stream);
void rewind(FILE *stream);
int fgetpos(FILE *stream, fpos_t *pos);
int fsetpos(FILE *stream, const fpos_t *pos);

void clearerr(FILE *stream);
int feof(FILE *stream);
int ferror(FILE *stream);
int fileno(FILE *stream);

char *getlogin(void);
int setlogin(const char *name);
int getlogin_r(char *buf, size_t bufsize);
int __getlogin_r_chk(char *buf, size_t bufsize);

int getc_unlocked(FILE *stream);
int getchar_unlocked(void);
int putc_unlocked(int c, FILE *stream);
int putchar_unlocked(int c);

void clearerr_unlocked(FILE *stream);
int feof_unlocked(FILE *stream);
int ferror_unlocked(FILE *stream);
int fileno_unlocked(FILE *stream);
int fflush_unlocked(FILE *stream);
int fgetc_unlocked(FILE *stream);
int fputc_unlocked(int c, FILE *stream);
size_t fread_unlocked(void *ptr, size_t size, size_t n, FILE *stream);
size_t __fread_unlocked_chk(void *ptr, size_t size, size_t n, FILE *stream);

size_t fwrite_unlocked(const void *ptr, size_t size, size_t n, FILE *stream);

char *fgets_unlocked(char *s, int n, FILE *stream);
char *__fgets_unlocked_chk(char *s, int n, FILE *stream);

int fputs_unlocked(const char *s, FILE *stream);

ssize_t getline(char **lineptr, size_t *n, FILE *stream);
ssize_t getdelim(char **lineptr, size_t *n, int delim, FILE *stream);

FILE *popen(const char *command, const char *type);
int pclose(FILE *stream);

void flockfile(FILE *filehandle);
int ftrylockfile(FILE *filehandle);
void funlockfile(FILE *filehandle);

FILE *open_memstream(char **ptr, size_t *sizeloc);


// stdlib.h
typedef uint32_t wchar_t; // Assumption, TODO: validate

struct div_t {
    int quot;
    int rem;
};
struct ldiv_t {
    long int quot;
    long int rem;
};
struct lldiv_t {
    long long int quot;
    long long int rem;
};
struct random_data {
    int32_t *fptr;
    int32_t *rptr;
    int32_t *state;
    int rand_type;
    int rand_deg;
    int rand_sep;
    int32_t *end_ptr;
};
struct drand48_data {
    unsigned short int x[3];
    unsigned short int old_x[3];
    unsigned short int c;
    unsigned short int init;
    unsigned long long int a;
};

double atof(const char *nptr);
int atoi(const char *nptr);
long atol(const char *nptr);
long long atoll(const char *nptr);
double strtod(const char *nptr, char **endptr);
float strtof(const char *nptr, char **endptr);
long double strtold(const char *nptr, char **endptr);
long int strtol(const char *nptr, char **endptr, int base);
long long int strtoll(const char *nptr, char **endptr, int base);
unsigned long int strtoul(const char *nptr, char **endptr, int base);
unsigned long long int strtoull(const char *nptr, char **endptr, int base);

long a64l(const char *str64);
char *l64a(long value);

int rand(void);
int rand_r(unsigned int *seedp);
void srand(unsigned int seed);

void *malloc(size_t size);
void free(void *ptr);
void *calloc(size_t nmemb, size_t size);
void *realloc(void *ptr, size_t size);
void *reallocarray(void *ptr, size_t nmemb, size_t size);
void *alloca(size_t size);
int posix_memalign(void **memptr, size_t alignment, size_t size);
void *aligned_alloc(size_t alignment, size_t size);
void *valloc(size_t size);


int atexit(void (*function)(void));
int on_exit(void (*function)(int , void *), void *arg);
char *getenv(const char *name);
int putenv(char *string);
char *secure_getenv(const char *name);
int setenv(const char *name, const char *value, int overwrite);
int unsetenv(const char *name);
int clearenv(void);

int at_quick_exit (void (*function) (void));
void quick_exit (int status) __noreturn;

int system(const char *command);

void *bsearch(const void *key, const void *base, size_t nmemb, size_t size, int (*compar)(const void *, const void *));
void qsort(void *base, size_t nmemb, size_t size, int (*compar)(const void *, const void *));

void qsort_r(void *base, size_t nmemb, size_t size, int (*compar)(const void *, const void *, void *),void *arg);

int abs(int j);
long int labs(long int j);
long long int llabs(long long int j);
div_t div(int numerator, int denominator);
ldiv_t ldiv(long numerator, long denominator);
lldiv_t lldiv(long long numerator, long long denominator);
char *ecvt(double number, int ndigits, int *decpt, int *sign);
char *fcvt(double number, int ndigits, int *decpt, int *sign);
char *gcvt(double number, int ndigit, char *buf);
char *qecvt(long double number, int ndigits, int *decpt, int *sign);
char *qfcvt(long double number, int ndigits, int *decpt, int *sign);
char *qgcvt(long double number, int ndigit, char *buf);

int ecvt_r(double number, int ndigits, int *decpt, int *sign, char *buf, size_t len);
int fcvt_r(double number, int ndigits, int *decpt, int *sign, char *buf, size_t len);
int qecvt_r(long double number, int ndigits, int *decpt, int *sign, char *buf, size_t len);
int qfcvt_r(long double number, int ndigits, int *decpt, int *sign, char *buf, size_t len);

int mblen(const char *s, size_t n);
int mbtowc(wchar_t *pwc, const char *s, size_t n);
int wctomb(char *s, wchar_t wc);
int __wctomb_chk(char *s, wchar_t wc);

size_t mbstowcs(wchar_t *dest, const char *src, size_t n);
size_t __mbstowcs_chk(wchar_t *dest, const char *src, size_t n);

size_t wcstombs(char *dest, const wchar_t *src, size_t n);
size_t __wcstombs_chk(char *dest, const wchar_t *src, size_t n);

long int random(void);
void srandom(unsigned int seed);
char *initstate(unsigned int seed, char *state, size_t n);
char *setstate(char *state);

int random_r(struct random_data *buf, int32_t *result);
int srandom_r(unsigned int seed, struct random_data *buf);
int initstate_r(unsigned int seed, char *statebuf, size_t statelen, struct random_data *buf);
int setstate_r(char *statebuf, struct random_data *buf);

double drand48(void);
double erand48(unsigned short xsubi[3]);
long int lrand48(void);
long int nrand48(unsigned short xsubi[3]);
long int mrand48(void);
long int jrand48(unsigned short xsubi[3]);
void srand48(long int seedval);
unsigned short *seed48(unsigned short seed16v[3]);
void lcong48(unsigned short param[7]);

int drand48_r(struct drand48_data *buffer, double *result);
int erand48_r(unsigned short xsubi[3], struct drand48_data *buffer, double *result);
int lrand48_r(struct drand48_data *buffer, long int *result);
int nrand48_r(unsigned short int xsubi[3], struct drand48_data *buffer, long int *result);
int mrand48_r(struct drand48_data *buffer, long int *result);
int jrand48_r(unsigned short int xsubi[3], struct drand48_data *buffer, long int *result);
int srand48_r(long int seedval, struct drand48_data *buffer);
int seed48_r(unsigned short int seed16v[3], struct drand48_data *buffer);
int lcong48_r(unsigned short int param[7], struct drand48_data *buffer);

void _Exit(int status) __noreturn;

char *mktemp(char *template);
int mkstemp(char *template);
int mkostemp(char *template, int flags);
int mkstemps(char *template, int suffixlen);
int mkostemps(char *template, int suffixlen, int flags);

char *realpath(const char *path, char *resolved_path);
char *__realpath_chk(const char *path, char *resolved_path);

int getsubopt(char **optionp, char * const *tokens, char **valuep);
int getloadavg(double loadavg[], int nelem);

char *ptsname(int fd);
int ptsname_r(int fd, char *buf, size_t buflen);
int __ptsname_r_chk(int fd, char *buf, size_t buflen);


// ctype.h
struct locale_t {
    void *locales[13]; // TODO: __locale_data struct
    const unsigned short int *ctype_b;
    const int *ctype_tolower;
    const int *ctype_toupper;
    const char *names[13];
};

int isalnum(int c);
int isalpha(int c);
int iscntrl(int c);
int isdigit(int c);
int isgraph(int c);
int islower(int c);
int isprint(int c);
int ispunct(int c);
int isspace(int c);
int isupper(int c);
int isxdigit(int c);

int isascii(int c);
int isblank(int c);

int isalnum_l(int c, locale_t locale);
int isalpha_l(int c, locale_t locale);
int isblank_l(int c, locale_t locale);
int iscntrl_l(int c, locale_t locale);
int isdigit_l(int c, locale_t locale);
int isgraph_l(int c, locale_t locale);
int islower_l(int c, locale_t locale);
int isprint_l(int c, locale_t locale);
int ispunct_l(int c, locale_t locale);
int isspace_l(int c, locale_t locale);
int isupper_l(int c, locale_t locale);
int isxdigit_l(int c, locale_t locale);

int isascii_l(int c, locale_t locale);

int toupper(int c);
int tolower(int c);
int toupper_l(int c, locale_t locale);
int tolower_l(int c, locale_t locale);


// unistd.h
typedef unsigned int uid_t;
typedef unsigned int gid_t;
typedef int pid_t;
typedef long int intptr_t;
typedef long int off_t;
typedef unsigned int useconds_t;

struct stat {
    unsigned long int   st_dev;
    unsigned long int   st_ino;
    unsigned int        st_mode;
    unsigned long int   st_nlink;
    unsigned int        st_uid;
    unsigned int        st_gid;
    unsigned long int   st_rdev;
    long int            st_size;
    long int            st_blksize;
    long int            st_blocks;
};

int access(const char *pathname, int mode);
int faccessat(int dirfd, const char *pathname, int mode, int flags);
unsigned int alarm(unsigned int seconds);
int brk(void *addr);
void *sbrk(intptr_t increment);
int chdir(const char *path);
int fchdir(int fd);
int chroot(const char *path);
int chown(const char *pathname, uid_t owner, gid_t group);
int fchown(int fd, uid_t owner, gid_t group);
int lchown(const char *pathname, uid_t owner, gid_t group);
int fchownat(int dirfd, const char *pathname, uid_t owner, gid_t group, int flags);
int close(int fd);
size_t confstr(int name, char *buf, size_t len);
size_t __confstr_chk(int name, char *buf, size_t len);

char *crypt(const char *key, const char *salt);
char *ctermid(char *s);
char *cuserid(char *string);
int dup(int fildes);
int dup2(int fildes, int fildes2);

int execve(const char *pathname, char *const argv[], char *const envp[]);
int fexecve(int fd, char *const argv[], char *const envp[]);

int execv(const char *pathname, char *const argv[]);
int execvp(const char *file, char *const argv[]);
int execvpe(const char *file, char *const argv[], char *const envp[]);

void _exit(int status) __noreturn;
pid_t fork(void);
long fpathconf(int fd, int name);
long pathconf(const char *path, int name);

int fsync(int fd);
int fdatasync(int fd);
void sync(void);
int syncfs(int fd);
int truncate(const char *path, off_t length);
int ftruncate(int fd, off_t length);

char *getcwd(char *buf, size_t size);
char *__getcwd_chk(char *buf, size_t size);

char *getwd(char *buf);
char *__getwd_chk(char *buf);

char *get_current_dir_name(void);
int getdtablesize(void);
gid_t getegid(void);
uid_t geteuid(void);
gid_t getgid(void);
int getgroups(int gidsetsize, gid_t grouplist[]);
int __getgroups_chk(int gidsetsize, gid_t grouplist[]);

long gethostid(void);
int sethostid(long hostid);
char *getlogin(void);
int getlogin_r(char *buf, size_t bufsize);

int getopt(int argc, char * const argv[], const char *optstring);

int getpagesize(void);
char *getpass(const char *prompt);
pid_t getpgid(pid_t pid);
pid_t getpgrp(void);
pid_t getpid(void);
pid_t getppid(void);
pid_t getsid(pid_t pid);
uid_t getuid(void);

int isatty(int fd);
int ttyslot(void);
int link(const char *oldpath, const char *newpath);
int linkat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags);
int lockf(int fd, int cmd, off_t len);
off_t lseek(int fd, off_t offset, int whence);
int nice(int inc);
int pause(void);
int pipe(int fildes[2]);
ssize_t pread(int fildes, void *buf, size_t nbyte, off_t offset);
ssize_t __pread_chk(int fildes, void *buf, size_t nbyte, off_t offset);

int pthread_atfork(void (*prepare)(void), void (*parent)(void), void (*child)(void));
ssize_t pwrite(int fildes, const void *buf, size_t nbyte, off_t offset);
ssize_t read(int fd, void *buf, size_t count);
ssize_t __read_chk(int fd, void *buf, size_t count);

ssize_t readlink(const char *pathname, char *buf, size_t bufsiz);
ssize_t __readlink_chk(const char *pathname, char *buf, size_t bufsiz);

ssize_t readlinkat(int dirfd, const char *pathname, char *buf, size_t bufsiz);
ssize_t __readlinkat_chk(int dirfd, const char *pathname, char *buf, size_t bufsiz);

int rmdir(const char *pathname);

int setgid(gid_t gid);
int setpgid(pid_t pid, pid_t pgid);
pid_t getpgid(pid_t pid);
pid_t setpgrp(void);
int setregid(gid_t rgid, gid_t egid);
int setreuid(uid_t ruid, uid_t euid);
pid_t setsid(void);
int setuid(uid_t uid);

unsigned int sleep(unsigned int seconds);
void swab(const void *from, void *to, ssize_t n);
int symlink(const char *path1, const char *path2);
int symlinkat(const char *path1, int fd, const char *path2);

long sysconf(int name);

pid_t tcgetpgrp(int fd);
int tcsetpgrp(int fd, pid_t pgrp);
char *ttyname(int fd);
int ttyname_r(int fd, char *buf, size_t buflen);
int __ttyname_r_chk(int fd, char *buf, size_t buflen);

useconds_t ualarm(useconds_t usecs, useconds_t interval);
int unlink(const char *pathname);
int unlinkat(int dirfd, const char *pathname, int flags);
int usleep(useconds_t usec);
pid_t vfork(void);
ssize_t write(int fd, const void *buf, size_t count);

int __xstat(int ver, const char * path, struct stat * stat_buf);

int gethostname(char *name, size_t len);
int __gethostname_chk(char *name, size_t len);

int sethostname(const char *name, size_t len);
int getdomainname(char *name, size_t len);
int __getdomainname_chk(char *name, size_t len);

int setdomainname(const char *name, size_t len);

int vhangup(void);
int revoke(const char *file);
int profil(unsigned short *buf, size_t bufsiz, size_t offset, unsigned int scale);
int acct(const char *filename);

char *getusershell(void);
void setusershell(void);
void endusershell(void);
int daemon(int nochdir, int noclose);
int getentropy(void *buffer, size_t length);



// fcntl.h
typedef int mode_t;

#ifdef SUPPORTED_VARIADIC

int fcntl(int fildes, int cmd, ...);

#endif

#ifdef SUPPORTED_VARIADIC
int open(const char *pathname, int flags, ...);
int openat(int dirfd, const char *pathname, int flags, ...);

#else
// Omitting mode param as default case
int open(const char *pathname, int flags);
int openat(int dirfd, const char *pathname, int flags);
#endif


int creat(const char *pathname, mode_t mode);

int lockf(int fd, int cmd, off_t len);
int posix_fadvise(int fd, off_t offset, off_t len, int advice);
int posix_fadvise(int fd, off_t offset, off_t len, int advice);


// getopt.h

struct option {
    const char *name;
    int has_arg;
    int *flag;
    int val;
};

int getopt_long(int argc, char * const argv[], const char *optstring, const struct option *longopts, int *longindex);
int getopt_long_only(int argc, char * const argv[], const char *optstring, const struct option *longopts, int *longindex);


// string.h
void *memcpy(void *dest, const void *src, size_t n);
void *__memcpy_chk(void *dest, const void *src, size_t n);

void *mempcpy(void *dest, const void *src, size_t n);
void *__mempcpy_chk(void *dest, const void *src, size_t n);

void *memmove(void *dest, const void *src, size_t n);
void *__memmove_chk(void *dest, const void *src, size_t n);

void *memccpy(void *dest, const void *src, int c, size_t n);
char *strcpy(char *dest, const char *src);
char *__strcpy_chk(char *dest, const char *src);

char *strncpy(char *dest, const char *src, size_t n);
char *__strncpy_chk(char *dest, const char *src, size_t n);

char *strcat(char *dest, const char *src);
char *__strcat_chk(char *dest, const char *src);

char *strncat(char *dest, const char *src, size_t n);
char *__strncat_chk(char *dest, const char *src, size_t n);

size_t strlcpy(char *dst, const char *src, size_t size);
size_t strlcat(char *dst, const char *src, size_t size);

int memcmp(const void *s1, const void *s2, size_t n);
int strcmp(const char *s1, const char *s2);
int strncmp(const char *s1, const char *s2, size_t n);
size_t strxfrm(char *dest, const char *src, size_t n);
size_t strxfrm_l(char * s1, const char * s2, size_t n, locale_t locale);

int strcoll(const char *s1, const char *s2);
int strcoll_l(const char *s1, const char *s2, locale_t locale);

char *strdup(const char *s);
char *strndup(const char *s, size_t n);
char *strdupa(const char *s);
char *strndupa(const char *s, size_t n);

void *memchr(const void *s, int c, size_t n);
void *memrchr(const void *s, int c, size_t n);
void *rawmemchr(const void *s, int c);

char *strchr(const char *s, int c);
char *strrchr(const char *s, int c);
char *strchrnul(const char *s, int c);
size_t strspn(const char *s, const char *accept);
size_t strcspn(const char *s, const char *reject);
char *strpbrk(const char *s, const char *accept);

char *strstr(const char *haystack, const char *needle);
char *strcasestr(const char *haystack, const char *needle);
char *strtok(char *str, const char *delim);
char *strtok_r(char *str, const char *delim, char **saveptr);

void *memset(void *s, int c, size_t n);
void *__memset_chk(void *s, int c, size_t n);

char *strerror(int errnum);
char *strerror_l(int errnum, locale_t locale);
int strerror_r(int errnum, char *buf, size_t buflen);

size_t strlen(const char *s);
size_t strnlen(const char *s, size_t maxlen);

int bcmp(const void *s1, const void *s2, size_t n);
void bcopy(const void *src, void *dest, size_t n);
void bzero(void *s, size_t n);
void explicit_bzero(void *s, size_t n);
void __explicit_bzero_chk(void *s, size_t n);

char *index(const char *s, int c);
char *rindex(const char *s, int c);

int ffs(int i);
int ffsl(long int i);
int ffsll(long long int i);

int strcasecmp(const char *s1, const char *s2);
int strcasecmp_l(const char *s1, const char *s2, locale_t locale);
int strncasecmp(const char *s1, const char *s2, size_t n);
int strncasecmp_l(const char *s1, const char *s2, size_t n, locale_t locale);

char *strsep(char **stringp, const char *delim);
char *strsignal(int sig);
char *stpcpy(char *dest, const char *src);
char *__stpcpy_chk(char *dest, const char *src);

char *stpncpy(char *dest, const char *src, size_t n);
char *__stpncpy_chk(char *dest, const char *src, size_t n);


// time.h
typedef long __kernel_time_t;

struct timespec {
	__kernel_time_t	tv_sec;
	long tv_nsec;
};

typedef long int clock_t;
typedef long int time_t;

struct tm
{
    int tm_sec;
    int tm_min;
    int tm_hour;
    int tm_mday;
    int tm_mon;
    int tm_year;
    int tm_wday;
    int tm_yday;
    int tm_isdst;
    long int tm_gmtoff;
    const char *tm_zone;
};

typedef int clockid_t;
typedef void* sigevent; // TODO
typedef void* timer_t;


struct itimerspec {
	struct timespec it_interval;
	struct timespec it_value;
};

clock_t clock(void);
time_t time(time_t *tloc);
double difftime(time_t time1, time_t time0);
char *asctime(const struct tm *tm);
char *asctime_r(const struct tm *tm, char *buf);
char *ctime(const time_t *timep);
char *ctime_r(const time_t *timep, char *buf);
struct tm *gmtime(const time_t *timep);
struct tm *gmtime_r(const time_t *timep, struct tm *result);
struct tm *localtime(const time_t *timep);
struct tm *localtime_r(const time_t *timep, struct tm *result);
time_t mktime(struct tm *tm);
size_t strftime(char *s, size_t max, const char *format, const struct tm *tm);
size_t strftime_l(char *s, size_t maxsize, const char *format, const struct tm *timeptr, locale_t locale);
void tzset(void);
int stime(const time_t *t);
time_t timelocal(struct tm *tm);
time_t timegm(struct tm *tm);
int dysize(int year);
int nanosleep(const struct timespec *rqtp, struct timespec *rmtp);
int clock_getres(clockid_t clk_id, struct timespec *res);
int clock_gettime(clockid_t clk_id, struct timespec *tp);
int clock_settime(clockid_t clk_id, const struct timespec *tp);
int clock_nanosleep(clockid_t clock_id, int flags, const struct timespec *rqtp, struct timespec *rmtp);
int clock_getcpuclockid(pid_t pid, clockid_t *clock_id);

int timer_create(clockid_t clockid, sigevent *evp, timer_t *timerid);
int timer_delete(timer_t timerid);
int timer_settime(timer_t timerid, int flags, const struct itimerspec *new_value, struct itimerspec *old_value);
int timer_gettime(timer_t timerid, struct itimerspec *curr_value);
int timer_getoverrun(timer_t timerid);
int timespec_get(struct timespec *ts, int base);


// pthread.h
typedef unsigned long int pthread_t;

union pthread_attr_t
{
    char __size[56]; // arch depenedent, just grabbed x86-64 as a default.
    long int __align;
};

struct sched_param
{
    int sched_priority;
};

typedef int pthread_once_t;

typedef void* pthread_mutex_t;       // TODO
typedef void* pthread_mutexattr_t;   // TODO
typedef void* pthread_rwlock_t;      // TODO
typedef void* pthread_rwlockattr_t;  // TODO
typedef void* pthread_cond_t;        // TODO
typedef void* pthread_condattr_t;    // TODO
typedef void* pthread_barrier_t;     // TODO
typedef void* pthread_barrierattr_t; // TODO

typedef volatile int pthread_spinlock_t;
typedef unsigned int pthread_key_t;

int pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine) (void *), void *arg);
int pthread_join(pthread_t thread, void **retval);
int pthread_detach(pthread_t thread);
pthread_t pthread_self(void);
int pthread_equal(pthread_t t1, pthread_t t2);

int pthread_attr_init(pthread_attr_t *attr);
int pthread_attr_destroy(pthread_attr_t *attr);
int pthread_attr_setdetachstate(pthread_attr_t *attr, int detachstate);
int pthread_attr_getdetachstate(const pthread_attr_t *attr, int *detachstate);
int pthread_attr_setguardsize(pthread_attr_t *attr, size_t guardsize);
int pthread_attr_getguardsize(const pthread_attr_t *attr, size_t *guardsize);
int pthread_attr_setschedparam(pthread_attr_t *attr, const struct sched_param *param);
int pthread_attr_getschedparam(const pthread_attr_t *attr, struct sched_param *param);
int pthread_attr_setschedpolicy(pthread_attr_t *attr, int policy);
int pthread_attr_getschedpolicy(const pthread_attr_t *attr, int *policy);
int pthread_attr_setinheritsched(pthread_attr_t *attr, int inheritsched);
int pthread_attr_getinheritsched(const pthread_attr_t *attr, int *inheritsched);
int pthread_attr_setscope(pthread_attr_t *attr, int scope);
int pthread_attr_getscope(const pthread_attr_t *attr, int *scope);
int pthread_attr_setstackaddr(pthread_attr_t *attr, void *stackaddr);
int pthread_attr_getstackaddr(const pthread_attr_t *attr, void **stackaddr);
int pthread_attr_setstacksize(pthread_attr_t *attr, size_t stacksize);
int pthread_attr_getstacksize(const pthread_attr_t *attr, size_t *stacksize);
int pthread_attr_setstack(pthread_attr_t *attr, void *stackaddr, size_t stacksize);
int pthread_attr_getstack(const pthread_attr_t *attr, void **stackaddr, size_t *stacksize);

int pthread_setschedparam(pthread_t thread, int policy, const struct sched_param *param);
int pthread_getschedparam(pthread_t thread, int *policy, struct sched_param *param);
int pthread_setschedprio(pthread_t thread, int prio);

int pthread_once(pthread_once_t *once_control, void (*init_routine)(void));
int pthread_setcancelstate(int state, int *oldstate);
int pthread_setcanceltype(int type, int *oldtype);
int pthread_cancel(pthread_t thread);
void pthread_testcancel(void);

int pthread_mutex_init(pthread_mutex_t *mutex, const pthread_mutexattr_t *attr);
int pthread_mutex_destroy(pthread_mutex_t *mutex);
int pthread_mutex_lock(pthread_mutex_t *mutex);
int pthread_mutex_trylock(pthread_mutex_t *mutex);
int pthread_mutex_unlock(pthread_mutex_t *mutex);
int pthread_mutex_timedlock(pthread_mutex_t *mutex, const struct timespec *abstime);
int pthread_mutex_getprioceiling(const pthread_mutex_t *mutex, int *prioceiling);
int pthread_mutex_setprioceiling(pthread_mutex_t *mutex, int prioceiling, int *old_ceiling);
int pthread_mutex_consistent(pthread_mutex_t *mutex);

int pthread_mutexattr_init(pthread_mutexattr_t *attr);
int pthread_mutexattr_destroy(pthread_mutexattr_t *attr);
int pthread_mutexattr_getpshared(const pthread_mutexattr_t *attr, int *pshared);
int pthread_mutexattr_setpshared(pthread_mutexattr_t *attr, int pshared);
int pthread_mutexattr_gettype(const pthread_mutexattr_t *attr, int *type);
int pthread_mutexattr_settype(pthread_mutexattr_t *attr, int type);
int pthread_mutexattr_getprotocol(const pthread_mutexattr_t *attr, int *protocol);
int pthread_mutexattr_setprotocol(pthread_mutexattr_t *attr, int protocol);
int pthread_mutexattr_getprioceiling(const pthread_mutexattr_t *attr, int *prioceiling);
int pthread_mutexattr_setprioceiling(pthread_mutexattr_t *attr, int prioceiling);
int pthread_mutexattr_getrobust(const pthread_mutexattr_t *attr, int *robustness);
int pthread_mutexattr_setrobust(const pthread_mutexattr_t *attr, int robustness);

int pthread_rwlock_destroy(pthread_rwlock_t *rwlock);
int pthread_rwlock_init(pthread_rwlock_t *rwlock, const pthread_rwlockattr_t *attr);
int pthread_rwlock_rdlock(pthread_rwlock_t *rwlock);
int pthread_rwlock_tryrdlock(pthread_rwlock_t *rwlock);
int pthread_rwlock_timedrdlock(pthread_rwlock_t *rwlock, const struct timespec *abstime);
int pthread_rwlock_wrlock(pthread_rwlock_t *rwlock);
int pthread_rwlock_trywrlock(pthread_rwlock_t *rwlock);
int pthread_rwlock_wrlock(pthread_rwlock_t *rwlock);
int pthread_rwlock_timedwrlock(pthread_rwlock_t *rwlock, const struct timespec *abstime);
int pthread_rwlock_unlock(pthread_rwlock_t *rwlock);
int pthread_rwlockattr_destroy(pthread_rwlockattr_t *attr);
int pthread_rwlockattr_init(pthread_rwlockattr_t *attr);

int pthread_rwlockattr_getpshared(const pthread_rwlockattr_t *attr, int *pshared);
int pthread_rwlockattr_setpshared(pthread_rwlockattr_t *attr, int pshared);
int pthread_rwlockattr_setkind_np(pthread_rwlockattr_t *attr, int pref);
int pthread_rwlockattr_getkind_np(const pthread_rwlockattr_t *attr, int *pref);
int pthread_cond_destroy(pthread_cond_t *cond);
int pthread_cond_init(pthread_cond_t *cond, const pthread_condattr_t *attr);
int pthread_cond_broadcast(pthread_cond_t *cond);
int pthread_cond_signal(pthread_cond_t *cond);
int pthread_cond_timedwait(pthread_cond_t *cond, pthread_mutex_t *mutex, const struct timespec *abstime);
int pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex);
int pthread_condattr_destroy(pthread_condattr_t *attr);
int pthread_condattr_init(pthread_condattr_t *attr);
int pthread_condattr_getpshared(const pthread_condattr_t *attr, int *pshared);
int pthread_condattr_setpshared(pthread_condattr_t *attr, int pshared);
int pthread_condattr_getclock(const pthread_condattr_t *attr, clockid_t *clock_id);
int pthread_condattr_setclock(pthread_condattr_t *attr, clockid_t clock_id);
int pthread_spin_init(pthread_spinlock_t *lock, int pshared);
int pthread_spin_destroy(pthread_spinlock_t *lock);
int pthread_spin_lock(pthread_spinlock_t *lock);
int pthread_spin_trylock(pthread_spinlock_t *lock);
int pthread_spin_unlock(pthread_spinlock_t *lock);
int pthread_barrier_destroy(pthread_barrier_t *barrier);
int pthread_barrier_init(pthread_barrier_t *barrier, const pthread_barrierattr_t *attr, unsigned int count);
int pthread_barrier_wait(pthread_barrier_t *barrier);
int pthread_barrierattr_destroy(pthread_barrierattr_t *attr);
int pthread_barrierattr_init(pthread_barrierattr_t *attr);
int pthread_barrierattr_getpshared(const pthread_barrierattr_t *attr, int *pshared);
int pthread_barrierattr_setpshared(pthread_barrierattr_t *attr, int pshared);
int pthread_key_create(pthread_key_t *key, void (*destructor)(void*));
int pthread_key_delete(pthread_key_t key);
void *pthread_getspecific(pthread_key_t key);
int pthread_setspecific(pthread_key_t key, const void *value);
int pthread_getcpuclockid(pthread_t thread, clockid_t *clock_id);


// signal.h
typedef void (*sighandler_t) (int);

typedef void* siginfo_t; // TODO
typedef unsigned long sigset_t;

struct sigvec {
    void (*sv_handler)(int);
    int sv_mask;
    int sv_flags;
};

typedef void (*__sighandler_t) (int);
typedef void* __sigrestore_t;

struct sigaction {
	__sighandler_t sa_handler;
	unsigned long sa_flags;
	__sigrestore_t sa_restorer;
	sigset_t sa_mask;
};

struct stack_t {
	void *ss_sp;
	int ss_flags;
	size_t ss_size;
};

union sigval
{
    int sival_int;
    void *sival_ptr;
};


sighandler_t signal(int signum, sighandler_t handler);
int kill(pid_t pid, int sig);
int killpg(int pgrp, int sig);
int raise(int sig);
int gsignal(int signum);
sighandler_t ssignal(int signum, sighandler_t action);
void psignal(int sig, const char *s);
void psiginfo(const siginfo_t *pinfo, const char *s);
int sigvec(int sig, const struct sigvec *vec, struct sigvec *ovec);
int sigmask(int signum);
int sigblock(int mask);
int sigsetmask(int mask);
int siggetmask(void);
int sigemptyset(sigset_t *set);
int sigfillset(sigset_t *set);
int sigaddset(sigset_t *set, int signum);
int sigdelset(sigset_t *set, int signum);
int sigismember(const sigset_t *set, int signum);
int sigprocmask(int how, const sigset_t *set, sigset_t *oldset);
int sigsuspend(const sigset_t *sigmask);
int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact);
int sigpending(sigset_t *set);
int sigwait(const sigset_t *set, int *sig);
int sigwaitinfo(const sigset_t *set, siginfo_t *info);
int sigtimedwait(const sigset_t *set, siginfo_t *info, const struct timespec *timeout);
int sigqueue(pid_t pid, int sig, const union sigval value);
int siginterrupt(int sig, int flag);
int sigaltstack(const stack_t *ss, stack_t *oss);
int pthread_sigmask(int how, const sigset_t *set, sigset_t *oldset);
int pthread_kill(pthread_t thread, int sig);

// sys/socket.h

typedef unsigned short int sa_family_t;
typedef unsigned int socklen_t;

struct sockaddr {
    sa_family_t sa_family;
    char sa_data[14];
};

struct iovec {
    void *iov_base;
    size_t iov_len;
};

struct msghdr {
    void *msg_name;
    socklen_t msg_namelen;
    struct iovec *msg_iov;
    size_t msg_iovlen;
    void *msg_control;
    size_t msg_controllen;
    int msg_flags;
};

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags);
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen);
int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen);

int listen(int socket, int backlog);

ssize_t recv(int sockfd, void *buf, size_t len, int flags);
ssize_t __recv_chk(int sockfd, void *buf, size_t len, int flags);

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen);
ssize_t __recvfrom_chk(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen);

ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags);

ssize_t send(int sockfd, const void *buf, size_t len, int flags);
ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);
ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags);

int shutdown(int sockfd, int how);
int socket(int domain, int type, int protocol);
int sockatmark(int sockfd);
int socketpair(int domain, int type, int protocol, int socket_vector[2]);
int isfdtype(int fd, int fdtype);

// libintl.h
char *gettext(const char *msgid);
char *dgettext(const char *domainname, const char *msgid);
char *dcgettext(const char *domainname, const char *msgid, int category);
char *ngettext(const char *msgid, const char *msgid_plural, unsigned long int n);
char *dngettext(const char *domainname, const char *msgid, const char *msgid_plural, unsigned long int n);
char *dcngettext(const char *domainname, const char *msgid, const char *msgid_plural, unsigned long int n, int category);
char *textdomain(const char *domainname);
char *bindtextdomain(const char *domainname, const char *dirname);
char *bind_textdomain_codeset(const char *domainname, const char *codeset);

// wctype.h


// wchar.h
typedef uint32_t wchat_t;
typedef unsigned int wint_t;

wchar_t *wcscpy(wchar_t *dest, const wchar_t *src);
wchar_t *__wcscpy_chk(wchar_t *dest, const wchar_t *src);
wchar_t *wcsncpy(wchar_t *dest, const wchar_t *src, size_t n);
wchar_t *__wcsncpy_chk(wchar_t *dest, const wchar_t *src, size_t n);

wchar_t *wcscat(wchar_t *dest, const wchar_t *src);
wchar_t *__wcscat_chk(wchar_t *dest, const wchar_t *src);

wchar_t *wcsncat(wchar_t *dest, const wchar_t *src, size_t n);
wchar_t *__wcsncat_chk(wchar_t *dest, const wchar_t *src, size_t n);
int wcscmp(const wchar_t *s1, const wchar_t *s2);
int wcsncmp(const wchar_t *s1, const wchar_t *s2, size_t n);
int wcscasecmp(const wchar_t *s1, const wchar_t *s2);
int wcsncasecmp(const wchar_t *s1, const wchar_t *s2, size_t n);
int wcscasecmp_l(const wchar_t *ws1, const wchar_t *ws2, locale_t locale);
int wcsncasecmp_l(const wchar_t *ws1, const wchar_t *ws2, size_t n, locale_t locale);
int wcscoll(const wchar_t *ws1, const wchar_t *ws2);
int wcscoll_l(const wchar_t *ws1, const wchar_t *ws2, locale_t locale);
size_t wcsxfrm(wchar_t * ws1, const wchar_t * ws2, size_t n);
size_t wcsxfrm_l(wchar_t * ws1, const wchar_t * ws2, size_t n, locale_t locale);
wchar_t *wcsdup(const wchar_t *s);
wchar_t *wcschr(const wchar_t *wcs, wchar_t wc);
wchar_t *wcsrchr(const wchar_t *wcs, wchar_t wc);
size_t wcscspn(const wchar_t *wcs, const wchar_t *reject);
size_t wcsspn(const wchar_t *wcs, const wchar_t *accept);
wchar_t *wcspbrk(const wchar_t *wcs, const wchar_t *accept);
wchar_t *wcsstr(const wchar_t *haystack, const wchar_t *needle);
wchar_t *wcstok(wchar_t *wcs, const wchar_t *delim, wchar_t **ptr);
size_t wcslen(const wchar_t *s);
size_t wcsnlen(const wchar_t *s, size_t maxlen);

wchar_t *wmemchr(const wchar_t *s, wchar_t c, size_t n);
int wmemcmp(const wchar_t *s1, const wchar_t *s2, size_t n);
wchar_t *wmemcpy(wchar_t *dest, const wchar_t *src, size_t n);
wchar_t *__wmemcpy_chk(wchar_t *dest, const wchar_t *src, size_t n);

wchar_t *wmemmove(wchar_t *dest, const wchar_t *src, size_t n);
wchar_t *__wmemmove_chk(wchar_t *dest, const wchar_t *src, size_t n);
wchar_t *wmemset(wchar_t *wcs, wchar_t wc, size_t n);
wchar_t *__wmemset_chk(wchar_t *wcs, wchar_t wc, size_t n);

wint_t btowc(int c);
int wctob(wint_t c);

int mbsinit(const mbstate_t *ps);
size_t mbrtowc(wchar_t *pwc, const char *s, size_t n, mbstate_t *ps);
size_t wcrtomb(char *s, wchar_t wc, mbstate_t *ps);
size_t __wcrtomb_chk(char *s, wchar_t wc, mbstate_t *ps);

size_t mbrlen(const char *s, size_t n, mbstate_t *ps);
size_t mbsrtowcs(wchar_t *dest, const char **src, size_t len, mbstate_t *ps);
size_t __mbsrtowcs_chk(wchar_t *dest, const char **src, size_t len, mbstate_t *ps);

size_t wcsrtombs(char *dest, const wchar_t **src, size_t len, mbstate_t *ps);
size_t __wcsrtombs_chk(char *dest, const wchar_t **src, size_t len, mbstate_t *ps);

size_t mbsnrtowcs(wchar_t *dest, const char **src, size_t nms, size_t len, mbstate_t *ps);
size_t __mbsnrtowcs_chk(wchar_t *dest, const char **src, size_t nms, size_t len, mbstate_t *ps);

size_t wcsnrtombs(char *dest, const wchar_t **src, size_t nwc, size_t len, mbstate_t *ps);
size_t __wcsnrtombs_chk(char *dest, const wchar_t **src, size_t nwc, size_t len, mbstate_t *ps);

double wcstod(const wchar_t *nptr, wchar_t **endptr);
float wcstof(const wchar_t *nptr, wchar_t **endptr);
long double wcstold(const wchar_t *nptr, wchar_t **endptr);
long wcstol(const wchar_t *nptr, wchar_t **endptr, int base);
long long wcstoll(const wchar_t *nptr, wchar_t **endptr, int base);
unsigned long wcstoul(const wchar_t *nptr, wchar_t **endptr, int base);
unsigned long long wcstoull(const wchar_t *nptr, wchar_t **endptr, int base);
wchar_t *wcpcpy(wchar_t *dest, const wchar_t *src);
wchar_t *__wcpcpy_chk(wchar_t *dest, const wchar_t *src);

wchar_t *wcpncpy(wchar_t *dest, const wchar_t *src, size_t n);
wchar_t *__wcpncpy_chk(wchar_t *dest, const wchar_t *src, size_t n);

FILE *open_wmemstream(wchar_t **ptr, size_t *sizeloc);
int fwide(FILE *stream, int mode);

#ifdef SUPPORTED_VARIADIC

int wprintf(const wchar_t *format, ...);
int __wprintf_chk(const wchar_t *format, ...);

int fwprintf(FILE *stream, const wchar_t *format, ...);
int __fwprintf_chk(FILE *stream, const wchar_t *format, ...);

int swprintf(wchar_t *wcs, size_t maxlen, const wchar_t *format, ...);
int __swprintf_chk(wchar_t *wcs, size_t maxlen, const wchar_t *format, ...);

int fwscanf(FILE *stream, const wchar_t *format, ...);
int swscanf(const wchar_t *ws, const wchar_t *format, ...);
int wscanf(const wchar_t *format, ...);

#endif

int vwprintf(const wchar_t *format, va_list args);
int __vwprintf_chk(const wchar_t *format, va_list args);

int vfwprintf(FILE *stream, const wchar_t *format, va_list args);
int __vfwprintf_chk(FILE *stream, const wchar_t *format, va_list args);

int vswprintf(wchar_t *wcs, size_t maxlen, const wchar_t *format, va_list args);
int __vswprintf_chk(wchar_t *wcs, size_t maxlen, const wchar_t *format, va_list args);

int vfwscanf(FILE *stream, const wchar_t *format, va_list arg);
int vswscanf(const wchar_t *ws, const wchar_t *format, va_list arg);
int vwscanf(const wchar_t *format, va_list arg);

wint_t fgetwc(FILE *stream);
wint_t getwc(FILE *stream);
wint_t getwchar(void);
wint_t fputwc(wchar_t wc, FILE *stream);
wint_t putwc(wchar_t wc, FILE *stream);
wint_t putwchar(wchar_t wc);
wchar_t *fgetws(wchar_t *ws, int n, FILE *stream);
wchar_t *__fgetws_chk(wchar_t *ws, int n, FILE *stream);

int fputws(const wchar_t *ws, FILE *stream);
wint_t ungetwc(wint_t wc, FILE *stream);
size_t wcsftime(wchar_t *wcs, size_t maxsize, const wchar_t *format, const struct tm *timeptr);

wchar_t *wmempcpy(wchar_t *dest, const wchar_t *src, size_t n);
wchar_t *__wmempcpy_chk(wchar_t *dest, const wchar_t *src, size_t n);
wint_t getwc_unlocked(FILE *stream);
wint_t getwchar_unlocked(void);
wint_t fgetwc_unlocked(FILE *stream);
wint_t fputwc_unlocked(wchar_t wc, FILE *stream);
wint_t putwc_unlocked(wchar_t wc, FILE *stream);
wint_t putwchar_unlocked(wchar_t wc);
wchar_t *fgetws_unlocked(wchar_t *ws, int n, FILE *stream);
wchar_t *__fgetws_unlocked_chk(wchar_t *ws, int n, FILE *stream);

int fputws_unlocked(const wchar_t *ws, FILE *stream);



// syslog.h

void openlog(const char *ident, int option, int facility);

#ifdef SUPPORTED_VARIADIC

void syslog(int priority, const char *format, ...);
void __syslog_chk(int priority, const char *format, ...);

#endif

void closelog(void);
void vsyslog(int priority, const char *format, va_list ap);
void __vsyslog_chk(int priority, const char *format, va_list ap);

int setlogmask(int mask);


// poll.h

struct pollfd {
	int fd;
	short events;
	short revents;
};

typedef unsigned long int nfds_t;


int poll(struct pollfd *fds, nfds_t nfds, int timeout);
int __poll_chk(struct pollfd *fds, nfds_t nfds, int timeout);

int ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *tmo_p, const sigset_t *sigmask);
int __ppoll_chk(struct pollfd *fds, nfds_t nfds, const struct timespec *tmo_p, const sigset_t *sigmask);
