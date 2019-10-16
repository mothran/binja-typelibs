// dlfcn.h
typedef long int Lmid_t;

void *dlopen(const char *filename, int flags);
int dlclose(void *handle);
void *dlmopen (Lmid_t lmid, const char *filename, int flags);
void *dlsym(void *handle, const char *symbol);
void *dlvsym(void *handle, char *symbol, char *version);
char *dlerror(void);
