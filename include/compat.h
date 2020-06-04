#include <sys/types.h>

void explicit_bzero(void *, size_t);
size_t portable_strlcat(char *dst, const char *src, size_t dsize);
size_t portable_strlcpy(char *dst, const char *src, size_t dsize);
long long strtonum(const char *, long long, long long, const char **);
int timingsafe_bcmp(const void *, const void *, size_t);
