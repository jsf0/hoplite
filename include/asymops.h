#include <stdio.h>

#include "hdr.h"

void asymcrypt(unsigned char *, unsigned char *,
    struct hdr *, FILE *, FILE *);
void asymdecrypt(unsigned char *, unsigned char *, unsigned long long,
    unsigned char *, FILE *, FILE *);
