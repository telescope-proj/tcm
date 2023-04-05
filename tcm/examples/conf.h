#define ssap struct sockaddr *

static inline float conv_float(float val, char ** unit)
{
    static char * vals[] = {"-", "K", "M", "G", "T", "P", "E", "-"};
    int i = 0;
    while (val > 1000 && i < 7)
    {
        val /= 1000;
        i++;
    }
    *unit = vals[i];
    return val;
}

/* --- Configuration below --- */

#define MSIZE       1
#define MCOUNT      1000
#define TRANSPORT   "verbs;ofi_rxm"