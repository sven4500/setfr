#ifndef GETOPT_H
#define GETOPT_H

#if defined(__cplusplus)
extern "C"
{
#endif

extern char *optarg;
int getopt(int nargc, char * const nargv[], const char *ostr) ;

#if defined(__cplusplus )
}
#endif

#endif
