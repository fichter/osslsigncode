#ifndef RSK_COMPAT_H
#define RSK_COMPAT_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#ifdef __WIN32__
#include "win32.h"
#endif

#ifndef HAVE_GETOPT
#include "getopt.h"
#else
#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif
#endif

#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#ifdef TIME_WITH_SYS_TIME
#include <sys/time.h>
#include <time.h>
#else
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#else
#include <time.h>
#endif
#endif

#endif
