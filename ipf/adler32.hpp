#pragma once

#ifndef OF /* function prototypes */
#  ifdef STDC
#    define OF(args)  args
#  else
#    define OF(args)  ()
#  endif
#endif

unsigned long adler32(unsigned long adler, const unsigned char *buf, unsigned int len);