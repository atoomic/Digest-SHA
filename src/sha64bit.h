/* 
 * The following macros supply placeholder values that enable the
 * `sha.c' module to successfully compile when 64-bit integer types 
 * aren't present.
 *
 * They are appropriately redefined in `sha64bit.c` if the compiler
 * provides a 64-bit type (i.e. when SHA_384_512 is defined).
 */

#define sha_384_512		0
#define load64(pval, p)		return(0)
#define digcpy64(s)		return
#define sha512			NULL
#define H0384			H01
#define H0512			H01
