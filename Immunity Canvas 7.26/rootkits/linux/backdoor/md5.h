 
/* typedef a 32 bit type */
 
typedef unsigned long int UINT4;

/* Data structure for MD5 (Message Digest) computation */
 
typedef struct {
 
  UINT4 i[2];                   /* number of _bits_ handled mod 2^64 */
 
  UINT4 buf[4];                                    /* scratch buffer */
 
  unsigned char in[64];                              /* input buffer */
 
  unsigned char digest[16];     /* actual digest after MD5Final call */
 
} MD5_CTX;
 
void MD5Init ();
void MD5Update ();
void MD5Final ();
char * MDBuf(const char *inString, unsigned int len);
char * MDString (const char *inString);
void MDPrint (MD5_CTX *mdContext);
char * MDStringH (const char *inString);
