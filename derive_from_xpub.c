#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <openssl/ssl.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <libbase58.h>


#ifndef NDEBUG
#include <assert.h>
#define ASSERT(exp) assert(exp)
#else
#define ASSERT(exp)
#endif

#define CK(x) ASSERT (x != NULL)
#define CKRC(call) \
    do { \
      if (1 != (rc = call)) { \
        ERR_print_errors_fp (stderr); \
        ASSERT (rc == 1); \
      }} while (0)

#ifdef __GNUC__
#define INT32_SET_BE(left, right) \
   left = __builtin_bswap32 (right);
#else
#define INT32_SET_BE(left, right) \
  (((unsigned char *) (&left))[0] = (unsigned char) ((right) >> 24), \
   ((unsigned char *) (&left))[1] = (unsigned char) ((right) >> 16), \
   ((unsigned char *) (&left))[2] = (unsigned char) ((right) >> 8), \
   ((unsigned char *) (&left))[3] = (unsigned char) ((right) ))
#endif

/* secp256k1 constants */
static const uint8_t n_bin[] = {
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
  0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41 };

static const uint8_t g_x_bin[] = {
  /* 0x02 - compressed */
  0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95,
  0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9,
  0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98 };

static BIGNUM *n, *g_x;
static EC_POINT *g_point;
static EC_GROUP *secp256k1_group;

static void 
init_secp256k1 ()
{
  int rc;
  secp256k1_group = EC_GROUP_new_by_curve_name (NID_secp256k1);
  n = BN_bin2bn(n_bin, sizeof (n_bin), 0);
  g_x = BN_bin2bn(g_x_bin, sizeof (g_x_bin), 0);
  g_point = EC_POINT_bn2point (secp256k1_group, g_x, 0, 0);
  CKRC( EC_POINT_make_affine (secp256k1_group, g_point, NULL) );
}

static void
done_secp256k1 ()
{
  BN_free(n);
  BN_free(g_x);
  EC_POINT_free (g_point);
  EC_GROUP_free (secp256k1_group);
}


#define CHAIN_OFFSET    (4 + 1 + 4 + 4)
#define CHAIN_SZ        32
#define PUB_SZ          33
#define PUB_OFFSET      (CHAIN_OFFSET + CHAIN_SZ)

static char * xpub_str_test = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs";

static const char *HEX_DIGITS = "0123456789ABCDEF";

static char * buf_bin2hex (unsigned char * buf, size_t buf_len, char * ret)
{
  char *p = ret;
  unsigned char *pbuf = buf;
  int i;
  for (i = buf_len; i > 0; i--) 
    {
      int v = (int)*(pbuf++);
      *(p++) = HEX_DIGITS[v >> 4];
      *(p++) = HEX_DIGITS[v & 0x0F];
    }
  *p = '\0';
  return ret;
}


static int
bip32_parse_dir (uint32_t *indexes, size_t indexes_len, char * dir_str)
{
  char *tok, *tok_s = NULL, * string = strdup (dir_str);
  uint32_t lvl = 0, i;
  tok = strtok_r (string, "/", &tok_s);
  while (tok)
    {
      if (tok[0] != 'm')
        {
          i = atoi (tok); 
          indexes[lvl] = i;
          lvl ++;
          ASSERT (lvl < indexes_len);
        }
      tok = strtok_r (NULL, "/", &tok_s);
    }
  return lvl;
}

int 
main (int argc, char ** argv)
{
  HMAC_CTX *hmac_ctx;
  EC_POINT *xpub_point;
  EC_POINT *Ki_point;
  BIGNUM *m, *bn;
  unsigned char decoded[512], *xpub_decoded;;
  size_t xpub_buf_len, xpub_len;
  unsigned char hmac_value[EVP_MAX_MD_SIZE];
  uint32_t hmac_len, Ki_len, indexes[256];
  uint32_t index;
  unsigned char *pub, *chain, *Ki_pub = NULL, *Ki_chain;
  int rc, lvl = 0, depth;
  char *xpub_str, *path = "m/0/0";

  if (argc < 2) 
    {
      printf ("Usage: derive_from_xpub [xpub] [path]\n");
      return -1;
    }
  if (!strcmp(argv[1], "test"))
    xpub_str = xpub_str_test;
  else
    xpub_str = argv[1];
  if (argc > 2)
    path = argv[2];

  init_secp256k1 ();
  depth = bip32_parse_dir (indexes, sizeof (indexes), path);

  xpub_buf_len = xpub_len = sizeof (decoded);
  rc = b58tobin (decoded, &xpub_len, xpub_str, 0);
  ASSERT (rc == true);
  ASSERT (xpub_len <= xpub_buf_len);
  xpub_decoded = &decoded[xpub_buf_len - xpub_len];

  pub = &xpub_decoded[PUB_OFFSET];
  chain = &xpub_decoded[CHAIN_OFFSET];
  for (lvl = 0; lvl < depth; lvl ++)
    {
      INT32_SET_BE(index, indexes[lvl]);
      bn = BN_bin2bn (pub, PUB_SZ, 0);
      CK(bn);
      xpub_point = EC_POINT_bn2point (secp256k1_group, bn, 0, 0);
      CK(xpub_point);

      hmac_ctx = HMAC_CTX_new();
      CKRC( HMAC_Init_ex (hmac_ctx, (void*) chain, CHAIN_SZ, EVP_sha512(), NULL));
      CKRC( HMAC_Update (hmac_ctx, (void*) pub, PUB_SZ) );
      CKRC( HMAC_Update (hmac_ctx, (void*) &index, sizeof (uint32_t)) );
      CKRC( HMAC_Final (hmac_ctx, hmac_value, &hmac_len) );
      HMAC_CTX_free (hmac_ctx);

      Ki_chain = &hmac_value[hmac_len/2];
      m = BN_bin2bn(&hmac_value[0], hmac_len/2, 0);
      CK(m);
      Ki_point = EC_POINT_new (secp256k1_group);
      CK(Ki_point);
      CKRC ( EC_POINT_mul (secp256k1_group, Ki_point, n, g_point, m, 0) );
      CKRC( EC_POINT_make_affine (secp256k1_group, xpub_point, NULL) );
      CKRC( EC_POINT_add (secp256k1_group, Ki_point, Ki_point, xpub_point, NULL) );
      if (Ki_pub)
        OPENSSL_free (Ki_pub);
      Ki_len = EC_POINT_point2buf(secp256k1_group, Ki_point, POINT_CONVERSION_COMPRESSED, &Ki_pub, 0);
      ASSERT (Ki_len == PUB_SZ);
      pub = Ki_pub;
      chain = Ki_chain;
      if (lvl == (depth - 1))
        {
          char chain_buf[CHAIN_SZ+1];
          char * hex = EC_POINT_point2hex (secp256k1_group, Ki_point, POINT_CONVERSION_COMPRESSED, 0);
          fprintf (stderr, "Ci = %s\n", buf_bin2hex (Ki_chain, CHAIN_SZ, &chain_buf[0]));
          fprintf (stdout, "Ki = %s\n", hex);
          if (xpub_str == xpub_str_test)
            {
              if (!strcasecmp (hex, "0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c"))
                fprintf (stdout, "PASSED");
              else
                fprintf (stdout, "***FAILED");
              fprintf (stdout, ": BIP-84 Account 0, first receiving address = m/84'/0'/0'/0/0\n");
            }
          OPENSSL_free (hex);
        }
      EC_POINT_free (xpub_point);
      EC_POINT_free (Ki_point);
      BN_free (m);
      BN_free (bn);
    }
  if (Ki_pub)
    OPENSSL_free (Ki_pub);
  done_secp256k1();
  return 0;
}
