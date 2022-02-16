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
#ifdef BIP84
#include "segwit_addr.h"
#endif


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
#define KEY_SZ          33
#define KEY_OFFSET      (CHAIN_OFFSET + CHAIN_SZ)
#define ZKEY_SZ         CHAIN_OFFSET + CHAIN_SZ + KEY_SZ

static char * xpub_str_test = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs";
static char * xpriv_str_test = "zprvAdG4iTXWBoARxkkzNpNh8r6Qag3irQB8PzEMkAFeTRXxHpbF9z4QgEvBRmfvqWvGp42t42nvgGpNgYSJA9iefm1yYNZKEm7z6qUWCroSQnE";

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

#if OPENSSL_VERSION_NUMBER < 0x10100000L
size_t EC_POINT_point2buf(const EC_GROUP *group,
                         const EC_POINT *point,
                         point_conversion_form_t form,
                         unsigned char **pbuf,
                         BN_CTX *ctx)
{
  unsigned char *buf;
  size_t buf_len = 0;

  buf_len = EC_POINT_point2oct(group, point, form, NULL, 0, ctx);
  if (buf_len == 0)
    return 0;

  if ((buf = OPENSSL_malloc(buf_len)) == NULL)
    return 0;

  if (!EC_POINT_point2oct(group, point, form, buf, buf_len, ctx)) {
    OPENSSL_free(buf);
    return 0;
  }
  *pbuf = buf;
  return buf_len;
}

HMAC_CTX *
HMAC_CTX_new (void)
{
  HMAC_CTX *ctx = OPENSSL_malloc (sizeof (HMAC_CTX));
  if (ctx != NULL)
    HMAC_CTX_init (ctx);
  return ctx;
}


void
HMAC_CTX_free (HMAC_CTX * ctx)
{
  if (ctx != NULL)
    {
      HMAC_CTX_cleanup (ctx);
      OPENSSL_free (ctx);
    }
}

EVP_MD_CTX *EVP_MD_CTX_new(void)
{
  EVP_MD_CTX *ctx = (EVP_MD_CTX *) OPENSSL_malloc (sizeof (EVP_MD_CTX));
  if (NULL != ctx)
    memset (ctx, 0, sizeof (EVP_MD_CTX));
  return ctx;
}

void EVP_MD_CTX_free(EVP_MD_CTX *ctx)
{
  EVP_MD_CTX_cleanup (ctx);
  OPENSSL_free(ctx);
}
#endif

static char *
compress_key (unsigned char *key, unsigned int * buf_len)
{
  unsigned char key_value[KEY_SZ + 5];
  unsigned char sha0[EVP_MAX_MD_SIZE];
  unsigned char sha[EVP_MAX_MD_SIZE];
  unsigned int len, rc;
  size_t b58_len;
  char * s;
  EVP_MD_CTX * ctx;

  memcpy (key_value, key, KEY_SZ);
  key_value[0] = '\x80';
  key_value[KEY_SZ] = '\x01';

  ctx = EVP_MD_CTX_new ();
  CKRC(EVP_DigestInit_ex (ctx, EVP_sha256(), NULL));
  CKRC(EVP_DigestUpdate (ctx, key_value, KEY_SZ + 1));
  CKRC(EVP_DigestFinal_ex (ctx, sha0, &len));
  EVP_MD_CTX_free (ctx);
  ctx = EVP_MD_CTX_new ();
  CKRC(EVP_DigestInit_ex (ctx, EVP_sha256(), NULL));
  CKRC(EVP_DigestUpdate (ctx, sha0, len));
  CKRC(EVP_DigestFinal_ex (ctx, sha, &len));
  EVP_MD_CTX_free (ctx);
  memcpy(key_value+KEY_SZ+1, sha, 4);
  b58_len = sizeof (key_value) * 2;
  s = malloc (b58_len);
  rc = b58enc(s, &b58_len, &key_value[0], sizeof (key_value));
  s[b58_len] = '\0';
  *buf_len = b58_len;
  return s;
}

static unsigned char *
hash160 (unsigned char *pub, int pub_len, unsigned int * script_len)
{
  unsigned char hash_value[EVP_MAX_MD_SIZE];
  unsigned char sha_value[EVP_MAX_MD_SIZE];
  unsigned char * hash;
  EVP_MD_CTX * ctx;
  unsigned int sha_len, hash_len, rc;

  ctx = EVP_MD_CTX_new ();
  CKRC(EVP_DigestInit_ex (ctx, EVP_sha256(), NULL));
  CKRC(EVP_DigestUpdate (ctx, pub, pub_len));
  CKRC(EVP_DigestFinal_ex (ctx, sha_value, &sha_len));
  EVP_MD_CTX_free (ctx);

  ctx = EVP_MD_CTX_new ();
  CKRC(EVP_DigestInit_ex (ctx, EVP_ripemd160(), NULL));
  CKRC(EVP_DigestUpdate (ctx, sha_value, sha_len));
  CKRC(EVP_DigestFinal_ex (ctx, hash_value, &hash_len));
  EVP_MD_CTX_free (ctx);

  hash = malloc (hash_len);
  memcpy (hash, hash_value, hash_len);
  *script_len = hash_len;
  return hash;
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
          if (tok[strlen(tok)-1] == 'h')
            i += 0x80000000;
          indexes[lvl] = i;
          lvl ++;
          ASSERT (lvl < indexes_len);
        }
      tok = strtok_r (NULL, "/", &tok_s);
    }
  free (string);
  return lvl;
}

int
main (int argc, char ** argv)
{
  HMAC_CTX *hmac_ctx;
  EC_POINT *xpub_point;
  EC_POINT *Ki_point = NULL, *Q_point = NULL;
  BIGNUM *offset, *key_int, *priv_int;
  unsigned char decoded[512], *xpub_decoded;;
  size_t xpub_buf_len, xpub_len;
  unsigned char hmac_value[EVP_MAX_MD_SIZE];
  uint32_t hmac_len, Ki_len, K_len, indexes[256];
  uint32_t index;
  unsigned char *key_bin = NULL, *chain, *Ki_pub = NULL, *K_priv = NULL, *Ki_chain;
  int rc, lvl = 0, depth;
  char *xkey_str, *path = "m/0/0";
  int xpriv = 0;

  if (argc < 2)
    {
      printf ("Usage: derive_from_xpub [xpub/xprv] [path m/0/0]\n");
      return -1;
    }
  if (!strcmp(argv[1], "xpub"))
    {
      xkey_str = xpub_str_test;
    }
  else if (!strcmp(argv[1], "xprv"))
    {
      xkey_str = xpriv_str_test;
      xpriv = 1;
    }
  else
    {
      xkey_str = argv[1];
      if (strlen (xkey_str) > 4 && strncmp (xkey_str+1, "pub", 3))
        xpriv = 1;
    }
  if (argc > 2)
    path = argv[2];

  /* TODO: check input string length, prefixe etc.*/

  init_secp256k1 ();
  depth = bip32_parse_dir (indexes, sizeof (indexes), path);

  xpub_buf_len = xpub_len = sizeof (decoded);
  rc = b58tobin (decoded, &xpub_len, xkey_str, 0);
  ASSERT (rc == true);
  ASSERT (xpub_len <= xpub_buf_len);
  ASSERT (xpub_len >= ZKEY_SZ);
  xpub_decoded = &decoded[xpub_buf_len - xpub_len];

  key_bin = &xpub_decoded[KEY_OFFSET];
  chain = &xpub_decoded[CHAIN_OFFSET];
  for (lvl = 0; lvl < depth; lvl ++)
    {
      INT32_SET_BE(index, indexes[lvl]);
      // int_key
      key_int = BN_bin2bn (key_bin, KEY_SZ, 0);
      CK(key_int);
      if (xpriv && indexes[lvl] > 0x7fffffff)
        K_priv = OPENSSL_malloc(KEY_SZ);
      else if (xpriv)
        {
          Q_point = EC_POINT_new (secp256k1_group);
          CK(Q_point);
          CKRC( EC_POINT_mul (secp256k1_group, Q_point, n, g_point, key_int, 0) );
          CKRC( EC_POINT_make_affine (secp256k1_group, Q_point, NULL) );
          if (K_priv)
            OPENSSL_free (K_priv);
          K_len = EC_POINT_point2buf(secp256k1_group, Q_point, POINT_CONVERSION_COMPRESSED, &K_priv, 0);
          EC_POINT_free (Q_point);
          key_bin = K_priv;
        }
      else
        {
          xpub_point = EC_POINT_bn2point (secp256k1_group, key_int, 0, 0);
          CK(xpub_point);
        }

      hmac_ctx = HMAC_CTX_new();
      CKRC( HMAC_Init_ex (hmac_ctx, (void*) chain, CHAIN_SZ, EVP_sha512(), NULL));
      CKRC( HMAC_Update (hmac_ctx, (void*) key_bin, KEY_SZ) );
      CKRC( HMAC_Update (hmac_ctx, (void*) &index, sizeof (uint32_t)) );
      CKRC( HMAC_Final (hmac_ctx, hmac_value, &hmac_len) );
      HMAC_CTX_free (hmac_ctx);

      Ki_chain = &hmac_value[hmac_len/2];
      offset = BN_bin2bn(&hmac_value[0], hmac_len/2, 0);
      CK(offset);
      if (xpriv)
        {
          BN_CTX * ctx = BN_CTX_new();
          priv_int = BN_new ();
          CKRC( BN_add (key_int, key_int, offset) );
          CKRC( BN_mod (priv_int, key_int, n, ctx) );
          K_len = BN_bn2bin (priv_int, K_priv + 1);
          BN_free (priv_int);
          BN_CTX_free (ctx);
          K_priv[0] = '\x0';
          key_bin = K_priv;
        }
      else
        {
          Ki_point = EC_POINT_new (secp256k1_group);
          CK(Ki_point);
          CKRC ( EC_POINT_mul (secp256k1_group, Ki_point, n, g_point, offset, 0) );
          CKRC( EC_POINT_make_affine (secp256k1_group, xpub_point, NULL) );
          CKRC( EC_POINT_add (secp256k1_group, Ki_point, Ki_point, xpub_point, NULL) );
          if (Ki_pub)
            OPENSSL_free (Ki_pub);
          Ki_len = EC_POINT_point2buf(secp256k1_group, Ki_point, POINT_CONVERSION_COMPRESSED, &Ki_pub, 0);
          ASSERT (Ki_len == KEY_SZ);
          key_bin = Ki_pub;
        }
      chain = Ki_chain;
      if (lvl == (depth - 1))
        {
          char chain_buf[CHAIN_SZ+1];
          char * hex = NULL, *khex;
          if (xpriv)
            khex = buf_bin2hex (K_priv, KEY_SZ, &chain_buf[0]);
          else
            hex = EC_POINT_point2hex (secp256k1_group, Ki_point, POINT_CONVERSION_COMPRESSED, 0);
          fprintf (stdout, "Ki = %s\n", xpriv ? khex : hex);
          fprintf (stderr, "Ci = %s\n", buf_bin2hex (Ki_chain, CHAIN_SZ, &chain_buf[0]));
          if (xkey_str == xpub_str_test)
            {
              if (!strcasecmp (hex, "0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c"))
                fprintf (stdout, "PASSED");
              else
                fprintf (stdout, "***FAILED");
              fprintf (stdout, ": BIP-84 Account 0, first receiving address = m/84'/0'/0'/0/0\n");
            }
#ifdef BIP84
          if (!xpriv)
            {
              char addr[93];
              unsigned int script_len;
              unsigned char * script;
              script = hash160 (key_bin, KEY_SZ, &script_len);
              segwit_addr_encode (addr, "bc", 0, script, script_len);
              OPENSSL_free (script);
              fprintf (stdout, "Address: %s\n", addr);
            }
          else
            {
              unsigned int wif_key_len;
              char * wif_key = compress_key (key_bin, &wif_key_len);
              fprintf (stdout, "Key: %s\n", wif_key);
              if (xkey_str == xpriv_str_test)
                {
                  if (!strcasecmp (wif_key, "KyZpNDKnfs94vbrwhJneDi77V6jF64PWPF8x5cdJb8ifgg2DUc9d"))
                    fprintf (stdout, "PASSED");
                  else
                    fprintf (stdout, "***FAILED");
                  fprintf (stdout, ": BIP-84 WIF key 0, for first receiving address = m/84'/0'/0'/0/0\n");
                }
              free (wif_key);
            }
#endif
          OPENSSL_free (hex);
        }
      EC_POINT_free (xpub_point);
      EC_POINT_free (Ki_point);
      BN_free (offset);
      BN_free (key_int);
    }
  if (key_bin)
    OPENSSL_free (key_bin);
  done_secp256k1();
  return 0;
}
