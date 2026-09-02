#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/time.h>
#endif

#define NONCE_LEN 16

typedef struct {
  uint32_t h[5];
  uint64_t len;
  unsigned char block[64];
  size_t block_len;
} Sha1;

static uint32_t rol32(uint32_t value, unsigned int bits) {
  return (value << bits) | (value >> (32 - bits));
}

static void sha1_process_block(Sha1 *ctx, const unsigned char block[64]) {
  uint32_t w[80];

  for (int i = 0; i < 16; i++) {
    w[i] = ((uint32_t)block[i * 4] << 24) |
           ((uint32_t)block[i * 4 + 1] << 16) |
           ((uint32_t)block[i * 4 + 2] << 8) |
           (uint32_t)block[i * 4 + 3];
  }

  for (int i = 16; i < 80; i++) {
    w[i] = rol32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
  }

  uint32_t a = ctx->h[0];
  uint32_t b = ctx->h[1];
  uint32_t c = ctx->h[2];
  uint32_t d = ctx->h[3];
  uint32_t e = ctx->h[4];

  for (int i = 0; i < 80; i++) {
    uint32_t f;
    uint32_t k;

    if (i < 20) {
      f = (b & c) | ((~b) & d);
      k = 0x5a827999;
    } else if (i < 40) {
      f = b ^ c ^ d;
      k = 0x6ed9eba1;
    } else if (i < 60) {
      f = (b & c) | (b & d) | (c & d);
      k = 0x8f1bbcdc;
    } else {
      f = b ^ c ^ d;
      k = 0xca62c1d6;
    }

    uint32_t temp = rol32(a, 5) + f + e + k + w[i];
    e = d;
    d = c;
    c = rol32(b, 30);
    b = a;
    a = temp;
  }

  ctx->h[0] += a;
  ctx->h[1] += b;
  ctx->h[2] += c;
  ctx->h[3] += d;
  ctx->h[4] += e;
}

static void sha1_init(Sha1 *ctx) {
  ctx->h[0] = 0x67452301;
  ctx->h[1] = 0xefcdab89;
  ctx->h[2] = 0x98badcfe;
  ctx->h[3] = 0x10325476;
  ctx->h[4] = 0xc3d2e1f0;
  ctx->len = 0;
  ctx->block_len = 0;
}

static void sha1_update(Sha1 *ctx, const unsigned char *data, size_t len) {
  ctx->len += (uint64_t)len * 8;

  while (len > 0) {
    size_t take = 64 - ctx->block_len;
    if (take > len) {
      take = len;
    }

    memcpy(ctx->block + ctx->block_len, data, take);
    ctx->block_len += take;
    data += take;
    len -= take;

    if (ctx->block_len == 64) {
      sha1_process_block(ctx, ctx->block);
      ctx->block_len = 0;
    }
  }
}

static void sha1_final(Sha1 *ctx, unsigned char digest[20]) {
  uint64_t bit_len = ctx->len;

  ctx->block[ctx->block_len++] = 0x80;
  if (ctx->block_len > 56) {
    while (ctx->block_len < 64) {
      ctx->block[ctx->block_len++] = 0;
    }
    sha1_process_block(ctx, ctx->block);
    ctx->block_len = 0;
  }

  while (ctx->block_len < 56) {
    ctx->block[ctx->block_len++] = 0;
  }

  for (int i = 7; i >= 0; i--) {
    ctx->block[ctx->block_len++] = (unsigned char)(bit_len >> (i * 8));
  }
  sha1_process_block(ctx, ctx->block);

  for (int i = 0; i < 5; i++) {
    digest[i * 4] = (unsigned char)(ctx->h[i] >> 24);
    digest[i * 4 + 1] = (unsigned char)(ctx->h[i] >> 16);
    digest[i * 4 + 2] = (unsigned char)(ctx->h[i] >> 8);
    digest[i * 4 + 3] = (unsigned char)ctx->h[i];
  }
}

static int is_hex_prefix(const char *value) {
  if (*value == '\0' || strlen(value) > 40) {
    return 0;
  }

  for (const char *p = value; *p; p++) {
    if (!((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f'))) {
      return 0;
    }
  }

  return 1;
}

static int hash_matches(const unsigned char digest[20], const char *target) {
  static const char hex[] = "0123456789abcdef";

  for (size_t i = 0; target[i]; i++) {
    unsigned char byte = digest[i / 2];
    char digit = (i % 2 == 0) ? hex[byte >> 4] : hex[byte & 0x0f];
    if (digit != target[i]) {
      return 0;
    }
  }

  return 1;
}

static void hash_to_hex(const unsigned char digest[20], char output[41]) {
  static const char hex[] = "0123456789abcdef";

  for (int i = 0; i < 20; i++) {
    output[i * 2] = hex[digest[i] >> 4];
    output[i * 2 + 1] = hex[digest[i] & 0x0f];
  }
  output[40] = '\0';
}

static unsigned char *read_stdin(size_t *size) {
  size_t capacity = 8192;
  size_t used = 0;
  unsigned char *buffer = malloc(capacity);
  if (!buffer) {
    return NULL;
  }

  for (;;) {
    if (used == capacity) {
      capacity *= 2;
      unsigned char *grown = realloc(buffer, capacity);
      if (!grown) {
        free(buffer);
        return NULL;
      }
      buffer = grown;
    }

    size_t count = fread(buffer + used, 1, capacity - used, stdin);
    used += count;

    if (count == 0) {
      if (ferror(stdin)) {
        free(buffer);
        return NULL;
      }
      break;
    }
  }

  *size = used;
  return buffer;
}

static unsigned char *find_nonce(unsigned char *content, size_t size) {
  const char marker[] = "nonce ";
  const size_t marker_len = sizeof(marker) - 1;

  if (size < marker_len + NONCE_LEN) {
    return NULL;
  }

  for (size_t i = 0; i + marker_len + NONCE_LEN <= size; i++) {
    int line_start = (i == 0 || content[i - 1] == '\n');
    if (line_start && memcmp(content + i, marker, marker_len) == 0) {
      return content + i + marker_len;
    }
  }

  return NULL;
}

static void format_nonce(uint64_t value, unsigned char nonce[NONCE_LEN]) {
  static const char hex[] = "0123456789abcdef";

  for (int i = NONCE_LEN - 1; i >= 0; i--) {
    nonce[i] = hex[value & 0x0f];
    value >>= 4;
  }
}

static long long now_ms(void) {
#ifdef _WIN32
  return (long long)GetTickCount64();
#else
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return (long long)tv.tv_sec * 1000 + tv.tv_usec / 1000;
#endif
}

int main(int argc, char **argv) {
  if (argc != 2 || !is_hex_prefix(argv[1])) {
    fprintf(stderr, "usage: hasher-helper <lowercase-hex-prefix>\n");
    return 2;
  }

  size_t content_size = 0;
  unsigned char *content = read_stdin(&content_size);
  if (!content) {
    fprintf(stderr, "hasher-helper: failed to read commit content\n");
    return 1;
  }

  unsigned char *nonce = find_nonce(content, content_size);
  if (!nonce) {
    fprintf(stderr, "hasher-helper: failed to find nonce header\n");
    free(content);
    return 1;
  }

  char object_header[64];
  int object_header_len = snprintf(object_header, sizeof(object_header), "commit %zu", content_size);
  if (object_header_len < 0 || (size_t)object_header_len + 1 > sizeof(object_header)) {
    fprintf(stderr, "hasher-helper: commit content is too large\n");
    free(content);
    return 1;
  }

  uint64_t attempts = 0;
  long long start_ms = now_ms();

  for (uint64_t counter = 0;; counter++) {
    unsigned char digest[20];
    Sha1 sha1;

    format_nonce(counter, nonce);

    sha1_init(&sha1);
    sha1_update(&sha1, (const unsigned char *)object_header, (size_t)object_header_len + 1);
    sha1_update(&sha1, content, content_size);
    sha1_final(&sha1, digest);

    attempts++;

    if (hash_matches(digest, argv[1])) {
      char hash[41];
      long long elapsed_ms = now_ms() - start_ms;
      hash_to_hex(digest, hash);
      printf("%.*s %s %llu %lld\n", NONCE_LEN, nonce, hash,
             (unsigned long long)attempts, elapsed_ms);
      free(content);
      return 0;
    }
  }
}
