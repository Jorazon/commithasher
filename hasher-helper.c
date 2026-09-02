#ifndef _WIN32
#define _POSIX_C_SOURCE 199309L
#endif

#include <stdint.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#endif

#define NONCE_LEN 16
#define PROGRESS_INTERVAL_ATTEMPTS 65536
#define MAX_THREADS 256

#ifdef _WIN32
typedef HANDLE Thread;
#define THREAD_RETURN DWORD WINAPI
#else
typedef pthread_t Thread;
#define THREAD_RETURN void *
#endif

typedef struct {
  uint32_t h[5];
  uint64_t len;
  unsigned char block[64];
  size_t block_len;
} Sha1;

typedef struct {
  const char *target;
  const unsigned char *base_content;
  size_t content_size;
  size_t nonce_offset;
  const unsigned char *object_header;
  size_t object_header_len;
  int thread_index;
  int thread_count;
  atomic_int *found;
  atomic_uint_fast64_t *attempts;
  unsigned char *result_nonce;
  char *result_hash;
} Worker;

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

static void print_progress(uint64_t attempts, long long elapsed_ms) {
  long long rate_ms = elapsed_ms;
  if (rate_ms < 1) {
    rate_ms = 1;
  }

  fprintf(stderr, "\rTested hashes: %llu | Duration: %lldm%llds | Hashrate: %llu H/s",
          (unsigned long long)attempts,
          elapsed_ms / (1000 * 60),
          (elapsed_ms / 1000) % 60,
          (unsigned long long)(attempts * 1000 / rate_ms));
  fflush(stderr);
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

static int cpu_count(void) {
#ifdef _WIN32
  DWORD count = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
  return count > 0 ? (int)count : 1;
#else
  long count = sysconf(_SC_NPROCESSORS_ONLN);
  return count > 0 ? (int)count : 1;
#endif
}

static int thread_count(void) {
  const char *override = getenv("HASHER_THREADS");
  if (override && *override) {
    char *end = NULL;
    long value = strtol(override, &end, 10);
    if (end && *end == '\0' && value > 0 && value <= MAX_THREADS) {
      return (int)value;
    }
  }

  int count = cpu_count();
  if (count < 1) {
    return 1;
  }
  if (count > MAX_THREADS) {
    return MAX_THREADS;
  }
  return count;
}

static uint64_t total_attempts(const atomic_uint_fast64_t *attempts, int count) {
  uint64_t total = 0;
  for (int i = 0; i < count; i++) {
    total += atomic_load_explicit(&attempts[i], memory_order_relaxed);
  }
  return total;
}

static THREAD_RETURN worker_main(void *raw_worker) {
  Worker *worker = (Worker *)raw_worker;
  unsigned char *content = malloc(worker->content_size);
  if (!content) {
    int expected = 0;
    if (atomic_compare_exchange_strong_explicit(worker->found, &expected, 1,
                                                memory_order_relaxed,
                                                memory_order_relaxed)) {
      worker->result_hash[0] = '\0';
    }
#ifdef _WIN32
    return 1;
#else
    return NULL;
#endif
  }

  memcpy(content, worker->base_content, worker->content_size);
  unsigned char *nonce = content + worker->nonce_offset;
  uint64_t local_attempts = 0;

  for (uint64_t counter = (uint64_t)worker->thread_index;
       !atomic_load_explicit(worker->found, memory_order_relaxed);
       counter += (uint64_t)worker->thread_count) {
    unsigned char digest[20];
    Sha1 sha1;

    format_nonce(counter, nonce);

    sha1_init(&sha1);
    sha1_update(&sha1, worker->object_header, worker->object_header_len);
    sha1_update(&sha1, content, worker->content_size);
    sha1_final(&sha1, digest);

    local_attempts++;

    if ((local_attempts & (PROGRESS_INTERVAL_ATTEMPTS - 1)) == 0) {
      atomic_store_explicit(&worker->attempts[worker->thread_index], local_attempts,
                            memory_order_relaxed);
    }

    if (hash_matches(digest, worker->target)) {
      int expected = 0;
      if (atomic_compare_exchange_strong_explicit(worker->found, &expected, 1,
                                                  memory_order_relaxed,
                                                  memory_order_relaxed)) {
        hash_to_hex(digest, worker->result_hash);
        memcpy(worker->result_nonce, nonce, NONCE_LEN);
        atomic_store_explicit(&worker->attempts[worker->thread_index], local_attempts,
                              memory_order_relaxed);
      }
      break;
    }
  }

  atomic_store_explicit(&worker->attempts[worker->thread_index], local_attempts,
                        memory_order_relaxed);
  free(content);

#ifdef _WIN32
  return 0;
#else
  return NULL;
#endif
}

static int start_thread(Thread *thread, Worker *worker) {
#ifdef _WIN32
  *thread = CreateThread(NULL, 0, worker_main, worker, 0, NULL);
  return *thread != NULL;
#else
  return pthread_create(thread, NULL, worker_main, worker) == 0;
#endif
}

static void join_thread(Thread thread) {
#ifdef _WIN32
  WaitForSingleObject(thread, INFINITE);
  CloseHandle(thread);
#else
  pthread_join(thread, NULL);
#endif
}

static void sleep_100ms(void) {
#ifdef _WIN32
  Sleep(100);
#else
  struct timespec ts;
  ts.tv_sec = 0;
  ts.tv_nsec = 100000000;
  nanosleep(&ts, NULL);
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

  int threads_count = thread_count();
  Thread *threads = calloc((size_t)threads_count, sizeof(Thread));
  Worker *workers = calloc((size_t)threads_count, sizeof(Worker));
  atomic_uint_fast64_t *attempts = calloc((size_t)threads_count, sizeof(atomic_uint_fast64_t));
  unsigned char result_nonce[NONCE_LEN];
  char result_hash[41] = {0};
  atomic_int found;

  if (!threads || !workers || !attempts) {
    fprintf(stderr, "hasher-helper: failed to allocate worker state\n");
    free(threads);
    free(workers);
    free(attempts);
    free(content);
    return 1;
  }

  long long start_ms = now_ms();
  long long last_report_ms = start_ms;
  int printed_progress = 0;
  atomic_init(&found, 0);

  for (int i = 0; i < threads_count; i++) {
    atomic_init(&attempts[i], 0);
    workers[i].target = argv[1];
    workers[i].base_content = content;
    workers[i].content_size = content_size;
    workers[i].nonce_offset = (size_t)(nonce - content);
    workers[i].object_header = (const unsigned char *)object_header;
    workers[i].object_header_len = (size_t)object_header_len + 1;
    workers[i].thread_index = i;
    workers[i].thread_count = threads_count;
    workers[i].found = &found;
    workers[i].attempts = attempts;
    workers[i].result_nonce = result_nonce;
    workers[i].result_hash = result_hash;

    if (!start_thread(&threads[i], &workers[i])) {
      fprintf(stderr, "hasher-helper: failed to start worker thread\n");
      atomic_store_explicit(&found, 1, memory_order_relaxed);
      for (int j = 0; j < i; j++) {
        join_thread(threads[j]);
      }
      free(threads);
      free(workers);
      free(attempts);
      free(content);
      return 1;
    }
  }

  while (!atomic_load_explicit(&found, memory_order_relaxed)) {
    sleep_100ms();

    long long current_ms = now_ms();
    if (current_ms - last_report_ms >= 1000) {
      print_progress(total_attempts(attempts, threads_count), current_ms - start_ms);
      last_report_ms = current_ms;
      printed_progress = 1;
    }
  }

  for (int i = 0; i < threads_count; i++) {
    join_thread(threads[i]);
  }

  long long elapsed_ms = now_ms() - start_ms;
  uint64_t final_attempts = total_attempts(attempts, threads_count);

  if (printed_progress) {
    fputc('\n', stderr);
  }

  if (result_hash[0] == '\0') {
    fprintf(stderr, "hasher-helper: worker failed\n");
    free(threads);
    free(workers);
    free(attempts);
    free(content);
    return 1;
  }

  printf("%.*s %s %llu %lld\n", NONCE_LEN, result_nonce, result_hash,
         (unsigned long long)final_attempts, elapsed_ms);

  free(threads);
  free(workers);
  free(attempts);
  free(content);
  return 0;
}
