/**
 * s3seal - an S3 proxy that encrypts, and still tells the truth about it.
 *
 * The whole of what the program says to its host. Everything else is in the
 * files beside it: `frame.h` for the format and why it is shaped that way,
 * `proxy.h` for what is stored where, `sign.h` for the signature going out.
 *
 * Nothing in this file mentions nginx, a task, a descriptor or an event.
 */
#include "s3.h"

#include <meta_http.h>

#include <stdio.h>
#include <stdlib.h>

static long long number(const char *name, long long otherwise) {

  const char *found = getenv(name);

  return found != NULL && found[0] != 0 ? strtoll(found, NULL, 10) : otherwise;
}

int main(void) {

  long long part = number("S3SEAL_MAX_PART", 16 * 1024 * 1024);

  /**
   * `static`, and it has to be: `http.option` keeps the pointer it is given
   * rather than the text, and the configuration is written much later from
   * inside nginx's master.
   */
  static char size[32];

  snprintf(size, sizeof size, "%lldm", part / (1024 * 1024));

  http.option("client_max_body_size", size);
  http.option("client_body_buffer_size", size);

  http.env("S3SEAL_UPSTREAM");
  http.env("S3SEAL_UPSTREAM_ACCESS");
  http.env("S3SEAL_UPSTREAM_SECRET");
  http.env("S3SEAL_REGION");
  http.env("S3SEAL_SEED");
  http.env("S3SEAL_SCRATCH");
  http.env("S3SEAL_CREDENTIALS");
  http.env("S3SEAL_MAX_PART");
  http.env("S3SEAL_ETAG");
  http.env("S3SEAL_TIMING");

  /**
   * The configuration is read in the master, before it forks; the seed and
   * the upstream client are opened in the worker, after it has.
   */
  http.once(s3seal_configure);
  http.eachWorker(s3seal_start);
  http.eachWorkerStop(s3seal_stop);

  s3seal_routes();

  http.listen((int)number("S3SEAL_PORT", 9000));

  return 0;
}
