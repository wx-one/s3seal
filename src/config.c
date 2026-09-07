#include "config.h"
#include "util.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

/** An environment variable, or the given default, copied either way. */
static @owns char *setting(const char *name, const char *otherwise) {

  const char *found = getenv(name);

  return s3seal_dup(found != NULL && found[0] != 0 ? found : otherwise);
}

static unsigned long long number(const char *name,
                                 unsigned long long otherwise) {

  const char *found = getenv(name);

  if (found == NULL || found[0] == 0)
    return otherwise;

  return strtoull(found, NULL, 10);
}

/**
 * `accessKey secret` per line, `#` for a comment.
 *
 * The file is refused if anybody but its owner can read it, on the same
 * argument as the master key: a secret with loose permissions is one that has
 * already been read, and finding that out later is worse than not starting.
 */
static int readCredentials(s3seal_config_t *self) {

  struct stat about;
  FILE *from = fopen(self->credentials, "r");
  char line[512];

  if (from == NULL) {
    fprintf(stderr, "s3seal: no credentials at %s: %s\n", self->credentials,
            strerror(errno));
    return -1;
  }

  defer fclose(from);

  if (fstat(fileno(from), &about) != 0)
    return -1;

  if ((about.st_mode & 0077) != 0) {
    fprintf(stderr, "s3seal: %s is readable by others - chmod 600 it\n",
            self->credentials);
    return -1;
  }

  while (fgets(line, sizeof line, from) != NULL) {

    s3seal_credential_t one;
    char access[128];
    char secret[256];

    if (line[0] in {'#', '\n', 0})
      continue;

    if (sscanf(line, "%127s %255s", access, secret) != 2)
      continue;

    one.access = s3seal_dup(access);
    one.secret = s3seal_dup(secret);

    if (one.access == NULL || one.secret == NULL || !self->keys.push(one)) {
      free(one.access);
      free(one.secret);
      return -1;
    }
  }

  if (self->keys.count == 0) {
    fprintf(stderr, "s3seal: %s names no credentials\n", self->credentials);
    return -1;
  }

  return 0;
}

int s3seal_config_t.read(s3seal_config_t *self) {

  memset(self, 0, sizeof *self);

  self->upstream = setting("S3SEAL_UPSTREAM", "");
  self->upstreamAccess = setting("S3SEAL_UPSTREAM_ACCESS", "");
  self->upstreamSecret = setting("S3SEAL_UPSTREAM_SECRET", "");

  self->region = setting("S3SEAL_REGION", "us-east-1");
  self->seed = setting("S3SEAL_SEED", "/var/lib/s3seal/seed");
  self->scratch = setting("S3SEAL_SCRATCH", ".s3seal/uploads");
  self->credentials = setting("S3SEAL_CREDENTIALS",
                              "/var/lib/s3seal/credentials");

  {
    char *how = setting("S3SEAL_ETAG", "md5");

    self->opaqueEtag = s3seal_same(how, "opaque");

    if (!self->opaqueEtag && !s3seal_same(how, "md5")) {
      fprintf(stderr, "s3seal: S3SEAL_ETAG is 'md5' or 'opaque', not '%s'\n",
              how);
      free(how);
      return -1;
    }

    free(how);
  }

  self->port = (int)number("S3SEAL_PORT", 9000);
  self->maxPart = number("S3SEAL_MAX_PART", 16 * 1024 * 1024);

  if (self->upstream == NULL || self->upstream[0] == 0) {
    fprintf(stderr, "s3seal: S3SEAL_UPSTREAM names the S3 to sit in front of\n");
    return -1;
  }

  /* a trailing slash would give every signed path a double one */
  {
    size_t at = strlen(self->upstream);

    while (at > 0 && self->upstream[at - 1] == '/')
      self->upstream[--at] = 0;
  }

  if (self->upstreamAccess[0] == 0 || self->upstreamSecret[0] == 0) {
    fprintf(stderr, "s3seal: no upstream credentials - set "
                    "S3SEAL_UPSTREAM_ACCESS and S3SEAL_UPSTREAM_SECRET\n");
    return -1;
  }

  return readCredentials(self);
}

void s3seal_config_t.drop(s3seal_config_t *self) {

  for (one in self->keys) {
    free(one->access);
    free(one->secret);
  }

  self->keys.release();

  free(self->upstream);
  free(self->upstreamAccess);
  free(self->upstreamSecret);
  free(self->region);
  free(self->seed);
  free(self->scratch);
  free(self->credentials);

  memset(self, 0, sizeof *self);
}

const char *s3seal_config_t.secretFor(s3seal_config_t *self,
                                     const char *access) {

  s3seal_credential_t *found = self->keys.find(one,
                                              strcmp(one->access, access) == 0);

  return found?->secret;
}

/**
 * Whether a key belongs to us rather than to a client.
 *
 * Parts of an open upload are parked on the upstream under `scratch`, so
 * every listing has to leave them out and no client may name one. Asked in
 * one place so the two rules cannot drift apart.
 */
int s3seal_config_t.ours(s3seal_config_t *self, const char *key) {

  return s3seal_startsWith(key, self->scratch);
}

