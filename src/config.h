#ifndef S3SEAL_CONFIG_H
#define S3SEAL_CONFIG_H

/**
 * Where everything lives, and who is allowed to talk to it.
 *
 * Read from the environment, because a module loaded into nginx has no
 * command line of its own - the launcher execs nginx and the module runs
 * inside it. `http.env` names the variables that have to survive into the
 * workers.
 *
 * ----------------------------------------------------------- credentials
 *
 * **Two sets, and they are not the same set.** A client signs to us with a
 * key from the credentials file; we sign to the upstream with a key of our
 * own. That is the shape of a proxy and it is worth having in the types: a
 * client never learns the upstream's key, and rotating one is not rotating
 * the other.
 */

#include "s3seal.h"

typedef struct s3seal_credential_t {
  char *access;
  char *secret;
} s3seal_credential_t;

typedef struct s3seal_config_t {
  /** Where the real S3 is: `https://s3.eu-central-1.amazonaws.com`. */
  char *upstream;

  /** What we sign to it with. Never told to a client. */
  char *upstreamAccess;
  char *upstreamSecret;

  char *region;

  /** The seed every object's wrapping key is derived from. */
  char *seed;

  /**
   * The prefix parts of an upload are parked under while it is open.
   *
   * On the upstream, because that is where a proxy is allowed to keep things.
   * Filtered out of every listing, and emptied when the upload completes or
   * is aborted.
   */
  char *scratch;

  /** What clients sign to us with. */
  char *credentials;

  int port;

  /** The largest single PUT or part, which bounds a worker's memory. */
  unsigned long long maxPart;

  s3seal_credential_t[] keys;
} s3seal_config_t;

/** Reads the environment and the credentials file. Non-zero and says why. */
int s3seal_config_t.read(s3seal_config_t *self);

void s3seal_config_t.drop(s3seal_config_t *self);

/** The secret for an access key, or NULL. */
const char *s3seal_config_t.secretFor(s3seal_config_t *self, const char *access);

/** Whether a key is one of ours to hide - the scratch prefix. */
int s3seal_config_t.ours(s3seal_config_t *self, const char *key);

#endif /* S3SEAL_CONFIG_H */
