/**
 * The small things, implemented.
 *
 * One translation unit of its own rather than `static inline` in the header,
 * because a header that carries bodies is a header every unit recompiles and
 * a body nobody can put a breakpoint in. build.sh lowers each unit on its own
 * and names them all in the addon's config, which is what nginx's build reads.
 */
#include "util.h"

#include <ctype.h>

@owns char *s3seal_dupn(const char *from, size_t length) {

  char *made;

  if (from == NULL)
    return NULL;

  made = malloc(length + 1);

  if (made == NULL)
    return NULL;

  memcpy(made, from, length);
  made[length] = 0;

  return made;
}

@owns char *s3seal_dup(const char *from) {
  return from != NULL ? s3seal_dupn(from, strlen(from)) : NULL;
}

@owns char *s3seal_join(const char *a, const char *between, const char *b) {

  size_t first = strlen(a);
  size_t middle = strlen(between);
  size_t second = strlen(b);
  char *made = malloc(first + middle + second + 1);

  if (made == NULL)
    return NULL;

  memcpy(made, a, first);
  memcpy(made + first, between, middle);
  memcpy(made + first + middle, b, second);
  made[first + middle + second] = 0;

  return made;
}

int s3seal_same(const char *a, const char *b) {

  while (*a != 0 && *b != 0) {

    if (tolower((unsigned char)*a) != tolower((unsigned char)*b))
      return 0;

    ++a;
    ++b;
  }

  return *a == *b;
}

int s3seal_startsWith(const char *text, const char *with) {

  size_t length = strlen(with);

  return strncmp(text, with, length) == 0;
}

/**
 * Lowercase letters, digits, dot and dash; three to sixty-three of them;
 * starting and ending on a letter or a digit.
 *
 * Narrower than AWS, which also allows a name that looks like an address.
 * A bucket ends up in a directory name and one day in a host name, and both
 * have opinions about what a name is.
 */
int s3seal_bucketOk(const char *name) {

  size_t length = strlen(name);

  if (length < 3 || length > S3SEAL_BUCKET_MAX)
    return 0;

  for (size_t at = 0; at < length; ++at) {

    char one = name[at];
    int ordinary = (one >= 'a' && one <= 'z') || (one >= '0' && one <= '9');

    if (ordinary)
      continue;

    if (one in {'.', '-'} && at != 0 && at + 1 != length)
      continue;

    return 0;
  }

  return 1;
}

/**
 * Non-empty, under the limit, and nothing that would make it a path we did
 * not mean. A key is never a filename here - the medium path comes out of the
 * metadb - but `..` in a key is the kind of thing that finds a second reader.
 */
int s3seal_keyOk(const char *key) {

  size_t length = strlen(key);

  if (length == 0 || length > S3SEAL_KEY_MAX)
    return 0;

  for (size_t at = 0; at < length; ++at)
    if ((unsigned char)key[at] < 0x20)
      return 0;

  return 1;
}

void s3seal_toHex(const unsigned char *from, size_t length, char *into) {

  static const char digits[] = "0123456789abcdef";

  for (size_t at = 0; at < length; ++at) {
    into[at * 2] = digits[from[at] >> 4];
    into[at * 2 + 1] = digits[from[at] & 15];
  }

  into[length * 2] = 0;
}

int s3seal_fromHex(const char *from, unsigned char *into, size_t room) {

  size_t length = strlen(from);

  if (length % 2 != 0 || length / 2 > room)
    return -1;

  for (size_t at = 0; at < length; at += 2) {

    int high = 0;
    int low = 0;

    for (int half = 0; half < 2; ++half) {

      char one = from[at + half];
      int value;

      if (one >= '0' && one <= '9')
        value = one - '0';
      else if (one >= 'a' && one <= 'f')
        value = one - 'a' + 10;
      else if (one >= 'A' && one <= 'F')
        value = one - 'A' + 10;
      else
        return -1;

      if (half == 0)
        high = value;
      else
        low = value;
    }

    into[at / 2] = (unsigned char)((high << 4) | low);
  }

  return (int)(length / 2);
}

unsigned int s3seal_crc32(const void *bytes, size_t length, unsigned int from) {

  const unsigned char *at = bytes;
  unsigned int state = ~from;

  for (size_t step = 0; step < length; ++step) {

    state ^= at[step];

    for (int bit = 0; bit < 8; ++bit)
      state = (state >> 1) ^ (0xEDB88320u & (unsigned int)(-(int)(state & 1)));
  }

  return ~state;
}

long long s3seal_now(void) {

  struct timespec when;

  clock_gettime(CLOCK_REALTIME, &when);

  return (long long)when.tv_sec;
}

void s3seal_iso8601(long long when, char *into, size_t room) {

  time_t seconds = (time_t)when;
  struct tm broken;

  gmtime_r(&seconds, &broken);

  snprintf(into, room, "%04d-%02d-%02dT%02d:%02d:%02d.000Z",
           broken.tm_year + 1900, broken.tm_mon + 1, broken.tm_mday,
           broken.tm_hour, broken.tm_min, broken.tm_sec);
}

void s3seal_amzTime(long long when, char *into, size_t room) {

  time_t seconds = (time_t)when;
  struct tm broken;

  gmtime_r(&seconds, &broken);

  snprintf(into, room, "%04d%02d%02dT%02d%02d%02dZ", broken.tm_year + 1900,
           broken.tm_mon + 1, broken.tm_mday, broken.tm_hour, broken.tm_min,
           broken.tm_sec);
}

void s3seal_amzDay(long long when, char *into, size_t room) {

  time_t seconds = (time_t)when;
  struct tm broken;

  gmtime_r(&seconds, &broken);

  snprintf(into, room, "%04d%02d%02d", broken.tm_year + 1900, broken.tm_mon + 1,
           broken.tm_mday);
}

void s3seal_httpDate(long long when, char *into, size_t room) {

  static const char *const days[] = {"Sun", "Mon", "Tue", "Wed",
                                     "Thu", "Fri", "Sat"};
  static const char *const months[] = {"Jan", "Feb", "Mar", "Apr",
                                       "May", "Jun", "Jul", "Aug",
                                       "Sep", "Oct", "Nov", "Dec"};

  time_t seconds = (time_t)when;
  struct tm broken;

  gmtime_r(&seconds, &broken);

  /* the names by hand, because strftime would use the process's locale */
  snprintf(into, room, "%s, %02d %s %04d %02d:%02d:%02d GMT",
           days[broken.tm_wday % 7], broken.tm_mday,
           months[broken.tm_mon % 12], broken.tm_year + 1900, broken.tm_hour,
           broken.tm_min, broken.tm_sec);
}

long long s3seal_readAmzTime(const char *text) {

  struct tm broken;
  int year = 0;
  int month = 0;
  int day = 0;
  int hour = 0;
  int minute = 0;
  int second = 0;

  if (strlen(text) < 16 || text[8] != 'T')
    return -1;

  if (sscanf(text, "%4d%2d%2dT%2d%2d%2dZ", &year, &month, &day, &hour, &minute,
             &second) != 6)
    return -1;

  memset(&broken, 0, sizeof broken);

  broken.tm_year = year - 1900;
  broken.tm_mon = month - 1;
  broken.tm_mday = day;
  broken.tm_hour = hour;
  broken.tm_min = minute;
  broken.tm_sec = second;

  return (long long)timegm(&broken);
}

/* --------------------------------------------------------------- a buffer */

int s3seal_buf_t.grow(s3seal_buf_t *self, size_t more) {

  size_t wanted;
  char *bigger;

  if (self->broke)
    return 0;

  if (self->count + more + 1 <= self->room)
    return 1;

  wanted = self->room != 0 ? self->room : 256;

  while (wanted < self->count + more + 1)
    wanted *= 2;

  bigger = realloc(self->at, wanted);

  if (bigger == NULL) {
    self->broke = 1;
    return 0;
  }

  self->at = bigger;
  self->room = wanted;

  return 1;
}

int s3seal_buf_t.addn(s3seal_buf_t *self, const void *bytes, size_t length) {

  if (!self->grow(length))
    return 0;

  memcpy(self->at + self->count, bytes, length);
  self->count += length;
  self->at[self->count] = 0;

  return 1;
}

int s3seal_buf_t.add(s3seal_buf_t *self, const char *text) {
  return self->addn(text, strlen(text));
}

int s3seal_buf_t.addf(s3seal_buf_t *self, const char *shape, ...) {

  va_list args;
  va_list again;
  int wanted;

  va_start(args, shape);
  va_copy(again, args);

  wanted = vsnprintf(NULL, 0, shape, args);
  va_end(args);

  if (wanted < 0 || !self->grow((size_t)wanted)) {
    va_end(again);
    return 0;
  }

  vsnprintf(self->at + self->count, (size_t)wanted + 1, shape, again);
  va_end(again);

  self->count += (size_t)wanted;

  return 1;
}

/**
 * The five XML calls for one, because a listing carries keys a client chose
 * and a key with an `&` in it is ordinary rather than an attack.
 */
int s3seal_buf_t.addXml(s3seal_buf_t *self, const char *text) {

  for (const char *at = text; *at != 0; ++at) {

    int ok;

    switch (*at) {
    case '&':
      ok = self->add("&amp;");
      break;
    case '<':
      ok = self->add("&lt;");
      break;
    case '>':
      ok = self->add("&gt;");
      break;
    case '"':
      ok = self->add("&quot;");
      break;
    case '\'':
      ok = self->add("&apos;");
      break;
    default:
      ok = self->addn(at, 1);
      break;
    }

    if (!ok)
      return 0;
  }

  return 1;
}

/**
 * RFC 3986 unreserved, and nothing else - which is what SigV4 means by
 * encoding a path, and what a listing means by `encoding-type=url`.
 *
 * `keepSlash` is the difference between the two uses: a canonical URI keeps
 * its separators and an encoded key does not.
 */
int s3seal_buf_t.addUri(s3seal_buf_t *self, const char *text, int keepSlash) {

  static const char digits[] = "0123456789ABCDEF";

  for (const unsigned char *at = (const unsigned char *)text; *at != 0; ++at) {

    int plain = (*at >= 'A' && *at <= 'Z') || (*at >= 'a' && *at <= 'z') ||
                (*at >= '0' && *at <= '9') || *at in {'-', '_', '.', '~'};

    if (plain || (keepSlash && *at == '/')) {

      if (!self->addn(at, 1))
        return 0;

      continue;
    }

    {
      char escaped[3];

      escaped[0] = '%';
      escaped[1] = digits[*at >> 4];
      escaped[2] = digits[*at & 15];

      if (!self->addn(escaped, 3))
        return 0;
    }
  }

  return 1;
}

void s3seal_buf_t.drop(s3seal_buf_t *self) {

  free(self->at);

  self->at = NULL;
  self->count = 0;
  self->room = 0;
  self->broke = 0;
}

size_t s3seal_unescape(const char *from, char *into, size_t room) {

  size_t wrote = 0;

  while (*from != 0 && wrote + 1 < room) {

    if (*from == '%' && from[1] != 0 && from[2] != 0) {

      unsigned char one;
      char pair[3];

      pair[0] = from[1];
      pair[1] = from[2];
      pair[2] = 0;

      if (s3seal_fromHex(pair, &one, 1) == 1) {
        into[wrote++] = (char)one;
        from += 3;
        continue;
      }
    }

    into[wrote++] = *from++;
  }

  into[wrote] = 0;

  return wrote;
}
