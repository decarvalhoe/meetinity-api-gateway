# Performance Tuning Guide

The API gateway exposes several environment variables that control network
behaviour, caching, and response compression. This guide complements the inline
notes in `src/app.py` and helps operators adjust the defaults to their
workloads.

## HTTP client timeouts and connection reuse

| Variable | Default | Description |
| --- | --- | --- |
| `PROXY_TIMEOUT_CONNECT` | `2` seconds | Socket connect timeout when calling upstream services. |
| `PROXY_TIMEOUT_READ` | `10` seconds | Time to wait for upstream responses once connected. |
| `PROXY_POOL_CONNECTIONS` | `10` | Number of connection pools created per scheme for the shared `requests.Session`. |
| `PROXY_POOL_MAXSIZE` | `10` | Maximum connections per pool; increase for high concurrency. |
| `PROXY_SESSION_KEEPALIVE` | `true` | Adds the `Connection: keep-alive` header to reuse TCP sessions when supported. |

Tune the timeouts conservatively to balance resiliency and user experience. The
pool parameters determine how many concurrent upstream calls can reuse existing
TCP connections before creating new sockets.

## Response caching

| Variable | Default | Description |
| --- | --- | --- |
| `CACHE_ENABLED` | `true` | Enables the shared response cache for idempotent GET requests. |
| `CACHE_BACKEND` | `memory` | Cache backend (`memory` or `redis`). |
| `CACHE_DEFAULT_TTL` | `5` seconds | Default time-to-live for cached responses. |
| `CACHE_REDIS_URL` | empty | Redis connection string when using the Redis backend. |
| `CACHE_REDIS_NAMESPACE` | `api-gateway` | Prefix for Redis keys to avoid collisions. |
| `CACHE_VARY_HEADERS` | `Authorization` | Headers used to scope cache keys (per user/API key). |

Cached entries can be invalidated programmatically with
`app.extensions['response_cache'].invalidate(prefix='GET:/path')`. Responses
containing `Set-Cookie` headers are excluded from caching to avoid leaking
session state.

## Response compression

| Variable | Default | Description |
| --- | --- | --- |
| `COMPRESSION_ENABLED` | `true` | Enables automatic gzip/brotli compression. |
| `COMPRESSION_MIN_SIZE` | `512` bytes | Minimum payload size before compression is applied. |
| `COMPRESSION_GZIP_LEVEL` | `6` | Gzip compression level. |
| `COMPRESSION_BR_QUALITY` | `5` | Brotli quality when the optional module is available. |

Compression respects the `Accept-Encoding` header and updates the `Vary` header
so downstream caches behave correctly.
