import json
import logging
from dataclasses import dataclass
from typing import Any

from redis.asyncio import Redis
from redis.exceptions import RedisError

logger = logging.getLogger(__name__)

CACHE_TTL_SECONDS = 15
SCOREBOARD_CACHE_KEY = "cyberarena:scoreboard:v1"
CHALLENGES_CACHE_KEY = "cyberarena:challenges:published:v1"


@dataclass(frozen=True)
class CacheRead:
    value: Any | None
    generation: int | None


def _generation_key(key: str) -> str:
    return f"{key}:generation"


def _value_key(key: str, generation: int) -> str:
    return f"{key}:generation:{generation}"


async def _read_generation(cache: Redis, key: str) -> int | None:
    try:
        value = await cache.get(_generation_key(key))
    except RedisError:
        logger.warning("Redis cache generation read failed for key %s", key, exc_info=True)
        return None
    if value is None:
        return 0
    try:
        return int(value)
    except (TypeError, ValueError):
        logger.warning("Ignoring invalid Redis cache generation for key %s", key)
        return None


async def get_json_cache(
    cache: Redis | None, key: str, expected_type: type
) -> CacheRead:
    if cache is None:
        return CacheRead(None, None)
    generation = await _read_generation(cache, key)
    if generation is None:
        return CacheRead(None, None)
    cache_key = _value_key(key, generation)
    try:
        value = await cache.get(cache_key)
    except RedisError:
        logger.warning("Redis cache read failed for key %s", cache_key, exc_info=True)
        return CacheRead(None, None)
    if value is None:
        return CacheRead(None, generation)
    try:
        result = json.loads(value)
    except (json.JSONDecodeError, TypeError):
        logger.warning("Ignoring invalid Redis cache value for key %s", cache_key)
        await delete_cache_keys(cache, cache_key)
        return CacheRead(None, generation)
    if not isinstance(result, expected_type):
        logger.warning("Ignoring Redis cache value with unexpected type for key %s", cache_key)
        await delete_cache_keys(cache, cache_key)
        return CacheRead(None, generation)
    return CacheRead(result, generation)


async def set_json_cache(
    cache: Redis | None, key: str, value: Any, generation: int | None
) -> None:
    if cache is None or generation is None:
        return
    current_generation = await _read_generation(cache, key)
    if current_generation is None or current_generation != generation:
        return
    try:
        await cache.set(
            _value_key(key, generation),
            json.dumps(value, separators=(",", ":")),
            ex=CACHE_TTL_SECONDS,
        )
    except RedisError:
        logger.warning("Redis cache write failed for key %s", key, exc_info=True)


async def delete_cache_keys(cache: Redis | None, *keys: str) -> None:
    if cache is None or not keys:
        return
    try:
        await cache.delete(*keys)
    except RedisError:
        logger.warning("Redis cache invalidation failed for keys %s", keys, exc_info=True)


async def invalidate_challenges_cache(cache: Redis | None) -> None:
    await _increment_generation(cache, CHALLENGES_CACHE_KEY)


async def invalidate_scoreboard_cache(cache: Redis | None) -> None:
    await _increment_generation(cache, SCOREBOARD_CACHE_KEY)


async def _increment_generation(cache: Redis | None, key: str) -> None:
    if cache is None:
        return
    try:
        await cache.incr(_generation_key(key))
    except RedisError:
        logger.warning("Redis cache invalidation failed for key %s", key, exc_info=True)
