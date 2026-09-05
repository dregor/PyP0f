import threading

import fakeredis
import redis
import pytest

from pyp0f.storage import RedisSink


@pytest.fixture
def fake_client():
    return fakeredis.FakeRedis()


def test_store_below_batch_size_is_not_flushed_yet(fake_client):
    sink = RedisSink(client=fake_client, batch_size=5, flush_interval_seconds=999)
    sink.store("1.2.3.4", "Linux")
    assert fake_client.exists("pyp0f:1.2.3.4") == 0


def test_store_reaching_batch_size_flushes(fake_client):
    sink = RedisSink(client=fake_client, batch_size=3, flush_interval_seconds=999)
    sink.store("1.2.3.4", "Linux")
    sink.store("1.2.3.5", "Windows")
    sink.store("1.2.3.6", "Mac OS X")

    assert fake_client.get("pyp0f:1.2.3.4") == b"Linux"
    assert fake_client.get("pyp0f:1.2.3.5") == b"Windows"
    assert fake_client.get("pyp0f:1.2.3.6") == b"Mac OS X"


def test_store_sets_the_configured_ttl(fake_client):
    sink = RedisSink(client=fake_client, batch_size=1, flush_interval_seconds=999, ttl_seconds=10800)
    sink.store("1.2.3.4", "Linux")
    ttl = fake_client.ttl("pyp0f:1.2.3.4")
    assert 0 < ttl <= 10800


def test_key_prefix_is_configurable(fake_client):
    sink = RedisSink(client=fake_client, key_prefix="custom:", batch_size=1, flush_interval_seconds=999)
    sink.store("1.2.3.4", "Linux")
    assert fake_client.get("custom:1.2.3.4") == b"Linux"


def test_time_based_flush_fires_even_below_batch_size(fake_client, monkeypatch):
    import pyp0f.storage as storage_module

    fake_now = [1000.0]
    monkeypatch.setattr(storage_module.time, "monotonic", lambda: fake_now[0])

    sink = RedisSink(client=fake_client, batch_size=50, flush_interval_seconds=1.0)
    sink.store("1.2.3.4", "Linux")
    assert fake_client.exists("pyp0f:1.2.3.4") == 0

    # Advance the clock past the flush interval, then make one more
    # observation - store() only checks the clock on its own calls, it does
    # not flush spontaneously in the background.
    fake_now[0] += 2.0
    sink.store("1.2.3.5", "Windows")

    assert fake_client.get("pyp0f:1.2.3.4") == b"Linux"
    assert fake_client.get("pyp0f:1.2.3.5") == b"Windows"


def test_manual_flush_writes_a_partial_batch(fake_client):
    sink = RedisSink(client=fake_client, batch_size=50, flush_interval_seconds=999)
    sink.store("1.2.3.4", "Linux")
    assert fake_client.exists("pyp0f:1.2.3.4") == 0

    sink.flush()
    assert fake_client.get("pyp0f:1.2.3.4") == b"Linux"


def test_flush_with_nothing_pending_is_a_no_op(fake_client):
    sink = RedisSink(client=fake_client, batch_size=50, flush_interval_seconds=999)
    sink.flush()  # must not raise
    sink.flush()


def test_flush_error_is_swallowed_and_resets_pending_state(fake_client, monkeypatch):
    sink = RedisSink(client=fake_client, batch_size=1, flush_interval_seconds=999)

    def _broken_execute():
        raise redis.RedisError("connection lost")

    monkeypatch.setattr(sink._pipe, "execute", _broken_execute)

    sink.store("1.2.3.4", "Linux")  # must not raise despite the broken pipe

    assert sink._pending == 0
    assert fake_client.exists("pyp0f:1.2.3.4") == 0


def test_flush_error_does_not_poison_subsequent_batches(fake_client):
    sink = RedisSink(client=fake_client, batch_size=1, flush_interval_seconds=999)

    call_count = {"n": 0}
    real_execute = sink._pipe.execute

    def _fail_once():
        call_count["n"] += 1
        if call_count["n"] == 1:
            raise redis.RedisError("connection lost")
        return real_execute()

    sink._pipe.execute = _fail_once

    sink.store("1.2.3.4", "Linux")  # this batch fails and is dropped
    sink.store("1.2.3.5", "Windows")  # this one must still succeed

    assert fake_client.exists("pyp0f:1.2.3.4") == 0
    assert fake_client.get("pyp0f:1.2.3.5") == b"Windows"


def test_concurrent_store_calls_do_not_corrupt_state(fake_client):
    sink = RedisSink(client=fake_client, batch_size=10, flush_interval_seconds=999)
    ips = [f"10.0.{i // 256}.{i % 256}" for i in range(200)]

    def _worker(chunk):
        for ip in chunk:
            sink.store(ip, "Linux")

    threads = [
        threading.Thread(target=_worker, args=(ips[i::8],)) for i in range(8)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    sink.flush()

    for ip in ips:
        assert fake_client.get(f"pyp0f:{ip}") == b"Linux"
