"""Streams inside a session: credit windows, frame and stream caps, and the services allowlist."""

import asyncio

import pytest

from cozychat.relay import framing, noise
from cozychat.relay.mux import (CLOSE, DATA, INITIAL_WINDOW, MAX_STREAMS, OPEN, Mux, ProtocolError,
                                SessionClose, StreamClose, close_payload, decode_frame,
                                encode_frame)


def run(coro):
    return asyncio.run(asyncio.wait_for(coro, 30))


def sessions():
    host, phone = noise.generate_private_key(), noise.generate_private_key()
    initiator = noise.Initiator(phone, noise.public_key(host), noise.ZERO_PSK)
    responder = noise.Responder(host)
    responder.read_message_1(initiator.write_message_1())
    message_2, host_session = responder.write_message_2(noise.ZERO_PSK)
    _, phone_session = initiator.read_message_2(message_2)
    return phone_session, host_session


async def connected(on_open):
    """A phone mux and a host mux over a real loopback TCP connection."""
    phone_session, host_session = sessions()
    accepted = asyncio.get_running_loop().create_future()
    server = await asyncio.start_server(lambda r, w: accepted.set_result((r, w)), "127.0.0.1", 0)
    phone_reader, phone_writer = await asyncio.open_connection(
        "127.0.0.1", server.sockets[0].getsockname()[1])
    host_reader, host_writer = await accepted
    server.close()
    phone = Mux(phone_session, phone_reader, phone_writer, initiator=True)
    host = Mux(host_session, host_reader, host_writer, initiator=False, on_open=on_open)
    tasks = [asyncio.ensure_future(phone.run()), asyncio.ensure_future(host.run())]
    return phone, host, tasks


async def finish(phone, host, tasks):
    await phone.close()
    await asyncio.gather(*tasks, return_exceptions=True)


def test_frames_round_trip_and_bad_frames_are_protocol_errors():
    assert decode_frame(encode_frame(DATA, 7, b"hi")) == (DATA, 7, b"hi")
    with pytest.raises(ProtocolError):
        decode_frame(b"\x02\x00")
    with pytest.raises(ProtocolError):
        decode_frame(bytes([9, 0, 0, 0, 1]))
    with pytest.raises(ProtocolError):
        decode_frame(encode_frame(DATA, 1) + bytes(framing.MAX_DATA + 1))
    with pytest.raises(ValueError):
        encode_frame(DATA, 1, bytes(framing.MAX_DATA + 1))


def test_a_frame_is_at_most_16384_bytes_header_included():
    """Contract sections 5.1 and 7: 16,384 bytes of plaintext including the 5-byte header, so 16,379
    of data, and 16,400 bytes on the wire with the tag."""
    assert framing.MAX_PLAINTEXT == 16384
    assert framing.MAX_DATA == 16379
    assert framing.TRANSPORT_MAX == 16400
    largest = encode_frame(DATA, 1, bytes(16379))
    assert len(largest) == 16384
    assert decode_frame(largest) == (DATA, 1, bytes(16379))
    with pytest.raises(ProtocolError):
        decode_frame(largest + b"\x00")
    with pytest.raises(ValueError):
        encode_frame(DATA, 1, bytes(16380))
    phone, host = sessions()
    assert len(phone.encrypt(largest)) == framing.TRANSPORT_MAX


def test_a_sender_stops_at_256_kib_until_the_reader_returns_credit():
    """Backpressure: a phone that does not read cannot make this computer send (or buffer) more."""
    total = 1024 * 1024
    host_streams = []

    async def on_open(mux, stream):
        host_streams.append(stream)
        await stream.write(bytes(total))
        await stream.close()

    async def scenario():
        phone, host, tasks = await connected(on_open)
        try:
            stream = await phone.open("bulk")
            await asyncio.sleep(0.5)
            sent = host_streams[0].bytes_sent
            assert sent == INITIAL_WINDOW  # stalled at exactly one window, nothing more
            assert host_streams[0].send_credit == 0

            received = 0
            while chunk := await stream.read():
                assert len(chunk) <= framing.MAX_DATA
                received += len(chunk)
            assert received == total
        finally:
            await finish(phone, host, tasks)

    run(scenario())


def test_overrunning_the_credit_closes_the_stream_with_code_4():
    async def on_open(mux, stream):
        await stream.read()  # read once, then stop; the phone pushes on regardless
        await asyncio.Event().wait()

    async def scenario():
        phone, host, tasks = await connected(on_open)
        try:
            stream = await phone.open("bulk")
            stream._send_credit = 10 * INITIAL_WINDOW  # a phone that ignores its credit
            try:
                await asyncio.wait_for(stream.write(bytes(2 * INITIAL_WINDOW)), 5)
            except ConnectionError:
                pass  # the close may land before the last frame is written
            assert await asyncio.wait_for(stream.read(), 5) == b""
            assert stream.close_code == StreamClose.FLOW_CONTROL
        finally:
            await finish(phone, host, tasks)

    run(scenario())


def test_streams_past_the_cap_are_closed_with_code_5():
    gate = asyncio.Event

    async def scenario():
        hold = gate()

        async def on_open(mux, stream):
            await hold.wait()

        phone, host, tasks = await connected(on_open)
        try:
            streams = [await phone.open("svc") for _ in range(MAX_STREAMS + 1)]
            assert await asyncio.wait_for(streams[-1].read(), 5) == b""
            assert streams[-1].close_code == StreamClose.LIMIT
            assert host.open_streams == MAX_STREAMS
            hold.set()
        finally:
            await finish(phone, host, tasks)

    run(scenario())


def test_a_bad_stream_id_ends_the_session_with_code_1():
    async def on_open(mux, stream):
        await stream.read()

    async def scenario():
        phone, host, tasks = await connected(on_open)
        try:
            await phone.send(OPEN, 2, b"api")  # even: the phone's ids are odd
            await asyncio.wait_for(phone.done.wait(), 5)
            assert phone.remote_close_code == SessionClose.PROTOCOL
        finally:
            await finish(phone, host, tasks)

    run(scenario())


def test_the_session_closes_with_its_code():
    async def scenario():
        phone, host, tasks = await connected(None)
        await host.close(SessionClose.SHUTTING_DOWN)
        await asyncio.wait_for(phone.done.wait(), 5)
        assert phone.remote_close_code == SessionClose.SHUTTING_DOWN
        await finish(phone, host, tasks)

    run(scenario())


def test_only_the_allowlisted_services_open(tmp_path):
    """`control` and `api` exist; any other name is code 1, and nothing reaches a raw port."""
    from cozychat.relay import services

    context = services.SessionContext(approved=True, capabilities=lambda: {},
                                      api=lambda: services.ApiTarget(port=1, key=None))

    async def scenario():
        phone, host, tasks = await connected(lambda m, s: services.serve(m, s, context))
        try:
            for name in ("dashboard", "files", "terminal", "127.0.0.1:22", ""):
                stream = await phone.open(name)
                assert await asyncio.wait_for(stream.read(), 5) == b""
                assert stream.close_code == StreamClose.UNKNOWN_SERVICE, name
            # `api` with nothing listening on its loopback port: unreachable, code 2.
            stream = await phone.open("api")
            assert await asyncio.wait_for(stream.read(), 10) == b""
            assert stream.close_code == StreamClose.UNREACHABLE
            stream = await phone.open("api", {"profile": "worker"})
            assert await asyncio.wait_for(stream.read(), 5) == b""
            assert stream.close_code == StreamClose.UNREACHABLE
        finally:
            await finish(phone, host, tasks)

    run(scenario())


def test_an_upstream_error_is_a_stream_error_and_other_streams_survive():
    from cozychat.relay import services

    async def scenario():
        async def broken(reader, writer):
            await reader.read(1)
            writer.transport.abort()

        server = await asyncio.start_server(broken, "127.0.0.1", 0)
        context = services.SessionContext(approved=True, capabilities=lambda: {},
            api=lambda: services.ApiTarget(server.sockets[0].getsockname()[1], "key"))
        phone, host, tasks = await connected(lambda m, s: services.serve(m, s, context))
        try:
            stream = await phone.open("api")
            await stream.write(b"request")
            assert await asyncio.wait_for(stream.read(), 5) == b""
            # A clean upstream EOF may close normally; a reset uses UNREACHABLE. Neither ends
            # the whole Noise session or prevents a fresh control stream.
            assert stream.close_code in (StreamClose.NORMAL, StreamClose.UNREACHABLE)
            assert not host.done.is_set()
            control = await phone.open("control")
            await control.write(b'{"id":1,"op":"info"}\n')
            assert b'"ok":true' in await asyncio.wait_for(control.read(), 5)
        finally:
            await finish(phone, host, tasks)
            server.close()
            await server.wait_closed()

    run(scenario())


def test_close_payload_carries_the_code():
    assert close_payload(StreamClose.LIMIT, "full")[:2] == b"\x00\x05"
    assert CLOSE == 3
