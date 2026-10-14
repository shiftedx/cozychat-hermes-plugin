"""Deterministic API Server fixture for reconnect tests; no Hermes imports or user state.

The producer outlives SSE subscribers. Commands finish the run or discard its in-memory replay
buffer, while status and session history remain durable, like Hermes after a gateway restart.
"""

from __future__ import annotations

import asyncio
import argparse
import json
from pathlib import Path
import sys
import time
from urllib.parse import parse_qs, urlsplit


class ResumeAPI:
    key = "resume-fixture-key"
    run_id = "run-resume"
    fragments = ["Hello ", "café ", "Hello ", "🙂"]
    reply = "".join(fragments)
    partial_reply = "".join(fragments[:2])

    def __init__(self, state_path=None):
        self.requests = []
        self.events = []
        self.finished = asyncio.Event()
        self.terminal_status = None
        self.scenario = "resume"
        self.submissions = 0
        self.replay_lost = False
        self.session_id = "native"
        self.input = "Repeat this phrase"
        self.created_at = time.time()
        self.writers = set()
        self.state_path = state_path
        if state_path is not None and state_path.exists():
            state = json.loads(state_path.read_text())
            for key in ("requests", "submissions", "session_id", "input", "created_at"):
                setattr(self, key, state[key])
            # Hermes hydrates a nonterminal durable run with a dead owner as interrupted
            # (gateway/platforms/api_server_runs.py:395-414), rather than resuming its producer.
            self.terminal_status = state.get("terminal_status") or "interrupted"
            self.finished.set()
            self.replay_lost = True

    async def start(self, port=0):
        self.server = await asyncio.start_server(self.handle, "127.0.0.1", port)
        return self.server.sockets[0].getsockname()[1]

    async def stop(self):
        self.server.close()
        for writer in list(self.writers):
            writer.close()
        await self.server.wait_closed()

    def advance(self):
        if self.finished.is_set():
            return
        self.events += [self.event("message.delta", delta=part) for part in self.fragments[2:]]
        self.events.append(self.event("run.completed", status="completed"))
        self.terminal_status = "completed"
        self.finished.set()
        self.persist()

    def snapshot(self):
        return {key: getattr(self, key) for key in
                ("requests", "submissions", "session_id", "input", "created_at", "terminal_status")} | {"finished": self.finished.is_set()}

    def persist(self):
        if self.state_path is not None:
            temporary = self.state_path.with_suffix(".tmp")
            temporary.write_text(json.dumps(self.snapshot()))
            temporary.replace(self.state_path)

    def event(self, kind, **fields):
        return {"run_id": self.run_id, "event": kind, **fields}

    async def handle(self, reader, writer):
        self.writers.add(writer)
        try:
            request = await reader.readuntil(b"\r\n\r\n")
            line, *lines = request.decode().split("\r\n")
            method, target, _ = line.split(" ")
            headers = {h.split(":", 1)[0].lower(): h.split(":", 1)[1].strip()
                       for h in lines if ":" in h}
            length = int(headers.get("content-length", 0))
            body = json.loads(await reader.readexactly(length)) if length else {}
            url = urlsplit(target)
            if headers.get("authorization") != f"Bearer {self.key}" and url.path != "/health":
                await self.json(writer, {}, status=401)
            elif url.path == "/health":
                await self.json(writer, {"status": "ok"})
            elif method == "POST" and url.path == "/v1/runs":
                self.submissions += 1
                self.session_id = body.get("session_id", "native")
                self.input = body.get("input", self.input)
                self.created_at = time.time()
                if not self.events:
                    self.events = [self.event("run.started", status="running")]
                    self.events += [self.event("message.delta", delta=part) for part in self.fragments[:2]]
                self.persist()
                await self.json(writer, {"run_id": self.run_id, "status": "started"}, status=202)
            elif url.path == f"/v1/runs/{self.run_id}/events":
                cursor = headers.get("last-event-id") or parse_qs(url.query).get("last_seq", [None])[0]
                self.requests.append({"header": headers.get("last-event-id"),
                                      "query": parse_qs(url.query).get("last_seq", [None])[0]})
                self.persist()
                if self.replay_lost:
                    await self.json(writer, {}, status=404)
                    return
                last_seq = int(cursor) if cursor is not None else -1
                if self.scenario == "ignore":
                    last_seq = -1
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n"
                             b"Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n")
                await writer.drain()
                if self.scenario == "truncated" and cursor is not None:
                    await self.chunk(writer, "data: " + json.dumps(self.event("replay.truncated")) + "\n\n")
                for seq, event in enumerate(self.events):
                    if seq > last_seq:
                        await self.sse(writer, seq, event)
                emitted = len(self.events)
                await self.finished.wait()
                for seq in range(emitted, len(self.events)):
                    if seq > last_seq:
                        await self.sse(writer, seq, self.events[seq])
                writer.write(b"0\r\n\r\n")
                await writer.drain()
            elif url.path == f"/v1/runs/{self.run_id}":
                await self.json(writer, {"run_id": self.run_id,
                                        "status": self.terminal_status or "running"})
            elif url.path == f"/api/sessions/{self.session_id}/messages":
                rows = [{"id": 1, "role": "user", "content": self.input, "timestamp": self.created_at}]
                if self.finished.is_set():
                    reply = self.reply if self.terminal_status == "completed" else self.partial_reply
                    rows.append({"id": 2, "role": "assistant", "content": reply,
                                 "timestamp": self.created_at + 0.1})
                await self.json(writer, {"session_id": self.session_id, "data": rows})
            else:
                await self.json(writer, {}, status=404)
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            self.writers.discard(writer)
            writer.close()

    @staticmethod
    async def json(writer, value, status=200):
        body = json.dumps(value).encode()
        writer.write(f"HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\n"
                     f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode() + body)
        await writer.drain()

    @staticmethod
    async def chunk(writer, text):
        data = text.encode()
        writer.write(f"{len(data):x}\r\n".encode() + data + b"\r\n")
        await writer.drain()

    async def sse(self, writer, seq, event):
        # Both wire forms are present, exactly as Hermes's _handle_run_events emits them.
        await self.chunk(writer, f"id: {seq}\ndata: {json.dumps(dict(event, seq=seq))}\n\n")


async def main(arguments):
    api = ResumeAPI(Path(arguments.state))
    port = await api.start(arguments.port)
    print(json.dumps({"port": port}), flush=True)
    try:
        while line := await asyncio.to_thread(sys.stdin.buffer.readline):
            request = json.loads(line)
            if request["op"] == "advance":
                api.advance()
            elif request["op"] == "scenario":
                api.scenario = request["value"]
            print(json.dumps(api.snapshot()), flush=True)
    finally:
        await api.stop()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", required=True)
    parser.add_argument("--port", type=int, default=0)
    asyncio.run(main(parser.parse_args()))
