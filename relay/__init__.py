"""The phone-to-computer tunnel: Noise end to end, over the home network (contract
``docs/relay-tunnel-v1.md``).

``noise.py``      Noise_IKpsk2 and the 6-digit pairing code.
``framing.py``    ``u32 length | message`` on TCP.
``mux.py``        streams, credit windows, close codes.
``services.py``   the allowlist: ``api`` to Hermes's loopback API Server, and ``control``.
``lan.py``        which addresses may be bound and which peers are answered.
``pairing.py``    host key, pairing window, allowlist, the pending attempt, the pairing link.
``host.py``       the listener: the handshake, rules P1 to P4, sessions.
``owner.py``      one listener per computer, by lock.
``runtime.py``    what ``register()`` assembles; ``cli.py`` is ``hermes cozychat pair``.

Loading the plugin starts nothing here until a pairing window opens, and then only in
``hermes serve`` or ``hermes gateway run``.
"""
