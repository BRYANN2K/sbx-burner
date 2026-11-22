# night-shift (crypto, medium)

The ops team encrypts handover notes with `stream.py` (included) and a seed
picked at random for each note. `message.enc` is last night's note. Every
note starts with `HANDOVER NOTE `.

Recover the note.

Flag format: `flag{32 hex characters}`.
