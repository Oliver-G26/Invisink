# invisink

> Invisible ink for plain text — zero-width steganography with AES-GCM.

Hide an encrypted message inside ordinary text. The text looks *exactly* the
same afterwards, because the message is carried by Unicode characters that have
no width and render as nothing at all.

```
This sentence carries a secret.        <- looks completely normal
'T‌h‍i‌s‍ s‌e‍n‌t...'   <- what is actually there
```

## About this project

This is a small, fun side project that grew out of a group assignment I wrote
for a cryptography course back in 2024. The brief was open-ended, and our group
went with text watermarking: take a short string, encrypt it, and hide the
result inside a paragraph so that nobody reading the paragraph would ever know
it was there.

The trick is a pair of Unicode characters — **U+200C** (Zero Width Non-Joiner)
and **U+200D** (Zero Width Joiner). Both are real, legal characters that browsers
and editors render as nothing, so one of them can stand for a `0` and the other
for a `1`. Slip one in after every visible character and you have a bit stream
threaded invisibly through an ordinary piece of writing.

I always liked the idea, so I came back to it later, rewrote it properly and
fixed the parts that were quietly broken. What it does today:

1. **Derive a key** from your password with **scrypt**, a memory-hard KDF that
   makes brute-forcing expensive.
2. **Encrypt** the message with **AES-256-GCM**, an authenticated cipher — so a
   wrong password or a tampered message is *detected* rather than silently
   returning garbage.
3. **Frame** the ciphertext in a small binary header (magic bytes, version,
   nonce, length, auth tag) so the tool can tell whether text carries a message
   at all, and tolerate junk after it.
4. **Embed** the resulting bytes as zero-width characters, one bit each.

It is a toy, and I have tried to be honest about that in the Limitations section
below. But it is a toy that does the cryptography correctly, which is more than
the original coursework version could claim.

## What it is for

The point is that the **carrier is public and the message is not**. You can post
the carrier wherever ordinary text goes — a chat message, a comment, a forum
post, a shared document — and it reads as exactly what it appears to be. Anyone
can see it. Only someone holding the password can read what is inside it.

That turns any public channel into a private one:

1. Agree on a password with the other side once, out of band.
2. Hide your message inside any innocuous piece of text.
3. Send that text through whatever normal channel you already use.
4. They run `reveal` with the password and get the message back.

Everyone else sees an ordinary sentence and has no particular reason to think
there is anything more to it. And someone who *does* suspect still cannot read
it: the payload is AES-256-GCM encrypted, not merely hidden. Concealment and
confidentiality are two separate layers here, and only the first one is fragile.

## Install

```bash
pip install -r requirements.txt   # just pycryptodome
python invisink.py
```

Or install it as a command:

```bash
pip install .
invisink
```

## Usage

Running the script opens a small console menu:

```
1. Hide a message
2. Reveal a message
3. Detect a message (no password needed)
4. Exit
```

As a library:

```python
from invisink import hide, reveal, detect

carrier = "Perfectly ordinary text, long enough to carry a few dozen bytes. " * 8

inked = hide(carrier, "alice@example.com", "my passphrase")
inked == carrier          # False — but they look identical
print(inked)              # indistinguishable from the original

reveal(inked, "my passphrase")   # 'alice@example.com'
detect(inked)                    # True, and no password required
reveal(inked, "wrong")           # raises StegoError
```

### Capacity

One bit rides along per character, so a carrier needs `8 x payload` characters.
The payload is 33 bytes of framing plus the UTF-8 length of your message:

| Message | Payload | Carrier needed |
|---|---|---|
| `hi` | 35 bytes | 280 characters |
| `alice@example.com` | 50 bytes | 400 characters |

A carrier that is too short is not an error — the leftover bits are appended to
the end. They are much easier to spot there, so prefer a longer carrier.

## Where it works, and where it breaks

Everything rests on a single condition: **the channel has to pass your text
through unchanged.**

Zero-width characters are ordinary, valid Unicode — not control codes, not
escape sequences. Software that treats text as text carries them without
noticing, which is why they survive typing, copying, pasting, quoting and
forwarding the same way any other character does. Across most everyday
messaging this works fine, and the carrier arrives intact.

It breaks wherever something along the way *rewrites* the text:

| What breaks it | Why |
|---|---|
| **Sanitisers** | U+200C and U+200D are Unicode `Cf` (format) characters, so anything that strips that category removes them — some platforms do this deliberately, precisely to stop tricks like this |
| **Re-rendering** | Markdown to HTML, rich-text conversion, or an editor that "cleans up" pasted text |
| **Retyping the content** | Screenshots, OCR, or asking an LLM to rewrite the passage — the words survive, the hidden bits do not |
| **Truncation** | Length limits cut the payload short, and a partial payload fails authentication |
| **Transliteration** | Anything that forces the text down to ASCII drops every non-ASCII character |

Worth knowing: plain Unicode normalisation is **not** on that list. All four
forms — NFC, NFD, NFKC and NFKD — preserve U+200C and U+200D, so text that is
merely normalised on its way through a system still arrives readable.

Some editors also *display* zero-width characters as dotted boxes or highlighted
markers. That does not destroy the message, but it does give away that something
is there.

### Test your channel before relying on it

Send yourself a message through the channel you intend to use, then check what
actually arrives:

```python
from invisink import detect, reveal

received = "...paste exactly what arrived..."

detect(received)             # False -> the channel stripped the characters
reveal(received, password)   # StegoError -> they arrived damaged
```

Because the payload is authenticated, a damaged message fails loudly instead of
returning plausible nonsense. You will always know whether it survived, which
makes testing a channel a thirty-second job.

## Security limitations

- **This is steganography, not a robust watermark.** It hides the *existence* of
  a message from a casual reader. It does not defeat anyone who knows the scheme
  and goes looking: a one-line regex strips every hidden bit. What protects the
  *content* is AES-GCM, not the hiding.
- **The salt is currently fixed**, not random per message. This saves 16 bytes of
  carrier capacity, but it means a given password always derives the same key —
  so precomputation attacks apply, and an observer can tell that two messages
  were made with the same password. The framing already has room for a random
  salt if you would rather have the security than the capacity.
- **Messages are capped at 65535 bytes** by the 2-byte length field.
- **The presence of a message is not deniable under scrutiny.** An adversary who
  suspects the scheme can confirm a payload is there without breaking it — the
  magic bytes are in the clear, by design, so the tool can tell carriers apart
  from ordinary text. Treat this as a fun and genuinely useful toy, not as
  protection where being caught carries real consequences.

## How it compares to the original coursework version

The core idea is unchanged. The cryptography is not:

| | Original | invisink |
|---|---|---|
| Cipher | AES-ECB | AES-GCM (authenticated) |
| Key derivation | `sha256(password)` | scrypt |
| Wrong password | silently returns garbage | detected and reported |
| Tampering | undetectable | detected |
| Binary conversion | per codepoint — broke on any non-ASCII message | per UTF-8 byte |
| Encoding | base64 first, costing 33% extra capacity | raw bytes |
| Framing | none | magic + version + length |

## License

MIT — see [LICENSE](LICENSE).
