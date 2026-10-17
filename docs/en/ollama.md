# Optional local AI review (Ollama)

> فارسی: [docs/fa/ollama.md](../fa/ollama.md)

AgentGuard's rule engines work with **zero** external services. If you also want
a model-written second opinion, connect a local [Ollama](https://ollama.com)
server.

## Setup

1. Install Ollama and start it (`ollama serve`, or the Windows tray app).
2. Pull a code-capable model, e.g.:

   ```bash
   ollama pull qwen2.5-coder:7b
   ```

3. In AgentGuard open **AI Review**, press **Test connection**. The app shows
   the server version and the models it found; pick one.
4. Enable *Enable local AI review* and press **Run AI review** after a scan.

## What is sent

Only a bounded prompt (default ≤ 24 000 characters) containing:

- the rule findings already detected (ids, severities, file:line), and
- a diff excerpt with **added/removed lines only**, with secrets masked.

Nothing else from your machine or repository is transmitted, and the request
goes only to the configured host (default `http://127.0.0.1:11434`).

## What you get

A short summary plus a list of insights with severity and file hints, shown in
the AI Review view and embedded in exported reports. The model output is
parsed leniently: if it is not valid JSON, the raw text is displayed instead.

## Tips

- Larger coder models (7 B+) give noticeably better insight quality.
- Keep the timeout high (default 180 s) for CPU-only inference.
- The AI never changes rule severities or the verdict; it is advisory only.
- If Ollama is offline, scans still complete normally and the report notes
  that the AI was unavailable.
