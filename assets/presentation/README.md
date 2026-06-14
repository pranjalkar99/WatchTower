# WatchTower Presentation Deck

Self-contained HTML slide deck for hackathon demos and judge presentations.

## Open

```bash
# From repo root — opens in default browser
xdg-open assets/presentation/watchtower-deck.html   # Linux
open assets/presentation/watchtower-deck.html      # macOS
start assets/presentation/watchtower-deck.html     # Windows
```

Or drag `watchtower-deck.html` into any browser. Works fully offline — no CDN dependencies.

## Present

| Action | Key |
|--------|-----|
| Next slide | `→` `↓` `Space` `Page Down` |
| Previous slide | `←` `↑` `Page Up` |
| First / last slide | `Home` / `End` |
| Fullscreen | `F` |
| Mobile | Swipe left/right, or tap left/right edges |

Progress bar and slide counter (top-right) show position. **14 slides** total.

## Record (screen capture)

1. Start backend + frontend (`README.md` at repo root).
2. Open the deck fullscreen (`F`).
3. Use OBS, QuickTime, or browser screen record at 1920×1080.
4. Optionally switch to live app (`localhost:3000/chat` + `/dashboard`) during demo slides (7–9).

## Render video (automated)

Headless Chrome screenshots + ffmpeg — no manual screen recording:

```bash
./assets/presentation/render-video.sh
# Output: assets/presentation/watchtower-deck.mp4
# Optional: SLIDE_SEC=10 WIDTH=1920 HEIGHT=1080 ./assets/presentation/render-video.sh
```

Requires `google-chrome` (or Chromium) and `ffmpeg`.

## Related assets

- Product launch animation: `assets/launch/watchtower-launch.html`
- Live demo runbook: `examples/travel-agent/DEMO.md`
