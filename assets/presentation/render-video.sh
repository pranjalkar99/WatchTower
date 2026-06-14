#!/usr/bin/env bash
# Render watchtower-deck.html to MP4 via headless Chrome screenshots + ffmpeg.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
DECK="$ROOT/watchtower-deck.html"
FRAMES="$ROOT/.render-frames"
OUT="$ROOT/watchtower-deck.mp4"
SLIDE_SEC="${SLIDE_SEC:-8}"
WIDTH="${WIDTH:-1920}"
HEIGHT="${HEIGHT:-1080}"

CHROME="${CHROME:-}"
for candidate in google-chrome google-chrome-stable chromium chromium-browser; do
  if command -v "$candidate" >/dev/null 2>&1; then
    CHROME="$candidate"
    break
  fi
done
if [[ -z "$CHROME" ]]; then
  echo "Error: Chrome or Chromium not found in PATH." >&2
  exit 1
fi
if ! command -v ffmpeg >/dev/null 2>&1; then
  echo "Error: ffmpeg not found in PATH." >&2
  exit 1
fi

TOTAL="$("$CHROME" --headless=new --disable-gpu --dump-dom \
  "file://$DECK?render=1&slide=1" 2>/dev/null | grep -o 'data-slide="[0-9]*"' | tail -1 | grep -o '[0-9]*' || true)"
if [[ -z "$TOTAL" ]]; then
  TOTAL=14
fi

rm -rf "$FRAMES"
mkdir -p "$FRAMES"

echo "Capturing $TOTAL slides at ${WIDTH}x${HEIGHT}..."
for i in $(seq 1 "$TOTAL"); do
  num=$(printf '%02d' "$i")
  "$CHROME" --headless=new --disable-gpu --hide-scrollbars \
    --window-size="${WIDTH},${HEIGHT}" \
    --screenshot="$FRAMES/slide-${num}.png" \
    "file://$DECK?render=1&slide=$i" 2>/dev/null
  echo "  slide $i/$TOTAL"
done

echo "Encoding ${SLIDE_SEC}s per slide -> $OUT"
ffmpeg -y -hide_banner -loglevel warning \
  -framerate "1/$SLIDE_SEC" -pattern_type glob -i "$FRAMES/slide-*.png" \
  -vf "fps=30,scale=${WIDTH}:${HEIGHT}:force_original_aspect_ratio=decrease,pad=${WIDTH}:${HEIGHT}:(ow-iw)/2:(oh-ih)/2:black" \
  -c:v libx264 -preset medium -crf 20 -pix_fmt yuv420p -movflags +faststart \
  "$OUT"

echo "Done: $OUT ($(du -h "$OUT" | cut -f1))"
