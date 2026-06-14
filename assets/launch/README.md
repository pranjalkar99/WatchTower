# WatchTower Product Launch Animation

~45 second cinematic intro using real product screenshots. Screen-record for your launch video.

## Open

```bash
xdg-open assets/launch/watchtower-launch.html
# Chrome → F11 fullscreen → H to hide controls
```

## Record

```bash
# OBS or ffmpeg (adjust geometry for your display)
ffmpeg -f x11grab -framerate 30 -video_size 1920x1080 -i :0.0 -t 48 watchtower-launch.mp4
```

## Storyboard

| Scene | Content |
|-------|---------|
| Logo | SentinelAI · WatchTower branding |
| **Why** | Unprotected agent breach (SSRF / .env exfil screenshot) |
| **Why 2** | Problem cards: injection, tool abuse, egress, no visibility |
| **What** | Tagline + User → WatchTower → Agent flow |
| **How** | Integration page + 3-line SDK code |
| **Feature** | Command Center dashboard |
| **Feature** | Network Security (webhook blocking) |
| **Features** | 8 capability cards |
| **CASCADE** | Detection layers + benchmark stats |
| **CTA** | github.com/pranjalkar99/WatchTower |

**Space** pause · **H** hide controls · **Replay** restarts

## Assets

Screenshots in `screenshots/`:
- `problem-breach.png` — unprotected agent demo
- `feature-command-center.png` — SOC dashboard
- `feature-integration.png` — SDK integration
- `feature-network.png` — network monitor
