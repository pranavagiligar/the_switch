# Telegram Bot Integration Setup

This document explains how to set up and run the Job Scheduler with Telegram bot notifications.

## Architecture

- **`main.go`** (Job Scheduler API) runs on port `8080` and executes scheduled jobs
- **`bot/bot.go`** (Telegram Bot) connects to Telegram and listens for job execution notifications on port `9090`
- When a job finishes, `main.go` sends an HTTP POST to `bot/bot.go` with job details (name, ID, next run time, status)
- The bot forwards this as a Telegram message to the authorized user

## Configuration

### Root `.env` (for main.go)

Create `.env` in the root directory:

```bash
DB_PATH=job_scheduler.db
ADMIN_PASS=your-secure-password
JWT_TOKEN_SECRET=your-jwt-secret-key
PORT=8080

# Bot integration
BOT_NOTIFY_URL=http://127.0.0.1:9090
BOT_INTERNAL_TOKEN=my-secret-token-12345
```

### Bot `.env` (for bot/bot.go)

Create `bot/.env`:

```bash
TELEGRAM_BOT_TOKEN=your-telegram-bot-token-here
TELEGRAM_USER_ID=your-telegram-user-id
API_BASE_URL=http://localhost:8080
DEFAULT_USERNAME=admin
DEFAULT_PASSWORD=your-secure-password

# Internal server for receiving notifications
BOT_INTERNAL_PORT=9090
BOT_INTERNAL_TOKEN=my-secret-token-12345
```

**Important:** The `BOT_INTERNAL_TOKEN` must be the **same in both `.env` files**. This is a shared secret that prevents unauthorized callers.

## How It Works

1. **Job Executes**: A scheduled job runs in `main.go`
2. **Log to DB**: Execution result is stored in `job_executions` table
3. **Notify Bot**: `main.go` POSTs to `http://127.0.0.1:9090/internal/notify` with:
   - Job ID, title, cron expression
   - Execution status (Success/Failure)
   - Duration and exit code
   - Next scheduled run time
4. **Validate Token**: Bot checks `X-INTERNAL-TOKEN` header matches `BOT_INTERNAL_TOKEN`
5. **Send Telegram**: Bot formats a message and sends it to the authorized user

## Message Format

Example Telegram notification:

```
✅ Job `Daily Health Check` (job-1) — Success
Next scheduled for: Jan 10, 2025 00:00:00 UTC
Duration: 125ms — Exit Code: 0
```

Or if failed:

```
❌ Job `Backup Script` (job-2) — Failure
Next scheduled for: Jan 11, 2025 02:00:00 UTC
Duration: 3500ms — Exit Code: 1
```

## Running Both Processes

### Terminal 1: Start the Scheduler API

```bash
cd /workspaces/the_switch
go build -o scheduler .
./scheduler
```

### Terminal 2: Start the Telegram Bot

```bash
cd /workspaces/the_switch/bot
go build -o telegram-bot .
./telegram-bot
```

## Testing the Notification Endpoint

If the bot is running, you can test the notification endpoint manually:

```bash
curl -X POST http://127.0.0.1:9090/internal/notify \
  -H "Content-Type: application/json" \
  -H "X-INTERNAL-TOKEN: my-secret-token-12345" \
  -d '{
    "jobId": "job-1",
    "title": "Test Job",
    "cronExpression": "0 0 * * *",
    "nextRunAt": 1704844800000,
    "status": "Success",
    "durationMs": 150,
    "exitCode": 0
  }'
```

Expected response: `{"ok":true}`

## Disabling Notifications

If `BOT_INTERNAL_TOKEN` is not set in `root/.env`, job notifications are silently skipped (no error).
If `BOT_INTERNAL_TOKEN` is not set in `bot/.env`, the notification endpoint returns 403 Forbidden.

## Security Notes

- The `BOT_INTERNAL_TOKEN` is a simple shared secret. For production, consider adding TLS (HTTPS).
- The endpoint only listens on `127.0.0.1` (localhost), so it's not exposed to the network.
- Each Telegram message is only sent to the authorized `TELEGRAM_USER_ID`.
