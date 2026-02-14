# CTF Platform — Local Network

A self-contained Capture The Flag platform for LAN competitions.  
Built with Flask, SQLite, and Jinja2.

## Quick Start

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Set environment variables

**Linux / macOS:**
```bash
export SECRET_KEY="something_random_and_long"
export ADMIN_PASSWORD="supersecretadmin"
```

**Windows (PowerShell):**
```powershell
$env:SECRET_KEY = "something_random_and_long"
$env:ADMIN_PASSWORD = "supersecretadmin"
```

**Windows (CMD):**
```cmd
set SECRET_KEY=something_random_and_long
set ADMIN_PASSWORD=supersecretadmin
```

### 3. Run the server

```bash
python app.py
```

The server starts on `http://0.0.0.0:5000` (all network interfaces).

## How Participants Connect

Participants on the same LAN should open their browser to:

```
http://<HOST_LOCAL_IP>:5000
```

Replace `<HOST_LOCAL_IP>` with the machine's local IP address.

### Finding the Host IP:

**Windows:**
1. Open Command Prompt (`cmd`) or PowerShell.
2. Type `ipconfig` and press Enter.
3. Look for **IPv4 Address** under your active adapter (e.g., Wi-Fi or Ethernet).

**Linux / macOS:**
1. Open Terminal.
2. Type `ip addr` or `ifconfig`.
3. Look for the IP address (usually `inet 192.168.x.x` or `10.x.x.x`).

**Firewall Note:**
Ensure your firewall allows incoming connections on port `5000` (TCP). if participants cannot connect, try temporarily disabling the firewall to test.

## Features

| Feature | Description |
|---|---|
| **Player Auth** | Registration + login with hashed passwords |
| **Dashboard** | Score, rank, challenge list, flag submission |
| **Leaderboard** | Public, sorted by score (tiebreak: earliest solve) |
| **Flag Engine** | SHA-256 hashed flags, one-solve-per-challenge |
| **Rate Limiting** | Max 5 flag submissions per minute per user |
| **Admin Panel** | Manage challenges, users, scores, view all logs |
| **Login Auditing** | IP + success/failure logged for every login |

## Admin Panel

Navigate to `/admin/login` and authenticate with `ADMIN_PASSWORD`.

From the admin dashboard you can:
- View full leaderboard, users, submissions, and login logs
- Add new challenges (flags are hashed on save)
- Manually adjust user scores

## Security Notes

- Passwords hashed with `werkzeug.security` (PBKDF2)
- Flags stored as SHA-256 hashes — never plaintext
- All SQL queries are parameterized (no string formatting)
- Session cookies are HttpOnly + SameSite=Lax
- Debug mode is **OFF**
- Admin uses a separate session key from players
- No stack traces exposed to users
