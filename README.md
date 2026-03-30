# Xiaomi Unlock Assistant (Diagnostic Pack)

Production-focused diagnostic tool for Mi Unlock bind failures.

This package includes:
- `xiaomi_unlock_assistant.py`
- this `README.md`

## What this tool does

- Event-driven `logcat` capture for bind failures
- Host network checks (DNS/TLS/latency)
- Classifier + decision engine with layer priority
- History/trend-aware diagnosis
- Policy overrides for authoritative server truth
- Human-readable explainability in reports

This tool is diagnostic-only. It does **not** unlock devices and does **not** bypass Xiaomi policies.

## Requirements

- Linux shell
- Python 3.10+
- `adb` in `PATH`
- Authorized Android device connected

## File location

Current package path:

`/home/andrew/Загрузки/xiaomi_unlock_assistant_pack`

## Quick start

```bash
python3 '/home/andrew/Загрузки/xiaomi_unlock_assistant_pack/xiaomi_unlock_assistant.py' diagnose-bind
```

## Useful examples

### 1) Basic event-driven run

```bash
python3 '/home/andrew/Загрузки/xiaomi_unlock_assistant_pack/xiaomi_unlock_assistant.py' diagnose-bind
```

### 2) Longer capture window (default is already +20s, now 140s)

```bash
python3 '/home/andrew/Загрузки/xiaomi_unlock_assistant_pack/xiaomi_unlock_assistant.py' diagnose-bind --duration 180
```

### 3) Control arming countdown after pressing Enter

```bash
python3 '/home/andrew/Загрузки/xiaomi_unlock_assistant_pack/xiaomi_unlock_assistant.py' diagnose-bind --arm-countdown 5
```

Disable countdown:

```bash
python3 '/home/andrew/Загрузки/xiaomi_unlock_assistant_pack/xiaomi_unlock_assistant.py' diagnose-bind --arm-countdown 0
```

### 4) Compact one-line output

```bash
python3 '/home/andrew/Загрузки/xiaomi_unlock_assistant_pack/xiaomi_unlock_assistant.py' diagnose-bind --minimal
```

### 5) Save reports

```bash
python3 '/home/andrew/Загрузки/xiaomi_unlock_assistant_pack/xiaomi_unlock_assistant.py' diagnose-bind --save --json --save-logcat
```

### 6) Disable colors

```bash
python3 '/home/andrew/Загрузки/xiaomi_unlock_assistant_pack/xiaomi_unlock_assistant.py' diagnose-bind --no-color
```

### 7) Enable optional phone-side network checks

```bash
python3 '/home/andrew/Загрузки/xiaomi_unlock_assistant_pack/xiaomi_unlock_assistant.py' diagnose-bind --phone-net-check
```

### 8) Local built-in self-checks (no CLI changes required)

```bash
XIAOMI_ASSISTANT_SELF_CHECK=1 python3 '/home/andrew/Загрузки/xiaomi_unlock_assistant_pack/xiaomi_unlock_assistant.py'
```

## Key diagnosis labels

- `REAL_SERVER_MAINTENANCE`
- `REAL_RATE_LIMIT`
- `SERVER_DEGRADATION`
- `SERVER_SILENT_DROP`
- `NETWORK_DISTORTION`
- `UNLOCK_AUTHORIZATION_REQUIRED`
- `POSSIBLE_SERVER_RATE_LIMIT`

## Timing controls (important)

- `--duration`: total capture time limit
- `--pre-seconds`: pre-trigger ring buffer
- `--post-seconds`: post-trigger context
- `--arm-countdown`: visible countdown after Enter

All of these can be tuned per run.

## Help

```bash
python3 '/home/andrew/Загрузки/xiaomi_unlock_assistant_pack/xiaomi_unlock_assistant.py' diagnose-bind --help
```

