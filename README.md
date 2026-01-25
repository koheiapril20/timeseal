# timeseal

A command-line tool for creating delay-sealed data bundles. Data sealed with timeseal cannot be recovered instantly—even by the creator—without completing a predetermined amount of sequential computation.

## Overview

timeseal uses a chained Argon2id key derivation function (DelayKDF) to enforce a computational delay before data can be unlocked. This approach ensures that:

- Lock strength is defined by **difficulty** (work units), not wall-clock time
- No third parties or online services are required
- The delay cannot be bypassed through parallelization

## Installation

```bash
git clone https://github.com/koheiapril20/timeseal.git
cd timeseal
make build
```

## Usage

### 1. Benchmark your machine

```bash
timeseal bench
```

Measures how long `difficulty=1` takes on your hardware.

### 2. Estimate appropriate difficulty

```bash
timeseal calibrate --target=1d
```

Suggests a difficulty value corresponding roughly to the target duration (e.g., `1h`, `12h`, `1d`, `7d`).

### 3. Seal data

```bash
timeseal seal --difficulty=90000 secret.txt -o bundle.tsl
```

For files larger than 64 KiB, an external payload file (`bundle.tsl.payload`) is created automatically.

### 4. Unlock data

```bash
timeseal unlock bundle.tsl -o secret.txt
```

The unlock process requires completing the full sequential computation.

### 5. Inspect a bundle

```bash
timeseal info bundle.tsl
```

Displays metadata without unlocking.

## Command Reference

| Command | Description |
|---------|-------------|
| `bench` | Benchmark local machine performance |
| `calibrate` | Suggest difficulty for a target duration |
| `seal` | Seal data with delay-based encryption |
| `unlock` | Recover sealed data after computation |
| `info` | Display bundle metadata |

## Technical Details

- **DelayKDF**: Chained Argon2id (256 MiB memory, sequential rounds)
- **Encryption**: ChaCha20-Poly1305 (AEAD)
- **Integrity**: SHA-256 for external payloads
- **Bundle format**: JSON with base64-encoded binary fields

## Disclaimer

THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NONINFRINGEMENT.

**By using this software, you acknowledge and agree that:**

1. **No Guarantee of Security**: While this tool implements cryptographic primitives, the author makes no claims regarding its suitability for any particular security purpose. The software has not undergone formal security audits.

2. **Risk of Data Loss**: Sealed data can only be recovered by completing the required computation. If you lose the bundle file, forget the difficulty parameters, or encounter hardware/software failures during the unlock process, **your data may be permanently unrecoverable**. The author assumes no responsibility for any data loss.

3. **Time Estimates Are Approximate**: The `calibrate` command provides rough estimates only. Actual unlock times depend on hardware, system load, and other factors beyond the author's control.

4. **Your Sole Responsibility**: You are solely responsible for evaluating whether this tool is appropriate for your use case, maintaining backups, and accepting all risks associated with its use.

5. **No Liability**: In no event shall the author be liable for any claim, damages, or other liability arising from the use of this software.

**Use at your own risk. Review the source code and understand the implications before relying on this tool for any purpose.**

## License

MIT License
