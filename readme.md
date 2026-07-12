# EvidenceGuard

## Overview

EvidenceGuard is a Digital Forensics Incident Response (DFIR) tool designed to protect digital evidence from unauthorized modification, deletion, or tampering during forensic investigations.

The application continuously monitors a selected evidence directory and automatically restores original files from a secure backup whenever unauthorized changes are detected.

---

## Features

- Real-time monitoring using Watchdog.
- Automatic restoration of deleted evidence files.
- Detection of file modifications using SHA-256 hashing.
- Automatic recovery of modified files.
- Protection against unauthorized file creation.
- Event logging inside the graphical interface.
- Live statistics:
  - Detected Modifications
  - Restored Files
- Emergency Kill Switch (F12).
- Simple GUI built with Tkinter.

---

## Technologies Used

- Python 3.x
- Watchdog
- Tkinter
- hashlib
- threading
- shutil
- os

---

## Installation

Install the required packages:

```bash
pip install watchdog
```

---

## Running the Program

Execute:

```bash
python EvidenceGuard.py
```

or

```bash
python main_fixed.py
```

---

## How It Works

1. Select the evidence folder.
2. The application creates a secure backup.
3. SHA-256 hashes are generated for every file.
4. Real-time monitoring begins.
5. If any file is:

- Modified
- Deleted
- Renamed
- Replaced

EvidenceGuard immediately restores the original copy.

---

## Project Structure

```
EvidenceGuard/
│
├── EvidenceGuard.py
├── icon.png
├── logo.png
├── README.md
└── requirements.txt
```

---

## Security Mechanisms

- SHA-256 Integrity Verification
- Automatic Backup
- Automatic File Recovery
- Continuous File Monitoring
- Evidence Tampering Detection

---

## Interface

The GUI displays:

- Protection Status
- Event Logs
- Number of detected modifications
- Number of restored files

---

## Emergency Stop

Press:

```
F12
```

to immediately stop monitoring and safely exit the application.

---

## Limitations

- Windows environment only.
- Local file monitoring only.
- Administrator privileges may be required for some protected folders.

---

## Future Improvements

- Recursive folder integrity database.
- SQLite hash database.
- PDF forensic reports.
- Email alerts.
- Multi-directory monitoring.
- Export logs to CSV.
- AES encrypted backup.
- Digital signature verification.

---

## Author

Ajlan Al Shammari

---

## License

This project is intended for educational and Digital Forensics research purposes.
