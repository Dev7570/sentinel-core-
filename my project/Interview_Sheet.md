# Interview Preparation Sheet: Sentinel-Core AV

This document serves as a comprehensive guide to the **Sentinel-Core AV** project, designed to help you confidently handle technical and architectural questions during an interview.

---

## 🚀 1. Project Journey: From Scratch to End

Building Sentinel-Core AV was an iterative process focused on creating a premium, high-performance security tool.

1.  **Phase 1: Conceptualization & Tech Stack Selection**
    *   Goal: Create a cross-platform, modern antivirus with a focus on USB security.
    *   Choice: **Electron** for the desktop environment, **Node.js** for deep system integration, and **Vanilla CSS** for a premium, high-performance UI.

2.  **Phase 2: Core Engine Development (The "Brain")**
    *   Developed the `Scanner` engine with support for asynchronous file tree traversal.
    *   Implemented the `Arbiter` logic—a weighted scoring system to evaluate multiple detection signals (Signatures, YARA, Heuristics, and Cloud).

3.  **Phase 3: Real-time Protection & USB Monitoring**
    *   Integrated `chokidar` for low-latency file system watching.
    *   Developed the `UsbMonitor` to detect hardware events and trigger immediate "interception scans."

4.  **Phase 4: Advanced Security Features**
    *   Added a **Quarantine Vault** for safe file isolation.
    *   Implemented the **Honeypot (Canary)** system to detect ransomware activity via hidden "tripwire" files.

5.  **Phase 5: UI/UX Refinement & Packaging**
    *   Built a dynamic, interactive dashboard with real-time stats.
    *   Configured `electron-builder` and `electron-updater` for professional distribution and auto-updates.

---

## 🛠️ 2. Technical Stack

*   **Runtime:** Node.js (v20+) & Electron (v33).
*   **Frontend:** HTML5, CSS3 (Advanced animations, CSS variables for theming), JavaScript (ES6+).
*   **Database:** `sql.js` (SQLite) for high-speed, local storage of threat signatures and scan history.
*   **Security Engines:**
    *   **Signature Engine:** Fast MD5/SHA-256 hash matching.
    *   **YARA:** Pattern matching for structural analysis.
    *   **Heuristics:** Behavioral analysis (e.g., detecting double extensions, suspicious headers).
    *   **VirusTotal API:** Cloud-orchestrated multi-engine consensus.

---

## ⚙️ 3. Core Operations & Features

| Feature | Description | Technical Implementation |
| :--- | :--- | :--- |
| **Multi-Engine Scan** | Full system or targeted folder scans. | `scanner.js` + `Arbiter` scoring. |
| **USB Protection** | Instant scan when a USB is plugged in. | `usb-monitor.js` using Node `disk-usage` or `wmic`. |
| **Real-time Watcher** | Background monitor for newly created files. | `chokidar` watching root/user directories. |
| **Ransomware Canary** | Detecting encryption attacks. | Hidden `.canary` files monitored by `honeypot.js`. |
| **Quarantine** | Safe isolation of malware. | AES-like obfuscation/restricting permissions on moved files. |
| **Game Mode** | Zero-interruption protection. | Throttling background scans during high CPU/GPU usage. |

---

## 🧠 4. Architectural Highlights & Key Logic

### The "Arbiter" Weighted Scoring Logic
Instead of relying on a single detection method, Sentinel-Core AV uses a **Weighted Consensus Model**:
*   **Signature Match**: 95% weight (High confidence).
*   **YARA Pattern**: 70% weight (Structural evidence).
*   **Heuristics**: 50% weight (Suspicious behavior).
*   **VirusTotal**: 98% weight (Global consensus).
The `Arbiter` aggregates these into a final score. If `score > 0.7`, the file is marked **MALICIOUS** and auto-quarantined.

### IPC (Inter-Process Communication)
*   The **Main Process** handles node-level tasks (File system, USB events, Database).
*   The **Renderer Process** handles the UI and user interactions.
*   Communication is handled via `ipcMain` and `ipcRenderer` with a `preload.js` script for security (Context Isolation).

---

## ❓ 5. Potential Interview Questions & Answers

### Q: Why did you choose Electron for an antivirus application?
> **Answer:** Electron allowed for a rapid development cycle of a high-fidelity, premium UI using web technologies. By combining it with Node.js, we maintained the ability to perform deep system-level operations like USB monitoring and file system traversal. We addressed performance concerns by moving heavy scanning logic to worker processes or asynchronous chunks to keep the UI fluid.

### Q: How does your application minimize False Positives?
> **Answer:** We implemented the "Arbiter" logic. A single heuristic flag won't quarantine a file. The system requires multiple "red flags" (e.g., a suspicious pattern + a cloud flag + a heuristic anomaly) to escalate a verdict to "Malicious." This multi-layered approach ensures we don't accidentally delete legitimate user files.

### Q: How do you handle large file scans without freezing the UI?
> **Answer:** I used asynchronous recursion and limited the concurrency of file reads. The scanner reports progress via IPC periodically, allowing the UI to remain responsive. We also use a "Watchdog" process to ensure the engine doesn't consume excessive system resources.

### Q: What is the most challenging part of this project?
> **Answer:** Managing the race conditions in real-time monitoring and ensuring the USB auto-scan triggers reliably across different Windows drive configurations. I solved this by implementing a robust event-driven architecture using Node's `EventEmitter`.

### Q: How would you scale this to a cloud-based enterprise solution?
> **Answer:** I would implement a central "Threat Intelligence Center" where local agents (like Sentinel-Core) upload unknown file hashes for sandboxed analysis. I'd also switch the local SQLite database to a synchronized cloud-edge model for global threat updates.

---

## 📈 6. Future Enhancements
*   **AI/ML Integration:** Use TensorFlow.js for local behavioral anomaly detection.
*   **Kernel-Level Driver:** (Advanced) Write a mini-filter driver for even deeper file system protection.
*   **Network Monitoring:** Add a firewall module to block malicious outbound traffic.
