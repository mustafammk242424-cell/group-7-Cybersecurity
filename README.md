# [03CIT4067] Cybersecurity Project - Group 7

## 🛡️ Project Overview
**Design and Implementation of a Web Application Security Risk Detection and Remediation Demonstration System Based on OWASP Top 10.**

This repository documents Group 7's deliverables, lab evidence, and hybrid inspection tooling (**PySec-Hybrid Inspector V2**) for the `03CIT4067` Cybersecurity Project (Topic 15), covering OWASP Top 10 risk verification and remediation validation in isolated lab environments.

## 💻 Core Technologies
- **Backend:** Python Flask (Custom Modules & Remediation Middleware)
- **Inspection Engine:** Python (`PySec-Hybrid Inspector V2` — Passive Header Audit, Active SQLi Probe, Fail-Closed Resilience Check)
- **Target Application:** OWASP Juice Shop & Local Flask Hardened Endpoints
- **Environment:** Docker Deployment & Isolated VirtualBox / Local Lab (`127.0.0.1`)

## 👥 Team Members
- **Max Wong** (Team Leader)
- **Muhammad Mustafa Khan**
- **Zou Tao**

## 📂 Folder Structure & Rename History

### Current Repository Structure
- `3-in-1-Inspection-Tool-and-Results/` — **PySec-Hybrid Inspector V2** source code, unit/self-check script, and Before/After execution reports (`.json` and `.txt`) for OWASP Juice Shop (`:3000`) and Flask hardened target (`:5000`).
- `Week5~Week7/` — Renamed from the legacy `CyberProject/` folder; contains earlier phase reports, weekly progress files, reference notes, and supporting screenshots (`Chapter5_Images/`, `Python/`, etc.).
- `[03CIT4067]_Week_9_Progress_Update_&_Phase_3_Deliverables_Group_7.../` — Week 9 progress and Phase 3 related deliverables.
- `[03CIT4067]_Week_11_Progress_Update_&_Phase_2_Deliverables_Group_7.../` — Week 11 progress and Phase 2 related deliverables.

### Naming & Migration Summary (Renames)
- **`CyberProject/` → `Week5~Week7/`**: Renamed the existing folder to reflect historical Week 5–7 materials and keep legacy deliverables separated from the consolidated 3-in-1 testing artifacts.
- **Added `3-in-1-Inspection-Tool-and-Results/`**: Created a dedicated English-named directory at the repository root to store `pysec_hybrid_inspector_v2.py`, `test_inspector_self_check.py`, `kali_juiceshop_3000.json`, `kali_juiceshop_3000_report.txt`, `kali_flask_5000.json`, and `kali_flask_5000_report.txt` cleanly without spaces or encoding issues.
- **Note on Legacy Reference (`[03CIT4067]_CyberProject/`)**: Earlier draft notes referenced `[03CIT4067]_CyberProject/`; in this repository, that legacy folder was renamed to `Week5~Week7/` while active 3-in-1 inspection artifacts reside in `3-in-1-Inspection-Tool-and-Results/`.
