# fileSecure
File sanitization service
!!!! create a config file with virustotal api key
# 🔐 FileSecure

A secure file upload and validation system built with FastAPI that ensures uploaded files are safe before permanent storage.  
It combines MIME validation, hashing, threat intelligence, and antivirus scanning into a single automated pipeline.

---

## 🚀 Features

- 📂 Secure file upload API using FastAPI  
- 🔍 MIME type validation (prevents malicious file types)  
- 🔑 SHA-256 hash generation for file fingerprinting  
- 🌐 VirusTotal hash lookup for threat intelligence  
- 🦠 ClamAV antivirus scanning  
- 📦 Secure file storage with restricted permissions  
- 🧹 Automatic cleanup of unsafe files  
- ⚡ Fully automated scanning pipeline  

---

## 🛠️ Tech Stack

- **Backend:** Python, FastAPI  
- **Security Tools:**  
  - ClamAV  
  - VirusTotal API  
- **Libraries:**  
  - python-magic  
  - hashlib  
  - requests  

---



### Pipeline Steps

1. Save file to temporary storage  
2. Validate MIME type  
3. Generate SHA-256 hash  
4. Check hash via VirusTotal  
5. Scan file using ClamAV  
6. Move safe file to secure storage  
7. Delete malicious/invalid files  

---



