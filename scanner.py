
#tempstorage
import os
import uuid
import shutil

TEMP_DIR = "temp_uploads"
SAFE_DIR = "safe_storage"

def save_to_temp(uploaded_file_path):
    temp_name = str(uuid.uuid4())
    temp_path = os.path.join(TEMP_DIR, temp_name)

    shutil.copy(uploaded_file_path, temp_path)
    return temp_path


#fileTypeCheck
import magic

ALLOWED_MIME = {
    "application/pdf",
    "image/png",
    "text/plain",
    "image/jpeg"
}

def validate_mime(file_path):
    mime = magic.from_file(file_path, mime=True)
    if mime not in ALLOWED_MIME:
        raise Exception(f"Blocked MIME type: {mime}")


#hashGerneration
import hashlib

def sha256_hash(file_path):
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


#hashlookup
import requests
from config import VT_API_KEY

def virustotal_hash_scan(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VT_API_KEY}

    r = requests.get(url, headers=headers)

    if r.status_code == 404:
        return "UNKNOWN"

    data = r.json()
    stats = data["data"]["attributes"]["last_analysis_stats"]

    if stats["malicious"] > 0:
        raise Exception("VirusTotal: Malicious file detected")

    return "CLEAN"


#antivirusScan
import subprocess

def clamav_scan(file_path):
    result = subprocess.run(
        ["clamscan", "--infected", "--no-summary", file_path],
        capture_output=True
    )

    if result.returncode == 1:
        raise Exception("ClamAV: Malware detected")

    if result.returncode == 2:
        raise Exception("ClamAV: Scan error")


#permaStorage
def move_to_safe_storage(file_path, original_ext):
    safe_name = f"{uuid.uuid4()}{original_ext}"
    safe_path = os.path.join(SAFE_DIR, safe_name)

    shutil.move(file_path, safe_path)
    os.chmod(safe_path, 0o600)

    return safe_path


#pipeline
def full_scan_pipeline(uploaded_file_path, original_ext):
    temp_path = save_to_temp(uploaded_file_path)

    try:
        validate_mime(temp_path)

        file_hash = sha256_hash(temp_path)
        print("SHA256:", file_hash)

        vt_result = virustotal_hash_scan(file_hash)
        print("VirusTotal:", vt_result)

        clamav_scan(temp_path)
        print("ClamAV: CLEAN")

        # sandbox_execute(temp_path)  # enable only in lab

        safe_path = move_to_safe_storage(temp_path, original_ext)
        print("Stored safely at:", safe_path)

    except Exception as e:
        os.remove(temp_path)
        print("BLOCKED:", e)







