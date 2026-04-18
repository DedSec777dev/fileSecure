from fastapi import FastAPI, File, UploadFile, HTTPException
import shutil
import os

from scanner import full_scan_pipeline

app = FastAPI()

UPLOAD_TMP = "incoming"

os.makedirs(UPLOAD_TMP, exist_ok=True)

@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    temp_input_path = os.path.join(UPLOAD_TMP, file.filename)

    # Save incoming file temporarily
    with open(temp_input_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    try:
        # 🔐 THIS RUNS EVERYTHING AUTOMATICALLY
        full_scan_pipeline(
            uploaded_file_path=temp_input_path,
            original_ext=os.path.splitext(file.filename)[1]
        )

        return {"status": "success", "message": "File accepted & secured"}

    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    finally:
        if os.path.exists(temp_input_path):
            os.remove(temp_input_path)
