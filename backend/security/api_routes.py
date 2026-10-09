from fastapi import APIRouter, File, HTTPException, UploadFile

from .api_analysis import analyze_explicit_file

router = APIRouter(prefix="/security", tags=["Security Analysis"])

MAX_UPLOAD_BYTES = 2 * 1024 * 1024


@router.post("/analyze-file")
async def analyze_file(file: UploadFile = File(...)):
    try:
        content = await file.read(MAX_UPLOAD_BYTES + 1)

        if len(content) > MAX_UPLOAD_BYTES:
            raise HTTPException(
                status_code=413,
                detail="File is too large. Maximum upload size is 2 MB.",
            )

        if not content:
            raise HTTPException(
                status_code=400,
                detail="Uploaded file is empty",
            )

        return analyze_explicit_file(
            file_name=file.filename or "uploaded_file",
            content=content,
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc
