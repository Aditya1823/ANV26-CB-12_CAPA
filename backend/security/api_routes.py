from fastapi import APIRouter, File, HTTPException, UploadFile

from .api_analysis import analyze_explicit_file

router = APIRouter(prefix="/security", tags=["Security Analysis"])


@router.post("/analyze-file")
async def analyze_file(file: UploadFile = File(...)):
    try:
        content = await file.read()

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
