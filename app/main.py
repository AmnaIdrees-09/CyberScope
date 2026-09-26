from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI
from app.api.investigate import router as investigate_router

app = FastAPI(title="CyberScope API", version="0.1.0")

app.include_router(investigate_router, prefix="/api")

@app.get("/")
def root():
    return {"message": "CyberScope API is running"}
from fastapi import FastAPI
from app.api.investigate import router as investigate_router

app = FastAPI(title="CyberScope API", version="0.1.0")

app.include_router(investigate_router, prefix="/api")

@app.get("/")
def root():
    return {"message": "CyberScope API is running"}