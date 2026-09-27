from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.investigate import router as investigate_router

app = FastAPI(title="CyberScope API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(investigate_router, prefix="/api")

@app.get("/")
def root():
    return {"message": "CyberScope API is running"}