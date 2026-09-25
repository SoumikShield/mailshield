from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from routes.email_routes import router as email_router
from database.mongodb import db


app = FastAPI(
    title="MailShield",
    description="Email Threat Detection & Investigation Platform",
    version="1.0.0"
)


# Allow requests from the deployed MailShield frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://mailshield-nejn.onrender.com"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Register email routes
app.include_router(email_router)


@app.get("/")
def home():
    return {
        "message": "MailShield API is running",
        "status": "online"
    }


@app.get("/health")
def health_check():
    try:
        db.command("ping")

        return {
            "status": "healthy",
            "database": "connected"
        }

    except Exception:
        return {
            "status": "unhealthy",
            "database": "disconnected"
        }