"""FastAPI application."""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from api.routes import dns, traffic, threat, dashboard, auth, users

app = FastAPI(
    title="Network Traffic DNS Logger API",
    description="API for network traffic monitoring and DNS logging",
    version="1.0.0"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify actual origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth.router)
app.include_router(users.router)
app.include_router(dns.router)
app.include_router(traffic.router)
app.include_router(threat.router)
app.include_router(dashboard.router)


@app.get("/")
async def root():
    """Root endpoint."""
    return {"message": "Network Traffic DNS Logger API", "version": "1.0.0"}


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy"}

