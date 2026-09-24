from app.api.stats.pypi import pypi_router
from fastapi import FastAPI, Response
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

app.add_middleware(CORSMiddleware, allow_origins=["*"])

app.include_router(pypi_router, prefix="/stats/pypi")


@app.head("/")
def health_check_head():
    return Response(status_code=200)


@app.get("/health")
def health_check():
    return {"status": "healthy"}
