from app.api.explain import explain_router

# from app.api.stats.pypi import pypi_router
from fastapi import FastAPI, Response
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

app.add_middleware(CORSMiddleware, allow_origins=["*"])

# app.include_router(pypi_router, prefix="/api/stats/pypi")
app.include_router(explain_router, prefix="/api/explain")


@app.head("/")
def health_check_head():
    return Response(status_code=200)


@app.get("/health")
def health_check():
    return {"status": "healthy"}
