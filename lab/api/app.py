from fastapi import FastAPI

app = FastAPI(title="Lab Platform")


@app.get("/health")
def health():
    return {"status": "ok"}
