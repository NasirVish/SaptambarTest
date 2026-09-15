import uvicorn
if __name__ == "__main__":
    # CWE-489: debug/reload left on; 0.0.0.0 exposes all interfaces
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
