import uvicorn

if __name__ == "__main__":
    uvicorn.run("threatgen.app:app", host="127.0.0.1", port=8899, reload=True, log_level="info")
