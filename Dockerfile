FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY main.py teacher_directory.py family_accounts.py entrypoint.py ./
ENV PORT=8000
CMD ["sh", "-c", "uvicorn entrypoint:app --host 0.0.0.0 --port ${PORT:-8000} --workers 1"]
