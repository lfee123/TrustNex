# simple Dockerfile for TrustNex Flask application

# use a lightweight Python base image
FROM python:3.11-slim

# set working directory
WORKDIR /app

# copy requirements and install dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# copy application code
COPY . ./

# expose default flask port
EXPOSE 5000

# environment variables (can be overridden by docker run or compose)
ENV FLASK_APP=app.py
ENV FLASK_ENV=production

# entrypoint
CMD ["flask", "run", "--host=0.0.0.0"]
