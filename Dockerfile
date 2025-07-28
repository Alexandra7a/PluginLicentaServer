# Use a minimal base image for Python
FROM python:3.11-slim-bullseye AS base

# Set a non-root user for security
RUN useradd -m appuser

# Set the working directory
WORKDIR /app

# Copy only the requirements file to leverage Docker cache
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . .

# Change to the non-root user
USER appuser

# Command to run the application
CMD ["python", "app.py"]