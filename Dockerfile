# Start with the official Python image.
FROM python:3.11-slim as base

# Set a non-root user
RUN adduser --disabled-password --gecos '' appuser && chown -R appuser /opt

# Set a working directory
WORKDIR /opt/app

# Copy over the application files to the working directory
COPY --chown=appuser:appuser /tmp/repo_989532492_46a312e1 /opt/app

# Switch to the non-root user
USER appuser

# Install any dependencies if requirements.txt were present
# RUN pip install --no-cache-dir -r requirements.txt

# Environment variables
ENV MODEL_PATH=/opt/app/models LOG_LEVEL=info

# Expose necessary ports (if any; not exposing since not specified)
# EXPOSE 80

# Default command (replace with actual entry point)
CMD ["python", "app.py"]