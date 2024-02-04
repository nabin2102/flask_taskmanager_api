# Use an official Python runtime as a parent image
FROM python:3.11.4-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Set the working directory in the container
WORKDIR /app

# Copy the dependencies file to the working directory
COPY requirements.txt .

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install gunicorn

# Copy the rest of the application code to the working directory
COPY . .

# Run Gunicorn with 4 worker processes
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "app:app"]
