# Use an official Python runtime as a parent image
FROM python:3.10.12

# Metadata indicating an image maintainer
LABEL maintainer="roy naor itamar"

# Set the working directory to /app inside the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app/

# Optionally, copy requirements.txt and install Python dependencies
# Note: Ensure you have a requirements.txt in your Malicious_n_Non-Malicious-URL directory
RUN pip install --no-cache-dir -r requirements.txt

# Make the predication script executable (if necessary)
RUN chmod +x predication.py

# No need to expose a port unless your script starts a web server
# EXPOSE 80

# Run predication.py when the container launches
CMD ["python", "predication.py"]
