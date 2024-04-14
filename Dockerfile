# Use an official Python runtime as a parent image
FROM python:3.10.12

# Metadata indicating an image maintainer
LABEL maintainer="Itamar Naor Roy"

# Set the working directory inside the container
WORKDIR /app

# Copy the Python application files into the container
COPY . .

# Copy data.csv from the current directory into the container
COPY daTa.csv /app/


# Install Python dependencies
RUN pip install --no-cache-dir --user -r requirements.txt && \
    pip install --no-cache-dir --user flask && \
    python -m nltk.downloader stopwords && \
    python -m nltk.downloader wordnet

# Make port 5000 available to the world outside this container
EXPOSE 5000

# Define environment variable
#ENV FLASK_APP=prediction.py

# Run the Python application
CMD ["python", "prediction.py"]
