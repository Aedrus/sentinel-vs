# This dockerfile defines the blueprint for building a docker image.
# Docker Images can be found on the Docker Desktop app.
# ===================================================
 
# Language Version
FROM python:3.9

# SRC file
ADD src/app.py .

# Install libraries
RUN pip install python-dotenv
RUN pip install zaproxy
RUN python -m pip install rich
RUN pip install beautifulsoup4


# Executes commands in container
CMD [ "python", "./src/app.py" ]