FROM python:3.12

RUN apt-get update && \
    apt-get install -y virt-viewer \
        x11-xserver-utils \
        x11-apps

COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy the directory and its contents into the container
COPY src /usr/src

# Copy the directory to the /etc dir
RUN mv /usr/src/vdiclient /etc/vdiclient

# Make the file executable
RUN chmod +x /usr/src/vdiclient.py

# Set the DISPLAY environment variable
ENV DISPLAY=:0

CMD [ "python", "/usr/src/vdiclient.py" ]