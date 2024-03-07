FROM python:3

WORKDIR /home/samt/SSH-Honeypot/basic_ssh_honeypot/

# set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# install dependencies
RUN pip3 install --upgrade pip
COPY ./requirements.txt .
RUN pip3 install -r requirements.txt

COPY . .

CMD ["basic_ssh_honeypot.py","-p","2222"]
ENTRYPOINT ["python3"]


# Install dependencies
RUN pip3 install paramiko==2.6.0 six

# Expose the port used by your script
EXPOSE 2222