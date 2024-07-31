# Set the starting image
FROM python:3.12

# Copy over the needed folders
COPY ./app.py /app/app.py
COPY ./controller.py /app/controller.py
COPY ./demo.py /app/demo.py
COPY ./requirements.txt /app/requirements.txt
# Copy over the needed files
COPY ./clamav /app/clamav
COPY ./src /app/src

# Set the working directory
WORKDIR /app

# Install al the python requirements
RUN pip install --no-cache-dir -r requirements.txt

# Install the required linux programs
RUN apt-get update && apt-get install -y \
    clamav-daemon \
    wget \
    socat \
    && rm -rf /var/lib/apt/lists/*

# Set the entrypoint
ENTRYPOINT [ "python" ]

# Start the flask server
CMD [ "app.py" ]


# This program has been developed by students from the bachelor Computer Science at Utrecht University within the Software Project course.
# © Copyright Utrecht University (Department of Information and Computing Sciences)
