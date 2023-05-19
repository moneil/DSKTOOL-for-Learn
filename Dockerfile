# Multistage docker build for Python containers

# -------------- Python Build ---------------
# NOTE: Any modifications here will not appear in the final container.
FROM python:latest as build

# set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Download required packages as wheels and build the wheels for libraries that don't have one on PyPi.
WORKDIR /build
COPY ./requirements.txt requirements.txt
RUN mkdir wheels && \
    pip wheel \
        --wheel-dir wheels \
        --requirement requirements.txt

# -------------- Python DSKTOOL App --------------
# NOTE: Any modifications here will appear in the final container.
FROM python:slim

# Set the user who will run the app
ARG USER=dsktool
ARG HOME=/home/${USER}
RUN addgroup --gid 1000 ${USER} &&\
    adduser --uid 1000 --gid 1000 --disabled-login --disabled-password --home ${HOME} --gecos "" ${USER}

# Copy source, python wheels and install dependencies
WORKDIR ${HOME}
COPY --from=build /build/wheels wheels
COPY . app
RUN pip install \
        --no-cache-dir \
        --no-index \
        --find-links wheels \
        --requirement app/requirements.txt && \
    chown -R ${USER}:${USER} ${HOME}/app

# Start server
WORKDIR ${HOME}/app
EXPOSE 8000
USER ${USER}
# CMD ["python", "manage.py", "runserver"]
CMD ["gunicorn", "--bind", ":8000", "--workers", "3", "dsktool.wsgi:application"]
