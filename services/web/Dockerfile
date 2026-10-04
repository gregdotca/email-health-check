###########
# BUILDER #
###########

# pull official base image
FROM python:3.13.16-slim AS builder

# set work directory
WORKDIR /usr/src/app

# set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
# pip runs as root in the build only (the app runs as "app"): its root warning is noise here
ENV PIP_ROOT_USER_ACTION=ignore PIP_DISABLE_PIP_VERSION_CHECK=1

# install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc

# lint
RUN pip install pip==26.2.1
RUN pip install flake8==7.4.1 mccabe==0.7.0 pycodestyle==2.15.0 pyflakes==4.0.2
COPY . .
RUN flake8 --ignore=E501,W503,F401 .

# install python dependencies
COPY ./requirements.txt .
# dkimpy and pyspf only come as source packages: they're built with this pinned setuptools rather than
# whatever version pip would fetch for an isolated build
RUN pip install setuptools==84.0.0
RUN pip wheel --no-cache-dir --no-deps --no-build-isolation --wheel-dir /usr/src/app/wheels -r requirements.txt


#########
# FINAL #
#########

# pull official base image
FROM python:3.13.16-slim

# create directory for the app user
RUN mkdir -p /home/app

ENV PIP_ROOT_USER_ACTION=ignore PIP_DISABLE_PIP_VERSION_CHECK=1

# create the app user
RUN addgroup --system app && adduser --system --group app

# create the appropriate directories
ENV HOME=/home/app
ENV APP_HOME=/home/app/web
RUN mkdir $APP_HOME
WORKDIR $APP_HOME

COPY --from=builder /usr/src/app/wheels /wheels
COPY --from=builder /usr/src/app/requirements.txt .
RUN pip install pip==26.2.1
RUN pip install --no-cache-dir --no-index /wheels/*  # only the pinned wheels, never the index

# copy project
COPY . $APP_HOME

# SQLite volume shared by web and poller
RUN mkdir /data

# chown all the files to the app user
RUN chown -R app:app $HOME /data  # its home (the app is in it) and the database volume

# change to the app user
USER app
