FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1

ARG USER=user
ARG WORKDIR=/wd
ARG GECKODRIVER_VERSION=0.34.0

RUN apt-get update && apt-get install --yes

WORKDIR ${WORKDIR}

# [user]-[BEGIN]
#   -S: system group/user
#   -G: Group
RUN addgroup --system ${USER} &&\
    adduser --system ${USER} --ingroup ${USER} --no-create-home &&\
    chown --recursive ${USER} ${WORKDIR}
# [user]-[END]

ARG GECKOARCHIVE_NAME=geckodriver-v${GECKODRIVER_VERSION}-linux64.tar.gz
# Download and install geckodriver
RUN apt-get install --yes wget &&\
    wget https://github.com/mozilla/geckodriver/releases/download/v${GECKODRIVER_VERSION}/${GECKOARCHIVE_NAME} &&\
    tar -xvzf ${GECKOARCHIVE_NAME} &&\
    mv geckodriver /usr/bin/ &&\
    chmod +x /usr/bin/geckodriver &&\
    rm ${GECKOARCHIVE_NAME} &&\
    apt-get remove --yes wget &&\
    apt-get autoremove --yes

# Download and install firefox
RUN apt-get install --yes firefox-esr


COPY --chown=${USER} requirements.txt .

RUN pip install pip --upgrade &&\
    pip install --requirement requirements.txt


COPY --chown=${USER} . .

# TODO: Fix user. It is better to use a non-root user
#USER ${USER}

ENTRYPOINT ["python", "xssrecon.py"]




