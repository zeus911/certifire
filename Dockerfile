FROM ubuntu

ARG VERSION
#ARG DB
ENV VERSION master
ENV VIRTUAL_ENV=/home/certifire/certifire
ENV PATH="$VIRTUAL_ENV/bin:$PATH"
#ENV DB=${DB}

ENV TZ=Asia/Kolkata
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

RUN apt update
RUN apt upgrade -y
RUN apt install -y python3-dev python3-pip python3-virtualenv libpq-dev build-essential libssl-dev libffi-dev
RUN useradd -m -s /bin/bash -G sudo -c "Certifire API Server" certifire
RUN echo "certifire:certifire" | chpasswd

COPY . ${VIRTUAL_ENV}
WORKDIR ${VIRTUAL_ENV}

RUN pip3 install -U virtualenv
RUN virtualenv -p python3 .
RUN pip install --upgrade pip
RUN pip install -r requirements.txt
RUN python setup.py install
# RUN echo "changeme" | certifire-manager init

WORKDIR /home/certifire
USER certifire
ENTRYPOINT ["/home/certifire/certifire/docker-entrypoint.sh"]
CMD ["certifire-manager","runserver"]
