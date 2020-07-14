FROM python:3

ENV TZ=Asia/Shanghai

RUN set -ex
ENV DOMAIN vultest.com
ENV LOCALIP 127.0.0.1

RUN sed -i "s@http://deb.debian.org@https://repo.huaweicloud.com@g" /etc/apt/sources.list
RUN sed -i "s@http://security.debian.org@https://repo.huaweicloud.com@g" /etc/apt/sources.list
RUN apt-get update -y && apt-get dist-upgrade -y && apt-get autoremove -y

ADD pip.conf /root/.pip/pip.conf
ADD requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt

ADD template.html /app/template.html
ADD vtest.py /app/vtest.py
RUN export PASSWORD=$(python -c "import random,string;print(''.join([random.choice(string.ascii_letters) for _ in range(32)]).encode());")

CMD ["sh", "-c", "cd /app && echo $DOMAIN $LOCALIP $PASSWORD && /usr/local/bin/python vtest.py -d \"$DOMAIN\" -h \"$LOCALIP\" -p \"$PASSWORD\""]
