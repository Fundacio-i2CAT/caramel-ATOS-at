FROM python:3.8-alpine3.12

RUN apk update &&\
    apk upgrade &&\
    apk add bash bash-doc bash-completion
ADD src/requirements.txt /requirements.txt
RUN pip install -r /requirements.txt

ADD src/ /src
ENTRYPOINT [ "python","-u", "/src/atos_at.py" ]