FROM python:3

WORKDIR /
RUN mkdir /app
WORKDIR /app

COPY ./ /app

RUN pip install -r requirements.txt

EXPOSE 8000

CMD uvicorn main:app --reload --host 0.0.0.0