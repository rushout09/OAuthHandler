FROM tiangolo/uvicorn-gunicorn-fastapi:python3.9

WORKDIR /code

COPY ./requirements.txt /code/requirements.txt

COPY ./firebase_config.json /code/firebase_config.json

COPY ./.env /code/.env

RUN pip install --no-cache-dir --upgrade -r /code/requirements.txt

COPY ./app /code/app

CMD ["gunicorn", "app.main:app", "--workers", "4", "--worker-class", "uvicorn.workers.UvicornWorker", "--bind", "127.0.0.1:8000"]
