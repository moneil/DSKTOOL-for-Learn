# Dockerfile

FROM python:latest

# copy source and install dependencies
RUN mkdir -p /dsktool
WORKDIR /dsktool
COPY . /dsktool
RUN pip install --no-cache-dir -r requirements.txt

RUN ls -a

# start server
EXPOSE 8000

#CMD ["python", "manage.py", "runserver"]
CMD ["gunicorn", "--bind", ":8000", "--workers", "3", "dsktool.wsgi:application"]
