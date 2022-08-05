Full directions coming soon...

See my DSKTool project for instructions.

in brief:
1. clone this project
2. cd into the project directory
3. copy config-template.py to config.py
4. edit config.py with your settings
5. run: virtualenv dsktool -p python3
6. run: source dsktool/bin/activate
7. run: pip install --no-cache-dir -r requirements.txt
8. run: pip install django-extensions Werkzeug
8. run: python manage.py migrate
9. run: python manage.py runserver 
	or 
	python manage.py runserver_plus --cert-file cert.pem --key-file key.pem

You can set up https by following this:
https://timonweb.com/django/https-django-development-server-ssl-certificate/

Notes:

calling BB api general way:

resp = bb.call('GetUser',userId="?userName=" + searchValueUsr, params={'fields':'id, userName, name.given, name.middle, name.family, externalId, contact.email, availability.available, dataSourceId, modified'}, sync=True )

Migrations:
python manage.py makemigrations dsktool
python manage.py migrate   