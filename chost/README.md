## Installation on cPanel: ##

1. Create dsktool directory in the home folder in the cPanel

2. Upload DskTool files to the dsktool directory

3. Make backup of the dsktool/dsktool/wsgi.py file as it will be overwritten in the process

4. Update/create config.py file with all the values
    * Update allowed hosts with your site URI!

5. Create Python app (cPanel option)
    * Set version to 3.8.6
    * App root: dsktool
    * App URL no change
    * App start up file: dsktool/wsgi.py
    * App entry point: application
    * Passenger log file is optional
    * Click on CREATE button
    * Stop the app - click on STOP APP button

6. Update wsgi.py file as the cpanel overwrites it with its own data

7. Go to virtual env: run in the terminal the command dispalyed at the top (example: source /home/dsktooltest/virtualenv/dsktool/3.8/bin/activate && cd /home/dsktooltest/dsktool)

8. Run: pip install --no-cache-dir -r requirements.txt

9. Run: python manage.py migrate

10. Run: python manage.py collectstatic

11. Start the app: press START APP button

12. Follow the instruction to set up Blackboard Learn

NOTE: 
  Disable (or add an exception) all ad-blockers plugins (ghostery, uBlock etc) in your browser.