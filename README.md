# DSKTOOL for Learn DEV v1.2.6 (07/05/2022)

See [Release Notes](#Release-Notes) below.

This project is a Django/Python and Learn REST replacement for the Original York DSK Building Block for Learn.

This project is built to be deployed in a variety of ways:
    
* Heroku: You may read about Heroku here: [https://heroku.com](https://heroku.com). See the Deploy to Heroku button below.
* Docker: You may read about Docker here: [https://www.docker.com](https://www.docker.com/). See this project's  `./docker/README.md` for Docker details.
* cHost: See this project's  `./chost/README.md` for cHost details.
* Localhost: See `./local/README.md` for running on localhost.

The DSKTOOL uses 3LO and as such requires a Learn account and use is restricted based on Learn account privileges.

**Note**: This is an open source community project and, even though I am an employee, *is not supported or sponsored by Blackboard Inc.*. If you find it of value please contribute! Pull requests welcome! Make a fork and share your work back to this project.

# Installation

## Pre-requisites:
You ***must*** have registered an application in your Developer Portal ([https://developer.blackboard.com](https://developer.blackboard.com)) account and added it to your Learn instance. 

NOTE: Make certain to store your Key and Secret as those will be required when you install the application.

## Blackboard Learn
1.	On your Learn instance create a user ‘DSKTOOLUSER’ and assign them a low, to no, privileged System Role - I have used "guest" - you may alternatively create a specific role if you choose.
**Do not** assign a System Administrator Role. You may assign the DSKTOOLUSER any Institution Role.
    <ul><li>Create a SYSTEM ROLE: DSKTOOLUSER_SYSTEM_ROLE with no privileges
    <li>Create a USER: DSKTOOLUSER and assign the system role of DSKTOOLUSER_SYSTEM_ROLE
    <li>and use DSKTOOLUSER as the user in the REST API Integration configuration in the next steps
    </ul>
2.	Navigate to the System Admin page and select the REST API Integrations link.
3.	Enter your Application Id into the Application Id field
4.	Set the REST integration user to your ‘DSKTOOLUSER’
5.	Set Available to 'Yes'
6.	Set End User Access to 'Yes'
7.	Set Authorized To Act As User to ‘Yes'
8.	Click Submit


Learn is now ready and you may proceed with the installation by clicking the below button and following the instructions.

## Heroku

Clicking any of the below 'Deploy to Heroku' buttons will open Heroku to your application setup screen and enable deploying the target branch. 

Note: if you do not have a Heroku account you will be prompted to create one and you will be directed to the setup screen on account create completion.

##### Deploy Latest Stable Release (v1.2.6): 
<a href="https://heroku.com/deploy?template=https://github.com/moneil/DSKTOOL-for-Heroku/tree/main">
  <img src="https://www.herokucdn.com/deploy/button.svg" alt="Deploy"> 
</a>

##### Deploy Latest Development Branch (v1.2.7 - note version on Heroku Create App Page):
**Important: Do not use for production**! This development branch is intended for development testing/preview purposes only! 

<a href="https://heroku.com/deploy?template=https://github.com/moneil/DSKTOOL-for-Heroku/tree/dev">
  <img src="https://www.herokucdn.com/deploy/button.svg" alt="Deploy"> 
</a>


### Configuring your application
On the setup screen you will need to name your application dyno, select a region and set the configuration variables:
 
1. Enter an application name - Heroku will let you know if it is valid. e.g. PostDSKTOOL.
2. Choose a region that applies or is closest to you.
3. Set the required **APPLICATION\_KEY** config variable using the APPLICATION KEY provided when you registered your Application in the Blackboard Developer Portal. (Contains hyphens)
4. Set the required **APPLICATION\_SECRET** config variable using the APPLICATION SECRET provided when you registered your Application. (Contains no hyphens)
5. Set the **BLACKBOARD\_LEARN\_INSTANCE** config variable to the FQDN for your target Blackboard Learn instance. E.g.: demo.blackboard.com. DO NOT include the protocol (http:// or https://)
6. Leave the required **DISABLE\_COLLECTSTATIC** config variable set to the current setting of 1 - this is required for a successful deploy.
7. Set the required **DJANGO\_SECRET\_KEY** config variable using the DJANGO SECRET gennerated from this website: https://djskgen.herokuapp.com NOTE: remove the single quotes e.g.: 
`=)**)-eozw)jt@hh!lkdc3k-h$gty+12sv)i(r8lp6rn9yn9w&` 
**NOT** 
`'=)**)-eozw)jt@hh!lkdc3k-h$gty+12sv)i(r8lp6rn9yn9w&'`
Retaining the single quotes will cause the install to fail.

After entering the above click the '**Deploy app**' button at the bottom of the page. 

This starts the deployment and on successful completion you will see a message at the bottom of the page '**Your app was successfully deployed.**' along with two buttons, one for Managing your app and one to View - click '**View**' button to open your app in your browser. 

This URL is sticky so bookmark it for later use and you are done!

**IMPORTANT:** After significant testing I have found that the 3LO redirect to login, which this tool uses, may not work correctly if you are using Direct Portal Entry (where your login is on the community/institution landing page). I believe v1.0.5 mediates this issue. 

Additionally, it appears that your 3LO session may expire hourly (check the "Who am I" link) requiring you to log out of the DSKTOOL via the "Learn Logout" link, return to the DSKTOOL homepage and when prompted relogin to Learn.

<hr>

## Release Notes
### v1.2.7 (IN PROGRESS)
<ul>
  <li>Add Date option to Enrollments Course/User searches</li>
  <li></li>
  <li>Released comparable v1.2.6 docker image [https://hub.docker.com/r/oscelot/oscelot-dsktool/tags](https://hub.docker.com/r/oscelot/oscelot-dsktool/tags) (**Note:** As I continue to migrate away from OSCELOT naming, this URL will permanently change in the future. Watch release notes and docker-compose.yml file.)</li>
</ul>

## ToDo
<ul>
  <li>Add Availability option to Enrollments Course/User searches</li>
  <li>Add Date option to Enrollments Course/User searches</li>
  <li>Add Role option to Course Membership updates</li>
  <li>Clean up code redundancies</li>
</ul>

### v1.2.6 (07/05/2022)
<ul>
  <li>Fixed Heroku deployment</li>
  <li>Fixed Docker deployment</li>
  <li>Upgraded Python to 3.10.5</li>
  <li>Upgraded Django to latest stable (4.0.6 as of this release).</li>
  <li>Removed OSCELOT references</li>
  <li>Moved to new git site with new project name "DSKTOOL for Learn" [https://github.com/moneil/DSKTOOL-for-Learn](https://github.com/moneil/DSKTOOL-for-Learn).</li>
  <li>Fixed change report error on empty database.</li>
  <li>Added capability to clear report database.</li>
  <li>Added capability to download .zip of report database</li>
  <li>Released comparable v1.2.6 docker image [https://hub.docker.com/r/oscelot/oscelot-dsktool/tags](https://hub.docker.com/r/oscelot/oscelot-dsktool/tags) (**Note:** As I continue to migrate away from OSCELOT naming, this URL will permanently change in the future. Watch release notes and docker-compose.yml file.)</li>
</ul>

### v1.2.5 (04/11/2022) ###
<ul>
  <li>Removed token expiration time from index page.</li>
  <li>Added 'Contains' search operator on Users and Courses - now supports 'Contains' and 'Exact' searches.</li>
  <li>Added User Family Name via 'Contains' only search operation.</li>
  <li>Added Course Name via 'Contains' only search operation.</li>
  <li>Added "Reason for change" feature - forces entry of why the change was made.</li>
  <li>Added how-to for hosting on CPANEL.</li>
  <li>Released comparable v1.2.5 docker image.</li>
</ul>

### v1.2.1 (03/23/2022)
<ul>
  <li>Removed token information from index page.</li>
  <li>Added token expiration time to index page.</li>
  <li>Altered 3LO behavior with 'offline' scope: Admin is no longer required to log in hourly on API access_token refresh.</li>
  <li>Released comparable v1.2.1 docker image</li>
</ul>

### v1.2.0 (03/14/2022)
<ul>
  <li>Added Date and Availability options to Users/Courses DSK search</li>
  <li>Added Course External Id to User Enrollment results</li>
  <li>Fixed a couple annoying UI issues that no one else probably noticed</li>
  <li>Released comparable v1.2.0 docker image</li>
</ul>

### v1.1.6 (08/24/2021)
<ul>
  <li>Fixed issue with DSK lists being truncated at 100</li>
  <li>Released comparable v1.2.0 docker image.</li>
</ul>


<!-- 
After you create and edit your config.py file in the next step you may then run: python manage.py runserver_plus --cert certname

If Using ngrok run pip install -r requirements.txt . Next run python manage.py migrate to apply the migrations. And last, start the server with python manage.py runserver
If Using your own cert run $ python manage.py runserver_plus --cert certname 
-->