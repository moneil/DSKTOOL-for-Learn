# OSCELOT DSKTOOL for HEROKU v1.2.5 (04/17/2022)

Note: I am temporarially disabling the Heroku Deploy buttons and docker container build update until I sort out some deployment issues... the project runs locally outside of Heroku and Docker just fine - use the Localhost instructions.

See [Release Notes](#Release-Notes) below.

This project is a Django/Python and Learn REST replacement for the Original York DSK Building Block for Learn.

This project is built to be deployed in a variety of ways:
    
* Heroku: You may read about Heroku here: [https://heroku.com](https://heroku.com).
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

Note: I have temporarially disabled the Heroku Deploy buttons and docker container build until I sort out some deployment issues... the project runs locally outside of Heroku and Docker just fine - use the Localhost instructions.

Clicking the below 'Deploy to Heroku' button will open Heroku to your application setup screen. 

Note: if you do not have a Heroku account you will be prompted to create one. You will be directed to the setup screen on account create completion.


##### Deploy Latest Stable Release (v1.2.1): 
<a href="https://heroku.com/deploy">
  <img src="https://www.herokucdn.com/deploy/button.svg" alt="Deploy"> 
</a>

##### Deploy Last Stable Release (v1.2.0):
<a href="https://heroku.com/deploy">
  <img src="https://www.herokucdn.com/deploy/button.svg" alt="Deploy"> 
</a>

##### Deploy Latest Beta Branch (v1.2.5):
<a href="https://heroku.com/deploy?template=https://github.com/moneil/OSCELOT-DSKTOOL-for-HEROKU/tree/Fix-Heroku-Deploy-Button">
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
### v1.2.5 (04/11/2022)
<ul>
  <li>Removed token expiration time from index page.</li>
  <li>Added 'Contains' search operator on Users and Courses - now supports 'Contains' and 'Exact' searches.</li>
  <li>Added User Family Name via 'Contains' only search operation</li>
  <li>Added Course Name via 'Contains' only search operation</li>
  <li>Added "Reason for change" feature - forces entry of why the change was made.
  <li>Added how-to for hosting on CPANEL
  <li>Released comparable v1.2.5 docker image</li>
</ul>

## ToDo
<ul>
  <li>Add Availability option to Enrollments Course/User searches</li>
  <li>Add Date option to Enrollments Course/User searches</li>
  <li>Add Role option to Course Membership updates</li>
  <li>Clean up code redundancies</li>
</ul>

### v1.2.1 (03/23/2022)
<ul>
  <li>Removed token information from index page</li>
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

### v1.1.5
<ul>
  <li>Fixed issue with Django ALLOW_HOSTS which prevented docker images from correctly running</li>
  <li>Released comparable v1.2.0 docker image.
</ul>

### 1.1.1 (02/29/2021)
<ul>
  <li>Fixed a few annoying UI/UX issues</li>
  <li>Added System Admin role check to page loads and API calls </li>
  <li>Cleaned up the code a bit in the process</li>
  <li>Released v1.1.1 docker image.</li>
</ul>

### 1.1.0 (01/04/2021)
<ul>
  <li>Fixed annoying 'undefined' error on User and Course searches</li>
  <li>Fixed a few annoying UI/UX issues</li>
  <li>Added Data Source Key searches to Courses and Users</li>
  <li>Added optional DSK filtering on Course and User Enrollment searches</li>
  <li>Added error alerts when re-login is required</li>
  <li>Released v1.1.0 docker image.</li>
</ul>

### v1.0.11 (10/04/2020)
<ul>
  <li>AJAX'd the Course page</li>
  <li>Cleaned up JS console logging</li>
</ul>

### v1.0.10 (09/29/2020)
<ul>
  <li>AJAX'd the User page</li>
  <li>Fixed enrollments availability selection bug</li>
  <li>Removed json details from pages for application consistency (all that, and much more, is written to the browser JavaScript console)</li>
  <li>Also fixed a few display issues.</li>
</ul>
Next up - AJAX Course/Org page.

### v1.0.9 (09/27/2020)
This release improves readibility of tables:
<ul>
  <li>Added 'sticky' table header and inner grid to all tables.</li>
  <li>Added Course User Role to enrollment results.</li>
  <li>Also fixed a display bug on loading non-enrollment pages.</li>
  <li>Removed release notes from application index page (you may find them here).</li>
  <li>Added version info to bottom of application index page.</li>
</ul>
Next up - AJAX Course/Org and User pages.
 
### v1.0.8 (09/25/2020)
This release focuses on improving the user experience for searching and updating Enrollments:
<ul>
  <li>Enrollments: Added Course/Org and User membership searches and updating to Enrollments
  <li>Enrollments: Course/Org and User membership searches support externalId and courseId/Username
  <li>Enrollments: Improved UI using AJAX
  <li>Enrollments: Added alerts for entry validation and errors
  <li>Enrollments: Substantial logging to Javascript console for debugging
  <li>Added Docker deployment support (docker-compose.yml) see docker/README.md for details.
</ul>

### v1.0.5 (08/16/2020)
<ul>
  <li>Begin support for single project for multiple deployment models (Heroku, Desktop, or Docker). Current code fully supports Heroku and local use. Use the above deploy button or follow the instructions in the local folder. Docker coming soon.</li>
  <li>Added 3LO handling for guest user results when target Learn instances use SSO or Direct Entry.</li>
  <li>Added 3LO and 500 error trapping.</li>
</ul>

### v1.0.4 (07/29/2020)
<ul>
  <li>Delete session cookie when Learn Logout link is used.</li>
  <li>Moved older release notes from app index page to here.</li>
</ul>

### v1.0.3 (07/29/2020)
<ul>
  <li>Heroku Deployable!</li>
  <li>3LO required on all pages</li>
</ul>

### v1.0.2 (07/28/2020)
<ul>
  <li>Heroku Enabled!(working out some DB details)</li>
  <li>3LO required on index load
  <li>strips spaces from around search terms
</ul>

### v1.0.1 (07/27/2020)
<ul>
  <li> Fixed django issues which were preventing correct loading </li>
  <li> Updated installation notes</li>
</ul>


### v1.0 (07/26/2020)
<ul>
  <li> Supports Data Source Key and Availability status for **single** User, Course, and Enrollment Records. </li>
  <li> Supports non-TLS (SSL) local python and Docker Desktop deployments
  <li> Supports TLS (SSL) deployments (see below TLS section)
</ul>
<hr>

<!-- 
After you create and edit your config.py file in the next step you may then run: python manage.py runserver_plus --cert certname

If Using ngrok run pip install -r requirements.txt . Next run python manage.py migrate to apply the migrations. And last, start the server with python manage.py runserver
If Using your own cert run $ python manage.py runserver_plus --cert certname 
-->