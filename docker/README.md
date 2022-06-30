# DSKTOOL for Learn on Docker v1.2.6 (04/11/2022)

See below [Docker Release Notes](#Release-Notes).

This directory contains the files for building and running the DSKTOOL as a Docker container.

# Installation
There are two methods for running the DSKTOOL in Docker.

1. Deploy using a prebuilt image - requires only the docker-compose.yml file
2. Build and deploy - requires a clone of this repository.

Both are suitable for local or remote deployment. For the sake of simplicity the below instructions cover option 1. because using a prebuilt image is significanlty more convenient.

> Note: Both require changes to the default configuration file or environment settings.

## Deploy Using a Prebuilt Image
With each release starting with 1.0.9 I will be providing a Docker image available at DockerHub.com. The docker-compose.yml file points to that image tagged with the latest version and will contain any changes necessary to support any future project changes.

> Note: The DSKTOOL uses three-legged OAuth (3LO) for authentication. 3LO requires `https`.

The installation is performed in three easy steps:

1. Provide TLS for https access
2. Install Docker
3. Deploy using `docker-compose.yml` file.

### 1. Provide TLS for https access
You may skip this step if you are running the image on a remote server already configured for SSL.

If you are running the Docker image on your desktop using Docker Desktop you need to provide a TLS service to enable SSL for the Docker URL. In this example you will use ngrok a TSL tunnel provider. 

1. Go to https://ngrok.io
1. Sign up for a free account if you don't already have one and login
1. Download the installer for your system https://ngrok.com/download
1. Visit https://dashboard.ngrok.com/get-started/setup and copy your authtoken
1. Expand ngrok into your applications folder
1. In a terminal cd to your ngrok directory and enter $ ./ngrok authtoken <your authtoken>
1. Start a tunnel to the DSKTOOL Port (8000): $ ./ngrok http 8000 Do not close your terminal - it must stay open while you are using the TLS connection.

You should see something like this:

> ngrok by @inconshreveable (Ctrl+C to quit)
> 
> Session Status           online
> 
> Account                      <your nginx username> (Plan: Free)
> 
> Version                        2.3.35
> 
> Region                         United States (us)
> 
> Web Interface             http://127.0.0.1:4040
> 
> Forwarding                  http://1b486ab37de2.ngrok.io -> http://localhost:8000
> 
> Forwarding                  https://1b486ab37de2.ngrok.io -> http://localhost:8000
> 
> Connections  ttl  opn  rt1    rt5     p50     p90
> 
>              0    0    0.00   0.00    0.00    0.00

The text in bold indicates the URL you should use for securely accessing and using the DSKTOOL running on your system.

Note: ngrok requires your terminal to be open while running. ngrok sessions do expire and will require restarting ngrok when they expire or after computer restarts etc. If ngrok is not running or has expired your browser will display the following: Tunnel the original ngrok https url not found. Just restart ngrok and use the new https url provided.

### 2. Docker
If running on your Desktop (OSX/WINDOWS) then install Docker Desktop : https://www.docker.com/products/docker-desktop

If running on a remote server install docker per your server: https://runnable.com/docker/install-docker-on-linux

Download the above docker-compose.yaml file to a directory of your choosing

Open the docker-compose.yaml file and edit the following:

> `DJANGO\_SECRET\_KEY: 'secret from https://djskgen.herokuapp.com see readme'`

NOTE: the above generator adds single quotes. Remove remove them after pasting. The field must be single quoted only. E.g.: use '=)...9w&' **NOT** ''=)...9w&''. Retaining the generated single quotes will cause the install to fail.

> `BLACKBOARD\_LEARN\_INSTANCE: "your Learn FQDN"` -- No protocol e.g. my.learn.server.com
> 
> `APPLICATION\_KEY: "your application key"`
> 
> `APPLICATION\_SECRET: "your application secret"`
>
> Note if you want to always run the latest image you may also edit:
> 
> Confirm target image version: `image: oscelot/oscelot-dsktool:version (see readme)` and replace "version (see readme)" with the  version indicated above e.g.: 1.1.6. 

Open a terminal, cd to the directory where you saved the docker-compose.yaml file and enter: `$ docker-compose up -d`

If you changed the file name you would use `$ docker-compose -f <your filename> up -d`

> Note: You may see the following message - `WARNING: The r variable is not set. Defaulting to a blank string.` This may be ignored, it has no impact on operations...tracking that down is on my ToDo list.

### Test

Open your Docker Desktop Dashboard to inspect that the DSKTOOL app is running
Log out of Learn
Browse to https URL provided by ngrok and click the whoami link to view the https site and ensure the site is functioning. You should be asked to login to the configured Learn instance.

If for some reason you get an error loading the site there are a few things to check:

1. Ensure the tool is properly installed in Learn
1. Ensure you changed the DJANGO\_SECRET\_KEY and that it is enclosed by single quotes **this is important**.
1. If you see an error indicating that you need to add localhost to allowed hosts - you need to setup https.


## Release Notes
This and future releases will update this section only with changes/additions to the Docker Image. 

Application Release Notes are available at: <a href='https://github.com/moneil/DSKTOOL-for-Heroku'>https://github.com/moneil/DSKTOOL-for-Heroku</a> </li>

### v1.1.5 (06/25/2021)
<ul>
  <li>Fixed issue with Django ALLOW_HOSTS which prevented docker images from correctly running</li>
  <li>Released comparable v1.1.5 docker image.
</ul>
 
### v1.0.8 (09/25/2020)
This Docker release focuses delivering the files supporting Docker deployment:
<ul>
	<li>This README</li>
	<li>docker-compose.yml to use provided or self-built images</li>
	<li>dockerfile for self-built images</li>
</ul>