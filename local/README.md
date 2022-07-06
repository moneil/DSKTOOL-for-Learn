# Install and Run DSKTool for Learn on Your Local Computer...

## In Brief:
### Run from source
Note: While not complicated running from source requires *some* familiarity with GIT, and a terminal. 

Note: You must also go to the [Anthology Developer Portal](https://developer.anthology.com) and create a REST Application as outlined in this project's [README.md](./README.md).

1. Clone or fork this project and cd into the project directory
3. Install and start ngrok or similar tunneling tool
4. copy config-template.py to config.py
5. edit config.py with your settings
6. run $ python .\manage.py migrate
7. run $ python .\manage.py runserver

### Run from Docker 
You may also run DSKTool for Learn using Docker for Desktop. See this project's  [./docker/README.md](./docker/README.md) for Docker details.

## Setup for Running from Source:
### Clone or Fork this project
This is a nice article on [the difference between Git Clone and Fork](https://www.toolsqa.com/git/difference-between-git-clone-and-git-fork/)

Basically, if you wish to contribute to the project please fork to a DSKTool project in your github account and clone your project. If you do not wish to be a contributor you will clone the project to your desktop.

If you are unsure which action to take, a clone is a good starting point as you may refresh/sync your local copy  with the main project to take future releases with a Fetch request.

Once you have retrieve the source you should cd into the directory, you will perform most commands in this terminal window.

### Set up ngrok or similar tunneling application
First you will install support for TLS using ngrok (or similar tunneling application), then you will install Docker and run your edited version of the project docker-compose.yaml file.

#### TLS
TLS support is provided by ngrok which provides a TSL tunnel to the DSKTOOL running on your local computer. 

Open a new terminal tab or window and browser.

1. Go to [https://ngrok.io](https://ngrok.com/download)
2. Sign up for a free account if you don't already have one and login
3. Download the installer for your system [https://ngrok.com/download](https://ngrok.com/download)
4. Visit [https://dashboard.ngrok.com/get-started/setup](https://dashboard.ngrok.com/get-started/setup) and copy your authtoken
5. Expand ngrok into your applications folder
6. In a terminal cd to your ngrok directory and enter `$ ./ngrok authtoken <your authtoken>`
5. Start a tunnel to the DSKTOOL Port (8000): `$ ./ngrok http 8000`
Do not close your terminal - it must stay open while you are using the TLS connection. 

You should see something like this:

> ngrok by @inconshreveable                                                    (Ctrl+C to quit)
> 
> Session Status&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;online
> 
> Account&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&lt;your nginx username&gt; (Plan: Free)
> 
> Version&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;2.3.35
> 
> Region&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;United States (us)
> 
> Web Interface&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;http://127.0.0.1:4040
> 
> Forwarding&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;http://1b486ab37de2.ngrok.io -> http://localhost:8000
> 
> Forwarding&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;**https://1b486ab37de2.ngrok.io -> http://localhost:8000**
> 
> Connections&nbsp;&nbsp;ttl&nbsp;&nbsp;opn&nbsp;&nbsp;rt1&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;rt5&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;p50&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;p90
>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;0&nbsp;&nbsp;0&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;0.00&nbsp;&nbsp;&nbsp;0.00&nbsp;&nbsp;&nbsp;&nbsp;0.00&nbsp;&nbsp;&nbsp;&nbsp;0.00

The text in bold indicates the URL you shoud use for securely accessing and using the DSKTOOL running on your system.

**Note**: ngrok requires your terminal to be open while running. ngrok sessions do expire and will require restarting ngrok when they expire or after computer restarts etc. If ngrok is not running or has expired your browser will display the following: Tunnel `the original ngrok https url` not found. Just restart ngrok and use the new https url provided.

### Copy config-template.py to config.py and edit config.py with your settings
Using the teminal window that is open to your project directory copy the config-template.py file to config.py:
`$ cp config-template.py config.py
`

Use your editor of choice and follow the directions in the config.py file:

>     "BLACKBOARD_LEARN_INSTANCE" : "Here you enter the FQDN for your Learn instance",
>     "APPLICATION_KEY" : "Here you enter your REST Application KEY",
>     "APPLICATION_SECRET" : "Here you enter your REST Application SECRET",
>     "django_secret_key" : 'Here you enter a secret generated from https://djskgen.herokuapp.com'

Example:
>     "BLACKBOARD_LEARN_INSTANCE" : "beards.ddns.net",
>     "APPLICATION_KEY" : "9d3306bff1-da5-4225-96cd6-e1d845-db53",
>     "APPLICATION_SECRET" : "ElWsmR6HahtEl3WiIpY3c50C7y8PrYhUoGs",
>     "django_secret_key" : "j07gpr1ny3k+upitofzhjwqigg@44)!7(cr*+(f1-b_34l-ydf"


### Create the Django database 
Using the teminal window that is open to your project directory run `$ python .\manage.py migrate`

### Start the DSKTool
Using the teminal window that is open to your project directory run `$ python .\manage.py runserver`

### Access your locally running copy of DSKTools
Open your browser and visit the URL provided by your tunneling app. 

Example ngrok URL: `https://3f20-67-172-47-55.ngrok.io`
