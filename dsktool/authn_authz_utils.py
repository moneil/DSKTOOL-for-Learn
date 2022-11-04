# Django imports
from curses import KEY_A1
from pickle import FALSE
import secrets
from django.shortcuts import render
from django.http import HttpResponse
from django.http import HttpResponseRedirect
from django.http import HttpRequest
from django.shortcuts import redirect
from django.urls import reverse
from django.template import loader, Template


# python imports
from datetime import datetime, timedelta, timezone
import os
import uuid
import time
import logging
import json

# PyPi imports
from bbrest import BbRest
import jsonpickle
# from dsktool.authn_util import ISGUESTUSER, ISVALIDROLE

# app imports
from dsktool.jwt_token_util import Jwt_token_util


class Auth_Utils:

    logging.basicConfig(
        format='%(asctime)s %(levelname)-8s %(message)s',
        level=logging.DEBUG,
        datefmt='%Y-%m-%d %H:%M:%S')

# if AUTHN_BB_JSON == None:
#     try:
#         AUTHN_BB = BbRest(str(AUTHN_KEY), str(AUTHN_SECRET), f"https://{AUTHN_LEARNFQDN}")
#         AUTHN_BB_JSON = jsonpickle.encode(AUTHN_BB)
#         logging.info('AUTHNZ: Pickled BbRest as AUTHN_BB_JSON.')

#     except BaseException as err:
#         logging.critical(
#             'AUTHNZ: Critical error setting up BbREST, Check Configuration AUTHN_KEY and AUTHN_SECRET.')
#         print(f"Unexpected {err=}, {type(err)=}")

    def __init__(self, request, target_view):
        logging.info('AUTH_UTILS INIT CALLED')

        # INSTANCE VARIABLES
        self.AUTHN_BB = None
        self.AUTHN_BB_JSON = None
        self.ISAUTHNVALIDROLE = False
        self.ISAUTHNGUESTUSER = True
        self.bb_refreshToken = None
        self.AUTHN_EXPIRE_AT = None
        self.AUTHN_START_EXPIRE = None
        self.AUTHN_ROLE = None
        self.AUTHN_KEY = None
        self.AUTHN_SECRET = None
        self.AUTHN_LEARNFQDN = None
        self.ROLE = None
        self.TARGET_VIEW = target_view
        self.REQUEST = request
        self.IN_JWT = None
        self.GENERATED_JWT = None
        self.CONTEXT = None
        

        try:
            from config import adict
            logging.info('AUTH_UTILS INIT: using config.py...')
            self.AUTHN_KEY = adict['APPLICATION_KEY']
            self.AUTHN_SECRET = adict['APPLICATION_SECRET']
            self.AUTHN_LEARNFQDN = adict['BLACKBOARD_LEARN_INSTANCE']
        except:
            logging.info('AUTH_UTILS INIT: using env settings...')
            self.AUTHN_KEY = os.environ['APPLICATION_KEY']
            self.AUTHN_SECRET = os.environ['APPLICATION_SECRET']
            self.AUTHN_LEARNFQDN = os.environ['BLACKBOARD_LEARN_INSTANCE']

        logging.info(f'AUTH_UTILS INIT: AUTHN_KEY: {self.AUTHN_KEY}')
        logging.info(f'AUTH_UTILS INIT: AUTHN_SECRET: {self.AUTHN_SECRET}')
        logging.info(f'AUTH_UTILS INIT: AUTHN_LEARNFQDN: {self.AUTHN_LEARNFQDN}')
        logging.info(f'AUTH_UTILS INIT: TARGET_VIEW: {self.TARGET_VIEW}')

    # Calling destructor
    def __del__(self):
        logging.info('AUTH_UTILS DESTRUCTOR CALLED')


# Authenticated Check
def isAuthenticated(request):
    # if AUTHN_BB_JSON IS IN THE REQUEST WE HAVE PREVIOUSLY AUTHENTICATED
    authenticated = False
    logging.info(f'session.keys: {request.session.keys()}')
    if "BB_JSON" in request.session.keys():
        logging.info('AUTHN_BB_JSON IN session...')
        authenticated = True
    
    return authenticated

def isAuthorized(request):
    jwt_util = Jwt_token_util()
    isAuthorized = False

    if ('JWT' in request.COOKIES):
        # logging.info(f'AUTHNZ: ISAUTHORIZED: TOKEN EXISTS: {request.COOKIES['JWT']}')
        logging.info('AUTHNZ: ISAUTHORIZED: TOKEN EXISTS:!')

        if (jwt_util.isVerified(request.COOKIES['JWT'])):
            isAuthorized = True
        else:
            logging.info('AUTHNZ: ISAUTHNAUTHORIZED TOKEN INVALID')
            isAuthorized = False
    else:
        # not authenticated (no jwt)
        # perform 3LO:
        #   if user authenticates and user has a valid role of system admin then
        #       build jwt and return
        #       caller then places jwt into response and we are done
        #   else
        #       user cannot authenticate or has an invalid role
        #       return empty token indicating not authorized.
        logging.info('AUTHNZ: ISAUTHNAUTHORIZED: THIS IS GOING TO FAIL THERE IS NO TOKEN')

    return isAuthorized

def authenticate(request, target=None):
    logging.info('AUTHENTICATE CALLED')

    global ROLE
    global KEY
    global SECRET
    global LEARNFQDN
    global AUTHN_BB_JSON
    global EXPIRE_AT
    global ISVALIDROLE
    global ISGUESTUSER
    global jwt_token
    global jwtClaims
    global user_json

    ROLE = None
    KEY = None
    SECRET = None
    LEARNFQDN = None
    response = None
    AUTHN_BB_JSON = None
    EXPIRE_AT = None
    ISVALIDROLE = False
    ISGUESTUSER = True
    # jwt_token = None


    #this is the code from authnz_util.py used by all pages requiriing authentication/authorization
    # authenticate and get a jwt_token
    # template = loader.get_template('notauthorized.html')
    # response = HttpResponse(template.render())
    logging.info('AUTH CHECK FAILED, that is what got you here...')
    logging.info('The why is NO or INVALID JWT_TOKEN')
    logging.info('To fix we are authenticating AND getting a new JWT...')

    try:
        from config import adict
        logging.info('AUTH_UTILS INIT: using config.py...')
        KEY = adict['APPLICATION_KEY']
        SECRET = adict['APPLICATION_SECRET']
        LEARNFQDN = adict['BLACKBOARD_LEARN_INSTANCE']
    except:
        logging.info('AUTH_UTILS INIT: using env settings...')
        KEY = os.environ['APPLICATION_KEY']
        SECRET = os.environ['APPLICATION_SECRET']
        LEARNFQDN = os.environ['BLACKBOARD_LEARN_INSTANCE']

    TARGET_VIEW = target

    logging.info(f'AUTH_UTILS INIT: AUTHN_KEY: {KEY}')
    logging.info(f'AUTH_UTILS INIT: AUTHN_SECRET: {SECRET}')
    logging.info(f'AUTH_UTILS INIT: AUTHN_LEARNFQDN: {LEARNFQDN}')
    logging.info(f'AUTH_UTILS INIT: TARGET_VIEW: {TARGET_VIEW}')

    # check for BBJSON in request or if already locally set...
    if "AUTHN_BB_JSON" not in request.session.keys(): #or AUTHN_BB_JSON is None:
        logging.info('AUTHNZ: BbRest not found in session')
        logging.info(f'AUTHNZ: KEY: {KEY}')
        logging.info(f'AUTHNZ: SECRET:' + str(SECRET))

        try:
            BB = BbRest(str(KEY), str(SECRET), f"https://{LEARNFQDN}")
            AUTHN_BB_JSON = jsonpickle.encode(BB)
            logging.info('AUTHNZ: Pickled BbRest added to session.')
            request.session['AUTHN_BB_JSON'] = AUTHN_BB_JSON
            if target:
                request.session['target_view'] = target
            return HttpResponseRedirect(reverse('authnz_get_3LO_token'))
        except BaseException as err:
            logging.critical(
                'AUTHNZ: Could not set BbREST in Session, Check Configuration KEY and SECRET.')
            logging.info(f"Unexpected {err=}, {type(err)=}")            
    else:
        logging.info('AUTHNZ: Found BbRest in session')
        AUTHN_BB_JSON = request.session['AUTHN_BB_JSON']
        BB = jsonpickle.decode(AUTHN_BB_JSON)
        logging.debug("AUTHNZ: AUTHN_BB_JSON: Original Token Info: " +
                    str(BB.token_info))
        if ISVALIDROLE is None:
            logging.info('AUTHNZ: NO VALID ROLE - Get 3LO and confirm role.')
            logging.info('AUTHNZ: CALL authnz_get_3LO_token')
            logging.debug(
                "AUTHNZ: ISVALIDROLE=FALSE: Updated Token Info: " + str(BB.token_info))
            return HttpResponseRedirect(reverse('authnz_get_3LO_token'))
        
        if BB.is_expired():
            logging.info('AUTHNZ: Expired API Auth Token.')
            logging.info('AUTHNZ: GET A NEW API Auth Token')
            # BB.expiration()
            BB.refresh_token()
            # EXPIRE_AT = None
            AUTHN_BB_JSON = jsonpickle.encode(BB)
            request.session['AUTHN_BB_JSON'] = AUTHN_BB_JSON
            request.session['target_view'] = TARGET_VIEW
        BB.supported_functions()  # This and the following are required after
        BB.method_generator()    # unpickling the pickled object.
    logging.debug("AUTHNZ: BB_JSON: Final Token Info: " + str(BB.token_info))
    logging.info(f'AUTHNZ: Token expiration: {BB.expiration()}')
    resp = BB.GetVersion()
    access_token = BB.token_info['access_token']
    refresh_token = BB.token_info.get('refresh_token')
    token_expiry = str(BB.expiration())[3:]
    version_json = resp.json()

    logging.info('GET SYSTEM ROLE')
    resp = BB.call('GetUser', userId="me", params={
        'fields': 'userName, uuid, externalId, systemRoleIds, contact.email'}, sync=True)
    user_json = resp.json()
    if "SystemAdmin" in user_json['systemRoleIds']:
        logging.info(f'USER HAS SYSTEMADMIN ROLE! SYSTEMROLEIDS: {user_json["systemRoleIds"]}')

    context = {
        'learn_server': LEARNFQDN,
        'version_json': version_json,
        'access_token': access_token,
        'refresh_token': refresh_token,
        'token_expiry': token_expiry,
        'expire_from': EXPIRE_AT,
        'jwt_token': "No Token",
    }

    logging.info(f'ln252:AUTHNZ:: ISGUESTUSER: {ISGUESTUSER}...ISVALIDROLE: {ISVALIDROLE}')
    jwt_utils = Jwt_token_util()

    # if (not ISGUESTUSER and ISVALIDROLE):
    if (ISGUESTUSER and not ISVALIDROLE):
        template = loader.get_template('guestusernotallowed.html')
        response = HttpResponse(template.render())


    else:
        logging.info('AUTHNZ: VALID USER SET JWT')

        resp = BB.call('GetUser', userId="me", params={
                    'fields': 'userName, uuid, externalId, systemRoleIds, contact.email'}, sync=True)
        user_json = resp.json()

        logging.info(f'USER_JSON: {user_json}')

        # Get the fully qualified domain name.
        fqdn = socket.getfqdn()
        logging.info(f"FQDN:{fqdn}")
        HTTP_X_REAL_IP = request.META.get('HTTP_X_REAL_IP')
        logging.info(f"HTTP_X_REAL_IP:{HTTP_X_REAL_IP}")

        REMOTE_ADDR = str(request.META.get('REMOTE_ADDR'))
        logging.info(f"REMOTE_ADDR:{REMOTE_ADDR}")

        jwtClaims = {
            'iss': 'DSKTool for Learn',
            'system': REMOTE_ADDR,
            'exp': datetime.now(tz=timezone.utc) + timedelta(minutes=2),
            'iat': datetime.now(tz=timezone.utc),
            'xsrfToken': uuid.uuid4().hex,
            'jti': uuid.uuid4().hex,
            'sub': user_json['uuid'],
            'userName': user_json['userName'],
            'userRole': ROLE,
            'userUuid': user_json['uuid'],
            'userEmail': user_json['contact']['email'],
        }

        logging.info(f"AUTHNZ:JWTCLAIMS:")
        logging.info(f"{jwtClaims}")

        jwt_token = jwt_utils.create_jwt(jwtClaims)

        context = {
            'learn_server': LEARNFQDN,
            'version_json': version_json,
            'access_token': access_token,
            'refresh_token': refresh_token,
            'token_expiry': token_expiry,
            'expire_from': EXPIRE_AT,
            'jwt_token': jwt_token,
            'decoded_token': jwt_utils.decodeJWT(jwt_token)
        }

        # The above updates the JWT every time vs only once if it exists.
        template = loader.get_template(TARGET_VIEW + '.html')
        response = HttpResponse(template.render(context))

        logging.info(f'AUTHNZ: session.keys: {request.session.keys()}')

        jwtSessionCookies = request.COOKIES
        logging.info(f"AUTHNZ:SESSION:COOKIES")
        logging.info(f"{jwtSessionCookies}")
        logging.info(f'AUTHNZ:JWTCLAIMS: {jwtClaims}')
        logging.info(f'AUTHNZ:JWT_TOKEN: {jwt_token}')


        if (not 'JWT' in request.COOKIES):
            logging.info(f'AUTHZN:SESSION:NO JWT ADD IT WITH THESE CLAIMS: {jwtClaims}')
            jwt_token = jwt_utils.create_jwt(jwtClaims)
            logging.info(f"JWTTOKENTOADD:{jwt_token}")
            response.set_cookie('JWT', jwt_token)
        else:
            logging.info(f"AUTHNZ:SETTING JWT COOKIE WITH:{jwt_token}")
            jwt_token = request.COOKIES['JWT']

            logging.info(f"AUTHNZ:SESSIONJWT:{jwt_token}")
            logging.info(f'AUTHNZ:CONTEXT: {context}')
            context["jwt_token"] = jwt_token
            logging.info(f'AUTHNZ:CONTEXTJWTTOKEN:{context["jwt_token"]}')
            response.set_cookie('JWT', jwt_token)

        logging.info(f'ln:326:AUTHNZ: JWTTOKEN {jwt_token}')

        decoded_jwt = jwt_utils.decodeJWT(jwt_token)
        logging.info(f'DECODED_JWT: {decoded_jwt}')

        timeremaining = (jwtClaims["iat"]+timedelta(minutes=1)
                        )-datetime.now(tz=timezone.utc)

        logging.info(f'TIME REMAINING: {timeremaining}')
        logging.info('AUTHNZ: Exiting authenticate block... ')

        logging.info(f'ONE MORE THING>>>ISGUESTUSER: {ISGUESTUSER}...ISVALIDROLE: {ISVALIDROLE}')

    return response

def isAUTHNGuestUser(BB_JSON):
    global ISGUESTUSER

    guestStatus = False

    BB = jsonpickle.decode(BB_JSON)
    resp = BB.call('GetUser', userId = "me", params = {'fields':'userName'}, sync=True ) 
    
    user_json = resp.json()

    logging.debug(f"ISGUESTUSER::userName: {user_json['userName']}")

    if user_json['userName'] == 'guest':
        guestStatus = True
        ISGUESTUSER = True
    else:
        guestStatus = False
        ISGUESTUSER = False

    logging.debug(f'ISGUESTUSER:: boolean: {ISGUESTUSER}')
    return guestStatus

def isAUTHNAuthorized(request):
    token_utils = Jwt_token_util()

    token = None
    if ('JWT' in request.COOKIES):
        if (token_utils.isVerified(request.COOKIES['JWT'])):
            token = request.COOKIES['JWT']
        else:
            logging.info('AUTHNZ: ISAUTHORIZED: TOKEN INVALID')
    else:
        # not authenticated (no jwt)
        # perform 3LO:
        #   if user authenticates and user has a valid role of system admin then
        #       build jwt and return
        #       caller then places jwt into response and we are done
        #   else
        #       user cannot authenticate or has an invalid role
        #       return empty token indicating not authorized.
        logging.info('OF COURSE THIS IS GOING TO FAIL THERE IS NO TOKEN')

        # return "GETTING NEW TOKEN"

    return token

# Getters/Setters
def set_context(self, context):
    self.CONTEXT = context

def get_context(self):
    return self.CONTEXT

def set_generated_jwt(self, jwt):
    self.GENERATED_JWT = jwt

def get_generated_jwt(self):
    return self.GENERATED_JWT

# 3LO below...
def authnz_get_API_token(request):
    global ROLE
    global KEY
    global SECRET
    global LEARNFQDN
    global AUTHN_BB_JSON
    global EXPIRE_AT
    global ISVALIDROLE
    global ISGUESTUSER

    logging.info(f'authnz_get_API_token variables:')
    logging.info(f'KEY: {KEY}')
    logging.info(f'SECRET: {SECRET}')
    logging.info(f'LEARNFQDN: {LEARNFQDN}')
    logging.info(f'ISVALIDROLE: {ISVALIDROLE}')
    logging.info(f'ISGUESTUSER: {ISGUESTUSER}')
    logging.info(f'ROLE: {ROLE}')



    # if request.session:
    #     print saysome

    # Happens when the user hits index the first time and hasn't authenticated on Learn
    # Part II. Get an access token for the user that logged in. Put that on their session.
    AUTHN_BB_JSON = request.session.get('AUTHN_BB_JSON')
    TARGET_VIEW = request.session.get('target_view')
    logging.info('authnz_get_API_token: got BbRest from session')
    logging.info(f'authnz_get_API_token: got target_view from session: {TARGET_VIEW}')
    
    AUTHN_BB = jsonpickle.decode(AUTHN_BB_JSON)
    AUTHN_BB.supported_functions()  # This and the following are required after
    AUTHN_BB.method_generator()    # unpickling the pickled object.
    # Next, get the code parameter value from the request
    redirect_uri = reverse(authnz_get_API_token)
    absolute_redirect_uri = f"https://{request.get_host()}{redirect_uri}"

    state = request.GET.get('state', default="NOSTATE")
    logging.info(f'authnz_get_API_token: GOT BACK state: {state}')
    stored_state = request.session.get('state')
    logging.info(f'authnz_get_API_token: STORED STATE: {stored_state}')
    if (stored_state != state):
        return HttpResponseRedirect(reverse('notauthorized'))

    code = request.GET.get('code', default=None)
    if (code == None):
        exit()

    user_bb = BbRest(
        KEY, SECRET, f"https://{LEARNFQDN}", code=code, redirect_uri=absolute_redirect_uri)

    AUTHN_BB_JSON = jsonpickle.encode(user_bb)
    # logging.info(f'GETAPITOKEN::USER_AUTHN_BB: {AUTHN_BB_JSON}')

    request.session['AUTHN_BB_JSON'] = AUTHN_BB_JSON

    if (isAUTHNGuestUser(AUTHN_BB_JSON)):
        logging.info('GUEST USER!!!')
        context = {
            'learn_server': LEARNFQDN,
        }
        return render(request, 'guestusernotallowed.html', context=context)

    # if (not isAUTHNAuthorized(request)):
    #     print("IS NOT VALID USER")
    #     # return notauthorized page
    #     return render(request, 'notauthorized.html')

    # obj_now = datetime.now().astimezone()
    obj_now = datetime.utcnow()
    isDST = time.localtime().tm_isdst
    logging.info("GETAPITOKEN: ISDST: " + str(isDST))
    AUTHN_START_EXPIRE = obj_now
    if not isDST:
        logging.info('GETAPITOKEN: NOT DST!')
        obj_now = obj_now - timedelta(minutes=60)
    token_expiry = str(AUTHN_BB.expiration())[3:]
    expireTime = obj_now + timedelta(minutes=59)
    AUTHN_EXPIRE_AT = str(expireTime.hour).zfill(2) + ":" + \
        str(expireTime.minute).zfill(2) + " (UTC)"

    logging.info('authnz_get_API_token: pickled BbRest and putting it on session')
    request.session['AUTHN_BB_JSON'] = AUTHN_BB_JSON

    return HttpResponseRedirect(reverse(f'{TARGET_VIEW}'))

# [DONE]
def authnz_get_3LO_token(request):
    global AUTHN_BB_JSON
    global AUTHN_BB
    global KEY

    logging.info('ENTER AUTHNZ_GET_3LO_TOKEN')

    if "AUTHN_BB_JSON" in request.session.keys():
        logging.info('AUTHN_BB_JSON IN session...')
    else:
        logging.info('NO AUTHN_BB_JSON in request.session!')

    # Happens when the user hits index the first time and hasn't authenticated on Learn
    # Part I. Request an authorization code oauth2/authorizationcode
    logging.info(
        f"authnz_get_3LO_token: REQUEST URI:{request.build_absolute_uri()}")
    try:
        AUTHN_BB_JSON = request.session.get('AUTHN_BB_JSON')
        logging.info('authnz_get_3LO_token: got BbRest from session')
        AUTHN_BB = jsonpickle.decode(AUTHN_BB_JSON)
    except:
        # sideways session go to index page and force authnz_get_API_token
        logging.info(
            f"authnz_get_3LO_token: Something went sideways with AUTHN_BB session, reverse to target e.g. 'index', maybe you should have thrown an error here.")
        return HttpResponseRedirect(reverse('target_view'))

    AUTHN_BB.supported_functions()  # This and the following are required after
    AUTHN_BB.method_generator()    # unpickling the pickled object.
    # The following gives the path to the resource on the server where we are running,
    # but not the protocol or host FQDN. We need to prepend those to get an absolute redirect uri.
    redirect_uri = reverse('authnz_get_API_token')
    absolute_redirect_uri = f"https://{request.get_host()}{redirect_uri}"
    state = str(uuid.uuid4())
    request.session['state'] = state
    authcodeurl = AUTHN_BB.get_auth_url(
        scope='read write delete offline', redirect_uri=absolute_redirect_uri, state=state)
    # authcodeurl = AUTHN_BB.get_auth_url(scope='read write delete', redirect_uri=absolute_redirect_uri, state=state)
    logging.info(f"authnz_get_3LO_token: AUTHCODEURL:{authcodeurl}")
    logging.info(
        f"authnz_get_3LO_token: And now the app is setup to act on behalf of the user.")

    AUTHN_BB_JSON = jsonpickle.encode(AUTHN_BB)
    request.session['AUTHN_BB_JSON'] = AUTHN_BB_JSON

    return HttpResponseRedirect(authcodeurl)


# HTTP Error handling:
class makeRequestHTTPError(Exception):
    def __init__(self, code, message):
        self.code = code
        self.message = message
    def __str__(self):
        return repr(self.code + ": " + self.message)
