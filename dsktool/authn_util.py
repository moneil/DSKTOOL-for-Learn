# Django imports
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

# app imports
from dsktool.jwt_token_util import Jwt_token_util


# class Auth_Util:

logging.basicConfig(
    format='%(asctime)s %(levelname)-8s %(message)s',
    level=logging.DEBUG,
    datefmt='%Y-%m-%d %H:%M:%S')

# if AUTHN_BB_JSON == None:
#     try:
#         AUTHN_BB = BbRest(str(AUTHN_KEY), str(AUTHN_SECRET), f"https://{AUTHN_LEARNFQDN}")
#         AUTHN_BB_JSON = jsonpickle.encode(AUTHN_BB)
#         logging.info('AUTHN_UTIL: Pickled BbRest as AUTHN_BB_JSON.')

#     except BaseException as err:
#         logging.critical(
#             'AUTHN_UTIL: Critical error setting up BbREST, Check Configuration AUTHN_KEY and AUTHN_SECRET.')
#         print(f"Unexpected {err=}, {type(err)=}")

# def __init__(self):
print("AUTHN_UTIL: in init")

# bb_refreshToken
AUTHN_BB = None
AUTHN_BB_JSON = None
ISAUTHNVALIDROLE = False
ISAUTHNGUESTUSER = True
bb_refreshToken = None
AUTHN_EXPIRE_AT = None
AUTHN_START_EXPIRE = None
AUTHN_ROLE = None
AUTHN_KEY = None
AUTHN_SECRET = None
AUTHN_LEARNFQDN = None

try:
    from config import adict
    print("AUTHN INIT: using config.py...")
    AUTHN_KEY = adict['APPLICATION_KEY']
    AUTHN_SECRET = adict['APPLICATION_SECRET']
    AUTHN_LEARNFQDN = adict['BLACKBOARD_LEARN_INSTANCE']
except:
    print("AUTHN INIT: using env settings...")
    AUTHN_KEY = os.environ['APPLICATION_KEY']
    AUTHN_SECRET = os.environ['APPLICATION_SECRET']
    AUTHN_LEARNFQDN = os.environ['BLACKBOARD_INSTANCE']

# print("AUTHN INIT: AUTHN_KEY: ", AUTHN_KEY)
# print("AUTHN INIT: AUTHN_SECRET: ", AUTHN_SECRET)
# print("AUTHN INIT: AUTHN_LEARNFQDN: ", AUTHN_LEARNFQDN)

# try:
#     AUTHN_BB = BbRest(str(AUTHN_KEY), str(AUTHN_SECRET), f"https://{AUTHN_LEARNFQDN}")
#     AUTHN_BB_JSON = jsonpickle.encode(AUTHN_BB)
#     print("AUTHN INIT: Pickled BbRest as AUTHN_BB_JSON.")

# except BaseException as err:
#     print("AUTHN_UTIL: Critical error setting up BbREST, Check Configuration AUTHN_KEY and AUTHN_SECRET.")
#     print(f"Unexpected {err=}, {type(err)=}")

def authN(request, target_view):
    # We need AUTHN_BB_JSON and AUTHN_BB to proceed
    # once 3LO is complete we GET the user (me) and determine if they are a valid user
    # if not we send them to the page indicating they cannot access the application.
    # if they are then we generate their jwt token...
    # and return them to their target page/API.

    global AUTHN_BB
    global AUTHN_BB_JSON
    global ISAUTHNVALIDROLE
    global ISAUTHNGUESTUSER
    global AUTHN_EXPIRE_AT
    global AUTHN_START_EXPIRE
    global AUTHN_ROLE

    jwt_token = None
    jwtClaims = None

    logging.info('AUTHN_UTIL: ENTER.')
    logging.info('AUTHN_UTIL: START: ISAUTHNVALIDROLE: ' + str(ISAUTHNVALIDROLE) + ':: ISAUTHNGUESTUSER: ' + str(ISAUTHNGUESTUSER))

    # BbRestSetup(request, 'index', True)
    obj_now = datetime.utcnow()

    # if (requests.request headers.get['X_AUTH_TOKEN']):
    #     logging.info('AUTHN_UTIL: X_AUTH_TOKEN:' + str(request.META['X_AUTH_TOKEN']))
    #     logging.info('CHECK IF VALID AND ...')
    #     logging.info('SKIP AUTH AND USE TOKEN FOR ACCESS UNTIL EXPIRED')
    #     logging.info('OR REAUTH')

    if "AUTHN_BB_JSON" not in request.session.keys(): #or AUTHN_BB_JSON is None:
        logging.info('AUTHN_UTIL: BbRest not found in session')
        # logging.info('AUTHN_UTIL: AUTHN_KEY: ' + str(AUTHN_KEY))
        # logging.info('AUTHN_UTIL: AUTHN_SECRET: ' + str(AUTHN_SECRET))
        request.session['apiKey'] = AUTHN_KEY
        request.session['apiSecret'] = AUTHN_SECRET
        request.session['learnFQDN'] = AUTHN_LEARNFQDN
        logging.info(f'AUTHN_UTIL: session.keys: {request.session.keys()}')


        try:
            AUTHN_BB = BbRest(AUTHN_KEY, AUTHN_SECRET, f"https://{AUTHN_LEARNFQDN}" )
            AUTHN_BB_JSON = jsonpickle.encode(AUTHN_BB)
            request.session['AUTHN_BB_JSON'] = AUTHN_BB_JSON
            request.session['target_view'] = target_view 
            logging.info('AUTHN_UTIL: Pickled BbRest (AUTHN_BB_JSON) added to session.')
            logging.info('AUTHN_UTIL: NO BB ON SESSION STARTING FROM SCRATCH: CALL authn_get_3LO_token')
            return HttpResponseRedirect(reverse('authn_get_3LO_token'))
        except:
            logging.critical('AUTHN_UTIL: Could not set BbREST in Session, Check Configuration KEY and SECRET.')
        # except BaseException as err:
        #     logging.critical(
        #         'AUTHN_UTIL: Could not set BbREST in Session, Check Configuration AUTHN_KEY and AUTHN_SECRET.')
            # print(f"Unexpected {err=}, {type(err)=}")
    else:
        logging.info('AUTHN_UTIL: Found BbRest in session')

        # redirect_uri = reverse(authn_get_API_token)

        # absolute_redirect_uri = f"https://{request.get_host()}{redirect_uri}"

        AUTHN_BB_JSON = request.session['AUTHN_BB_JSON']

        # code = request.GET.get('code', default=None)

        # if (code == None):
        #     exit()

        # user_bb = BbRest(AUTHN_KEY, AUTHN_SECRET, f"https://{AUTHN_LEARNFQDN}", code=code, redirect_uri=absolute_redirect_uri)
        # AUTHN_BB_JSON = jsonpickle.encode(user_bb)

        ISAUTHNGUESTUSER = isAUTHNGuestUser(AUTHN_BB_JSON)
        ISAUTHNVALIDROLE = isAUTHNValidRole(AUTHN_BB_JSON)
        logging.info(f'AUTHN_UTIL: : ISAUTHNGUESTUSER: {ISAUTHNGUESTUSER}...ISAUTHNVALIDROLE: {ISAUTHNVALIDROLE}')

        AUTHN_BB = jsonpickle.decode(AUTHN_BB_JSON)
        logging.debug("AUTHN_UTIL: AUTHN_BB_JSON: Original Token Info: " +
                      str(AUTHN_BB.token_info))
        if not ISAUTHNVALIDROLE:
            logging.info('AUTHN_UTIL: NO VALID ROLE - Get 3LO and confirm role.')
            logging.info('AUTHN_UTIL: CALL authn_get_3LO_token')
            # logging.debug(
                # "AUTHN_UTIL: ISAUTHNVALIDROLE=FALSE: Updated Token Info: " + str(AUTHN_BB.token_info))
            return HttpResponseRedirect(reverse('authn_get_3LO_token'))
        
        if AUTHN_BB.is_expired():
            logging.info('AUTHN_UTIL: Expired API Auth Token.')
            logging.info('AUTHN_UTIL: GET A NEW API Auth Token')
            # AUTHN_BB.expiration()
            AUTHN_BB.refresh_token()
            # AUTHN_EXPIRE_AT = None
            AUTHN_BB_JSON = jsonpickle.encode(AUTHN_BB)
            request.session['AUTHN_BB_JSON'] = AUTHN_BB_JSON
            request.session['target_view'] = target_view
        AUTHN_BB.supported_functions()  # This and the following are required after
        AUTHN_BB.method_generator()    # unpickling the pickled object.
    # logging.debug("AUTHN_UTIL: AUTHN_BB_JSON: Final Token Info: " + str(AUTHN_BB.token_info))
    logging.info(f'AUTHN_UTIL: Token expiration: {AUTHN_BB.expiration()}')
    resp = AUTHN_BB.GetVersion()
    access_token = AUTHN_BB.token_info['access_token']
    refresh_token = AUTHN_BB.token_info.get('refresh_token')
    token_expiry = str(AUTHN_BB.expiration())[3:]
    version_json = resp.json()

    context = {
        'learn_server': AUTHN_LEARNFQDN,
        'version_json': version_json,
        'access_token': access_token,
        'refresh_token': refresh_token,
        'token_expiry': token_expiry,
        'expire_from': AUTHN_EXPIRE_AT,
        'jwt_token': "No Token",
    }

    logging.info(f'AUTHN_UTIL: AFTER 3LO: ISAUTHNGUESTUSER: {ISAUTHNGUESTUSER}...ISAUTHNVALIDROLE: {ISAUTHNVALIDROLE}')

    resp = AUTHN_BB.call('GetUser', userId="me", params={'fields': 'userName, uuid, externalId, contact.email'}, sync=True)
    user_json = resp.json()
    logging.info(user_json)
    request.session['userJSON'] = user_json
    logging.info(f'AUTHN_UTIL:authN: session.keys: {request.session.keys()}')

    jwt_utils = Jwt_token_util()

    if (not ISAUTHNGUESTUSER and ISAUTHNVALIDROLE):
        logging.info('AUTHN_UTIL: VALID USER SET JWT')

        resp = AUTHN_BB.call('GetUser', userId="me", params={
                       'fields': 'userName, uuid, externalId, contact.email'}, sync=True)
        user_json = resp.json()

        logging.info(user_json)

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
            'exp': datetime.now(tz=timezone.utc) + timedelta(minutes=3),
            'iat': datetime.now(tz=timezone.utc),
            'xsrfToken': uuid.uuid4().hex,
            'jti': uuid.uuid4().hex,
            'sub': user_json['uuid'],
            'userName': user_json['userName'],
            'userRole': AUTHN_ROLE,
            'userUuid': user_json['uuid'],
            'userEmail': user_json['contact']['email'],
        }

        logging.info(f"AUTHN_UTIL:JWTCLAIMS:")
        logging.info(f"{jwtClaims}")

        jwt_token = jwt_utils.create_jwt(jwtClaims)

        context = {
            'learn_server': AUTHN_LEARNFQDN,
            'version_json': version_json,
            'access_token': access_token,
            'refresh_token': refresh_token,
            'token_expiry': token_expiry,
            'expire_from': AUTHN_EXPIRE_AT,
            'jwt_token': jwt_token,
        }

    # The above updates the JWT every time vs only once if it exists.
    template = loader.get_template(target_view+'.html')
    response = HttpResponse(template.render(context))

    jwt_token = jwt_utils.create_jwt(jwtClaims)

    # jwtSessionCookies = request.COOKIES
    jwtSessionCookies = request.session.keys()
    logging.info(f"AUTHN_UTIL:SESSION:COOKIES/KEYS")
    logging.info(f"{jwtSessionCookies}")

    # if (not 'JWT' in request.COOKIES):
    if (not 'JWT' in request.session.keys()):
        logging.info(f"AUTHN_UTIL:SESSION:NO JWT ADD IT")
        logging.info(f"JWTTOKENTOADD:{jwt_token}")
        # response.set_cookie('JWT', jwt_token)
        request.session['JWT'] = jwt_token
    else:
        # add validation code for refresh if require and update if necessary, for now roll with what we have..,
        # token_from_cookies = request.COOKIES['JWT']
        token_from_cookies = request.session['JWT']

        logging.info(f"AUTHN_UTIL:SESSIONJWT:{token_from_cookies}")
        # logging.info(f'AUTHN_UTIL:CONTEXTJWTTOKEN:{context["jwt_token"]}')
        # response.set_cookie('JWT', jwt_token)
        request.session['JWT'] = jwt_token

    # logging.info(f'JWTTOKEN-ISSUED:{jwtClaims["iat"]}')
    # logging.info(f'JWTTOKEN-EXPIRES:{jwtClaims["exp"]}')
    # timeremaining = (jwtClaims["iat"]+timedelta(minutes=1)
    #                  )-datetime.now(tz=timezone.utc)
    # logging.info(f'TIME REMAINING: {timeremaining}')
    logging.info('AUTHN_UTIL: Exiting authN block... ')

    return response  # render(request, 'index.html', context)

def isAUTHNValidRole(BB_JSON):
    global ISVALIDROLE

    ISVALIDROLE=False

    validRoles=['SystemAdmin']
    VALIDROLE=False

    BB = jsonpickle.decode(BB_JSON)
    resp = BB.call('GetUser', userId = "me", params = {'fields':'userName, systemRoleIds'}, sync=True ) 
    
    user_json = resp.json()

    userSystemRoles = user_json['systemRoleIds']
    #logging.debug("userSystemRoles: " + json.dumps(userSystemRoles))
    for role in userSystemRoles:
        if role in validRoles:
            logging.debug("ISVALIDROLE: ValidRole: " + role)
            VALIDROLE=True

    ISVALIDROLE=VALIDROLE
    logging.debug("ISVALIDROLE: boolean: " + str(ISVALIDROLE))

    return VALIDROLE

# [DONE]
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

    logging.debug("ISGUESTUSER:: boolean: " + str(ISGUESTUSER))
    return guestStatus

def isAUTHNAuthorized(request):
    token_utils = Jwt_token_util()

    token = None
    if ('JWT' in request.session.keys()):
    # if ('JWT' in request.COOKIES):
        # if (token_utils.isVerified(request.COOKIES['JWT'])):
        if (token_utils.isVerified(request.session['JWT'])):
            # token = request.COOKIES['JWT']
            token = request.session['JWT']

        else:
            print("AUTHN_UTIL: ISAUTHORIZED: TOKEN INVALID")
    else:
        # not authenticated (no jwt)
        # perform 3LO:
        #   if user authenticates and user has a valid role of system admin then
        #       build jwt and return
        #       caller then places jwt into response and we are done
        #   else
        #       user cannot authenticate or has an invalid role
        #       return empty token indicating not authorized.
        print("AUTHN_UTIL: OF COURSE THIS IS GOING TO FAIL THERE IS NO TOKEN")

        # return "GETTING NEW TOKEN"

    return token

# 3LO below...
def authn_get_API_token(request):
    global AUTHN_BB_JSON
    global AUTHN_BB

    # Happens when the user hits index the first time and hasn't authenticated on Learn
    # Part II. Get an access token for the user that logged in. Put that on their session.
    AUTHN_BB_JSON = request.session.get('AUTHN_BB_JSON')
    target_view = request.session.get('target_view')
    logging.info('AUTHN_UTIL: authn_get_API_token: got BbRest from session')
    logging.info('AUTHN_UTIL: authn_get_API_token: got target_view from session: {target_view}')
    
    AUTHN_BB = jsonpickle.decode(AUTHN_BB_JSON)
    AUTHN_BB.supported_functions()  # This and the following are required after
    AUTHN_BB.method_generator()    # unpickling the pickled object.
    # Next, get the code parameter value from the request
    redirect_uri = reverse(authn_get_API_token)
    absolute_redirect_uri = f"https://{request.get_host()}{redirect_uri}"

    state = request.GET.get('state', default="NOSTATE")
    logging.info(f'AUTHN_UTIL: authn_get_API_token: GOT BACK state: {state}')
    stored_state = request.session.get('state')
    logging.info(f'AUTHN_UTIL: authn_get_API_token: STORED STATE: {stored_state}')
    if (stored_state != state):
        return HttpResponseRedirect(reverse('notauthorized'))

    code = request.GET.get('code', default=None)
    if (code == None):
        exit()

    user_bb = BbRest(
        AUTHN_KEY, AUTHN_SECRET, f"https://{AUTHN_LEARNFQDN}", code=code, redirect_uri=absolute_redirect_uri)

    AUTHN_BB_JSON = jsonpickle.encode(user_bb)
    # logging.info(f'GETAPITOKEN::USER_AUTHN_BB: {AUTHN_BB_JSON}')

    request.session['AUTHN_BB_JSON'] = AUTHN_BB_JSON

    if (isAUTHNGuestUser(AUTHN_BB_JSON)):
        print("GUEST USER!!!")
        context = {
            'learn_server': AUTHN_LEARNFQDN,
        }
        return render(request, 'guestusernotallowed.html', context=context)

    if (not isAUTHNValidRole(AUTHN_BB_JSON)):
        print("IS NOT VALID USER")
        # return notauthorized page
        return render(request, 'notauthorized.html')

    # obj_now = datetime.now().astimezone()
    obj_now = datetime.utcnow()
    isDST = time.localtime().tm_isdst
    # logging.info("GETAPITOKEN: ISDST: " + str(isDST))
    AUTHN_START_EXPIRE = obj_now
    if not isDST:
        # logging.info('GETAPITOKEN: NOT DST!')
        obj_now = obj_now - timedelta(minutes=60)
    token_expiry = str(AUTHN_BB.expiration())[3:]
    expireTime = obj_now + timedelta(minutes=59)
    AUTHN_EXPIRE_AT = str(expireTime.hour).zfill(2) + ":" + \
        str(expireTime.minute).zfill(2) + " (UTC)"

    logging.info('AUTHN_UTIL: authn_get_API_token: pickled BbRest and putting it on session')
    request.session['AUTHN_BB_JSON'] = AUTHN_BB_JSON

    return HttpResponseRedirect(reverse(f'{target_view}'))

# [DONE]
def authn_get_3LO_token(request):
    global AUTHN_BB_JSON
    global AUTHN_BB

    print("ENTER AUTHN_UTIL::AUTHN_GET_3LO_TOKEN")

    # Happens when the user hits index the first time and hasn't authenticated on Learn
    # Part I. Request an authorization code oauth2/authorizationcode
    # logging.info(
    #     f"authn_get_3LO_token: REQUEST URI:{request.build_absolute_uri()}")
    try:
        AUTHN_BB_JSON = request.session.get('AUTHN_BB_JSON')
        logging.info('authn_get_3LO_token: got BbRest from session')
        AUTHN_BB = jsonpickle.decode(AUTHN_BB_JSON)
    except:
        # sideways session go to index page and force authn_get_API_token
        logging.info(
            f"authn_get_3LO_token: Something went sideways with AUTHN_BB session, reverse to target e.g. 'index', maybe you should have thrown an error here.")
        return HttpResponseRedirect(reverse('authzpage'))

    AUTHN_BB.supported_functions()  # This and the following are required after
    AUTHN_BB.method_generator()    # unpickling the pickled object.
    # The following gives the path to the resource on the server where we are running,
    # but not the protocol or host FQDN. We need to prepend those to get an absolute redirect uri.
    redirect_uri = reverse(authn_get_API_token)
    absolute_redirect_uri = f"https://{request.get_host()}{redirect_uri}"
    state = str(uuid.uuid4())
    request.session['state'] = state
    authcodeurl = AUTHN_BB.get_auth_url(
        scope='read write delete offline', redirect_uri=absolute_redirect_uri, state=state)
    # authcodeurl = AUTHN_BB.get_auth_url(scope='read write delete', redirect_uri=absolute_redirect_uri, state=state)
    # logging.info(f"authn_get_3LO_token: AUTHCODEURL:{authcodeurl}")
    logging.info(
        f"authn_get_3LO_token: And now the app is setup to act on behalf of the user.")

    AUTHN_BB_JSON = jsonpickle.encode(AUTHN_BB)
    request.session['AUTHN_BB_JSON'] = AUTHN_BB_JSON

    return HttpResponseRedirect(authcodeurl)



def isAUTHNValidRole(AUTHN_BB_JSON):
    global ISAUTHNVALIDROLE
    global AUTHN_ROLE

    print("ENTER isAUTHNValidRole...")

    ISAUTHNVALIDROLE = False
    print("INITIAL GLOBAL ISAUTHNVALIDROLE::", ISAUTHNVALIDROLE)

    validRoles = ['SystemAdmin']
    VALIDROLE = False
    print("INITIAL LOCAL VALIDROLE::", VALIDROLE)

    AUTHN_BB = jsonpickle.decode(AUTHN_BB_JSON)
    for authn_bb_key in AUTHN_BB:
        print (authn_bb_key) 

    resp = AUTHN_BB.call('GetUser', userId="me", params={
        'fields': 'userName, systemRoleIds'}, sync=True)

    user_json = resp.json()

    userSystemRoles = user_json['systemRoleIds']
    #logging.debug("userSystemRoles: " + json.dumps(userSystemRoles))
    for role in userSystemRoles:
        if role in validRoles:
            logging.debug("isAUTHNValidRole: ISAUTHNVALIDROLE: ValidRole: " + role)
            VALIDROLE = True
            ROLE = role

    ISAUTHNVALIDROLE = VALIDROLE
    logging.debug("isAUTHNValidRole: ISAUTHNVALIDROLE: boolean: " + str(ISAUTHNVALIDROLE))
    print("EXIT isAUTHNValidRole...return VALIDROLE:", VALIDROLE)

    return VALIDROLE


# HTTP Error handling:
class makeRequestHTTPError(Exception):
    def __init__(self, code, message):
        self.code = code
        self.message = message
    def __str__(self):
        return repr(self.code + ": " + self.message)
