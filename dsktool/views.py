from urllib import response
from django.http import HttpResponse
from django.http import HttpResponseRedirect
# from django.http import HttpRequest
from django.http import JsonResponse
from django.shortcuts import render
from django.shortcuts import redirect
from django.urls import reverse
from django.views.decorators.cache import never_cache
from django.template import loader, Template
from django.http import StreamingHttpResponse


from bbrest import BbRest
import jsonpickle
import json
from datetime import datetime, timedelta
import time
import pytz
from dsktool.rfc import Rfc
from dsktool.models import Messages
from dsktool.models import Logs
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger

# python imports
import logging
from datetime import datetime, timedelta, timezone
import time
import os
import uuid
import requests
import socket
import csv
from zipfile import *
import io
from wsgiref.util import FileWrapper


# my modules
from dsktool.jwt_token_util import Jwt_token_util
# from dsktool.authn_util import Authn_util
# import dsktool.authn_util
from config import adict
# from dsktool.authn_util import authN, authn_get_API_token, authn_get_3LO_token, isAUTHNValidRole, isAUTHNGuestUser
# from dsktool.authn_authz_utils import Auth_Utils
import dsktool.authn_authz_utils


# Globals
# BB: BbRest object - required for all BbRest requests
# AUTHN_BB_JSON: BbRest session details
# ISGUESTUSER: 3LO'd as a guest user

# global BB
# global AUTHN_BB_JSON
# global ISGUESTUSER
# global ISVALIDROLE
# global EXPIRE_AT
# global START_EXPIRE
# global ROLE

# BB = None
# AUTHN_BB_JSON = None
# ISVALIDROLE = False
# ISGUESTUSER = True
# bb_refreshToken = None
# EXPIRE_AT = None
# START_EXPIRE = None
# ROLE = None

# Pull configuration... use env settings if no local config file
try:
    from config import adict

    logging.info("VIEWS: using config.py...")

    KEY = adict['APPLICATION_KEY']
    SECRET = adict['APPLICATION_SECRET']
    LEARNFQDN = adict['BLACKBOARD_LEARN_INSTANCE']

except:
    logging.info("VIEWS: using env settings...")

    KEY = os.environ['APPLICATION_KEY']
    SECRET = os.environ['APPLICATION_SECRET']
    LEARNFQDN = os.environ['BLACKBOARD_LEARN_INSTANCE']

logging.basicConfig(
    format='%(asctime)s %(levelname)-8s %(message)s',
    level=logging.INFO,
    datefmt='%Y-%m-%d %H:%M:%S')

# HTTP Error handling:


class makeRequestHTTPError(Exception):
    def __init__(self, code, message):
        self.code = code
        self.message = message

    def __str__(self):
        return repr(self.code + ": " + self.message)


# def isValidRole(AUTHN_BB_JSON):
#     global ISVALIDROLE
#     global ROLE

#     ISVALIDROLE = False

#     validRoles = ['SystemAdmin']
#     VALIDROLE = False

#     BB = jsonpickle.decode(AUTHN_BB_JSON)
#     resp = BB.call('GetUser', userId="me", params={
#                    'fields': 'userName, systemRoleIds'}, sync=True)

#     user_json = resp.json()

#     userSystemRoles = user_json['systemRoleIds']
#     #logging.debug("userSystemRoles: " + json.dumps(userSystemRoles))
#     for role in userSystemRoles:
#         if role in validRoles:
#             logging.debug("ISVALIDROLE: ValidRole: " + role)
#             VALIDROLE = True
#             ROLE = role

#     ISVALIDROLE = VALIDROLE
#     logging.debug("ISVALIDROLE: boolean: " + str(ISVALIDROLE))

#     return VALIDROLE

# [DONE]


# def isGuestUser(AUTHN_BB_JSON):
#     global ISGUESTUSER

#     guestStatus = False

#     BB = jsonpickle.decode(AUTHN_BB_JSON)
#     resp = BB.call('GetUser', userId="me", params={
#                    'fields': 'userName'}, sync=True)

#     user_json = resp.json()

#     logging.debug(f"ISGUESTUSER::userName: {user_json['userName']}")

#     if user_json['userName'] == 'guest':
#         guestStatus = True
#         ISGUESTUSER = True
#     else:
#         guestStatus = False
#         ISGUESTUSER = False

#     logging.debug("ISGUESTUSER:: boolean: " + str(ISGUESTUSER))
#     return guestStatus

def getBBRest(request):
    BBR = jsonpickle.decode(request.session['AUTHN_BB_JSON'])
    BBR.supported_functions()  # This and the following are required after
    BBR.method_generator()    # unpickling the pickled object.
        
    # logging.info(f'WHOAMI: API Token expiration: {BB.expiration()}')
    if BBR.is_expired():
        logging.info('GETBBREST: Expired API Auth Token.')
        logging.info('GETBBREST: GET A NEW API Auth Token')
        BBR.refresh_token()
        # EXPIRE_AT = None
        AUTHN_BB_JSON = jsonpickle.encode(BBR)
        request.session['AUTHN_BB_JSON'] = AUTHN_BB_JSON

    return BBR


# Desired Page behavior:
#   Original example contained two functions - one for 3LO and one for API auth.
#       get_auth_code - for API Auth
#       get_access_token - for 3LO setup.
#   on loading index (same for every page):
#   if there is no BbREST instance (BB) on the session as identified by AUTHN_BB_JSON then
#       instantiate BbREST which sets two things: 3LO and access_token for API use:
#           1. Validate 3LO for user
#               if there is no valid refresh_token then the user is directed to log
#               into Learn
#           2. Validate that the user is a System Admin and set VALIDROLE True||False
#               2.1 This validation makes a user request - BbREST should set a valid
#                   API access token on the session as a result of this request.
#   if there is a valid BbREST instance: session BB!=None as indicated by AUTHN_BB_JSON!=None then
#            1. We /should/ not have to do anything because BbREST /should/ update expired
#               access_tokens automatically on subsequent REST requests.
#            But 1. does not appear to be working - immediately log expired tokens and make
#            a system request to try and get a new token.
# BbREST object and AUTHN_BB_JSON:
#   We need a valid instantiation of BbREST and a valid AUTHN_BB_JSON...
#   1. instantiate BbREST and set a global variable via:
#      BB = BbRest(KEY, SECRET, f"https://{LEARNFQDN}" )
#      OR
#      should we just instantiate everything via a call to get_auth_code which appears to
#      do both 3LO and access_token management?

# [DONE] Index page loader: Authorizes user after AuthN if necessary
@never_cache
def index(request):
    response = None
    context = None

    logging.info(f'INDEX: session.keys: {request.session.keys()}\n')

    if dsktool.authn_authz_utils.isAuthenticated(request) and dsktool.authn_authz_utils.isAuthorized(request):
        jwt_utils = Jwt_token_util()
        jwt_token = jwt_utils.getSessionJWT(request)
        
        context = {
            'learn_server': request.session['LEARNFQDN'],
            'version_json': request.session['LEARNVERSIONJSON'],
            'access_token': request.session['ACCESSTOKEN'],
            'refresh_token': request.session['REFRESHTOKEN'],
            'token_expiry': request.session['TOKENEXPIRY'],
            'jwt_token': request.session['JWT'],
            'decoded_token': jwt_utils.decodeJWT(jwt_token),
        }

        template = loader.get_template('index.html')
        response = HttpResponse(template.render(context))
        jwt_utils = None
    else:
        logging.info(
            f'AUTHN_AUTHZ_UTILS: AUTHN or AUTHZ FAILED! ... AUTHENTICATING!')
        response = dsktool.authn_authz_utils.authenticate(
            request, target='index')

    return response

# [DONE] WHOAMI returns the current user info/status
@never_cache
def whoami(request):
    response = None
    context = None

    logging.info(f'WHOAMI: session.keys: {request.session.keys()}')

    if dsktool.authn_authz_utils.isAuthenticated(request) and dsktool.authn_authz_utils.isAuthorized(request):
        jwt_utils = Jwt_token_util()
        jwt_token = jwt_utils.getSessionJWT(request)

        BB = getBBRest(request)

        dskresp = BB.GetDataSource(dataSourceId=request.session['userJSON']['dataSourceId'], sync=True)
        dsk_json = dskresp.json()
        request.session['userJSON']['dataSourceExternalId'] = dsk_json['externalId']

        # logging.info(f'WHOAMI: userJSON:dataSourceExternalId: {request.session["userJSON"]["dataSourceExternalId"]}')

        context = {
            'user_json': request.session['userJSON'],
            'dataSourceExternalId': request.session['userJSON']['dataSourceExternalId'],
            'jwt_token': request.session['JWT'],
            'decoded_jwt': jwt_utils.decodeJWT(jwt_token),
        }

        template = loader.get_template('whoami.html')
        response = HttpResponse(template.render(context))
        jwt_utils = None
    else:
        logging.info(f'WHOAMI: AUTHN or AUTHZ FAILED! ... AUTHENTICATING!')
        response = dsktool.authn_authz_utils.authenticate(
            request, target='whoami')

    # Render the HTML template index.html with the data in the context variable
    # return render(request, 'whoami.html', context)

    return response


# [DONE] Courses page loader: TASK BASED
@never_cache
def courses(request):
    response = None
    context = None

    logging.info(f'COURSES: session.keys: {request.session.keys()}\n')

    if dsktool.authn_authz_utils.isAuthenticated(request) and dsktool.authn_authz_utils.isAuthorized(request):
        jwt_utils = Jwt_token_util()
        jwt_token = jwt_utils.getSessionJWT(request)

        BB = getBBRest(request)

        task = request.GET.get('task')
        searchBy = request.GET.get('searchBy')
        searchValue = request.GET.get('searchValue')
        if (searchValue is not None):
            searchValue = searchValue.strip()
        logging.info(f"COURSES: SEARCHBY: {searchBy}")
        logging.info(f"COURSES: SEARCHVALUE: {searchValue}")
        logging.info(f"COURSES: TASK: {task}")

        if (task == 'search'):
            # Process request...
            logging.info(f"COURSES:COURSE REQUEST: ACTION {task}")
            searchValue = request.GET.get('searchValue')
            if (searchValue is not None):
                searchValue = searchValue.strip()

            logging.debug(f"COURSES: COURSE REQUEST: CRS: {searchValue}")
            logging.debug(f"Process by {searchBy}")
            if (searchBy == 'externalId'):
                crs = "externalId:" + searchValue
                logging.debug(f"COURSES: COURSE REQUEST: course pattern: {crs}")
            elif (searchBy == 'primaryId'):
                crs = searchValue
                logging.debug(f"COURSES: COURSE REQUEST: course pattern: {crs}")
            elif (searchBy == 'courseId'):
                crs = "courseId:" + searchValue
                logging.debug(f"COURSES: COURSE REQUEST: course pattern: {crs}")
            
            resp = BB.GetCourse(courseId=crs, params={
                                'fields': 'id, courseId, externalId, name, availability.available, dataSourceId, created'}, sync=True)
            
            if (resp.status_code == 200):
                course_json = resp.json()
                dskresp = BB.GetDataSource(
                    dataSourceId=course_json['dataSourceId'], sync=True)
                dsk_json = dskresp.json()
                course_json['dataSourceId'] = dsk_json['externalId']
                course_json['searchValue'] = searchValue
                course_json['searchBy'] = searchBy
                dskresp = BB.GetDataSources(
                    limit=5000, params={'fields': 'id, externalId'}, sync=True)
                dsks_json = dskresp.json()
                logging.debug("COURSES: COURSE REQUEST: DSKS:\n",
                            dsks_json["results"])
                dsks = dsks_json["results"]
                dsks = sortDsk(dsks, 'externalId')
                logging.debug(
                    "COURSES: COURSE REQUEST: SIZE OF DSK LIST:", len(dsks))

                context = {
                    'course_json': course_json,
                    'dsks_json': dsks,
                }
            else:
                error_json = resp.json()
                logging.debug(f"COURSES: COURSE REQUEST: RESPONSE:\n", error_json)
                context = {
                    'error_json': error_json,
                }
            # complete the course search, created context from the results and calling course.html
            # return render(request, 'courses.html', context=context)
            template = loader.get_template('courses.html')
            response = HttpResponse(template.render(context))

        if (task == 'process'):
            logging.debug(f"COURSES: COURSE REQUEST: ACTION {task}")
            logging.debug(f"COURSES: COURSE REQUEST: Process by {searchBy}")
            logging.debug('COURSES: COURSE REQUEST: Request:\n ')
            logging.debug(request)
            payload = {}
            if (request.GET.get('isAvailabilityUpdateRequired1')):
                if (request.GET.get('isAvailabilityUpdateRequired1') == 'true'):
                    payload = {'availability': {
                        "available": request.GET.get('selectedAvailability')}}
            if (request.GET.get('isDataSourceKeyUpdateRequired1')):
                if (request.GET.get('isDataSourceKeyUpdateRequired1') == 'true'):
                    payload["dataSourceId"] = request.GET.get(
                        'selectedDataSourceKey')

            logging.debug("COURSES: COURSE REQUEST: PAYLOAD\n")
            for x, y in payload.items():
                logging.debug(x, y)

            # Build and make BB request...
            if (searchBy == 'externalId'):
                crs = "externalId:" + searchValue
            elif (searchBy == 'primaryId'):
                crs = searchValue
                logging.debug(f"COURSES: COURSE REQUEST: course pattern: {crs}")
            elif (searchBy == 'courseId'):
                crs = "courseId:" + searchValue
                logging.debug(f"COURSES: COURSE REQUEST: course pattern: {crs}")

            logging.debug(f"COURSES: COURSE REQUEST: course pattern: {crs}")

            resp = BB.UpdateCourse(courseId=crs, payload=payload, params={
                                'fields': 'id, courseId, externalId, name, availability.available, dataSourceId, created'}, sync=True)
            if (resp.status_code == 200):
                result_json = resp.json()  # return actual error
                dskresp = BB.GetDataSource(
                    dataSourceId=result_json['dataSourceId'], sync=True)
                dsk_json = dskresp.json()
                result_json['dataSourceId'] = dsk_json['externalId']

                context = {
                    'result_json': result_json,
                }
            else:
                error_json = resp.json()
                logging.debug(f"COURSES: COURSE REQUEST: RESPONSE:\n", error_json)
                context = {
                    'error_json': error_json,
                }

            # return render(request, 'courses.html', context=context)
            template = loader.get_template('courses.html')
            response = HttpResponse(template.render(context))

        if task is None:
            template = loader.get_template('courses.html')
            response = HttpResponse(template.render(context))

        # dskresp = BB.GetDataSource(dataSourceId=request.session['userJSON']['dataSourceId'], sync=True)
        # dsk_json = dskresp.json()
        # request.session['userJSON']['dataSourceExternalId'] = dsk_json['externalId']

        # logging.info(f'WHOAMI: userJSON:dataSourceExternalId: {request.session["userJSON"]["dataSourceExternalId"]}')

        # context = {
        #     'user_json': request.session['userJSON'],
        #     'dataSourceExternalId': request.session['userJSON']['dataSourceExternalId'],
        #     'jwt_token': request.session['JWT'],
        #     'decoded_jwt': jwt_utils.decodeJWT(jwt_token),
        # }

        # template = loader.get_template('courses.html')
        # response = HttpResponse(template.render(context))
        # jwt_utils = None

    else:
        logging.info(f'COURSES: AUTHN or AUTHZ FAILED! ... AUTHENTICATING!')
        response = dsktool.authn_authz_utils.authenticate(
            request, target='courses')

    # Render the HTML template index.html with the data in the context variable
    # return render(request, 'courses.html', context)
    return response  #was: return render(request, 'courses.html')

# [DONE] Enrollments page loader: TASK BASED
@never_cache
def enrollments(request):
    response = None
    context = None

    # View function for site enrollments page.
    logging.info('ENROLLMENTS: ENTER ')

    if dsktool.authn_authz_utils.isAuthenticated(request) and dsktool.authn_authz_utils.isAuthorized(request):
        BB = getBBRest(request)

        task = request.GET.get('task')
        searchBy = request.GET.get('searchBy')

        if (task == 'search'):
            # Process request...
            logging.info(f"ENROLLMENTS REQUEST: ACTION {task}")
            searchValueCrs = request.GET.get('searchValueCrs')
            if (searchValueCrs is not None):
                searchValueCrs = searchValueCrs.strip()
            searchValueUsr = request.GET.get('searchValueUsr')
            if (searchValueUsr is not None):
                searchValueUsr = searchValueUsr.strip()
            logging.info(f"ENROLLMENTS REQUEST: CRS: {searchValueCrs}")
            logging.info(f"ENROLLMENTS REQUEST: USR: {searchValueUsr}")

            if (searchBy == 'byCrsUsr'):
                logging.info("Process by Course AND User")
                crs = "externalId:" + searchValueCrs
                usr = "externalId:" + searchValueUsr
                resp = BB.GetMembership(courseId=crs, userId=usr, params={
                                        'expand': 'user', 'fields': 'id, user.userName, user.name.given, user.name.middle, user.name.family, user.externalId, user.contact.email, availability.available, user.availability.available, dataSourceId, created'}, sync=True)
                if (resp.status_code == 200):
                    member_json = resp.json()
                    logging.info("MBRJSON:\n", member_json["results"])

                    dskresp = BB.GetDataSource(
                        dataSourceId=member_json['dataSourceId'], sync=True)
                    dsk_json = dskresp.json()
                    member_json['dataSourceId'] = dsk_json['externalId']
                    member_json['crsExternalId'] = searchValueCrs
                    member_json['usrExternalId'] = searchValueUsr
                    member_json['searchBy'] = searchBy
                    dskresp = BB.GetDataSources(
                        limit=5000, params={'fields': 'id, externalId'}, sync=True)
                    dsks_json = dskresp.json()
                    logging.info("DSKS:\n", dsks_json["results"])
                    dsks = dsks_json["results"]
                    dsks = sortDsk(dsks, 'externalId')
                    logging.info("SIZE OF DSK LIST:", len(dsks))

                    context = {
                        'member_json': member_json,
                        'dsks_json': dsks,
                    }
                else:
                    error_json = resp.json()
                    logging.info(f"RESPONSE:\n", error_json)
                    context = {
                        'error_json': error_json,
                    }
                logging.debug(
                    "EXITING ENROLLMENTS: searchBy task: search by byCrsUsr")

                # return render(request, 'enrollments.html', context=context)
                template = loader.get_template('enrollments.html')
                response = HttpResponse(template.render(context))

            elif (searchBy == 'byCrs'):
                logging.info("Process by Course Only")
                error_json = {
                    'message': 'Searching by Course is not currently supported'
                }
                logging.info(f"RESPONSE:\n", error_json)
                context = {
                    'error_json': error_json,
                }
                logging.debug(
                    "EXITING ENROLLMENTS: searchBy task: search by byCrs")

                # return render(request, 'enrollments.html', context=context)
                template = loader.get_template('enrollments.html')
                response = HttpResponse(template.render(context))

            elif (searchBy == 'byUsr'):
                logging.info("Process by User Only")
                error_json = {
                    'message': 'Searching by Course is not currently supported'
                }
                logging.info(f"RESPONSE:\n", error_json)
                context = {
                    'error_json': error_json,
                }
                logging.debug(
                    "EXITING ENROLLMENTS: searchBy task: search by byUsr")

                # return render(request, 'enrollments.html', context=context)
                template = loader.get_template('enrol{lments.html')
                response = HttpResponse(template.render(context))

            else:
                logging.info("Cannot process request")
                error_json = {
                    'message': 'Cannot process request'
                }
                logging.info(f"RESPONSE:\n", error_json)
                context = {
                    'error_json': error_json,
                }
                logging.debug("EXITING ENROLLMENTS: searchBy task: ERROR")

                # return render(request, 'enrollments.html', context=context)
                template = loader.get_template('enrollments.html')
                response = HttpResponse(template.render(context))

        elif (task == 'process'):
            # print incoming parameters and then afterward submit the patch request.

            if (searchBy == 'byCrsUsr'):
                logging.info("processing by crsusr")
                logging.info('Request:\n ')
                logging.info(request)

                payload = {}
                if (request.GET.get('isAvailabilityUpdateRequired1')):
                    if (request.GET.get('isAvailabilityUpdateRequired1') == 'true'):
                        payload = {'availability': {
                            "available": request.GET.get('selectedAvailability')}}
                if (request.GET.get('isDataSourceKeyUpdateRequired1')):
                    if (request.GET.get('isDataSourceKeyUpdateRequired1') == 'true'):
                        payload["dataSourceId"] = request.GET.get(
                            'selectedDataSourceKey')

                logging.info("PAYLOAD\n")
                for x, y in payload.items():
                    logging.info(x, y)

                # Build and make BB request...
                crs = "externalId:"+request.GET.get('crsExternalId')
                logging.info("crs:", crs)
                usr = "externalId:"+request.GET.get('usrExternalId')
                logging.info("usr", usr)

                resp = BB.UpdateMembership(courseId=crs, userId=usr, payload=payload, params={
                                        'expand': 'user', 'fields': 'id, user.userName, user.name.given, user.name.middle, user.name.family, user.externalId, user.contact.email, availability.available, user.availability.available, dataSourceId, created'}, sync=True)
                if (resp.status_code == 200):
                    result_json = resp.json()  # return actual error
                    dskresp = BB.GetDataSource(
                        dataSourceId=result_json['dataSourceId'], sync=True)
                    dsk_json = dskresp.json()
                    result_json['dataSourceId'] = dsk_json['externalId']

                    context = {
                        'result_json': result_json,
                    }
                else:
                    error_json = resp.json()
                    logging.info(f"RESPONSE:\n", error_json)
                    context = {
                        'error_json': error_json,
                    }

                logging.debug("EXITING ENROLLMENTS: Processing task: byCrsUsr")

                # return render(request, 'enrollments.html', context)
                template = loader.get_template('enrollments.html')
                response = HttpResponse(template.render(context))

        else:
            logging.debug("EXITING ENROLLMENTS: No task specified")

            # return render(request, 'enrollments.html')
            template = loader.get_template('enrollments.html')
            response = HttpResponse(template.render(context))
    else:
        logging.info(f'ENROLLMENTS: AUTHN or AUTHZ FAILED! ... AUTHENTICATING!')
        response = dsktool.authn_authz_utils.authenticate(request, target='enrollments')

    return response  #was: return render(request, 'enrollments.html')


# [DONE] Users page loader: no tasks - refactor others to same model
@never_cache
def users(request):
    # global BB
    # global AUTHN_BB_JSON
    # global EXPIRE_AT

    # View function for site enrollments page.
    logging.info('USERS: ENTER ')
    if dsktool.authn_authz_utils.isAuthenticated(request) and dsktool.authn_authz_utils.isAuthorized(request):

        BB = getBBRest(request)

        logging.info(f'API TOKEN EXPIRATION: {str(BB.expiration())[3:]}')
        logging.info(f'JWT TOKEN EXPIRATION: {getSessionJWTTimeRemaining(request)}')

        context = {
            'learn_server': request.session['LEARNFQDN'],
            'version_json': request.session['LEARNVERSIONJSON'],
        }

        template = loader.get_template('users.html')
        response = HttpResponse(template.render(context))
        #  template.RequestContext 

        return render(request, 'users.html')

    else:
        logging.info(f'USERS: AUTHN or AUTHZ FAILED! ... AUTHENTICATING!')
        response = dsktool.authn_authz_utils.authenticate(request, target='users')
        return response

    # return response  #was:     return render_to_response('index.html', context_instance=RequestContext(request))

# [DONE]
def isup(request):
    return render(request, 'isup.html')

# [DONE]
def learnlogout(request):
    # global BB
    # global AUTHN_BB_JSON
    # global ISVALIDROLE

    logging.info(
        "LEARNLOGOUT: Flushing session and redirecting to Learn for logout")
    site_domain = request.META['HTTP_HOST']
    response = HttpResponse("Cookies Cleared")
    response.delete_cookie(site_domain)
    # request.session['AUTHN_BB_JSON'] = None
    if "AUTHN_BB_JSON" in request.session.keys():
        logging.info('LEARNLOGOUT: Deleting session key AUTHN_BB_JSON')
        del request.session["AUTHN_BB_JSON"]
        # del request.session['AUTHN_BB_JSON']
        request.session.modified = True
        if "AUTHN_BB_JSON" in request.session.keys():
            logging.info('LEARNLOGOUT: AUTHN_BB_JSON not deleted?')
            for key, value in request.session.items():
                logging.info('{} => {}'.format(key, value))
    # ISVALIDROLE = False
    # BB = None
    # try:
    #     request.session.get(['AUTHN_BB_JSON'] is None:
    #     logging.info('LEARNLOGOUT: Session AUTHN_BB_JSON == None')
    # logging.info('LEARNLOGOUT: ISVALIDROLE: ' + str(ISVALIDROLE))
    request.session.clear()
    request.session.delete()
    request.session.clear_expired()
    request.session.flush()
    return HttpResponseRedirect(f"https://{LEARNFQDN}/webapps/login?action=logout")

# [DONE]
def notauthorized(request):
    context = {}
    return render(request, 'notauthorized.html', context=context)

# [DONE] Retrieve User data


def getUser(request):
    # returns a list of one user - saves on javascript side.

    searchBy = request.GET.get('searchBy')
    searchValueUsr = request.GET.get('searchValueUsr')
    if (searchValueUsr is not None):
        searchValueUsr = searchValueUsr.strip()
    logging.info("getUser: SEARCHBY: ", searchBy)
    logging.info("getUser: SEARCHVALUEUSR: ", searchValueUsr)

    usr = ''

    BB = getBBRest(request)

    if (searchBy == 'externalId'):
        usr = "externalId:" + searchValueUsr
    elif (searchBy == 'userName'):
        usr = "userName:" + searchValueUsr
    elif (searchBy == 'familyName'):
        usr = "name.family:" + searchValueUsr

    logging.info(f"user pattern: {usr}")

    # Process request...
    resp = BB.GetUser(userId=usr, params={
                    'fields': 'id, userName, name.given, name.middle, name.family, externalId, contact.email, availability.available, dataSourceId, created, modified'}, sync=True)
    if (resp.status_code == 200):
        user_json = resp.json()
        dskresp = BB.GetDataSource(
            dataSourceId=user_json['dataSourceId'], sync=True)
        dsk_json = dskresp.json()
        user_json['dataSourceId'] = dsk_json['externalId']
        user_json['searchValueUsr'] = searchValueUsr
        user_json['searchBy'] = searchBy
        dskresp = BB.GetDataSources(
            limit=5000, params={'fields': 'id, externalId'}, sync=True)
        dsks_json = dskresp.json()
        dsks = dsks_json["results"]
        dsks = sortDsk(dsks, 'externalId')

        context = {
            'user_json': user_json,
            'dsks_json': dsks,
        }

    else:
        error_json = resp.json()
        logging.info(f"RESPONSE:\n", error_json)
        context = {
            'error_json': error_json,
        }

    return JsonResponse(context)


# [DONE] Update User data
def updateUser(request):
    logging.info('USERS: ENTER ')

    # logging.info("UPDATE USER...")
    # logging.info('Request:\n ')
    # logging.info(request)
    # logging.info("isUpdateRequired1: ", request.GET.get("isUpdateRequired1"))
    # logging.info("isAvailabilityUpdateRequired1:", request.GET.get("isAvailabilityUpdateRequired1"))
    # logging.info("selectedAvailability: ", request.GET.get("selectedAvailability"))
    # logging.info("isDataSourceKeyUpdateRequired1: ", request.GET.get("isDataSourceKeyUpdateRequired1"))
    selectedDSK = request.GET.get("selectedDataSourceKey")
    # logging.info("selectedDataSourceKey: ", selectedDSK)
    updateValue = request.GET.get('pmcUserId[]')
    # logging.info("UPDATE VALUE: ", updateValue)

    BB = getBBRest(request)

    isFoundStatus = False
    passedPayload = {}

    if (request.GET.get('isAvailabilityUpdateRequired1')):
        if (request.GET.get('isAvailabilityUpdateRequired1') == 'true'):
            logging.info("AVAILABILITY UPDATE REQUIRED")
            passedPayload = {'availability': {
                "available": request.GET.get('selectedAvailability')}}
    if (request.GET.get('isDataSourceKeyUpdateRequired1')):
        if (request.GET.get('isDataSourceKeyUpdateRequired1') == 'true'):
            passedPayload["dataSourceId"] = request.GET.get(
                'selectedDataSourceKey')
            logging.info("DATASOURCE UPDATE REQUIRED")

    logging.info("PASSABLE PAYLOAD:\n", passedPayload)

    # ----------------------------------------------
    # get user data BEFORE the change
    # and insert message and log to local DB
    rfc = Rfc()
    message = rfc.save_message(request, "user")
    rfc.save_log(request=request, userSearch=updateValue,
                message=message, call_name='user', state='before')
    # ----------------------------------------------

    resp = BB.UpdateUser(userId=updateValue, payload=passedPayload, params={
                        'fields': 'id, userName, name.given, name.middle, name.family, externalId, contact.email, availability.available, dataSourceId, created, modified'}, sync=True)

    if (resp.status_code == 200):
        # ----------------------------------------------
        # get data AFTER the change
        # and insert log to local DB
        rfc.save_log(request=request, userSearch=updateValue,
                    message=message, call_name='user', state='after')
        # ----------------------------------------------

        result_json = resp.json()
        dskresp = BB.GetDataSource(
            dataSourceId=result_json['dataSourceId'], sync=True)
        dsk_json = dskresp.json()
        logging.info(f"RESPONSE:\n", result_json)
        isFoundStatus = True

        result_json['dataSourceId'] = dsk_json['externalId']
        context = {
            "is_found": isFoundStatus,
            'result_json': result_json,
        }
    else:
        error_json = resp.json()  # return actual error
        logging.info(f"RESPONSE:\n", error_json)
        context = {
            "is_found": isFoundStatus,
            'error_json': error_json,
        }
    return JsonResponse(context)

# [DONE] Retrieve user list (based on DSK)


def getUsers(request):
    response = None
    context = None

    logging.info("NEW QUERY: getUsers")
    context = ""
    searchBy = request.GET.get('searchBy')
    searchValueUsr = request.GET.get('searchValueUsr')
    searchOptions = request.GET.get('searchOptions')
    searchAvailabilityOption = request.GET.get('searchAvailabilityOption')
    searchDate = request.GET.get('searchDate')
    searchDateOption = request.GET.get('searchDateOption')
    searchOptionList = None

    BB = getBBRest(request)

    if (searchValueUsr is not None):
        searchValueUsr = searchValueUsr.strip()
        if (searchBy):
            logging.info("GETUSERS SEARCH BY: ", searchBy)
    else:
        logging.info("GETUSERS SEARCHBY NOT SET")
    if (searchValueUsr is not None):
        logging.info("GETUSERS SEARCHVALUEUSR: ", searchValueUsr)
    else:
        logging.info("GETUSERS SEARCHVALUEUSR NOT SET")
    if (searchOptions is not None):
        logging.info(f"GETUSERS SEARCHOPTIONS: ", searchOptions)
        searchOptionList = searchOptions.split(';')
        logging.info(f"GETUSERS SEARCHOPTIONLIST: ", searchOptionList)
        logging.info(f"IS BY AVAILABILITY A SELECTED OPTION? ",
            searchOptionList.count('searchAvailability'))
        logging.info(f"IS BY DATE A SELECTED OPTION? ",
            searchOptionList.count('date'))
    else:
        logging.info("GETUSERS SEARCHOPTIONLIST NOT SET")
    if (searchAvailabilityOption is not None):
        logging.info(f"GETUSERS searchAvailabilityOption: ", searchAvailabilityOption)
    else:
        logging.info("GETUSERS searchAvailabilityOption NOT SET")
    if (searchDate is not None):
        logging.info(f"GETUSERS searchDate: ", searchDate)
    else:
        logging.info("GETUSERS searchDate NOT SET")
    if (searchDateOption is not None):
        logging.info(f"GETUSERS searchDateOption: ", searchDateOption)
    else:
        logging.info("GETUSERS searchDateOption NOT SET")
    logging.info(f"GETUSERS REQUEST:\n", request)
    isFoundStatus = False
    searchByDate = False
    searchByAvailability = False
    filterByAvailability = False
    filterByDSK = False

    if (searchOptions is not None):
        if searchOptionList.count('date') == 1:
            searchByDate = True
        if searchOptionList.count('availability') == 1:
            searchByAvailability = True
    logging.info("SEARCH OPTIONS: byAvailability: ",
        searchByAvailability, "byDate: ", searchByDate)

    # BbRestSetup(request, 'users', True)

    # currently not supporting any allUsers searches and we only use the date picker on DSK searches...

    if searchBy == 'DSK':
        if searchByDate:
            # use searchDate parameter
            # ...
            logging.info("SEARCH FOR ALL USERS USING DATE...")

            resp = BB.GetUsers(limit=500000, params={'created': searchDate, 'createdCompare': searchDateOption,
                            'fields': 'id, userName, name.given, name.middle, name.family, externalId, contact.email, availability.available, dataSourceId, created, modified'}, sync=True)

            filterByDSK = True

            if searchByAvailability:
                filterByAvailability = True
            else:
                filterByAvailability = False
        else:
            # Not by date request, just do a standard request and return everything and filter on availability if requested
            # ...
            resp = BB.GetUsers(limit=500000, params={
                            'dataSourceId': searchValueUsr, 'fields': 'id, userName, name.given, name.middle, name.family, externalId, contact.email, availability.available, dataSourceId, created, modified'}, sync=True)

            filterByDSK = False

            if searchByAvailability:
                filterByAvailability = True
            else:
                filterByAvailability = False
            """ elif searchBy == "ALLUSERS": 
            # eventually we will support an allUsers search as below
            # do a normal search and return everything...
            resp = BB.GetUsers(limit = 500000, params = {'fields':'id, userName, name.given, name.middle, name.family, externalId, contact.email, availability.available, dataSourceId, created'}, sync=True ) """

    else:
        if (searchBy == 'familyName'):
            resp = BB.GetUsers(limit=500000, params={
                            'name.family': searchValueUsr, 'fields': 'id, userName, name.given, name.middle, name.family, externalId, contact.email, availability.available, dataSourceId, modified'}, sync=True)
        else:
            resp = BB.GetUsers(limit=500000, params={
                            'userName': searchValueUsr, 'fields': 'id, userName, name.given, name.middle, name.family, externalId, contact.email, availability.available, dataSourceId, modified'}, sync=True)

    # Otherwise search is by specifics in which case getUser was called and which should just return single user.

    # in either case we process the results filtering out undesired DSKs and availability options if requested...

    if (resp.status_code == 200):
        users_json = resp.json()
        logging.info(f"USER COUNT(prepurge): ", len(users_json["results"]))

        dsksResp = BB.GetDataSources(
            limit=5000, params={'fields': 'id, externalId'})
        dsks_json = dsksResp.json()
        dsks = dsks_json["results"]
        dsks = sortDsk(dsks, 'externalId')

        if filterByAvailability:
            # filter resp by selected availability...
            logging.info("GETUSERS EXECUTE AVAILABILITY PURGE")
            logging.info("AVAILABILITY OPTION: ", searchAvailabilityOption)
            purgedResults = availabilityPurge(
                users_json, searchAvailabilityOption)
            # logging.info("FILTERBYAVAILABILITY PURGED AVAILABILITY RESULTS:\n", purgedResults)
            logging.info("FILTERBYAVAILABILITY PURGED RESULTS COUNT: ",
                len(purgedResults["results"]))
            users_json = purgedResults

        if filterByDSK:
            # filter resp by selected date...
            logging.info("PURGING RESULTS based on DSK")
            purgedResults = datasourcePurge(users_json, searchValueUsr)
            # logging.info("FILTERBYDSK PURGED DSK RESULTS:\n", purgedResults)
            logging.info("FILTERBYDSK PURGED RESULTS COUNT: ",
                len(purgedResults["results"]))
            users_json = purgedResults

        users_json["length"] = len(users_json)
        # logging.info("DATASOURCE PURGE: users_json: /n", users_json)
        logging.info("users_json SIZE: ", len(users_json))

        # we always want to replace dsk primary keys with the dsk externalId...
        for idx, user in enumerate(users_json["results"]):
            for dsk in dsks:
                logging.debug("DSK:\n", dsk)
                logging.debug("DSKID: ", dsk["id"])
                if (dsk["id"] == user["dataSourceId"]):
                    users_json["results"][idx]["dataSourceId"] = dsk["externalId"]

    if (users_json):
            logging.debug("USERS_JSON TYPE: ", type(users_json))
    if (dsks):
            logging.debug("DSKS TYPE: ", type(dsks))

    context = {
        'users_json': users_json,
        'dsks_json': dsks,
    }

    return JsonResponse(context)


# [DONE] Update selected users from user list (based on DSK)
#   take request and iterate over each selected item, calling update user
#   concatenate result into error and success context
#   when done return context for processing in the UI
def updateUsers(request):
    response = None
    context = None

    context = ""
    finalResponse = {}
    isFoundStatus = False
    resps = {'results': []}
    logging.info("RESPS SET TO EMPTY RESULTS")

    logging.info("UPDATE USERS...")
    logging.debug('updateUsers: Request:\n ')
    # print (request)
    logging.debug("updateUsers: isUpdateRequired1: ",
        request.GET.get("isUpdateRequired1"))
    logging.debug("updateUsers: isAvailabilityUpdateRequired1:",
        request.GET.get("isAvailabilityUpdateRequired1"))
    logging.debug("updateUsers: selectedAvailability: ",
        request.GET.get("selectedAvailability"))
    logging.debug("updateUsers: isDataSourceKeyUpdateRequired1: ",
        request.GET.get("isDataSourceKeyUpdateRequired1"))
    selectedDSK = request.GET.get("selectedDataSourceKey")
    logging.debug("updateUsers: selectedDataSourceKey: ", selectedDSK)
    logging.debug("updateUsers: pmcUserId[]: " + request.GET.get("pmcUserId[]"))
    updateList = request.GET.get('pmcUserId[]')
    # updateList = request.POST.getlist('pmcUserId[]')
    logging.debug("updateUsers: updateList: ", updateList)
    updateUserList = updateList.split(',')

    passedPayload = {}

    BB = getBBRest(request)

    if (request.GET.get('isAvailabilityUpdateRequired1')):
        if (request.GET.get('isAvailabilityUpdateRequired1') == 'true'):
            logging.info("updateUsers: AVAILABILITY UPDATE REQUIRED")
            passedPayload = {'availability': {
                "available": request.GET.get('selectedAvailability')}}
    if (request.GET.get('isDataSourceKeyUpdateRequired1')):
        if (request.GET.get('isDataSourceKeyUpdateRequired1') == 'true'):
            passedPayload["dataSourceId"] = request.GET.get(
                'selectedDataSourceKey')
            logging.info("updateUsers: DATASOURCE UPDATE REQUIRED")

    logging.debug("updateUsers: PASSED PAYLOAD:\n", passedPayload)

    dsks_json = BB.GetDataSources(
        limit=5000, params={'fields': 'id, externalId'}).json()
    dsks = dsks_json["results"]

    # ----------------------------------------------
    # insert message to local DB
    rfc = Rfc()
    message = rfc.save_message(request, "user")
    # ----------------------------------------------

    for x in range(len(updateUserList)):
        logging.debug("userPK: ", updateUserList[x])
        updateValue = updateUserList[x]

        # ----------------------------------------------
        # get data BEFORE the change
        # and insert log to local DB
        rfc.save_log(request=request, userSearch=updateValue,
                    message=message, call_name='user', state='before')
        # ----------------------------------------------

        # updateUser
        resp = BB.UpdateUser(userId=updateValue, payload=passedPayload, params={
                            'fields': 'id, userName, name.given, name.middle, name.family, externalId, contact.email, availability.available, dataSourceId, created, modified'}, sync=True)

        respJSON = resp.json()

        if (resp.status_code == 200):
            # ----------------------------------------------
            # get user data AFTER the change
            # and insert log to local DB
            rfc.save_log(request=request, userSearch=updateValue,
                        message=message, call_name='user', state='after')
            # ----------------------------------------------

            logging.debug("RESP:\n", resp.json())
            logging.debug("RESPJSON:\n", respJSON)
            logging.debug("RESPJSON:dataSourceId", respJSON["dataSourceId"])
            isFoundStatus = True
            for dsk in dsks:
                # logging.info("DSK:\n", dsk)
                # logging.info("DSKID: ", dsk["id"])
                if (dsk["id"] == respJSON["dataSourceId"]):
                    logging.info("DSKEXTERNALID: ", dsk["externalId"])
                    respJSON["dataSourceId"] = dsk["externalId"]
                    logging.info("RESPJSON:dataSourceId", respJSON["dataSourceId"])

            resps["results"].append(respJSON)
            logging.info("RESPS:\n", resps)

            finalResponse = {
                "is_found": isFoundStatus,
                "result_json": resps["results"],
            }

        logging.info("FINAL RESPONSE:\n", finalResponse)
    # STOPPED HERE
    return JsonResponse(finalResponse)


# [DONE] Sorts the DSK list
def sortDsk(dsks, sortBy):
    return sorted(dsks, key=lambda x: x[sortBy])

# [DONE]
def guestusernotallowed(request):
    context = {
        'learn_server': LEARNFQDN,
    }
    return render(request, 'guestusernotallowed.html', context=context)

# [DONE]
def error_500(request):
    data = {}
    return render(request, 'error_500.html', data)

# [DONE]
def updateCourseMemberships(request):
    response = None
    context = None

    finalResponse = {}
    logging.info("request method: ", request.method)
    logging.info("request: ", request)
    searchValue = request.GET.get("crsSearchValue")
    logging.info("request searchValue: ", searchValue)
    searchBy = request.GET.get("crsSearchBy")
    logging.info("request searchBy: ", searchBy)
    userArray = request.GET.getlist('pmcUserId[]')
    logging.info("request pmcUsersList: \n", userArray)

    if (searchBy == "externalId"):
        crs = "externalId:"+searchValue
        logging.info("COURSE TO UPDATE: ", crs)
    elif (searchBy == "courseId"):
        crs = "courseId:"+searchValue
        logging.info("COURSE TO UPDATE:", crs)

    #BbRestSetup(request, redirectRequired=True)
    BB = getBBRest(request)

    dsks_json = BB.GetDataSources(
        limit=5000, params={'fields': 'id, externalId'}).json()
    dsks = dsks_json["results"]

    resps = {'results': []}
    logging.info("RESPS SET TO EMPTY RESULTS")

    if (request.GET.get('isUpdateRequired1') == 'true'):
        logging.info("isUpdateRequired1", request.GET.get('isUpdateRequired1'))

        # ----------------------------------------------
        # insert message to local DB
        rfc = Rfc()
        message = rfc.save_message(request, "enrollments")
        # ----------------------------------------------

        for user in userArray:
            payload = {}
            if (request.GET.get('isAvailabilityUpdateRequired1')):
                logging.info(user + ": isAvailabilityUpdateRequired1: ",
                    request.GET.get('isAvailabilityUpdateRequired1'))

                if (request.GET.get('isAvailabilityUpdateRequired1') == 'true'):
                    payload = {'availability': {
                        "available": request.GET.get('selectedAvailability')}}
                    logging.info(user + ": availability: ",
                        request.GET.get('selectedAvailability'))

            if (request.GET.get('isDataSourceKeyUpdateRequired1')):
                logging.info(user + ": isDataSourceKeyUpdateRequired1: ",
                    request.GET.get('isDataSourceKeyUpdateRequired1'))

                if (request.GET.get('isDataSourceKeyUpdateRequired1') == 'true'):
                    payload["dataSourceId"] = request.GET.get(
                        'selectedDataSourceKey')
                    logging.info(user + ": dataSourceId: ",
                        request.GET.get('selectedDataSourceKey'))

            logging.info("PAYLOAD: \n", payload)

            # ----------------------------------------------
            # get data BEFORE the change
            # and log to local DB
            rfc.save_log(request=request, crs=crs, usr=user,
                        message=message, call_name='membership', state='before')
            # ----------------------------------------------

            resp = BB.UpdateMembership(courseId=crs, userId=user, payload=payload, params={
                                    'expand': 'user', 'fields': 'id, courseId, userId, availability.available, dataSourceId, created, modified, courseRoleId, user.userName, user.name.given, user.name.middle, user.name.family, user.externalId, user.contact.email'}, sync=True)

            respJSON = resp.json()

            if (resp.status_code == 200):
                # ----------------------------------------------
                # get data AFTER the change
                # and log to local DB
                rfc.save_log(request=request, crs=crs, usr=user,
                            message=message, call_name='membership', state='after')
                # ----------------------------------------------

                logging.info("RESP:\n", resp.json())
                # resps["results"].append(respJSON["results"])
                logging.info("User:" + user + "UPDATED WITH PAYLOAD: \n", payload)
                logging.info("RESPJSON:\n", respJSON)
                logging.info("RESPJSON:dataSourceId", respJSON["dataSourceId"])

                for dsk in dsks:
                    #logging.info("DSK:\n", dsk)
                    #logging.info("DSKID: ", dsk["id"])
                    if (dsk["id"] == respJSON["dataSourceId"]):
                        logging.info("DSKEXTERNALID: ", dsk["externalId"])
                        respJSON["dataSourceId"] = dsk["externalId"]
                        logging.info("RESPJSON:dataSourceId",
                            respJSON["dataSourceId"])

            else:
                error_json["results":] = resp.json()
                logging.info("resp.status_code:", resp.status_code)
                logging.info(f"RESPONSE:\n", error_json)

            resps["results"].append(respJSON)
            logging.info("RESPS:\n", resps)

        finalResponse = {
            "updateList": userArray,
            "resps": resps,
        }

        logging.info("FINAL RESPONSE:\n", finalResponse)

    # return JsonResponse(finalResponse)

    # else:
    #     logging.info(f'USERS: AUTHN or AUTHZ FAILED! ... AUTHENTICATING!')
    #     response = dsktool.authn_authz_utils.authenticate(request, target='enrollments')
    #     return response

# [DONE]


def getCourseMemberships(request):
    response = None
    context = None

    logging.info("getCourseMembers Called...")
    logging.info("request method: ", request.method)

    task = request.GET.get('task')
    searchBy = request.GET.get('searchBy')  # externalId || userName
    searchValue = request.GET.get('searchValue')
    getThemAll = request.GET.get('getEmAll')
    if (searchValue is not None):
        searchValue = searchValue.strip()
    logging.info("LEARNFQDN", LEARNFQDN)
    logging.info("SEARCHBY: ", searchBy)
    logging.info("SEARCHVALUE: ", searchValue)
    logging.info("TASK: ", task)
    logging.info("GET EM ALL?: ", getThemAll)

    if (searchBy == 'externalId'):
        crs = "externalId:" + searchValue
    else:
        crs = "courseId:" + searchValue

    BB = getBBRest(request)

    memberships_result = BB.GetCourseMemberships(courseId=crs, limit=1500, params={
                                                'expand': 'user', 'fields': 'id, courseId, userId, availability.available, dataSourceId, created, modified, courseRoleId, user.userName, user.name.given, user.name.middle, user.name.family, user.externalId, user.contact.email'}, sync=True)

    logging.info("memberships_result status: ", memberships_result.status_code)
    membershipsResultJSON = memberships_result.json()
    logging.info(f"\nmemberships_result:\n", membershipsResultJSON)

    if (memberships_result.status_code == 200):
        dsksResp = BB.GetDataSources(
            limit=5000, params={'fields': 'id, externalId'})
        dsks_json = dsksResp.json()
        #logging.info("DSKS_JSON: \n", dsks_json)
        dsks = dsks_json["results"]
        #logging.info("DSKS: \n", dsks)
        dsks = sortDsk(dsks, 'externalId')
        #logging.info("SORTEDDSKS: \n", dsks)

        for idx, membership in enumerate(membershipsResultJSON["results"]):
            logging.info("\nMEMBERSHIP: ", membership["dataSourceId"])
            for dsk in dsks:
                #logging.info("DSK:\n", dsk)
                #logging.info("DSKID: ", dsk["id"])
                if (dsk["id"] == membership["dataSourceId"]):
                    logging.info("DSKEXTERNALID: ", dsk["externalId"])
                    membershipsResultJSON["results"][idx]["dataSourceId"] = dsk["externalId"]
                    logging.info(
                        membershipsResultJSON["results"][idx]["dataSourceId"])

        logging.info(f"\nmemberships_result AFTER:\n", membershipsResultJSON)

    # Use asynchronous when processing requests
    # tasks = []
    # for user in users:
    #     tasks.append(BB.GetUser(user), sync=False)
    #     resps = await asynchio.gather(*tasks)

    context = {
        'memberships_json': membershipsResultJSON,
        'dsks_json': dsks,
    }

    return JsonResponse(context)


# AJAX STUFF...
def getSessionJWTTimeRemaining(request):
    jwt = None
    timeRemaining = None
    
    jwt_utils = Jwt_token_util()

    if ('JWT' in request.session.keys()):
        jwt = request.session['JWT']
        decoded_jwt = jwt_utils.decodeJWT(jwt)
        if decoded_jwt:
            exp_epoch = decoded_jwt['exp']
            exp_time = datetime.utcfromtimestamp( exp_epoch )
            # logging.info("EXPIRES:", exp_time)        
            timeRemaining = (exp_time)-datetime.utcnow()
            # logging.info(f'TIME REMAINING: {timeRemaining}')
                
    return timeRemaining

# [DONE] Reduce error opportunity by validating form entered values
def validate_userIdentifier(request):
    logging.info("ENTER validate_userIdentifier...")
    response = None
    context = None

    if ("ISVALIDUSER" in request.session.keys() and request.session['ISVALIDUSER']): #authenticated 
        logging.info(f'ISVALIDUSER: {request.session["ISVALIDUSER"]}')
    
        searchBy = request.GET.get('searchBy')  # externalId || userName
        searchValue = request.GET.get('searchValue')
        searchOperator = request.GET.get('searchOperator')
        if (searchValue is not None):
            searchValue = searchValue.strip()

        if (searchBy == 'externalId'):
            usr = "externalId:" + searchValue
        elif (searchBy == 'userName'):
            usr = "userName:" + searchValue
        elif (searchOperator == 'contains' or searchBy == 'familyName'):
            usr = searchValue

        # if LEARNFQDN:
        #     logging.info("validate_userIdentifier: LEARNFQDN", LEARNFQDN)
        # if searchBy:
        #     logging.info("validate_userIdentifier: SEARCHBY: ", searchBy)
        # if searchValue:
        #     logging.info("validate_userIdentifier: SEARCHVALUE: ", searchValue)
        # if searchOperator:
        #     logging.info("validate_userIdentifier: SEARCHOPERATOR: ", searchOperator)
        # logging.info("user pattern: ", usr)

        BB = getBBRest(request)

        if (searchOperator == 'contains'):
            if (searchBy == 'familyName'):
                validationresult = BB.GetUsers(limit=1, params={
                                            'name.family': usr, 'fields': 'id, userName, name.given, name.middle, name.family, externalId, contact.email, availability.available, dataSourceId, modified'}, sync=True)
            elif (searchBy == 'externalId'):
                validationresult = BB.GetUsers(limit=1, params={
                                            'externalId': usr, 'fields': 'id, userName, name.given, name.middle, name.family, externalId, contact.email, availability.available, dataSourceId, modified'}, sync=True)
            elif (searchBy == 'userName'):
                validationresult = BB.GetUsers(limit=1, params={
                                            'userName': usr, 'fields': 'id, userName, name.given, name.middle, name.family, externalId, contact.email, availability.available, dataSourceId, modified'}, sync=True)

        else:
            if (searchBy == 'familyName'):
                validationresult = BB.GetUsers(limit=1, params={
                                            'name.family': usr, 'fields': 'id, userName, name.given, name.middle, name.family, externalId, contact.email, availability.available, dataSourceId, modified'}, sync=True)
            else:
                validationresult = BB.GetUser(userId=usr, params={
                                            'fields': 'id, userName, name.given, name.middle, name.family, externalId, contact.email, availability.available, dataSourceId, created'}, sync=True)

        if (validationresult.status_code == 200):
            foundStatus = True
            # logging.info("VALIDATIONRESULT_STATUS: ", validationresult.status_code)
            # logging.info(f"VALIDATIONRESULT:\n", validationresult.json())

        data = {
            'is_found': foundStatus
        }

    else: 
        data = {
            'notauthorized': True
        }


    return JsonResponse(data)

# [DONE] Reduce error opportunity by validating form entered values

def validate_courseIdentifier(request):
    response = None
    context = None

    if ("ISVALIDUSER" in request.session.keys() and request.session['ISVALIDUSER']): #authenticated 
        logging.info("validate_courseIdentifier called....")
        searchBy = request.GET.get('searchBy')  # externalId || userName
        searchValue = request.GET.get('searchValue')
        searchOperator = request.GET.get('searchOperator')


        if (searchValue is not None):
            searchValue = searchValue.strip()

        if (searchBy == 'externalId'):
            crs = "externalId:" + searchValue
        elif (searchOperator == 'contains' or searchBy == 'primaryId' or searchBy == 'courseName'):
            crs = searchValue
        else:
            crs = "courseId:" + searchValue

        logging.debug(f"validate_courseIdentifier: SEARCHBY: {searchBy}")
        logging.debug(f"validate_courseIdentifier: SEARCHVALUE: {searchValue}")
        logging.debug(f"validate_courseIdentifier: SEARCHOPERATOR: {searchOperator}")
        logging.debug(f"validate_courseIdentifier: user pattern: {crs}")

        BB = getBBRest(request)

        if (searchOperator == 'contains'):
            if (searchBy == 'courseName'):
                validationresult = BB.GetCourses(limit=1, params={'name': crs}, sync=True)
            elif (searchBy == 'externalId'):
                validationresult = BB.GetCourses(limit=1, params={'externalId': crs}, sync=True)
            elif (searchBy == 'courseId'):
                validationresult = BB.GetCourses(limit=1, params={'courseId': crs}, sync=True)

        else:
            if (searchBy == 'courseName'):
                validationresult = BB.GetCourses(limit=1, params={'name': crs}, sync=True)
            else:
                validationresult = BB.GetCourse(courseId=crs, sync=True)

        logging.debug(f"VALIDATIONRESULT_STATUS: {validationresult.status_code}")
        logging.debug(f"VALIDATIONRESULT:\n{validationresult.json()}")

        if (validationresult.status_code == 200):
            foundStatus = True
        else:
            foundStatus = False

        data = {
            'is_found': foundStatus
        }

    else: 
        data = {
            'notauthorized': True
        }

    return JsonResponse(data)

# [DONE] Retrieve a single course membership


def getCourseMembership(request):
    response = None
    context = None
    if dsktool.authn_authz_utils.isAuthenticated(request) and dsktool.authn_authz_utils.isAuthorized(request):
        # Get a single course membership
        logging.info("\ngetCourseMember Called...")
        logging.info("request method: ", request.method)

        # {"searchByCrs":"externalId","searchValueCrs":"moneil-available","searchValueUsr":"moneil","searchByUsr":"externalId"}
        crsSearchBy = request.GET.get('crsSearchBy')  # externalId || userName
        crsToSearchFor = request.GET.get('crsToSearchFor')
        usrSearchBy = request.GET.get('usrSearchBy')  # externalId || userName
        usrToSearchFor = request.GET.get('usrToSearchFor')
        logging.info("getCourseMembership::crsSearchBy", crsSearchBy)
        logging.info("getCourseMembership::crsToSearch: ", crsToSearchFor)
        logging.info("getCourseMembership::usrSearchBy: ", usrSearchBy)
        logging.info("getCourseMembership::usrToSearchFor", usrToSearchFor)

        if (crsSearchBy == 'externalId'):
            crs = "externalId:" + crsToSearchFor
        else:
            crs = "courseId:" + crsToSearchFor
        if (usrSearchBy == 'externalId'):
            usr = "externalId:" + usrToSearchFor
        else:
            usr = "userName:" + usrToSearchFor

        BB = getBBRest(request)

        membership_result = BB.GetMembership(courseId=crs, userId=usr, params={
                                            'expand': 'user', 'fields': 'id, courseId, userId, availability.available, dataSourceId, created, modified, courseRoleId, childCourseId, user.userName, user.name.given, user.name.middle, user.name.family, user.externalId, user.contact.email'}, sync=True)

        logging.info("getCourseMembership::membership_result status: ",
            membership_result.status_code)

        if (membership_result.status_code == 200):
            member_json = membership_result.json()
            logging.info("MBRJSON:\n", member_json)

            dskresp = BB.GetDataSource(
                dataSourceId=member_json['dataSourceId'], sync=True)
            dsk_json = dskresp.json()
            member_json['dataSourceId'] = dsk_json['externalId']
            member_json['crsToSearchFor'] = crsToSearchFor
            member_json['crsSearchBy'] = crsSearchBy
            member_json['usrToSearchFor'] = usrToSearchFor
            member_json['usrSearchBy'] = usrSearchBy
            logging.info("updated member_json: \n", member_json)
            dskresp = BB.GetDataSources(
                limit=5000, params={'fields': 'id, externalId'}, sync=True)
            dsks_json = dskresp.json()
            logging.info("DSKS:\n", dsks_json["results"])
            dsks = dsks_json["results"]
            dsks = sortDsk(dsks, 'externalId')
            logging.info("SIZE OF DSK LIST:", len(dsks))

            context = {
                'member_json': member_json,
                'dsks_json': dsks,
            }
        else:
            error_json = membership_result.json()
            logging.info(f"RESPONSE:\n", error_json)
            data = {
                'is_found': False,
                'error_json': error_json,
            }

            return JsonResponse(data)

        data = {
            'is_found': True,
            'memberships_json': member_json,
            'dsks_json': dsks,
        }

        return JsonResponse(data)

    else:
        logging.info(f'USERS: AUTHN or AUTHZ FAILED! ... AUTHENTICATING!')
        response = dsktool.authn_authz_utils.authenticate(request, target='enrollments')
        return response

# [DONE] Retrieve a list of course memberships


def getCourseMemberships(request):
    response = None
    context = None
    if dsktool.authn_authz_utils.isAuthenticated(request) and dsktool.authn_authz_utils.isAuthorized(request):

        logging.info("getCourseMembers Called...")
        logging.info("request method: ", request.method)

        searchBy = request.GET.get('searchBy')
        searchValue = request.GET.get('searchValue')
        filterByDSK = request.GET.get('filterByDSK')
        filterByDSKValue = request.GET.get('filterDSK')
        if (searchValue is not None):
            searchValue = searchValue.strip()
        logging.info("LEARNFQDN", LEARNFQDN)
        logging.info("SEARCHBY: ", searchBy)
        logging.info("SEARCHVALUE: ", searchValue)
        logging.info("filterByDSK: ", filterByDSK)
        logging.info("filterByDSKValue: ", filterByDSKValue)

        if (searchBy == 'externalId'):
            crs = "externalId:" + searchValue
        else:
            crs = "courseId:" + searchValue

        BB = getBBRest(request)

        if (filterByDSK == "true"):
            memberships_result = BB.GetCourseMemberships(courseId=crs, limit=1500, params={
                                                        'dataSourceId': filterByDSKValue, 'expand': 'user', 'fields': 'id, courseId, userId, availability.available, dataSourceId, created, modified, courseRoleId, childCourseId, user.userName, user.name.given, user.name.middle, user.name.family, user.externalId, user.contact.email'}, sync=True)
        else:
            memberships_result = BB.GetCourseMemberships(courseId=crs, limit=1500, params={
                                                        'expand': 'user', 'fields': 'id, courseId, userId, availability.available, dataSourceId, created, modified, courseRoleId, childCourseId, user.userName, user.name.given, user.name.middle, user.name.family, user.externalId, user.contact.email'}, sync=True)

        logging.info("memberships_result status: ", memberships_result.status_code)
        membershipsResultJSON = memberships_result.json()
        logging.info(f"\nmemberships_result:\n", membershipsResultJSON)

        if (memberships_result.status_code == 200):
            dsksResp = BB.GetDataSources(
                limit=5000, params={'fields': 'id, externalId'})
            dsks_json = dsksResp.json()
            #logging.info("DSKS_JSON: \n", dsks_json)
            dsks = dsks_json["results"]
            #logging.info("DSKS: \n", dsks)
            dsks = sortDsk(dsks, 'externalId')
            #logging.info("SORTEDDSKS: \n", dsks)

            for idx, membership in enumerate(membershipsResultJSON["results"]):
                logging.info("\nMEMBERSHIP: ", membership["dataSourceId"])
                for dsk in dsks:
                    #logging.info("DSK:\n", dsk)
                    #logging.info("DSKID: ", dsk["id"])
                    if (dsk["id"] == membership["dataSourceId"]):
                        logging.info("DSKEXTERNALID: ", dsk["externalId"])
                        membershipsResultJSON["results"][idx]["dataSourceId"] = dsk["externalId"]
                        logging.info(
                            membershipsResultJSON["results"][idx]["dataSourceId"])

            logging.info(f"\nmemberships_result AFTER:\n", membershipsResultJSON)

        # Use asynchronous when processing requests
        # tasks = []
        # for user in users:
        #     tasks.append(BB.GetUser(user), sync=False)
        #     resps = await asynchio.gather(*tasks)

        context = {
            'is_found': True,
            'memberships_json': membershipsResultJSON,
            'dsks_json': dsks,
        }

        return JsonResponse(context)

    else:
        logging.info(f'USERS: AUTHN or AUTHZ FAILED! ... AUTHENTICATING!')
        response = dsktool.authn_authz_utils.authenticate(request, target='users')
        return response

# [DONE] Update a single course membership


def updateCourseMembership(request):
    response = None
    context = None
    if dsktool.authn_authz_utils.isAuthenticated(request) and dsktool.authn_authz_utils.isAuthorized(request):
        logging.info("\ngetCourseMember Called...")
        logging.info("request method: ", request.method)

        finalResponse = {}
        isFoundStatus = False
        resps = {'results': []}
        logging.info("RESPS SET TO EMPTY RESULTS")

        crsSearchBy = request.GET.get('crsSearchBy')  # externalId || userName
        crsToSearchFor = request.GET.get('crsToSearchFor')
        usrSearchBy = request.GET.get('usrSearchBy')  # externalId || userName
        usrToSearchFor = request.GET.get('usrToSearchFor')
        userArray = request.GET.getlist('pmcUserId[]')
        logging.info("getCourseMembership::crsSearchBy", crsSearchBy)
        logging.info("getCourseMembership::crsToSearch: ", crsToSearchFor)
        logging.info("getCourseMembership::usrSearchBy: ", usrSearchBy)
        logging.info("getCourseMembership::usrToSearchFor", usrToSearchFor)
        logging.info("request pmcUsersList: \n", userArray)

        if (crsSearchBy == 'externalId'):
            crs = "externalId:" + crsToSearchFor
        else:
            crs = "courseId:" + crsToSearchFor
        if (usrSearchBy == 'externalId'):
            usr = "externalId:" + usrToSearchFor
        else:
            usr = "userName:" + usrToSearchFor

        BB = getBBRest(request)

        dsks_json = BB.GetDataSources(
            limit=5000, params={'fields': 'id, externalId'}).json()
        dsks = dsks_json["results"]

        resps = {'results': []}
        logging.info("RESPS SET TO EMPTY RESULTS")

        # if (request.GET.get('isUpdateRequired1') == 'true'):
        logging.info("isUpdateRequired1", request.GET.get('isUpdateRequired1'))
        payload = {}
        if (request.GET.get('isAvailabilityUpdateRequired1')):
            logging.info("isAvailabilityUpdateRequired1: ",
                request.GET.get('isAvailabilityUpdateRequired1'))

            if (request.GET.get('isAvailabilityUpdateRequired1') == 'true'):
                payload = {'availability': {
                    "available": request.GET.get('selectedAvailability')}}
                logging.info("availability: ", request.GET.get('selectedAvailability'))

        if (request.GET.get('isDataSourceKeyUpdateRequired1')):
            logging.info("isDataSourceKeyUpdateRequired1: ",
                request.GET.get('isDataSourceKeyUpdateRequired1'))

            if (request.GET.get('isDataSourceKeyUpdateRequired1') == 'true'):
                payload["dataSourceId"] = request.GET.get('selectedDataSourceKey')
                logging.info("dataSourceId: ", request.GET.get('selectedDataSourceKey'))

                logging.info("PAYLOAD: \n", payload)

        # ----------------------------------------------
        # get data BEFORE the change
        # and insert message and log to local DB
        rfc = Rfc()
        message = rfc.save_message(request, "enrollments")
        rfc.save_log(request=request, crs=crs, usr=usr, message=message,
                    call_name='membership', state='before')
        # ----------------------------------------------

        resp = BB.UpdateMembership(courseId=crs, userId=usr, payload=payload, params={
                                'expand': 'user', 'fields': 'id, courseId, userId, availability.available, dataSourceId, created, modified, courseRoleId, user.userName, user.name.given, user.name.middle, user.name.family, user.externalId, user.contact.email'}, sync=True)

        respJSON = resp.json()

        if (resp.status_code == 200):
            logging.info("RESP:\n", resp.json())
            # resps["results"].append(respJSON["results"])
            logging.info("RESPJSON:\n", respJSON)
            logging.info("RESPJSON:dataSourceId", respJSON["dataSourceId"])
            isFoundStatus = True

            for dsk in dsks:
                #logging.info("DSK:\n", dsk)
                #logging.info("DSKID: ", dsk["id"])
                if (dsk["id"] == respJSON["dataSourceId"]):
                    logging.info("DSKEXTERNALID: ", dsk["externalId"])
                    respJSON["dataSourceId"] = dsk["externalId"]
                    logging.info("RESPJSON:dataSourceId", respJSON["dataSourceId"])
                # else:
                #     error_json["results":] = resp.json()
                #     logging.info("resp.status_code:", resp.status_code)
                #     print (f"RESPONSE:\n", error_json)

            resps["results"].append(respJSON)
            logging.info("RESPS:\n", resps)

            finalResponse = {
                "is_found": isFoundStatus,
                "updateList": resps["results"],
            }

            # ----------------------------------------------
            # get data AFTER the change
            # and insert log to local DB
            rfc.save_log(request=request, crs=crs, usr=usr,
                        message=message, call_name='membership', state='after')
            # ----------------------------------------------

            logging.info("FINAL RESPONSE:\n", finalResponse)

        return JsonResponse(finalResponse)

    else:
        logging.info(f'USERS: AUTHN or AUTHZ FAILED! ... AUTHENTICATING!')
        response = dsktool.authn_authz_utils.authenticate(request, target='users')
        return response

# [DONE] Update a list of course memberships


def updateCourseMemberships(request):
    response = None
    context = None
    
    finalResponse = {}
    logging.info("request method: ", request.method)
    logging.info("request: ", request)

    if (request.GET.get("crsorusr") == 'byCrsUsr'):
        searchValue = request.GET.get("crsSearchValue")
        logging.info("request searchValue: ", searchValue)
        searchBy = request.GET.get("crsSearchBy")
        logging.info("request searchBy: ", searchBy)
    elif (request.GET.get("crsorusr") == 'byCrs'):
        searchValue = request.GET.get("crsToSearchFor")
        logging.info("request searchValue: ", searchValue)
        searchBy = request.GET.get("crsSearchBy")
        logging.info("request searchBy: ", searchBy)
    elif (request.GET.get("crsorusr") == 'byUsr'):
        searchValue = request.GET.get("crsToSearchFor")
        logging.info("request searchValue: ", searchValue)
        searchBy = request.GET.get("crsSearchBy")
        logging.info("request searchBy: ", searchBy)

    userArray = request.GET.getlist('pmcUserId[]')
    logging.info("request pmcUsersList: \n", userArray)

    if (searchBy == "externalId"):
        crs = "externalId:"+searchValue
        logging.info("COURSE TO UPDATE: ", crs)
    elif (searchBy == "courseId"):
        crs = "courseId:"+searchValue
        logging.info("COURSE TO UPDATE:", crs)

    BB = getBBRest(request)

    dsks_json = BB.GetDataSources(
        limit=5000, params={'fields': 'id, externalId'}).json()
    dsks = dsks_json["results"]

    resps = {'results': []}
    logging.info("RESPS SET TO EMPTY RESULTS")
    isFoundStatus = False

    if (request.GET.get('isUpdateRequired1') == 'true'):
        logging.info("isUpdateRequired1", request.GET.get('isUpdateRequired1'))

        # ----------------------------------------------
        # insert message to local DB
        rfc = Rfc()
        message = rfc.save_message(request, "enrollments")
        # ----------------------------------------------

        for user in userArray:
            payload = {}
            if (request.GET.get('isAvailabilityUpdateRequired1')):
                logging.info(user + ": isAvailabilityUpdateRequired1: ",
                    request.GET.get('isAvailabilityUpdateRequired1'))

                if (request.GET.get('isAvailabilityUpdateRequired1') == 'true'):
                    payload = {'availability': {
                        "available": request.GET.get('selectedAvailability')}}
                    logging.info(user + ": availability: ",
                        request.GET.get('selectedAvailability'))

            if (request.GET.get('isDataSourceKeyUpdateRequired1')):
                logging.info(user + ": isDataSourceKeyUpdateRequired1: ",
                    request.GET.get('isDataSourceKeyUpdateRequired1'))

                if (request.GET.get('isDataSourceKeyUpdateRequired1') == 'true'):
                    payload["dataSourceId"] = request.GET.get(
                        'selectedDataSourceKey')
                    logging.info(user + ": dataSourceId: ",
                        request.GET.get('selectedDataSourceKey'))

            logging.info("PAYLOAD: \n", payload)

            # ----------------------------------------------
            # get data BEFORE the change
            # and insert log to local DB
            rfc.save_log(request=request, crs=crs, usr=user,
                        message=message, call_name='membership', state='before')
            # ----------------------------------------------

            resp = BB.UpdateMembership(courseId=crs, userId=user, payload=payload, params={
                                    'expand': 'user', 'fields': 'id, courseId, userId, availability.available, dataSourceId, created, modified, courseRoleId, user.userName, user.name.given, user.name.middle, user.name.family, user.externalId, user.contact.email'}, sync=True)

            respJSON = resp.json()

            if (resp.status_code == 200):
                # ----------------------------------------------
                # get user data AFTER the change
                # and insert log to local DB
                rfc.save_log(request=request, crs=crs, usr=user,
                            message=message, call_name='membership', state='after')
                # ----------------------------------------------

                logging.info("RESP:\n", resp.json())
                # resps["results"].append(respJSON["results"])
                logging.info("User:" + user + "UPDATED WITH PAYLOAD: \n", payload)
                logging.info("RESPJSON:\n", respJSON)
                logging.info("RESPJSON:dataSourceId", respJSON["dataSourceId"])
                isFoundStatus = True

                for dsk in dsks:
                    #logging.info("DSK:\n", dsk)
                    #logging.info("DSKID: ", dsk["id"])
                    if (dsk["id"] == respJSON["dataSourceId"]):
                        logging.info("DSKEXTERNALID: ", dsk["externalId"])
                        respJSON["dataSourceId"] = dsk["externalId"]
                        logging.info("RESPJSON:dataSourceId",
                            respJSON["dataSourceId"])
                resps["results"].append(respJSON)

            elif (resp.status_code == 409):
                logging.info("resp.status_code:", resp.status_code)
                logging.info("CHILD COURSE MEMBERSHIP: Get Child Course...")
                logging.info("crsToSearchFor: ", searchValue)
                cqmembership_result = BB.GetMembership(courseId=searchValue, userId=user, params={
                                                    'fields': 'id, courseId, userId, childCourseId'}, sync=True)

                cqmembership_resultJSON = cqmembership_result.json()
                logging.info("CHILD QUEST:JSON", cqmembership_resultJSON)
                logging.info("CHILD QUEST:CHILDCOURSEID",
                    cqmembership_resultJSON["childCourseId"])

                # ----------------------------------------------
                # get data BEFORE the change
                rfc.save_log(request=request, crs=cqmembership_resultJSON["childCourseId"],
                            usr=user, message=message, call_name='membership', state='before')
                # ----------------------------------------------

                resp2 = BB.UpdateMembership(courseId=cqmembership_resultJSON["childCourseId"], userId=user, payload=payload, params={
                                            'expand': 'user', 'fields': 'id, courseId, userId, availability.available, dataSourceId, created, modified, courseRoleId, user.userName, user.name.given, user.name.middle, user.name.family, user.externalId, user.contact.email'}, sync=True)

                # ----------------------------------------------
                # get data AFTER the change
                # and insert log to local DB
                rfc.save_log(request=request, crs=cqmembership_resultJSON["childCourseId"],
                            usr=user, message=message, call_name='membership', state='after')
                # ----------------------------------------------

                logging.info("RESP2:\n", resp2.json())

            logging.info("RESPS:\n", resps)

        logging.info("ISFOUNDSTATUS: ", isFoundStatus)
        finalResponse = {
            "is_found": isFoundStatus,
            "pmcUserId[]": userArray,
            "updateList": resps["results"],
        }

        logging.info("FINAL RESPONSE:\n", finalResponse)

    return JsonResponse(finalResponse)

# [DONE] Retrieve a list of user memberships


def getUserMemberships(request):
    response = None
    context = None

    logging.info("getUserMemberships Called...")
    logging.info("request method: ", request.method)

    searchBy = request.GET.get('searchBy')
    searchValue = request.GET.get('searchValue')
    filterByDSK = request.GET.get('filterByDSK')
    filterByDSKValue = request.GET.get('filterDSK')
    if (searchValue is not None):
        searchValue = searchValue.strip()
    logging.info("LEARNFQDN", LEARNFQDN)
    logging.info("SEARCHBY: ", searchBy)
    logging.info("SEARCHVALUE: ", searchValue)
    logging.info("filterByDSK: ", filterByDSK)
    logging.info("filterByDSKValue: ", filterByDSKValue)

    if (searchBy == 'externalId'):
        usr = "externalId:" + searchValue
    else:
        usr = "userName:" + searchValue

    BB = getBBRest(request)

    if (filterByDSK == "true"):
        memberships_result = BB.GetUserMemberships(userId=usr, limit=1500, params={
                                                'dataSourceId': filterByDSKValue, 'expand': 'course', 'fields': 'id, courseId, userId, availability.available, dataSourceId, created, modified, courseRoleId, course.name, childCourseId, course.externalId'}, sync=True)
    else:
        memberships_result = BB.GetUserMemberships(userId=usr, limit=1500, params={
                                                'expand': 'course', 'fields': 'id, courseId, userId, availability.available, dataSourceId, created, modified, courseRoleId, course.name, childCourseId, course.externalId'}, sync=True)

    logging.info("memberships_result status: ", memberships_result.status_code)
    membershipsResultJSON = memberships_result.json()
    logging.info(f"\nmemberships_result:\n", membershipsResultJSON)

    if (memberships_result.status_code == 200):
        dsksResp = BB.GetDataSources(
            limit=5000, params={'fields': 'id, externalId'})
        dsks_json = dsksResp.json()
        #logging.info("DSKS_JSON: \n", dsks_json)
        dsks = dsks_json["results"]
        #logging.info("DSKS: \n", dsks)
        dsks = sortDsk(dsks, 'externalId')
        #logging.info("SORTEDDSKS: \n", dsks)

        for idx, membership in enumerate(membershipsResultJSON["results"]):
            logging.info("\nMEMBERSHIP: ", membership["dataSourceId"])
            for dsk in dsks:
                #logging.info("DSK:\n", dsk)
                #logging.info("DSKID: ", dsk["id"])
                if (dsk["id"] == membership["dataSourceId"]):
                    logging.info("DSKEXTERNALID: ", dsk["externalId"])
                    membershipsResultJSON["results"][idx]["dataSourceId"] = dsk["externalId"]
                    logging.info(
                        membershipsResultJSON["results"][idx]["dataSourceId"])

        logging.info(f"\nmemberships_result AFTER:\n", membershipsResultJSON)

    # Use asynchronous when processing requests
    # tasks = []
    # for user in users:
    #     tasks.append(BB.GetUser(user), sync=False)
    #     resps = await asynchio.gather(*tasks)

    context = {
        'is_found': True,
        'memberships_json': membershipsResultJSON,
        'dsks_json': dsks,
    }

    return JsonResponse(context)

# [DONE] Update a list of user memberships
def updateUserMemberships(request):
    response = None
    context = None

    # {"crsSearchBy":"not_required","crsToSearchFor":"not_required","usrToSearchFor":"moneil","usrSearchBy":"externalId","isUpdateRequired1":"true","isAvailabilityUpdateRequired1":"true","selectedAvailability":"Yes","isDataSourceKeyUpdateRequired1":"true","selectedDataSourceKey":"_7_1","pmcUserId[]":["_9682_1:_1354_1","_9681_1:_1354_1"],"crsorusr":"byUsr"}
    finalResponse = {}
    logging.info("request method: ", request.method)
    logging.info("request: ", request)

    crsArray = request.GET.getlist('pmcUserId[]')
    logging.info("REQUEST pmcUsersList: \n", crsArray)

    BB = getBBRest(request)

    dsks_json = BB.GetDataSources(
        limit=5000, params={'fields': 'id, externalId'}).json()
    dsks = dsks_json["results"]

    resps = {'results': []}
    logging.info("RESPS SET TO EMPTY RESULTS")
    isFoundStatus = False

    if (request.GET.get('isUpdateRequired1') == 'true'):
        logging.info("isUpdateRequired1", request.GET.get('isUpdateRequired1'))

        # ----------------------------------------------
        # insert message to local DB
        rfc = Rfc()
        message = rfc.save_message(request, "enrollments")
        # ----------------------------------------------

        for crs in crsArray:
            payload = {}
            #logging.info("COURSE RECORD: ", crs)
            passedCrsId, passedUsrId = crs.split(':', 1)
            #logging.info("COURSE ID: ", passedCrsId)
            #logging.info("USER ID: ", passedUsrId)
            if (request.GET.get('isAvailabilityUpdateRequired1')):
                logging.info("isAvailabilityUpdateRequired1: ",
                    request.GET.get('isAvailabilityUpdateRequired1'))

                if (request.GET.get('isAvailabilityUpdateRequired1') == 'true'):
                    payload = {'availability': {
                        "available": request.GET.get('selectedAvailability')}}
                    logging.info("availability: ", request.GET.get(
                        'selectedAvailability'))

            if (request.GET.get('isDataSourceKeyUpdateRequired1')):
                logging.info("isDataSourceKeyUpdateRequired1: ",
                    request.GET.get('isDataSourceKeyUpdateRequired1'))

                if (request.GET.get('isDataSourceKeyUpdateRequired1') == 'true'):
                    payload["dataSourceId"] = request.GET.get(
                        'selectedDataSourceKey')
                    logging.info("dataSourceId: ", request.GET.get(
                        'selectedDataSourceKey'))

            logging.info("PAYLOAD: \n", payload)

            # ----------------------------------------------
            # get data BEFORE the change
            # and log to local DB
            rfc.save_log(request=request, crs=passedCrsId, usr=passedUsrId,
                        message=message, call_name='membership', state='before')
            # ----------------------------------------------

            resp = BB.UpdateMembership(courseId=passedCrsId, userId=passedUsrId, payload=payload, params={
                                    'expand': 'course', 'fields': 'id, courseId, userId, availability.available, dataSourceId, created, modified, courseRoleId, course.name, course.externalId'}, sync=True)

            respJSON = resp.json()

            if (resp.status_code == 200):
                #logging.info("RESP:\n", resp.json())
                # resps["results"].append(respJSON["results"])
                logging.info("UPDATED MEMBERSHIP WITH PAYLOAD: \n", payload)
                #logging.info("RESPJSON:\n", respJSON)
                #logging.info("RESPJSON:dataSourceId", respJSON["dataSourceId"])
                isFoundStatus = True

                for dsk in dsks:
                    #logging.info("DSK:\n", dsk)
                    #logging.info("DSKID: ", dsk["id"])
                    if (dsk["id"] == respJSON["dataSourceId"]):
                        #logging.info("DSKEXTERNALID: ", dsk["externalId"])
                        respJSON["dataSourceId"] = dsk["externalId"]
                        #logging.info("RESPJSON:dataSourceId", respJSON["dataSourceId"])

                    # add course name...
                    crsResp = BB.GetCourse(courseId=passedCrsId, params={
                                        'fields': 'name, externalId'})

                    if (resp.status_code == 200):
                        #logging.info("CRSRESP:\n", crsResp.json())
                        respJSON["course"] = crsResp.json()
                        #logging.info("RESPRESP:\n", respJSON)

                # ----------------------------------------------
                # get data AFTER the change
                # and log to local DB
                rfc.save_log(request=request, crs=passedCrsId, usr=passedUsrId,
                            message=message, call_name='membership', state='after')
                # ----------------------------------------------
            else:
                error_json["results":] = resp.json()
                logging.info("resp.status_code:", resp.status_code)
                logging.info(f"RESPONSE:\n", error_json)

            resps["results"].append(respJSON)
            #logging.info("RESPS:\n", resps)

        logging.info("ISFOUNDSTATUS: ", isFoundStatus)
        finalResponse = {
            "is_found": isFoundStatus,
            "updateList": resps["results"],
        }

        logging.info("FINAL RESPONSE:\n", finalResponse)

    return JsonResponse(finalResponse)

# [DONE] Retrieve a single course data - called from users page
def getCourse(request):
    # returns a list of one course - saves on javascript side.
    response = None
    context = None

    searchBy = request.GET.get('searchBy')
    searchValue = request.GET.get('searchValue')
    if (searchValue is not None):
        searchValue = searchValue.strip()
    logging.info("SEARCHBY: ", searchBy)
    logging.info("SEARCHVALUE: ", searchValue)

    # Process request...
    if (searchBy == 'externalId'):
        crs = "externalId:" + searchValue
    elif (searchBy == 'userName'):
        crs = "userName:" + searchValue
    else:
        crs = searchValue

    logging.info(f"course pattern: {crs}")

    isFoundStatus = False

    BB = getBBRest(request)

    resp = BB.GetCourse(courseId=crs, params={
                        'fields': 'id, courseId, externalId, name, organization, availability.available, dataSourceId, created, modified'}, sync=True)

    logging.info("GETCOURSE RESP: \n", resp.json())

    if (resp.status_code == 200):
        course_json = resp.json()

        dskresp = BB.GetDataSource(
            dataSourceId=course_json['dataSourceId'], sync=True)
        dsk_json = dskresp.json()
        course_json['dataSourceId'] = dsk_json['externalId']
        course_json['searchValue'] = searchValue
        course_json['searchBy'] = searchBy
        dskresp = BB.GetDataSources(
            limit=5000, params={'fields': 'id, externalId'}, sync=True)
        dsks_json = dskresp.json()
        dsks = dsks_json["results"]
        dsks = sortDsk(dsks, 'externalId')

        isFoundStatus = True

        context = {
            'is_found': isFoundStatus,
            'result_json': course_json,
            'dsks_json': dsks,
        }

    else:
        error_json = resp.json()
        logging.info(f"RESPONSE:\n", error_json)
        context = {
            'error_json': error_json,
        }

    return JsonResponse(context)

# [DONE] Update a single course - called from users page
def updateCourse(request):
    response = None
    context = None

    logging.info("UPDATE COURSE...")
    logging.info('Request:\n ')
    logging.info(request)
    logging.info("isUpdateRequired1: ", request.GET.get("isUpdateRequired1"))
    logging.info("isAvailabilityUpdateRequired1:",
        request.GET.get("isAvailabilityUpdateRequired1"))
    logging.info("selectedAvailability: ", request.GET.get("selectedAvailability"))
    logging.info("isDataSourceKeyUpdateRequired1: ",
        request.GET.get("isDataSourceKeyUpdateRequired1"))
    selectedDSK = request.GET.get("selectedDataSourceKey")
    logging.info("selectedDataSourceKey: ", selectedDSK)
    updateValue = request.GET.get('pmcCourseId[]')
    logging.info("UPDATE VALUE: ", updateValue)

    isFoundStatus = False
    passedPayload = {}

    if (request.GET.get('isAvailabilityUpdateRequired1')):
        if (request.GET.get('isAvailabilityUpdateRequired1') == 'true'):
            logging.info("AVAILABILITY UPDATE REQUIRED")
            passedPayload = {'availability': {
                "available": request.GET.get('selectedAvailability')}}
    if (request.GET.get('isDataSourceKeyUpdateRequired1')):
        if (request.GET.get('isDataSourceKeyUpdateRequired1') == 'true'):
            passedPayload["dataSourceId"] = request.GET.get(
                'selectedDataSourceKey')
            logging.info("DATASOURCE UPDATE REQUIRED")

    logging.info("PASSABLE PAYLOAD:\n", passedPayload)

    BB = getBBRest(request)

    # ----------------------------------------------
    # get data BEFORE the change
    # and insert message and log to local DB
    rfc = Rfc()
    message = rfc.save_message(request, "course")
    rfc.save_log(request=request, updateValue=updateValue,
                message=message, call_name='course', state='before')
    # ----------------------------------------------

    resp = BB.UpdateCourse(courseId=updateValue, payload=passedPayload, params={
                        'fields': 'id, courseId, externalId, name, organization, availability.available, dataSourceId, created, modified'}, sync=True)

    if (resp.status_code == 200):

        # ----------------------------------------------
        # get data AFTER the change
        # and insert log to local DB
        rfc.save_log(request=request, updateValue=updateValue,
                    message=message, call_name='course', state='after')
        # ----------------------------------------------

        result_json = resp.json()  # return actual error
        dskresp = BB.GetDataSource(
            dataSourceId=result_json['dataSourceId'], sync=True)
        dsk_json = dskresp.json()
        logging.info(f"RESPONSE:\n", result_json)
        isFoundStatus = True

        result_json['dataSourceId'] = dsk_json['externalId']

        context = {
            "is_found": isFoundStatus,
            'result_json': result_json,
        }
    else:
        error_json = resp.json()
        logging.info(f"RESPONSE:\n", error_json)
        context = {
            "is_found": isFoundStatus,
            'error_json': error_json,
        }

    return JsonResponse(context)
    

# [Done (DSK); INPROGRESS (ALLCOURSES)] Retrieve course list (All or based on DSK)
# this method handles:
# Query by:
#   DSK
#   ALLCOURSES
#   NAME
# Additionally this method supports searching by:
#   DATE
#   AVAILABILITY
#   NAME
def getCourses(request):
    response = None
    context = None

    logging.info("NEW QUERY: getCourses")
    context = ""
    searchBy = request.GET.get('searchBy')
    searchValue = request.GET.get('searchValue')
    searchOperator = request.GET.get('searchOperator')
    searchOptions = request.GET.get('searchOptions')
    searchAvailabilityOption = request.GET.get('searchAvailabilityOption')
    searchDate = request.GET.get('searchDate')
    searchDateOption = request.GET.get('searchDateOption')
    searchOptionList = None

    BB = getBBRest(request)

    if (searchValue is not None):
        searchValue = searchValue.strip()
        logging.info("GETCOURSES SEARCHBY: ", searchBy)
    if (searchValue is not None):
        logging.info("GETCOURSES SEARCHVALUE: ", searchValue)
    if (searchOperator is not None):
        logging.info("GETCOURSES SEARCHOPERATOR: ", searchOperator)
    if (searchOptions is not None):
        logging.info(f"GETCOURSES SEARCHOPTIONS: ", searchOptions)
        searchOptionList = searchOptions.split(';')
        logging.info(f"GETCOURSES SEARCHOPTIONLIST: ", searchOptionList)
        logging.info(f"IS BY AVAILABILITY A SELECTED OPTION? ",
            searchOptionList.count('searchAvailability'))
        logging.info(f"IS BY DATE A SELECTED OPTION? ",
            searchOptionList.count('date'))
    if (searchAvailabilityOption is not None):
        logging.info(f"GETCOURSES searchAvailabilityOption: ", searchAvailabilityOption)
    if (searchDate is not None):
        logging.info(f"GETCOURSES searchDate: ", searchDate)
    if (searchDateOption is not None):
        logging.info(f"GETCOURSES searchDateOption: ", searchDateOption)
    logging.info(f"GETCOURSES REQUEST:\n", request)
    isFoundStatus = False
    searchByDate = False
    searchByAvailability = False
    filterByAvailability = False
    filterByDSK = False

    if (searchOptions is not None):
        if searchOptionList.count('date') == 1:
            searchByDate = True
        if searchOptionList.count('availability') == 1:
            searchByAvailability = True
    logging.info("SEARCH OPTIONS: byAvailability: ",
        searchByAvailability, "byDate: ", searchByDate)

    if searchBy == "DSK":  # we want courses with a specific DSK
        if searchByDate:
            # Search by Date then filter results by availability, then purge DSKs
            logging.info(
                "GETCOURSES EXECUTE DATE SEARCH on DSK search; Then purge non-matching DSKs")
            resp = BB.GetCourses(limit=500000, params={'created': searchDate, 'createdCompare': searchDateOption,
                                'fields': 'id, courseId, externalId, name, organization, availability.available, dataSourceId, created, modified, hasChildren, parentId'}, sync=True)
            filterByDSK = True
            if searchByAvailability:
                filterByAvailability = True

        else:
            logging.info(
                "GETCOURSES EXECUTE DSK ONLY SEARCH; Then filter on availability if selected...")

            # DSK post request filter only, just do a standard request and return everything.
            resp = BB.GetCourses(limit=500000, params={'dataSourceId': searchValue, 'createdCompare': searchDateOption,
                                'fields': 'id, courseId, externalId, name, organization, availability.available, dataSourceId, created, modified, hasChildren, parentId'}, sync=True)
            # this is set to true to capture child courses that don't match the DSK...
            filterByDSK = True
            if searchByAvailability:
                filterByAvailability = True
            else:
                filterByAvailability = False

    # else: search is by specifics in which case unless searchOptions were for 'contains' getCourse was called and which should just return single courses.

    elif (searchBy == 'courseName'):
        resp = BB.GetCourses(limit=500000, params={
                            'name': searchValue, 'fields': 'id, courseId, externalId, name, organization, availability.available, dataSourceId, created, modified'})
    elif (searchBy == 'courseId'):
        resp = BB.GetCourses(limit=500000, params={
                            'courseId': searchValue, 'fields': 'id, courseId, externalId, name, organization, availability.available, dataSourceId, created, modified'})
    elif (searchBy == 'externalId'):
        resp = BB.GetCourses(limit=500000, params={
                            'externalId': searchValue, 'fields': 'id, courseId, externalId, name, organization, availability.available, dataSourceId, created, modified'})

    if (resp.status_code == 200):
        courses_json = resp.json()
        logging.info(f"COURSES COUNT(prepurge): ", len(courses_json["results"]))

        # are we purging DSKs based on incoming option?
        # purge results based on options
        # if this is a DSK search we have already pulled the courses based on DSK
        dsksResp = BB.GetDataSources(
            limit=5000, params={'fields': 'id, externalId'})
        dsks_json = dsksResp.json()
        dsks = dsks_json["results"]
        dsks = sortDsk(dsks, 'externalId')

        if filterByAvailability:
            # filter resp by selected availability...
            logging.info("GETCOURSES EXECUTE AVAILABILITY PURGE")
            logging.info("AVAILABILITY OPTION: ", searchAvailabilityOption)
            purgedResults = availabilityPurge(
                courses_json, searchAvailabilityOption)
            logging.info("FILTERBYAVAILABILITY PURGED AVAILABILITY RESULTS:\n", purgedResults)
            logging.info("FILTERBYAVAILABILITY PURGED RESULTS COUNT: ",
                len(purgedResults["results"]))
            courses_json = purgedResults

        if filterByDSK:
            # filter resp by selected date...
            logging.info("PURGING RESULTS based on DSK")
            purgedResults = datasourcePurge(courses_json, searchValue)
            logging.info("FILTERBYDSK PURGED DSK RESULTS:\n", purgedResults)
            logging.info("FILTERBYDSK PURGED RESULTS COUNT: ",
                len(purgedResults["results"]))
            courses_json = purgedResults

        courses_json["length"] = len(courses_json)
        logging.info("DATASOURCE PURGE: courses_json: /n", courses_json)
        logging.info("courses_json SIZE: ", len(courses_json))

        # we always want to replace dsk primary keys with the dsk externalId...
        for idx, course in enumerate(courses_json["results"]):
            for dsk in dsks:
                #logging.info("DSK:\n", dsk)
                #logging.info("DSKID: ", dsk["id"])
                if (dsk["id"] == course["dataSourceId"]):
                    courses_json["results"][idx]["dataSourceId"] = dsk["externalId"]

        logging.info("COURSES_JSON TYPE: ", type(courses_json))
        logging.info("DSKS TYPE: ", type(dsks))

        context = {
            'result_json': courses_json,
            'dsks_json': dsks,
        }

    return JsonResponse(context)

# [DONE] Update selected courses from course list (based on DSK)
def updateCourses(request):
    logging.info("UPDATE COURSES...")
    response = None
    context = None

    context = ""
    finalResponse = {}
    isFoundStatus = False
    resps = {'results': []}
    logging.info("RESPS SET TO EMPTY RESULTS")
    logging.info('updateCourses: Request:\n ')
    # print (request)
    logging.info("updateCourses: isUpdateRequired1: ",
        request.GET.get("isUpdateRequired1"))
    logging.info("updateCourses: isAvailabilityUpdateRequired1:",
        request.GET.get("isAvailabilityUpdateRequired1"))
    logging.info("updateCourses: selectedAvailability: ",
        request.GET.get("selectedAvailability"))
    logging.info("updateCourses: isDataSourceKeyUpdateRequired1: ",
        request.GET.get("isDataSourceKeyUpdateRequired1"))
    selectedDSK = request.GET.get("selectedDataSourceKey")
    logging.info("updateCourses: selectedDataSourceKey: ", selectedDSK)
    logging.info("updateCourses: pmcCourseId[]: " + request.GET.get("pmcCourseId[]"))
    updateList = request.GET.get('pmcCourseId[]')
    logging.info("updateCourses: updateList: ", updateList)
    updateCourseList = updateList.split(',')

    logging.info("updateCourses: updateCourseList: ", updateCourseList)

    passedPayload = {}

    if (request.GET.get('isAvailabilityUpdateRequired1')):
        if (request.GET.get('isAvailabilityUpdateRequired1') == 'true'):
            logging.info("updateCourses: AVAILABILITY UPDATE REQUIRED")
            passedPayload = {'availability': {
                "available": request.GET.get('selectedAvailability')}}
    if (request.GET.get('isDataSourceKeyUpdateRequired1')):
        if (request.GET.get('isDataSourceKeyUpdateRequired1') == 'true'):
            passedPayload["dataSourceId"] = request.GET.get(
                'selectedDataSourceKey')
            logging.info("updateCourses: DATASOURCE UPDATE REQUIRED")

    logging.info("updateCourses: PASSABLE PAYLOAD:\n", passedPayload)

    BB = getBBRest(request)

    dsks_json = BB.GetDataSources(
        limit=5000, params={'fields': 'id, externalId'}).json()
    dsks = dsks_json["results"]

    # ----------------------------------------------
    # insert message to local DB
    rfc = Rfc()
    message = rfc.save_message(request, "course")
    # ----------------------------------------------

    for x in range(len(updateCourseList)):
        logging.info("coursePK: ", updateCourseList[x])
        updateValue = updateCourseList[x]

        # ----------------------------------------------
        # get data BEFORE the change
        # and insert log to local DB
        rfc.save_log(request=request, updateValue=updateValue,
                    message=message, call_name='course', state='before')
        # ----------------------------------------------

        # updateCourse
        resp = BB.UpdateCourse(courseId=updateValue, payload=passedPayload, params={
                            'fields': 'id, courseId, externalId, name, availability.available, dataSourceId, created, modified'}, sync=True)

        respJSON = resp.json()

        if (resp.status_code == 200):

            # ----------------------------------------------
            # get user data AFTER the change
            # and insert log to local DB
            rfc.save_log(request=request, updateValue=updateValue,
                        message=message, call_name='course', state='after')
            # ----------------------------------------------

            logging.info("RESP:\n", resp.json())
            # resps["results"].append(respJSON["results"])
            logging.info("RESPJSON:\n", respJSON)
            logging.info("RESPJSON:dataSourceId", respJSON["dataSourceId"])
            isFoundStatus = True
            for dsk in dsks:
                # logging.info("DSK:\n", dsk)
                # logging.info("DSKID: ", dsk["id"])
                if (dsk["id"] == respJSON["dataSourceId"]):
                    logging.info("DSKEXTERNALID: ", dsk["externalId"])
                    respJSON["dataSourceId"] = dsk["externalId"]
                    logging.info("RESPJSON:dataSourceId", respJSON["dataSourceId"])
        # else:
        #     error_json["results":] = resp.json()
        #     logging.info("resp.status_code:", resp.status_code)
        #     print (f"RESPONSE:\n", error_json)

            resps["results"].append(respJSON)
            logging.info("RESPS:\n", resps)

            finalResponse = {
                "is_found": isFoundStatus,
                "result_json": resps["results"],
            }

        logging.info("FINAL RESPONSE:\n", finalResponse)
    # STOPPED HERE
    return JsonResponse(finalResponse)

# [DONE] GET memberships on selected course (based on DSK)
def getMembershipsByDSK(request):
    response = None
    context = None

    logging.info("GET MEMBERSHIPS BY DSK CALLED")
    logging.info("request method: ", request.method)

    searchBy = request.GET.get('searchBy')
    searchValue = request.GET.get('searchValue')
    crsAvailFilter = request.GET.get('crsAvailFilter')
    # pmc = request.GET.get('searchValue')
    if (searchValue is not None):
        searchValue = searchValue.strip()
    logging.info("LEARNFQDN", LEARNFQDN)
    logging.info("SEARCHBY: ", searchBy)
    logging.info("SEARCHVALUE: ", searchValue)
    logging.info("CRSAVAILFILTER: ", crsAvailFilter)

    isFoundStatus = False

    BB = getBBRest(request)

    memberships_result = BB.GetMemberships(limit=500000, params={'datasource': 'searchValue', 'expand': 'course',
                                        'fields': 'id, courseId, userId, availability.available, dataSourceId, created, modified, courseRoleId, course.name, childCourseId, course.externalId'}, sync=True)

    # logging.info("memberships_result status: ", memberships_result.status_code)
    membershipsResultJSON = memberships_result.json()
    # logging.info(f"\nmemberships_result:\n", membershipsResultJSON)

    context = {
        "is_found": isFoundStatus,
        'result_json': membershipsResultJSON,
    }

    return JsonResponse(context)

# [DONE] Retrieve the full list of Data Source Keys
def getDataSourceKeys(request):
    response = None
    context = None

    logging.info(f"getDataSourceKeys request:\n", request)

    BB = getBBRest(request)

    resp = BB.GetDataSources(
        limit=5000, params={'fields': 'id, externalId'}, sync=True)

    isFoundStatus = False
    if (resp.status_code == 200):
        result_json = resp.json()  # return actual error

        logging.info(f"GET DSKS RESP: \n", resp.json())
        logging.info(f"DSK COUNT: ", len(result_json["results"]))

        dsks = result_json["results"]
        dsks = sortDsk(dsks, 'externalId')

        isFoundStatus = True

        context = {
            "is_found": isFoundStatus,
            'result_json': dsks,
        }
    else:
        error_json = resp.json()
        logging.info(f"ERROR RESPONSE:\n", error_json)
        context = {
            "is_found": isFoundStatus,
            'error_json': error_json,
        }

    return JsonResponse(context)

# [DONE] Take a response and refactor, purging unwanted DSKs
# called by any COLLECTION request requiring availability as a search option e.g. getCourses, getUsers
#  purgedResults = datasourcePurge(resp, searchValue)
def datasourcePurge(resp, dataSourceOption):
    dataSourceToKeep = dataSourceOption
    purgedResponse = {"results": []}
    #dataSourceExternalId = dskList[dataSourceToKeep]["externalId"]
    logging.info("CALLED DATASOURCEPURGE...")
    logging.info("DATASOURCE PURGE: datasourceOption: ", dataSourceToKeep)
    logging.info("RESP:\n", resp)
    #logging.info("DATASOURCE EXTERNALID: ", dataSourceExternalId)

    # iterate over resp, and remove any records not matching the datasourceOption
    # if result:dataSourceId == datasourceToKeep then update the dataSourseExternalId.
    items = purgedResponse["results"]

    BB = getBBRest(request)

    for idx, item in enumerate(resp["results"]):
        if (item["dataSourceId"] == dataSourceToKeep):
            logging.info("ITEM: ", item)
            logging.info(type(item))
            items.append(item)
            if "hasChildren" in item and item["hasChildren"] == True:
                # get children and add to items
                logging.info("GET ITEM CHILDREN.")
                children = BB.GetCourseChildren(courseId=item["id"], limit=500000, params={
                                                'fields': 'childCourse.id, childCourse.courseId, childCourse.externalId, childCourse.name, childCourse.organization, childCourse.availability.available, childCourse.dataSourceId, childCourse.created, childCourse.hasChildren, childCourse.parentId'}, sync=True)
                if (children.status_code == 200):
                    children_json = children.json()
                    for idx2, child in enumerate(children_json["results"]):
                        child["childCourse"]["modified"] = child["childCourse"]["created"]
                        logging.info("CHILD: ", child["childCourse"])
                        items.append(child["childCourse"])

    logging.info("DATASOURCE PURGE PURGEDRESPONSE SIZE: ", len(purgedResponse))

    return purgedResponse

# [DONE] Take a response and refactor, purging unwanted Availabilty records
# called by any COLLECTION request requiring availability as a search option e.g. getCourses, getUsers
def availabilityPurge(resp, searchAvailabilityOption):
    availabilityToKeep = searchAvailabilityOption
    purgedResponse = {"results": []}

    logging.info("Called availabilityPurge")
    logging.info("AVAILABILITY PURGE: searchAvailabilityOption: ", availabilityToKeep)
    items = purgedResponse["results"]

    for idx, item in enumerate(resp["results"]):
        itemAvailability = item["availability"]["available"]
        logging.info("ITEM AVAILABILITY: ", itemAvailability.upper())
        if (item["availability"]["available"].upper() == availabilityToKeep.upper()):
            logging.info("ITEM: ", item)
            logging.info(type(item))
            items.append(item)
    # logging.info("AVAILABILITY PURGE: purgedResponse: ", purgedResponse)
    logging.info("AVAILABILITY PURGE PURGEDRESPONSE SIZE: ", len(purgedResponse))

    return purgedResponse

#[DONE: Added authwrapper]
@never_cache
def rfcreport(request):
    # global BB
    # global AUTHN_BB_JSON
    # global ISVALIDROLE
    # global EXPIRE_AT

    # AUTHN_BB_JSON = request.session.get('AUTHN_BB_JSON')
    logging.info('RFCREPORT: ENTER ')
    # logging.info('RFCREPORT: ISVALIDROLE: ' + str(ISVALIDROLE))

    if dsktool.authn_authz_utils.isAuthenticated(request) and dsktool.authn_authz_utils.isAuthorized(request):
        # get all messages
        # messages = Messages.objects.all().prefetch_related('logs')
        paginator = Paginator(Messages.objects.all().order_by(
            '-id').prefetch_related('logs'), 10)
        page = request.GET.get('page', 1)

        try:
            messages = paginator.page(page)
        except (PageNotAnInteger):
            messages = paginator.page(1)
        except (EmptyPage):
            messages = paginator.page(paginator.num_pages)
        except:
            logging.error("RFCREPORT:NO RECORDS")
            messages = ""

        context = {
            'messages': messages,
        }

        template = loader.get_template('rfcreport.html')
        response = HttpResponse(template.render(context))
    else:
        logging.info(
            f'AUTHN_AUTHZ_UTILS: AUTHN or AUTHZ FAILED! ... AUTHENTICATING!')
        response = dsktool.authn_authz_utils.authenticate(
            request, target='rfcreport')

    return response #was return render(request, 'rfcreport.html', context=context)

# [DONE] exportcsv returns only the messages table csv
def exportcsv(request):
    logging.info("ENTER EXPORTCSV")
    response = exportmessagescsv(request)
    # # exportLogs(request)
    # return HttpResponseRedirect(request.META.get('HTTP_REFERER'))
    return response

# exportcsvzip returns a zipfile containing both
# messages and logs csv files
def exportcsvzip(request):
    # from dsktool.exportzip import exportzip
    logging.info("ENTER EXPORTCSVZIP")

    # response = HttpResponse(
    #     content_type='application/zip',
    #     headers={'Content-Disposition': 'attachment; filename="DSKLogs.zip"'},
    # )

    # # get data from the database
    # messages = Messages.objects.all()
    # logs = Logs.objects.all()

    # #take streams and add to this zip

    # # write messages to the zip file

    # response = exportmessagescsv(request)
    response = exportzip(request)
    return response

# [DONE]
def exportmessagescsv(request):
    logging.info("ENTER EXPORTMESSAGES")
    items = Messages.objects.all()
    logging.info("items")
    for obj in items:
        logging.info(obj.id)
        logging.info(obj.created_at)
        logging.info(obj.user_id)
        logging.info(obj.change_type)
        logging.info(obj.change_comment)

    logging.info("PRE RESPONSE SETUP")

    response = HttpResponse(
        content_type='text/csv',
        headers={'Content-Disposition': 'attachment; filename="DSKMessages.csv"'},
    )

    logging.info("POST RESPONSE SETUP")

    logging.info("PRE WRITER INSTANTIATION")
    writer = csv.writer(response, delimiter=',')
    logging.info("WRITER INSTANTIATED")
    logging.info("WRITE HEADER")
    writer.writerow(['Time Stamp', 'User Id', 'Change Type', 'Change Comment'])

    # writer = csv.writer(response)
    # print ("WRITER INSTANTIATED")
    # print ("WRITE HEADER")
    # writer.writerow(['First row', 'Foo', 'Bar', 'Baz'])
    # print ("WRITE DATA ROW")
    # writer.writerow(['Second row', 'A', 'B', 'C', '"Testing"', "Here's a quote"])

    # messagesEntries = messagesExport.values_list('id', 'created_at', 'user_id', 'change_type', 'change_comment')

    for obj in items:
        writer.writerow([obj.id, obj.created_at, obj.user_id,
                        obj.change_type, obj.change_comment])

    return response

# [DONE]
def exportlogscsv(request):
    items = Logs.objects.all()
    logging.info("items")
    for obj in items:
        logging.info(obj.id)
        logging.info(obj.message_id)
        logging.info(obj.external_id)
        logging.info(obj.course_id)
        logging.info(obj.course_role)
        logging.info(obj.availability_status)
        logging.info(obj.datasource_id)
        logging.info(obj.state)
        logging.info(obj.created_at)

    response = HttpResponse(
        content_type='text/csv',
        headers={'Content-Disposition': 'attachment; filename="DSKLogs.csv"'},
    )
    writer = csv.writer(response, delimiter=',')
    writer.writerow(['Id', 'Message Id', 'External Id', 'Course Id', 'Course Role',
                    'Availability Status', 'Data Source', 'State', 'Created Date'])
    # logEntries = logExport.values_list('id','message_id', 'external_id', 'course_id', 'course_role', 'availability_status', 'datasource_id', 'state', 'created_at')
    for obj in items:
        writer.writerow([obj.id, obj.message_id, obj.external_id, obj.course_id, obj.course_role,
                        obj.availability_status, obj.datasource_id, obj.state, obj.created_at])

    return response

# [DONE]
def purgeData(request):
    logging.error("PURGEDATA:START")

    items = Messages.objects.all()
    items.delete()
    items = Logs.objects.all()
    items.delete()

    logging.error("PURGEDATA:END, returning to rfcreport.")

    return HttpResponseRedirect(reverse('rfcreport'))

# [DONE]
def exportzip(request):
    csv_datas = build_multiple_csv_files()
    for datum in csv_datas:
        logging.info(datum)
    timestr = time.strftime("%Y%m%d-%H%M")
    zip_file_name = "DSKTOOL_CVS__(" + timestr + ").zip"
    logging.info("ZIPFILENAME: ", zip_file_name)

    inMemoryFile = io.BytesIO()

    # zf = zipfile.ZipFile("sample.zip", mode="w", compression=zipfile.ZIP_DEFLATED)

    # with ZipFile(inMemoryFile, "w", ZIP_DEFLATED) as inMemoryFileOpened:
    # add csv files each library
    logArchiveFile = "DSKTOOL_LOGS_(" + timestr + ").csv"
    msgArchiveFile = "DSKTOOL_MSGS_(" + timestr + ").csv"
    os.environ["TZ"] = "UTC"
    for x, data in enumerate(csv_datas):
        if (x == 0):
            msgContents = ""
            csvname = "Messages.csv"
            logging.info("setting csv name for messages")
            logging.info("CSNAME: ", csvname)
            logging.info("DATA[X] TYPE: ", type(data[x]))
            msgContents = "Id,User Name,Change Type,Comment,Change Date\n"
            items = Messages.objects.all()
            for obj in items:
                changeDate = obj.created_at.strftime("%m/%d/%Y %H:%M:%S %Z")

                # 'Time Stamp', 'User Id', 'Change Type', 'Change Comment'
                objdata = [str(obj.id), str(obj.user_id), str(
                    obj.change_type), str(obj.change_comment), changeDate]
                msgContents = msgContents + ",".join(objdata) + "\n"

            # print ("MSGCONTENTS: ", msgContents)
            # inMemoryFileOpened.writestr("DSKTOOL_MSGS.csv", msgContents)

        elif (x == 1):
            logsContents = ""
            csvname = "Logs.csv"
            logging.info("CSNAME: ", csvname)
            logging.info("DATA[X] TYPE (logs expected): ", type(data[x]))
            logsContents = " ,Id,Message Id,External Id,Course Id,Course Role, Availability Status,DataSource Id,Change Date\n"
            items = Logs.objects.all()
            for obj in items:
                changeDate = obj.created_at.strftime("%m/%d/%Y %H:%M:%S %Z")
                logging.info("CHANGEDATE: ", changeDate)
                objdata = [str(obj.state), str(obj.id), str(obj.message_id), str(obj.external_id), str(
                    obj.course_id), str(obj.course_role), str(obj.availability_status), str(obj.datasource_id), changeDate]
                logsContents = logsContents + ",".join(objdata) + "\n"

            # print ("LOGCONTENTS: ", logContents)
            # print ("inMemoryFileOpened TYPE: ", inMemoryFile)
            # inMemoryFileOpened.writestr('DSKTOOL_LOGS.csv', logContents)
        else:
            logging.info("should never ever see this")

        BinaryZipPath = "DSKTOOL_CSV_(" + timestr + ").zip"

    cb = io.BytesIO()
    cbzf = ZipFile(cb, mode='w')
    cbzf.writestr(msgArchiveFile, msgContents)
    cbzf.writestr(logArchiveFile, logsContents)
    cbzf.close()
    # write buffer to disk for testing only - cannot save to disk with docker or heroku...
    # open(BinaryZipPath, 'wb').write(cb.getbuffer())
    # with ZipFile(cb) as zip_archive:
    #     for item in zip_archive.filelist:
    #         logging.info(f'\nThere are {len(zip_archive.filelist)} ZipInfo objects present in archive')

    response = HttpResponse(cb.getvalue())
    response['Content-Type'] = 'application/x-zip-compressed'
    response['Content-Disposition'] = 'attachment; filename='+zip_file_name

    return response

# [DONE]
def build_multiple_csv_files():
    messagesCSV = Messages.objects.all()
    logsCSV = Logs.objects.all()

    csv_files = [messagesCSV, logsCSV]
    return csv_files

# [DONE] AUTHNZ page using Authn_authz_Utils...
@never_cache
def authnzpage(request):
    response = None
    context = None

    logging.info(f'AUTHNZPAGE: session.keys: {request.session.keys()}')
    logging.info(" ")

    if dsktool.authn_authz_utils.isAuthenticated(request) and dsktool.authn_authz_utils.isAuthorized(request):
        jwt_utils = Jwt_token_util()
        jwt_token = jwt_utils.getSessionJWT(request)
        context = {
            'jwt_token': jwt_token,
            'decoded_token': jwt_utils.decodeJWT(jwt_token),
        }
        template = loader.get_template('authzpage.html')
        response = HttpResponse(template.render(context))
        jwt_utils = None
    else:
        logging.info(
            f'AUTHN_AUTHZ_UTILS: AUTHN or AUTHZ FAILED! ... AUTHENTICATING!')
        response = dsktool.authn_authz_utils.authenticate(
            request, target='authnzpage')

    return response
