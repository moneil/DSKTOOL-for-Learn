from time import time
import jwt
import math
from datetime import datetime, timedelta, timezone
import json
import uuid
import logging
import os

logging.basicConfig(
    format='%(asctime)s %(levelname)-8s %(message)s',
    level=logging.INFO,
    datefmt='%Y-%m-%d %H:%M:%S')


class Jwt_token_util:

    def __init__(self) -> None:
        # logging.debug('JWT_TOKEN_UTIL INIT CALLED')
        try:
            from config import adict
            # logging.info('JWT_TOKEN_UTIL INIT: using config.py...')
            self.JWT_SECRET = adict['JWT_SECRET']
        except:
            # logging.info('JWT_TOKEN_UTIL INIT: using env settings...')
            self.JWT_SECRET = os.environ['JWT_SECRET']
            
        self.JWT_ALGORITHM = "HS256"

    def __del__(self):
        # logging.info('JWT_TOKEN_UTIL DESTRUCTOR CALLED')
        pass

    def create_jwt(self, jwtClaims):
        # print("JWT_UTILS: CREATE_JWT: CLAIMS:", jwtClaims)
        # logging.info(f'JWT_UTILS: CREATE_JWT: CLAIMS: {jwtClaims}')
        # logging.info(f'JWT_UTILS: CREATE_JWT: CLAIMS.')
        token = None
        try:
            token = jwt.encode(
                payload=jwtClaims,
                key=self.JWT_SECRET,
                algorithm="HS256"
            )

        except:
            # print("JWT_UTILS: ERROR CREATING TOKEN")
            logging.info('JWT_TOKEN_UTIL: ERROR CREATING TOKEN')

        return token

    def isVerified(self, token):
        isVerified = False
        decoded = None

        try:
            # print("JWT_UTILS: isVerified:in-token",token)
            # print("JWT_UTILS: isVerified:secret:", self.JWT_SECRET)
            # print("JWT_UTILS: isVerified:algorithm:", self.JWT_ALGORITHM)
            # logging.info(f'JWT_UTILS: isVerified: in-token: {token}')

            decoded = json.loads(json.dumps(
                jwt.decode(token, self.JWT_SECRET, self.JWT_ALGORITHM)))
            # logging.info(f'JWT_UTILS: isVerified: decoded-token: {decoded}')

            if (decoded['userRole'] == 'SystemAdmin'):
                isVerified = True
            else:
                logging.info(f'JWT_UTILS: isVerified:isVerified: {isVerified}')

            # logging.info(f'isVerified: {isVerified}')
            # logging.info(f'JWT_UTILS: isVerified token: {decoded}')
            # logging.info(f'JWT_UTILS: decoded token!')

        except jwt.ExpiredSignatureError:
            # decoded = jwt.decode(token, self.JWT_ALGORITHM, options={"verify_signature": False})
            logging.info('JWT_UTILS: decodeJWT: decode expired token:ExpiredSignatureError!')
        except jwt.exceptions.InvalidSignatureError:
            logging.info('JWT_UTILS: decodeJWT: invalid signature secret: InvalidSignatureError!')

        # logging.info(f'JWT_UTILS: isVerified returning isVerified: {isVerified}')
        

        return isVerified

    def decodeJWT(self, token):
        decoded = False
        try:
            decoded = json.loads(json.dumps(
                jwt.decode(token, self.JWT_SECRET, self.JWT_ALGORITHM)))
            # print(f'DECODED IAT: { decoded["iat"] }')

        except jwt.ExpiredSignatureError:
            # decoded = jwt.decode(token, self.JWT_ALGORITHM, options={"verify_signature": False})
            # logging.info(f'JWT_UTILS: decodeJWT: expired token: {decoded}')
            logging.debug(f'JWT_UTILS: decodeJWT: will not decode expired token!')

        return decoded

    def setSessionJWT(self, request):
        print("SETTING SESSION JWT")

    def getSessionJWT(self, request):
        jwt = None

        if ('JWT' in request.session.keys()):
            jwt = request.session['JWT']
            # logging.info(f"JWTTOKEN:{jwt}")
        return jwt
