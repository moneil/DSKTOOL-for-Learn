import jwt
import math
from datetime import datetime, timedelta, timezone
import json
import uuid
import logging

logging.basicConfig(
    format='%(asctime)s %(levelname)-8s %(message)s',
    level=logging.DEBUG,
    datefmt='%Y-%m-%d %H:%M:%S')

class Jwt_token_util:

    def __init__(self) -> None:
        logging.info('JWT_TOKEN_UTIL INIT CALLED')

        self.JWT_SECRET = 'ca6dfabd-77e7-452a-8888-84c0d89edf76'
        self.JWT_ALGORITHM = "HS256"

    def __del__(self):
        logging.info('JWT_TOKEN_UTIL DESTRUCTOR CALLED')

    def create_jwt(self, jwtClaims):
        # print("JWT_UTILS: CREATE_JWT: CLAIMS:", jwtClaims)
        logging.info(f'JWT_UTILS: CREATE_JWT: CLAIMS: {jwtClaims}')
        token = None
        try:
            token = jwt.encode(
                payload=jwtClaims,
                key=self.JWT_SECRET,
                algorithm="HS256"
            )

        except:
            # print("JWT_UTILS: ERROR CREATING TOKEN")
            logging.info('JWT_UTILS: ERROR CREATING TOKEN')
        
        return token

    def isVerified(self, token):
        isVerified = False

        try:
            # print("JWT_UTILS: isVerified:in-token",token)
            # print("JWT_UTILS: isVerified:secret:", self.JWT_SECRET)
            # print("JWT_UTILS: isVerified:algorithm:", self.JWT_ALGORITHM)
            # logging.info(f'JWT_UTILS: isVerified:in-token: {token}')
            
            decoded = json.loads(json.dumps(
                jwt.decode(token, self.JWT_SECRET, self.JWT_ALGORITHM)))
            if (decoded['userRole'] == 'SystemAdmin'): 
                isVerified=True
            else:
                logging.info(f'JWT_UTILS: isVerified:isVerified: {isVerified}')
            print("isVerified: ", isVerified)
            logging.info(f'JWT_UTILS: isVerified token: {decoded}')
            logging.info(f'JWT_UTILS: decoded token!')

        except jwt.ExpiredSignatureError:
            # decoded = jwt.decode(token, self.JWT_ALGORITHM, options={"verify_signature": False})
            logging.info('JWT_UTILS: decodeJWT: decode expired token:ExpiredSignatureError!')

        # except:
        #     print("ERROR DECODING TOKEN")

        logging.info(f'JWT_UTILS: isVerified returning isVerified: {isVerified}')

        return isVerified

    def decodeJWT(self, token):
        decoded = False
        try:
            decoded = json.loads(json.dumps(
                jwt.decode(token, self.JWT_SECRET, self.JWT_ALGORITHM)))

        except jwt.ExpiredSignatureError:
            decoded = jwt.decode(token, self.JWT_ALGORITHM, options={"verify_signature": False})
            logging.info(f'JWT_UTILS: decodeJWT: expired token: {decoded}')
            logging.info(f'JWT_UTILS: decodeJWT:decode expired token!')

        return decoded

    def setSessionJWT(self, request):
        print ("SETTING SESSION JWT")

    def getSessionJWT(self, request):
        jwt = None

        if ('JWT' in request.COOKIES):
           jwt = request.COOKIES['JWT']
        #    logging.info(f"JWTTOKEN:{jwt}")
        return jwt