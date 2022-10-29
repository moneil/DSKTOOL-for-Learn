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

    JWT_SECRET = 'ca6dfabd-77e7-452a-8888-84c0d89edf76'
    JWT_ALGORITHM = "HS256"

    def __del__(self):
        print("JWT_TOKEN_UTIL DESTRUCTOR CALLED")

    def create_jwt(self, jwtClaims):
        # print("JWT_UTILS: CREATE_JWT: CLAIMS:", jwtClaims)
        logging.info('JWT_UTILS: CREATE_JWT: CLAIMS: {jwtClaims}')
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
            logging.info('JWT_UTILS: isVerified:in-token: ' + str(token))
            
            decoded = json.loads(json.dumps(
                jwt.decode(token, self.JWT_SECRET, self.JWT_ALGORITHM)))
            if (decoded['userRole'] == 'SystemAdmin'): 
                isVerified=True
            else:
                logging.info('JWT_UTILS: isVerified:isVerified: ' + str(isVerified))
            print("isVerified: ", isVerified)
            logging.info('JWT_UTILS: decoded token: ' + str(decoded))

        except jwt.ExpiredSignatureError:
            # decoded = jwt.decode(token, self.JWT_ALGORITHM, options={"verify_signature": False})
            print("decodeJWT:decode expired token:ExpiredSignatureError")

        # except:
        #     print("ERROR DECODING TOKEN")

        logging.info('JWT_UTILS: returning isVerified: ' + str(isVerified))

        return isVerified

    def decodeJWT(self, token):
        decoded = False
        try:
            decoded = json.loads(json.dumps(
                jwt.decode(token, self.JWT_SECRET, self.JWT_ALGORITHM)))

        except jwt.ExpiredSignatureError:
            decoded = jwt.decode(token, self.JWT_ALGORITHM, options={"verify_signature": False})
            print("decodeJWT:decode expired token:", decoded)
        
        return decoded
