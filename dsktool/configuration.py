import logging
import os

logging.basicConfig(
    format='%(asctime)s %(levelname)-8s %(message)s',
    level=logging.INFO,
    datefmt='%Y-%m-%d %H:%M:%S')

class Configuration():

    def __init__(self) -> None:

        try:
            from config import adict
            logging.info('CONFIGURATION CLASS INIT: using config.py...')
            self.AUTHN_KEY = adict['APPLICATION_KEY']
            self.AUTHN_SECRET = adict['APPLICATION_SECRET']
            self.AUTHN_LEARNFQDN = adict['BLACKBOARD_LEARN_INSTANCE']
            self.JWT_SECRET = adict['JWT_SECRET']
            self.DJANGO_DEBUG = adict['DJANGO_DEBUG']
            self.DJANGO_ALLOWED_HOSTS = adict['DJANGO_ALLOWED_HOSTS']
            self.DJANGO_SECRET_KEY = adict['DJANGO_SECRET_KEY']
            self.LOGGING_LEVEL = adict['LOGGING_LEVEL']

        except:
            logging.info('CONFIGURATION CLASS INIT: using os.environs...')
            self.AUTHN_KEY = os.environ['APPLICATION_KEY']
            self.AUTHN_SECRET = os.environ['APPLICATION_SECRET']
            self.AUTHN_LEARNFQDN = os.environ['BLACKBOARD_LEARN_INSTANCE']
            self.JWT_SECRET = os.environ['JWT_SECRET']
            self.DJANGO_DEBUG = os.environ['DJANGO_DEBUG']
            self.DJANGO_ALLOWED_HOSTS = os.environ['DJANGO_ALLOWED_HOSTS']
            self.DJANGO_SECRET_KEY = os.environ['DJANGO_SECRET_KEY']
            self.LOGGING_LEVEL = os.environ['LOGGING_LEVEL']

        logging.debug('CONFIGURATION CLASS INIT: config datums')
        logging.debug(f'AUTHN_KEY: {self.AUTHN_KEY}')
        logging.debug(f'AUTHN_SECRET: {self.AUTHN_SECRET}')
        logging.debug(f'AUTHN_LEARNFQDN: {self.AUTHN_LEARNFQDN}')
        logging.debug(f'JWT_SECRET: {self.JWT_SECRET}')
        logging.debug(f'DJANGO_DEBUG: {self.DJANGO_DEBUG}')
        logging.debug(f'DJANGO_ALLOWED_HOSTS: {self.DJANGO_ALLOWED_HOSTS}')
        logging.debug(f'DJANGO_SECRET_KEY: {self.DJANGO_SECRET_KEY}')
        logging.debug(f'LOGGING_LEVEL: {self.LOGGING_LEVEL}')


        
    def __del__(self):
        # logging.info('JWT_TOKEN_UTIL DESTRUCTOR CALLED')
        pass


    def getAUTHN_KEY(self):
        return self.AUTHN_KEY

    def getAUTHN_SECRET(self):
        return self.AUTHN_SECRET

    def getAUTHN_LEARNFQDN(self):
        return self.AUTHN_LEARNFQDN

    def getJWT_SECRET(self):
        return self.JWT_SECRET

    def getDJANGO_DEBUG(self):
        return self.DJANGO_DEBUG

    def getDJANGO_ALLOWED_HOSTS(self):
        return self.DJANGO_ALLOWED_HOSTS

    def getDJANGO_SECRET_KEY(self):
        return self.DJANGO_SECRET_KEY

    def getLOGGING_LEVEL(self):
        return self.LOGGING_LEVEL

    def setLOGGING_LEVEL(self, level):
        self.LOGGING_LEVEL = level

