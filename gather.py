from os import getenv


ES_HOST = getenv(key='ES_HOST')
ES_USER = getenv(key='ES_USER')
ES_PASS = getenv(key='ES_PASS')
ES_MAX_RESULT = getenv(key='ES_MAX_RESULT')

BACKEND_HOST = getenv(key='BACKEND_HOST')
BACKEND_PORT = getenv(key='BACKEND_PORT')
BACKEND_DEFAULT_FIREWALL = getenv(key='BACKEND_DEFAULT_FIREWALL')
BACKEND_DEFAULT_SWARM = getenv(key='BACKEND_DEFAULT_SWARM')

ANSIBLE_DATA_DIR = getenv(key='ANSIBLE_DATA_DIR')
ANSIBLE_INVENTORY = getenv(key='ANSIBLE_INVENTORY')
ANSIBLE_FIREWALL_USERNAME = getenv(key='ANSIBLE_FIREWALL_USERNAME')
ANSIBLE_FIREWALL_PASSWORD = getenv(key='ANSIBLE_FIREWALL_PW')
ANSIBLE_CRS_PATH_DIR = getenv(key='ANSIBLE_CRS_PATH_DIR')
ANSIBLE_MODSEC_CONAME = getenv(key='ANSIBLE_MODSEC_CONAME')
ANSIBLE_SWARM_USERNAME = getenv(key='ANSIBLE_SWARM_USERNAME')
ANSIBLE_SWARM_PASSWORD = getenv(key='ANSIBLE_SWARM_PW')

RABBITMQ_HOST = getenv(key='RABBITMQ_HOST')
RABBITMQ_MANAGEMENT_PORT = getenv(key='RABBITMQ_MANAGEMENT_PORT')
RABBITMQ_OPERATION_PORT = getenv(key='RABBITMQ_OPERATION_PORT')
RABBITMQ_QUEUE_NAME = getenv(key='RABBITMQ_QUEUE_NAME')
RABBITMQ_SCALER_QNAME = getenv(key='RABBITMQ_SCALER_QNAME')
RABBITMQ_USERNAME = getenv(key='RABBITMQ_USERNAME')
RABBITMQ_PASSWORD = getenv(key='RABBITMQ_PW')

PROMETHEUS_HOST = getenv(key='PROMETHEUS_HOST')
PROMETHEUS_PORT = getenv(key='PROMETHEUS_PORT')
