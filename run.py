from os import getenv
from api import application
from gather import BACKEND_HOST, BACKEND_PORT
from setup import setup_elasticsearch


if __name__ == '__main__':
    environment_variables = {
        'ES_HOST': 'http://localhost:9200',
        'ES_USER': 'elastic',
        'ES_PASS': 'elastic',
        'ES_MAX_RESULT': 1000000000,
        'BACKEND_HOST': '0.0.0.0',
        'BACKEND_PORT': 9948,
        'BACKEND_DEFAULT_FIREWALL': '192.168.1.14',
        'BACKEND_DEFAULT_SWARM': '192.168.1.7',
        'ANSIBLE_FIREWALL_USERNAME': 'root',
        'ANSIBLE_FIREWALL_PW': 'cxt',
        'ANSIBLE_SWARM_USERNAME': 'root',
        'ANSIBLE_SWARM_PW': 'cxt9',
        'RABBITMQ_HOST': 'rabbitmq',
        'RABBITMQ_MANAGEMENT_PORT': 15672,
        'RABBITMQ_OPERATION_PORT': 5672,
        'RABBITMQ_QUEUE_NAME': 'modsecurity-rules',
        'RABBITMQ_USERNAME': 'admin',
        'RABBITMQ_PW': 'admin',
        'PROMETHEUS_HOST': 'http://prometheus',
        'PROMETHEUS_PORT': 9090
    }
    config = {variable: getenv(variable, default) for variable, default in environment_variables.items()}
    print('========== Environment Variable Configurations ==========')
    for variable, value in config.items():
        if variable in ['ES_PASS', 'ANSIBLE_FIREWALL_PW', 'ANSIBLE_SWARM_PW', 'RABBITMQ_PW']:
            print(f'{variable.replace('PW', 'PASSWORD')} = {"*" * value.__len__()}')
        else:
            print(f'{variable} = {value}')
    print('=========================================================', end='\n\n')
    print('=============== Elasticsearch Setting Up ================')
    setup_elasticsearch()
    print('=========================================================', end='\n\n')
    application.run(debug=True, host=BACKEND_HOST, port=BACKEND_PORT)