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
        'ANSIBLE_DATA_DIR': '/root/Responsers/config/.',
        'ANSIBLE_INVENTORY': '/root/Responsers/config/hosts',
        'ANSIBLE_FIREWALL_USERNAME': 'cxt',
        'ANSIBLE_FIREWALL_PASSWORD': 'cxt',
        'ANSIBLE_SWARM_USERNAME': '',
        'ANSIBLE_SWARM_PASSWORD': ''
    }
    config = {variable: getenv(variable, default) for variable, default in environment_variables.items()}
    print('========== Environment Variable Configurations ==========')
    for variable, value in config.items():
        if variable in ['ES_PASS', 'ANSIBLE_FIREWALL_PASSWORD', 'ANSIBLE_SWARM_PASSWORD']:
            print(f'{variable} = {"*" * value.__len__()}')
        else:
            print(f'{variable} = {value}')
    print('=========================================================', end='\n\n')
    print('=============== Elasticsearch Setting Up ================')
    setup_elasticsearch()
    print('=========================================================', end='\n\n')
    application.run(debug=True, host=BACKEND_HOST, port=BACKEND_PORT)