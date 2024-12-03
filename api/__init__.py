from json import loads
from flask import Flask, request
from flask_cors import CORS

from .iptables import iptables_main_blueprint, iptables_responser_blueprint
from .modsecurity import modsecurity_main_blueprint, modsecurity_responser_blueprint

from .storage import ES_USER, ES_PASS, reset_elasticsearch

application = Flask(import_name=__name__)
CORS(app=application)

@application.route(rule='/', methods=['GET', 'POST'])
def root_page():
    return {
        'type': 'connections',
        'data': None,
        'reason': 'Success: Hello World from Responsers'
    }

@application.route(rule='/reset-elasticsearch', methods=['POST'])
def reset_elasticsearch_page():
    try:
        loads(request.data)
    except:
        return {
            'type': 'storages', 
            'reason': 'BadRequest: Body must be JSON', 
            'data': None
        }, 400
    request_body = dict(request.get_json())
    elasticsearch_username = request_body.get('elasticsearchUsername')
    elasticsearch_password = request_body.get('elasticsearchPassword')
    if elasticsearch_username is None or elasticsearch_password is None:
        return {
            'type': 'storages', 
            'reason': 'BadRequest: Username or Password are required', 
            'data': None
        }, 400
    if elasticsearch_username != ES_USER or elasticsearch_password != ES_PASS:
        return {
            'type': 'storages', 
            'reason': 'Unauthorized: Incorrect Username or Password', 
            'data': None
        }, 401
    if reset_elasticsearch() is False:
        return {
            'type': 'storages', 
            'reason': 'InternalServerError: Can\'t connect to Elasticsearch', 
            'data': None
        }, 500
    return {
        'type': 'storages', 
        'reason': 'Success', 
        'data': None
    }
    

@application.errorhandler(code_or_exception=404)
def not_found_page(error):
    return {
        'type': 'errors',
        'data': None,
        'reason': 'NotFound'
    }, 404

@application.errorhandler(code_or_exception=405)
def method_not_allowed_page(error):
    return {
        'type': 'errors',
        'data': None,
        'reason': 'MethodNotAllowed'
    }, 405

@application.errorhandler(code_or_exception=500)
def internal_server_error_page(error):
    return {
        'type': 'errors',
        'data': None,
        'reason': 'InternalServerError'
    }, 500


application.register_blueprint(blueprint=iptables_main_blueprint, url_prefix='/api')
application.register_blueprint(blueprint=modsecurity_main_blueprint, url_prefix='/api')

application.register_blueprint(blueprint=iptables_responser_blueprint)
application.register_blueprint(blueprint=modsecurity_responser_blueprint)
