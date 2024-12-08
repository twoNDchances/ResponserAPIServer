from flask_restful import Resource
from json import loads
from ...storage import response_elasticsearch, ES_MAX_RESULT


class ModSecurityLists(Resource):
    def get(self):
        if response_elasticsearch.ping() is False:
            return {
                'type': 'modsecurity',
                'data': None,
                'reason': 'InternalServerError: Can\'t connect to Elasticsearch'
            }, 500
        modsecurity = response_elasticsearch.search(index='responser-modsecurity', query={'match_all': {}}, size=ES_MAX_RESULT).raw
        if modsecurity['hits']['hits'].__len__() == 0:
            return {
                'type': 'modsecurity',
                'data': None,
                'reason': 'NotFound'
            }, 404
        return {
            'type': 'modsecurity',
            'data': [{
                'id': modsec['_id'],
                'responser_name': modsec['_source']['responser_name'],
                'is_enabled': loads(modsec['_source']['responser_configuration']).get('is_enabled'),
                'ip_address': loads(modsec['_source']['responser_configuration']).get('ip_address').get('is_used'),
                'payload': loads(modsec['_source']['responser_configuration']).get('payload').get('is_used'),
                'advanced': loads(modsec['_source']['responser_configuration']).get('advanced').get('is_enabled'),
            } for modsec in modsecurity['hits']['hits']],
            'reason': 'Success'
        }


class ModSecurityExecutionLists(Resource):
    def get(self):
        if response_elasticsearch.ping() is False:
            return {
                'type': 'modsecurity',
                'data': None,
                'reason': 'InternalServerError: Can\'t connect to Elasticsearch'
            }, 500
        modsecurity_executions = response_elasticsearch.search(index='responser-modsecurity-executions', query={'match_all': {}}, size=ES_MAX_RESULT).raw
        if modsecurity_executions['hits']['hits'].__len__() == 0:
            return {
                'type': 'modsecurity',
                'data': None,
                'reason': 'NotFound'
            }, 404
        return {
            'type': 'modsecurity',
            'data': [{
                'id': modsecurity_execution['_id'],
                'responser_name': modsecurity_execution['_source']['responser_name'],
                'status': modsecurity_execution['_source']['status'],
                'secrule_id': modsecurity_execution['_source']['secrule_id'],
                'type': modsecurity_execution['_source']['type'],
                'for': modsecurity_execution['_source']['for'],
                'start': modsecurity_execution['_source']['start'],
                'relationship': modsecurity_execution['_source']['relationship']
            } for modsecurity_execution in modsecurity_executions['hits']['hits']],
            'reason': 'Success'
        }


class ModSecurityErrorlogLists(Resource):
    def get(self, responser_name: str):
        if response_elasticsearch.ping() is False:
            return {
                'type': 'modsecurity',
                'data': None,
                'reason': 'InternalServerError: Can\'t connect to Elasticsearch'
            }, 500
        if not responser_name:
            return {
                'type': 'modsecurity',
                'data': None,
                'reason': 'BadRequest: Responser Name is required'
            }, 400
        error_logs = response_elasticsearch.search(index='responser-modsecurity-errorlogs', query={
            'term': {
                'responser_name.keyword': responser_name
            }
        }, size=ES_MAX_RESULT).raw
        if error_logs['hits']['hits'].__len__() == 0:
            return {
                'type': 'modsecurity',
                'data': None,
                'reason': 'NotFound'
            }, 404
        return {
            'type': 'modsecurity',
            'data': [{
                'message': error_log['_source']['message'],
                'pattern': error_log['_source']['pattern']
            } for error_log in error_logs['hits']['hits']],
            'reason': 'NotFound'
        }
