from flask_restful import Resource
from ...storage import response_elasticsearch, ES_MAX_RESULT


class ModSecurityManifests(Resource):
    def get(self, id: str):
        if response_elasticsearch.ping() is False:
            return {
                'type': 'modsecurity',
                'data': None,
                'reason': 'InternalServerError: Can\'t connect to Elasticsearch'
            }, 500
        if not id:
            return {
                'type': 'modsecurity',
                'data': None,
                'reason': 'BadRequest: ID is required'
            }, 400
        try:
            modsecurity = response_elasticsearch.get(index='responser-modsecurity', id=id).raw
        except:
            return {
                'type': 'modsecurity',
                'data': None,
                'reason': 'NotFound'
            }, 404
        return {
            'type': 'modsecurity',
            'data': {
                'id': modsecurity['_id'],
                'responser_name': modsecurity['_source']['responser_name'],
                'responser_configuration': modsecurity['_source']['responser_configuration']
            },
            'reason': 'Success'
        }


class ModSecurityPayloadManifests(Resource):
    def get(self, id: str):
        if response_elasticsearch.ping() is False:
            return {
                'type': 'modsecurity',
                'data': None,
                'reason': 'InternalServerError: Can\'t connect to Elasticsearch'
            }, 500
        if not id:
            return {
                'type': 'modsecurity',
                'data': None,
                'reason': 'BadRequest: ID is required'
            }, 400
        try:
            payload = response_elasticsearch.get(index='responser-modsecurity-executions', id=id).raw
        except:
            return {
                'type': 'modsecurity',
                'data': None,
                'reason': 'NotFound'
            }, 404
        data = payload['_source']['payload'].replace('<', '$lt').replace('>', '$gt')
        return {
            'type': 'modsecurity',
            'data': data,
            'reason': 'Success'
        }
