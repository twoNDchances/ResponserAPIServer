from flask_restful import Resource
from ansible_runner import run
from shutil import rmtree
from uuid import uuid4
from ...storage import (
    response_elasticsearch, 
    ES_MAX_RESULT, 
    ANSIBLE_DATA_DIR, 
    ANSIBLE_INVENTORY, 
    ANSIBLE_FIREWALL_USERNAME, 
    ANSIBLE_FIREWALL_PASSWORD, 
    ANSIBLE_MODSEC_CONAME, 
    ANSIBLE_CRS_PATH_DIR
)


class SwarmTerminations(Resource):
    def delete(self, responser_name: str):
        if response_elasticsearch.ping() is False:
            return {
                'type': 'swarm',
                'data': None,
                'reason': 'InternalServerError: Can\'t connect to Elasticsearch'
            }, 500
        if not responser_name:
            return {
                'type': 'swarm',
                'data': None,
                'reason': 'BadRequest: Responser Name is required'
            }, 400
        swarm = response_elasticsearch.search(index='responser-swarm', query={
            'term': {
                'responser_name.keyword': responser_name
            }
        }, size=ES_MAX_RESULT).raw
        if swarm['hits']['hits'].__len__() != 1:
            return {
                'type': 'swarm',
                'data': None,
                'reason': 'NotFound'
            }, 404
        response_elasticsearch.delete(index='responser-swarm', id=swarm['hits']['hits'][0]['_id'])
        response_elasticsearch.delete_by_query(index='responser-swarm-timestamps', query={
            'term': {
                'responser_name.keyword': responser_name
            }
        })
        response_elasticsearch.delete_by_query(index='responser-swarm-errorlogs', query={
            'term': {
                'responser_name.keyword': responser_name
            }
        })
        response_elasticsearch.delete_by_query(index='responser-swarm-executions', query={
            'term': {
                'responser_name.keyword': responser_name
            }
        })
        return {
            'type': 'swarm',
            'data': None,
            'reason': 'Success'
        }


class SwarmEmptyErrorLogs(Resource):
    def delete(self, responser_name: str):
        if response_elasticsearch.ping() is False:
            return {
                'type': 'swarm',
                'data': None,
                'reason': 'InternalServerError: Can\'t connect to Elasticsearch'
            }, 500
        if not responser_name:
            return {
                'type': 'swarm',
                'data': None,
                'reason': 'BadRequest: Responser Name is required'
            }, 400
        swarm_error_logs = response_elasticsearch.search(index='responser-swarm-errorlogs', query={
            'term': {
                'responser_name.keyword': responser_name
            }
        }, size=ES_MAX_RESULT).raw
        if swarm_error_logs['hits']['hits'].__len__() == 0:
            return {
                'type': 'swarm',
                'data': None,
                'reason': 'NotFound'
            }, 404
        response_elasticsearch.delete_by_query(index='responser-swarm-errorlogs', query={
            'term': {
                'responser_name.keyword': responser_name
            }
        })
        return {
            'type': 'swarm',
            'data': None,
            'reason': 'Success'
        }
