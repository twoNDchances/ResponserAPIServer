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


class ModSecurityTerminations(Resource):
    def delete(self, responser_name: str):
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
        modsecurity = response_elasticsearch.search(index='responser-modsecurity', query={
            'term': {
                'responser_name.keyword': responser_name
            }
        }, size=ES_MAX_RESULT).raw
        if modsecurity['hits']['hits'].__len__() != 1:
            return {
                'type': 'modsecurity',
                'data': None,
                'reason': 'NotFound'
            }, 404
        response_elasticsearch.delete(index='responser-modsecurity', id=modsecurity['hits']['hits'][0]['_id'])
        response_elasticsearch.delete_by_query(index='responser-modsecurity-timestamps', query={
            'term': {
                'responser_name.keyword': responser_name
            }
        })
        response_elasticsearch.delete_by_query(index='responser-modsecurity-errorlogs', query={
            'term': {
                'responser_name.keyword': responser_name
            }
        })
        return {
            'type': 'modsecurity',
            'data': None,
            'reason': 'Success'
        }


class ModSecurityExecutionTerminations(Resource):
    def delete(self, id: str):
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
                'reason': 'BadRequest: ID is required, or must in ["error", "duplicated"]'
            }, 400
        if id in ['error', 'duplicated']:
            modsecurity_executions = response_elasticsearch.search(index='responser-modsecurity-executions', query={
                'term': {
                    'status.keyword': id
                }
            }, size=ES_MAX_RESULT).raw['hits']['hits']
            if modsecurity_executions.__len__() > 0:
                response_elasticsearch.delete_by_query(index='responser-modsecurity-executions', query={
                    'term': {
                        'status.keyword': id
                    }
                })
            return {
                'type': 'modsecurity',
                'data': [
                    modsecurity_execution_id['_id'] for modsecurity_execution_id in modsecurity_executions
                ],
                'reason': 'Success'
            }
        try:
            modsecurity_execution = response_elasticsearch.get(index='responser-modsecurity-executions', id=id).raw
        except:
            return {
                'type': 'modsecurity',
                'data': None,
                'reason': 'NotFound'
            }, 404
        data = []
        unique_id = uuid4()
        if modsecurity_execution['_source']['relationship'] is None:
            data = [{'id': modsecurity_execution['_id']}]
            if modsecurity_execution['_source']['status'] == 'running':
                delete_single_runner = run(
                    private_data_dir=ANSIBLE_DATA_DIR,
                    playbook='../api/modsecurity/playbooks/ansible_delete_modsecurity.yaml',
                    inventory=ANSIBLE_INVENTORY,
                    extravars={
                        'username_firewall_node': ANSIBLE_FIREWALL_USERNAME,
                        'password_firewall_node': ANSIBLE_FIREWALL_PASSWORD,
                        'secrule_file': f'{ANSIBLE_CRS_PATH_DIR}/REQUEST-{modsecurity_execution["_source"]["secrule_id"]}-*',
                        'modsec_container_name': ANSIBLE_MODSEC_CONAME
                    },
                    host_pattern='firewall',
                    json_mode=True,
                    quiet=True,
                    ident=unique_id
                )
                error_message = None
                for event in delete_single_runner.events:
                    if event.get('event') == 'runner_on_unreachable':
                        error_message = event['stdout']
                        break
                    if event.get('event') == 'runner_on_failed':
                        error_message = event['stdout']
                        break
                if delete_single_runner.status == 'failed':
                    rmtree(path=f'{ANSIBLE_DATA_DIR.replace('.', '')}artifacts/{unique_id}', ignore_errors=True)
                    return {
                        'type': 'modsecurity',
                        'data': None,
                        'reason': 'InternalServerError' if error_message is None else f'InternalServerError: {error_message}'
                    }, 500
            response_elasticsearch.delete(index='responser-modsecurity-executions', id=modsecurity_execution['_id'])
        else:
            try:
                modsecurity_execution_relationship = response_elasticsearch.get(
                    index='responser-modsecurity-executions',
                    id=modsecurity_execution['_source']['real_id_relationship']
                )
            except:
                response_elasticsearch.delete(index='responser-modsecurity-executions', id=modsecurity_execution['_id'])
                return {
                    'type': 'modsecurity',
                    'data': [{
                        'id': modsecurity_execution['_id']
                    }],
                    'reason': f'NotFound: Execution related not found with SecRule ID is {modsecurity_execution["_source"]['relationship']}'
                }, 404
            data = [
                {'id': modsecurity_execution['_id']},
                {'id': modsecurity_execution_relationship['_id']}
            ]
            if modsecurity_execution_relationship['_source']['status'] == 'running' and modsecurity_execution['_source']['status'] == 'running':
                delete_multiple_runner = run(
                    private_data_dir=ANSIBLE_DATA_DIR,
                    playbook='../api/modsecurity/playbooks/ansible_delete_modsecurity.yaml',
                    inventory=ANSIBLE_INVENTORY,
                    extravars={
                        'username_firewall_node': ANSIBLE_FIREWALL_USERNAME,
                        'password_firewall_node': ANSIBLE_FIREWALL_PASSWORD,
                        'secrule_file': f'{ANSIBLE_CRS_PATH_DIR}/REQUEST-{(
                            modsecurity_execution["_source"]["secrule_id"] 
                            if modsecurity_execution["_source"]["for"] == "ip" 
                            else modsecurity_execution_relationship["_source"]["secrule_id"]
                        )}-{(
                            modsecurity_execution_relationship["_source"]["secrule_id"] 
                            if modsecurity_execution_relationship["_source"]["for"] == 'chain' 
                            else modsecurity_execution["_source"]["secrule_id"]
                        )}-*',
                        'modsec_container_name': ANSIBLE_MODSEC_CONAME
                    },
                    host_pattern='firewall',
                    json_mode=True,
                    quiet=True,
                    ident=unique_id
                )
                error_message = None
                for event in delete_multiple_runner.events:
                    if event.get('event') == 'runner_on_unreachable':
                        error_message = event['stdout']
                        break
                    if event.get('event') == 'runner_on_failed':
                        error_message = event['stdout']
                        break
                if delete_multiple_runner.status == 'failed':
                    rmtree(path=f'{ANSIBLE_DATA_DIR.replace('.', '')}artifacts/{unique_id}', ignore_errors=True)
                    return {
                        'type': 'modsecurity',
                        'data': None,
                        'reason': 'InternalServerError' if error_message is None else f'InternalServerError: {error_message}'
                    }, 500
            response_elasticsearch.delete(index='responser-modsecurity-executions', id=modsecurity_execution['_id'])
            response_elasticsearch.delete(index='responser-modsecurity-executions', id=modsecurity_execution_relationship['_id'])
        rmtree(path=f'{ANSIBLE_DATA_DIR.replace('.', '')}artifacts/{unique_id}', ignore_errors=True)
        return {
            'type': 'modsecurity',
            'data': data,
            'reason': 'Success'
        }

class ModSecurityEmptyErrorLogs(Resource):
    def delete(self, responser_name: str):
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
        modsecurity_error_logs = response_elasticsearch.search(index='responser-modsecurity-errorlogs', query={
            'term': {
                'responser_name.keyword': responser_name
            }
        }, size=ES_MAX_RESULT).raw
        if modsecurity_error_logs['hits']['hits'].__len__() == 0:
            return {
                'type': 'modsecurity',
                'data': None,
                'reason': 'NotFound'
            }, 404
        response_elasticsearch.delete_by_query(index='responser-modsecurity-errorlogs', query={
            'term': {
                'responser_name.keyword': responser_name
            }
        })
        return {
            'type': 'modsecurity',
            'data': None,
            'reason': 'Success'
        }
