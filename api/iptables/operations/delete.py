from flask_restful import Resource
from ansible_runner import run
import re
from shutil import rmtree
import uuid
from ...storage import response_elasticsearch, ES_MAX_RESULT, ANSIBLE_DATA_DIR, ANSIBLE_FIREWALL_PASSWORD, ANSIBLE_FIREWALL_USERNAME, ANSIBLE_INVENTORY


class IPTablesTerminations(Resource):
    def delete(self, responser_name: str):
        if response_elasticsearch.ping() is False:
            return {
                'type': 'iptables',
                'data': None,
                'reason': 'InternalServerError: Can\'t connect to Elasticsearch'
            }, 500
        if not responser_name:
            return {
                'type': 'iptables',
                'data': None,
                'reason': 'BadRequest: Responser Name is required'
            }, 400
        iptables = response_elasticsearch.search(index='responser-iptables', query={
            'term': {
                'responser_name.keyword': responser_name
            }
        }, size=ES_MAX_RESULT).raw
        if iptables['hits']['hits'].__len__() != 1:
            return {
                'type': 'iptables',
                'data': None,
                'reason': 'NotFound'
            }, 404
        response_elasticsearch.delete(index='responser-iptables', id=iptables['hits']['hits'][0]['_id'])
        response_elasticsearch.delete_by_query(index='responser-iptables-timestamps', query={
            'term': {
                'responser_name.keyword': responser_name
            }
        })
        response_elasticsearch.delete_by_query(index='responser-iptables-errorlogs', query={
            'term': {
                'responser_name.keyword': responser_name
            }
        })
        return {
            'type': 'iptables',
            'data': None,
            'reason': 'Success'
        }


class IPTablesExecutionTerminations(Resource):
    def delete(self, id: str):
        if response_elasticsearch.ping() is False:
            return {
                'type': 'iptables',
                'data': None,
                'reason': 'InternalServerError: Can\'t connect to Elasticsearch'
            }, 500
        if not id:
            return {
                'type': 'iptables',
                'data': None,
                'reason': 'BadRequest: ID is required'
            }, 400
        try:
            iptables_execution = response_elasticsearch.get(index='responser-iptables-executions', id=id).raw
        except:
            return {
                'type': 'iptables',
                'data': None,
                'reason': 'NotFound'
            }, 404
        state = iptables_execution['_source']['state']
        if state in ['limitation', 'temporary']:
            response_elasticsearch.delete(index='responser-iptables-executions', id=iptables_execution['_id'])
        if state in ['forever']:
            unique_id_list_iptables = uuid.uuid4()
            runner = run(
                private_data_dir=ANSIBLE_DATA_DIR,
                playbook='../api/iptables/playbooks/ansible_list_iptables.yaml',
                inventory=ANSIBLE_INVENTORY,
                extravars={
                    'username_firewall_node': ANSIBLE_FIREWALL_USERNAME,
                    'password_firewall_node': ANSIBLE_FIREWALL_PASSWORD
                },
                host_pattern='firewall',
                json_mode=True,
                quiet=True,
                ident=unique_id_list_iptables
            )
            if runner.rc != 0:
                return {
                    'type': 'iptables',
                    'data': None,
                    'reason': 'InternalServerError: "ansible_list_iptables.yaml" can\'t run'
                }, 500
            related_rules = []
            for event in runner.events:
                if event['event'] == 'runner_on_ok':
                    related_rules = event['event_data']['res']['stdout_lines']
            pattern = r'DOCKER-USER -s (\d+\.\d+\.\d+\.\d+(?:/\d+)?) -j DROP$'
            related_rule_matches = []
            for related_rule in related_rules:
                match = re.search(pattern, related_rule)
                if match:
                    related_rule_matches.append(related_rule)
            related_rule_ips = []
            for related_rule_match in related_rule_matches:
                if iptables_execution['_source']['target_ip_field'] in related_rule_match:
                    related_rule_ips.append(related_rule_match)
            unique_id_delete_iptables = uuid.uuid4()
            if related_rule_ips.__len__() == 1:
                delete_single_runner = run(
                    private_data_dir=ANSIBLE_DATA_DIR,
                    playbook='../api/iptables/playbooks/ansible_delete_single_iptables.yaml',
                    inventory=ANSIBLE_INVENTORY,
                    extravars={
                        'username_firewall_node': ANSIBLE_FIREWALL_USERNAME,
                        'password_firewall_node': ANSIBLE_FIREWALL_PASSWORD,
                        'target_ip_field': iptables_execution['_source']['target_ip_field']
                    },
                    host_pattern='firewall',
                    json_mode=True,
                    quiet=True,
                    ident=unique_id_delete_iptables
                )
                if delete_single_runner.rc != 0:
                    return {
                        'type': 'iptables',
                        'data': None,
                        'reason': 'InternalServerError: "ansible_delete_single_iptables.yaml" can\'t run'
                    }, 500
            if related_rule_ips.__len__() > 1:
                delete_multiple_runner = run(
                    private_data_dir=ANSIBLE_DATA_DIR,
                    playbook='../api/iptables/playbooks/ansible_delete_multiple_iptables.yaml',
                    inventory=ANSIBLE_INVENTORY,
                    extravars={
                        'username_firewall_node': ANSIBLE_FIREWALL_USERNAME,
                        'password_firewall_node': ANSIBLE_FIREWALL_PASSWORD,
                        'ip_list': [iptables_execution['_source']['target_ip_field'] for _ in range(related_rule_ips.__len__())]
                    },
                    host_pattern='firewall',
                    json_mode=True,
                    quiet=True,
                    ident=unique_id_delete_iptables
                )
                if delete_multiple_runner.rc != 0:
                    return {
                        'type': 'iptables',
                        'data': None,
                        'reason': 'InternalServerError: "ansible_delete_single_iptables.yaml" can\'t run'
                    }, 500
            response_elasticsearch.delete(index='responser-iptables-executions', id=iptables_execution['_id'])
            rmtree(path=f'{ANSIBLE_DATA_DIR.replace('.', '')}artifacts/{unique_id_delete_iptables}', ignore_errors=True)
            rmtree(path=f'{ANSIBLE_DATA_DIR.replace('.', '')}artifacts/{unique_id_list_iptables}', ignore_errors=True)
        return {
            'type': 'iptables',
            'data': None,
            'reason': 'Success'
        }


class IPTablesEmptyErrorLogs(Resource):
    def delete(self, responser_name: str):
        if response_elasticsearch.ping() is False:
            return {
                'type': 'iptables',
                'data': None,
                'reason': 'InternalServerError: Can\'t connect to Elasticsearch'
            }, 500
        if not responser_name:
            return {
                'type': 'iptables',
                'data': None,
                'reason': 'BadRequest: Responser Name is required'
            }, 400
        iptables_error_logs = response_elasticsearch.search(index='responser-iptables-errorlogs', query={
            'term': {
                'responser_name.keyword': responser_name
            }
        }, size=ES_MAX_RESULT).raw
        if iptables_error_logs['hits']['hits'].__len__() == 0:
            return {
                'type': 'iptables',
                'data': None,
                'reason': 'NotFound'
            }, 404
        response_elasticsearch.delete_by_query(index='responser-iptables-errorlogs', query={
            'term': {
                'responser_name.keyword': responser_name
            }
        })
        return {
            'type': 'iptables',
            'data': None,
            'reason': 'Success'
        }
