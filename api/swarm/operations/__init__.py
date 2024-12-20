from flask import Blueprint
from flask_restful import Api
from .create import SwarmCreation
from .list import SwarmLists, SwarmExecutionLists, SwarmErrorLogsLists
from .show import SwarmManifests, SwarmExecutionLastLogs
from .update import SwarmModifications
from .delete import SwarmTerminations, SwarmEmptyErrorLogs


swarm_operation_blueprint = Blueprint(name='swarm_operation_blueprint', import_name=__name__)
swarm_operation_api = Api(app=swarm_operation_blueprint)

swarm_operation_api.add_resource(SwarmCreation, '/create')
swarm_operation_api.add_resource(SwarmLists, '/list')
swarm_operation_api.add_resource(SwarmExecutionLists, '/list-executions')
swarm_operation_api.add_resource(SwarmErrorLogsLists, '/list-errorlogs/<string:responser_name>')
swarm_operation_api.add_resource(SwarmManifests, '/show/<string:id>')
swarm_operation_api.add_resource(SwarmExecutionLastLogs, '/show-lastlogs/<string:id>')
swarm_operation_api.add_resource(SwarmModifications, '/update/<string:id>')
swarm_operation_api.add_resource(SwarmTerminations, '/delete/<string:responser_name>')
swarm_operation_api.add_resource(SwarmEmptyErrorLogs, '/empty-errorlogs/<string:responser_name>')
