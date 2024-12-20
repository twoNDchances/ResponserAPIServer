from flask import Blueprint
from .operations import resources_operation_blueprint


resources_main_blueprint = Blueprint(name='resources_main_blueprint', import_name=__name__)

resources_main_blueprint.register_blueprint(blueprint=resources_operation_blueprint, url_prefix='/resources')
