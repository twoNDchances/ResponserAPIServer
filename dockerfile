FROM python:3

WORKDIR /responsers

COPY requirements.txt ./
RUN apt update -y && apt install -y ansible sshpass && pip install --no-cache-dir -r requirements.txt

COPY . .

ENV ES_HOST="http://elasticsearch:9200" \
    ES_USER="elastic" \
    ES_PASS="elastic" \
    ES_MAX_RESULT=1000000000 \
    BACKEND_HOST="0.0.0.0" \
    BACKEND_PORT=9948 \
    BACKEND_DEFAULT_FIREWALL="192.168.1.15" \
    BACKEND_DEFAULT_SWARM="192.168.1.7" \
    ANSIBLE_DATA_DIR="/responsers/config/." \
    ANSIBLE_INVENTORY="/responsers/config/hosts" \
    ANSIBLE_CRS_PATH_DIR="/crs" \
    ANSIBLE_MODSEC_CONAME="modsecurity" \
    ANSIBLE_FIREWALL_USERNAME="root" \
    ANSIBLE_FIREWALL_PW="cxt" \
    ANSIBLE_SWARM_USERNAME="root" \
    ANSIBLE_SWARM_PW="cxt7" \
    RABBITMQ_HOST="rabbitmq" \
    RABBITMQ_MANAGEMENT_PORT=15672 \
    RABBITMQ_OPERATION_PORT=5672 \
    RABBITMQ_QUEUE_NAME="modsecurity-raw" \
    RABBITMQ_SCALER_QNAME="swarm-scaling" \
    RABBITMQ_USERNAME="guest" \
    RABBITMQ_PW="guest" \
    PROMETHEUS_HOST="prometheus" \
    PROMETHEUS_PORT=9090

CMD [ "python", "./run.py" ]
