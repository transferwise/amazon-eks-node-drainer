import boto3
import logging
import os

import kubernetes as k8s
from kubernetes.client.rest import ApiException

from k8s_utils import (abandon_lifecycle_action,
                       cordon_node, node_exists, remove_all_pods)

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

KUBE_FILEPATH = '/tmp/kubeconfig'
KUBE_CONFIG_SECRET_ARN = os.environ.get('KUBE_CONFIG_SECRET_ARN')
REGION = os.environ['AWS_REGION']

ec2 = boto3.client('ec2', region_name=REGION)
asg = boto3.client('autoscaling', region_name=REGION)
secretsmanager = boto3.client('secretsmanager', region_name=REGION)

KUBE_CLIENT_CONFIGURED = False


def get_kube_config_from_secrets_manager(secretsmanager):
    """Downloads the Kubernetes config file from SecretsManager."""
    response = secretsmanager.get_secret_value(SecretId=KUBE_CONFIG_SECRET_ARN)
    kubeconfig = response['SecretBinary'].decode('utf-8')
    with open(KUBE_FILEPATH, 'w') as f:
        f.write(kubeconfig)


def lambda_handler(event, _):
    global KUBE_CLIENT_CONFIGURED
    if not KUBE_CLIENT_CONFIGURED:
        logger.info('Downloading KUBECONFIG from Secrets Manager %s to %s', KUBE_CONFIG_SECRET_ARN, KUBE_FILEPATH)
        get_kube_config_from_secrets_manager(secretsmanager)
        k8s.config.load_kube_config(KUBE_FILEPATH)
        KUBE_CLIENT_CONFIGURED = True

    lifecycle_hook_name = event['detail']['LifecycleHookName']
    auto_scaling_group_name = event['detail']['AutoScalingGroupName']

    instance_id = event['detail']['EC2InstanceId']
    logger.info('Instance ID: ' + instance_id)
    instance = ec2.describe_instances(InstanceIds=[instance_id])[
        'Reservations'][0]['Instances'][0]

    node_name = instance['PrivateDnsName']
    logger.info('Node name: ' + node_name)

    logger.info('Checking K8s version...')
    version_api = k8s.client.VersionApi()
    k8s_version = version_api.get_code()
    logger.info('K8s version: %s', k8s_version.git_version)

    v1 = k8s.client.CoreV1Api()

    try:
        if not node_exists(v1, node_name):
            logger.error('Node not found.')
            abandon_lifecycle_action(
                asg, auto_scaling_group_name, lifecycle_hook_name, instance_id)
            return

        cordon_node(v1, node_name)

        remove_all_pods(v1, node_name, k8s_version)

        asg.complete_lifecycle_action(LifecycleHookName=lifecycle_hook_name,
                                      AutoScalingGroupName=auto_scaling_group_name,
                                      LifecycleActionResult='CONTINUE',
                                      InstanceId=instance_id)
    except ApiException:
        logger.exception(
            'There was an error removing the pods from the node {}'.format(node_name))
        abandon_lifecycle_action(
            asg, auto_scaling_group_name, lifecycle_hook_name, instance_id)

