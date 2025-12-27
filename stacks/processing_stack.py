"""
Processing Stack
Lambda, Step Functions, DynamoDB, and Amazon Fraud Detector for real-time fraud scoring
"""

from aws_cdk import (
    Stack,
    Duration,
    RemovalPolicy,
    CfnOutput,
    Tags,
    aws_lambda as lambda_,
    aws_lambda_event_sources as lambda_events,
    aws_iam as iam,
    aws_dynamodb as dynamodb,
    aws_stepfunctions as sfn,
    aws_stepfunctions_tasks as tasks,
    aws_logs as logs,
    aws_cloudwatch as cloudwatch,
    aws_cloudwatch_actions as cw_actions,
    aws_sqs as sqs,
    aws_frauddetector as frauddetector,
)
from constructs import Construct


class ProcessingStack(Stack):
    """Real-time fraud processing and ML scoring pipeline"""

    def __init__(self, scope: Construct, construct_id: str, streaming_stack, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        self.streaming = streaming_stack

        # Apply tags
        Tags.of(self).add("Project", "RTFraudDetection")
        Tags.of(self).add("Component", "Processing")
        Tags.of(self).add("Compliance", "PCI-DSS")

        # =================================================================
        # DYNAMODB TABLES
        # =================================================================
        
        # Transactions table - stores all transactions with fraud scores
        self.transactions_table = dynamodb.Table(
            self, "TransactionsTable",
            table_name="fraud-detection-transactions",
            partition_key=dynamodb.Attribute(
                name="transaction_id",
                type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="timestamp",
                type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            encryption=dynamodb.TableEncryption.CUSTOMER_MANAGED,
            encryption_key=self.streaming.encryption_key,
            point_in_time_recovery=True,
            removal_policy=RemovalPolicy.RETAIN,
            time_to_live_attribute="ttl",
            stream=dynamodb.StreamViewType.NEW_AND_OLD_IMAGES,
        )

        # Add GSI for querying by customer
        self.transactions_table.add_global_secondary_index(
            index_name="customer-index",
            partition_key=dynamodb.Attribute(
                name="customer_id",
                type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="timestamp",
                type=dynamodb.AttributeType.STRING
            ),
            projection_type=dynamodb.ProjectionType.ALL,
        )

        # Add GSI for querying by fraud status
        self.transactions_table.add_global_secondary_index(
            index_name="fraud-status-index",
            partition_key=dynamodb.Attribute(
                name="fraud_status",
                type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="timestamp",
                type=dynamodb.AttributeType.STRING
            ),
            projection_type=dynamodb.ProjectionType.ALL,
        )

        # Customer profiles table - for velocity checks
        self.customer_profiles_table = dynamodb.Table(
            self, "CustomerProfilesTable",
            table_name="fraud-detection-customer-profiles",
            partition_key=dynamodb.Attribute(
                name="customer_id",
                type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            encryption=dynamodb.TableEncryption.CUSTOMER_MANAGED,
            encryption_key=self.streaming.encryption_key,
            removal_policy=RemovalPolicy.RETAIN,
        )

        # Rules table - for custom fraud rules
        self.rules_table = dynamodb.Table(
            self, "FraudRulesTable",
            table_name="fraud-detection-rules",
            partition_key=dynamodb.Attribute(
                name="rule_id",
                type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            encryption=dynamodb.TableEncryption.CUSTOMER_MANAGED,
            encryption_key=self.streaming.encryption_key,
            removal_policy=RemovalPolicy.RETAIN,
        )

        # =================================================================
        # SQS DEAD LETTER QUEUE
        # =================================================================
        
        self.dlq = sqs.Queue(
            self, "ProcessingDLQ",
            queue_name="fraud-detection-processing-dlq",
            encryption=sqs.QueueEncryption.KMS,
            encryption_master_key=self.streaming.encryption_key,
            retention_period=Duration.days(14),
        )

        # =================================================================
        # LAMBDA EXECUTION ROLE
        # =================================================================
        
        self.lambda_role = iam.Role(
            self, "FraudProcessingLambdaRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSLambdaBasicExecutionRole"
                )
            ]
        )

        # Grant permissions
        self.transactions_table.grant_read_write_data(self.lambda_role)
        self.customer_profiles_table.grant_read_write_data(self.lambda_role)
        self.rules_table.grant_read_data(self.lambda_role)
        self.streaming.transaction_stream.grant_read(self.lambda_role)
        self.streaming.scored_stream.grant_write(self.lambda_role)
        self.streaming.alerts_stream.grant_write(self.lambda_role)
        self.streaming.fraud_alert_topic.grant_publish(self.lambda_role)
        self.streaming.encryption_key.grant_encrypt_decrypt(self.lambda_role)
        self.dlq.grant_send_messages(self.lambda_role)

        # Add Fraud Detector permissions
        self.lambda_role.add_to_policy(
            iam.PolicyStatement(
                actions=[
                    "frauddetector:GetEventPrediction",
                    "frauddetector:BatchGetVariable",
                    "frauddetector:GetDetectorVersion",
                ],
                resources=["*"]
            )
        )

        # Add Step Functions permissions
        self.lambda_role.add_to_policy(
            iam.PolicyStatement(
                actions=[
                    "states:StartExecution",
                    "states:DescribeExecution",
                ],
                resources=["*"]
            )
        )

        # =================================================================
        # LAMBDA FUNCTIONS
        # =================================================================
        
        # Stream processor Lambda - processes Kinesis records
        self.stream_processor = lambda_.Function(
            self, "StreamProcessorLambda",
            function_name="fraud-detection-stream-processor",
            runtime=lambda_.Runtime.PYTHON_3_11,
            handler="index.handler",
            code=lambda_.Code.from_inline(self._get_stream_processor_code()),
            role=self.lambda_role,
            timeout=Duration.seconds(30),
            memory_size=512,
            reserved_concurrent_executions=100,
            environment={
                "TRANSACTIONS_TABLE": self.transactions_table.table_name,
                "CUSTOMER_PROFILES_TABLE": self.customer_profiles_table.table_name,
                "SCORED_STREAM": self.streaming.scored_stream.stream_name,
                "ALERTS_STREAM": self.streaming.alerts_stream.stream_name,
                "FRAUD_ALERT_TOPIC": self.streaming.fraud_alert_topic.topic_arn,
            },
            tracing=lambda_.Tracing.ACTIVE,
            dead_letter_queue=self.dlq,
        )

        # Add Kinesis trigger
        self.stream_processor.add_event_source(
            lambda_events.KinesisEventSource(
                self.streaming.transaction_stream,
                starting_position=lambda_.StartingPosition.LATEST,
                batch_size=100,
                max_batching_window=Duration.seconds(5),
                retry_attempts=3,
                parallelization_factor=10,
                on_failure=lambda_events.SqsDlq(self.dlq),
            )
        )

        # Fraud scorer Lambda - calls Fraud Detector or ML model
        self.fraud_scorer = lambda_.Function(
            self, "FraudScorerLambda",
            function_name="fraud-detection-scorer",
            runtime=lambda_.Runtime.PYTHON_3_11,
            handler="index.handler",
            code=lambda_.Code.from_inline(self._get_fraud_scorer_code()),
            role=self.lambda_role,
            timeout=Duration.seconds(10),
            memory_size=256,
            environment={
                "FRAUD_DETECTOR_ID": "transaction_fraud_detector",
                "FRAUD_DETECTOR_EVENT_TYPE": "transaction_event",
            },
            tracing=lambda_.Tracing.ACTIVE,
        )

        # Alert handler Lambda - sends notifications
        self.alert_handler = lambda_.Function(
            self, "AlertHandlerLambda",
            function_name="fraud-detection-alert-handler",
            runtime=lambda_.Runtime.PYTHON_3_11,
            handler="index.handler",
            code=lambda_.Code.from_inline(self._get_alert_handler_code()),
            role=self.lambda_role,
            timeout=Duration.seconds(30),
            memory_size=256,
            environment={
                "FRAUD_ALERT_TOPIC": self.streaming.fraud_alert_topic.topic_arn,
                "ALERTS_STREAM": self.streaming.alerts_stream.stream_name,
            },
            tracing=lambda_.Tracing.ACTIVE,
        )

        # Velocity check Lambda - checks transaction patterns
        self.velocity_checker = lambda_.Function(
            self, "VelocityCheckerLambda",
            function_name="fraud-detection-velocity-checker",
            runtime=lambda_.Runtime.PYTHON_3_11,
            handler="index.handler",
            code=lambda_.Code.from_inline(self._get_velocity_checker_code()),
            role=self.lambda_role,
            timeout=Duration.seconds(10),
            memory_size=256,
            environment={
                "TRANSACTIONS_TABLE": self.transactions_table.table_name,
                "CUSTOMER_PROFILES_TABLE": self.customer_profiles_table.table_name,
            },
            tracing=lambda_.Tracing.ACTIVE,
        )

        # =================================================================
        # STEP FUNCTIONS STATE MACHINE
        # =================================================================
        
        # Define tasks
        store_transaction_task = tasks.DynamoPutItem(
            self, "StoreTransaction",
            table=self.transactions_table,
            item={
                "transaction_id": tasks.DynamoAttributeValue.from_string(
                    sfn.JsonPath.string_at("$.transaction_id")
                ),
                "timestamp": tasks.DynamoAttributeValue.from_string(
                    sfn.JsonPath.string_at("$.timestamp")
                ),
                "customer_id": tasks.DynamoAttributeValue.from_string(
                    sfn.JsonPath.string_at("$.customer_id")
                ),
                "amount": tasks.DynamoAttributeValue.from_number(
                    sfn.JsonPath.number_at("$.amount")
                ),
                "merchant_id": tasks.DynamoAttributeValue.from_string(
                    sfn.JsonPath.string_at("$.merchant_id")
                ),
                "card_bin": tasks.DynamoAttributeValue.from_string(
                    sfn.JsonPath.string_at("$.card_bin")
                ),
                "fraud_status": tasks.DynamoAttributeValue.from_string("PENDING"),
            },
            result_path="$.storeResult"
        )

        # Velocity check task
        velocity_check_task = tasks.LambdaInvoke(
            self, "VelocityCheck",
            lambda_function=self.velocity_checker,
            payload=sfn.TaskInput.from_object({
                "customer_id": sfn.JsonPath.string_at("$.customer_id"),
                "amount": sfn.JsonPath.number_at("$.amount"),
                "timestamp": sfn.JsonPath.string_at("$.timestamp"),
            }),
            result_path="$.velocityResult",
            result_selector={
                "velocity_score": sfn.JsonPath.string_at("$.Payload.velocity_score"),
                "transaction_count_1h": sfn.JsonPath.number_at("$.Payload.transaction_count_1h"),
                "amount_sum_1h": sfn.JsonPath.number_at("$.Payload.amount_sum_1h"),
            }
        )

        # Fraud scoring task
        fraud_score_task = tasks.LambdaInvoke(
            self, "FraudScore",
            lambda_function=self.fraud_scorer,
            payload=sfn.TaskInput.from_object({
                "transaction_id": sfn.JsonPath.string_at("$.transaction_id"),
                "customer_id": sfn.JsonPath.string_at("$.customer_id"),
                "amount": sfn.JsonPath.number_at("$.amount"),
                "merchant_id": sfn.JsonPath.string_at("$.merchant_id"),
                "card_bin": sfn.JsonPath.string_at("$.card_bin"),
                "ip_address": sfn.JsonPath.string_at("$.ip_address"),
                "device_id": sfn.JsonPath.string_at("$.device_id"),
                "velocity_score": sfn.JsonPath.string_at("$.velocityResult.velocity_score"),
            }),
            result_path="$.fraudResult",
            result_selector={
                "fraud_score": sfn.JsonPath.number_at("$.Payload.fraud_score"),
                "outcome": sfn.JsonPath.string_at("$.Payload.outcome"),
                "risk_factors": sfn.JsonPath.string_at("$.Payload.risk_factors"),
            }
        )

        # Update transaction with fraud result
        update_transaction_task = tasks.DynamoUpdateItem(
            self, "UpdateTransaction",
            table=self.transactions_table,
            key={
                "transaction_id": tasks.DynamoAttributeValue.from_string(
                    sfn.JsonPath.string_at("$.transaction_id")
                ),
                "timestamp": tasks.DynamoAttributeValue.from_string(
                    sfn.JsonPath.string_at("$.timestamp")
                ),
            },
            update_expression="SET fraud_score = :score, fraud_status = :status, risk_factors = :factors",
            expression_attribute_values={
                ":score": tasks.DynamoAttributeValue.from_number(
                    sfn.JsonPath.number_at("$.fraudResult.fraud_score")
                ),
                ":status": tasks.DynamoAttributeValue.from_string(
                    sfn.JsonPath.string_at("$.fraudResult.outcome")
                ),
                ":factors": tasks.DynamoAttributeValue.from_string(
                    sfn.JsonPath.string_at("$.fraudResult.risk_factors")
                ),
            },
            result_path="$.updateResult"
        )

        # Alert task for fraud
        send_alert_task = tasks.LambdaInvoke(
            self, "SendFraudAlert",
            lambda_function=self.alert_handler,
            payload=sfn.TaskInput.from_object({
                "transaction_id": sfn.JsonPath.string_at("$.transaction_id"),
                "customer_id": sfn.JsonPath.string_at("$.customer_id"),
                "amount": sfn.JsonPath.number_at("$.amount"),
                "fraud_score": sfn.JsonPath.number_at("$.fraudResult.fraud_score"),
                "outcome": sfn.JsonPath.string_at("$.fraudResult.outcome"),
                "risk_factors": sfn.JsonPath.string_at("$.fraudResult.risk_factors"),
            }),
            result_path="$.alertResult"
        )

        # Approve transaction (no alert needed)
        approve_task = sfn.Pass(
            self, "ApproveTransaction",
            result=sfn.Result.from_object({"status": "APPROVED"}),
            result_path="$.approvalResult"
        )

        # Define the workflow
        definition = store_transaction_task.next(
            velocity_check_task
        ).next(
            fraud_score_task
        ).next(
            update_transaction_task
        ).next(
            sfn.Choice(self, "CheckFraudOutcome")
            .when(
                sfn.Condition.string_equals("$.fraudResult.outcome", "BLOCK"),
                send_alert_task
            )
            .when(
                sfn.Condition.string_equals("$.fraudResult.outcome", "INVESTIGATE"),
                send_alert_task
            )
            .otherwise(approve_task)
        )

        # Create State Machine
        self.state_machine = sfn.StateMachine(
            self, "FraudDetectionStateMachine",
            state_machine_name="fraud-detection-workflow",
            definition_body=sfn.DefinitionBody.from_chainable(definition),
            timeout=Duration.seconds(30),
            tracing_enabled=True,
            logs=sfn.LogOptions(
                destination=logs.LogGroup(
                    self, "StateMachineLogGroup",
                    log_group_name="/aws/stepfunctions/fraud-detection",
                    retention=logs.RetentionDays.ONE_MONTH,
                    removal_policy=RemovalPolicy.DESTROY
                ),
                level=sfn.LogLevel.ALL
            )
        )

        # Grant state machine access
        self.transactions_table.grant_read_write_data(self.state_machine)
        self.state_machine.grant_start_execution(self.lambda_role)

        # Update stream processor with state machine ARN
        self.stream_processor.add_environment(
            "STATE_MACHINE_ARN", self.state_machine.state_machine_arn
        )

        # =================================================================
        # CLOUDWATCH ALARMS
        # =================================================================
        
        # Lambda error alarm
        lambda_error_alarm = cloudwatch.Alarm(
            self, "StreamProcessorErrorAlarm",
            alarm_name="fraud-detection-processor-errors",
            metric=self.stream_processor.metric_errors(period=Duration.minutes(5)),
            threshold=10,
            evaluation_periods=2,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
            alarm_description="Alert when stream processor has errors"
        )
        lambda_error_alarm.add_alarm_action(
            cw_actions.SnsAction(self.streaming.ops_alert_topic)
        )

        # State machine failure alarm
        sfn_failure_alarm = cloudwatch.Alarm(
            self, "StateMachineFailureAlarm",
            alarm_name="fraud-detection-workflow-failures",
            metric=self.state_machine.metric_failed(period=Duration.minutes(5)),
            threshold=5,
            evaluation_periods=2,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
            alarm_description="Alert when fraud detection workflow has failures"
        )
        sfn_failure_alarm.add_alarm_action(
            cw_actions.SnsAction(self.streaming.ops_alert_topic)
        )

        # DLQ alarm
        dlq_alarm = cloudwatch.Alarm(
            self, "DLQMessagesAlarm",
            alarm_name="fraud-detection-dlq-messages",
            metric=self.dlq.metric_approximate_number_of_messages_visible(
                period=Duration.minutes(5)
            ),
            threshold=1,
            evaluation_periods=1,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
            alarm_description="Alert when messages are in DLQ"
        )
        dlq_alarm.add_alarm_action(
            cw_actions.SnsAction(self.streaming.ops_alert_topic)
        )

        # =================================================================
        # CLOUDWATCH DASHBOARD
        # =================================================================
        
        self.dashboard = cloudwatch.Dashboard(
            self, "ProcessingDashboard",
            dashboard_name="FraudDetection-Processing"
        )

        self.dashboard.add_widgets(
            cloudwatch.TextWidget(
                markdown="# Fraud Detection - Processing Metrics",
                width=24,
                height=1
            )
        )

        self.dashboard.add_widgets(
            cloudwatch.GraphWidget(
                title="Lambda Invocations",
                left=[
                    self.stream_processor.metric_invocations(),
                    self.fraud_scorer.metric_invocations(),
                    self.alert_handler.metric_invocations(),
                ],
                width=12
            ),
            cloudwatch.GraphWidget(
                title="Lambda Duration",
                left=[
                    self.stream_processor.metric_duration(),
                    self.fraud_scorer.metric_duration(),
                ],
                width=12
            )
        )

        self.dashboard.add_widgets(
            cloudwatch.GraphWidget(
                title="Step Functions Executions",
                left=[
                    self.state_machine.metric_started(),
                    self.state_machine.metric_succeeded(),
                    self.state_machine.metric_failed(),
                ],
                width=12
            ),
            cloudwatch.GraphWidget(
                title="DynamoDB Operations",
                left=[
                    self.transactions_table.metric_consumed_read_capacity_units(),
                    self.transactions_table.metric_consumed_write_capacity_units(),
                ],
                width=12
            )
        )

        # Custom fraud metrics
        self.dashboard.add_widgets(
            cloudwatch.SingleValueWidget(
                title="Transactions Processed (5 min)",
                metrics=[
                    self.stream_processor.metric_invocations(
                        statistic="Sum",
                        period=Duration.minutes(5)
                    )
                ],
                width=6
            ),
            cloudwatch.SingleValueWidget(
                title="Fraud Blocked (5 min)",
                metrics=[
                    cloudwatch.Metric(
                        namespace="FraudDetection",
                        metric_name="FraudBlocked",
                        statistic="Sum",
                        period=Duration.minutes(5)
                    )
                ],
                width=6
            ),
            cloudwatch.SingleValueWidget(
                title="Avg Processing Time (ms)",
                metrics=[
                    self.state_machine.metric("ExecutionTime", statistic="Average")
                ],
                width=6
            ),
            cloudwatch.SingleValueWidget(
                title="DLQ Messages",
                metrics=[
                    self.dlq.metric_approximate_number_of_messages_visible()
                ],
                width=6
            )
        )

        # =================================================================
        # OUTPUTS
        # =================================================================
        
        CfnOutput(self, "TransactionsTableName",
            value=self.transactions_table.table_name,
            description="DynamoDB table for transactions",
            export_name="FraudDetectionTransactionsTable"
        )

        CfnOutput(self, "StateMachineArn",
            value=self.state_machine.state_machine_arn,
            description="Step Functions state machine ARN",
            export_name="FraudDetectionStateMachine"
        )

        CfnOutput(self, "StreamProcessorArn",
            value=self.stream_processor.function_arn,
            description="Stream processor Lambda ARN"
        )

        CfnOutput(self, "DLQUrl",
            value=self.dlq.queue_url,
            description="Dead letter queue URL"
        )

    def _get_stream_processor_code(self) -> str:
        """Lambda code for processing Kinesis stream records"""
        return '''
import json
import os
import base64
import boto3
from datetime import datetime

sfn = boto3.client('stepfunctions')
kinesis = boto3.client('kinesis')
cloudwatch = boto3.client('cloudwatch')

STATE_MACHINE_ARN = os.environ['STATE_MACHINE_ARN']
SCORED_STREAM = os.environ['SCORED_STREAM']

def handler(event, context):
    """Process batch of transactions from Kinesis stream"""
    processed = 0
    errors = 0
    
    for record in event['Records']:
        try:
            # Decode Kinesis data
            payload = base64.b64decode(record['kinesis']['data']).decode('utf-8')
            transaction = json.loads(payload)
            
            # Add metadata
            transaction['processing_timestamp'] = datetime.utcnow().isoformat()
            transaction['event_id'] = record['eventID']
            
            # Ensure required fields
            if 'transaction_id' not in transaction:
                transaction['transaction_id'] = record['eventID']
            if 'timestamp' not in transaction:
                transaction['timestamp'] = datetime.utcnow().isoformat()
            
            # Default optional fields
            transaction.setdefault('ip_address', '0.0.0.0')
            transaction.setdefault('device_id', 'unknown')
            transaction.setdefault('card_bin', '000000')
            transaction.setdefault('merchant_id', 'unknown')
            
            # Start Step Functions execution
            execution_name = f"txn-{transaction['transaction_id']}-{int(datetime.utcnow().timestamp())}"
            
            sfn.start_execution(
                stateMachineArn=STATE_MACHINE_ARN,
                name=execution_name[:80],  # Max 80 chars
                input=json.dumps(transaction)
            )
            
            processed += 1
            
        except Exception as e:
            print(f"Error processing record: {str(e)}")
            errors += 1
    
    # Publish metrics
    try:
        cloudwatch.put_metric_data(
            Namespace='FraudDetection',
            MetricData=[
                {
                    'MetricName': 'TransactionsProcessed',
                    'Value': processed,
                    'Unit': 'Count'
                },
                {
                    'MetricName': 'ProcessingErrors',
                    'Value': errors,
                    'Unit': 'Count'
                }
            ]
        )
    except Exception as e:
        print(f"Failed to publish metrics: {e}")
    
    return {
        'statusCode': 200,
        'body': json.dumps({
            'processed': processed,
            'errors': errors
        })
    }
'''

    def _get_fraud_scorer_code(self) -> str:
        """Lambda code for fraud scoring"""
        return '''
import json
import os
import boto3
from datetime import datetime

frauddetector = boto3.client('frauddetector')
cloudwatch = boto3.client('cloudwatch')

DETECTOR_ID = os.environ.get('FRAUD_DETECTOR_ID', 'transaction_fraud_detector')
EVENT_TYPE = os.environ.get('FRAUD_DETECTOR_EVENT_TYPE', 'transaction_event')

def handler(event, context):
    """Score transaction for fraud using Amazon Fraud Detector or rules"""
    try:
        transaction_id = event.get('transaction_id', 'unknown')
        customer_id = event.get('customer_id', 'unknown')
        amount = float(event.get('amount', 0))
        merchant_id = event.get('merchant_id', 'unknown')
        ip_address = event.get('ip_address', '0.0.0.0')
        device_id = event.get('device_id', 'unknown')
        velocity_score = event.get('velocity_score', 'LOW')
        
        # Try Amazon Fraud Detector first
        try:
            response = frauddetector.get_event_prediction(
                detectorId=DETECTOR_ID,
                eventId=transaction_id,
                eventTypeName=EVENT_TYPE,
                eventTimestamp=datetime.utcnow().isoformat(),
                entities=[
                    {
                        'entityType': 'customer',
                        'entityId': customer_id
                    }
                ],
                eventVariables={
                    'amount': str(amount),
                    'merchant_id': merchant_id,
                    'ip_address': ip_address,
                    'device_id': device_id,
                }
            )
            
            # Extract outcome from Fraud Detector
            outcomes = response.get('ruleResults', [])
            if outcomes:
                outcome = outcomes[0].get('outcomes', ['APPROVE'])[0]
                fraud_score = float(response.get('modelScores', [{}])[0].get('scores', {}).get('fraud_score', 0))
            else:
                outcome = 'APPROVE'
                fraud_score = 0.0
                
        except Exception as e:
            print(f"Fraud Detector unavailable, using rules: {e}")
            # Fallback to simple rules-based scoring
            fraud_score, outcome = calculate_rules_score(
                amount, velocity_score, customer_id, ip_address
            )
        
        # Determine risk factors
        risk_factors = []
        if amount > 5000:
            risk_factors.append('high_amount')
        if velocity_score == 'HIGH':
            risk_factors.append('high_velocity')
        if ip_address.startswith('10.') or ip_address == '0.0.0.0':
            risk_factors.append('suspicious_ip')
        
        # Publish metrics
        publish_fraud_metrics(outcome, fraud_score)
        
        return {
            'fraud_score': fraud_score,
            'outcome': outcome,
            'risk_factors': ','.join(risk_factors) if risk_factors else 'none'
        }
        
    except Exception as e:
        print(f"Error in fraud scoring: {str(e)}")
        # Default to approve on error (fail open)
        return {
            'fraud_score': 0.0,
            'outcome': 'APPROVE',
            'risk_factors': 'scoring_error'
        }


def calculate_rules_score(amount, velocity_score, customer_id, ip_address):
    """Simple rules-based fraud scoring as fallback"""
    score = 0.0
    
    # Amount-based rules
    if amount > 10000:
        score += 0.4
    elif amount > 5000:
        score += 0.2
    elif amount > 1000:
        score += 0.1
    
    # Velocity-based rules
    if velocity_score == 'HIGH':
        score += 0.3
    elif velocity_score == 'MEDIUM':
        score += 0.1
    
    # IP-based rules (simplified)
    if ip_address == '0.0.0.0' or ip_address.startswith('10.'):
        score += 0.2
    
    # Determine outcome
    if score >= 0.7:
        outcome = 'BLOCK'
    elif score >= 0.4:
        outcome = 'INVESTIGATE'
    else:
        outcome = 'APPROVE'
    
    return score, outcome


def publish_fraud_metrics(outcome, score):
    """Publish fraud detection metrics to CloudWatch"""
    try:
        cloudwatch.put_metric_data(
            Namespace='FraudDetection',
            MetricData=[
                {
                    'MetricName': 'FraudScore',
                    'Value': score,
                    'Unit': 'None'
                },
                {
                    'MetricName': 'FraudBlocked',
                    'Value': 1 if outcome == 'BLOCK' else 0,
                    'Unit': 'Count'
                },
                {
                    'MetricName': 'FraudInvestigate',
                    'Value': 1 if outcome == 'INVESTIGATE' else 0,
                    'Unit': 'Count'
                },
                {
                    'MetricName': 'FraudApproved',
                    'Value': 1 if outcome == 'APPROVE' else 0,
                    'Unit': 'Count'
                }
            ]
        )
    except Exception as e:
        print(f"Failed to publish metrics: {e}")
'''

    def _get_alert_handler_code(self) -> str:
        """Lambda code for handling fraud alerts"""
        return '''
import json
import os
import boto3
from datetime import datetime

sns = boto3.client('sns')
kinesis = boto3.client('kinesis')

FRAUD_ALERT_TOPIC = os.environ['FRAUD_ALERT_TOPIC']
ALERTS_STREAM = os.environ['ALERTS_STREAM']

def handler(event, context):
    """Send fraud alerts to SNS and alerts stream"""
    try:
        transaction_id = event.get('transaction_id', 'unknown')
        customer_id = event.get('customer_id', 'unknown')
        amount = event.get('amount', 0)
        fraud_score = event.get('fraud_score', 0)
        outcome = event.get('outcome', 'UNKNOWN')
        risk_factors = event.get('risk_factors', 'none')
        
        alert_timestamp = datetime.utcnow().isoformat()
        
        # Create alert message
        alert_message = {
            'alert_type': 'FRAUD_DETECTED',
            'timestamp': alert_timestamp,
            'transaction_id': transaction_id,
            'customer_id': customer_id,
            'amount': amount,
            'fraud_score': fraud_score,
            'outcome': outcome,
            'risk_factors': risk_factors,
            'action_required': 'BLOCK' if outcome == 'BLOCK' else 'REVIEW'
        }
        
        # Send to SNS
        sns.publish(
            TopicArn=FRAUD_ALERT_TOPIC,
            Subject=f"[{outcome}] Fraud Alert - Transaction {transaction_id}",
            Message=json.dumps(alert_message, indent=2),
            MessageAttributes={
                'outcome': {
                    'DataType': 'String',
                    'StringValue': outcome
                },
                'fraud_score': {
                    'DataType': 'Number',
                    'StringValue': str(fraud_score)
                }
            }
        )
        
        # Send to alerts stream for downstream processing
        kinesis.put_record(
            StreamName=ALERTS_STREAM,
            Data=json.dumps(alert_message),
            PartitionKey=customer_id
        )
        
        return {
            'statusCode': 200,
            'alert_id': f"alert-{transaction_id}-{int(datetime.utcnow().timestamp())}",
            'message': 'Alert sent successfully'
        }
        
    except Exception as e:
        print(f"Error sending alert: {str(e)}")
        return {
            'statusCode': 500,
            'error': str(e)
        }
'''

    def _get_velocity_checker_code(self) -> str:
        """Lambda code for velocity checks"""
        return '''
import json
import os
import boto3
from datetime import datetime, timedelta
from boto3.dynamodb.conditions import Key

dynamodb = boto3.resource('dynamodb')

TRANSACTIONS_TABLE = os.environ['TRANSACTIONS_TABLE']
CUSTOMER_PROFILES_TABLE = os.environ['CUSTOMER_PROFILES_TABLE']

def handler(event, context):
    """Check transaction velocity for customer"""
    try:
        customer_id = event.get('customer_id', 'unknown')
        amount = float(event.get('amount', 0))
        timestamp = event.get('timestamp', datetime.utcnow().isoformat())
        
        # Get customer profile
        profiles_table = dynamodb.Table(CUSTOMER_PROFILES_TABLE)
        profile_response = profiles_table.get_item(
            Key={'customer_id': customer_id}
        )
        
        profile = profile_response.get('Item', {})
        avg_transaction = float(profile.get('avg_transaction_amount', 500))
        max_transaction = float(profile.get('max_transaction_amount', 5000))
        
        # Query recent transactions (last 1 hour)
        transactions_table = dynamodb.Table(TRANSACTIONS_TABLE)
        one_hour_ago = (datetime.fromisoformat(timestamp.replace('Z', '')) - timedelta(hours=1)).isoformat()
        
        try:
            response = transactions_table.query(
                IndexName='customer-index',
                KeyConditionExpression=Key('customer_id').eq(customer_id) & Key('timestamp').gte(one_hour_ago),
                Limit=100
            )
            recent_transactions = response.get('Items', [])
        except Exception as e:
            print(f"Error querying transactions: {e}")
            recent_transactions = []
        
        # Calculate velocity metrics
        transaction_count_1h = len(recent_transactions)
        amount_sum_1h = sum(float(t.get('amount', 0)) for t in recent_transactions)
        
        # Determine velocity score
        velocity_score = 'LOW'
        
        if transaction_count_1h >= 10:
            velocity_score = 'HIGH'
        elif transaction_count_1h >= 5:
            velocity_score = 'MEDIUM'
        
        if amount_sum_1h > max_transaction * 3:
            velocity_score = 'HIGH'
        elif amount_sum_1h > max_transaction * 1.5:
            if velocity_score != 'HIGH':
                velocity_score = 'MEDIUM'
        
        if amount > avg_transaction * 5:
            velocity_score = 'HIGH'
        elif amount > avg_transaction * 2:
            if velocity_score == 'LOW':
                velocity_score = 'MEDIUM'
        
        return {
            'velocity_score': velocity_score,
            'transaction_count_1h': transaction_count_1h,
            'amount_sum_1h': amount_sum_1h,
            'avg_transaction': avg_transaction,
            'current_amount': amount
        }
        
    except Exception as e:
        print(f"Error in velocity check: {str(e)}")
        return {
            'velocity_score': 'UNKNOWN',
            'transaction_count_1h': 0,
            'amount_sum_1h': 0,
            'error': str(e)
        }
'''
