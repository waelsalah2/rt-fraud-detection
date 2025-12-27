"""
Streaming Stack
Amazon Kinesis Data Streams for real-time transaction ingestion
"""

from aws_cdk import (
    Stack,
    Duration,
    RemovalPolicy,
    CfnOutput,
    Tags,
    aws_kinesis as kinesis,
    aws_kms as kms,
    aws_iam as iam,
    aws_logs as logs,
    aws_cloudwatch as cloudwatch,
    aws_cloudwatch_actions as cw_actions,
    aws_sns as sns,
    aws_apigateway as apigw,
    aws_lambda as lambda_,
)
from constructs import Construct


class StreamingStack(Stack):
    """Real-time streaming infrastructure for fraud detection"""

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Apply tags
        Tags.of(self).add("Project", "RTFraudDetection")
        Tags.of(self).add("Component", "Streaming")
        Tags.of(self).add("Compliance", "PCI-DSS")

        # =================================================================
        # KMS ENCRYPTION KEY
        # =================================================================
        
        self.encryption_key = kms.Key(
            self, "FraudDetectionKey",
            alias="alias/fraud-detection-key",
            description="KMS key for encrypting fraud detection data",
            enable_key_rotation=True,
            removal_policy=RemovalPolicy.RETAIN,
        )

        # =================================================================
        # SNS TOPICS FOR ALERTS
        # =================================================================
        
        self.fraud_alert_topic = sns.Topic(
            self, "FraudAlertTopic",
            topic_name="fraud-detection-alerts",
            master_key=self.encryption_key,
            display_name="Fraud Detection Alerts"
        )

        self.ops_alert_topic = sns.Topic(
            self, "OpsAlertTopic",
            topic_name="fraud-detection-ops-alerts",
            master_key=self.encryption_key,
            display_name="Fraud Detection Operations Alerts"
        )

        # =================================================================
        # KINESIS DATA STREAM - Main Transaction Stream
        # =================================================================
        
        self.transaction_stream = kinesis.Stream(
            self, "TransactionStream",
            stream_name="fraud-detection-transactions",
            shard_count=4,  # Adjust based on expected throughput
            retention_period=Duration.hours(24),
            encryption=kinesis.StreamEncryption.KMS,
            encryption_key=self.encryption_key,
            stream_mode=kinesis.StreamMode.PROVISIONED,
        )

        # =================================================================
        # KINESIS DATA STREAM - Enriched/Scored Transactions
        # =================================================================
        
        self.scored_stream = kinesis.Stream(
            self, "ScoredTransactionStream",
            stream_name="fraud-detection-scored",
            shard_count=2,
            retention_period=Duration.hours(24),
            encryption=kinesis.StreamEncryption.KMS,
            encryption_key=self.encryption_key,
            stream_mode=kinesis.StreamMode.PROVISIONED,
        )

        # =================================================================
        # KINESIS DATA STREAM - Fraud Alerts Stream
        # =================================================================
        
        self.alerts_stream = kinesis.Stream(
            self, "AlertsStream",
            stream_name="fraud-detection-alerts-stream",
            shard_count=1,
            retention_period=Duration.hours(24),
            encryption=kinesis.StreamEncryption.KMS,
            encryption_key=self.encryption_key,
            stream_mode=kinesis.StreamMode.PROVISIONED,
        )

        # =================================================================
        # API GATEWAY FOR TRANSACTION INGESTION
        # =================================================================
        
        # IAM Role for API Gateway to write to Kinesis
        api_kinesis_role = iam.Role(
            self, "ApiKinesisRole",
            assumed_by=iam.ServicePrincipal("apigateway.amazonaws.com"),
        )
        self.transaction_stream.grant_write(api_kinesis_role)

        # REST API for transaction ingestion
        self.ingestion_api = apigw.RestApi(
            self, "TransactionIngestionAPI",
            rest_api_name="Fraud Detection Transaction API",
            description="API for ingesting transactions into fraud detection pipeline",
            deploy_options=apigw.StageOptions(
                stage_name="v1",
                logging_level=apigw.MethodLoggingLevel.INFO,
                data_trace_enabled=True,
                metrics_enabled=True,
                throttling_rate_limit=10000,
                throttling_burst_limit=20000,
            ),
            default_cors_preflight_options=apigw.CorsOptions(
                allow_origins=apigw.Cors.ALL_ORIGINS,
                allow_methods=["POST", "OPTIONS"],
            )
        )

        # Kinesis integration for direct streaming
        kinesis_integration = apigw.AwsIntegration(
            service="kinesis",
            action="PutRecord",
            integration_http_method="POST",
            options=apigw.IntegrationOptions(
                credentials_role=api_kinesis_role,
                request_templates={
                    "application/json": f'''{{
                        "StreamName": "{self.transaction_stream.stream_name}",
                        "Data": "$util.base64Encode($input.body)",
                        "PartitionKey": "$input.path('$.transaction_id')"
                    }}'''
                },
                integration_responses=[
                    apigw.IntegrationResponse(
                        status_code="200",
                        response_templates={
                            "application/json": '{"status": "accepted", "message": "Transaction queued for processing"}'
                        }
                    ),
                    apigw.IntegrationResponse(
                        status_code="500",
                        selection_pattern="5\\d{2}",
                        response_templates={
                            "application/json": '{"status": "error", "message": "Failed to queue transaction"}'
                        }
                    )
                ],
                passthrough_behavior=apigw.PassthroughBehavior.NEVER,
            )
        )

        # /transactions endpoint
        transactions_resource = self.ingestion_api.root.add_resource("transactions")
        transactions_resource.add_method(
            "POST",
            kinesis_integration,
            method_responses=[
                apigw.MethodResponse(status_code="200"),
                apigw.MethodResponse(status_code="500"),
            ],
            api_key_required=True
        )

        # Batch ingestion endpoint
        batch_integration = apigw.AwsIntegration(
            service="kinesis",
            action="PutRecords",
            integration_http_method="POST",
            options=apigw.IntegrationOptions(
                credentials_role=api_kinesis_role,
                request_templates={
                    "application/json": f'''{{
                        "StreamName": "{self.transaction_stream.stream_name}",
                        "Records": [
                            #foreach($record in $input.path('$.transactions'))
                            {{
                                "Data": "$util.base64Encode($input.json("$.transactions[$foreach.index]"))",
                                "PartitionKey": "$record.transaction_id"
                            }}#if($foreach.hasNext),#end
                            #end
                        ]
                    }}'''
                },
                integration_responses=[
                    apigw.IntegrationResponse(
                        status_code="200",
                        response_templates={
                            "application/json": '{"status": "accepted", "count": $input.json("$.FailedRecordCount")}'
                        }
                    )
                ],
                passthrough_behavior=apigw.PassthroughBehavior.NEVER,
            )
        )

        batch_resource = transactions_resource.add_resource("batch")
        batch_resource.add_method(
            "POST",
            batch_integration,
            method_responses=[
                apigw.MethodResponse(status_code="200"),
            ],
            api_key_required=True
        )

        # API Key and Usage Plan
        api_key = self.ingestion_api.add_api_key(
            "FraudDetectionAPIKey",
            api_key_name="fraud-detection-api-key"
        )

        usage_plan = self.ingestion_api.add_usage_plan(
            "FraudDetectionUsagePlan",
            name="FraudDetectionPlan",
            throttle=apigw.ThrottleSettings(
                rate_limit=5000,
                burst_limit=10000
            ),
            quota=apigw.QuotaSettings(
                limit=1000000,
                period=apigw.Period.DAY
            )
        )
        usage_plan.add_api_key(api_key)
        usage_plan.add_api_stage(stage=self.ingestion_api.deployment_stage)

        # =================================================================
        # CLOUDWATCH ALARMS
        # =================================================================
        
        # Stream throughput alarm
        stream_records_alarm = cloudwatch.Alarm(
            self, "StreamRecordsAlarm",
            alarm_name="fraud-detection-stream-throughput",
            metric=self.transaction_stream.metric_incoming_records(
                period=Duration.minutes(1),
                statistic="Sum"
            ),
            threshold=100000,  # Alert if >100k records/min
            evaluation_periods=2,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
            alarm_description="Alert when transaction volume is unusually high"
        )
        stream_records_alarm.add_alarm_action(cw_actions.SnsAction(self.ops_alert_topic))

        # Iterator age alarm (processing lag)
        iterator_age_alarm = cloudwatch.Alarm(
            self, "IteratorAgeAlarm",
            alarm_name="fraud-detection-iterator-age",
            metric=self.transaction_stream.metric_get_records_iterator_age_milliseconds(
                period=Duration.minutes(1),
                statistic="Maximum"
            ),
            threshold=60000,  # 1 minute lag
            evaluation_periods=3,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
            alarm_description="Alert when stream processing is falling behind"
        )
        iterator_age_alarm.add_alarm_action(cw_actions.SnsAction(self.ops_alert_topic))

        # =================================================================
        # CLOUDWATCH DASHBOARD
        # =================================================================
        
        self.dashboard = cloudwatch.Dashboard(
            self, "StreamingDashboard",
            dashboard_name="FraudDetection-Streaming"
        )

        self.dashboard.add_widgets(
            cloudwatch.TextWidget(
                markdown="# Fraud Detection - Streaming Metrics",
                width=24,
                height=1
            )
        )

        self.dashboard.add_widgets(
            cloudwatch.GraphWidget(
                title="Transaction Stream - Incoming Records",
                left=[
                    self.transaction_stream.metric_incoming_records(statistic="Sum"),
                    self.transaction_stream.metric_incoming_bytes(statistic="Sum"),
                ],
                width=12
            ),
            cloudwatch.GraphWidget(
                title="Transaction Stream - Processing",
                left=[
                    self.transaction_stream.metric_get_records_success(statistic="Sum"),
                    self.transaction_stream.metric_get_records_iterator_age_milliseconds(statistic="Average"),
                ],
                width=12
            )
        )

        self.dashboard.add_widgets(
            cloudwatch.GraphWidget(
                title="Scored Transactions Stream",
                left=[
                    self.scored_stream.metric_incoming_records(statistic="Sum"),
                ],
                width=8
            ),
            cloudwatch.GraphWidget(
                title="Alerts Stream",
                left=[
                    self.alerts_stream.metric_incoming_records(statistic="Sum"),
                ],
                width=8
            ),
            cloudwatch.GraphWidget(
                title="API Gateway Requests",
                left=[
                    cloudwatch.Metric(
                        namespace="AWS/ApiGateway",
                        metric_name="Count",
                        dimensions_map={"ApiName": self.ingestion_api.rest_api_name},
                        statistic="Sum"
                    )
                ],
                width=8
            )
        )

        # =================================================================
        # OUTPUTS
        # =================================================================
        
        CfnOutput(self, "TransactionStreamName",
            value=self.transaction_stream.stream_name,
            description="Kinesis stream for incoming transactions",
            export_name="FraudDetectionTransactionStream"
        )

        CfnOutput(self, "TransactionStreamArn",
            value=self.transaction_stream.stream_arn,
            description="Kinesis stream ARN",
            export_name="FraudDetectionTransactionStreamArn"
        )

        CfnOutput(self, "ScoredStreamName",
            value=self.scored_stream.stream_name,
            description="Kinesis stream for scored transactions",
            export_name="FraudDetectionScoredStream"
        )

        CfnOutput(self, "IngestionAPIEndpoint",
            value=self.ingestion_api.url,
            description="API Gateway endpoint for transaction ingestion",
            export_name="FraudDetectionIngestionAPI"
        )

        CfnOutput(self, "FraudAlertTopicArn",
            value=self.fraud_alert_topic.topic_arn,
            description="SNS topic for fraud alerts",
            export_name="FraudDetectionAlertTopic"
        )

        CfnOutput(self, "EncryptionKeyArn",
            value=self.encryption_key.key_arn,
            description="KMS key for encryption",
            export_name="FraudDetectionKMSKey"
        )
