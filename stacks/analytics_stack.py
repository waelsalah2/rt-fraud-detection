"""
Analytics Stack
Kinesis Firehose, S3 Data Lake, and QuickSight data sources for fraud analytics
"""

from aws_cdk import (
    Stack,
    Duration,
    RemovalPolicy,
    CfnOutput,
    Tags,
    aws_s3 as s3,
    aws_iam as iam,
    aws_kinesisfirehose as firehose,
    aws_lambda as lambda_,
    aws_glue as glue,
    aws_athena as athena,
    aws_logs as logs,
    aws_cloudwatch as cloudwatch,
)
from constructs import Construct


class AnalyticsStack(Stack):
    """Analytics and reporting infrastructure for fraud insights"""

    def __init__(self, scope: Construct, construct_id: str, streaming_stack, processing_stack, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        self.streaming = streaming_stack
        self.processing = processing_stack

        # Apply tags
        Tags.of(self).add("Project", "RTFraudDetection")
        Tags.of(self).add("Component", "Analytics")
        Tags.of(self).add("Compliance", "PCI-DSS")

        # =================================================================
        # S3 DATA LAKE BUCKETS
        # =================================================================
        
        # Raw transactions bucket (from Firehose)
        self.raw_data_bucket = s3.Bucket(
            self, "RawDataBucket",
            bucket_name=f"fraud-detection-raw-{self.account}-{self.region}",
            encryption=s3.BucketEncryption.KMS,
            encryption_key=self.streaming.encryption_key,
            enforce_ssl=True,
            versioned=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            removal_policy=RemovalPolicy.RETAIN,
            lifecycle_rules=[
                s3.LifecycleRule(
                    id="TransitionToIA",
                    transitions=[
                        s3.Transition(
                            storage_class=s3.StorageClass.INFREQUENT_ACCESS,
                            transition_after=Duration.days(90)
                        ),
                        s3.Transition(
                            storage_class=s3.StorageClass.GLACIER,
                            transition_after=Duration.days(365)
                        )
                    ]
                )
            ]
        )

        # Enriched/scored transactions bucket
        self.enriched_data_bucket = s3.Bucket(
            self, "EnrichedDataBucket",
            bucket_name=f"fraud-detection-enriched-{self.account}-{self.region}",
            encryption=s3.BucketEncryption.KMS,
            encryption_key=self.streaming.encryption_key,
            enforce_ssl=True,
            versioned=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            removal_policy=RemovalPolicy.RETAIN,
            lifecycle_rules=[
                s3.LifecycleRule(
                    id="IntelligentTiering",
                    transitions=[
                        s3.Transition(
                            storage_class=s3.StorageClass.INTELLIGENT_TIERING,
                            transition_after=Duration.days(30)
                        )
                    ]
                )
            ]
        )

        # Aggregated analytics bucket
        self.analytics_bucket = s3.Bucket(
            self, "AnalyticsBucket",
            bucket_name=f"fraud-detection-analytics-{self.account}-{self.region}",
            encryption=s3.BucketEncryption.KMS,
            encryption_key=self.streaming.encryption_key,
            enforce_ssl=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            removal_policy=RemovalPolicy.RETAIN,
        )

        # Athena query results bucket
        self.athena_results_bucket = s3.Bucket(
            self, "AthenaResultsBucket",
            bucket_name=f"fraud-detection-athena-{self.account}-{self.region}",
            encryption=s3.BucketEncryption.KMS,
            encryption_key=self.streaming.encryption_key,
            enforce_ssl=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=True,
            lifecycle_rules=[
                s3.LifecycleRule(
                    expiration=Duration.days(7)
                )
            ]
        )

        # =================================================================
        # FIREHOSE IAM ROLE
        # =================================================================
        
        self.firehose_role = iam.Role(
            self, "FirehoseRole",
            assumed_by=iam.ServicePrincipal("firehose.amazonaws.com"),
        )

        # Grant permissions
        self.raw_data_bucket.grant_read_write(self.firehose_role)
        self.enriched_data_bucket.grant_read_write(self.firehose_role)
        self.streaming.transaction_stream.grant_read(self.firehose_role)
        self.streaming.scored_stream.grant_read(self.firehose_role)
        self.streaming.encryption_key.grant_encrypt_decrypt(self.firehose_role)

        # CloudWatch Logs permissions
        self.firehose_role.add_to_policy(
            iam.PolicyStatement(
                actions=[
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                ],
                resources=["*"]
            )
        )

        # =================================================================
        # ENRICHMENT LAMBDA
        # =================================================================
        
        self.enrichment_lambda_role = iam.Role(
            self, "EnrichmentLambdaRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSLambdaBasicExecutionRole"
                )
            ]
        )

        # Add Fraud Detector permissions for enrichment
        self.enrichment_lambda_role.add_to_policy(
            iam.PolicyStatement(
                actions=[
                    "frauddetector:GetEventPrediction",
                ],
                resources=["*"]
            )
        )

        self.enrichment_lambda = lambda_.Function(
            self, "EnrichmentLambda",
            function_name="fraud-detection-enrichment",
            runtime=lambda_.Runtime.PYTHON_3_11,
            handler="index.handler",
            code=lambda_.Code.from_inline(self._get_enrichment_code()),
            role=self.enrichment_lambda_role,
            timeout=Duration.seconds(60),
            memory_size=256,
        )

        # Grant Firehose permission to invoke Lambda
        self.enrichment_lambda.grant_invoke(self.firehose_role)

        # =================================================================
        # KINESIS FIREHOSE - Raw Transactions
        # =================================================================
        
        # Log group for Firehose
        firehose_log_group = logs.LogGroup(
            self, "FirehoseLogGroup",
            log_group_name="/aws/firehose/fraud-detection",
            retention=logs.RetentionDays.ONE_MONTH,
            removal_policy=RemovalPolicy.DESTROY
        )

        firehose_log_stream = logs.LogStream(
            self, "FirehoseLogStream",
            log_group=firehose_log_group,
            log_stream_name="raw-transactions"
        )

        # Raw transactions Firehose
        self.raw_firehose = firehose.CfnDeliveryStream(
            self, "RawTransactionsFirehose",
            delivery_stream_name="fraud-detection-raw-transactions",
            delivery_stream_type="KinesisStreamAsSource",
            kinesis_stream_source_configuration=firehose.CfnDeliveryStream.KinesisStreamSourceConfigurationProperty(
                kinesis_stream_arn=self.streaming.transaction_stream.stream_arn,
                role_arn=self.firehose_role.role_arn
            ),
            extended_s3_destination_configuration=firehose.CfnDeliveryStream.ExtendedS3DestinationConfigurationProperty(
                bucket_arn=self.raw_data_bucket.bucket_arn,
                role_arn=self.firehose_role.role_arn,
                prefix="transactions/year=!{timestamp:yyyy}/month=!{timestamp:MM}/day=!{timestamp:dd}/hour=!{timestamp:HH}/",
                error_output_prefix="errors/!{firehose:error-output-type}/year=!{timestamp:yyyy}/month=!{timestamp:MM}/day=!{timestamp:dd}/",
                buffering_hints=firehose.CfnDeliveryStream.BufferingHintsProperty(
                    interval_in_seconds=300,
                    size_in_m_bs=64
                ),
                compression_format="GZIP",
                encryption_configuration=firehose.CfnDeliveryStream.EncryptionConfigurationProperty(
                    kms_encryption_config=firehose.CfnDeliveryStream.KMSEncryptionConfigProperty(
                        awskms_key_arn=self.streaming.encryption_key.key_arn
                    )
                ),
                cloud_watch_logging_options=firehose.CfnDeliveryStream.CloudWatchLoggingOptionsProperty(
                    enabled=True,
                    log_group_name=firehose_log_group.log_group_name,
                    log_stream_name=firehose_log_stream.log_stream_name
                ),
                data_format_conversion_configuration=firehose.CfnDeliveryStream.DataFormatConversionConfigurationProperty(
                    enabled=True,
                    input_format_configuration=firehose.CfnDeliveryStream.InputFormatConfigurationProperty(
                        deserializer=firehose.CfnDeliveryStream.DeserializerProperty(
                            open_x_json_ser_de=firehose.CfnDeliveryStream.OpenXJsonSerDeProperty(
                                case_insensitive=True,
                                convert_dots_in_json_keys_to_underscores=True
                            )
                        )
                    ),
                    output_format_configuration=firehose.CfnDeliveryStream.OutputFormatConfigurationProperty(
                        serializer=firehose.CfnDeliveryStream.SerializerProperty(
                            parquet_ser_de=firehose.CfnDeliveryStream.ParquetSerDeProperty(
                                compression="SNAPPY"
                            )
                        )
                    ),
                    schema_configuration=firehose.CfnDeliveryStream.SchemaConfigurationProperty(
                        database_name="fraud_detection_db",
                        table_name="raw_transactions",
                        region=self.region,
                        role_arn=self.firehose_role.role_arn
                    )
                )
            )
        )

        # =================================================================
        # KINESIS FIREHOSE - Scored Transactions (with enrichment)
        # =================================================================
        
        enriched_log_stream = logs.LogStream(
            self, "EnrichedLogStream",
            log_group=firehose_log_group,
            log_stream_name="enriched-transactions"
        )

        self.enriched_firehose = firehose.CfnDeliveryStream(
            self, "EnrichedTransactionsFirehose",
            delivery_stream_name="fraud-detection-enriched-transactions",
            delivery_stream_type="KinesisStreamAsSource",
            kinesis_stream_source_configuration=firehose.CfnDeliveryStream.KinesisStreamSourceConfigurationProperty(
                kinesis_stream_arn=self.streaming.scored_stream.stream_arn,
                role_arn=self.firehose_role.role_arn
            ),
            extended_s3_destination_configuration=firehose.CfnDeliveryStream.ExtendedS3DestinationConfigurationProperty(
                bucket_arn=self.enriched_data_bucket.bucket_arn,
                role_arn=self.firehose_role.role_arn,
                prefix="scored/year=!{timestamp:yyyy}/month=!{timestamp:MM}/day=!{timestamp:dd}/hour=!{timestamp:HH}/",
                error_output_prefix="errors/!{firehose:error-output-type}/year=!{timestamp:yyyy}/month=!{timestamp:MM}/day=!{timestamp:dd}/",
                buffering_hints=firehose.CfnDeliveryStream.BufferingHintsProperty(
                    interval_in_seconds=300,
                    size_in_m_bs=64
                ),
                compression_format="GZIP",
                encryption_configuration=firehose.CfnDeliveryStream.EncryptionConfigurationProperty(
                    kms_encryption_config=firehose.CfnDeliveryStream.KMSEncryptionConfigProperty(
                        awskms_key_arn=self.streaming.encryption_key.key_arn
                    )
                ),
                cloud_watch_logging_options=firehose.CfnDeliveryStream.CloudWatchLoggingOptionsProperty(
                    enabled=True,
                    log_group_name=firehose_log_group.log_group_name,
                    log_stream_name=enriched_log_stream.log_stream_name
                ),
                processing_configuration=firehose.CfnDeliveryStream.ProcessingConfigurationProperty(
                    enabled=True,
                    processors=[
                        firehose.CfnDeliveryStream.ProcessorProperty(
                            type="Lambda",
                            parameters=[
                                firehose.CfnDeliveryStream.ProcessorParameterProperty(
                                    parameter_name="LambdaArn",
                                    parameter_value=self.enrichment_lambda.function_arn
                                ),
                                firehose.CfnDeliveryStream.ProcessorParameterProperty(
                                    parameter_name="BufferSizeInMBs",
                                    parameter_value="1"
                                ),
                                firehose.CfnDeliveryStream.ProcessorParameterProperty(
                                    parameter_name="BufferIntervalInSeconds",
                                    parameter_value="60"
                                )
                            ]
                        )
                    ]
                )
            )
        )

        # =================================================================
        # AWS GLUE DATA CATALOG
        # =================================================================
        
        self.glue_database = glue.CfnDatabase(
            self, "FraudDetectionDatabase",
            catalog_id=self.account,
            database_input=glue.CfnDatabase.DatabaseInputProperty(
                name="fraud_detection_db",
                description="Database for fraud detection analytics"
            )
        )

        # Glue Crawler Role
        self.glue_role = iam.Role(
            self, "GlueCrawlerRole",
            assumed_by=iam.ServicePrincipal("glue.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSGlueServiceRole"
                )
            ]
        )

        self.raw_data_bucket.grant_read(self.glue_role)
        self.enriched_data_bucket.grant_read(self.glue_role)
        self.streaming.encryption_key.grant_decrypt(self.glue_role)

        # Raw transactions table
        self.raw_transactions_table = glue.CfnTable(
            self, "RawTransactionsTable",
            catalog_id=self.account,
            database_name="fraud_detection_db",
            table_input=glue.CfnTable.TableInputProperty(
                name="raw_transactions",
                description="Raw transaction data from Kinesis",
                table_type="EXTERNAL_TABLE",
                parameters={
                    "classification": "parquet",
                    "compressionType": "gzip"
                },
                storage_descriptor=glue.CfnTable.StorageDescriptorProperty(
                    location=f"s3://{self.raw_data_bucket.bucket_name}/transactions/",
                    input_format="org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat",
                    output_format="org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat",
                    serde_info=glue.CfnTable.SerdeInfoProperty(
                        serialization_library="org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe"
                    ),
                    columns=[
                        glue.CfnTable.ColumnProperty(name="transaction_id", type="string"),
                        glue.CfnTable.ColumnProperty(name="timestamp", type="string"),
                        glue.CfnTable.ColumnProperty(name="customer_id", type="string"),
                        glue.CfnTable.ColumnProperty(name="amount", type="double"),
                        glue.CfnTable.ColumnProperty(name="merchant_id", type="string"),
                        glue.CfnTable.ColumnProperty(name="card_bin", type="string"),
                        glue.CfnTable.ColumnProperty(name="ip_address", type="string"),
                        glue.CfnTable.ColumnProperty(name="device_id", type="string"),
                        glue.CfnTable.ColumnProperty(name="transaction_type", type="string"),
                        glue.CfnTable.ColumnProperty(name="currency", type="string"),
                    ]
                ),
                partition_keys=[
                    glue.CfnTable.ColumnProperty(name="year", type="string"),
                    glue.CfnTable.ColumnProperty(name="month", type="string"),
                    glue.CfnTable.ColumnProperty(name="day", type="string"),
                    glue.CfnTable.ColumnProperty(name="hour", type="string"),
                ]
            )
        )
        self.raw_transactions_table.add_dependency(self.glue_database)

        # Scored transactions table
        self.scored_transactions_table = glue.CfnTable(
            self, "ScoredTransactionsTable",
            catalog_id=self.account,
            database_name="fraud_detection_db",
            table_input=glue.CfnTable.TableInputProperty(
                name="scored_transactions",
                description="Transactions with fraud scores",
                table_type="EXTERNAL_TABLE",
                parameters={
                    "classification": "json",
                    "compressionType": "gzip"
                },
                storage_descriptor=glue.CfnTable.StorageDescriptorProperty(
                    location=f"s3://{self.enriched_data_bucket.bucket_name}/scored/",
                    input_format="org.apache.hadoop.mapred.TextInputFormat",
                    output_format="org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
                    serde_info=glue.CfnTable.SerdeInfoProperty(
                        serialization_library="org.openx.data.jsonserde.JsonSerDe"
                    ),
                    columns=[
                        glue.CfnTable.ColumnProperty(name="transaction_id", type="string"),
                        glue.CfnTable.ColumnProperty(name="timestamp", type="string"),
                        glue.CfnTable.ColumnProperty(name="customer_id", type="string"),
                        glue.CfnTable.ColumnProperty(name="amount", type="double"),
                        glue.CfnTable.ColumnProperty(name="fraud_score", type="double"),
                        glue.CfnTable.ColumnProperty(name="fraud_status", type="string"),
                        glue.CfnTable.ColumnProperty(name="risk_factors", type="string"),
                        glue.CfnTable.ColumnProperty(name="velocity_score", type="string"),
                    ]
                ),
                partition_keys=[
                    glue.CfnTable.ColumnProperty(name="year", type="string"),
                    glue.CfnTable.ColumnProperty(name="month", type="string"),
                    glue.CfnTable.ColumnProperty(name="day", type="string"),
                    glue.CfnTable.ColumnProperty(name="hour", type="string"),
                ]
            )
        )
        self.scored_transactions_table.add_dependency(self.glue_database)

        # =================================================================
        # AMAZON ATHENA
        # =================================================================
        
        self.athena_workgroup = athena.CfnWorkGroup(
            self, "FraudAnalyticsWorkgroup",
            name="fraud-detection-analytics",
            description="Workgroup for fraud detection analytics",
            work_group_configuration=athena.CfnWorkGroup.WorkGroupConfigurationProperty(
                result_configuration=athena.CfnWorkGroup.ResultConfigurationProperty(
                    output_location=f"s3://{self.athena_results_bucket.bucket_name}/results/",
                    encryption_configuration=athena.CfnWorkGroup.EncryptionConfigurationProperty(
                        encryption_option="SSE_KMS",
                        kms_key=self.streaming.encryption_key.key_arn
                    )
                ),
                enforce_work_group_configuration=True,
                publish_cloud_watch_metrics_enabled=True,
            ),
            state="ENABLED"
        )

        # Saved queries for common analysis
        athena.CfnNamedQuery(
            self, "FraudSummaryQuery",
            database="fraud_detection_db",
            query_string="""
                SELECT 
                    DATE(timestamp) as date,
                    fraud_status,
                    COUNT(*) as transaction_count,
                    SUM(amount) as total_amount,
                    AVG(fraud_score) as avg_fraud_score
                FROM scored_transactions
                WHERE year = CAST(YEAR(CURRENT_DATE) AS VARCHAR)
                GROUP BY DATE(timestamp), fraud_status
                ORDER BY date DESC, fraud_status
            """,
            name="Daily Fraud Summary",
            description="Daily summary of transactions by fraud status",
            work_group="fraud-detection-analytics"
        )

        athena.CfnNamedQuery(
            self, "HighRiskCustomersQuery",
            database="fraud_detection_db",
            query_string="""
                SELECT 
                    customer_id,
                    COUNT(*) as fraud_count,
                    SUM(amount) as total_fraud_amount,
                    AVG(fraud_score) as avg_fraud_score
                FROM scored_transactions
                WHERE fraud_status IN ('BLOCK', 'INVESTIGATE')
                GROUP BY customer_id
                HAVING COUNT(*) >= 3
                ORDER BY fraud_count DESC
                LIMIT 100
            """,
            name="High Risk Customers",
            description="Customers with multiple fraud flags",
            work_group="fraud-detection-analytics"
        )

        athena.CfnNamedQuery(
            self, "FraudByMerchantQuery",
            database="fraud_detection_db",
            query_string="""
                SELECT 
                    r.merchant_id,
                    COUNT(*) as total_transactions,
                    SUM(CASE WHEN s.fraud_status = 'BLOCK' THEN 1 ELSE 0 END) as blocked_count,
                    SUM(CASE WHEN s.fraud_status = 'INVESTIGATE' THEN 1 ELSE 0 END) as investigate_count,
                    ROUND(100.0 * SUM(CASE WHEN s.fraud_status IN ('BLOCK', 'INVESTIGATE') THEN 1 ELSE 0 END) / COUNT(*), 2) as fraud_rate
                FROM raw_transactions r
                LEFT JOIN scored_transactions s ON r.transaction_id = s.transaction_id
                GROUP BY r.merchant_id
                HAVING COUNT(*) >= 100
                ORDER BY fraud_rate DESC
                LIMIT 50
            """,
            name="Fraud by Merchant",
            description="Fraud rates by merchant",
            work_group="fraud-detection-analytics"
        )

        # =================================================================
        # CLOUDWATCH DASHBOARD
        # =================================================================
        
        self.dashboard = cloudwatch.Dashboard(
            self, "AnalyticsDashboard",
            dashboard_name="FraudDetection-Analytics"
        )

        self.dashboard.add_widgets(
            cloudwatch.TextWidget(
                markdown="# Fraud Detection - Analytics & Data Pipeline",
                width=24,
                height=1
            )
        )

        self.dashboard.add_widgets(
            cloudwatch.GraphWidget(
                title="Firehose - Incoming Records",
                left=[
                    cloudwatch.Metric(
                        namespace="AWS/Firehose",
                        metric_name="IncomingRecords",
                        dimensions_map={"DeliveryStreamName": "fraud-detection-raw-transactions"},
                        statistic="Sum"
                    ),
                    cloudwatch.Metric(
                        namespace="AWS/Firehose",
                        metric_name="IncomingRecords",
                        dimensions_map={"DeliveryStreamName": "fraud-detection-enriched-transactions"},
                        statistic="Sum"
                    )
                ],
                width=12
            ),
            cloudwatch.GraphWidget(
                title="Firehose - Delivery Success",
                left=[
                    cloudwatch.Metric(
                        namespace="AWS/Firehose",
                        metric_name="DeliveryToS3.Success",
                        dimensions_map={"DeliveryStreamName": "fraud-detection-raw-transactions"},
                        statistic="Average"
                    ),
                    cloudwatch.Metric(
                        namespace="AWS/Firehose",
                        metric_name="DeliveryToS3.Success",
                        dimensions_map={"DeliveryStreamName": "fraud-detection-enriched-transactions"},
                        statistic="Average"
                    )
                ],
                width=12
            )
        )

        self.dashboard.add_widgets(
            cloudwatch.GraphWidget(
                title="S3 Bucket Size",
                left=[
                    cloudwatch.Metric(
                        namespace="AWS/S3",
                        metric_name="BucketSizeBytes",
                        dimensions_map={
                            "BucketName": self.raw_data_bucket.bucket_name,
                            "StorageType": "StandardStorage"
                        },
                        statistic="Average",
                        period=Duration.days(1)
                    ),
                    cloudwatch.Metric(
                        namespace="AWS/S3",
                        metric_name="BucketSizeBytes",
                        dimensions_map={
                            "BucketName": self.enriched_data_bucket.bucket_name,
                            "StorageType": "StandardStorage"
                        },
                        statistic="Average",
                        period=Duration.days(1)
                    )
                ],
                width=12
            ),
            cloudwatch.GraphWidget(
                title="Enrichment Lambda",
                left=[
                    self.enrichment_lambda.metric_invocations(),
                    self.enrichment_lambda.metric_errors(),
                ],
                right=[
                    self.enrichment_lambda.metric_duration(),
                ],
                width=12
            )
        )

        # =================================================================
        # OUTPUTS
        # =================================================================
        
        CfnOutput(self, "RawDataBucketName",
            value=self.raw_data_bucket.bucket_name,
            description="S3 bucket for raw transaction data",
            export_name="FraudDetectionRawBucket"
        )

        CfnOutput(self, "EnrichedDataBucketName",
            value=self.enriched_data_bucket.bucket_name,
            description="S3 bucket for enriched/scored data",
            export_name="FraudDetectionEnrichedBucket"
        )

        CfnOutput(self, "GlueDatabaseName",
            value="fraud_detection_db",
            description="Glue database name",
            export_name="FraudDetectionGlueDB"
        )

        CfnOutput(self, "AthenaWorkgroupName",
            value="fraud-detection-analytics",
            description="Athena workgroup for queries",
            export_name="FraudDetectionAthenaWorkgroup"
        )

        CfnOutput(self, "RawFirehoseName",
            value="fraud-detection-raw-transactions",
            description="Firehose for raw transactions"
        )

        CfnOutput(self, "EnrichedFirehoseName",
            value="fraud-detection-enriched-transactions",
            description="Firehose for enriched transactions"
        )

    def _get_enrichment_code(self) -> str:
        """Lambda code for Firehose record enrichment"""
        return '''
import json
import base64
from datetime import datetime

def handler(event, context):
    """Enrich Firehose records with additional metadata"""
    output = []
    
    for record in event['records']:
        try:
            # Decode the data
            payload = base64.b64decode(record['data']).decode('utf-8')
            data = json.loads(payload)
            
            # Add enrichment fields
            data['enrichment_timestamp'] = datetime.utcnow().isoformat()
            data['enrichment_version'] = '1.0'
            
            # Add derived fields
            amount = float(data.get('amount', 0))
            if amount > 10000:
                data['amount_category'] = 'very_high'
            elif amount > 5000:
                data['amount_category'] = 'high'
            elif amount > 1000:
                data['amount_category'] = 'medium'
            else:
                data['amount_category'] = 'low'
            
            # Re-encode
            enriched_data = json.dumps(data) + '\\n'
            
            output.append({
                'recordId': record['recordId'],
                'result': 'Ok',
                'data': base64.b64encode(enriched_data.encode('utf-8')).decode('utf-8')
            })
            
        except Exception as e:
            print(f"Error processing record: {e}")
            output.append({
                'recordId': record['recordId'],
                'result': 'ProcessingFailed',
                'data': record['data']
            })
    
    return {'records': output}
'''
