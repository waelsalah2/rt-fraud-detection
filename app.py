#!/usr/bin/env python3
"""
RT Fraud Detection Platform - CDK Application
Real-time fraud detection pipeline using streaming analytics and ML
"""

import aws_cdk as cdk
from stacks.streaming_stack import StreamingStack
from stacks.processing_stack import ProcessingStack
from stacks.analytics_stack import AnalyticsStack

app = cdk.App()

# Get environment configuration
env = cdk.Environment(
    account=app.node.try_get_context("account"),
    region=app.node.try_get_context("region") or "us-east-1"
)

# Streaming Stack - Kinesis streams and ingestion
streaming = StreamingStack(
    app,
    "RTFraudDetectionStreaming",
    description="Real-time streaming infrastructure for fraud detection",
    env=env
)

# Processing Stack - Lambda, Step Functions, Fraud Detector, DynamoDB
processing = ProcessingStack(
    app,
    "RTFraudDetectionProcessing",
    streaming_stack=streaming,
    description="Real-time fraud processing and ML scoring pipeline",
    env=env
)

# Analytics Stack - S3, Firehose, QuickSight data sources
analytics = AnalyticsStack(
    app,
    "RTFraudDetectionAnalytics",
    streaming_stack=streaming,
    processing_stack=processing,
    description="Analytics and reporting infrastructure for fraud insights",
    env=env
)

app.synth()
