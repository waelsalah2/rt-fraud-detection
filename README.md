# RT Fraud Detection - AWS CDK

A comprehensive AWS CDK Python project implementing a real-time fraud detection pipeline using streaming analytics and machine learning for financial transaction monitoring.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              SECURITY & COMPLIANCE                               │
│  ┌──────────┐  ┌───────────────┐  ┌─────────────┐  ┌────────────────────────┐   │
│  │   IAM    │  │      KMS      │  │  CloudTrail │  │  PCI-DSS Compliance    │   │
│  │  Roles   │  │  Encryption   │  │   Logging   │  │                        │   │
│  └──────────┘  └───────────────┘  └─────────────┘  └────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────────┘
                                        │
┌───────────────────────────────────────┼─────────────────────────────────────────┐
│                         TRANSACTION INGESTION                                    │
│                                                                                  │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐              │
│  │  POS Systems    │    │  Web Checkouts  │    │  Mobile Apps    │              │
│  └────────┬────────┘    └────────┬────────┘    └────────┬────────┘              │
│           └──────────────────────┼──────────────────────┘                        │
│                                  ▼                                               │
│  ┌───────────────────────────────────────────────────────────────┐              │
│  │              API Gateway (Transaction Ingestion)               │              │
│  │           POST /transactions  │  POST /transactions/batch      │              │
│  └───────────────────────────────────────────────────────────────┘              │
│                                  │                                               │
│                                  ▼                                               │
│  ┌───────────────────────────────────────────────────────────────┐              │
│  │              Amazon Kinesis Data Streams                       │              │
│  │              (fraud-detection-transactions)                    │              │
│  └───────────────────────────────────────────────────────────────┘              │
└─────────────────────────────────────────────────────────────────────────────────┘
                                        │
                    ┌───────────────────┴───────────────────┐
                    ▼                                       ▼
┌───────────────────────────────────────┐  ┌───────────────────────────────────────┐
│         REAL-TIME PROCESSING          │  │           DATA LAKE (S3)              │
│                                       │  │                                       │
│  ┌─────────────────────────────────┐  │  │  ┌─────────────────────────────────┐  │
│  │  Lambda (Stream Processor)      │  │  │  │  Kinesis Firehose               │  │
│  │  - Batch processing             │  │  │  │  - Parquet conversion           │  │
│  │  - Triggers Step Functions      │  │  │  │  - Partitioned by date/hour     │  │
│  └─────────────┬───────────────────┘  │  │  └─────────────┬───────────────────┘  │
│                ▼                      │  │                ▼                      │
│  ┌─────────────────────────────────┐  │  │  ┌─────────────────────────────────┐  │
│  │  AWS Step Functions Workflow    │  │  │  │  S3 Data Lake                   │  │
│  │  1. Store Transaction (DynamoDB)│  │  │  │  - Raw transactions (Parquet)   │  │
│  │  2. Velocity Check (Lambda)     │  │  │  │  - Scored transactions          │  │
│  │  3. Fraud Score (Fraud Detector)│  │  │  └─────────────────────────────────┘  │
│  │  4. Update Transaction          │  │  │                                       │
│  │  5. Alert if Fraud (SNS)        │  │  │  ┌─────────────────────────────────┐  │
│  └─────────────────────────────────┘  │  │  │  AWS Glue + Amazon Athena       │  │
│                                       │  │  │  - Data catalog & SQL queries   │  │
│  ┌─────────────────────────────────┐  │  │  └─────────────────────────────────┘  │
│  │  DynamoDB Tables                │  │  │                                       │
│  │  - Transactions (with GSIs)     │  │  └───────────────────────────────────────┘
│  │  - Customer Profiles            │  │
│  │  - Fraud Rules                  │  │
│  └─────────────────────────────────┘  │
└───────────────────────────────────────┘
                    │
                    ▼
┌───────────────────────────────────────────────────────────────────────────────┐
│                              ALERTING & ACTIONS                                │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐            │
│  │  Amazon SNS     │───▶│  Security Team  │    │  Mobile Push    │            │
│  │  (Fraud Alerts) │    │  Notifications  │    │  Notifications  │            │
│  └─────────────────┘    └─────────────────┘    └─────────────────┘            │
│  Actions: BLOCK (halt) │ INVESTIGATE (flag) │ APPROVE (continue)              │
└───────────────────────────────────────────────────────────────────────────────┘
```

## AWS Well-Architected Alignment

| Pillar | Implementation |
|--------|----------------|
| **Operational Excellence** | Serverless architecture, CloudWatch dashboards, automated deployment |
| **Security** | KMS encryption, IAM least-privilege, PCI-DSS compliance |
| **Reliability** | Kinesis replication, DynamoDB Multi-AZ, DLQ for failures |
| **Performance** | Sub-second latency, Lambda parallelization, DynamoDB millisecond access |
| **Cost Optimization** | Pay-per-use serverless, S3 lifecycle policies, on-demand DynamoDB |
| **Sustainability** | Multi-tenant serverless, auto-scaling, efficient resource utilization |

## Stacks

### 1. StreamingStack
- Kinesis Data Streams (transactions, scored, alerts)
- API Gateway for transaction ingestion
- SNS Topics for alerts
- KMS encryption key

### 2. ProcessingStack
- Lambda functions (stream processor, fraud scorer, velocity checker, alert handler)
- Step Functions workflow for fraud detection
- DynamoDB tables (transactions, customer profiles, fraud rules)
- SQS dead letter queue

### 3. AnalyticsStack
- Kinesis Firehose with Parquet conversion
- S3 data lake buckets
- AWS Glue data catalog
- Amazon Athena workgroup

## Prerequisites

- AWS CLI configured
- Node.js 18.x+
- Python 3.11+
- AWS CDK CLI (`npm install -g aws-cdk`)

## Installation

```bash
cd rt-fraud-detection
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cdk bootstrap aws://ACCOUNT-ID/REGION
```

## Deployment

```bash
cdk synth
cdk deploy --all
```

## API Usage

### Submit Transaction
```bash
POST /v1/transactions
{
  "transaction_id": "txn-12345",
  "customer_id": "cust-789",
  "amount": 1500.00,
  "merchant_id": "merch-456",
  "card_bin": "411111",
  "ip_address": "192.168.1.1",
  "device_id": "device-abc"
}
```

## Fraud Scoring

### Amazon Fraud Detector (Primary)
- Returns fraud_score (0-1) and outcome (BLOCK/INVESTIGATE/APPROVE)

### Rules-Based Fallback
| Rule | Score |
|------|-------|
| Amount > $10,000 | +0.4 |
| Amount > $5,000 | +0.2 |
| High velocity (10+ txn/hr) | +0.3 |
| Suspicious IP | +0.2 |

**Outcomes:** Score ≥0.7: BLOCK, ≥0.4: INVESTIGATE, <0.4: APPROVE

## Monitoring

### CloudWatch Dashboards
- `FraudDetection-Streaming`: Kinesis, API Gateway metrics
- `FraudDetection-Processing`: Lambda, Step Functions, DynamoDB
- `FraudDetection-Analytics`: Firehose, S3 storage

### Alarms
- Stream iterator age > 1 minute
- Lambda errors > 10/5min
- Step Functions failures > 5/5min
- DLQ messages > 0

## Cost Estimates

| Component | Monthly Cost |
|-----------|--------------|
| Kinesis (4 shards) | $50 |
| Lambda (1M invocations) | $20 |
| Step Functions | $25 |
| DynamoDB | $25-100 |
| Firehose + S3 | $40 |
| **Total** | **~$160-215** |

## License

MIT License
