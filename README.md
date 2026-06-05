# SOAR Platform

Cloud-native Security Orchestration, Automation and Response — built on AWS

A production-grade SOAR platform that ingests security alerts from multiple sources,
correlates them into incidents, triggers automated playbooks, and manages the full
case lifecycle — all running on AWS-native services.

## Architecture

    Ingest             Detect              Orchestrate
    ──────────────     ──────────────      ──────────────
    API Gateway        EventBridge         Step Functions
    Security Hub       Kinesis Streams     Lambda Actions
    CrowdStrike        Correlation Engine  Playbook Store
    SIEM webhooks      SQS P1/P2/P3        ECS Workers

## Services

    ingestor         FastAPI, Python 3.12    Normalize alerts from any source
    correlator       Python, asyncio         Dedup, cluster, score alerts
    playbook-engine  FastAPI, Step Functions Trigger automated responses
    case-manager     FastAPI, PostgreSQL      Case lifecycle management
    enricher         Python, Redis           VirusTotal, Shodan enrichment
    notification-svc Python                  Slack, PagerDuty, SNS

## Supported Sources

- AWS Security Hub (GuardDuty, Inspector, Macie)
- CrowdStrike Falcon
- Splunk (coming soon)
- Elastic SIEM (coming soon)

## Quick Start

    git clone https://github.com/GeekyBlessing/soar-platform
    cd soar-platform
    make up

Platform starts at:
- Ingestor API  http://localhost:8001
- API Docs      http://localhost:8001/docs

## Send a test alert

    BODY='{"detail":{"findings":[{"Id":"test-001","Title":"EC2 communicating with C2","Description":"Test","Severity":{"Label":"CRITICAL"},"Confidence":92,"Criticality":88,"Resources":[{"Type":"AwsEc2Instance","Id":"i-0test123","Region":"us-east-1","Details":{"AwsEc2Instance":{"IpV4Addresses":["172.31.10.5"],"ImageId":"ami-test"}}}]}]}}'
    SIG=$(echo -n "$BODY" | openssl dgst -sha256 -hmac "dev-hmac-secret" | cut -d' ' -f2)
    curl -s -X POST http://localhost:8001/v1/ingest/webhook \
      -H "Content-Type: application/json" \
      -H "X-SOAR-Source: aws.securityhub" \
      -H "X-SOAR-Signature: sha256=$SIG" \
      -d "$BODY"

## Run tests

    make test

## Key Design Decisions

- Immutable events — SOAREvent is a frozen Pydantic model. Forensic integrity guaranteed.
- HMAC-SHA256 auth — every webhook verified before processing
- Source x Severity routing — precise playbook targeting
- Sliding-window correlation — related alerts grouped into incidents automatically
- IRSA everywhere — zero node-level IAM exposure in production

## Stack

Python 3.12, FastAPI, PostgreSQL, Redis, AWS Kinesis, EventBridge,
Step Functions, SQS, LocalStack, Docker, Terraform, Helm
