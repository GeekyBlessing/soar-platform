.PHONY: up down logs test test-unit test-int test-all coverage lint send-test-alert send-crowdstrike send-splunk help

help:
	@echo ""
	@echo "  SOAR Platform — Available Commands"
	@echo ""
	@echo "  make up               Start full platform"
	@echo "  make down             Stop platform"
	@echo "  make logs             Tail all logs"
	@echo "  make logs-ingestor    Tail ingestor logs"
	@echo "  make test-unit        Run unit tests"
	@echo "  make test-int         Run integration tests"
	@echo "  make test-all         Run all tests"
	@echo "  make coverage         Run tests with coverage report"
	@echo "  make lint             Run ruff linter"
	@echo "  make send-test-alert  Send AWS SecurityHub test alert"
	@echo "  make send-crowdstrike Send CrowdStrike test alert"
	@echo "  make send-splunk      Send Splunk test alert"
	@echo ""

up:
	docker compose up -d
	@echo ""
	@echo "  Ingestor  -> http://localhost:8001"
	@echo "  API Docs  -> http://localhost:8001/docs"
	@echo "  Metrics   -> http://localhost:8001/metrics"
	@echo "  Sources   -> http://localhost:8001/v1/ingest/sources"
	@echo ""

down:
	docker compose down

logs:
	docker compose logs -f --tail=50

logs-%:
	docker compose logs -f --tail=100 $*

restart-%:
	docker compose restart $*

test-unit:
	python -m pytest tests/unit/ -v --tb=short

test-int:
	python -m pytest tests/integration/ -v --tb=short

test-all:
	python -m pytest tests/ -v --tb=short

coverage:
	python -m pytest tests/ -v \
		--cov=services \
		--cov=shared \
		--cov-report=term-missing \
		--cov-fail-under=80

lint:
	python -m ruff check services/ shared/ tests/ --output-format=concise

format:
	python -m ruff format services/ shared/ tests/

send-test-alert:
	$(eval BODY := {"detail":{"findings":[{"Id":"test-001","Title":"EC2 communicating with C2","Description":"Test","Severity":{"Label":"CRITICAL"},"Confidence":92,"Criticality":88,"Resources":[{"Type":"AwsEc2Instance","Id":"i-0test123","Region":"us-east-1","Details":{"AwsEc2Instance":{"IpV4Addresses":["172.31.10.5"],"ImageId":"ami-test"}}}]}]}})
	$(eval SIG := $(shell echo -n '$(BODY)' | openssl dgst -sha256 -hmac "dev-hmac-secret" | cut -d' ' -f2))
	curl -s -X POST http://localhost:8001/v1/ingest/webhook \
		-H "Content-Type: application/json" \
		-H "X-SOAR-Source: aws.securityhub" \
		-H "X-SOAR-Signature: sha256=$(SIG)" \
		-d '$(BODY)' | python3 -m json.tool

send-crowdstrike:
	$(eval BODY := {"event":{"DetectionId":"cs-001","DetectName":"Malware Detected","DetectDescription":"Malicious file","SeverityName":"critical","MaxSeverity":95,"Behavior":"MaliciousFile","UserName":"administrator","DeviceDetails":{"Hostname":"PROD-WS-01","LocalIP":"10.0.0.50","ExternalIP":"1.2.3.4","OSVersion":"Windows 11"}}})
	$(eval SIG := $(shell echo -n '$(BODY)' | openssl dgst -sha256 -hmac "dev-hmac-secret" | cut -d' ' -f2))
	curl -s -X POST http://localhost:8001/v1/ingest/webhook \
		-H "Content-Type: application/json" \
		-H "X-SOAR-Source: crowdstrike.falcon" \
		-H "X-SOAR-Signature: sha256=$(SIG)" \
		-d '$(BODY)' | python3 -m json.tool

send-splunk:
	$(eval BODY := {"result":{"search_name":"Brute Force Detected","message":"Multiple failed logins","severity":"high","event_id":"splunk-001","src_ip":"192.168.1.100","dest_ip":"10.0.0.1","host":"auth-server-01","user":"admin"}})
	$(eval SIG := $(shell echo -n '$(BODY)' | openssl dgst -sha256 -hmac "dev-hmac-secret" | cut -d' ' -f2))
	curl -s -X POST http://localhost:8001/v1/ingest/webhook \
		-H "Content-Type: application/json" \
		-H "X-SOAR-Source: splunk.es" \
		-H "X-SOAR-Signature: sha256=$(SIG)" \
		-d '$(BODY)' | python3 -m json.tool

setup:
	python3 -m venv .venv
	source .venv/bin/activate && pip install -r requirements.txt

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null; true
	find . -name "*.pyc" -delete 2>/dev/null; true
	rm -rf .coverage coverage-report/ 2>/dev/null; true
