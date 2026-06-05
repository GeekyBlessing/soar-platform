.PHONY: up down logs test send-test-alert

up:
	docker compose up -d
	@echo "Ingestor → http://localhost:8001"
	@echo "Docs     → http://localhost:8001/docs"

down:
	docker compose down

logs:
	docker compose logs -f --tail=50

logs-%:
	docker compose logs -f --tail=100 $*

test:
	pytest tests/ -v --tb=short

setup:
	python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt

send-test-alert:
	@BODY=$$(cat tests/fixtures/securityhub_finding.json); \
	SIG=$$(echo -n "$$BODY" | openssl dgst -sha256 -hmac "dev-hmac-secret" | cut -d' ' -f2); \
	curl -s -X POST http://localhost:8001/v1/ingest/webhook \
		-H "Content-Type: application/json" \
		-H "X-SOAR-Source: aws.securityhub" \
		-H "X-SOAR-Signature: sha256=$$SIG" \
		-d "$$BODY" | python3 -m json.tool
