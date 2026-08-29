# HTTP E2E Security Smoke Test

This directory contains a repeatable HTTP smoke test for the running platform. It requires Docker infrastructure and all services to be running.

Start infrastructure:

```powershell
docker compose up -d
```

Start services in separate terminals with `JWT_SECRET` and `INTERNAL_REQUEST_SECRET` set:

```powershell
mvn -pl auth-service spring-boot:run
mvn -pl permission-service spring-boot:run
mvn -pl audit-service spring-boot:run
mvn -pl admin-api spring-boot:run
mvn -pl business-service spring-boot:run
mvn -pl gateway-service spring-boot:run
```

Run the smoke test:

```powershell
.\e2e\security-smoke.ps1
```

The script checks gateway health, login, missing credentials, internal route hiding, Refresh Token rejection on a business route, business data routing, and an authorized admin route. It is a smoke test, not a replacement for concurrency, fault-injection, migration, or load testing.
