# aws-terraform-opa-guardrails

## Rules

TAG-001
- `ApplicationID`, `Environment`, `Owner` present
- ApplicationID is `APP-NNNNN` and registered and active



---

[Beeceptor.com](https://app.beeceptor.com/console/muarwi)
endpoint: https://muarwi.free.beeceptor.com/
```
GET /healthz
GET /v1/applications/:id/validate

{
  "application_id": "{{ pathParam "id"}}",
  "valid": {{#switch (pathParam 'id')}}{{#case 'APP-00001'}}true{{/case}}{{#case 'APP-00002'}}true{{/case}}{{#case 'APP-00003'}}true{{/case}}{{#default}}false{{/default}}{{/switch}}
}
```