CARGO ?= cargo
HELM ?= helm
TAILWIND ?= tailwindcss
.PHONY: check demo css helm-lint
check:
	$(CARGO) fmt --check
	$(CARGO) clippy --all-targets --locked -- -D warnings
	$(CARGO) test --locked
demo:
	$(CARGO) run --locked -- --demo
css:
	$(TAILWIND) -i assets/app.css -o assets/dist/app.css --minify
helm-lint:
	$(HELM) lint --strict deploy/helm/digest-diff-2 --set oidc.issuer=https://idp.example.com
	$(HELM) template digest-diff-2 deploy/helm/digest-diff-2 --set oidc.issuer=https://idp.example.com --set serviceMonitor.enabled=true --set prometheusRule.enabled=true --set grafanaDashboard.enabled=true >/dev/null
