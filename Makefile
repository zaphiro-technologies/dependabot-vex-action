.PHONY: ci-pre-build test release

ci-pre-build:
	@mkdir -p build

test:
	yarn test:cov

release:
	@test -n "$(TAG)" || (echo "TAG is required, for example: make release TAG=1.2.3" >&2; exit 1)
	@node -e 'const fs = require("node:fs"); const file = "package.json"; const packageJson = JSON.parse(fs.readFileSync(file, "utf8")); packageJson.version = process.argv[1]; fs.writeFileSync(file, JSON.stringify(packageJson, null, 2) + "\n");' "$(TAG)"
