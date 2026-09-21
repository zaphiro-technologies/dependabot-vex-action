# Copyright 2026 Zaphiro Technologies
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

.PHONY: ci-pre-build test release

ci-pre-build:
	@mkdir -p build

test:
	yarn test:cov

release:
	@test -n "$(TAG)" || (echo "TAG is required, for example: make release TAG=1.2.3" >&2; exit 1)
	@node -e 'const fs = require("node:fs"); const file = "package.json"; const packageJson = JSON.parse(fs.readFileSync(file, "utf8")); packageJson.version = process.argv[1]; fs.writeFileSync(file, JSON.stringify(packageJson, null, 2) + "\n");' "$(TAG)"
