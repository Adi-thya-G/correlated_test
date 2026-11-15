# Correlation test folder

- correlation-test-repo/  Scan this repo with your scanners, then check the Correlation collection.
- backend-test/           Standalone scoring test. Run: npm install && npm test

Windows (PowerShell):
    cd backend-test
    npm install
    npm test

Expected: the two "same function" cases fail until services/correlationScore.ts requires sameFile before adding the function bonus:
    if (sameFile && a.function && a.function === b.function) {
