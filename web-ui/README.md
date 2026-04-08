# Web UI

This React + TypeScript application is the interactive demonstration interface
for the `hello-pqc` prototype.

It is intentionally lightweight. The UI exists to make the signing and
verification flow visible to a human operator, not to act as the canonical
benchmarking interface.

## What The UI Does

- API key login and session handling
- file upload to the gateway
- selection of signature profile and hash algorithm
- manifest inspection after signing
- verification by `request_id` plus uploaded file
- display of detailed verification checks and metadata

## Important Boundary

The UI does **not** compute cryptographic operations locally.

- hashing happens in the backend hasher service
- signing happens in the backend manifest builder service
- verification happens through the backend API flow

This keeps the benchmark and security model consistent with the rest of the
project.

## Development

Install dependencies and start the dev server:

```bash
npm install
npm run dev
```

The app expects the API gateway to be reachable at the configured backend URL
used by the frontend API client.
