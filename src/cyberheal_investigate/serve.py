"""Convenience launcher for the loopback-only student backend."""

import argparse
import os
import secrets

import uvicorn


def main():
    parser = argparse.ArgumentParser(description="Start Member B offline mock API")
    parser.add_argument("--opa", required=True)
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    os.environ["CYBERHEAL_OPA_EXE"] = args.opa
    for role in ("DETECTOR", "OPERATOR", "INTERNAL"):
        name = f"CYBERHEAL_{role}_TOKEN"
        os.environ.setdefault(name, secrets.token_urlsafe(32))
        print(f"{name} = {os.environ[name]}", flush=True)
    print(
        "Private local development tokens above. Do not include them in screenshots or share them.",
        flush=True,
    )
    print(f"OFFLINE MOCK ONLY. Swagger: http://127.0.0.1:{args.port}/docs", flush=True)
    uvicorn.run(
        "cyberheal_investigate.api:app_from_env",
        factory=True,
        host="127.0.0.1",
        port=args.port,
    )


if __name__ == "__main__":
    main()
