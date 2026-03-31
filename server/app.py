"""
OpenEnv server entrypoint expected by multi-mode validators.
"""

import uvicorn

from main import app


def main() -> None:
    """Run the FastAPI app on the default OpenEnv port."""
    uvicorn.run(app, host="0.0.0.0", port=7860)


if __name__ == "__main__":
    main()

