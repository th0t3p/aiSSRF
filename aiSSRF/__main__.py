"""Entry point: ``python -m aiSSRF`` to run the full pipeline."""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys

from aiSSRF.config import AiSsrfConfig
from aiSSRF.orchestrator import Orchestrator


def _configure_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="aiSSRF",
        description="Automated SSRF candidate discovery, payload "
                    "generation, OAST verification, and LLM judgment.",
    )
    parser.add_argument(
        "-o", "--output", type=str, default=None,
        help="Write the JSON report to this file instead of stdout.",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Enable debug-level logging.",
    )
    parser.add_argument(
        "--scope", action="append", default=None,
        help="Override AISSRF_AUTHORIZED_SCOPE for this run only "
             "(repeatable, e.g. --scope '*.example.com' --scope other.com). "
             "Overrides .env for this run only.",
    )
    return parser.parse_args()


async def _main() -> int:
    args = _parse_args()
    _configure_logging(args.verbose)
    logger = logging.getLogger("aiSSRF")

    overrides: dict = {}
    if args.scope:
        overrides["authorized_scope"] = args.scope

    try:
        config = AiSsrfConfig(**overrides)
    except Exception:
        logger.exception("Failed to load configuration — check your .env file")
        return 1

    if not config.authorized_scope:
        logger.error(
            "authorized_scope is empty — refusing to run (fail-closed). "
            "Set AISSRF_AUTHORIZED_SCOPE in .env or pass --scope."
        )
        return 1

    logger.info("Starting aiSSRF run — scope: %s", config.authorized_scope)
    orch = Orchestrator(config)
    report = await orch.run()

    output_json = report.model_dump_json(indent=2)
    if args.output:
        with open(args.output, "w") as f:
            f.write(output_json)
        logger.info("Report written to %s", args.output)
    else:
        print(output_json)

    logger.info(
        "Done — %d candidates, %d confirmed, %d inconclusive, %d false positives",
        report.total_candidates,
        report.confirmed,
        report.inconclusive,
        report.false_positives,
    )
    return 0


def _sync_main() -> None:
    """Synchronous wrapper for ``[project.scripts]`` entry point."""
    sys.exit(asyncio.run(_main()))


if __name__ == "__main__":
    _sync_main()
