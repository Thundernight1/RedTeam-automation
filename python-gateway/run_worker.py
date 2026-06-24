"""
Worker entry point for ZumrutAutomation scanner agents.
Reads WORKER_TYPE from environment and starts the appropriate agent.
"""

import os
import sys
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('worker')

# Add agent modules to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'agents'))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'agents', 'red_team'))

from agents.agent_runner import create_agent


def main():
    worker_type = os.getenv('WORKER_TYPE', 'web_scanner')
    logger.info(f"Starting worker with type: {worker_type}")

    try:
        agent = create_agent(worker_type)
        agent.run()
    except KeyboardInterrupt:
        logger.info("Worker interrupted by user")
    except Exception as e:
        logger.error(f"Worker failed: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
