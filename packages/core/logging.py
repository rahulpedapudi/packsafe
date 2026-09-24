import logging


def setup_logging():
    logging.basicConfig(
        filename="app-dev.log",
        filemode="w",
        # capturing INFO level and above
        level=logging.INFO,
        format=("%(asctime)s | %(levelname)s | %(name)s | %(message)s"),
    )
