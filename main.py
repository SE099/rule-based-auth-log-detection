import sys

from parsers.auth_parser import parse_auth_log
from engine.rule_engine import RuleEngine


def main():
    """
    Application entry point.

    The main function connects the parser and the rule engine.
    It reads the specified authentication log file line by line,
    parses each line into a structured event, and forwards valid
    events to the rule engine for evaluation.
    """

    # Ensure that a log file was provided.
    #
    # Example:
    # python main.py logs/scenario1_bruteforce.log
    if len(sys.argv) != 2:
        print(
            "Usage: python main.py <log_file>"
        )
        sys.exit(1)

    # Retrieve the log file path from the command-line argument.
    log_file = sys.argv[1]

    # Initialize the rule engine.
    engine = RuleEngine()

    # Open and process the specified log file.
    with open(log_file, "r") as f:

        # Process each log entry individually.
        for line in f:

            # Convert raw log data into a structured event.
            parsed_event = parse_auth_log(line)

            # Ignore lines that do not match the expected log format.
            if parsed_event:
                engine.process(parsed_event)


if __name__ == "__main__":
    main()