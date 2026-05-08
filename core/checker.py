import sys

required_modules = [
    "rich",
    "requests",
    "psutil",
    "whois"
]

def check_modules():

    for module in required_modules:

        try:

            __import__(module)

        except ImportError:

            print(f"Missing Module: {module}")

            print(
                "Run: pip install -r requirements.txt"
            )

            sys.exit()