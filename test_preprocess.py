import sys
from pathlib import Path


# Add src folder to Python path
ROOT = Path(__file__).resolve().parent

sys.path.insert(
    0,
    str(ROOT / "src")
)


from preprocess import prepare_for_model


messages = [
    "URGENT!!! Click https://example.com to WIN ₹50,000.",
    "Congratulations! You won a prize.",
    "Please attend the meeting tomorrow."
]


for message in messages:

    print("\nOriginal:")
    print(message)

    print("Cleaned:")

    # SMS channel
    print(
        prepare_for_model(
            message,
            "sms"
        )
    )