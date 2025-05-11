# pcap-keystrokes

This Python script ([`src/main.py`](src/main.py)) processes USB Human Interface Device keystroke data from either a raw data file or a PCAP file. It then reconstructs the sequence of typed characters.

## Features

*   **Raw Data Parsing**: Parses raw HID data from `.txt` files (hex-encoded, one report per line).
*   **PCAP Extraction**: Extracts USB HID data from `.pcap` or `.pcapng` files using `pyshark`.
*   **Keystroke Translation**: Translates HID keycodes into characters, with support for modifier keys (e.g., Shift).
*   **Destructive Backspace**: Offers an option for destructive backspace behavior, where a backspace key press removes the previously typed character from the output.

## Requirements

The script requires the following Python libraries:

*   `tqdm`: For displaying progress bars, especially useful when processing large PCAP files.
*   `pyshark`: For parsing PCAP files and extracting USB HID data.

You can install these libraries using pip:

```sh
pip install tqdm pyshark
```

**Note**: `pyshark` relies on `tshark`, which is part of the Wireshark distribution. Ensure `tshark` is installed and available in your system's PATH.

## Usage

Run the script from the command line, providing the path to your data file.
Alternatively, you can initialise the `HIDpcap` class, providing a source file for the code to load from.
