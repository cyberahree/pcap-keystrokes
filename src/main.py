from tqdm import tqdm
import pyshark

MODIFIERS = {
    0x01: "LeftCtrl",
    0x02: "LeftShift",
    0x04: "LeftAlt",
    0x08: "LeftGUI",
    0x10: "RightCtrl",
    0x20: "RightShift",
    0x40: "RightAlt",
    0x80: "RightGUI",
}

HID_KEYCODES = {
    0x04: ('a', 'A'), 0x05: ('b', 'B'), 0x06: ('c', 'C'), 0x07: ('d', 'D'),
    0x08: ('e', 'E'), 0x09: ('f', 'F'), 0x0A: ('g', 'G'), 0x0B: ('h', 'H'),
    0x0C: ('i', 'I'), 0x0D: ('j', 'J'), 0x0E: ('k', 'K'), 0x0F: ('l', 'L'),
    0x10: ('m', 'M'), 0x11: ('n', 'N'), 0x12: ('o', 'O'), 0x13: ('p', 'P'),
    0x14: ('q', 'Q'), 0x15: ('r', 'R'), 0x16: ('s', 'S'), 0x17: ('t', 'T'),
    0x18: ('u', 'U'), 0x19: ('v', 'V'), 0x1A: ('w', 'W'), 0x1B: ('x', 'X'),
    0x1C: ('y', 'Y'), 0x1D: ('z', 'Z'), 0x1E: ('1', '!'), 0x1F: ('2', '"'),
    0x20: ('3', '£'), 0x21: ('4', '$'), 0x22: ('5', '%'), 0x23: ('6', '^'),
    0x24: ('7', '&'), 0x25: ('8', '*'), 0x26: ('9', '('), 0x27: ('0', ')'),
    0x28: ('\n', '\n'), 0x29: ('\t', '\t'), 0x2A: ('\b', '\b'), 0x2B: ('\t', '\t'),
    0x2C: (' ', ' '), 0x2D: ('-', '_'), 0x2E: ('=', '+'), 0x2F: ('[', '{'),
    0x30: (']', '}'), 0x31: ('\\', '|'), 0x32: ('#', '~'), 0x33: (';', ':'),
    0x34: ('\'', '"'), 0x35: ('`', '~'), 0x36: (',', '<'), 0x37: ('.', '>'),
    0x38: ('/', '?')
}

class HIDreport:
    report_id: int
    active_modifiers: list[str]
    pressed_keys: list[str]
    pressing_key: bool
    is_modified: bool

class HIDpcap:
    def __init__(self, data_file: str, destructive_backspace: bool = True) -> None:
        """
        Initializes the HIDpcap object.

        Args:
            data_file: Path to the file containing HID data (.txt or .pcap).
            destructive_backspace: If True, backspace removes the last character.
        """

        # load data
        file_extension = data_file.split('.')[-1].lower()

        if file_extension == "txt":
            with open(data_file, "r") as file:
                self.content = [bytes.fromhex(line.strip()) for line in file if line.strip()]
        elif file_extension.startswith("pcap"):
            self.content = self._parse_pcap(data_file)
        else:
            raise ValueError("Unsupported file format. Please provide a .txt or .pcap file.")
        
        self.destructive_backspace = destructive_backspace

    def _parse_pcap(self, pcap_file: str) -> list[bytes]:
        """
        Parses a pcap file to extract USB HID data.

        Args:
            pcap_file: Path to the pcap file.

        Returns:
            A list of byte strings, each representing HID data.
        """

        # tshark -r click.pcapng -Y "usbhid.data" -T fields -e usbhid.data | grep -E "." | grep -v '0000000000000000' > capdata.txt

        content = []
        capture = pyshark.FileCapture(
            input_file=pcap_file,
            keep_packets=True,
            display_filter="usbhid.data",
            include_raw=True,
            use_json=True,
        )
        
        for packet in tqdm(capture, desc="Collecting bytes from packet capture"):
            data_bytes = packet.get_raw_packet()
            data_len = int(packet.usb.urb_len)

            if (type(data_bytes) is not bytes) or (data_len < 1):
                continue

            content.append(
                data_bytes[-data_len:]
            )

        return content

    def _generate_report(self, keystroke_data: bytes) -> HIDreport:
        """
        Generates an HIDreport object from raw keystroke data.

        Args:
            keystroke_data: Bytes representing a single HID report.

        Returns:
            An HIDreport object.
        """

        report = HIDreport()
        report.report_id = keystroke_data[0]

        # reserved = data[2]
        modifier_byte = keystroke_data[1]
        keycodes = keystroke_data[3:9]

        report.active_modifiers = [name for bit, name in MODIFIERS.items() if modifier_byte & bit]
        report.pressed_keys = [HID_KEYCODES.get(kc, f"Unknown(0x{kc:02x})") for kc in keycodes if kc != 0]
        report.pressing_key = len(report.pressed_keys) > 0
        report.is_modified = len(report.active_modifiers) > 0
        
        return report

    def generate_keystrokes(self) -> str:
        """
        Converts the parsed HID data into a string of keystrokes.

        Returns:
            A string representing the typed characters.
        """

        keystrokes = ""

        for hid_content in self.content:
            report = self._generate_report(hid_content)

            if not report.pressing_key:
                continue

            # append the pressed keys to the keystrokes string
            for key_tuple in report.pressed_keys:
                # is it a backspace?
                if key_tuple[0] == '\b' and self.destructive_backspace:
                    keystrokes = keystrokes[:-1]
                else:
                    keystrokes += key_tuple[0] if not report.is_modified else key_tuple[1]

        return keystrokes

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Process USB HID keystroke data from a file.")

    parser.add_argument(
        "file",
        help="The file containing either raw HID data (e.g., capdata.txt) or a pcap file containing USB HID data"
    )

    parser.add_argument(
        "--dbs",
        action="store_true",
        help="Enable destructive backspace behavior (removes the last character on backspace)",
        default=True
    )

    args = parser.parse_args()

    parser = HIDpcap(
        args.file,
        destructive_backspace=args.dbs
    )

    keystrokes = parser.generate_keystrokes()

    print(keystrokes)
