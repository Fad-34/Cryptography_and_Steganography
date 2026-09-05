# StegoShield Web

Web version of the `Assignment2/steganography_tool.py` Tkinter application.

## Features

- Encode/hide any file inside a cover image using 1-bit LSB substitution.
- Decode/extract files from StegoShield PNG images.
- Same `MAGIC = b"STEGv1\x00\x00"` and `HEADER_FMT = ">8sHQ"` payload layout as the original app.
- Cover-image capacity calculation.
- File-size and pixel/channel difference analysis.
- Responsive browser UI.

## Install

```bash
pip install -r requirements.txt
```

## Run

```bash
python app.py
```

Then open:

```text
http://127.0.0.1:5000
```

## Suggested repository structure

```text
Cryptography_and_Steganography/
└── Assignment2/
    ├── steganography_tool.py
    └── web/
        ├── app.py
        ├── requirements.txt
        └── templates/
            └── index.html
```

You can copy the `stegoshield_web` folder into `Assignment2/web`.
