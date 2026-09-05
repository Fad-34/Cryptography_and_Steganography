import os # Interact with operating system to get file paths, names, and sizes.

# struct packs metadata into bytes and unpacks it during decoding.
import struct

# tkinter provides the graphical user interface.
import tkinter as tk

# filedialog = open/save dialogs
# messagebox = popup messages
# ttk = themed tkinter widgets
from tkinter import filedialog, messagebox, ttk

# Pillow classes:
# Image      -> open and manipulate images
# ImageTk    -> show Pillow images inside Tkinter
# ImageChops -> calculate the difference between two images
# ImageStat  -> calculate statistics from an image
from PIL import Image, ImageTk, ImageChops, ImageStat

# matplotlib is used to draw RGB histograms.
import matplotlib.pyplot as plt


# ------------------------------------------------------------
# PAYLOAD HEADER SETTINGS
# ------------------------------------------------------------

# A fixed 8-byte signature written at the start of every hidden payload.
# During decoding, this tells the program that the image was created
# by this StegoShield application.
MAGIC = b"STEGv1\x00\x00"

# >  = big-endian byte order
# 8s = 8-byte string for MAGIC
# H  = unsigned short (2 bytes) for filename length
# Q  = unsigned long long (8 bytes) for secret-file length
HEADER_FMT = ">8sHQ"

# Calculate the number of bytes needed by the fixed header.
HEADER_SIZE = struct.calcsize(HEADER_FMT)


# ============================================================
# MAIN GUI CLASS
# ============================================================
class SteganographyGUI:

    # __init__ runs automatically when an object of this class is created.
    def __init__(self, root):
        # Store the main Tkinter window.
        self.root = root

        # Set the window title.
        self.root.title("StegoShield - Image Steganography Tool")

        # Set the default window size.
        self.root.geometry("1180x780")

        # Prevent the window from becoming too small.
        self.root.minsize(1000, 680)

        # Paths selected by the user.
        self.cover_path = ""
        self.secret_path = ""
        self.stego_path = ""

        # References to preview images.
        # Keeping references prevents Tkinter from removing them from memory.
        self.cover_photo = None
        self.stego_photo = None

        # Configure the visual style.
        self.setup_style()

        # Build all interface widgets.
        self.build_ui()


    # --------------------------------------------------------
    # GUI STYLE
    # --------------------------------------------------------
    def setup_style(self):
        # Create a ttk style manager.
        style = ttk.Style()

        # Try to use the "clam" theme because it is easy to customise.
        try:
            style.theme_use("clam")
        except tk.TclError:
            # If the theme is unavailable, continue with the default theme.
            pass

        # General frame appearance.
        style.configure("TFrame", background="#F5F7FB")

        # General label appearance.
        style.configure(
            "TLabel",
            background="#F5F7FB",
            foreground="#1F2937",
            font=("Segoe UI", 10)
        )

        # Large application title.
        style.configure(
            "Title.TLabel",
            font=("Segoe UI", 24, "bold"),
            foreground="#111827"
        )

        # Smaller subtitle/status text.
        style.configure(
            "Subtitle.TLabel",
            font=("Segoe UI", 10),
            foreground="#6B7280"
        )

        # White card/panel backgrounds.
        style.configure("Card.TFrame", background="#FFFFFF")
        style.configure(
            "Card.TLabel",
            background="#FFFFFF",
            foreground="#111827"
        )

        # Card section title.
        style.configure(
            "CardTitle.TLabel",
            background="#FFFFFF",
            foreground="#111827",
            font=("Segoe UI", 12, "bold")
        )

        # Primary button styling.
        style.configure(
            "Primary.TButton",
            font=("Segoe UI", 10, "bold"),
            padding=(14, 10)
        )

        # Secondary button styling.
        style.configure(
            "Secondary.TButton",
            font=("Segoe UI", 10),
            padding=(12, 9)
        )

        # Notebook/tab styling.
        style.configure(
            "TNotebook",
            background="#F5F7FB",
            borderwidth=0
        )
        style.configure(
            "TNotebook.Tab",
            font=("Segoe UI", 10, "bold"),
            padding=(16, 9)
        )

        # Capacity progress-bar thickness.
        style.configure("Horizontal.TProgressbar", thickness=12)


    # --------------------------------------------------------
    # BUILD MAIN WINDOW
    # --------------------------------------------------------
    def build_ui(self):
        # Set the root-window background colour.
        self.root.configure(bg="#F5F7FB")

        # Main container with padding.
        outer = ttk.Frame(self.root, padding=20)
        outer.pack(fill="both", expand=True)

        # ---------- Header ----------
        header = ttk.Frame(outer)
        header.pack(fill="x", pady=(0, 14))

        # Application name.
        ttk.Label(
            header,
            text="StegoShield",
            style="Title.TLabel"
        ).pack(anchor="w")

        # Application description.
        ttk.Label(
            header,
            text="Hide complete files inside images using Least Significant Bit (LSB) steganography.",
            style="Subtitle.TLabel"
        ).pack(anchor="w", pady=(2, 0))

        # ---------- Tabs ----------
        self.notebook = ttk.Notebook(outer)
        self.notebook.pack(fill="both", expand=True)

        # Create the three application pages.
        self.encode_tab = ttk.Frame(self.notebook, padding=14)
        self.decode_tab = ttk.Frame(self.notebook, padding=14)
        self.analysis_tab = ttk.Frame(self.notebook, padding=14)

        # Add each page to the tab control.
        self.notebook.add(self.encode_tab, text="Encode")
        self.notebook.add(self.decode_tab, text="Decode")
        self.notebook.add(self.analysis_tab, text="Analysis")

        # Build the contents of each tab.
        self.build_encode_tab()
        self.build_decode_tab()
        self.build_analysis_tab()

        # ---------- Status bar ----------
        status_bar = ttk.Frame(outer)
        status_bar.pack(fill="x", pady=(12, 0))

        # StringVar lets the program change status text dynamically.
        self.status_var = tk.StringVar(value="Ready")

        # Left side: program status.
        ttk.Label(
            status_bar,
            textvariable=self.status_var,
            style="Subtitle.TLabel"
        ).pack(side="left")

        # Right side: course/assignment label.
        ttk.Label(
            status_bar,
            text="IKB 21303 • Assignment 2",
            style="Subtitle.TLabel"
        ).pack(side="right")


    # Helper function used to make a white card/panel.
    def card(self, parent):
        return ttk.Frame(parent, style="Card.TFrame", padding=16)


    # --------------------------------------------------------
    # ENCODE TAB
    # --------------------------------------------------------
    def build_encode_tab(self):
        # Allow the two columns to expand equally.
        self.encode_tab.columnconfigure(0, weight=1)
        self.encode_tab.columnconfigure(1, weight=1)

        # Allow the preview row to expand vertically.
        self.encode_tab.rowconfigure(1, weight=1)

        # Create the upper control card.
        controls = self.card(self.encode_tab)
        controls.grid(
            row=0,
            column=0,
            columnspan=2,
            sticky="ew",
            pady=(0, 12)
        )

        # Let the middle column stretch.
        controls.columnconfigure(1, weight=1)

        # Section title.
        ttk.Label(
            controls,
            text="Create Stego Image",
            style="CardTitle.TLabel"
        ).grid(
            row=0,
            column=0,
            columnspan=3,
            sticky="w",
            pady=(0, 12)
        )

        # ---------- Cover image selection ----------
        ttk.Label(
            controls,
            text="Cover image",
            style="Card.TLabel"
        ).grid(
            row=1,
            column=0,
            sticky="w",
            padx=(0, 10)
        )

        # Holds the cover filename displayed in the GUI.
        self.cover_var = tk.StringVar(value="No image selected")

        ttk.Label(
            controls,
            textvariable=self.cover_var,
            style="Card.TLabel"
        ).grid(
            row=1,
            column=1,
            sticky="ew"
        )

        # Calls choose_cover() when clicked.
        ttk.Button(
            controls,
            text="Browse Image",
            style="Secondary.TButton",
            command=self.choose_cover
        ).grid(
            row=1,
            column=2,
            padx=(10, 0)
        )

        # ---------- Secret file selection ----------
        ttk.Label(
            controls,
            text="Secret file",
            style="Card.TLabel"
        ).grid(
            row=2,
            column=0,
            sticky="w",
            padx=(0, 10),
            pady=(10, 0)
        )

        # Holds the displayed secret filename and size.
        self.secret_var = tk.StringVar(value="No file selected")

        ttk.Label(
            controls,
            textvariable=self.secret_var,
            style="Card.TLabel"
        ).grid(
            row=2,
            column=1,
            sticky="ew",
            pady=(10, 0)
        )

        # Calls choose_secret() when clicked.
        ttk.Button(
            controls,
            text="Browse File",
            style="Secondary.TButton",
            command=self.choose_secret
        ).grid(
            row=2,
            column=2,
            padx=(10, 0),
            pady=(10, 0)
        )

        # ---------- Capacity indicator ----------
        # Text displayed above the capacity bar.
        self.capacity_var = tk.StringVar(value="Capacity: —")

        ttk.Label(
            controls,
            textvariable=self.capacity_var,
            style="Card.TLabel"
        ).grid(
            row=3,
            column=0,
            columnspan=3,
            sticky="w",
            pady=(12, 4)
        )

        # Progress bar showing how much cover capacity will be used.
        self.capacity_bar = ttk.Progressbar(
            controls,
            mode="determinate",
            maximum=100
        )
        self.capacity_bar.grid(
            row=4,
            column=0,
            columnspan=3,
            sticky="ew"
        )

        # Main encode button.
        ttk.Button(
            controls,
            text="Hide Secret File",
            style="Primary.TButton",
            command=self.encode_file
        ).grid(
            row=5,
            column=0,
            columnspan=3,
            sticky="ew",
            pady=(14, 0)
        )

        # ---------- Image preview cards ----------
        cover_card = self.card(self.encode_tab)
        cover_card.grid(
            row=1,
            column=0,
            sticky="nsew",
            padx=(0, 6)
        )

        stego_card = self.card(self.encode_tab)
        stego_card.grid(
            row=1,
            column=1,
            sticky="nsew",
            padx=(6, 0)
        )

        # Cover image heading.
        ttk.Label(
            cover_card,
            text="Cover Image",
            style="CardTitle.TLabel"
        ).pack(anchor="w")

        # Widget where the cover-image preview will appear.
        self.cover_preview = tk.Label(
            cover_card,
            text="Select a cover image",
            bg="#FFFFFF",
            fg="#6B7280",
            font=("Segoe UI", 11),
            relief="groove",
            bd=1
        )
        self.cover_preview.pack(
            fill="both",
            expand=True,
            pady=(10, 0)
        )

        # Stego image heading.
        ttk.Label(
            stego_card,
            text="Stego Image",
            style="CardTitle.TLabel"
        ).pack(anchor="w")

        # Widget where the generated stego image will appear.
        self.stego_preview = tk.Label(
            stego_card,
            text="Stego image will appear here",
            bg="#FFFFFF",
            fg="#6B7280",
            font=("Segoe UI", 11),
            relief="groove",
            bd=1
        )
        self.stego_preview.pack(
            fill="both",
            expand=True,
            pady=(10, 0)
        )


    # --------------------------------------------------------
    # DECODE TAB
    # --------------------------------------------------------
    def build_decode_tab(self):
        # Create one large card for the decoder.
        card = self.card(self.decode_tab)
        card.pack(fill="both", expand=True)

        # Decoder title.
        ttk.Label(
            card,
            text="Extract Hidden File",
            style="CardTitle.TLabel"
        ).pack(anchor="w")

        # Decoder instructions.
        ttk.Label(
            card,
            text="Choose a stego PNG created by this application. The original filename and data will be recovered.",
            style="Card.TLabel"
        ).pack(anchor="w", pady=(5, 18))

        # Button that starts the decode process.
        ttk.Button(
            card,
            text="Choose Stego Image and Extract",
            style="Primary.TButton",
            command=self.decode_file
        ).pack(fill="x")

        # Text area that shows extraction details.
        self.decode_info = tk.Text(
            card,
            height=18,
            wrap="word",
            font=("Consolas", 10),
            bg="#F9FAFB",
            fg="#111827",
            relief="flat",
            padx=12,
            pady=12
        )
        self.decode_info.pack(
            fill="both",
            expand=True,
            pady=(16, 0)
        )

        # Initial message.
        self.decode_info.insert(
            "end",
            "Extraction log will appear here.\n"
        )

        # Make the log read-only.
        self.decode_info.configure(state="disabled")


    # --------------------------------------------------------
    # ANALYSIS TAB
    # --------------------------------------------------------
    def build_analysis_tab(self):
        # Top control card.
        top = self.card(self.analysis_tab)
        top.pack(fill="x", pady=(0, 12))

        # Analysis heading.
        ttk.Label(
            top,
            text="Image Analysis",
            style="CardTitle.TLabel"
        ).pack(anchor="w")

        # Analysis description.
        ttk.Label(
            top,
            text="Compare cover and stego image file sizes, pixel changes and RGB histograms.",
            style="Card.TLabel"
        ).pack(anchor="w", pady=(5, 12))

        # Container for analysis buttons.
        buttons = ttk.Frame(top, style="Card.TFrame")
        buttons.pack(fill="x")

        # File-size analysis button.
        ttk.Button(
            buttons,
            text="Compare File Sizes",
            style="Secondary.TButton",
            command=self.compare_sizes
        ).pack(side="left", padx=(0, 8))

        # Histogram button.
        ttk.Button(
            buttons,
            text="Show RGB Histograms",
            style="Secondary.TButton",
            command=self.show_histograms
        ).pack(side="left", padx=(0, 8))

        # Pixel-difference button.
        ttk.Button(
            buttons,
            text="Pixel Difference",
            style="Secondary.TButton",
            command=self.pixel_difference
        ).pack(side="left")

        # Card that displays analysis text.
        result_card = self.card(self.analysis_tab)
        result_card.pack(fill="both", expand=True)

        ttk.Label(
            result_card,
            text="Analysis Results",
            style="CardTitle.TLabel"
        ).pack(anchor="w")

        # Read-only text box used for results.
        self.analysis_text = tk.Text(
            result_card,
            height=20,
            wrap="word",
            font=("Consolas", 10),
            bg="#F9FAFB",
            fg="#111827",
            relief="flat",
            padx=12,
            pady=12
        )
        self.analysis_text.pack(
            fill="both",
            expand=True,
            pady=(10, 0)
        )

        self.analysis_text.insert(
            "end",
            "Create a stego image first, then use the analysis buttons above.\n"
        )

        # Disable editing by the user.
        self.analysis_text.configure(state="disabled")


    # --------------------------------------------------------
    # SMALL GUI HELPER FUNCTIONS
    # --------------------------------------------------------
    def set_status(self, text):
        # Change the message in the status bar.
        self.status_var.set(text)


    def write_decode(self, text):
        # Temporarily enable the decode log.
        self.decode_info.configure(state="normal")

        # Add new text.
        self.decode_info.insert("end", text + "\n")

        # Scroll to the newest line.
        self.decode_info.see("end")

        # Make it read-only again.
        self.decode_info.configure(state="disabled")


    def write_analysis(self, text, clear=False):
        # Temporarily enable the analysis result box.
        self.analysis_text.configure(state="normal")

        # Delete previous contents when clear=True.
        if clear:
            self.analysis_text.delete("1.0", "end")

        # Insert the new result.
        self.analysis_text.insert("end", text + "\n")

        # Scroll to the newest result.
        self.analysis_text.see("end")

        # Make the box read-only again.
        self.analysis_text.configure(state="disabled")


    # --------------------------------------------------------
    # FILE SELECTION
    # --------------------------------------------------------
    def choose_cover(self):
        # Open a file-selection dialog for the cover image.
        path = filedialog.askopenfilename(
            title="Choose Cover Image",
            filetypes=[
                ("Image files", "*.png *.bmp *.tif *.tiff *.jpg *.jpeg"),
                ("All files", "*.*")
            ]
        )

        # If the user presses Cancel, stop this function.
        if not path:
            return

        # Save the full path.
        self.cover_path = path

        # Display only the file name in the GUI.
        self.cover_var.set(os.path.basename(path))

        # Show the selected image in the preview panel.
        self.show_preview(
            path,
            self.cover_preview,
            "cover"
        )

        # Recalculate payload capacity.
        self.update_capacity()

        # Update status bar.
        self.set_status("Cover image selected")


    def choose_secret(self):
        # Open a file-selection dialog for the secret file.
        path = filedialog.askopenfilename(
            title="Choose Secret File",
            filetypes=[
                ("Assignment files", "*.txt *.pdf *.doc *.docx *.png *.jpg *.jpeg"),
                ("All files", "*.*")
            ]
        )

        # Stop if the dialog was cancelled.
        if not path:
            return

        # Save the secret-file path.
        self.secret_path = path

        # Find its size in bytes.
        size = os.path.getsize(path)

        # Display filename and readable size.
        self.secret_var.set(
            f"{os.path.basename(path)}  •  {self.format_bytes(size)}"
        )

        # Recalculate capacity usage.
        self.update_capacity()

        # Update status.
        self.set_status("Secret file selected")


    # --------------------------------------------------------
    # IMAGE PREVIEW
    # --------------------------------------------------------
    def show_preview(self, path, widget, which):
        # Open image and force RGB format.
        img = Image.open(path).convert("RGB")

        # Resize only the preview copy while keeping aspect ratio.
        # The actual source image is NOT resized.
        img.thumbnail((470, 340))

        # Convert Pillow image to a format Tkinter can display.
        photo = ImageTk.PhotoImage(img)

        # Place the image inside the requested label.
        widget.configure(image=photo, text="")

        # Store the image reference in the widget.
        widget.image = photo

        # Also keep a class-level reference.
        if which == "cover":
            self.cover_photo = photo
        else:
            self.stego_photo = photo


    # --------------------------------------------------------
    # CAPACITY CALCULATION
    # --------------------------------------------------------
    def payload_capacity(self):
        # If no cover image is selected, capacity is zero.
        if not self.cover_path:
            return 0

        # Open cover image as RGB.
        img = Image.open(self.cover_path).convert("RGB")

        # Each RGB pixel has 3 channel bytes:
        # Red, Green and Blue.
        #
        # The program stores one payload bit in each channel byte.
        # Therefore:
        #
        # available bits = width × height × 3
        # available bytes = available bits / 8
        return (img.width * img.height * 3) // 8


    def update_capacity(self):
        # If there is no cover image, reset the UI.
        if not self.cover_path:
            self.capacity_var.set("Capacity: —")
            self.capacity_bar["value"] = 0
            return

        # Calculate total capacity in bytes.
        cap = self.payload_capacity()

        # If a secret file is also selected...
        if self.secret_path:
            # Convert the original file name to UTF-8 bytes.
            name_bytes = os.path.basename(
                self.secret_path
            ).encode("utf-8")

            # Required payload consists of:
            # fixed header + filename + secret file contents.
            required = (
                HEADER_SIZE
                + len(name_bytes)
                + os.path.getsize(self.secret_path)
            )

            # Convert usage into percentage.
            # min(100, ...) prevents the progress bar exceeding 100%.
            pct = min(
                100,
                (required / cap * 100) if cap else 100
            )

            # Update the progress bar.
            self.capacity_bar["value"] = pct

            # Show capacity information.
            self.capacity_var.set(
                f"Payload usage: "
                f"{self.format_bytes(required)} / "
                f"{self.format_bytes(cap)}  "
                f"({pct:.1f}%)"
            )

        else:
            # Cover selected, but no secret selected yet.
            self.capacity_bar["value"] = 0
            self.capacity_var.set(
                f"Maximum payload capacity: "
                f"{self.format_bytes(cap)}"
            )


    # --------------------------------------------------------
    # BYTE SIZE FORMATTING
    # --------------------------------------------------------
    @staticmethod
    def format_bytes(value):
        # Convert input into a floating-point number.
        value = float(value)

        # Try B, KB, MB and GB in sequence.
        for unit in ["B", "KB", "MB", "GB"]:

            # Stop when the value fits the current unit.
            if value < 1024 or unit == "GB":
                return f"{value:.2f} {unit}"

            # Otherwise convert to the next unit.
            value /= 1024


    # --------------------------------------------------------
    # BYTE -> BIT CONVERSION
    # --------------------------------------------------------
    @staticmethod
    def bytes_to_bits(data):
        # Process one byte at a time.
        for byte in data:

            # Read bit positions 7 down to 0.
            # This means most-significant bit first.
            for shift in range(7, -1, -1):

                # Shift the target bit to position 0,
                # then AND with 1 to keep only that bit.
                yield (byte >> shift) & 1


    # --------------------------------------------------------
    # BIT -> BYTE CONVERSION
    # --------------------------------------------------------
    @staticmethod
    def bits_to_bytes(bits):
        # Bytearray is used because it can grow efficiently.
        output = bytearray()

        # Holds the byte currently being constructed.
        current = 0

        # Number of bits added to current byte.
        count = 0

        # Read bits one by one.
        for bit in bits:

            # Shift existing bits left and add new bit.
            current = (current << 1) | bit

            # One more bit has been collected.
            count += 1

            # Once 8 bits are collected, one byte is complete.
            if count == 8:
                output.append(current)

                # Reset for the next byte.
                current = 0
                count = 0

        # Convert bytearray to immutable bytes.
        return bytes(output)


    # ========================================================
    # ENCODING / HIDING PROCESS
    # ========================================================
    def encode_file(self):

        # Cover image is required.
        if not self.cover_path:
            messagebox.showwarning(
                "Missing Cover Image",
                "Choose a cover image first."
            )
            return

        # Secret file is required.
        if not self.secret_path:
            messagebox.showwarning(
                "Missing Secret File",
                "Choose a secret file first."
            )
            return

        try:
            # Open cover image and convert to RGB.
            # Converting to RGB gives exactly 3 bytes per pixel.
            image = Image.open(
                self.cover_path
            ).convert("RGB")

            # Open the secret file in binary mode.
            with open(self.secret_path, "rb") as file:
                secret = file.read()

            # Get only the filename, not its full folder path.
            # Convert the filename to bytes for storage.
            filename = os.path.basename(
                self.secret_path
            ).encode("utf-8")

            # Build the payload.
            #
            # struct.pack creates:
            # [MAGIC][filename length][secret-file length]
            #
            # Then we append:
            # [filename][actual secret file bytes]
            payload = (
                struct.pack(
                    HEADER_FMT,
                    MAGIC,
                    len(filename),
                    len(secret)
                )
                + filename
                + secret
            )

            # Convert all RGB pixel/channel bytes into a mutable bytearray.
            image_bytes = bytearray(
                image.tobytes()
            )

            # Every payload byte contains 8 bits.
            bits_needed = len(payload) * 8

            # Check whether the image has enough channel bytes
            # to store every payload bit.
            if bits_needed > len(image_bytes):

                # Estimate maximum secret-file size.
                max_secret = max(
                    0,
                    (len(image_bytes) // 8)
                    - HEADER_SIZE
                    - len(filename)
                )

                # Stop encoding and show an error.
                raise ValueError(
                    "The secret file is too large for this cover image.\n\n"
                    "Approximate maximum secret size: "
                    + self.format_bytes(max_secret)
                )

            # ------------------------------------------------
            # CORE LSB STEGANOGRAPHY LOOP
            # ------------------------------------------------
            # enumerate gives:
            # i   = RGB-byte position
            # bit = secret payload bit (0 or 1)
            for i, bit in enumerate(
                self.bytes_to_bits(payload)
            ):

                # image_bytes[i] & 0xFE
                # clears the current least significant bit.
                #
                # 0xFE in binary = 11111110
                #
                # Then "| bit" sets the LSB to the secret bit.
                #
                # Example:
                # original byte = 11010110
                # secret bit    = 1
                # cleared byte  = 11010110
                # result        = 11010111
                image_bytes[i] = (
                    image_bytes[i] & 0xFE
                ) | bit

            # Rebuild a Pillow image using the modified RGB bytes.
            stego = Image.frombytes(
                "RGB",
                image.size,
                bytes(image_bytes)
            )

            # Ask where to save the output.
            save_path = filedialog.asksaveasfilename(
                title="Save Stego Image",
                initialfile="stego.png",
                defaultextension=".png",
                filetypes=[("PNG image", "*.png")]
            )

            # Stop if user cancels save dialog.
            if not save_path:
                return

            # Save as PNG.
            # PNG is lossless, so it preserves the modified LSB values.
            stego.save(
                save_path,
                format="PNG"
            )

            # Remember the stego-image path.
            self.stego_path = save_path

            # Display stego preview.
            self.show_preview(
                save_path,
                self.stego_preview,
                "stego"
            )

            # Update status bar.
            self.set_status(
                "Secret file hidden successfully"
            )

            # Display information in Analysis tab.
            self.write_analysis(
                f"Stego image created successfully.\n"
                f"Cover: {os.path.basename(self.cover_path)}\n"
                f"Secret: {os.path.basename(self.secret_path)}\n"
                f"Output: {os.path.basename(self.stego_path)}\n",
                clear=True
            )

            # Success popup.
            messagebox.showinfo(
                "Encoding Successful",
                "The secret file was hidden successfully.\n\n"
                "The stego image has been saved as a PNG."
            )

        # Catch any error and show it instead of crashing.
        except Exception as error:
            messagebox.showerror(
                "Encoding Failed",
                str(error)
            )
            self.set_status("Encoding failed")


    # ========================================================
    # DECODING / EXTRACTION PROCESS
    # ========================================================
    def decode_file(self):

        # Ask the user to choose a stego image.
        path = filedialog.askopenfilename(
            title="Choose Stego Image",
            filetypes=[
                ("PNG image", "*.png"),
                ("All files", "*.*")
            ]
        )

        # Stop if the dialog is cancelled.
        if not path:
            return

        try:
            # Open the image as RGB.
            image = Image.open(path).convert("RGB")

            # Convert all RGB values into raw bytes.
            raw = image.tobytes()

            # Create a generator containing only the LSB of every RGB byte.
            #
            # value & 1 returns:
            # 0 if the LSB is 0
            # 1 if the LSB is 1
            bit_iter = (
                value & 1
                for value in raw
            )

            # Read enough bits to reconstruct the fixed header.
            header_bits = [
                next(bit_iter)
                for _ in range(HEADER_SIZE * 8)
            ]

            # Convert header bits back into bytes.
            header = self.bits_to_bytes(
                header_bits
            )

            # Decode the metadata fields from the header.
            magic, filename_length, file_length = struct.unpack(
                HEADER_FMT,
                header
            )

            # Verify that the image contains a valid StegoShield signature.
            if magic != MAGIC:
                raise ValueError(
                    "This image does not contain a valid StegoShield payload."
                )

            # Read the exact number of bits used by the filename.
            filename_bits = [
                next(bit_iter)
                for _ in range(filename_length * 8)
            ]

            # Convert filename bits into bytes,
            # then decode UTF-8 bytes into text.
            filename = self.bits_to_bytes(
                filename_bits
            ).decode(
                "utf-8",
                errors="replace"
            )

            # Read exactly the number of bits needed
            # for the original secret file.
            data_bits = [
                next(bit_iter)
                for _ in range(file_length * 8)
            ]

            # Convert file bits back to the original bytes.
            data = self.bits_to_bytes(
                data_bits
            )

            # Ask the user where to save the recovered file.
            save_path = filedialog.asksaveasfilename(
                title="Save Extracted File",
                initialfile=filename,
                defaultextension=os.path.splitext(filename)[1]
            )

            # Stop if save is cancelled.
            if not save_path:
                return

            # Write the recovered bytes back to a file.
            with open(save_path, "wb") as output:
                output.write(data)

            # Add extraction details to the GUI log.
            self.write_decode(
                f"EXTRACTION SUCCESSFUL\n"
                f"---------------------\n"
                f"Stego image : {os.path.basename(path)}\n"
                f"Filename    : {filename}\n"
                f"File size   : {self.format_bytes(len(data))}\n"
                f"Saved to    : {save_path}\n"
            )

            # Update the status bar.
            self.set_status(
                "Hidden file extracted successfully"
            )

            # Show success popup.
            messagebox.showinfo(
                "Extraction Successful",
                f"Recovered: {filename}"
            )

        # StopIteration happens if the image ends before
        # all expected payload bits can be read.
        except StopIteration:
            messagebox.showerror(
                "Extraction Failed",
                "The image ended before the payload was completely recovered."
            )

        # Handle all other decoding errors.
        except Exception as error:
            messagebox.showerror(
                "Extraction Failed",
                str(error)
            )
            self.set_status("Extraction failed")


    # --------------------------------------------------------
    # CHECK THAT ANALYSIS IMAGES EXIST
    # --------------------------------------------------------
    def require_images(self):
        # Analysis needs both the original cover and generated stego image.
        if not self.cover_path or not self.stego_path:
            messagebox.showwarning(
                "Images Required",
                "Choose a cover image and create a stego image first."
            )
            return False

        # Both paths exist in the program state.
        return True


    # ========================================================
    # FILE SIZE ANALYSIS
    # ========================================================
    def compare_sizes(self):
        # Stop if cover/stego images are unavailable.
        if not self.require_images():
            return

        # Get actual file sizes from disk.
        cover_size = os.path.getsize(
            self.cover_path
        )
        stego_size = os.path.getsize(
            self.stego_path
        )

        # Positive = stego is larger.
        # Negative = stego is smaller.
        difference = stego_size - cover_size

        # Calculate percentage change.
        percent = (
            difference / cover_size * 100
        ) if cover_size else 0

        # Display results.
        self.write_analysis(
            f"FILE SIZE COMPARISON\n"
            f"--------------------\n"
            f"Cover image : {self.format_bytes(cover_size)} "
            f"({cover_size:,} bytes)\n"
            f"Stego image : {self.format_bytes(stego_size)} "
            f"({stego_size:,} bytes)\n"
            f"Difference  : {difference:+,} bytes\n"
            f"Change      : {percent:+.2f}%\n\n"
            f"Explanation:\n"
            f"The image dimensions remain unchanged, but the PNG file size "
            f"may change because modifying pixel LSB values changes how "
            f"efficiently the image data is compressed.\n",
            clear=True
        )

        # Update status.
        self.set_status(
            "File-size analysis completed"
        )


    # ========================================================
    # PIXEL / CHANNEL DIFFERENCE ANALYSIS
    # ========================================================
    def pixel_difference(self):
        # Check required images.
        if not self.require_images():
            return

        # Open original cover.
        cover = Image.open(
            self.cover_path
        ).convert("RGB")

        # Open generated stego image.
        stego = Image.open(
            self.stego_path
        ).convert("RGB")

        # Analysis only makes sense when dimensions match.
        if cover.size != stego.size:
            messagebox.showerror(
                "Analysis Error",
                "The two images do not have the same dimensions."
            )
            return

        # Create an image containing absolute pixel differences.
        diff = ImageChops.difference(
            cover,
            stego
        )

        # Calculate statistical information from difference image.
        stat = ImageStat.Stat(diff)

        # For each channel, get (minimum difference, maximum difference).
        extrema = diff.getextrema()

        # Find the largest difference among R, G and B.
        max_change = max(
            channel[1]
            for channel in extrema
        )

        # Convert both images into raw RGB bytes.
        cover_bytes = cover.tobytes()
        stego_bytes = stego.tobytes()

        # Count how many RGB channel bytes changed.
        changed = sum(
            1
            for a, b in zip(
                cover_bytes,
                stego_bytes
            )
            if a != b
        )

        # Total number of RGB bytes.
        total = len(cover_bytes)

        # Percentage of RGB bytes that changed.
        changed_pct = (
            changed / total * 100
        ) if total else 0

        # Display the analysis.
        self.write_analysis(
            f"PIXEL / CHANNEL DIFFERENCE\n"
            f"--------------------------\n"
            f"Image dimensions       : {cover.width} × {cover.height}\n"
            f"Total RGB channel bytes: {total:,}\n"
            f"Changed channel bytes  : {changed:,}\n"
            f"Changed percentage     : {changed_pct:.4f}%\n"
            f"Maximum channel change : {max_change}\n"
            f"Mean absolute change   : "
            f"R={stat.mean[0]:.6f}, "
            f"G={stat.mean[1]:.6f}, "
            f"B={stat.mean[2]:.6f}\n\n"
            f"Interpretation:\n"
            f"With LSB substitution, an altered RGB channel changes "
            f"by only 1 intensity level. Therefore, the maximum expected "
            f"channel difference is 1 and the visual impact is very small.\n",
            clear=True
        )

        # Update status.
        self.set_status(
            "Pixel difference analysis completed"
        )


    # ========================================================
    # RGB HISTOGRAM ANALYSIS
    # ========================================================
    def show_histograms(self):
        # Check that both images are available.
        if not self.require_images():
            return

        # Open both images as RGB.
        cover = Image.open(
            self.cover_path
        ).convert("RGB")

        stego = Image.open(
            self.stego_path
        ).convert("RGB")

        # Pillow histogram() returns 768 values for RGB:
        # first 256   = Red
        # next 256    = Green
        # final 256   = Blue
        cover_hist = cover.histogram()
        stego_hist = stego.histogram()

        # X-axis pixel intensity values.
        x = list(range(256))

        # Channel names used in the loop.
        labels = ["Red", "Green", "Blue"]

        # Create a graph window.
        plt.figure(figsize=(10, 6))

        # Plot each colour channel.
        for index, name in enumerate(labels):

            # Work out the correct 256-value slice.
            start = index * 256
            end = start + 256

            # Solid line = cover image.
            plt.plot(
                x,
                cover_hist[start:end],
                label=f"Cover {name}"
            )

            # Dashed line = stego image.
            plt.plot(
                x,
                stego_hist[start:end],
                linestyle="--",
                label=f"Stego {name}"
            )

        # Add graph title and axis labels.
        plt.title(
            "Cover Image vs Stego Image - RGB Histogram"
        )
        plt.xlabel("Pixel Intensity")
        plt.ylabel("Frequency")

        # Display the line labels.
        plt.legend()

        # Improve graph spacing.
        plt.tight_layout()

        # Show the histogram window.
        plt.show()

        # Write interpretation into the app.
        self.write_analysis(
            "HISTOGRAM ANALYSIS\n"
            "------------------\n"
            "The RGB histogram comparison has been displayed.\n\n"
            "Expected observation:\n"
            "The cover and stego histograms should be almost identical. "
            "Small differences can appear between neighbouring intensity "
            "values because LSB embedding changes selected RGB values "
            "by at most one.\n",
            clear=True
        )

        # Update status.
        self.set_status("Histogram displayed")


# ============================================================
# PROGRAM ENTRY POINT
# ============================================================

# This block runs only when this file is executed directly.
if __name__ == "__main__":

    # Create the main Tkinter window.
    root = tk.Tk()

    # Create the application object and give it the root window.
    app = SteganographyGUI(root)

    # Start Tkinter's event loop.
    # The program stays here waiting for button clicks and other events.
    root.mainloop()
