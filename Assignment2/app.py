import io
import os
import struct
from flask import Flask, render_template, request, send_file, jsonify
from PIL import Image, ImageChops, ImageStat

app = Flask(__name__)

MAGIC = b"STEGv1\x00\x00"
HEADER_FMT = ">8sHQ"
HEADER_SIZE = struct.calcsize(HEADER_FMT)


def bytes_to_bits(data):
    for byte in data:
        for shift in range(7, -1, -1):
            yield (byte >> shift) & 1


def bits_to_bytes(bits):
    output = bytearray()
    current = 0
    count = 0

    for bit in bits:
        current = (current << 1) | bit
        count += 1

        if count == 8:
            output.append(current)
            current = 0
            count = 0

    return bytes(output)


def format_bytes(value):
    value = float(value)
    for unit in ["B", "KB", "MB", "GB"]:
        if value < 1024 or unit == "GB":
            return f"{value:.2f} {unit}"
        value /= 1024


def encode_image(cover_file, secret_file):
    image = Image.open(cover_file).convert("RGB")
    secret = secret_file.read()

    filename = os.path.basename(secret_file.filename).encode("utf-8")

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

    image_bytes = bytearray(image.tobytes())
    bits_needed = len(payload) * 8

    if bits_needed > len(image_bytes):
        max_secret = max(
            0,
            (len(image_bytes) // 8) - HEADER_SIZE - len(filename)
        )
        raise ValueError(
            "The secret file is too large for this cover image. "
            f"Approximate maximum secret size: {format_bytes(max_secret)}"
        )

    for i, bit in enumerate(bytes_to_bits(payload)):
        image_bytes[i] = (image_bytes[i] & 0xFE) | bit

    stego = Image.frombytes("RGB", image.size, bytes(image_bytes))

    output = io.BytesIO()
    stego.save(output, format="PNG")
    output.seek(0)

    return output


def decode_image(stego_file):
    image = Image.open(stego_file).convert("RGB")
    raw = image.tobytes()

    bit_iter = (value & 1 for value in raw)

    try:
        header_bits = [next(bit_iter) for _ in range(HEADER_SIZE * 8)]
        header = bits_to_bytes(header_bits)

        magic, filename_length, file_length = struct.unpack(
            HEADER_FMT,
            header
        )

        if magic != MAGIC:
            raise ValueError(
                "This image does not contain a valid StegoShield payload."
            )

        # Basic sanity check against malicious/corrupt metadata.
        max_payload_bytes = len(raw) // 8
        if (
            filename_length > max_payload_bytes
            or file_length > max_payload_bytes
            or HEADER_SIZE + filename_length + file_length > max_payload_bytes
        ):
            raise ValueError("The embedded payload metadata is invalid.")

        filename_bits = [
            next(bit_iter)
            for _ in range(filename_length * 8)
        ]
        filename = bits_to_bytes(filename_bits).decode(
            "utf-8",
            errors="replace"
        )

        # Strip path components to avoid unsafe download filenames.
        filename = os.path.basename(filename) or "extracted_file"

        data_bits = [
            next(bit_iter)
            for _ in range(file_length * 8)
        ]
        data = bits_to_bytes(data_bits)

        return filename, data

    except StopIteration:
        raise ValueError(
            "The image ended before the payload was completely recovered."
        )


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/encode", methods=["POST"])
def encode():
    try:
        cover = request.files.get("cover")
        secret = request.files.get("secret")

        if not cover or not secret:
            return jsonify({
                "ok": False,
                "error": "Please choose both a cover image and a secret file."
            }), 400

        result = encode_image(cover, secret)

        return send_file(
            result,
            mimetype="image/png",
            as_attachment=True,
            download_name="stego.png"
        )

    except Exception as error:
        return jsonify({
            "ok": False,
            "error": str(error)
        }), 400


@app.route("/decode", methods=["POST"])
def decode():
    try:
        stego = request.files.get("stego")

        if not stego:
            return jsonify({
                "ok": False,
                "error": "Please choose a stego PNG image."
            }), 400

        filename, data = decode_image(stego)

        return send_file(
            io.BytesIO(data),
            as_attachment=True,
            download_name=filename,
            mimetype="application/octet-stream"
        )

    except Exception as error:
        return jsonify({
            "ok": False,
            "error": str(error)
        }), 400


@app.route("/capacity", methods=["POST"])
def capacity():
    try:
        cover = request.files.get("cover")

        if not cover:
            return jsonify({
                "ok": False,
                "error": "Please choose a cover image."
            }), 400

        image = Image.open(cover).convert("RGB")
        capacity_bytes = (image.width * image.height * 3) // 8

        return jsonify({
            "ok": True,
            "width": image.width,
            "height": image.height,
            "capacity_bytes": capacity_bytes,
            "capacity_text": format_bytes(capacity_bytes)
        })

    except Exception as error:
        return jsonify({
            "ok": False,
            "error": str(error)
        }), 400


@app.route("/analyze", methods=["POST"])
def analyze():
    try:
        cover_file = request.files.get("cover")
        stego_file = request.files.get("stego")

        if not cover_file or not stego_file:
            return jsonify({
                "ok": False,
                "error": "Choose both the original cover and stego image."
            }), 400

        cover_bytes_on_disk = cover_file.read()
        stego_bytes_on_disk = stego_file.read()

        cover = Image.open(io.BytesIO(cover_bytes_on_disk)).convert("RGB")
        stego = Image.open(io.BytesIO(stego_bytes_on_disk)).convert("RGB")

        if cover.size != stego.size:
            raise ValueError("The two images do not have the same dimensions.")

        diff = ImageChops.difference(cover, stego)
        stat = ImageStat.Stat(diff)
        extrema = diff.getextrema()
        max_change = max(channel[1] for channel in extrema)

        cover_raw = cover.tobytes()
        stego_raw = stego.tobytes()

        changed = sum(
            1 for a, b in zip(cover_raw, stego_raw)
            if a != b
        )
        total = len(cover_raw)
        changed_pct = (changed / total * 100) if total else 0

        size_difference = len(stego_bytes_on_disk) - len(cover_bytes_on_disk)
        size_percent = (
            size_difference / len(cover_bytes_on_disk) * 100
            if cover_bytes_on_disk else 0
        )

        return jsonify({
            "ok": True,
            "dimensions": f"{cover.width} × {cover.height}",
            "cover_size": format_bytes(len(cover_bytes_on_disk)),
            "stego_size": format_bytes(len(stego_bytes_on_disk)),
            "size_difference": size_difference,
            "size_percent": round(size_percent, 2),
            "changed_channels": changed,
            "total_channels": total,
            "changed_percent": round(changed_pct, 4),
            "max_channel_change": max_change,
            "mean_r": round(stat.mean[0], 6),
            "mean_g": round(stat.mean[1], 6),
            "mean_b": round(stat.mean[2], 6),
        })

    except Exception as error:
        return jsonify({
            "ok": False,
            "error": str(error)
        }), 400


if __name__ == "__main__":
    app.run(debug=True)
