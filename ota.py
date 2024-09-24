#!/usr/bin/python3

import argparse
import hashlib
import io
import os
import socket
import struct

import secrets
import sys
import time
from enum import Enum

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

FlashSectorSize = 4096
FlashSectorsPerBlock = 16
FlashBlockSize = FlashSectorsPerBlock * FlashSectorSize


class Status(Enum):
    OK = 0
    ERROR = 1
    SEND_SECTORS = 2
    BLOCKING = 3
    RESTART_PENDING = 4
    DONE = 10


# Function to read 16-byte AES encryption key from stdin
def read_aes_key():
    aes_key = input("Enter 16-byte AES encryption key: ")
    if len(aes_key) != 32:
        raise ValueError("Invalid AES key length. Key must be 32 characters long.")
    print()
    return bytearray.fromhex(aes_key)


# Function to calculate MD5 hash and file size
def calculate_md5_and_size(file_path):
    sector_data = []
    with open(file_path, 'rb') as file:
        md5 = hashlib.md5()
        while chunk := file.read(FlashSectorSize):
            chunk += b'\0' * (FlashSectorSize - len(chunk))
            sector_data.append(chunk)
            md5.update(chunk)
        file_size = os.path.getsize(file_path)
        # Data is being padded to the next flash sector size
        if (file_size % FlashSectorSize) != 0:
            file_size += FlashSectorSize - (file_size % FlashSectorSize)
    return md5.hexdigest(), file_size, sector_data


def check_status(s: socket.socket) -> Status:
    try:
        status = s.recv(1)
    except BlockingIOError:
        return Status.BLOCKING

    status_code = Status(struct.unpack('<B', status)[0])

    was_blocking = s.getblocking()
    s.setblocking(True)
    message_size = struct.unpack('<I', s.recv(4))[0]
    message = s.recv(message_size).decode('utf-8')
    sys.stdout.write(message)
    sys.stdout.flush()
    s.setblocking(was_blocking)

    if status_code == Status.ERROR:
        exit(2)

    return status_code


def send_sector(sector_data, s: socket.socket):
    while True:
        try:
            s.sendall(sector_data)
            return
        except BlockingIOError:
            time.sleep(0.1)


def run_ota_update(flash_file_path, update_type: str, remote_ip, remote_port, aes_key):
    if update_type != "request_recovery":
        firmware_hash, flash_file_size, sector_data = calculate_md5_and_size(flash_file_path)
    else:
        firmware_hash = "00000000000000000000000000000000"
        flash_file_size = 0
        sector_data = []

    iv = secrets.token_bytes(16)

    if update_type == "firmware":
        update_type_char = b'f'
    elif update_type == "data":
        update_type_char = b'd'
    elif update_type == "request_recovery":
        update_type_char = b'r'
    else:
        raise f"Unknown update type {update_type}"

    header = b'aaaaaaaaaaaaaaaa' + firmware_hash.encode() + struct.pack("<I", flash_file_size) + update_type_char
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    encrypted_header = cipher.encrypt(pad(header, 16))

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        print(f"Connecting to {remote_ip}:{remote_port}")
        while True:
            try:
                s.connect((remote_ip, remote_port))
                break
            except ConnectionRefusedError:
                print("Target refused connection, trying again")
                time.sleep(0.5)
        print(f"Connected")

        s.sendall(iv)
        s.sendall(encrypted_header)

        if update_type == "request_recovery":
            while check_status(s) != Status.RESTART_PENDING:
                pass
            return

        while check_status(s) != Status.SEND_SECTORS:
            pass

        s.setblocking(False)

        for sector in sector_data:
            send_sector(cipher.encrypt(sector), s)
            while check_status(s) != Status.BLOCKING:
                pass

        s.setblocking(True)

        while check_status(s) != Status.DONE:
            # Read status until micro controller finishes
            pass


def parse_arguments():
    parser = argparse.ArgumentParser(description="ESP32 encrypted ota helper")
    parser.add_argument("flash_file", help="Binary file of the firmware or data to flash.", default='none')
    parser.add_argument("update_type", choices=["firmware", "data", "request_recovery"],
                        default="firmware", help="Update type")
    parser.add_argument("remote_ip", help="IP address of the microcontroller to update")
    parser.add_argument("remote_port", type=int, help="Port to connect to")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_arguments()
    aes_key_ = read_aes_key()
    run_ota_update("", "request_recovery", args.remote_ip, args.remote_port, aes_key_)
    if args.flash_file != 'none':
        run_ota_update(args.flash_file, args.update_type, args.remote_ip, args.remote_port, aes_key_)
