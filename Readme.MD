# Ratatoskr

## Description

This is a Python script that allows you to hide and reveal messages using steganography techniques. Steganography is the practice of concealing messages or information within other non-secret data, such as images.

The script uses the `stegano` library to perform steganography operations. It provides a command-line interface for users to hide messages within images and later reveal those messages using a password.

![alt text](https://raw.githubusercontent.com/0d1nss0n/Ratatosrk/main/img/ratatoskr.png)

## Features

- Hide a message within an image using a password.
- Reveal a hidden message from an image using the correct password.

## Prerequisites

Before using the script, make sure that you install the dependancies:

- pip3 install -r requirements.txt

## Usage

1. Run the script using the command: `python3 ratatoskr.py`

2. Follow the on-screen instructions to choose options and provide necessary inputs.

3. Choose whether to hide a message within an image or reveal a hidden message from an image.

4. If hiding a message, provide a password, the message to be hidden, the input image path, and the output image path.

5. If revealing a message, provide the image with the hidden message and the correct password.

6. Exit the script when done.
