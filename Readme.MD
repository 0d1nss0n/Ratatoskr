# Ratatoskr

## Description

Ratatoskr is a sophisticated Python script that leverages steganography to conceal and reveal messages within images. Utilizing the `stegano` library for steganography tasks, Ratatoskr introduces an additional layer of security by encrypting messages with a password before hiding them. The script's innovation lies in its encryption method, which incorporates a salt to ensure that each encryption is unique, significantly enhancing the security of the hidden message.

![Ratatoskr](https://raw.githubusercontent.com/0d1nss0n/Ratatoskr/main/img/ratatoskr.png "Ratatoskr Steganography Tool")

## Features

- **Secure Message Hiding**: Employs a combination of password-based encryption and a randomly generated salt to securely hide messages within images.
- **Message Retrieval**: Allows for the safe extraction of hidden messages from images, provided the correct password is supplied.
- **Enhanced Security**: Utilizes salted encryption to protect against brute-force attacks and ensure that each encryption is unique, even when the same password is reused.

## Prerequisites

To use Ratatoskr, you must first install its dependencies. Ensure Python 3 is installed on your system and then execute the following command:

```sh
pip3 install -r requirements.txt
