# Secret Messenger

Secret Messenger is a simple Tkinter-based application that allows users to encrypt and decrypt messages using a secret key. The encryption uses AES (Advanced Encryption Standard) for secure communication.

## Features

- Encrypt messages using AES encryption.
- Decrypt messages with the correct secret key.
- User-friendly interface with Tkinter.
- Support for handling special characters and padding.

## Installation

1. **Clone the repository:**

    ```
    git clone https://github.com/W45P85/Secret-Messenger
    cd secret-messenger
    ```

2. **Create and activate a virtual environment using Anaconda:**

    ```
    conda create -n secret-messenger-env python=3.9
    conda activate secret-messenger-env
    ```

3. **Install the required dependencies:**

    ```
    pip install -r requirements.txt
    ```

## Usage

1. **Run the application:**

    ```
    python secret_messager.py
    ```

2. **Encrypting a Message:**

    - Enter your message in the text box.
    - Enter your secret key.
    - Click the `ENCRYPT` button.
    - The encrypted message will be displayed in a new window.

3. **Decrypting a Message:**

    - Enter the encrypted message in the text box.
    - Enter the same secret key used for encryption.
    - Click the `DECRYPT` button.
    - The decrypted message will be displayed in a new window.

