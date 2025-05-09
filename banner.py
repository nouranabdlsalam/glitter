import os
import importlib.resources


def print_banner():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    banner_path = os.path.join(script_dir, "assets", "banner.txt")

    try:
        with open(banner_path, "r") as file:
            banner_content = file.read()
            print(banner_content)
    except FileNotFoundError:
        print("Error: banner.txt not found in the current directory.")


