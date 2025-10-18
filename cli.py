import argparse
import stat
from ryujin import *

def main():
    status = 0
    parser = argparse.ArgumentParser(description='Remove junk code and find real instructions in Ryujin-packed binary')
    parser.add_argument(
        '-f', '--file-exe', help='Binary input file to be processed', type=str, required=True
    )
    parser.add_argument(
        '-d', '--decrypt-binary', help='Decrypt binary', action='store_true', default=False
    )

    args = parser.parse_args()
    config = Config(
        file_exe=args.file_exe
    )
    ryujin = Ryujin(config)
   
    if args.decrypt_binary:
        ryujin.decrypt()
        status = 1
    else:
        ryujin.log("Invalid arguments")
   
    return exit(status)

if __name__ == "__main__":
    main()