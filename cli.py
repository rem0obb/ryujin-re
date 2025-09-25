import argparse
from ryujin import *

def main():
    status = 0
    parser = argparse.ArgumentParser(description='Remove junk code and find real instructions in Ryujin-packed binary')
    parser.add_argument(
        '-f', '--file-exe', help='Binary input file to be processed', type=str, required=True
    )
    parser.add_argument(
        '-r', '--remove-junkcode', help='Remove junk code', action='store_true', default=False
    )
    parser.add_argument(
        '-d', '--decrypt-binary', help='Decrypt binary', action='store_true', default=False
    )
    parser.add_argument(
        '-n', '--nops-control', help='Set nops control count for cleanup', type=int, default=5
    )
    parser.add_argument(
        '--target-ea', help='Target function EA to process (for single function mode)', type=int, default=None
    )
   
    args = parser.parse_args()
    config = Config(
        nops_control=args.nops_control,
        file_exe=args.file_exe,
        target_function_ea=args.target_ea
    )
    ryujin = Ryujin(config)
   
    if args.decrypt_binary:
        ryujin.decrypt()
        status = 1
    elif args.remove_junkcode:
        ryujin.remove_junkcode()
        status = 1
    else:
        ryujin.log("Invalid arguments")
   
    return exit(status)

if __name__ == "__main__":
    main()