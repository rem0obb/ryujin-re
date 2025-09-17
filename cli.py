import argparse
from ryujin import *

def main(config: Config) -> int:
    ryujin = Ryujin(config)
    ryujin.remove_junkcode()
    return 0

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Remove junk code and find real instructions in Ryujin-packed binary')
    parser.add_argument(
        '-f', '--file-database', help='Binary input file to be processed', type=str, required=False
    )
    parser.add_argument(
        '-n', '--nops-control', help='Set nops control count for cleanup', type=int, required=False, default=5
    )
    parser.add_argument(
        '--target-ea', help='Target function EA to process (for single function mode)', type=int, required=False, default=None
    )
    
    args = parser.parse_args()
    config = Config(
        nops_control=args.nops_control,
        file_database=args.file_database,
        target_function_ea=args.target_ea
    )
    exit(main(config))