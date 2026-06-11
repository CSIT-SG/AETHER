import argparse
import sys

from utils.set_connection import set_connection

DEFAULT_ADDRESS = "0x140009050"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Call the IDA RPC server to change variable name at given function address and variable name."
    )
    parser.add_argument("--host", default="127.0.0.1", help="RPC server host")
    parser.add_argument("--port", type=int, required=True, help="RPC server port")
    parser.add_argument(
        "--address",
        default=DEFAULT_ADDRESS,
        help="Target function address (hex like 0x000080F0 or decimal)",
    )
    parser.add_argument(
        "--old_name",
        default="v1",
        help="Variable name to change",
    )
    parser.add_argument(
        "--new_name",
        default="testing_from_rpc",
        help="Variable name to change to",
    )
    args = parser.parse_args()

    conn = set_connection(args.host, args.port)

    try:
        conn.root.rename_local_variable(
            function_address=args.address, old_var_name=args.old_name, new_var_name=args.new_name
        )
    except Exception as exc:
        print(f"RPC call failed: {exc}", file=sys.stderr)
        return 1
    finally:
        conn.close()

    print(f"Changed variable name at {args.address}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
