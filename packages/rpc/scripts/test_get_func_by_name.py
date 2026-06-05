import argparse
import sys

import rpyc

from utils.set_connection import set_connection

DEFAULT_ADDRESS = "0x140009050"

def init_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Get function metadata by name."
    )
    parser.add_argument("--host", default="127.0.0.1", help="RPC server host")
    parser.add_argument("--port", type=int, required=True, help="RPC server port")
    parser.add_argument(
        "--name",
        default="function_name",
        required = True,
        help="Target function name",
    )
    args = parser.parse_args()
    return args

def main() -> int:
    args = init_args()
    conn = set_connection(args.host, args.port)
    try:
        func = conn.root.get_function_by_name(function_name=args.name)
        print(conn.root.get_function_by_name)
        print(f"got function metadata for {args.name}\n {func}")
    except Exception as exc:
        print(f"RPC call failed: {exc}", file=sys.stderr)
        return 1
    finally:
        conn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
