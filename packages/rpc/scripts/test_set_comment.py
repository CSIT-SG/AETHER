import argparse
import sys

import rpyc

DEFAULT_ADDRESS = "0x000080F0"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Call the IDA RPC server to set a comment at a specific address."
    )
    parser.add_argument("--host", default="127.0.0.1", help="RPC server host")
    parser.add_argument("--port", type=int, required=True, help="RPC server port")
    parser.add_argument(
        "--address",
        default=DEFAULT_ADDRESS,
        help="Target address (hex like 0x000080F0 or decimal)",
    )
    parser.add_argument(
        "--comment",
        default="test comment from rpc",
        help="Comment to set at the target address",
    )
    args = parser.parse_args()

    try:
        conn = rpyc.connect(
            args.host,
            args.port,
            config={
                "allow_public_attrs": True,
                "allow_pickle": True,
            },
        )
    except Exception as exc:
        print(f"Failed to connect to RPC server: {exc}", file=sys.stderr)
        return 1

    try:
        conn.root.set_comment(address=args.address, comment=args.comment)
    except Exception as exc:
        print(f"RPC call failed: {exc}", file=sys.stderr)
        return 1
    finally:
        conn.close()

    print(f"Set comment at {args.address}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
