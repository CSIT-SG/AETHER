from .server import build_server_context, run_server


# TODO: This is merely for testing, do not use in real use
# Just follow this format to deploy server
def main() -> None:
    ctx = build_server_context(
        idb_path="test.idb",
        architecture="x86",
        bitness=64,
        entry_point=0x401000,
    )

    run_server(ctx, host="127.0.0.1", port=8000)


if __name__ == "__main__":
    main()
